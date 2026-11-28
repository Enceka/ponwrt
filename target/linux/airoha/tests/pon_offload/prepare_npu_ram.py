#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat

from verify_pon_payload import INSTALLED_NAMES, verify as verify_pon_payload


FIRMWARE = 'lib/firmware/airoha/hg5585f-ct/'
NAMES = ('npu_rebuilt_rv32.bin', 'npu_rebuilt_data.bin')
FEATURES = ('fe_pon_generic', 'fe_pon_auth', 'fe_pipeline', 'fe_auth',
            'fe_auth_mailbox', 'bank1_gate', 'eth_return')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def archive_entries(content):
    entries = []
    names = set()
    position = 0
    while True:
        require(content[position:position + 6] == b'070701', 'expected newc header')
        header = content[position + 6:position + 110]
        require(len(header) == 104 and re.fullmatch(rb'[0-9a-fA-F]{104}', header),
                'invalid newc fields')
        fields = [int(header[index:index + 8], 16) for index in range(0, 104, 8)]
        size, name_size = fields[6], fields[11]
        name_end = position + 110 + name_size
        require(name_size > 1 and name_end <= len(content) and content[name_end - 1] == 0,
                'invalid newc name')
        name = content[position + 110:name_end - 1].decode('utf-8')
        require(name not in names and '\0' not in name, 'duplicate or invalid newc name')
        require(not name.startswith('/') and '..' not in name.split('/'), 'unsafe newc path')
        names.add(name)
        start = (name_end + 3) & ~3
        end = start + size
        position = (end + 3) & ~3
        require(position <= len(content), 'truncated newc payload')
        require(fields[12] == 0, 'unexpected newc checksum')
        if name == 'TRAILER!!!':
            require(size == 0 and not any(content[position:]), 'data after newc trailer')
            return entries, fields
        entries.append((name, fields, content[start:end]))


def encode_archive(entries, trailer):
    output = bytearray()
    for name, original, payload in [*entries, ('TRAILER!!!', trailer, b'')]:
        fields = original.copy()
        encoded = name.encode('utf-8') + b'\0'
        fields[6], fields[11] = len(payload), len(encoded)
        output.extend(b'070701' + ''.join(f'{value:08x}' for value in fields).encode())
        output.extend(encoded)
        output.extend(bytes(-len(output) % 4))
        output.extend(payload)
        output.extend(bytes(-len(output) % 4))
    output.extend(bytes(-len(output) % 512))
    return bytes(output)


def replace_loader(source, old_payloads, payloads):
    expression = r'(static const u8 lab_sha256\[\]\[SHA256_DIGEST_SIZE\] = \{)(.*?)(\n\t\};)'
    matches = list(re.finditer(expression, source, re.S))
    require(len(matches) == 1, 'expected one RAM loader digest table')
    match = matches[0]
    actual = bytes(int(word, 16) for word in re.findall(r'0x([0-9a-fA-F]{2})\b', match[2]))
    require(actual == b''.join(hashlib.sha256(blob).digest() for blob in old_payloads),
            'loader and baseline initramfs disagree')
    require('0x18000, lab_sha256[0], false)' in source and
            '4, lab_sha256[1], false)' in source, 'unsupported RAM loader')
    rows = ['\n\t\t{ ' + ', '.join(f'0x{value:02x}' for value in hashlib.sha256(blob).digest()) + ' },'
            for blob in payloads]
    return source[:match.start(2)] + ''.join(rows) + source[match.end(2):]


def production_loader(source, payloads):
    tables = {}
    for name, dimensions in (('pon_sha256', r'\[SHA256_DIGEST_SIZE\]'),
                             ('lab_sha256', r'\[\]\[SHA256_DIGEST_SIZE\]')):
        matches = re.findall(r'static const u8 ' + name + dimensions +
                             r' = \{(.*?)\n\t\};', source, re.S)
        require(len(matches) == 1, 'expected one production loader table: ' + name)
        tables[name] = bytes(int(word, 16) for word in re.findall(r'0x([0-9a-fA-F]{2})\b', matches[0]))
    require(tables['pon_sha256'] == hashlib.sha256(payloads[0]).digest() and
            len(tables['lab_sha256']) == 64 and
            tables['lab_sha256'][32:] == hashlib.sha256(payloads[1]).digest(),
            'production loader digest mismatch')
    require(all('airoha/hg5585f-ct/' + name in source for name in INSTALLED_NAMES.values()) and
            '0x18000, pon ? pon_sha256 :' in source and
            '4, lab_sha256[1], false)' in source, 'unsupported production loader')
    return source


def module_replacements(directory, entries):
    result = {}
    for path in sorted(directory.glob('*.ko')):
        require(path.is_file() and not path.is_symlink(), 'module must be a regular file')
        matches = [(name, fields) for name, fields, _ in entries
                   if name.startswith('lib/modules/') and Path(name).name == path.name]
        require(len(matches) == 1, 'missing or ambiguous baseline module: ' + path.name)
        name, fields = matches[0]
        require(stat.S_ISREG(fields[1]) and fields[4] == 1, 'baseline module must be regular and unlinked')
        blob = path.read_bytes()
        release = name.split('/')[2].encode()
        require(blob[:6] == b'\x7fELF\x02\x01' and blob[18:20] == b'\xb7\0' and
                b'vermagic=' + release + b' ' in blob, 'module architecture or release mismatch: ' + path.name)
        result[name] = blob
    require(result, 'no replacement modules')
    return result


def prepare(payload_dir, acceptance, archive, loader, profile='diagnostic', modules=None):
    require(profile in ('diagnostic', 'production-session'), 'unknown RAM profile')
    if profile == 'production-session':
        verify_pon_payload(payload_dir)
    manifest = json.loads((payload_dir / 'ram-payload.json').read_text())
    require(acceptance.get('passed') is True, 'RV32 acceptance failed')
    require(acceptance['elf_sha256'] == manifest['elf']['sha256'], 'untested RV32 ELF')
    require(manifest['native_abi'] == 3 and manifest['native_caps'] == 63,
            'native firmware ABI mismatch')
    require((manifest['ct_bridge_guard_profile'], manifest['ct_tdma_bank_profile']) == (2, 2)
            and manifest['ct_short_pad'] is True and manifest['ct_native_pairs'] is True
            and manifest['ct_fe_native'] is True, 'missing native compatibility')
    require(all(manifest['features'].get(name) is True for name in FEATURES)
            and manifest['features'].get('eth_return_dma') is False, 'PON feature mismatch')
    end = int(manifest['local_sram']['bss_end'], 16)
    require(0x3e900004 <= end <= 0x3e9037c8 and
            manifest['local_sram']['remaining_bytes'] == 0x3e9037c8 - end,
            'invalid local SRAM bounds')
    blobs = {}
    for section, name in (('elf', 'lab.elf'), ('code', 'ram-npu_rv32.bin'),
                          ('data', 'ram-npu_data.bin')):
        description = manifest[section]
        require(description['name'] == name, 'unexpected payload name')
        blob = (payload_dir / name).read_bytes()
        require(len(blob) == description['bytes'] and sha256(blob) == description['sha256'],
                'payload identity mismatch: ' + name)
        blobs[section] = blob
    require(0 < len(blobs['code']) <= 0x18000 and blobs['data'] == bytes(4), 'payload bounds')
    require(manifest['code']['npu_address'] == '0x84000000' and
            manifest['data']['npu_address'] == '0x3e900000' and
            manifest['data']['host_address'] == '0x1e900000', 'payload load addresses')
    entries, trailer = archive_entries(archive)
    old = {name: content for name, _, content in entries}
    replacements = dict(zip((FIRMWARE + name for name in NAMES), (blobs['code'], blobs['data'])))
    require(replacements.keys() <= old.keys(), 'missing baseline RAM firmware')
    for name, fields, _ in entries:
        if name in replacements:
            require(stat.S_ISREG(fields[1]) and fields[4] == 1, 'firmware must be a regular unlinked file')
    installed = dict(zip(replacements, (FIRMWARE + name for name in INSTALLED_NAMES.values())))
    if profile == 'production-session':
        require(not set(installed.values()) & old.keys(), 'baseline already contains production firmware')
        source = production_loader(loader, [blobs['code'], blobs['data']])
    else:
        installed = {name: name for name in replacements}
        source = replace_loader(loader, [old[FIRMWARE + name] for name in NAMES],
                                [blobs['code'], blobs['data']])
    firmware_sha256 = {installed[name]: sha256(content) for name, content in replacements.items()}
    updated_modules = module_replacements(modules, entries) if modules is not None else {}
    replacements.update(updated_modules)
    installed.update({name: name for name in updated_modules})
    rewritten = [(installed.get(name, name), fields, replacements.get(name, content))
                 for name, fields, content in entries]
    result = encode_archive(rewritten, trailer)
    verified, _ = archive_entries(result)
    require([(name, fields[:6] + fields[7:11] + fields[12:], content)
             for name, fields, content in verified] ==
            [(name, fields[:6] + fields[7:11] + fields[12:], content)
             for name, fields, content in rewritten], 'archive roundtrip mismatch')
    report = dict(purpose='isolated RAM PON validation', profile=profile,
                  elf_sha256=manifest['elf']['sha256'],
                  features=manifest['features'], local_sram=manifest['local_sram'],
                  baseline_initramfs_sha256=sha256(archive), initramfs_sha256=sha256(result),
                  baseline_loader_sha256=sha256(loader.encode()), loader_sha256=sha256(source.encode()),
                  initramfs_entries=len(entries),
                  changed_entries=[installed[name] for name, content in replacements.items()
                                   if old[name] != content or installed[name] != name],
                  firmware_sha256=firmware_sha256,
                  modules_sha256={name: sha256(content) for name, content in updated_modules.items()})
    return source, result, report


def main():
    parser = argparse.ArgumentParser(description='Prepare an accepted PON payload for an isolated RAM build')
    parser.add_argument('--payload', type=Path, required=True)
    parser.add_argument('--acceptance', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--loader', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=('diagnostic', 'production-session'), default='diagnostic')
    parser.add_argument('--modules', type=Path, help='Flat directory of rebuilt replacements for existing rootfs modules')
    args = parser.parse_args()
    output = args.output.resolve()
    repo = Path(__file__).resolve().parents[5]
    require(not output.is_relative_to(repo), 'generated output must be outside ponwrt')
    source, archive, report = prepare(args.payload, json.loads(args.acceptance.read_text()),
                                      args.archive.read_bytes(), args.loader.read_text(), args.profile, args.modules)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'airoha_npu.c').write_text(source)
    (output / 'pon-npu.cpio').write_bytes(archive)
    (output / 'prepared.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
