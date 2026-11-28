#!/usr/bin/env python3
"""Check a PON full-image recovery/sysupgrade pair before board validation."""
import argparse
import importlib.util
import json
import lzma
from pathlib import Path
import posixpath
import shlex
import stat
import struct
import subprocess
import sys
import tempfile
import zlib

from prepare_npu_ram import archive_entries, require, sha256
from verify_pon_payload import PACKAGE, load_identity


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


def walk(node):
    yield node
    for child in node.children:
        yield from walk(child)


def inspect_fit(path, image, resident, config, recovery):
    content = path.read_bytes()
    fit = image.Fit(content)
    image.verify_fit_hashes(fit)
    images = fit.root.child('images')
    configurations = fit.root.child('configurations')
    selected = configurations.child(image.text(configurations.properties['default']))
    require(not {'firmware', 'ramdisk'} & selected.properties.keys(),
            'unexpected auxiliary FIT load target')
    filesystem = [node for node in images.children if node.properties.get('type') == b'filesystem\0']
    require(len(filesystem) == (0 if recovery else 1), 'wrong FIT filesystem count')
    if not recovery:
        require(not {'load', 'entry'} & filesystem[0].properties.keys(),
                'filesystem must not have load/entry')
    if 'loadables' in selected.properties:
        targets = selected.properties['loadables']
        require(not recovery and targets.endswith(b'\0') and targets.count(b'\0') == 1 and
                images.child(image.text(targets)) is filesystem[0],
                'unexpected auxiliary FIT load target')
    kernel = images.child(image.text(selected.properties['kernel']))
    compressed = fit.image_data(kernel)[0]
    compression = image.text(kernel.properties['compression'])
    require(compression in ('lzma', 'gzip'), 'unexpected kernel compression')
    raw = lzma.decompress(compressed) if compression == 'lzma' else zlib.decompress(compressed, 31)
    require(raw[56:60] == b'ARMd', 'expected ARM64 kernel')
    require(image.integer(kernel.properties['load']) ==
            image.integer(kernel.properties['entry']) == 0x8a000000, 'wrong kernel load/entry')
    fdt = images.child(image.text(selected.properties['fdt']))
    dtb = fit.image_data(fdt)[0]
    tree = image.Fit(dtb).root
    audit = resident.Audit()
    resident.check_config(audit, config)
    resident.check_tree(audit, resident.FlatTree(dtb), False, 'pon-full')
    require(all(check['ok'] for check in audit.checks),
            'resident preflight: ' + json.dumps([check for check in audit.checks if not check['ok']]))
    require(tree.properties.get('variant') == b'pon-full\0', 'wrong network variant')
    symbols = tree.child('__symbols__').properties

    def device(label):
        node = tree
        for part in image.text(symbols[label]).strip('/').split('/'):
            node = node.child(part)
        return node.properties

    for label in ('pnand', 'pnand_ecc', 'xpon_mac', 'hg5585f_bosa', 'gdm2', 'pon_pcs'):
        require(device(label).get('status', b'okay\0') in (b'okay\0', b'ok\0'),
                'disabled persistent device: ' + label)
    for label in ('xpon_mac', 'hg5585f_bosa'):
        require('nvmem-cells' in device(label), 'missing factory calibration: ' + label)
    require(device('xpon_mac')['data-path'] == device('gdm2')['phandle'], 'wrong PON data path')
    require('airoha,connac2-pon-er-diagnostic' not in device('eth'), 'diagnostic mode in full image')
    nodes = list(walk(tree))
    require(not any('mediatek,eeprom-data' in node.properties for node in nodes), 'inline radio calibration')
    partition_nodes = [node for node in nodes if node.properties.get('label') in (b'bl2\0', b'ubi\0')]
    require(len(partition_nodes) == 2, 'duplicate or missing flash partition')
    partitions = {image.text(node.properties['label']): struct.unpack('>II', node.properties['reg'])
                  for node in partition_nodes}
    require(partitions == {'bl2': (0, 131072), 'ubi': (131072, 0)}, 'changed flash partition layout')
    for volume in (b'fit\0', b'factory\0'):
        require(any(node.properties.get('volname') == volume for node in nodes), 'missing UBI volume')
    ranges = [(0x8a000000, 0x8a000000 + max(len(raw), struct.unpack_from('<Q', raw, 16)[0])),
              (0x90000000, 0x90000000 + len(content))]
    for region in tree.child('reserved-memory').children:
        address, size = struct.unpack('>QQ', region.properties['reg'])
        ranges.append((address, address + size))
    ranges.sort()
    require(all(0x80000000 <= start < end <= 0xa0000000 for start, end in ranges) and
            all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:])), 'RAM overlap')
    rootfs = None if recovery else fit.image_data(filesystem[0])[0]
    require(rootfs is None or rootfs[:4] == b'hsqs', 'expected squashfs')
    return raw, dtb, rootfs, {'sha256': sha256(content), 'bytes': len(content),
                             'resident_checks': audit.checks, 'memory_ranges': ranges}


def verify(args):
    image = module('pon_image_helper', args.image_helper)
    resident_path = Path(__file__).resolve().parent.parent / 'npu_resident_config/verify.py'
    resident = module('pon_image_resident', resident_path)
    config = args.config.read_text()
    recovery, recovery_dt, _, recovery_report = inspect_fit(args.recovery, image, resident, config, True)
    kernel, sysupgrade_dt, rootfs, sysupgrade_report = inspect_fit(args.sysupgrade, image, resident, config, False)
    require(recovery_dt == sysupgrade_dt, 'recovery/sysupgrade DTB mismatch')
    archive = args.initramfs_archive.read_bytes()
    require(recovery.count(archive) == 1, 'recovery does not embed the supplied initramfs')
    entries, _ = archive_entries(archive)
    files = {posixpath.normpath(name): payload for name, _, payload in entries}
    modes = {posixpath.normpath(name): fields[1] for name, fields, _ in entries}
    require(len(files) == len(entries), 'duplicate normalized initramfs names')
    identity = load_identity()
    pins = {}
    for manifest in ('SHA256SUMS', 'SHA256SUMS.pon-full'):
        for line in (PACKAGE / manifest).read_text().splitlines():
            digest, name = line.split()
            pins['lib/firmware/airoha/hg5585f-ct/' + name] = digest
    for name, digest in pins.items():
        require(name in files and sha256(files[name]) == digest, 'firmware pin mismatch: ' + name)
    for kind in ('code', 'data'):
        digest = bytes.fromhex(identity['manifest'][kind]['sha256'])
        require(digest in recovery and digest in kernel, 'missing production loader digest: ' + kind)
    require(not any(name.startswith(('lib/firmware/airoha/hg5585f-ct/npu_rebuilt_',
                                     'lib/firmware/airoha/hg5585f-ct/npu_full_test_')) for name in files),
            'conflicting firmware package in image')
    modules = sorted(name for name in files if name.endswith('.ko'))
    for name in ('airoha-xpon', 'mt7915e', 'ct_wed_platform', 'ct_wed_guard_v2', 'nf_flow_table'):
        require(any(path.endswith('/' + name + '.ko') for path in modules), 'missing module: ' + name)
    board_network = 'etc/board.d/02_network'
    board_source = PACKAGE.parents[2] / 'target/linux/airoha/an7581/base-files' / board_network
    require(files.get('etc/config/network') == b'', 'nonempty seed overrides board port roles')
    require(files.get(board_network) == board_source.read_bytes(), 'wrong network generator')
    metadata = 'etc/hg5585f-ct-build.json'
    require(json.loads(files[metadata]) == json.loads(args.source_manifest.read_bytes()), 'stale build provenance')
    selected = modules + list(pins) + [board_network, metadata, 'etc/config/network',
                                     'etc/config/wireless', 'etc/dropbear/authorized_keys',
                                     'etc/modules.d/19-mt7916-ct-wed-prepare', 'etc/modules.d/mt7915e']
    for name in selected:
        require(name in files and stat.S_ISREG(modes[name]), 'missing or non-regular initramfs file: ' + name)
    with tempfile.TemporaryDirectory(prefix='pon-image-', dir=args.output.parent) as temporary:
        root = Path(temporary)
        squashfs = root / 'image.squashfs'
        squashfs.write_bytes(rootfs)
        result = subprocess.run(shlex.split(args.unsquashfs) +
                                ['-no-progress', '-d', str(root / 'root'), str(squashfs),
                                 'lib/modules', 'lib/firmware/airoha/hg5585f-ct', *selected],
                                capture_output=True, text=True, timeout=120)
        require(result.returncode == 0, 'unsquashfs failed: ' + result.stderr)
        extracted = root / 'root'
        rootfs_modules = sorted(str(path.relative_to(extracted)) for path in
                                (extracted / 'lib/modules').rglob('*.ko'))
        require(rootfs_modules == modules, 'rootfs module inventory mismatch')
        firmware_directory = 'lib/firmware/airoha/hg5585f-ct/'
        rootfs_firmware = sorted(str(path.relative_to(extracted)) for path in
                                 (extracted / firmware_directory).rglob('*') if not path.is_dir())
        archive_firmware = sorted(name for name in files if name.startswith(firmware_directory)
                                  and not stat.S_ISDIR(modes[name]))
        require(rootfs_firmware == archive_firmware, 'rootfs firmware inventory mismatch')
        for name in selected:
            path = extracted / name
            require(path.exists() and stat.S_ISREG(path.lstat().st_mode),
                    'missing or non-regular rootfs file: ' + name)
            require(path.read_bytes() == files[name], 'rootfs mismatch: ' + name)
    return {'passed': True, 'profile': 'pon-full', 'recovery': recovery_report,
            'sysupgrade': sysupgrade_report, 'dtb_sha256': sha256(recovery_dt),
            'compared_files': len(selected), 'modules': len(modules), 'firmware': pins,
            'source_manifest_sha256': sha256(args.source_manifest.read_bytes()),
            'image_helper_sha256': sha256(args.image_helper.read_bytes()),
            'config_sha256': sha256(args.config.read_bytes()), 'board_tested': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('recovery', 'sysupgrade', 'initramfs-archive', 'config', 'source-manifest', 'image-helper', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--unsquashfs', required=True, help='executable and optional prefix arguments, shell quoted')
    args = parser.parse_args()
    require(not args.output.resolve().is_relative_to(PACKAGE.parents[2]), 'output must be outside ponwrt')
    require(not args.output.exists(), 'output must be new')
    result = verify(args)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
