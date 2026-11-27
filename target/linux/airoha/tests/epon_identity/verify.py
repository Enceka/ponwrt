import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PATCHES = ROOT.parents[1] / 'patches-6.18'
PATCH = PATCHES / '999-zb-net-airoha-publish-epon-registration-identity.patch'
DRIVER = Path('drivers/net/ethernet/airoha')
PUBLIC = Path('include/linux/airoha-eth.h')


def function(text, name):
    match = re.search(r'(?m)^(?:static )?(?:int|void|bool|u32)\s*\n?' +
                      re.escape(name) + r'\([^;]*?\)\n\{', text)
    if not match:
        raise ValueError('Missing function: ' + name)
    return text[match.start():text.index('\n}', match.end()) + 2] + '\n'


def structure(text, name):
    match = re.search(r'(?ms)^struct ' + re.escape(name) + r' \{.*?^};', text)
    if not match:
        raise ValueError('Missing structure: ' + name)
    return match.group() + '\n'


def apply(snapshot, patch):
    result = subprocess.run(['patch', '-p1', '--batch', '--fuzz=0'], cwd=snapshot,
                            input=patch, text=True, capture_output=True)
    print(result.stdout, end='')
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)


def header_patch(path):
    blocks = re.split(r'(?m)(?=^--- (?:a/|/dev/null))', path.read_text())
    return ''.join(block for block in blocks if '\n+++ b/' + str(PUBLIC) + '\n' in block)


def compile_test(source, output, includes, sanitize=False):
    command = ['cc', '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-function', '-Wno-macro-redefined']
    if sanitize:
        command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    command += ['-I' + str(path) for path in includes]
    subprocess.run(command + [str(source), '-o', str(output)], check=True)


def verify_metadata(source, output, sanitize):
    ppe = (source / 'airoha_ppe.c').read_text()
    header = (source / 'airoha_eth.h').read_text()
    functions = ['airoha_ppe_foe_set_bridge_addrs', 'airoha_ppe_pon_lookup_tag',
                 'airoha_ppe_pon_select_flow', 'airoha_ppe_foe_entry_prepare']
    (output / 'production_functions.inc').write_text(''.join(function(ppe, name) for name in functions))
    start = header.rfind('enum {', 0, header.index('AIROHA_FOE_STATE_INVALID'))
    types = header[start:header.index('struct airoha_foe_stats {', start)]
    start = header.rfind('enum {', 0, header.index('FE_PSE_PORT_CDM1'))
    types += header[start:header.index('};', start) + 2] + '\n'
    start = header.index('enum airoha_dev_flags {')
    types += header[start:header.index('struct airoha_pon_flow_entry {', start)]
    types += ''.join(structure(header, name) for name in
                     ['airoha_flow_data', 'airoha_pon_flow_entry', 'airoha_pon_flow_table'])
    (output / 'production_types.inc').write_text(types)
    existing = ROOT.parent / 'pon_offload'
    executable = output / ('ppe-sanitized' if sanitize else 'ppe')
    compile_test(existing / 'metadata_runner.c', executable, [output, existing], sanitize)
    cases, inputs = [], []
    identities = [0, 0xffff] + [1 << bit for bit in range(16)]
    for channel in range(32):
        for kind in (0, 5):
            for encapsulation in range(4):
                vlans = (0, 1, 2, 0)[encapsulation]
                pppoe = int(encapsulation == 3)
                for llid in identities:
                    tag = 0xc0000000 | channel << 16 | llid
                    cases.append((channel, kind, encapsulation, tag))
                    inputs.append(f'{kind} {vlans} 100 200 {pppoe} 17185 46 6 {tag} 0 0')
    result = subprocess.run([str(executable)], input='\n'.join(inputs) + '\n',
                            text=True, capture_output=True, check=True)
    lines = result.stdout.splitlines()
    if len(lines) != len(cases):
        raise AssertionError('Incomplete PPE output')
    baseline = {}
    for case, line in zip(cases, lines):
        channel, kind, encapsulation, tag = case
        fields = line.split()
        assert [int(value) for value in fields[:4]] == [0, tag, 0, 1], case
        raw = bytes.fromhex(fields[-1])
        key = channel, kind, encapsulation
        assert raw == baseline.setdefault(key, raw), ('LLID changed hardware encoding', case)
        ib2, layer2 = (44, 48) if kind == 5 else (16, 44)
        assert struct.unpack_from('<I', raw, 40)[0] >> 11 & 31 == channel, case
        assert struct.unpack_from('<I', raw, ib2)[0] & 31 == channel, case
        assert struct.unpack_from('<H', raw, layer2 + 2)[0] == 0, case
    print(f'PASS {len(cases)} PPE identity/encoding vectors ({"sanitized" if sanitize else "plain"})')
    return len(cases)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    snapshot = output / 'source'
    source = args.source.resolve() / DRIVER
    destination = snapshot / DRIVER
    destination.mkdir(parents=True)
    names = ['airoha_eth.c', 'airoha_eth.h', 'airoha_regs.h', 'airoha_ppe.c', 'airoha_pon_transaction.h']
    hashes = {}
    for name in names:
        shutil.copyfile(source / name, destination / name)
        hashes[name] = hashlib.sha256((source / name).read_bytes()).hexdigest()
    public = snapshot / PUBLIC
    public.parent.mkdir(parents=True)
    if (args.source / PUBLIC).is_file():
        shutil.copyfile(args.source / PUBLIC, public)
    else:
        for pattern in ('922-*', '959-*'):
            candidates = list(PATCHES.glob(pattern))
            if len(candidates) != 1:
                raise ValueError('Ambiguous header patch: ' + pattern)
            apply(snapshot, header_patch(candidates[0]))
    apply(snapshot, PATCH.read_text())
    eth = (destination / 'airoha_eth.c').read_text()
    header = (destination / 'airoha_eth.h').read_text()
    transaction = (destination / 'airoha_pon_transaction.h').read_text()
    registers = (destination / 'airoha_regs.h').read_text()
    bodies = function(transaction, 'airoha_pon_table_channels')
    bodies += function(eth, 'airoha_eth_pon_commit_config')
    bodies += function(eth, 'airoha_eth_pon_configure_epon')
    (output / 'production.h').write_text(bodies)
    declaration = re.search(r'(?m)^int airoha_eth_pon_configure_epon\([^;]+;', public.read_text()).group()
    (output / 'api.h').write_text(declaration + '\n')
    masks = re.findall(r'(?m)^#define AIROHA_PON_QDMA_\w+[^\n]+', header)
    for name in ('QDMA_ETH_TXMSG_CHAN_MASK', 'QDMA_ETH_TXMSG_QUEUE_MASK', 'QDMA_ETH_TXMSG_SP_TAG_MASK'):
        masks.append(re.search(r'(?m)^#define ' + name + r'\s+[^\n]+', registers).group())
    (output / 'masks.h').write_text('\n'.join(masks) + '\n')
    start = eth.index('} else if (pon) {', eth.index('static netdev_tx_t airoha_dev_xmit'))
    end = eth.index('\n\t} else {', start)
    tx = eth[start + len('} else if (pon) {'):end]
    (output / 'tx.h').write_text(
        'static int encode_tx(struct airoha_gdm_dev *dev, unsigned int qid, u32 *message, u8 *nbq)\n{\n'
        'u32 pon_tag = dev->pon_qdma_tag, msg0 = 0; u8 nboq = 0; struct sk_buff *skb = NULL;\n' +
        tx + '\n*message = msg0; *nbq = nboq; return 0;\nerror: return -ENOENT;\n}\n')
    results = []
    for sanitize in (False, True):
        executable = output / ('identity-sanitized' if sanitize else 'identity')
        compile_test(ROOT / 'identity_test.c', executable, [output], sanitize)
        result = subprocess.run([str(executable)], text=True, capture_output=True, check=True)
        print(result.stdout, end='')
        results.append(dict(sanitized=sanitize, identity=result.stdout.strip(),
                            ppe_vectors=verify_metadata(destination, output, sanitize)))
    mutations = {
        'missing-llid': ('AIROHA_PON_QDMA_LLID_MASK, llid', 'AIROHA_PON_QDMA_LLID_MASK, llid & 0'),
        'truncated-llid': ('AIROHA_PON_QDMA_LLID_MASK, llid', 'AIROHA_PON_QDMA_LLID_MASK, llid & 0x7fff'),
        'invalid-keeps-llid': ('u32 value = 0;', 'u32 value = llid;'),
    }
    try:
        for name, (before, after) in mutations.items():
            assert bodies.count(before) == 1, name
            (output / 'production.h').write_text(bodies.replace(before, after))
            executable = output / name
            compile_test(ROOT / 'identity_test.c', executable, [output])
            result = subprocess.run([str(executable)], text=True, capture_output=True)
            assert result.returncode == 1 and 'FAIL line' in result.stderr, (name, result)
            print('PASS rejected ' + name)
    finally:
        (output / 'production.h').write_text(bodies)
    checks = output / 'api-check'
    (checks / 'linux').mkdir(parents=True)
    (checks / 'linux/types.h').write_text('#include <stdint.h>\n#include <stdbool.h>\n'
        'typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;\n')
    command = ['cc', '-std=gnu11', '-Werror', '-fsyntax-only', '-x', 'c',
               '-I' + str(checks), '-I' + str(snapshot / 'include'), '-']
    for legacy in (False, True):
        call = 'netdev, 0, true' if legacy else 'netdev, 31, 0xffff, true'
        code = '#include <linux/airoha-eth.h>\nint probe(struct net_device *netdev) { return airoha_eth_pon_configure_epon(' + call + '); }\n'
        result = subprocess.run(command, input=code, text=True, capture_output=True)
        assert (result.returncode != 0) == legacy, result.stderr
        if legacy:
            assert 'too few arguments' in result.stderr, result.stderr
    print('PASS full public header: four arguments accepted, legacy three arguments rejected')
    report = dict(passed=True, source=str(args.source.resolve()), source_sha256=hashes,
                  patch_sha256=hashlib.sha256(PATCH.read_bytes()).hexdigest(),
                  results=results, mutations=list(mutations), public_header_checked=True)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
