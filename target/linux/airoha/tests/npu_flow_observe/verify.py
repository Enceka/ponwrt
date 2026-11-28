#!/usr/bin/env python3
"""Bind ZZ exactly and test its IPv4 parser and original-ingress observation."""

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[4]
sys.path.insert(0, str(HERE.parent / 'npu_ingress'))
from source_binding import SourceBinding, exact_hunks, HUNK

DRIVER = Path('drivers/net/ethernet/airoha')
PATCH = '999-zz-net-airoha-observe-pon-ingress-flow-identity.patch'
HEADERS = ('airoha_npu_auth_publish.h', 'airoha_npu_flow_key.h', 'airoha_npu_flow_observe.h')
UPSTREAM = ('airoha_eth.h', 'airoha_eth.c', 'airoha_ppe.c')
FUNCTIONS = {
    'airoha_ppe.c': ('airoha_ppe_foe_get_entry_hash', 'airoha_ppe_foe_compare_entry',
                     'airoha_ppe_ct_pon_dev_ready', 'airoha_ppe_ct_remove_pon_flow',
                     'airoha_ppe_pon_observe_frame'),
    'airoha_eth.c': ('airoha_qdma_pon_learnable', 'airoha_qdma_observe_pon_skb'),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def block(text, pattern, semicolon=False):
    matches = list(re.finditer(pattern, text, re.M))
    assert len(matches) == 1, pattern
    start = matches[0].start()
    opening = text.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    if semicolon:
        assert text[end] == ';'
        end += 1
    return text[start:end] + '\n'


def reverse_section(section):
    lines = section.splitlines(True)
    reversed_lines = [lines[0].replace('--- a/', '--- b/', 1),
                      lines[1].replace('+++ b/', '+++ a/', 1)]
    for line in lines[2:]:
        match = HUNK.match(line)
        if match:
            line = '@@ -' + match[3] + ',' + (match[4] or '1') + ' +' + match[1] + ',' + (match[2] or '1') + ' @@\n'
        elif line.startswith('+'):
            line = '-' + line[1:]
        elif line.startswith('-'):
            line = '+' + line[1:]
        reversed_lines.append(line)
    return ''.join(reversed_lines)


def generated_abi(text, regs):
    names = ('airoha_foe_mac_info_common', 'airoha_foe_mac_info', 'airoha_foe_bridge',
             'airoha_foe_l2b', 'airoha_foe_ipv4_tuple', 'airoha_foe_ipv4',
             'airoha_foe_ipv4_dslite', 'airoha_foe_ipv6', 'airoha_foe_entry')
    pieces = []
    for marker in ('AIROHA_FOE_STATE_INVALID', 'PPE_PKT_TYPE_IPV4_HNAPT', 'AIROHA_DEV_F_WAN', 'FLOW_TYPE_L4'):
        pieces.append(block(text, r'^enum[^\n{]*\{(?=\s*' + marker + r'\b)', True))
    for line in (text + '\n' + regs).splitlines():
        if re.match(r'#define (?:AIROHA_FOE_IB1_BIND_(?:UDP|STATE|PACKET_TYPE)\b|AIROHA_PON_QDMA_\w+|QDMA_ETH_RXMSG_\w+|PPE_ENTRY_SIZE\b)', line):
            pieces.append(line + '\n')
    pieces += [block(text, r'^struct ' + name + r'\s*(?=\{)', True) for name in names]
    pieces += [line + '\n' for line in text.splitlines()
               if line.startswith('static_assert(')]
    return '\n'.join(pieces)


def mutations():
    parser = 'airoha_npu_flow_observe.h'
    production = 'production.inc'
    return [
        ('parser-service-truncation', parser, 'service > 0xffffu', '0'),
        ('parser-wrong-service', parser, 'parsed.service = service;', 'parsed.service = service ^ 1u;'),
        ('parser-fragment-acceptance', parser, '& 0xbfffu', '& 0x8000u'),
        ('parser-lost-inner-tag', parser, 'parsed.vlan[parsed.vlan_count++]', 'parsed.vlan[0 * parsed.vlan_count++]'),
        ('parser-nat-port-order', parser, 'parsed.source_port = airoha_npu_frame_be16(frame + transport);',
         'parsed.source_port = airoha_npu_frame_be16(frame + transport + 2);'),
        ('parser-failure-output-write', parser, 'if (!source_any || !destination_any)',
         '*identity = parsed;\n\tif (!source_any || !destination_any)'),
        ('observe-nat-instead-of-original', production, 'tuple.ipv4.orig_tuple.src_ip = identity.source_ip;',
         'tuple.ipv4.new_tuple.src_ip = identity.source_ip;'),
        ('observe-wrong-cookie-device', production, 'entry->pon_ingress_dev != dev ||', 'false ||'),
        ('observe-bridge-accepted', production, 'entry->ct_bridge ||', 'false ||'),
        ('observe-wrong-type-accepted', production, 'entry->type != FLOW_TYPE_L4 ||', 'false ||'),
        ('observe-sticky-conflict-lost', production, 'entry->pon_ingress_conflict ||', 'false ||'),
        ('observe-service-conflict-lost', production, 'entry->pon_ingress_service != service ||', 'false ||'),
        ('observe-key-conflict-lost', production, 'memcmp(entry->pon_ingress_key, rule.raw + 9,',
         '0 * memcmp(entry->pon_ingress_key, rule.raw + 9,'),
        ('observe-conflict-still-seen', production, 'entry->pon_ingress_seen = false;', 'entry->pon_ingress_seen = true;'),
        ('observe-stopping-ignored', production, 'ppe->ct_stopping ||', 'false ||'),
        ('observe-blocked-ignored', production, '!READ_ONCE(dev->pon_update_blocked) &&', 'true &&'),
        ('qdma-wrong-dma-accepted', production, 'rx_qdma != &dev->eth->qdma[1] ||', '((void)rx_qdma, false) ||'),
        ('qdma-nonlinear-accepted', production, 'skb_is_nonlinear(skb) ||', 'false ||'),
        ('qdma-vlan-offload-accepted', production, 'skb_vlan_tag_present(skb) ||', 'false ||'),
        ('qdma-missing-ethernet-header-length', production, 'skb->len + ETH_HLEN, service', 'skb->len, service'),
        ('qdma-gem-mapping-ignored', production, 'FIELD_GET(AIROHA_PON_QDMA_GEM_MASK, tag) == gem', '((void)gem, true)'),
        ('qdma-error-descriptor-accepted', production, 'QDMA_ETH_RXMSG_OAM_MASK | QDMA_ETH_RXMSG_CRC_ERR_MASK |', '0 |'),
        ('withdraw-keeps-seen', production, 'e->pon_ingress_seen = false;', 'e->pon_ingress_seen = true;'),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=REPOSITORY.parent / 'pon-npu-diag-20261127/production-ingress/source')
    parser.add_argument('--firmware', type=Path, default=REPOSITORY.parent.parent / 'an7581-npu-firmware')
    parser.add_argument('--output', type=Path, default=REPOSITORY.parent / 'pon-npu-diag-20261127/production-ingress' / datetime.now().strftime('observe-%Y%m%d-%H%M%S'))
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    args = parser.parse_args()
    source, firmware, output = args.source.resolve(), args.firmware.resolve(), args.output.resolve()
    if output.is_relative_to(REPOSITORY) or any(output.is_relative_to(root) or root.is_relative_to(output) for root in (source, firmware)):
        parser.error('output must be a new directory outside the repository and input trees')
    paths = [source / DRIVER / name for name in (*HEADERS, *UPSTREAM, 'airoha_regs.h', 'npu_auth_mailbox_abi.h')]
    paths += [firmware / path for path in ('src/ingress_auth.c', 'include/npu_ingress_auth.h', 'include/npu_auth_mailbox_abi.h')]
    paths += sorted(path for path in HERE.iterdir() if path.is_file())
    paths += [HERE.parent / 'npu_ingress/source_binding.py']
    inputs = {path: path.read_bytes() for path in paths}
    output.mkdir(parents=True, exist_ok=False)
    temporary = output / 'tmp'
    temporary.mkdir()
    environment = dict(os.environ, TMPDIR=str(temporary), ASAN_OPTIONS='halt_on_error=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    commands = []

    def run(command, log, cwd=None, required=True):
        command = list(map(str, command))
        commands.append(command)
        result = subprocess.run(command, cwd=cwd, env=environment, text=True, capture_output=True, timeout=120)
        log.write_text(result.stdout + result.stderr)
        if required and result.returncode:
            raise RuntimeError(str(log) + '\n' + result.stdout + result.stderr)
        return result

    binding = SourceBinding(REPOSITORY / 'target/linux/airoha/patches-6.18', output, PATCH)
    binding.bind(source / DRIVER, HEADERS)
    sections = list(binding.sections(binding.snapshot[PATCH], UPSTREAM))
    assert {name for name, added, section in sections} == set(UPSTREAM)
    replay = output / 'replay'
    (replay / DRIVER).mkdir(parents=True)
    for name in UPSTREAM:
        (replay / DRIVER / name).write_bytes(inputs[source / DRIVER / name])
    for name, added, section in sections:
        assert not added
        exact_hunks(inputs[source / DRIVER / name], reverse_section(section))
    replay_patch = output / 'zz-upstream.patch'
    replay_patch.write_text(''.join(section for name, added, section in sections))
    for reverse in (True, False):
        if not reverse:
            for name, added, section in sections:
                exact_hunks((replay / DRIVER / name).read_bytes(), section)
        result = run(['patch', '--batch', '--fuzz=0', '-R' if reverse else '--forward', '-p1', '-i', replay_patch],
                     output / ('reverse.log' if reverse else 'replay.log'), cwd=replay)
        assert not re.search(r'fuzz|offset|FAILED|reversed', result.stdout + result.stderr, re.I)
    for name in UPSTREAM:
        assert (replay / DRIVER / name).read_bytes() == inputs[source / DRIVER / name]
    print('PASS SourceBinding through ZZ and exact upstream reverse/replay', flush=True)
    extracted = []
    function_hashes = {}
    for name, functions in FUNCTIONS.items():
        text = inputs[source / DRIVER / name].decode()
        for function in functions:
            body = block(text, r'^(?:static )?(?:bool|int|u32|void) ' + function + r'\(')
            extracted.append(body)
            function_hashes[function] = digest(body.encode())
    production = '\n'.join(extracted)
    abi = generated_abi(inputs[source / DRIVER / 'airoha_eth.h'].decode(), inputs[source / DRIVER / 'airoha_regs.h'].decode())
    eth = inputs[source / DRIVER / 'airoha_eth.c'].decode()
    call = 'airoha_qdma_observe_pon_skb(dev, q->qdma, q->skb, msg0);'
    assert eth.count(call) == 1
    position = eth.index(call)
    assert position < eth.index('airoha_qdma_learn_skb(dev, q->qdma, q->skb, hash, msg0);', position)
    assert position < eth.index('napi_gro_receive(', position)
    assert inputs[source / DRIVER / 'npu_auth_mailbox_abi.h'] == inputs[firmware / 'include/npu_auth_mailbox_abi.h']
    compiler = shlex.split(args.cc)
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wshadow', '-Wstrict-prototypes',
             '-fno-omit-frame-pointer', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-DNPU_CT_FE_PON_AUTH=1']
    version = run(compiler + ['--version'], output / 'compiler.log').stdout
    firmware_object = output / 'firmware.o'
    run(compiler + flags + ['-I', firmware / 'include', '-c', firmware / 'src/ingress_auth.c', '-o', firmware_object], output / 'firmware-build.log')
    contents = {name: inputs[source / DRIVER / name].decode() for name in HEADERS}
    contents['npu_auth_mailbox_abi.h'] = inputs[source / DRIVER / 'npu_auth_mailbox_abi.h'].decode()
    contents.update({'production.inc': production, 'production_abi.h': abi})

    def build_run(label, test, changed=None):
        directory = output / label
        directory.mkdir(exist_ok=True)
        for name, data in (contents | (changed or {})).items():
            (directory / name).write_text(data)
        binary = directory / test
        command = compiler + flags + ['-I', directory, '-I', HERE, '-I', firmware / 'include', HERE / (test + '.c')]
        if test == 'parser_test':
            command.append(firmware_object)
        run(command + ['-o', binary], directory / (test + '-build.log'))
        return run([binary], directory / (test + '-run.log'), required=False)

    summaries = {}
    for test in ('parser_test', 'observe_test'):
        result = build_run('baseline', test)
        assert not result.returncode, result.stdout + result.stderr
        summaries[test] = json.loads(result.stdout)
        assert summaries[test]['passed']
        print('PASS ' + test + ' ' + result.stdout.strip(), flush=True)
    caught = []
    for name, target, before, after in mutations():
        assert contents[target].count(before) == 1, name
        result = build_run(name, 'parser_test' if target.endswith('.h') else 'observe_test',
                           {target: contents[target].replace(before, after, 1)})
        assert result.returncode == 1 and 'CHECK failed [' in result.stderr and not re.search(r'Sanitizer|runtime error:', result.stderr), (name, result.stdout, result.stderr)
        caught.append({'name': name, 'assertion': result.stderr.strip()})
        print('PASS runtime mutant ' + name, flush=True)
    binding.verify_unchanged()
    assert (binding.patches / PATCH).read_bytes() == binding.snapshot[PATCH]
    for path, data in inputs.items():
        assert path.read_bytes() == data, 'input changed: ' + str(path)
    report = {'passed': True, 'baseline': summaries, 'source_binding': binding.report(),
              'upstream_zz_reverse_replay': {'passed': True, 'files': list(UPSTREAM), 'fuzz': 0, 'offset': 0},
              'patch_sha256': digest(binding.snapshot[PATCH]), 'functions_sha256': function_hashes,
              'inputs_sha256': {str(path): digest(data) for path, data in inputs.items()},
              'sanitizers': ['address', 'undefined'], 'mutants': caught, 'compiler': version, 'commands': commands}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS report: ' + str(output / 'report.json'), flush=True)


if __name__ == '__main__':
    main()
