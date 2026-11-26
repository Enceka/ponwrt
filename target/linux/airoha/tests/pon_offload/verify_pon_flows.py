#!/usr/bin/env python3
"""Execute production PON retirement functions with SRAM failures and retries."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import subprocess

def function(text, signature):
    start = text.index(signature)
    pos = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[pos] == '{') - (text[pos] == '}')
        pos += 1
    return text[start:pos] + '\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = args.source.resolve() / 'drivers/net/ethernet/airoha'
    ppe = (source/'airoha_ppe.c').read_text()
    header = (source/'airoha_eth.h').read_text()
    begin = header.index('enum {\n\tAIROHA_FOE_STATE_INVALID,')
    end = header.index('static_assert(sizeof(struct airoha_foe_entry) == PPE_ENTRY_SIZE);', begin)
    end += len('static_assert(sizeof(struct airoha_foe_entry) == PPE_ENTRY_SIZE);')
    types = header[begin:end]
    (out/'foe_types.inc').write_text(types)
    signatures = ('static bool airoha_ppe_foe_compare_entry(',
                  'static bool airoha_ppe_ct_pon_row_matches(',
                  'static int airoha_ppe_ct_remove_pon_flow(',
                  'int airoha_ppe_remove_egress_flows(',
                  'static bool airoha_ppe_ct_pon_flow(',
                  'static int airoha_ppe_flow_offload_destroy(')
    functions = ''.join(function(ppe, name) for name in signatures)
    template = (Path(__file__).parent/'pon_flows_test.c').read_text()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    def run(label, content, expected):
        (out/'production.inc').write_text(content)
        c = out/(label+'.c'); c.write_text(template)
        exe = out/label
        build = subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', str(c), '-o', str(exe)],
                       capture_output=True, text=True)
        (out/(label+'.build.log')).write_text(build.stdout+build.stderr)
        assert build.returncode == 0, build.stderr
        result = subprocess.run([str(exe)], capture_output=True, text=True)
        (out/(label+'.log')).write_text(result.stdout+result.stderr)
        assert (result.returncode == 0) == expected, (label, result.returncode, result.stderr)
        return result.stdout.strip()
    result = run('lifecycle', functions, True)
    mutations = {
        'omit-ingress-destroy': ('return e->pon_ingress_dev ||', 'return'),
        'omit-ingress-retirement': ('e->egress_dev == dev || e->pon_ingress_dev == dev', 'e->egress_dev == dev'),
        'ignore-write-error': ('err = airoha_ppe_foe_commit_entry(ppe, &invalid, e->hash, false);',
                               '(void)airoha_ppe_foe_commit_entry(ppe, &invalid, e->hash, false);'),
        'forget-failed-hash': ('if (!err)\n\t\te->hash = 0xffff;', 'e->hash = 0xffff;'),
        'erase-reused-row': ('airoha_ppe_ct_pon_row_matches(e, hwe)', '(airoha_ppe_ct_pon_row_matches(e, hwe), true)'),
        'duplicate-resize-node': ('list_empty(&e->gc_node)', 'true'),
        'lose-retry-cookie': ('err = airoha_ppe_ct_remove_pon_flow(eth->ppe, e);\n\t\t\tif (err)\n\t\t\t\tcontinue;',
                              'err = airoha_ppe_ct_remove_pon_flow(eth->ppe, e);'),
    }
    for label, (old, new) in mutations.items():
        assert functions.count(old) == 1, label
        run(label, functions.replace(old, new), False)
    (out/'production.inc').write_text(functions)
    report = dict(passed=True, result=result, negative_controls=list(mutations),
                  sanitizers=['address','undefined'], source=str(args.source.resolve()),
                  source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in (source/'airoha_ppe.c',source/'airoha_eth.h')})
    (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(result)
    print('PASS', len(mutations), 'runtime-caught negative controls')

if __name__ == '__main__':
    main()
