#!/usr/bin/env python3
"""Extract production PON classifier/FOE code, execute it, compare stock ARM64.

No device I/O. The stock oracle executes real, hash-checked function binaries;
Linux readiness/admission and optical operation are separate test stages.
"""
import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
from stock_oracle import StockOracle

ROOT = Path(__file__).resolve().parent
VALID, EPON, ANY, CORE_MASK = 1 << 31, 1 << 30, 0xffff, 0xc01fffff


def function(text, name):
    pos = text.index(name + '(')
    start = text.rfind('\nstatic ', 0, pos) + 1
    assert start > 0, name
    opening = text.index('{', pos)
    depth, end = 1, opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'


def structure(text, name):
    pos = text.index('struct ' + name + ' {')
    opening = text.index('{', pos)
    depth, end = 1, opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    assert text[end] == ';'
    return text[pos:end+1] + '\n'


def extract(source, build):
    text = (source / 'airoha_ppe.c').read_text()
    header = (source / 'airoha_eth.h').read_text()
    names = ['airoha_ppe_foe_set_bridge_addrs', 'airoha_ppe_pon_lookup_tag',
             'airoha_ppe_pon_select_flow', 'airoha_ppe_foe_entry_prepare']
    functions = '\n'.join(function(text, n) for n in names)
    (build / 'production_functions.inc').write_text(functions)
    start = header.rfind('enum {', 0, header.index('AIROHA_FOE_STATE_INVALID'))
    end = header.index('struct airoha_foe_stats {', start)
    types = header[start:end]
    start = header.rfind('enum {', 0, header.index('FE_PSE_PORT_CDM1'))
    end = header.index('};', start) + 2
    types += header[start:end] + '\n'
    start = header.index('enum airoha_dev_flags {')
    end = header.index('struct airoha_pon_flow_entry {', start)
    types += header[start:end]
    types += ''.join(structure(header, n) for n in ['airoha_flow_data', 'airoha_pon_flow_entry', 'airoha_pon_flow_table'])
    (build / 'production_types.inc').write_text(types)
    return dict(functions=names, sha256={n: hashlib.sha256((source / n).read_bytes()).hexdigest()
                                       for n in ['airoha_ppe.c', 'airoha_eth.h']},
                extracted_sha256=hashlib.sha256(functions.encode()).hexdigest())


def entry(vid, mask, gem, tcont, valid=True):
    return (vid, mask, (VALID if valid else 0) | (mask << 21) | (tcont << 16) | gem)


def vectors():
    result = []
    def add(label, entries=(), *, kind=0, vlans=(), sid=0, ds=0, proto=6, fixed=0, present=True):
        result.append(dict(label=label, entries=list(entries), kind=kind, vlans=list(vlans),
                           sid=sid, ds=ds, proto=proto, fixed=fixed, present=present))
    for gem, tc, kind, encap in itertools.product([0, 1, 255, 1023, 4095, 4096, 65534, 65535], range(32), [0, 5], range(4)):
        vlans = [100] if encap == 1 else [100, 200] if encap == 2 else []
        sid = 0x4321 if encap == 3 else 0
        add('bearer', [entry(vlans[-1] if vlans else ANY, 255, gem, tc)], kind=kind, vlans=vlans, sid=sid)
    for kind in [0, 1, 2, 3, 4, 5, 7]:
        for sid in [0, 1, 65535]:
            add('layout', [entry(ANY, 255, 0x1234, 29)], kind=kind, sid=sid)
    for ds, proto in itertools.product([0, 1, 2, 3, 0x2e, 0xfc, 0xff], [6, 17]):
        add('dscp-ecn', [entry(ANY, 255, 100, 23)], ds=ds, proto=proto)
    add('null-table', present=False)
    add('empty-table')
    add('vid-miss', [entry(200, 255, 1, 1)], vlans=[100])
    add('untagged-pbit0-miss', [entry(ANY, 254, 1, 1)])
    add('invalid-tag', [entry(ANY, 255, 1, 1, False)])
    for pbit in range(8):
        add('pcp-missing', [entry(100, 255 ^ (1 << pbit), 11, 3)], vlans=[100])
        add('pcp-gem-split', [entry(100, 1 << pbit, 12, 3), entry(100, 255 ^ (1 << pbit), 11, 3)], vlans=[100])
        add('pcp-tcont-split', [entry(100, 1 << pbit, 11, 4), entry(100, 255 ^ (1 << pbit), 11, 3)], vlans=[100])
        add('pcp-same-bearer', [entry(100, 1 << pbit, 11, 3), entry(100, 255 ^ (1 << pbit), 11, 3)], vlans=[100])
        add('lookup-exact-after-any', [entry(ANY, 255, 31, 2), entry(100, 1 << pbit, 41, 5)], vlans=[100])
    for order in [False, True]:
        entries = [entry(ANY, 255, 17, 4), entry(100, 255, 33, 8)]
        if order: entries.reverse()
        add('exact-before-fallback', entries, vlans=[100])
        add('fallback', entries, vlans=[200])
        add('double-vlan-outer', entries, vlans=[200, 100])
    for tc in range(32):
        add('epon-fixed-llid', fixed=VALID | EPON | (tc << 16), present=False)
    # Adjacent vectors model table replacement, deletion and re-addition;
    # live FOE revocation is exercised in the separate lifecycle harness.
    for gem, tc, present in [(11, 2, True), (22, 31, True), (0, 0, False), (33, 7, True)]:
        add('mapping-generation-input', [entry(100, 255, gem, tc)] if present else [], vlans=[100], present=present)
    return result


def expectation(v):
    vid = v['vlans'][-1] if v['vlans'] else ANY
    def lookup(pbit):
        candidates = [e for e in v['entries'] if e[1] & (1 << pbit)]
        exact = [e for e in candidates if e[0] == vid]
        fallback = [e for e in candidates if e[0] == ANY]
        return (exact or fallback or [(0, 0, 0)])[0][2]
    lookups = [lookup(pbit) for pbit in range(8)]
    if v['fixed'] & VALID:
        return 0, v['fixed'], lookups
    if not v['present']:
        return -95, 0x55aa55aa, lookups
    if not v['vlans']:
        return (0, lookups[0], lookups) if lookups[0] & VALID else (-95, 0x55aa55aa, lookups)
    tags = {tag & CORE_MASK for tag in lookups}
    if any(not tag & VALID for tag in lookups) or len(tags) != 1:
        return -95, 0x55aa55aa, lookups
    return 0, tags.pop(), lookups


def input_text(vs):
    lines = []
    for v in vs:
        vlans = v['vlans'] + [0, 0]
        row = [v['kind'], len(v['vlans']), *vlans[:2], bool(v['sid']), v['sid'], v['ds'], v['proto'],
               v['fixed'], v['present'], len(v['entries'])]
        row.extend(x for e in v['entries'] for x in e)
        lines.append(' '.join(str(int(x)) for x in row))
    return '\n'.join(lines) + '\n'


def compare(vs, output, oracle=None):
    lines = output.splitlines()
    assert len(lines) == len(vs), (len(lines), len(vs))
    stock_cases, rejections = 0, 0
    for i, (v, line) in enumerate(zip(vs, lines)):
        parts = line.split()
        assert len(parts) == 13, parts
        ret, tag, prep, egress, *lookups = [int(x) for x in parts[:-1]]
        want_ret, want_tag, want_lookups = expectation(v)
        assert (ret, tag, prep, egress, lookups) == (want_ret, want_tag, want_ret, 1, want_lookups), (i, v, line)
        if ret:
            rejections += 1
            continue
        raw = bytes.fromhex(parts[-1])
        u32 = lambda off: struct.unpack_from('<I', raw, off)[0]
        u16 = lambda off: struct.unpack_from('<H', raw, off)[0]
        kind = v['kind']
        ib2off = 44 if kind >= 4 else 16
        l2off = 48 if kind >= 4 else 44
        tc, gem = (tag >> 16) & 31, 0 if tag & EPON else tag & 65535
        assert (u32(40) >> 11) & 31 == tc, (i, 'channel')
        assert u32(ib2off) & 31 == tc, (i, 'nbq')
        assert (u32(ib2off) >> 5) & 15 == 2, (i, 'GDM2')
        assert u32(ib2off) & (1 << 9), (i, 'PSE QoS')
        assert u16(l2off + 2) == gem, (i, 'GEM', raw.hex())
        assert (u32(0) >> 22) & 1 == bool(v['sid']), (i, 'PPPoE flag')
        assert (u16(l2off + 16) if kind <= 3 else u32(l2off + 12) & 65535) == v['sid'], (i, 'PPPoE sid')
        assert [u16(l2off + off) for off in [0, 8]][:len(v['vlans'])] == v['vlans'], (i, 'VLAN')
        assert u32(ib2off) >> 24 == v['ds'], (i, 'DSCP/ECN')
        if oracle and not tag & EPON:
            original = oracle.foe(gem, tc, kind=kind, vpm=len(v['vlans']), sid=v['sid'],
                                  vlan1=(v['vlans'] + [0])[0], vlan2=(v['vlans'] + [0, 0])[1])
            stock32 = lambda off: struct.unpack_from('<I', original, off)[0]
            stock16 = lambda off: struct.unpack_from('<H', original, off)[0]
            # Stock type2 uses hardware L2B layout; production prepare emits
            # its software bridge template before later native conversion.
            stock_ib2off = 44 if kind >= 4 or kind == 2 else 16
            stock_l2off = 48 if kind >= 4 or kind == 2 else 44
            assert ((stock32(40) >> 11) & 31, stock32(stock_ib2off) & 31, stock16(stock_l2off + 2)) == (tc, tc, gem), (i, 'stock', original.hex())
            # Session/VLAN fields are inputs to the stock port mapper: verify
            # it preserves those fields while replacing etype with GEM.
            assert [stock16(stock_l2off + off) for off in [0, 8]][:len(v['vlans'])] == v['vlans']
            assert stock16(60) == v['sid'], (i, 'stock PPPoE sid')
            tx = oracle.tx_message(gem, tc)
            msg0, msg1 = tx['msg']
            assert tx['result'] == 0 and ((msg0 >> 14) & 65535, (msg0 >> 3) & 31, (msg1 >> 15) & 31) == (gem, tc, tc)
            assert (msg1 >> 20) & 15 == 2 and not msg0 & (1 << 8) and not msg1 & (1 << 31)
            stock_cases += 1
    return dict(cases=len(vs), rejected=rejections, stock_compared=stock_cases)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=Path, required=True,
                   help='Kernel source root or directory containing airoha_ppe.c and airoha_eth.h')
    p.add_argument('--modules', '--stock-dir', dest='modules', type=Path, required=True,
                   help='Directory containing the four SHA-pinned stock kernel modules')
    p.add_argument('--output', type=Path, required=True,
                   help='Directory for extracted sources, binaries, logs and verification.json')
    p.add_argument('--mutations', action='store_true')
    a = p.parse_args()
    source = a.source / 'drivers/net/ethernet/airoha' if (a.source / 'drivers').is_dir() else a.source
    source = source.resolve()
    build = a.output.resolve()
    build.mkdir(parents=True, exist_ok=True)
    sources = extract(source, build)
    for name in ['metadata_runner.c', 'metadata_stubs.h']:
        shutil.copyfile(ROOT / name, build / name)
    vs = vectors()
    stdin = input_text(vs)
    (build / 'vectors.json').write_text(json.dumps(vs, indent=2) + '\n')
    (build / 'input.txt').write_text(stdin)
    oracle = StockOracle(a.modules.resolve())
    results = []
    def run(mode, flags, stock):
        exe = build / ('test-' + mode)
        cmd = ['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-macro-redefined', '-O1',
               *flags, '-I'+str(build), str(build / 'metadata_runner.c'), '-o', str(exe)]
        c = subprocess.run(cmd, text=True, capture_output=True)
        (build / (mode + '-compile.log')).write_text(c.stdout + c.stderr)
        c.check_returncode()
        r = subprocess.run([str(exe)], input=stdin, text=True, capture_output=True)
        (build / (mode + '.log')).write_text(r.stdout + r.stderr)
        r.check_returncode()
        return compare(vs, r.stdout, oracle if stock else None)
    results.append(dict(mode='plain', **run('plain', [], True)))
    results.append(dict(mode='asan-ubsan', **run('sanitized', ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'], False)))
    for gem, tc in [(0, 0), (1, 31), (65535, 17)]:
        assert oracle.tx_message(gem, tc, valid=False)['result'] == -1
        assert oracle.tx_message(gem, tc, alloc_valid=False)['result'] == -1
    # Exercise stock chip-layout branches with the same bounded bearer cases.
    hir_cases, missing_hook_cases = 0, 0
    stock_layouts = []
    for hir, kind, gem, tc in itertools.product([0xa, 0xc, 0xe, 0xf, 0x10], [0, 5], [1, 65535], [0, 15, 16, 31]):
        for qos_remap in (0, None):
            raw = oracle.foe(gem, tc, kind=kind, hir=hir, qos_remap=qos_remap)
            ib2, l2 = (44, 48) if kind >= 4 else (16, 44)
            channel = tc + 16 if qos_remap is None and hir != 0xa and tc < 16 else tc
            actual = ((struct.unpack_from('<I', raw, 40)[0] >> 11) & 31,
                      struct.unpack_from('<I', raw, ib2)[0] & 31,
                      struct.unpack_from('<H', raw, l2 + 2)[0])
            assert actual == (channel, tc, gem), (hir, kind, gem, tc, qos_remap, actual)
            stock_layouts.append(dict(hir=hir, kind=kind, gem=gem, tcont=tc,
                                      qos_remap=qos_remap, channel=channel, raw=raw.hex()))
            if qos_remap is None:
                missing_hook_cases += 1
            else:
                hir_cases += 1
    (build / 'stock-chip-layouts.json').write_text(json.dumps(stock_layouts, indent=2) + '\n')
    hqos_hooks = oracle.verify_hqos_hooks()
    mutations = []
    if a.mutations:
        path = build / 'production_functions.inc'
        original = path.read_text()
        changes = {
            'gem-replaced-by-pppoe': ('FIELD_GET(AIROHA_PON_QDMA_GEM_MASK, pon_tag);', 'ETH_P_PPP_SES;'),
            'channel-truncated-to-four': ('channel = FIELD_GET(AIROHA_PON_QDMA_TCONT_MASK,', 'channel = 3 & FIELD_GET(AIROHA_PON_QDMA_TCONT_MASK,'),
            'ignore-pcp-split': ('else if (tag != first_tag)', 'else if (0 && tag != first_tag)'),
            'fallback-overrides-exact': ('if (entry->vlan_id == vlan_id)', 'if (entry->vlan_id == vlan_id || entry->vlan_id == AIROHA_PON_VID_ANY)'),
            'ignore-missing-tag': ('if (!(tag & AIROHA_PON_QDMA_VALID))', 'if (0 && !(tag & AIROHA_PON_QDMA_VALID))'),
        }
        try:
            for name, (before, after) in changes.items():
                assert before in original, name
                path.write_text(original.replace(before, after))
                try:
                    run('mutation-' + name, [], False)
                except AssertionError as error:
                    mutations.append(dict(name=name, detected=True, failure=str(error)[:600]))
                else:
                    raise RuntimeError('mutation survived: ' + name)
        finally:
            path.write_text(original)
    report = dict(passed=True, source=str(source), sources=sources, results=results,
                  labels=dict(Counter(v['label'] for v in vs)), stock=oracle.metadata(),
                  stock_invalid_mapping_cases=6, stock_chip_layout_cases=hir_cases,
                  stock_missing_qos_hook_cases=missing_hook_cases,
                  stock_hqos_hook_cases=hqos_hooks, mutations=mutations,
                  boundaries=['Production classifier/FOE template functions only; flow admission is tested separately.',
                              'Queue selection fixed at zero; DSCP/ECN retention checked.',
                              'Mapping replacement inputs checked; concurrent live FOE invalidation is tested by lifecycle suite.',
                              'Stock ELF functions run from entry to return with listed environment stubs.'])
    (build / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
