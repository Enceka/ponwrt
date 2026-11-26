#!/usr/bin/env python3
"""Exercise actual route, failure, IFC and retirement functions with MMIO faults."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess

root = Path(__file__).resolve().parent
source = root / 'candidate/drivers/net/ethernet/airoha'
build = root / 'build/cpu-fallback'
build.mkdir(parents=True, exist_ok=True)


def extract(filename, name):
    text = (source / filename).read_text()
    pos = text.index(name + '(')
    start = text.rfind('\nstatic ', 0, pos) + 1
    begin = text.index('{', pos)
    depth, end = 1, begin + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'


functions = [('airoha_eth.c', 'airoha_set_gdm_port_fwd_cfg'),
             ('airoha_ct_ifc.h', 'ct_ifc_write_reg'),
             ('airoha_ct_native_pair.h', 'airoha_ct_pair_wlan_gate'),
             ('airoha_ct_native_pair.h', 'airoha_ct_pair_close_once'),
             ('airoha_ct_native_pair.h', 'airoha_ct_pair_fault_close'),
             ('airoha_ppe.c', 'airoha_ppe_ct_bridge_fail_closed_from'),
             ('airoha_ct_fe_native.h', 'airoha_ct_fe_quiesce')]
(build / 'cpu_fallback_extracted.inc').write_text('\n'.join(extract(f, n) for f, n in functions))
shutil.copyfile(source / 'airoha_ct_cpu_fallback.h', build / 'airoha_ct_cpu_fallback.h')
shutil.copyfile(root / 'verify_cpu_fallback.c', build / 'test.c')
results = []
for mode, flags in [('plain', []), ('sanitized', ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])]:
    binary = build / ('test-' + mode)
    command = ['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-O1',
               *flags, '-I' + str(build), str(build / 'test.c'), '-o', str(binary)]
    compiled = subprocess.run(command, capture_output=True, text=True)
    (build / (mode + '-compile.log')).write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    tested = subprocess.run([str(binary)], capture_output=True, text=True)
    (build / (mode + '.log')).write_text(tested.stdout + tested.stderr)
    tested.check_returncode()
    match = re.fullmatch(r'PASS: (\d+) scenario groups; (\d+) selector combinations; extracted production functions\s*', tested.stdout)
    assert match, tested.stdout
    results.append(dict(mode=mode, cases=int(match[1]), selector_combinations=int(match[2]), returncode=tested.returncode))
assert results[0]['cases'] == results[1]['cases']
files = sorted({f for f, n in functions} | {'airoha_ct_cpu_fallback.h'})
report = dict(passed=True, cases=results[0]['cases'], selector_combinations=results[0]['selector_combinations'],
              modes=results, source_sha256={name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in files})
(root / 'build/cpu-fallback-verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
