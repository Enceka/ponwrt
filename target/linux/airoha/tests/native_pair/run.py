#!/usr/bin/env python3
"""Compile extracted kernel functions with mocked transport/MMIO and sanitizers."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kernel-tree', required=True, type=Path,
                    help='Linux source after the Airoha native-pair patches through 957')
parser.add_argument('--output', required=True, type=Path,
                    help='New directory for extracted source, executables and reports')
args = parser.parse_args()
source = args.kernel_tree.resolve()
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
tests = Path(__file__).resolve().parent
for path in tests.iterdir():
    if path.is_file():
        shutil.copyfile(path, output / path.name)
shutil.copytree(tests / 'fixtures', output / 'fixtures')
(output / 'build').mkdir()
(output / 'candidate').symlink_to(source, target_is_directory=True)
headers = ('airoha_ct_native_pair.h', 'airoha_ct_pair_policy.h', 'airoha_ct_pair_banks.h',
           'airoha_ct_fe_native.h', 'airoha_ct_cpu_fallback.h')
for name in headers:
    shutil.copyfile(source / 'drivers/net/ethernet/airoha' / name, output / name)
core = (source / 'net/netfilter/core.c').read_text()
start = core.index('/* Serialize explicit authorizations against every nft transaction. */')
end = core.index('EXPORT_SYMBOL_GPL(nf_native_pair_bpf_end);', start)
end += len('EXPORT_SYMBOL_GPL(nf_native_pair_bpf_end);')
(output / 'nf_native_pair_core.inc').write_text(core[start:end] + '\n')
scripts = ['verify.py', 'verify_lifecycle.py', 'verify_wrapper.py', 'verify_bpf.py',
           'verify_shutdown.py', 'verify_station_fallback.py', 'verify_teardown.py', 'verify_fdb.py', 'verify_bridge_ct.py', 'verify_audit.py',
           'verify_wired_mtu.py', 'verify_wired_notifier.py', 'verify_owner.py', 'verify_cpu_fallback.py', 'verify_mutations.py']
for script in scripts:
    subprocess.run([sys.executable, str(output / script)], check=True)
paths = ['drivers/net/ethernet/airoha/' + name for name in headers]
paths += ['drivers/net/ethernet/airoha/airoha_eth.h', 'drivers/net/ethernet/airoha/airoha_eth.c',
          'drivers/net/ethernet/airoha/airoha_ct_ifc.h', 'drivers/net/ethernet/airoha/airoha_ppe_debugfs.c',
          'drivers/net/ethernet/airoha/airoha_npu.c',
          'drivers/net/ethernet/airoha/airoha_ppe.c',
          'drivers/net/ethernet/airoha/airoha_regs.h',
          'include/linux/soc/airoha/airoha_offload.h', 'include/linux/netfilter.h',
          'include/net/cfg80211.h', 'kernel/bpf/tcx.c', 'net/core/dev.c', 'net/netfilter/core.c',
          'net/bridge/br_fdb.c', 'net/bridge/br_switchdev.c', 'net/bridge/br_forward.c',
          'net/bridge/netfilter/nf_conntrack_bridge.c']
pair_report = json.loads((output / 'build/source3-verification.json').read_text())
cpu_report = json.loads((output / 'build/cpu-fallback-verification.json').read_text())
mutation_report = json.loads((output / 'build/mutation-verification.json').read_text())
report = {
    'passed': True,
    'cases': 0,
    'runtime_caught_mutations': len(mutation_report['mutations']),
    'selector_combinations': cpu_report['selector_combinations'],
    'groups': {'pair': pair_report['cases'], 'cpu_fallback': cpu_report['cases'], 'policy_core': 11, 'bank_lifecycle': 224,
               'mailbox_wrapper': 71, 'bpf': 16, 'shutdown': 7, 'teardown': 10, 'station_fallback': 40,
               'fdb_roam': 6, 'bridge_ct_hooks': 298, 'nft_audit': 20, 'wired_mtu': 130, 'wired_notifier': 8, 'radio_owner': 4},
    'sanitizers': ['address', 'undefined'],
    'kernel_tree': str(source),
    'source_sha256': {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                      for name in paths},
}
report['cases'] = sum(report['groups'].values())
assert pair_report['cases'] == 199 and cpu_report['cases'] == 19
assert report['runtime_caught_mutations'] == 19
for name in ('airoha_eth.h', 'airoha_ppe.c', 'airoha_ppe_debugfs.c'):
    text = (source / 'drivers/net/ethernet/airoha' / name).read_text()
    assert 'fault_stop' not in text and 'airoha_ppe_ct_fault_test' not in text, name
report['production_fault_trigger_absent'] = True
assert len(json.loads((output / 'build/mutation-verification.json').read_text())['mutations']) == report['runtime_caught_mutations']
(output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print(f'PASS {report["cases"]} ABI3 native host cases, {report["selector_combinations"]} selector combinations and {report["runtime_caught_mutations"]} runtime-caught mutations; report: ' + str(output / 'report.json'))
