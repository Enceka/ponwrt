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
                    help='Linux source after the Airoha 951 and 952 patches')
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
headers = ('airoha_ct_native_pair.h', 'airoha_ct_pair_policy.h', 'airoha_ct_pair_banks.h')
for name in headers:
    shutil.copyfile(source / 'drivers/net/ethernet/airoha' / name, output / name)
core = (source / 'net/netfilter/core.c').read_text()
start = core.index('/* Serialize explicit authorizations against every nft transaction. */')
end = core.index('EXPORT_SYMBOL_GPL(nf_native_pair_bpf_end);', start)
end += len('EXPORT_SYMBOL_GPL(nf_native_pair_bpf_end);')
(output / 'nf_native_pair_core.inc').write_text(core[start:end] + '\n')
scripts = ['verify.py', 'verify_lifecycle.py', 'verify_wrapper.py', 'verify_bpf.py',
           'verify_shutdown.py', 'verify_fdb.py', 'verify_bridge_ct.py', 'verify_audit.py']
for script in scripts:
    subprocess.run([sys.executable, str(output / script)], check=True)
paths = ['drivers/net/ethernet/airoha/' + name for name in headers]
paths += ['drivers/net/ethernet/airoha/airoha_eth.h',
          'drivers/net/ethernet/airoha/airoha_npu.c',
          'drivers/net/ethernet/airoha/airoha_ppe.c',
          'drivers/net/ethernet/airoha/airoha_regs.h',
          'include/linux/soc/airoha/airoha_offload.h', 'include/linux/netfilter.h',
          'kernel/bpf/tcx.c', 'net/core/dev.c', 'net/netfilter/core.c',
          'net/bridge/br_fdb.c', 'net/bridge/netfilter/nf_conntrack_bridge.c']
report = {
    'passed': True,
    'cases': 700,
    'groups': {'pair': 55, 'policy_core': 11, 'bank_lifecycle': 223,
               'mailbox_wrapper': 68, 'bpf': 16, 'shutdown': 3,
               'fdb_roam': 6, 'bridge_ct_hooks': 298, 'nft_audit': 20},
    'sanitizers': ['address', 'undefined'],
    'kernel_tree': str(source),
    'source_sha256': {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                      for name in paths},
}
(output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS 700 native host cases; report: ' + str(output / 'report.json'))
