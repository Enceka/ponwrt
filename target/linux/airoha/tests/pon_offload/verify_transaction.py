#!/usr/bin/env python3
import argparse,hashlib,json,resource,shutil,subprocess
from pathlib import Path
from verify_lifecycle import function
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
d=a.source.resolve()/'drivers/net/ethernet/airoha';o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
inputs=['airoha_eth.c','airoha_pon_transaction.h','airoha_pon_retire.h'];src={n:(d/n).read_text() for n in inputs}
owner_close='airoha_ppe_npu_owner_close_locked(eth)' in src['airoha_pon_transaction.h']
for n in inputs[1:]: (o/n).write_text(src[n])
(o/'commit.inc').write_text(function(src['airoha_eth.c'],'static int\nairoha_eth_pon_commit_config('))
shutil.copyfile(Path(__file__).with_name('transaction_test.c'),o/'test.c')
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def run(name,mutate=None):
 for n in inputs[1:]: (o/n).write_text(src[n])
 if mutate:
  n,old,new=mutate;assert src[n].count(old)==1,(name,src[n].count(old));(o/n).write_text(src[n].replace(old,new))
 exe=o/name
 options=['-DAIROHA_TEST_NPU_OWNER'] if owner_close else []
 b=subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=address,undefined',*options,str(o/'test.c'),'-o',str(exe)],capture_output=True,text=True)
 (o/(name+'.build.log')).write_text(b.stdout+b.stderr);assert not b.returncode,b.stderr
 r=subprocess.run([str(exe)],capture_output=True,text=True);(o/(name+'.log')).write_text(r.stdout+r.stderr)
 assert bool(r.returncode)==bool(mutate),(name,r.stdout,r.stderr)
 return r.stdout.strip()
result=run('transaction')
mutations={
 'skip_pending':('airoha_pon_transaction.h','1000, 100000, false, &dev->pon_tx_pending);','1000, 100000, false, &dev->pon_tx_pending);\n\terr = 0;'),
 'forget_old_channels':('airoha_pon_transaction.h','channel_mask | airoha_pon_mapping_channels(dev)','channel_mask | (airoha_pon_mapping_channels(dev) & 0)'),
 'release_on_reopen_failure':('airoha_pon_transaction.h','reclose:\n','reclose:\n\tWRITE_ONCE(dev->pon_update_blocked, false);\n'),
 'ignore_foe_failure':('airoha_pon_transaction.h','err = airoha_ppe_remove_egress_flows(dev);','err = airoha_ppe_remove_egress_flows(dev);\n\terr = 0;'),
 'clear_cmd_aging':('airoha_pon_retire.h','AIROHA_PON_RETIRE_CMD_MASK, 0);','~0U, 0);'),
}
if owner_close:
 mutations['ignore_owner_close_failure']=('airoha_pon_transaction.h','err = airoha_ppe_npu_owner_close_locked(eth);','err = airoha_ppe_npu_owner_close_locked(eth);\n\terr = 0;')
for name,m in mutations.items():run(name,m)
for n in inputs[1:]: (o/n).write_text(src[n])
report={'passed':True,'result':result,'negative_controls':list(mutations),'source_sha256':{n:hashlib.sha256((d/n).read_bytes()).hexdigest() for n in inputs}}
(o/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
