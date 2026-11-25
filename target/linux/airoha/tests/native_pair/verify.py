from pathlib import Path
import json,subprocess,hashlib
r=Path(__file__).resolve().parent;b=r/'build';b.mkdir(exist_ok=True)
policy=(r/'airoha_ct_pair_policy.h').read_text();a=policy.index('static int airoha_ct_pair_policy_event(');z=policy.index('static bool airoha_ct_pair_bridge_ct_hook',a);(b/'pair_policy_event.inc').write_text(policy[a:z])
h=(r/'candidate/drivers/net/ethernet/airoha/airoha_eth.h').read_text()
a=h.index('enum {\n\tAIROHA_FOE_STATE_INVALID,');z=h.index('struct airoha_foe_stats {',a);(b/'foe_layout.inc').write_text(h[a:z])
h=(r/'candidate/include/linux/soc/airoha/airoha_offload.h').read_text();a=h.index('/* Native WLAN endpoint pair ABI');z=h.index('struct airoha_npu {',a);(b/'pair_abi.inc').write_text(h[a:z])
def function(text, signature):
 a=text.index(signature);brace=text.index('{',a);depth=0
 for z in range(brace,len(text)):
  depth+=(text[z]=='{')-(text[z]=='}')
  if depth==0:return text[a:z+1]
 raise AssertionError(signature)
bridge=(r/'candidate/net/bridge/br_switchdev.c').read_text()
(b/'bridge_fdb_lookup.inc').write_text(function(bridge,'static bool br_switchdev_fdb_notifies(')+'\n'+function(bridge,'struct net_device *br_switchdev_fdb_find_port(')+'\n')
forward=(r/'candidate/net/bridge/br_forward.c').read_text();a=forward.index('\tif (netif_is_bridge_port(skb->dev) && skb->skb_iif &&');z=forward.index('\tdev_queue_xmit(skb);',a)
(b/'bridge_frame_notify.inc').write_text(forward[a:z])
subprocess.run(['clang','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=address,undefined',
 '-I'+str(b),'-I'+str(r),str(r/'verify_pair.c'),'-o',str(b/'verify_pair')],check=True)
p=subprocess.run([str(b/'verify_pair')],capture_output=True,text=True,check=True)
(b/'verification.json').write_text(json.dumps({'passed':True,'source_sha256':hashlib.sha256((r/'airoha_ct_native_pair.h').read_bytes()).hexdigest(),'bridge_fdb_lookup_sha256':hashlib.sha256((b/'bridge_fdb_lookup.inc').read_bytes()).hexdigest(),'bridge_frame_notify_sha256':hashlib.sha256((b/'bridge_frame_notify.inc').read_bytes()).hexdigest(),'sanitizers':['address','undefined'],'result':p.stdout},indent=2)+'\n')
print(p.stdout)

subprocess.run(['clang','-std=gnu11','-Wall','-Wextra','-Werror','-pthread','-fsanitize=address,undefined','-I'+str(r),str(r/'verify_policy_core.c'),'-o',str(b/'verify_policy_core')],check=True)
p=subprocess.run([str(b/'verify_policy_core')],capture_output=True,text=True,check=True);print(p.stdout)
(b/'policy-core-verification.json').write_text(json.dumps({'passed':True,'result':p.stdout,'sanitizers':['address','undefined']},indent=2)+'\n')
