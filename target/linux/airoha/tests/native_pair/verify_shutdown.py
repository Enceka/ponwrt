from pathlib import Path
import subprocess,json
r=Path(__file__).resolve().parent;s=(r/'candidate/drivers/net/ethernet/airoha/airoha_ppe.c').read_text();a=s.index('int airoha_ppe_deinit(');z=s.index('\n}',a)+2;f=s[a:z]
a=s.index('int airoha_ppe_ct_shutdown(');z=s.index('\n}',a)+2;f=s[a:z]+'\n'+f
pre=r'''
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
struct airoha_npu {struct{void(*ppe_deinit)(struct airoha_npu*);}ops;};
struct airoha_ppe {bool ct_stopping,ct_restore_pending,ct_host_ppe;int ct_bridge_notifier,l2_flows,debugfs_dir;};
struct airoha_eth {struct airoha_ppe*ppe;struct airoha_npu*npu;int flow_table;};
static int flow_offload_mutex,ppe_lock,stage,requested,stops,deinit_count,stop_error,unregisters,optical_deinits;
#define dev_err(...) ((void)0)
#define dev_info(...) ((void)0)
static bool airoha_ppe_ct_requested(struct airoha_eth*e){assert(e);return requested;}
static void unregister_switchdev_notifier(int*p){assert(p&&!flow_offload_mutex&&stage>=2&&!optical_deinits);unregisters++;}
#define mutex_lock(p) (*(p)=1)
#define mutex_unlock(p) (*(p)=0)
#define spin_lock_bh(p) (*(p)=1)
#define spin_unlock_bh(p) (*(p)=0)
#define lockdep_is_held(p) (*(p))
static struct airoha_eth*current;
static int airoha_ppe_ct_stop(struct airoha_ppe*p){assert(current->npu&&flow_offload_mutex&&p->ct_stopping&&!p->ct_host_ppe);stops++;if(stop_error)return stop_error;stage=1;p->ct_restore_pending=false;return 0;}
static struct airoha_npu*replace(struct airoha_npu**p,bool held){assert(held);if(stops)assert(stage==1);struct airoha_npu*n=*p;*p=0;stage=2;return n;}
#define rcu_replace_pointer(p,v,held) replace(&(p),(held))
static void synchronize_rcu(void){assert(stage==2);}
static void airoha_npu_put(struct airoha_npu*n){assert(n&&stage==2);stage=3;}
static void airoha_ct_pon_ifc_cpu_deinit(struct airoha_ppe*p){assert(p&&!flow_offload_mutex&&stage>=2&&!current->npu&&!p->ct_restore_pending);assert(unregisters==requested);optical_deinits++;}
static void airoha_ct_pair_policy_deinit(struct airoha_ppe*p){assert(p&&!flow_offload_mutex&&optical_deinits==1);if(current->npu==0)assert(stage>=2);stage=4;}
static void rhashtable_destroy(int*p){assert(p&&stage==4);}
static void debugfs_remove(int d){(void)d;assert(stage==4);}
static void legacy_deinit(struct airoha_npu*n){assert(n);deinit_count++;}
'''
main=r'''
int main(void){unsigned cases=0;struct airoha_npu n={.ops.ppe_deinit=legacy_deinit};
for(int native=0;native<2;native++)for(int pending=0;pending<2;pending++){
 if(!native&&pending)continue;struct airoha_ppe p={.ct_host_ppe=true,.ct_restore_pending=pending};struct airoha_eth e={.ppe=&p,.npu=&n};current=&e;requested=native;stage=stops=deinit_count=unregisters=optical_deinits=0;assert(!airoha_ppe_deinit(&e));assert(stops==pending&&deinit_count==!native&&stage==4&&optical_deinits==1);cases++;
}
const int failures[]={-EAGAIN,-ETIMEDOUT,-EIO,-EOPNOTSUPP};
for(unsigned i=0;i<4;i++){
 struct airoha_ppe p={.ct_host_ppe=true,.ct_restore_pending=true};struct airoha_eth e={.ppe=&p,.npu=&n};
 current=&e;requested=1;stage=stops=deinit_count=unregisters=optical_deinits=0;stop_error=failures[i];
 for(unsigned retry=0;retry<3;retry++){
  assert(airoha_ppe_deinit(&e)==stop_error&&e.npu==&n&&p.ct_restore_pending&&p.ct_stopping&&!p.ct_host_ppe);
  assert(!stage&&!deinit_count&&!unregisters&&!optical_deinits&&!flow_offload_mutex);
 }
 stop_error=0;assert(!airoha_ppe_deinit(&e)&&e.npu==0&&!p.ct_restore_pending&&stage==4&&unregisters==1);cases++;
}
for(unsigned failure=0;failure<4;failure++){
 struct airoha_ppe p={.ct_host_ppe=true,.ct_restore_pending=true};struct airoha_eth e={.ppe=&p,.npu=&n};
 current=&e;requested=1;stage=stops=deinit_count=unregisters=optical_deinits=0;stop_error=failures[failure];
 for(unsigned retry=0;retry<3;retry++){
  assert(airoha_ppe_ct_shutdown(&e)==stop_error&&stops==(int)retry+1);
  assert(e.npu==&n&&p.ct_restore_pending&&p.ct_stopping&&!p.ct_host_ppe);
  assert(!stage&&!deinit_count&&!unregisters&&!optical_deinits&&!flow_offload_mutex&&!ppe_lock);
 }
 stop_error=0;assert(!airoha_ppe_ct_shutdown(&e)&&stops==4&&!p.ct_restore_pending&&e.npu==&n&&stage==1);
 assert(!optical_deinits&&!unregisters&&!deinit_count&&!flow_offload_mutex);
 assert(!airoha_ppe_deinit(&e)&&stops==4&&!e.npu&&stage==4&&optical_deinits==1&&unregisters==1);cases++;
}
for(int native=0;native<2;native++){
 struct airoha_ppe p={.ct_host_ppe=true};struct airoha_eth e={.ppe=&p,.npu=&n};
 current=&e;requested=native;stage=stops=deinit_count=unregisters=optical_deinits=0;
 assert(!airoha_ppe_ct_shutdown(&e)&&!stops&&!stage&&e.npu==&n);
 assert(p.ct_stopping==native&&p.ct_host_ppe==!native&&!flow_offload_mutex&&!ppe_lock);
 assert(!unregisters&&!optical_deinits&&!deinit_count);cases++;
}
printf("PASS %u actual deinit NPU-reference, revoke-before-unlink and policy-lock order cases\n",cases);}
'''
(r/'build/verify_shutdown.c').write_text(pre+f+main)
subprocess.run(['clang','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(r/'build/verify_shutdown.c'),'-o',str(r/'build/verify_shutdown')],check=True)
p=subprocess.run([str(r/'build/verify_shutdown')],capture_output=True,text=True,check=True);print(p.stdout)
(r/'build/shutdown-verification.json').write_text(json.dumps({'passed':True,'cases':int(p.stdout.split()[1]),'result':p.stdout,'sanitizers':['address','undefined']},indent=2)+'\n')
