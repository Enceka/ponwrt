from pathlib import Path
import json
import subprocess

r = Path(__file__).resolve().parent
source = (r / 'airoha_ct_pair_policy.h').read_text()
functions = source[source.index('static int airoha_ct_pair_policy_init('):]
pre = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
struct notifier_block {int(*notifier_call)(struct notifier_block*,unsigned long,void*);};
struct airoha_eth {void*dev;};
struct airoha_ppe {struct airoha_eth*eth;bool ct_native_pairs,ct_pair_wired_registered,ct_pair_policy_registered;struct notifier_block ct_pair_wired_notifier,ct_pair_policy_notifier;};
static unsigned active_net,active_policy,active_file,step;
static int fail_stage,dev_attr_ct_native_pair_policy;
static int airoha_ct_pair_wired_event(struct notifier_block*n,unsigned long e,void*p){(void)n;(void)e;(void)p;return 0;}
static int airoha_ct_pair_policy_event(struct notifier_block*n,unsigned long e,void*p){(void)n;(void)e;(void)p;return 0;}
static int register_netdevice_notifier(struct notifier_block*n){assert(n->notifier_call==airoha_ct_pair_wired_event&&++step==1);if(fail_stage==1)return -EIO;active_net++;return 0;}
static int nf_native_pair_register(struct notifier_block*n){assert(n->notifier_call==airoha_ct_pair_policy_event&&active_net&&++step==2);if(fail_stage==2)return -EIO;active_policy++;return 0;}
static int device_create_file(void*d,int*a){assert(d&&a==&dev_attr_ct_native_pair_policy&&active_net&&active_policy&&++step==3);if(fail_stage==3)return -EIO;active_file++;return 0;}
static void unregister_netdevice_notifier(struct notifier_block*n){assert(n->notifier_call==airoha_ct_pair_wired_event&&active_net==1);active_net--;}
static void nf_native_pair_unregister(struct notifier_block*n){assert(n->notifier_call==airoha_ct_pair_policy_event&&active_policy==1);active_policy--;}
static void device_remove_file(void*d,int*a){assert(d&&a==&dev_attr_ct_native_pair_policy&&active_file==1);active_file--;}
'''
main = r'''
int main(void){unsigned cases=0;struct airoha_eth e={.dev=(void*)1};
 for(unsigned enabled=0;enabled<2;enabled++)for(fail_stage=0;fail_stage<4;fail_stage++){
  struct airoha_ppe p={.eth=&e,.ct_native_pairs=enabled};step=active_net=active_policy=active_file=0;
  int result=airoha_ct_pair_policy_init(&p);assert(result==((enabled&&fail_stage)?-EIO:0));
  bool live=enabled&&!fail_stage;assert(active_net==live&&active_policy==live&&active_file==live);assert(p.ct_pair_wired_registered==live&&p.ct_pair_policy_registered==live);
  airoha_ct_pair_policy_deinit(&p);airoha_ct_pair_policy_deinit(&p);assert(!active_net&&!active_policy&&!active_file&&!p.ct_pair_wired_registered&&!p.ct_pair_policy_registered);cases++;
 }
 printf("PASS %u actual wired notifier registration, failure unwind and idempotent teardown cases\n",cases);
}
'''
(r / 'build/verify_wired_notifier.c').write_text(pre + functions + main)
subprocess.run(['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                '-fsanitize=address,undefined', str(r / 'build/verify_wired_notifier.c'),
                '-o', str(r / 'build/verify_wired_notifier')], check=True)
p = subprocess.run([str(r / 'build/verify_wired_notifier')], capture_output=True, text=True, check=True)
print(p.stdout)
(r / 'build/wired-notifier-verification.json').write_text(json.dumps(
    dict(passed=True, result=p.stdout, sanitizers=['address', 'undefined']), indent=2) + '\n')
