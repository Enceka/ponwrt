"""Exercise extracted cleanup/remove ordering and fixed-DT provider publication."""
from pathlib import Path
import json
import subprocess

root = Path(__file__).resolve().parent
sources = root / 'candidate/drivers/net/ethernet/airoha'
eth = (sources / 'airoha_eth.c').read_text()
ppe = (sources / 'airoha_ppe.c').read_text()
npu = (sources / 'airoha_npu.c').read_text()
optical = (sources / 'airoha_ct_pon_ifc_cpu.h').read_text()

def function(text, name):
    pos = text.index(name + '(')
    start = text.rfind('\nstatic ', 0, pos) + 1
    begin = text.index('{', pos)
    end, depth = begin + 1, 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

pre = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#define WARN_ON(x) (x)
#define dev_err(...) ((void)0)
struct net_device {struct {void*of_node;}dev;};
struct airoha_qdma {int id;};
struct airoha_gdm_dev {struct net_device netdev;void*phylink;};
struct airoha_gdm_port {struct airoha_gdm_dev*devs[2];};
struct airoha_eth {struct airoha_qdma qdma[2];struct airoha_gdm_port*ports[4];void*napi_dev;void*dev;};
struct platform_device {struct airoha_eth*eth;};
static int shutdown_error,deinit_error,preflights,deinits,cleaned,stopped,tx,unregistered,metadata,freed;
static bool allow_cleanup;
static int airoha_ppe_ct_shutdown(struct airoha_eth*e){assert(e);preflights++;return shutdown_error;}
static int airoha_ppe_deinit(struct airoha_eth*e){assert(e);deinits++;if(deinit_error)return deinit_error;allow_cleanup=true;return 0;}
static void airoha_qdma_cleanup(struct airoha_eth*e,struct airoha_qdma*q){assert(e&&q&&allow_cleanup);cleaned++;}
static struct airoha_eth*platform_get_drvdata(struct platform_device*p){return p->eth;}
static void platform_set_drvdata(struct platform_device*p,void*v){assert(!v);p->eth=v;}
static void airoha_qdma_stop_napi(struct airoha_qdma*q){assert(q&&preflights&&!shutdown_error);stopped++;}
static void airoha_qdma_tx_cleanup(struct airoha_qdma*q){assert(q&&preflights&&!shutdown_error);tx++;}
static struct net_device*netdev_from_priv(struct airoha_gdm_dev*d){return &d->netdev;}
static void unregister_netdev(struct net_device*n){assert(n&&preflights&&!shutdown_error);unregistered++;}
static void phylink_destroy(void*p){assert(p);}
static void of_node_put(void*p){(void)p;}
static void airoha_metadata_dst_free(struct airoha_gdm_port*p){assert(p&&preflights&&!shutdown_error);metadata++;}
static void free_netdev(void*p){assert(p&&allow_cleanup&&cleaned==2);freed++;}
static void reset(void){shutdown_error=deinit_error=preflights=deinits=cleaned=stopped=tx=unregistered=metadata=freed=0;allow_cleanup=false;}
'''
main = r'''
int main(void){
 unsigned cases=0;struct airoha_eth e={.napi_dev=(void*)1};struct platform_device p={.eth=&e};
 struct airoha_gdm_dev dev={0};struct airoha_gdm_port port={.devs={&dev,NULL}};e.ports[0]=&port;
 const int errors[]={-EAGAIN,-ETIMEDOUT,-EIO,-EOPNOTSUPP};
 for(unsigned i=0;i<4;i++){
  reset();deinit_error=errors[i];assert(airoha_hw_cleanup(&e)==errors[i]&&deinits==1&&!cleaned&&!allow_cleanup);cases++;
  reset();shutdown_error=errors[i];airoha_remove(&p);
  assert(preflights==1&&!deinits&&!cleaned&&!stopped&&!tx&&!unregistered&&!metadata&&!freed&&p.eth==&e);cases++;
 }
 reset();assert(!airoha_hw_cleanup(&e)&&deinits==1&&cleaned==2);cases++;
 reset();airoha_remove(&p);assert(preflights==1&&deinits==1&&stopped==2&&tx==2&&cleaned==2&&unregistered==1&&metadata==1&&freed==1&&!p.eth);cases++;
 printf("PASS %u extracted cleanup and remove ordering cases\n",cases);
}
'''
build = root / 'build/teardown'
build.mkdir(exist_ok=True)
(build / 'test.c').write_text(pre + function(eth, 'airoha_hw_cleanup') + function(eth, 'airoha_remove') + main)
subprocess.run(['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-sign-compare', '-fsanitize=address,undefined',
                str(build / 'test.c'), '-o', str(build / 'test')], check=True)
result = subprocess.check_output([str(build / 'test')], text=True)
init_pre = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#define READ_ONCE(value) (value)
#define WRITE_ONCE(value, next) ((value)=(next))
struct device {void *of_node;};
struct notifier_block {void (*notifier_call)(void);};
struct delayed_work {bool initialized,pending;};
struct airoha_eth;
struct airoha_ppe {
 struct airoha_eth *eth;
 bool ct_native_pairs,ct_pon_ifc_registered,ct_pon_ifc_work_stopping;
 struct delayed_work ct_pon_ifc_work;
 struct notifier_block ct_bridge_notifier;
 int l2_flows;
};
struct airoha_eth {struct device *dev;struct airoha_ppe *ppe;int flow_table;};
static int airoha_flow_table_params,airoha_l2_flow_table_params,dev_attr_ct_pon_cpu_probe;
static unsigned failure,hash_calls,hash_destroys,notifier_calls,notifier_removes;
static unsigned debug_calls,policy_calls,policy_removes,work_inits,file_calls,file_removes,cancels;
static int injected_error;
static bool requested,ram_lab,notifier_live,policy_live,file_live;
static struct airoha_eth *current;
static bool airoha_ppe_ct_requested(struct airoha_eth *eth){assert(eth==current);return requested;}
static bool of_property_read_bool(void *node,const char *name){
 assert(node==current->dev->of_node&&!strcmp(name,"airoha,connac2-ram-native-pairs"));return ram_lab;
}
static int rhashtable_init(int *table,const int *params){
 hash_calls++;
 assert((hash_calls==1&&table==&current->flow_table&&params==&airoha_flow_table_params)||
        (hash_calls==2&&table==&current->ppe->l2_flows&&params==&airoha_l2_flow_table_params));
 assert(!*table);if(failure==hash_calls)return injected_error;*table=1;return 0;
}
static void rhashtable_destroy(int *table){
 assert(*table==1&&!notifier_live&&!policy_live&&!file_live);
 if(table==&current->flow_table)assert(!current->ppe->l2_flows);
 else assert(table==&current->ppe->l2_flows&&current->flow_table);
 *table=0;hash_destroys++;
}
static void airoha_ppe_ct_bridge_event(void){}
static int register_switchdev_notifier(struct notifier_block *notifier){
 assert(notifier==&current->ppe->ct_bridge_notifier&&notifier->notifier_call==airoha_ppe_ct_bridge_event);
 assert(current->flow_table&&current->ppe->l2_flows&&!debug_calls);
 notifier_calls++;if(failure==3)return injected_error;notifier_live=true;return 0;
}
static void unregister_switchdev_notifier(struct notifier_block *notifier){
 assert(notifier==&current->ppe->ct_bridge_notifier&&notifier_live&&!policy_live&&!file_live);
 notifier_live=false;notifier_removes++;
}
static int airoha_ppe_debugfs_init(struct airoha_ppe *ppe){
 assert(ppe==current->ppe&&ppe->l2_flows&&current->flow_table&&notifier_live==requested);
 debug_calls++;return failure==4?injected_error:0;
}
static int airoha_ct_pair_policy_init(struct airoha_ppe *ppe){
 assert(ppe==current->ppe&&debug_calls==1&&!file_calls);
 policy_calls++;if(failure==5)return injected_error;policy_live=true;return 0;
}
static void airoha_ct_pair_policy_deinit(struct airoha_ppe *ppe){
 assert(ppe==current->ppe&&policy_live&&file_calls==1&&!file_live&&!ppe->ct_pon_ifc_registered);
 assert(notifier_live==requested&&ppe->l2_flows&&current->flow_table&&!hash_destroys);
 policy_live=false;policy_removes++;
}
static void airoha_ct_pon_ifc_repair_work(void){}
static void init_work(struct delayed_work *work,void (*callback)(void)){
 assert(work==&current->ppe->ct_pon_ifc_work&&callback==airoha_ct_pon_ifc_repair_work&&policy_live);
 assert(!work->initialized);work->initialized=true;work_inits++;
}
#define INIT_DELAYED_WORK(work, callback) init_work(work, callback)
static int device_create_file(struct device *dev,const int *attribute){
 assert(dev==current->dev&&attribute==&dev_attr_ct_pon_cpu_probe&&work_inits==1&&policy_live);
 assert(!current->ppe->ct_pon_ifc_registered&&!current->ppe->ct_pon_ifc_work_stopping);
 file_calls++;if(failure==6)return injected_error;file_live=true;return 0;
}
static void device_remove_file(struct device *dev,const int *attribute){
 assert(dev==current->dev&&attribute==&dev_attr_ct_pon_cpu_probe&&file_live&&!cancels);
 assert(current->ppe->ct_pon_ifc_registered&&current->ppe->ct_pon_ifc_work_stopping);
 file_live=false;file_removes++;
}
static void cancel_delayed_work_sync(struct delayed_work *work){
 assert(work==&current->ppe->ct_pon_ifc_work&&work->initialized&&!file_live&&file_removes==1);
 assert(current->ppe->ct_pon_ifc_registered&&current->ppe->ct_pon_ifc_work_stopping);
 work->pending=false;cancels++;
}
'''
init_main = r'''
int main(void){
 unsigned cases=0;
 const int errors[]={-ENOMEM,-EIO,-EAGAIN,-ETIMEDOUT};
 for(unsigned native=0;native<2;native++)for(unsigned ram=0;ram<2;ram++)
 for(unsigned target=0;target<=6;target++)for(unsigned error=0;error<4;error++){
  if((!target&&error)||(target==3&&!native)||(target==6&&!(native&&ram)))continue;
  struct device dev={.of_node=(void*)1};struct airoha_eth eth={.dev=&dev};
  struct airoha_ppe owner={.eth=&eth,.ct_native_pairs=native};eth.ppe=&owner;current=&eth;
  requested=native;ram_lab=ram;failure=target;injected_error=errors[error];
  hash_calls=hash_destroys=notifier_calls=notifier_removes=debug_calls=policy_calls=policy_removes=0;
  work_inits=file_calls=file_removes=cancels=0;notifier_live=policy_live=file_live=false;
  assert(init_tables(&eth)==(target?injected_error:0));
  assert(hash_calls==(target==1?1:2));
  assert(notifier_calls==(native&&(!target||target>=3)));
  assert(debug_calls==(!target||target>=4));
  assert(policy_calls==(!target||target>=5));
  assert(file_calls==(native&&ram&&(!target||target==6))&&work_inits==file_calls);
  assert(policy_removes==(target==6));
  if(target){
   assert(!eth.flow_table&&!owner.l2_flows&&!notifier_live&&!policy_live&&!file_live);
   assert(hash_destroys==(target==1?0:target==2?1:2));
   assert(notifier_removes==(native&&target>=4));
   assert(!owner.ct_pon_ifc_registered&&!owner.ct_pon_ifc_work.pending&&!cancels&&!file_removes);
   airoha_ct_pon_ifc_cpu_deinit(&owner);
   assert(!cancels&&!file_removes&&!owner.ct_pon_ifc_work_stopping);
  }else{
   assert(eth.flow_table&&owner.l2_flows&&notifier_live==requested&&policy_live&&!hash_destroys);
   assert(owner.ct_pon_ifc_registered==(native&&ram)&&file_live==(native&&ram));
   assert(!owner.ct_pon_ifc_work_stopping);
   owner.ct_pon_ifc_work.pending=native&&ram;
   airoha_ct_pon_ifc_cpu_deinit(&owner);
   assert(!owner.ct_pon_ifc_registered&&!owner.ct_pon_ifc_work.pending&&!file_live);
   assert(cancels==(native&&ram)&&file_removes==cancels&&owner.ct_pon_ifc_work_stopping==(native&&ram));
   airoha_ct_pon_ifc_cpu_deinit(&owner);assert(cancels==(native&&ram)&&file_removes==cancels);
  }
  cases++;
 }
 printf("PASS %u extracted initialization cleanup, RAM eligibility and optical worker teardown cases\n",cases);
}
'''
init_start = ppe.index('int airoha_ppe_init(')
init_start = ppe.index('\terr = rhashtable_init(&eth->flow_table,', init_start)
init_end = ppe.index('\n}', init_start) + 2
init_body = ('static int init_tables(struct airoha_eth *eth)\n{\n'
             '\tstruct airoha_ppe *ppe = eth->ppe;\n\tint err;\n' + ppe[init_start:init_end])
(build / 'init.c').write_text(init_pre + function(optical, 'airoha_ct_pon_ifc_cpu_init') +
                            function(optical, 'airoha_ct_pon_ifc_cpu_deinit') + init_body + init_main)
subprocess.run(['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                str(build / 'init.c'), '-o', str(build / 'init')], check=True)
init_result = subprocess.check_output([str(build / 'init')], text=True)
assert '.suppress_bind_attrs = true' in eth and '.suppress_bind_attrs = true' in npu
probe = function(eth, 'airoha_probe')
assert probe.index('airoha_register_gdm_devices(eth)') < probe.index('airoha_ppe_ct_prepare(eth)')
setup = function(ppe, 'airoha_ppe_offload_setup')
assert setup.index('DEV_STATE_REGISTERED') < setup.index('airoha_ppe_npu_get(eth)')
get = ppe[ppe.index('struct airoha_ppe_dev *airoha_ppe_get_dev('):ppe.index('EXPORT_SYMBOL_GPL(airoha_ppe_get_dev)')]
assert '!test_bit(DEV_STATE_REGISTERED, &eth->state)' in get and 'err = -EPROBE_DEFER;' in get
(root / 'build/teardown-verification.json').write_text(json.dumps(dict(passed=True,
    cases=10 + int(init_result.split()[1]), cleanup_cases=10,
    initialization_cases=int(init_result.split()[1]), initialization_result=init_result.strip(),
    result=result.strip(), provider_contract_checks=4, sanitizers=['address', 'undefined']), indent=2) + '\n')
print(result, end='')
print(init_result, end='')
