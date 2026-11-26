#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define U32_MAX UINT32_MAX
#define READ_ONCE(x) (x)
#define EXPORT_SYMBOL_GPL(x)
struct list_head {int unused;};
#define LIST_HEAD(x) struct list_head x={0}
struct airoha_eth {bool ct_cpu_fallback,ct_cpu_routes_ready,ct_cpu_ifc_disabled,ct_cpu_wlan_gated;int flow_table;};
struct airoha_ppe {struct airoha_eth*eth;bool ct_stopping,ct_host_ppe,ct_native_pairs,ct_pair_failed,ct_pair_hw_stopped;struct{bool health_stopping;}ct_fe;u32 ct_wlan_epoch[2][151];bool ct_wlan_blocked[2][151];u32 retained_owner,retained_inflight;};
struct airoha_ppe_dev {struct airoha_ppe*priv;};
struct airoha_flow_table_entry {void*egress_dev;int data,node;bool ct_bridge;struct{u8 band;u16 wcid;}ct_src;struct list_head gc_node;};
struct rhashtable_iter {int unused;};
static struct airoha_eth eth;
static struct airoha_ppe ppe;
static struct airoha_ppe_dev pdev={.priv=&ppe};
static int flow_offload_mutex,ppe_lock,airoha_flow_table_params;
static unsigned revoke_calls,walk_calls,remove_calls,free_calls;
static int revoke_error;
static bool fault_on_lock;
static void spin_lock_bh(int*p){assert(!*p);*p=1;if(fault_on_lock){fault_on_lock=false;ppe.ct_stopping=true;}}
static void spin_unlock_bh(int*p){assert(*p);*p=0;}
static void mutex_lock(int*p){assert(!*p&&!ppe_lock);*p=1;}
static void mutex_unlock(int*p){assert(*p&&!ppe_lock);*p=0;}
#define lockdep_assert_held(p) assert(*(p))
static int airoha_ct_native_pair_revoke(struct airoha_ppe*p,int band,u16 wcid){assert(p&&ppe_lock&&flow_offload_mutex&&band<=1&&wcid);revoke_calls++;return revoke_error;}
static void rhashtable_walk_enter(int*t,struct rhashtable_iter*i){assert(t&&i&&flow_offload_mutex&&!ppe_lock);walk_calls++;}
static void rhashtable_walk_start(struct rhashtable_iter*i){assert(i);}
static void*rhashtable_walk_next(struct rhashtable_iter*i){assert(i);return NULL;}
static void rhashtable_walk_stop(struct rhashtable_iter*i){assert(i);}
static void rhashtable_walk_exit(struct rhashtable_iter*i){assert(i);}
#define IS_ERR(p) false
static bool list_empty(struct list_head*h){assert(h);return true;}
static bool airoha_ppe_ct_wlan_entry(int*d,u8 b,u16 w){assert(d&&b<=1&&w);return true;}
static void list_add_tail(struct list_head*a,struct list_head*b){assert(a&&b);}
#define list_for_each_entry_safe(e,tmp,head,member) for((e)=NULL,(tmp)=NULL;(e);(e)=(tmp))
static void list_del_init(struct list_head*h){assert(h);}
static int airoha_ppe_ct_remove_wlan_flow(struct airoha_ppe*p,struct airoha_flow_table_entry*e){assert(p&&e);remove_calls++;return 0;}
static void rhashtable_remove_fast(int*t,int*n,int p){assert(t&&n);(void)p;}
static void kfree(void*p){assert(p);free_calls++;}
#include "station_functions.inc"
static void reset(void){
 memset(&eth,0,sizeof eth);memset(&ppe,0,sizeof ppe);ppe.eth=&eth;
 ppe.ct_stopping=ppe.ct_host_ppe=ppe.ct_native_pairs=ppe.ct_pair_failed=ppe.ct_pair_hw_stopped=true;
 eth.ct_cpu_fallback=eth.ct_cpu_routes_ready=eth.ct_cpu_ifc_disabled=eth.ct_cpu_wlan_gated=true;
 ppe.retained_owner=0x1234;ppe.retained_inflight=1;
 revoke_calls=walk_calls=remove_calls=free_calls=0;revoke_error=0;fault_on_lock=false;
 assert(!flow_offload_mutex&&!ppe_lock);
}
/* MAIN */
int main(void){
 unsigned cases=0;const u16 wcids[]={1,7,150};
 for(unsigned band=0;band<2;band++)for(unsigned i=0;i<3;i++)for(unsigned held=0;held<2;held++){
  reset();ppe.retained_inflight=held;ppe.ct_wlan_epoch[band][wcids[i]]=held?U32_MAX:41;ppe.ct_wlan_blocked[band][wcids[i]]=held;
  struct airoha_ppe before=ppe;struct airoha_eth prior=eth;
  assert(!airoha_ppe_ct_flush_wlan(&pdev,band,wcids[i]));
  assert(!memcmp(&before,&ppe,sizeof ppe)&&!memcmp(&prior,&eth,sizeof eth));
  assert(!revoke_calls&&!walk_calls&&!remove_calls&&!free_calls&&!airoha_ppe_ct_wlan_epoch(&pdev,band,wcids[i]));cases++;
 }
 for(unsigned band=0;band<2;band++)for(unsigned guard=0;guard<9;guard++){
  reset();switch(guard){case 0:ppe.ct_host_ppe=false;break;case 1:ppe.ct_native_pairs=false;break;case 2:ppe.ct_pair_failed=false;break;case 3:ppe.ct_fe.health_stopping=true;break;case 4:ppe.ct_pair_hw_stopped=false;break;case 5:eth.ct_cpu_fallback=false;break;case 6:eth.ct_cpu_routes_ready=false;break;case 7:eth.ct_cpu_ifc_disabled=false;break;case 8:eth.ct_cpu_wlan_gated=false;break;}
  struct airoha_ppe before=ppe;struct airoha_eth prior=eth;
  assert(airoha_ppe_ct_flush_wlan(&pdev,band,7)==-ESHUTDOWN);
  assert(!memcmp(&before,&ppe,sizeof ppe)&&!memcmp(&prior,&eth,sizeof eth));
  assert(!revoke_calls&&!walk_calls&&!remove_calls&&!free_calls);cases++;
 }
 const unsigned bad[][2]={{2,1},{0,0},{1,151},{255,65535}};
 for(unsigned i=0;i<4;i++){reset();assert(airoha_ppe_ct_flush_wlan(&pdev,bad[i][0],bad[i][1])==-EINVAL&&!revoke_calls&&!walk_calls&&!flow_offload_mutex&&!ppe_lock);cases++;}
 for(unsigned band=0;band<2;band++)for(unsigned fail=0;fail<2;fail++){
  reset();ppe.ct_stopping=ppe.ct_pair_failed=false;eth.ct_cpu_fallback=false;ppe.ct_wlan_epoch[band][7]=41;
  revoke_error=fail?-EAGAIN:0;assert(airoha_ppe_ct_flush_wlan(&pdev,band,7)==revoke_error);
  assert(revoke_calls==1&&walk_calls==!fail&&ppe.ct_wlan_epoch[band][7]==(fail?41:42)&&ppe.ct_wlan_blocked[band][7]==!!fail);
  assert(airoha_ppe_ct_wlan_epoch(&pdev,band,7)==(fail?0:43));cases++;
 }
 reset();ppe.ct_stopping=false;fault_on_lock=true;
 assert(!airoha_ppe_ct_flush_wlan(&pdev,0,7)&&ppe.ct_stopping&&!revoke_calls&&!walk_calls);cases++;
 reset();ppe.ct_stopping=ppe.ct_host_ppe=false;
 assert(!airoha_ppe_ct_flush_wlan(&pdev,1,7)&&!revoke_calls&&!walk_calls&&!airoha_ppe_ct_wlan_epoch(&pdev,1,7));cases++;
 printf("PASS %u station fault cutover, retained ownership, epoch and teardown cases\n",cases);
}
