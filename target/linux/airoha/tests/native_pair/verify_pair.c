#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int32_t s32;typedef u16 __le16;typedef u32 __le32;typedef u64 __le64;
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define cpu_to_le64(x) ((u64)(x))
#define le16_to_cpu(x) ((u16)(x))
#define le32_to_cpu(x) ((u32)(x))
#define le64_to_cpu(x) ((u64)(x))
#define U32_MAX UINT32_MAX
#define U16_MAX UINT16_MAX
#define FIELD_GET(mask,val) (((val)&(mask))>>__builtin_ctz(mask))
#define FIELD_PREP(mask,val) ((((u32)(val))<<__builtin_ctz(mask))&(mask))
#define BIT(n) (UINT32_C(1)<<(n))
#define GENMASK(hi,lo) ((UINT32_MAX>>(31-(hi)))&(UINT32_MAX<<(lo)))
#define PPE_ENTRY_SIZE 80
#define DECLARE_FLEX_ARRAY(type,name) type name[0]
#undef static_assert
#define static_assert(x) _Static_assert(x,#x)
#define FE_PSE_PORT_GDM3 3
#define PPE_SRAM_NUM_ENTRIES 8192
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define BR_STATE_FORWARDING 3
#define BR_ISOLATED 1
#define BR_PORT_LOCKED 2
#define BR_HAIRPIN_MODE 4
#include "foe_layout.inc"
#include "pair_abi.inc"
struct airoha_ct_native_pair;
struct notifier_block {int unused;};
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define notifier_from_errno(e) (e)
enum{NF_NATIVE_PAIR_PRE=1,NF_NATIVE_PAIR_POST};
struct airoha_npu {struct {int(*ct_pair_cmd)(struct airoha_npu*,struct airoha_ct_pair_msg*);}ops;};
struct airoha_eth {struct airoha_npu*npu;};
struct airoha_ppe {struct airoha_eth*eth;bool ct_native_pairs,ct_pair_failed,ct_host_ppe,ct_stopping,ct_pair_policy_allowed,ct_pair_hw_stopped;
 struct notifier_block ct_pair_policy_notifier;
 u32 ct_pair_token,ct_wlan_epoch[2][151];bool ct_wlan_blocked[2][151];struct airoha_ct_native_pair*ct_pairs;};
struct airoha_wdma_info {u8 idx,bss;u16 wcid;};
struct airoha_ct_bridge_peer {u32 epoch;u16 wcid;u8 band,bss;};
struct device {void*parent;};struct wiphy {struct device dev;};struct wireless_dev {struct wiphy*wiphy;};
struct net_device {struct wireless_dev*ieee80211_ptr;struct net_device*master;
 int ifindex,state;u32 flags;bool bridge,master_bridge,vlan;struct airoha_wdma_info wdma;int wdma_err;};
struct ethhdr {u8 h_dest[6],h_source[6];u16 h_proto;};
struct sk_buff {struct net_device*dev;int skb_iif;bool vlan;struct ethhdr hdr;};
static int ppe_lock,rcu;
static u64 ticks,generation;
static struct net_device*devices[3],*fdbsrc,*fdbdst;
static struct airoha_foe_entry rows[8192];
static unsigned writes,reads,failclosed,calls,put_count,retries;
static int send_error,read_error,write_error,stop_error;
static u16 lastop;static bool barrier_complete;
static struct airoha_ct_pair_msg lastmsg;
typedef u64 ktime_t;
#define ktime_get() (ticks)
#define ktime_add_us(a,b) ((a)+(b))
#define ktime_before(a,b) ((a)<(b))
#define udelay(n) (ticks+=(n))
#define lockdep_assert_held(l) assert(*(l))
#define READ_ONCE(x) (x)
#define rcu_dereference(x) (x)
static void rcu_read_lock(void){rcu++;}
static void rcu_read_unlock(void){assert(rcu);rcu--;}
static void spin_lock_bh(int*l){assert(!*l);*l=1;}
static void spin_unlock_bh(int*l){assert(*l);*l=0;}
static bool ether_addr_equal(const u8*a,const u8*b){return !memcmp(a,b,6);}
static void ether_addr_copy(u8*a,const u8*b){memcpy(a,b,6);}
static bool is_valid_ether_addr(const u8*a){return !(a[0]&1)&&memcmp(a,"\0\0\0\0\0\0",6);}
static u32 get_unaligned_be32(const void*p){u32 x;memcpy(&x,p,4);return ntohl(x);}
static u16 get_unaligned_be16(const void*p){u16 x;memcpy(&x,p,2);return ntohs(x);}
#define eth_hdr(s) (&(s)->hdr)
#define skb_vlan_tag_present(s) ((s)->vlan)
static u64 br_flow_offload_generation(void){return generation;}
static int init_net;
static bool net_eq(int net,int*expected){return net==1&&expected==&init_net;}
static int dev_net(struct net_device*d){assert(d);return 1;}
static struct net_device*dev_get_by_index_rcu(int net,int idx){assert(net==1&&rcu);return idx>0&&idx<3?devices[idx]:NULL;}
static bool netif_is_bridge_port(struct net_device*d){return d->bridge;}
static struct net_device*netdev_master_upper_dev_get_rcu(struct net_device*d){assert(rcu);return d->master;}
static bool netif_is_bridge_master(struct net_device*d){return d->master_bridge;}
static bool br_vlan_enabled(struct net_device*d){return d->vlan;}
static int br_port_get_stp_state(struct net_device*d){return d->state;}
static bool br_port_flag_is_set(struct net_device*d,u32 f){return d->flags&f;}
static struct net_device*br_fdb_find_port(struct net_device*d,const u8*a,u16 v){assert(d&&v==0);return a[0]==2?fdbsrc:fdbdst;}
static struct device*wiphy_dev(struct wiphy*w){return &w->dev;}
static int airoha_ppe_get_wdma_info(struct net_device*d,const u8*a,struct airoha_wdma_info*w,bool bridge){assert(a&&bridge);*w=d->wdma;return d->wdma_err;}
static u32 airoha_ppe_ct_epoch_locked(struct airoha_ppe*p,u8 b,u16 w){assert(ppe_lock&&b<2&&w<151);return p->ct_wlan_blocked[b][w]||p->ct_wlan_epoch[b][w]==U32_MAX?0:p->ct_wlan_epoch[b][w]+1;}
static int airoha_ppe_ct_bridge_fail_closed(struct airoha_ppe*p){assert(ppe_lock);p->ct_stopping=true;failclosed++;return stop_error;}
static struct airoha_foe_entry*airoha_ppe_foe_get_entry_locked(struct airoha_ppe*p,u32 h){assert(p&&ppe_lock&&h<8192);reads++;return read_error?NULL:&rows[h];}
static int airoha_ppe_foe_commit_entry(struct airoha_ppe*p,struct airoha_foe_entry*e,u32 h,bool wlan){assert(p&&ppe_lock&&wlan&&h<8192);if(!FIELD_GET(AIROHA_FOE_IB1_BIND_STATE,e->ib1))assert(barrier_complete);writes++;if(write_error)return write_error;e->ib1=(e->ib1&~AIROHA_FOE_IB1_BIND_TIMESTAMP)|123;rows[h]=*e;return 0;}
static int mock_send(struct airoha_npu*n,struct airoha_ct_pair_msg*m){assert(n&&(m->op==AIROHA_CT_PAIR_CAP||(ppe_lock&&rcu)));calls++;lastmsg=*m;lastop=m->op;if(retries){retries--;return -EAGAIN;}if(send_error)return send_error;if(m->op==AIROHA_CT_PAIR_PUT)put_count++;else barrier_complete=true;return 0;}
#include "airoha_ct_native_pair.h"
#include "pair_policy_event.inc"
static struct airoha_ct_native_pair pairs[32];
static struct airoha_npu npu={.ops.ct_pair_cmd=mock_send};
static struct airoha_eth eth={.npu=&npu};
static struct airoha_ppe ppe;
static struct wiphy phy={.dev.parent=(void*)1};static struct wireless_dev wd={.wiphy=&phy};
static struct net_device master,src,dst;
static struct sk_buff skb;
static void reset(void){
 memset(pairs,0,sizeof pairs);memset(rows,0,sizeof rows);ppe=(struct airoha_ppe){.eth=&eth,.ct_native_pairs=true,.ct_host_ppe=true,.ct_pair_policy_allowed=true,.ct_pairs=pairs};
 ppe_lock=rcu=0;ticks=0;generation=1;writes=reads=failclosed=calls=put_count=retries=0;send_error=read_error=write_error=stop_error=0;barrier_complete=false;
 master=(struct net_device){.master_bridge=true};src=(struct net_device){.ieee80211_ptr=&wd,.master=&master,.ifindex=1,.state=3,.bridge=true,.wdma={0,2,7}};
 dst=(struct net_device){.ieee80211_ptr=&wd,.master=&master,.ifindex=2,.state=3,.bridge=true,.wdma={1,3,8}};
 devices[1]=fdbsrc=&src;devices[2]=fdbdst=&dst;skb=(struct sk_buff){.dev=&dst,.skb_iif=1,.hdr={.h_source={2},.h_dest={4},.h_proto=htons(ETH_P_IP)}};
}
static void frame(void){rcu_read_lock();airoha_ct_native_pair_frame(&ppe,&skb);rcu_read_unlock();assert(!ppe_lock&&!rcu);}
static void learned(u32 h){struct airoha_ct_pair_msg*m=&pairs[0].msg;rows[h]=(struct airoha_foe_entry){.ib1=FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE,AIROHA_FOE_STATE_UNBIND)|FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE,PPE_PKT_TYPE_BRIDGE)};
 rows[h].l2b.src_mac_hi=get_unaligned_be32(m->smac);rows[h].l2b.src_mac_lo=get_unaligned_be16(m->smac+4);rows[h].l2b.dest_mac_hi=get_unaligned_be32(m->dmac);rows[h].l2b.dest_mac_lo=get_unaligned_be16(m->dmac+4);rows[h].l2b.key=0xa55a1234;}
static void test_bind(u32 h,struct airoha_ct_bridge_peer*peer){spin_lock_bh(&ppe_lock);airoha_ct_native_pair_bind(&ppe,&skb,h,peer);spin_unlock_bh(&ppe_lock);}
static int revoke(int band,u16 wcid){int e;spin_lock_bh(&ppe_lock);e=airoha_ct_native_pair_revoke(&ppe,band,wcid);spin_unlock_bh(&ppe_lock);return e;}
int main(void){
 unsigned cases=0;
 for(unsigned mode=0;mode<24;mode++){
  reset();switch(mode){case 1:ppe.ct_native_pairs=false;break;case 2:skb.vlan=true;break;case 3:skb.hdr.h_proto=htons(0x0806);break;case 4:generation=0;break;case 5:skb.skb_iif=0;break;case 6:src.wdma_err=-1;break;case 7:dst.wdma_err=-1;break;case 8:master.vlan=true;break;case 9:src.flags=BR_ISOLATED;break;case 10:dst.flags=BR_PORT_LOCKED;break;case 11:src.state=0;break;case 12:fdbsrc=NULL;break;case 13:fdbdst=NULL;break;case 14:src.wdma.wcid=0;break;case 15:dst.wdma.wcid=151;break;case 16:ppe.ct_wlan_blocked[0][7]=true;break;case 17:ppe.ct_wlan_epoch[1][8]=U32_MAX;break;case 18:ppe.ct_pair_failed=true;break;case 19:ppe.ct_stopping=true;break;case 20:ppe.ct_host_ppe=false;break;case 21:skb.hdr.h_source[0]|=1;break;case 22:dst.master=NULL;break;case 23:ppe.ct_pair_policy_allowed=false;break;}
  frame();assert(put_count==(mode==0));cases++;
 }
 reset();frame();frame();assert(put_count==1&&pairs[0].msg.src_selector==1&&pairs[0].msg.dst_selector==0&&pairs[0].msg.src_epoch==1);cases++;
 struct airoha_ct_bridge_peer peer={.epoch=1,.band=0,.bss=2,.wcid=7};
 for(unsigned mode=0;mode<14;mode++){
  reset();frame();learned(0x900);struct airoha_ct_bridge_peer p=peer;
  switch(mode){case 1:p.epoch++;break;case 2:p.wcid++;break;case 3:p.band=1;break;case 4:p.bss++;break;case 5:generation++;break;case 6:ppe.ct_wlan_epoch[1][8]++;break;case 7:rows[0x900].l2b.ingress_vlan=1;break;case 8:rows[0x900].l2b.src_mac_hi^=1;break;case 9:rows[0x900].ib1|=AIROHA_FOE_IB1_BIND_STATIC;break;case 10:skb.hdr.h_dest[0]^=2;break;case 11:rows[0x900].ib1=0;break;case 12:ppe.ct_pair_failed=true;break;case 13:ppe.ct_pair_policy_allowed=false;break;}
  test_bind(0x900,&p);assert(writes==(mode==0));if(!mode){assert(rows[0x900].l2b.key==0xa55a1234);assert(!(rows[0x900].ib1&AIROHA_FOE_IB1_BIND_TTL));assert(rows[0x900].l2b.etype==(8<<6|3));assert(!revoke(-1,0));assert(writes==2&&!pairs[0].used);}cases++;
 }
 reset();frame();learned(0x268);test_bind(8192,&peer);assert(!writes);cases++;
 reset();frame();learned(0x268);test_bind(0x268,&peer);retries=5;assert(!revoke(0,7));assert(calls==7&&lastop==4&&lastmsg.src_selector==1&&lastmsg.src_epoch==1&&writes==2);cases++;
 reset();frame();learned(0x268);test_bind(0x268,&peer);retries=20000;assert(revoke(-1,0)==-ETIMEDOUT&&ppe.ct_pair_failed&&ppe.ct_stopping&&writes==1&&pairs[0].used);cases++;
 reset();frame();learned(0x268);test_bind(0x268,&peer);rows[0x268].l2b.ib2^=1;assert(!revoke(-1,0)&&writes==1&&!pairs[0].used);cases++;
 reset();frame();learned(0x268);test_bind(0x268,&peer);read_error=-ETIMEDOUT;assert(revoke(-1,0)==-ETIMEDOUT&&ppe.ct_pair_failed&&pairs[0].used);cases++;
 reset();send_error=-ETIMEDOUT;frame();assert(ppe.ct_pair_failed&&ppe.ct_stopping&&pairs[0].used);cases++;
 reset();ppe.ct_pair_token=U32_MAX;frame();assert(ppe.ct_pair_failed&&!calls);cases++;
 reset();ppe.ct_wlan_epoch[0][7]=U32_MAX;assert(revoke(0,7)==-EOVERFLOW&&!calls);cases++;
 reset();frame();learned(0x268);write_error=-ETIMEDOUT;test_bind(0x268,&peer);assert(pairs[0].hashes[0]==0x268&&ppe.ct_pair_failed);cases++;
 reset();frame();for(unsigned h=0;h<4;h++){learned(h);test_bind(h,&peer);}learned(4);test_bind(4,&peer);assert(writes==4);assert(!revoke(-1,0)&&writes==8);cases++;
 reset();for(unsigned i=0;i<32;i++){skb.hdr.h_dest[5]=i;frame();}assert(put_count==32);skb.hdr.h_dest[5]=32;frame();assert(put_count==32);cases++;
 reset();frame();learned(0x268);test_bind(0x268,&peer);assert(!airoha_ct_pair_policy_event(&ppe.ct_pair_policy_notifier,NF_NATIVE_PAIR_PRE,NULL));assert(!ppe.ct_pair_policy_allowed&&!pairs[0].used&&writes==2);frame();assert(put_count==1);assert(!airoha_ct_pair_policy_event(&ppe.ct_pair_policy_notifier,NF_NATIVE_PAIR_POST,NULL));assert(!ppe.ct_pair_policy_allowed);cases++;
 reset();frame();send_error=-ETIMEDOUT;assert(airoha_ct_pair_policy_event(&ppe.ct_pair_policy_notifier,NF_NATIVE_PAIR_PRE,NULL)==-ETIMEDOUT);assert(!ppe.ct_pair_policy_allowed&&ppe.ct_pair_failed);assert(!airoha_ct_pair_policy_event(&ppe.ct_pair_policy_notifier,NF_NATIVE_PAIR_POST,NULL));assert(!ppe.ct_pair_policy_allowed);cases++;
 reset();struct airoha_ct_pair_msg cap={.op=AIROHA_CT_PAIR_CAP};retries=5;assert(!airoha_ct_pair_exchange(&npu,&cap)&&calls==6&&!ppe_lock&&!rcu);cases++;
 reset();retries=20000;assert(airoha_ct_pair_exchange(&npu,&cap)==-ETIMEDOUT&&!ppe_lock&&!rcu);cases++;
 reset();send_error=-EPROTO;stop_error=-EBUSY;frame();assert(ppe.ct_pair_failed&&!ppe.ct_pair_hw_stopped);spin_lock_bh(&ppe_lock);assert(airoha_ct_pair_fail(&ppe,-EPROTO)==-EBUSY);spin_unlock_bh(&ppe_lock);cases++;
 printf("PASS %u native host pair admission, bank0 binding, epoch, FDB, revoke barrier, row reuse, timeout and overflow cases\n",cases);
}
