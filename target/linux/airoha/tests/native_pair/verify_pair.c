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
#define FE_PSE_PORT_GDM4 9
#define AIROHA_GDM4_IDX 4
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define NOTIFY_DONE 0
enum {NETDEV_GOING_DOWN=1,NETDEV_DOWN,NETDEV_UNREGISTER,NETDEV_CHANGE,NETDEV_PRE_CHANGEADDR,NETDEV_PRECHANGEMTU,NETDEV_PRECHANGEUPPER,NETDEV_UP,NETDEV_CHANGEADDR,NETDEV_CHANGEMTU,NETDEV_CHANGEUPPER};
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
struct airoha_gdm_port; struct device;
struct airoha_eth {struct airoha_npu*npu;struct airoha_gdm_port*ports[4];struct device*dev;};
struct airoha_ppe {struct airoha_eth*eth;bool ct_native_pairs,ct_pair_failed,ct_host_ppe,ct_stopping,ct_pair_policy_allowed,ct_pair_hw_stopped;
 struct notifier_block ct_pair_policy_notifier,ct_pair_wired_notifier;u32 ct_pair_wired_epoch;bool ct_pair_wired_blocked;
 u32 ct_pair_token,ct_wlan_epoch[2][151];bool ct_wlan_blocked[2][151];struct airoha_ct_native_pair*ct_pairs;};
struct airoha_wdma_info {u8 idx,bss;u16 wcid;};
struct airoha_ct_bridge_peer {u32 epoch;u16 wcid;u8 band,bss;};
struct device_node {int id;};
struct device {struct device*parent;struct device_node*of_node;};struct wiphy {struct device dev;};struct wireless_dev {struct wiphy*wiphy;};
struct net_device {struct wireless_dev*ieee80211_ptr;struct net_device*master;
 int ifindex,state;u32 flags;bool bridge,master_bridge,vlan,running,carrier;struct airoha_wdma_info wdma;int wdma_err;};
struct airoha_gdm_dev {int nbq;struct net_device*netdev;};
struct airoha_gdm_port {int id;struct airoha_gdm_dev*devs[2];};
static bool airoha_is_7581(struct airoha_eth*eth){return !!eth;}
static struct net_device*netdev_from_priv(struct airoha_gdm_dev*d){return d->netdev;}
static bool netif_running(struct net_device*d){return d->running;}
static bool netif_carrier_ok(struct net_device*d){return d->carrier;}
static struct net_device*netdev_notifier_info_to_dev(void*p){return p;}
static struct device_node*phandle,*phandle_input;
static struct device_node*of_parse_phandle(struct device_node*n,const char*key,int i){assert(!strcmp(key,"airoha,eth")&&!i);return n&&n==phandle_input?phandle:NULL;}
static void of_node_put(struct device_node*n){(void)n;}
struct ethhdr {u8 h_dest[6],h_source[6];u16 h_proto;};
struct sk_buff {struct net_device*dev;int skb_iif;bool vlan;struct ethhdr hdr;};
static int ppe_lock,rcu;
static bool napi;
static unsigned fdb_reads,fdb_reads_locked,fdb_move;
static unsigned long fdb_flags[2];
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
static bool netif_is_bridge_master(const struct net_device*d){return d->master_bridge;}
static bool br_vlan_enabled(struct net_device*d){return d->vlan;}
static int br_port_get_stp_state(struct net_device*d){return d->state;}
static bool br_port_flag_is_set(struct net_device*d,u32 f){return d->flags&f;}
enum { BR_FDB_LOCAL,BR_FDB_LOCKED,BR_FDB_ADDED_BY_USER,BR_FDB_STATIC,BR_FDB_ADDED_BY_EXT_LEARN };
struct net_bridge {int unused;};
struct net_bridge_port {struct net_device*dev;};
struct net_bridge_fdb_entry {struct net_bridge_port*dst;unsigned long flags;};
static struct net_bridge br;
static bool rcu_read_lock_held(void){return rcu>0;}
#define RCU_LOCKDEP_WARN(condition,message) assert(!(condition))
static bool test_bit(unsigned bit,const unsigned long*flags){return !!(*flags&(1ul<<bit));}
static struct net_bridge*netdev_priv(const struct net_device*d){assert(d&&d->master_bridge&&rcu);return &br;}
static struct net_bridge_fdb_entry*br_fdb_find_rcu(struct net_bridge*b,const u8*a,u16 v){
 static struct net_bridge_port ports[2];static struct net_bridge_fdb_entry entries[2];
 assert(b==&br&&v==0&&rcu&&napi);fdb_reads++;fdb_reads_locked+=!!ppe_lock;
 if(fdb_move==1&&fdb_reads==3)fdbsrc=fdbdst;
 if(fdb_move==2&&fdb_reads==4)fdbdst=fdbsrc;
 unsigned i=a[0]!=2;struct net_device*d=i?fdbdst:fdbsrc;if(!d)return NULL;
 ports[i].dev=d;entries[i]=(struct net_bridge_fdb_entry){.dst=&ports[i],.flags=fdb_flags[i]};return &entries[i];
}
#include "bridge_fdb_lookup.inc"
#include "wiphy_dev.inc"
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
static struct device_node eth_node={1},wifi_node={2};
static struct device pci_bridge;
static struct device eth_dev={.of_node=&eth_node},wifi_dev={.parent=&pci_bridge,.of_node=&wifi_node};
static struct airoha_eth eth={.npu=&npu,.dev=&eth_dev};
static struct airoha_gdm_dev wired;static struct airoha_gdm_port gdm4;
static struct airoha_ppe ppe;
static struct wiphy phy={.dev.parent=&wifi_dev};static struct wireless_dev wd={.wiphy=&phy};
static struct net_device master,src,dst;
static struct sk_buff skb;
static void reset(void){
 memset(pairs,0,sizeof pairs);memset(rows,0,sizeof rows);ppe=(struct airoha_ppe){.eth=&eth,.ct_native_pairs=true,.ct_host_ppe=true,.ct_pair_policy_allowed=true,.ct_pairs=pairs};
 ppe_lock=rcu=0;napi=false;fdb_reads=fdb_reads_locked=fdb_move=0;fdb_flags[0]=fdb_flags[1]=0;ticks=0;generation=1;writes=reads=failclosed=calls=put_count=retries=0;send_error=read_error=write_error=stop_error=0;barrier_complete=false;
 master=(struct net_device){.master_bridge=true};src=(struct net_device){.ieee80211_ptr=&wd,.master=&master,.ifindex=1,.state=3,.bridge=true,.wdma={0,2,7}};
 dst=(struct net_device){.ieee80211_ptr=&wd,.master=&master,.ifindex=2,.state=3,.bridge=true,.wdma={1,3,8}};
 wired=(struct airoha_gdm_dev){.nbq=0,.netdev=&dst};gdm4=(struct airoha_gdm_port){.id=4,.devs={&wired}};eth.ports[3]=&gdm4;phandle=&eth_node;phandle_input=&wifi_node;wifi_dev.of_node=&wifi_node;phy.dev.parent=&wifi_dev;
 devices[1]=fdbsrc=&src;devices[2]=fdbdst=&dst;skb=(struct sk_buff){.dev=&dst,.skb_iif=1,.hdr={.h_source={2},.h_dest={4},.h_proto=htons(ETH_P_IP)}};
}
enum {SWITCHDEV_BRIDGE_NATIVE_PAIR_FRAME=42};
struct switchdev_notifier_info {int unused;};
struct switchdev_notifier_native_pair_info {struct switchdev_notifier_info info;struct sk_buff*skb;};
static bool is_multicast_ether_addr(const u8*a){return !!(a[0]&1);}
static void call_switchdev_notifiers(unsigned event,struct net_device*d,struct switchdev_notifier_info*info,void*extack){
 struct switchdev_notifier_native_pair_info*frame=container_of(info,struct switchdev_notifier_native_pair_info,info);
 assert(event==SWITCHDEV_BRIDGE_NATIVE_PAIR_FRAME&&d==frame->skb->dev&&!extack&&rcu&&napi&&!ppe_lock);
 airoha_ct_native_pair_frame(&ppe,frame->skb);
}
static void frame(void){struct sk_buff*packet=&skb;struct sk_buff*skb=packet;napi=true;
#include "bridge_frame_notify.inc"
 napi=false;assert(!ppe_lock&&!rcu);
}
static void learned(u32 h){struct airoha_ct_pair_msg*m=&pairs[0].msg;rows[h]=(struct airoha_foe_entry){.ib1=FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE,AIROHA_FOE_STATE_UNBIND)|FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE,PPE_PKT_TYPE_BRIDGE)};
 rows[h].l2b.src_mac_hi=get_unaligned_be32(m->smac);rows[h].l2b.src_mac_lo=get_unaligned_be16(m->smac+4);rows[h].l2b.dest_mac_hi=get_unaligned_be32(m->dmac);rows[h].l2b.dest_mac_lo=get_unaligned_be16(m->dmac+4);rows[h].l2b.key=0xa55a1234;}
static void test_bind(u32 h,struct airoha_ct_bridge_peer*peer){spin_lock_bh(&ppe_lock);airoha_ct_native_pair_bind(&ppe,&skb,h,peer);spin_unlock_bh(&ppe_lock);}
static int revoke(int band,u16 wcid){int e;spin_lock_bh(&ppe_lock);e=airoha_ct_native_pair_revoke(&ppe,band,wcid);spin_unlock_bh(&ppe_lock);return e;}
static void wired_reset(void){reset();dst.ieee80211_ptr=NULL;dst.running=dst.carrier=true;}
static int wired_event(unsigned long event){return airoha_ct_pair_wired_event(&ppe.ct_pair_wired_notifier,event,&dst);}
int main(void){
 unsigned cases=0;
 for(unsigned mode=0;mode<24;mode++){
  reset();switch(mode){case 1:ppe.ct_native_pairs=false;break;case 2:skb.vlan=true;break;case 3:skb.hdr.h_proto=htons(0x0806);break;case 4:generation=0;break;case 5:skb.skb_iif=0;break;case 6:src.wdma_err=-1;break;case 7:dst.wdma_err=-1;break;case 8:master.vlan=true;break;case 9:src.flags=BR_ISOLATED;break;case 10:dst.flags=BR_PORT_LOCKED;break;case 11:src.state=0;break;case 12:fdbsrc=NULL;break;case 13:fdbdst=NULL;break;case 14:src.wdma.wcid=0;break;case 15:dst.wdma.wcid=151;break;case 16:ppe.ct_wlan_blocked[0][7]=true;break;case 17:ppe.ct_wlan_epoch[1][8]=U32_MAX;break;case 18:ppe.ct_pair_failed=true;break;case 19:ppe.ct_stopping=true;break;case 20:ppe.ct_host_ppe=false;break;case 21:skb.hdr.h_source[0]|=1;break;case 22:dst.master=NULL;break;case 23:ppe.ct_pair_policy_allowed=false;break;}
  frame();assert(put_count==(mode==0));cases++;
 }
 /* Actual switchdev lookup and the actual bridge notifier RCU scope execute
  * with a simulated NAPI caller; no RTNL primitive is supplied by this harness.
  * Both admission passes must stay inside that scope, including ppe_lock. */
 reset();frame();assert(put_count==1&&fdb_reads==4&&fdb_reads_locked==2);cases++;
 const unsigned long flags[]={0,BIT(BR_FDB_LOCAL),BIT(BR_FDB_LOCKED),BIT(BR_FDB_ADDED_BY_USER),BIT(BR_FDB_ADDED_BY_EXT_LEARN),BIT(BR_FDB_ADDED_BY_USER)|BIT(BR_FDB_STATIC),BIT(BR_FDB_ADDED_BY_USER)|BIT(BR_FDB_ADDED_BY_EXT_LEARN),BIT(BR_FDB_STATIC),BIT(BR_FDB_LOCAL)|BIT(BR_FDB_STATIC)|BIT(BR_FDB_ADDED_BY_USER)};
 for(unsigned side=0;side<2;side++)for(unsigned mode=0;mode<sizeof(flags)/sizeof(flags[0]);mode++){
  reset();fdb_flags[side]=flags[mode];frame();assert(put_count==(mode==0||mode==5||mode==6||mode==7));cases++;
 }
 for(unsigned side=1;side<=2;side++){reset();fdb_move=side;frame();assert(!put_count&&!pairs[0].used);cases++;}
 reset();rcu_read_lock();assert(!br_switchdev_fdb_find_port(&src,skb.hdr.h_source,0));rcu_read_unlock();assert(!fdb_reads);cases++;
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
 /* All existing WLAN pair cases above remain live. The wired cases execute
  * the same compiled functions with real ABI and FOE layout declarations. */
 for(unsigned mode=0;mode<17;mode++){
  wired_reset();switch(mode){case 1:dst.running=false;break;case 2:dst.carrier=false;break;case 3:ppe.ct_pair_wired_blocked=true;break;case 4:ppe.ct_pair_wired_epoch=U32_MAX;break;case 5:eth.ports[3]=NULL;break;case 6:gdm4.id=3;break;case 7:wired.nbq=1;break;case 8:phandle=NULL;break;case 9:phandle=&wifi_node;break;case 10:fdbdst=&src;break;case 11:dst.state=0;break;case 12:dst.flags=BR_ISOLATED;break;case 13:master.vlan=true;break;case 14:src.ieee80211_ptr=NULL;break;case 15:src.wdma.wcid=151;break;case 16:ppe.ct_pair_policy_allowed=false;break;}
  frame();assert(put_count==(mode==0));
  if(!mode){assert(pairs[0].msg.src_selector==1&&pairs[0].msg.dst_selector==2&&pairs[0].msg.dst_wcid==24&&pairs[0].msg.dst_bss==0&&pairs[0].msg.dst_epoch==1);learned(0x912);test_bind(0x912,&peer);assert(writes==1);assert(FIELD_GET(AIROHA_FOE_IB2_PSE_PORT,rows[0x912].l2b.ib2)==9);assert(!FIELD_GET(AIROHA_FOE_IB2_NBQ,rows[0x912].l2b.ib2));assert(rows[0x912].l2b.ib2&AIROHA_FOE_IB2_FAST_PATH);assert(FIELD_GET(AIROHA_FOE_CHANNEL,rows[0x912].l2b.data)==4);assert(!rows[0x912].l2b.etype&&!(rows[0x912].ib1&AIROHA_FOE_IB1_BIND_TTL));assert(rows[0x912].l2b.key==0xa55a1234);}
  cases++;
 }
 for(unsigned mode=0;mode<7;mode++){
  wired_reset();frame();learned(0x912);switch(mode){case 1:dst.carrier=false;break;case 2:dst.running=false;break;case 3:ppe.ct_pair_wired_blocked=true;break;case 4:ppe.ct_pair_wired_epoch++;break;case 5:dst.ifindex++;break;case 6:eth.ports[3]=NULL;break;}test_bind(0x912,&peer);assert(writes==(mode==0));cases++;
 }
 const unsigned events[]={NETDEV_GOING_DOWN,NETDEV_DOWN,NETDEV_UNREGISTER,NETDEV_CHANGE,NETDEV_PRE_CHANGEADDR,NETDEV_PRECHANGEMTU,NETDEV_PRECHANGEUPPER};
 for(unsigned i=0;i<ARRAY_SIZE(events);i++){
  wired_reset();frame();learned(0x912);test_bind(0x912,&peer);retries=3;assert(!wired_event(events[i]));assert(lastmsg.op==AIROHA_CT_PAIR_ENDPOINT_REVOKE&&lastmsg.src_selector==2&&lastmsg.src_wcid==24&&lastmsg.src_epoch==1);assert(!pairs[0].used&&writes==2&&ppe.ct_pair_wired_epoch==1);assert(ppe.ct_pair_wired_blocked==(events[i]!=NETDEV_CHANGE));if(events[i]!=NETDEV_CHANGE){frame();assert(put_count==1);}assert(!wired_event(NETDEV_UP));frame();assert(put_count==2&&pairs[0].msg.dst_epoch==2);cases++;
 }
 wired_reset();assert(!wired_event(NETDEV_CHANGE)&&!calls&&ppe.ct_pair_wired_epoch==1&&!ppe.ct_pair_wired_blocked);cases++;
 wired_reset();frame();learned(0x912);test_bind(0x912,&peer);dst.carrier=false;assert(!wired_event(NETDEV_CHANGE));assert(ppe.ct_pair_wired_blocked&&!pairs[0].used);assert(!wired_event(NETDEV_UP)&&ppe.ct_pair_wired_blocked);dst.carrier=true;assert(!wired_event(NETDEV_CHANGE)&&!ppe.ct_pair_wired_blocked);frame();assert(pairs[0].msg.dst_epoch==3);cases++;
 wired_reset();frame();send_error=-ETIMEDOUT;assert(wired_event(NETDEV_GOING_DOWN)==-ETIMEDOUT&&ppe.ct_pair_failed&&ppe.ct_pair_wired_blocked&&ppe.ct_stopping&&ppe.ct_pair_wired_epoch==0);cases++;
 wired_reset();ppe.ct_pair_wired_epoch=U32_MAX;assert(wired_event(NETDEV_CHANGE)==-EOVERFLOW&&ppe.ct_pair_failed&&ppe.ct_pair_wired_blocked&&!calls);cases++;
 wired_reset();frame();learned(0x912);test_bind(0x912,&peer);assert(!airoha_ct_pair_policy_event(&ppe.ct_pair_policy_notifier,NF_NATIVE_PAIR_PRE,NULL));assert(!pairs[0].used&&!ppe.ct_pair_policy_allowed&&writes==2);cases++;
 wired_reset();frame();learned(0x912);test_bind(0x912,&peer);assert(!revoke(-1,0)&&!pairs[0].used&&writes==2);generation++;frame();assert(put_count==2&&pairs[0].msg.generation==2);cases++;
 wired_reset();frame();learned(0x912);test_bind(0x912,&peer);rows[0x912].l2b.ib2^=1;assert(!wired_event(NETDEV_DOWN)&&writes==1&&!pairs[0].used);cases++;
 wired_reset();frame();assert(!airoha_ct_pair_wired_event(&ppe.ct_pair_wired_notifier,NETDEV_CHANGE,&src)&&put_count==1&&calls==1);cases++;
 reset();frame();assert(!wired_event(NETDEV_CHANGE)&&pairs[0].used&&put_count==1&&calls==1);cases++;
 /* Kernel wiphy_dev() returns the physical radio, not &wiphy->dev.
  * Sharing a PCI bridge must never make different radios the same owner. */
 struct wiphy phy2={.dev.parent=&wifi_dev};struct wireless_dev wd2={.wiphy=&phy2};
 struct device_node wrong_node={3};
 struct device radio2={.parent=&pci_bridge,.of_node=&wrong_node};
 reset();dst.ieee80211_ptr=&wd2;frame();assert(put_count==1);cases++;
 reset();phy2.dev.parent=&radio2;dst.ieee80211_ptr=&wd2;frame();assert(!put_count);cases++;
 wired_reset();wifi_dev.of_node=NULL;frame();assert(!put_count);cases++;
 wired_reset();phy.dev.parent=NULL;frame();assert(!put_count);cases++;
 wired_reset();phy2.dev.parent=&radio2;src.ieee80211_ptr=&wd2;frame();assert(!put_count);cases++;
 wired_reset();phandle_input=&wrong_node;pci_bridge.of_node=&wrong_node;frame();assert(!put_count);cases++;
 reset();pci_bridge.of_node=NULL;
 printf("PASS %u actual host native pair admission/binding/FDB/policy and wired endpoint/link epoch/revoke cases\n",cases);
}
