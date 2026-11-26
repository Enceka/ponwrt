#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t __be16;
typedef uint16_t __u16;
#define U8_MAX UINT8_MAX
#define U16_MAX UINT16_MAX
#define U32_MAX UINT32_MAX
#define BIT(n) (UINT32_C(1) << (n))
#define BIT_ULL(n) (UINT64_C(1) << (n))
#define GENMASK(h,l) ((UINT32_MAX >> (31-(h))) & (UINT32_MAX << (l)))
#define FIELD_GET(m,v) (((v)&(m)) >> __builtin_ctz(m))
#define FIELD_PREP(m,v) (((u32)(v) << __builtin_ctz(m)) & (m))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define READ_ONCE(v) (v)
#define DECLARE_FLEX_ARRAY(t,n) t n[0]
#define PPE_ENTRY_SIZE 80
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_8021Q 0x8100
#define ARPHRD_ETHER 1
#define IFF_LOOPBACK 8
#define AIROHA_DEV_F_PON 1
#define AIROHA_MAX_DSA_PORTS 7
#define AIROHA_PON_QDMA_HQOS_CFG 0x90
#define AIROHA_PON_QDMA_HQOS_EN BIT(31)
#define FE_PSE_PORT_GDM3 3
#undef static_assert
#define static_assert(e) _Static_assert(e,#e)
#include "foe_types.inc"

enum {
 FLOW_DISSECTOR_KEY_META, FLOW_DISSECTOR_KEY_CONTROL, FLOW_DISSECTOR_KEY_BASIC,
 FLOW_DISSECTOR_KEY_PORTS, FLOW_DISSECTOR_KEY_IPV4_ADDRS, FLOW_DISSECTOR_KEY_IPV6_ADDRS,
 FLOW_DISSECTOR_KEY_ETH_ADDRS, FLOW_DISSECTOR_KEY_IP, FLOW_DISSECTOR_KEY_TCP,
 FLOW_DISSECTOR_KEY_VLAN, FLOW_DISSECTOR_KEY_CVLAN, FLOW_DISSECTOR_KEY_PPPOE,
 FLOW_DISSECTOR_KEY_ENC_CONTROL
};
struct key_meta { u32 ingress_ifindex; u16 ingress_iftype; u8 l2_miss; };
struct key_control { u16 thoff,addr_type; u32 flags; };
struct key_basic { u16 n_proto; u8 ip_proto; };
struct key_ports { u16 src,dst; };
struct key_ipv4_addrs { u32 src,dst; };
struct key_ipv6_addrs { struct in6_addr src,dst; };
struct key_eth_addrs { u8 dst[6],src[6]; };
struct key_ip { u8 tos,ttl; };
struct key_tcp { u16 flags; };
struct flow_dissector { u64 used_keys; };
struct keys {
 struct key_meta meta; struct key_control control; struct key_basic basic;
 struct key_ports ports; struct key_ipv4_addrs ipv4_addrs;
 struct key_ipv6_addrs ipv6_addrs; struct key_eth_addrs eth_addrs;
 struct key_ip ip; struct key_tcp tcp;
};
struct flow_rule { struct { struct flow_dissector *dissector; } match; struct keys key,mask; };
#define MATCH(n) struct flow_match_##n { struct key_##n *key,*mask; }; \
 static void flow_rule_match_##n(struct flow_rule *r,struct flow_match_##n *m) {m->key=&r->key.n;m->mask=&r->mask.n;}
MATCH(meta) MATCH(control) MATCH(basic) MATCH(ports) MATCH(ipv4_addrs)
MATCH(ipv6_addrs) MATCH(eth_addrs) MATCH(ip) MATCH(tcp)
static bool flow_rule_match_key(struct flow_rule *r,unsigned k) {return !!(r->match.dissector->used_keys & BIT_ULL(k));}
static void *memchr_inv(const void *p,int c,size_t n) {const u8 *s=p;for(size_t i=0;i<n;i++)if(s[i]!=(u8)c)return (void*)&s[i];return NULL;}
static bool is_zero_ether_addr(const u8 *p) {return !memchr_inv(p,0,6);}
static bool is_valid_ether_addr(const u8 *p) {return !(p[0]&1) && !is_zero_ether_addr(p);}
static bool ether_addr_equal(const u8 *a,const u8 *b) {return !memcmp(a,b,6);}

struct net {int id;};
struct airoha_eth;
struct net_device {
 int ifindex; struct net *net; void *priv,*ieee80211_ptr;
 struct net_device *dsa_conduit;
 bool running,carrier,uses_dsa; int dsa_port; unsigned refs,flags,type,addr_len; u8 dev_addr[6];
};
struct airoha_qdma {u32 hqos;};
struct airoha_gdm_dev {struct airoha_eth *eth;struct net_device *netdev;unsigned long flags;bool pon_update_blocked;struct airoha_qdma *qdma;};
struct airoha_gdm_port {struct airoha_gdm_dev *devs[4];};
struct airoha_ppe;
struct airoha_eth {struct airoha_gdm_port *ports[4];struct airoha_qdma qdma[2];struct airoha_ppe *ppe;int flow_table;};
static struct net_device *devices[8];
static struct net *dev_net(struct net_device *n) {return n->net;}
static bool net_eq(struct net *a,struct net *b) {return a==b;}
static struct net_device *dev_get_by_index(struct net *n,u32 i) {for(unsigned k=0;k<8;k++)if(devices[k] && devices[k]->net==n && (u32)devices[k]->ifindex==i){devices[k]->refs++;return devices[k];}return NULL;}
static void dev_put(struct net_device *n) {assert(n->refs);n->refs--;}
static void *netdev_priv(struct net_device *n) {return n->priv?n->priv:n;}
static struct net_device *netdev_from_priv(struct airoha_gdm_dev *d) {return d->netdev;}
static bool netdev_uses_dsa(struct net_device *n) {return n->uses_dsa;}
static bool netif_running(struct net_device *n) {return n->running;}
static bool netif_carrier_ok(struct net_device *n) {return n->carrier;}
static bool test_bit(unsigned bit,unsigned long *v) {return !!(*v & (1UL<<bit));}
static int airoha_get_dsa_port(struct net_device **n) {if((*n)->dsa_conduit){int port=(*n)->dsa_port;*n=(*n)->dsa_conduit;return port;}return -ENODEV;}
#define rcu_access_pointer(p) (p)
static u32 airoha_qdma_rr(struct airoha_qdma *q,u32 reg) {assert(reg==0x90);return q->hqos;}

enum {FLOW_TYPE_L4,FLOW_TYPE_L2,FLOW_TYPE_L2_SUBFLOW};
struct hlist_node {bool linked;};
struct ethhdr {u8 h_dest[6],h_source[6];u16 h_proto;};
#define METADATA_HW_PORT_MUX 3
struct metadata_dst {int type; union {struct {int port_id;} port_info;} u;};
struct sk_buff {struct net_device *dev;struct ethhdr hdr;struct metadata_dst *md;bool vlan_tag;};
static bool skb_vlan_tag_present(struct sk_buff *s) {return s->vlan_tag;}
static struct metadata_dst *skb_metadata_dst(struct sk_buff *s) {return s->md;}
struct airoha_ct_bridge_peer {u32 epoch;};
struct airoha_flow_table_entry {
 struct hlist_node list; struct airoha_gdm_dev *egress_dev,*pon_ingress_dev,*ct_ingress_gdm; int ct_ingress_dsa_port;
 int type,ct_ingress_ifindex,node,ct_bridge_node; bool ct_bridge; u32 hash; u64 ct_bridge_generation; struct airoha_foe_entry data;
 struct airoha_ct_bridge_peer ct_dest;
};
struct airoha_ppe {
 struct airoha_eth *eth;bool ct_host_ppe,ct_pon_qualified,ct_stopping,ct_native_pairs,ct_bridge_failed;int ct_bridge_flows;
 struct airoha_flow_table_entry *foe_flow[1];int l2_flows;
 u32 ct_wlan_epoch[2][151];bool ct_wlan_blocked[2][151];
};
static int ppe_lock,airoha_l2_flow_table_params;
static struct airoha_foe_entry learned;
static unsigned commits,links,cookies,removed_cookies;
static int flow_offload_mutex=1,airoha_flow_table_params,index_error;
#define lockdep_assert_held(p) assert(*(p))
static void spin_lock_bh(int *l) {assert(!*l);*l=1;}
static void spin_unlock_bh(int *l) {assert(*l);*l=0;}
#define hlist_for_each_entry(e,h,m) for((e)=*(h);(e);(e)=NULL)
static void hlist_add_head(struct hlist_node *n,struct airoha_flow_table_entry **h) {assert(ppe_lock);*h=(void*)((char*)n - offsetof(struct airoha_flow_table_entry,list));n->linked=true;links++;}
static void list_add_tail(int *n,int *h) {(void)n;(void)h;assert(false);}
static u64 br_flow_offload_generation(void) {return 3;}
static int airoha_ppe_foe_l2_flow_commit_entry(struct airoha_ppe *p,struct airoha_flow_table_entry *e) {(void)p;(void)e;assert(false);return 0;}
static int rhashtable_insert_fast(int *t,int *n,int p) {(void)t;(void)n;(void)p;if(index_error)return index_error;cookies++;return 0;}
static void rhashtable_remove_fast(int *t,int *n,int p) {(void)t;(void)n;(void)p;assert(cookies);cookies--;removed_cookies++;}
#define hlist_for_each_entry_safe(e,n,h,m) for((e)=*(h),(n)=NULL;(e);(e)=NULL)
static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *p,u32 hash) {(void)p;assert(ppe_lock && hash==5);return &learned;}
static bool airoha_is_7581(struct airoha_eth *eth) {(void)eth;return true;}
static void airoha_ct_native_pair_bind(struct airoha_ppe *p,struct sk_buff *s,u32 h,const struct airoha_ct_bridge_peer *peer) {(void)p;(void)s;(void)h;(void)peer;assert(false);}
static u32 airoha_ppe_foe_get_entry_hash(struct airoha_ppe *p,const struct airoha_foe_entry *h) {(void)p;(void)h;return 0;}
static void airoha_ppe_foe_remove_flow(struct airoha_ppe *p,struct airoha_flow_table_entry *e) {(void)p;(void)e;assert(false);}
static bool airoha_ppe_ct_bridge_current(struct airoha_ppe *p,struct airoha_flow_table_entry *e,const struct airoha_ct_bridge_peer *peer,struct sk_buff *s) {(void)p;(void)e;(void)peer;(void)s;return true;}
static int airoha_ppe_foe_commit_entry(struct airoha_ppe *p,struct airoha_foe_entry *h,u32 hash,bool wlan) {(void)p;(void)wlan;assert(ppe_lock && hash==5);learned=*h;commits++;return 0;}
static struct ethhdr *eth_hdr(struct sk_buff *s) {return &s->hdr;}
static void airoha_ppe_foe_set_bridge_addrs(struct airoha_foe_bridge *b,struct ethhdr *h) {(void)b;(void)h;}
static struct airoha_flow_table_entry *rhashtable_lookup_fast(int *t,struct airoha_foe_bridge *b,int p) {(void)t;(void)b;(void)p;return NULL;}
static void airoha_ppe_foe_commit_subflow_entry(struct airoha_ppe *p,struct airoha_flow_table_entry *e,u32 h,bool w) {(void)p;(void)e;(void)h;(void)w;assert(false);}

#define NF_FLOW_TABLE_ENCAP_MAX 2
enum {DEV_PATH_ETHERNET,DEV_PATH_IEEE80211,DEV_PATH_DSA,DEV_PATH_MTK_WDMA,DEV_PATH_VLAN,DEV_PATH_PPPOE,DEV_PATH_BRIDGE};
enum {DEV_PATH_BR_VLAN_UNTAG_HW,DEV_PATH_BR_VLAN_KEEP_HW,DEV_PATH_BR_VLAN_TAG,DEV_PATH_BR_VLAN_UNTAG,DEV_PATH_BR_VLAN_KEEP};
enum flow_offload_xmit_type {FLOW_OFFLOAD_XMIT_NEIGH,FLOW_OFFLOAD_XMIT_DIRECT};
struct net_device_path {int type;struct net_device *dev;struct {u16 id,proto;u8 h_dest[6];} encap;struct {int vlan_mode;u16 vlan_id,vlan_proto;} bridge;};
struct net_device_path_stack {int num_paths;struct net_device_path path[4];};
struct nf_flowtable {bool hw;};
static bool nf_flowtable_hw_offload(struct nf_flowtable *f) {return f->hw;}
struct airoha_qdma_desc {u32 msg1;};
#define QDMA_ETH_RXMSG_SPORT_MASK GENMASK(25,21)
#define le32_to_cpu(x) (x)
#define fallthrough __attribute__((fallthrough))
enum {HSGMII_LAN_7581_PCIE0_SRCPORT=22,HSGMII_LAN_7581_PCIE1_SRCPORT=23,HSGMII_LAN_7581_ETH_SRCPORT=24,HSGMII_LAN_7581_USB_SRCPORT=25};
#include "admission_production.inc"

static struct flow_dissector dissector;
static struct flow_rule valid_rule(bool ipv6,bool udp) {
 struct flow_rule r={.match.dissector=&dissector};
 dissector.used_keys=BIT_ULL(FLOW_DISSECTOR_KEY_META)|BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL)|BIT_ULL(FLOW_DISSECTOR_KEY_BASIC)|BIT_ULL(FLOW_DISSECTOR_KEY_PORTS)|BIT_ULL(ipv6?FLOW_DISSECTOR_KEY_IPV6_ADDRS:FLOW_DISSECTOR_KEY_IPV4_ADDRS)|BIT_ULL(FLOW_DISSECTOR_KEY_IP);
 r.key.meta.ingress_ifindex=2;r.mask.meta.ingress_ifindex=U32_MAX;
 r.key.control.addr_type=ipv6?FLOW_DISSECTOR_KEY_IPV6_ADDRS:FLOW_DISSECTOR_KEY_IPV4_ADDRS;r.mask.control.addr_type=U16_MAX;
 r.key.basic.n_proto=htons(ipv6?ETH_P_IPV6:ETH_P_IP);r.mask.basic.n_proto=htons(U16_MAX);r.key.basic.ip_proto=udp?IPPROTO_UDP:IPPROTO_TCP;r.mask.basic.ip_proto=U8_MAX;
 r.key.ports.src=htons(12345);r.key.ports.dst=htons(443);r.mask.ports.src=r.mask.ports.dst=htons(U16_MAX);
 memset(&r.mask.ipv4_addrs,0xff,sizeof(r.mask.ipv4_addrs));memset(&r.mask.ipv6_addrs,0xff,sizeof(r.mask.ipv6_addrs));
 r.key.eth_addrs.src[0]=2;r.key.eth_addrs.dst[0]=4;memset(&r.mask.eth_addrs,0xff,sizeof(r.mask.eth_addrs));
 r.mask.ip.tos=U8_MAX;
 if(!udp){dissector.used_keys|=BIT_ULL(FLOW_DISSECTOR_KEY_TCP);r.mask.tcp.flags=htons(5);}
 return r;
}
static struct metadata_dst *rx_metadata;
static u16 rx_proto;
static bool rx_vlan_tag;
static unsigned run_bind(struct airoha_ppe *ppe,struct airoha_flow_table_entry *e,struct net_device *dev) {
 struct sk_buff skb={.dev=dev,.md=rx_metadata,.vlan_tag=rx_vlan_tag};
 skb.hdr.h_proto=htons(rx_proto?rx_proto:(FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE,e->data.ib1)==PPE_PKT_TYPE_IPV6_ROUTE_5T?ETH_P_IPV6:ETH_P_IP));
 ppe->foe_flow[0]=e;learned=e->data;
 learned.ib1=(learned.ib1&~AIROHA_FOE_IB1_BIND_STATE)|FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE,AIROHA_FOE_STATE_UNBIND);
 commits=0;airoha_ppe_foe_insert_entry(ppe,&skb,5,false,NULL);assert(!ppe_lock);return commits;
}

static unsigned test_wlan_epoch(struct airoha_ppe *ppe, struct net_device *input,
                                struct airoha_gdm_dev *pon, bool ipv6, u8 band, u16 wcid)
{
 struct airoha_flow_table_entry flow = {};
 u32 ib2 = FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_GDM3) |
           FIELD_PREP(AIROHA_FOE_IB2_NBQ, 2 + band);
 u32 data = FIELD_PREP(AIROHA_FOE_CHANNEL, 8 + band);
 u16 etype = (wcid << 6) | 63;
 flow.data.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE,
                            ipv6 ? PPE_PKT_TYPE_IPV6_ROUTE_5T : PPE_PKT_TYPE_IPV4_HNAPT);
 if (ipv6) {
  flow.data.ipv6.ib2 = ib2;
  flow.data.ipv6.data = data;
  flow.data.ipv6.l2.etype = etype;
 } else {
  flow.data.ipv4.ib2 = ib2;
  flow.data.ipv4.data = data;
  flow.data.ipv4.l2.common.etype = etype;
 }
 ppe->foe_flow[0] = NULL;
 ppe->ct_wlan_epoch[band][wcid] = 37;
 ppe->ct_wlan_blocked[band][wcid] = true;
 assert(airoha_ppe_foe_flow_commit_entry(ppe, &flow) == -ESTALE && !ppe->foe_flow[0]);
 ppe->ct_wlan_blocked[band][wcid] = false;
 assert(airoha_ppe_foe_flow_commit_entry(ppe, &flow) == 0 && flow.ct_dest.epoch == 38);
 assert(run_bind(ppe, &flow, input) == 1);
 /* Exercise the bind gate independently of the unfinished IFC admission. */
 flow.pon_ingress_dev = pon;
 ppe->ct_pon_qualified = false;
 assert(!run_bind(ppe, &flow, pon->netdev));
 ppe->ct_pon_qualified = true;
 assert(run_bind(ppe, &flow, pon->netdev) == 1);
 flow.pon_ingress_dev = NULL;
 ppe->ct_wlan_blocked[!band][wcid] = true;
 assert(run_bind(ppe, &flow, input) == 1);
 ppe->ct_wlan_blocked[!band][wcid] = false;
 ppe->ct_wlan_blocked[band][wcid] = true;
 assert(!run_bind(ppe, &flow, input));
 ppe->ct_wlan_blocked[band][wcid] = false;
 ppe->ct_wlan_epoch[band][wcid]++;
 assert(!run_bind(ppe, &flow, input));
 flow.pon_ingress_dev = pon;
 assert(!run_bind(ppe, &flow, pon->netdev));
 flow.pon_ingress_dev = NULL;
 ppe->foe_flow[0] = NULL;
 assert(airoha_ppe_foe_flow_commit_entry(ppe, &flow) == 0 && flow.ct_dest.epoch == 39);
 assert(run_bind(ppe, &flow, input) == 1);
 ppe->ct_wlan_epoch[band][wcid] = U32_MAX;
 assert(!run_bind(ppe, &flow, input));
 ppe->foe_flow[0] = NULL;
 assert(airoha_ppe_foe_flow_commit_entry(ppe, &flow) == -ESTALE && !ppe->foe_flow[0]);
 return 13;
}

int main(void) {
 unsigned cases=0;
 struct net ns={1},other_ns={2};struct airoha_eth eth={};
 struct net_device pn={.ifindex=2,.net=&ns,.running=true,.carrier=true,.type=ARPHRD_ETHER,.addr_len=6,.dev_addr={2}},lan={.ifindex=24,.net=&ns,.running=true,.carrier=true},wifi={.ifindex=30,.net=&ns,.ieee80211_ptr=&wifi},foreign={.ifindex=2,.net=&other_ns},vlan={.ifindex=40,.net=&ns},ppp={.ifindex=41,.net=&ns},dsa={.ifindex=42,.net=&ns,.dsa_conduit=&lan,.dsa_port=1};
 struct airoha_gdm_dev pon={.eth=&eth,.netdev=&pn,.flags=1<<AIROHA_DEV_F_PON,.qdma=&eth.qdma[1]},wired={.eth=&eth,.netdev=&lan};
 struct airoha_gdm_port port={.devs={&pon,&wired}};eth.ports[0]=&port;pn.priv=&pon;lan.priv=&wired;
 struct net_device *list[]={&pn,&lan,&wifi,&foreign,&vlan,&ppp,&dsa};memcpy(devices,list,sizeof list);
 for(unsigned ip=0;ip<2;ip++)for(unsigned udp=0;udp<2;udp++) {
  struct airoha_ppe ppe={.eth=&eth,.ct_host_ppe=true};eth.ppe=&ppe;
  struct flow_rule rule=valid_rule(ip,udp),up=rule;up.key.meta.ingress_ifindex=24;struct airoha_gdm_dev *found;int index,dsa_port;
  assert(!ppe.ct_pon_qualified);cases++;
  assert(!airoha_ppe_ct_pon_rule_supported(&ppe,&rule,&pon,&wired,false));cases++;
  assert(!airoha_ppe_ct_pon_rule_supported(&ppe,&up,&wired,&pon,false));cases++;
  assert(!airoha_ppe_ct_pon_rule_supported(&ppe,&up,NULL,&pon,false));cases++;
  assert(airoha_ppe_ct_pon_rule_supported(&ppe,&up,&wired,&wired,false));cases++;
  ppe.ct_pon_qualified=true;
  assert(airoha_ppe_ct_ip_rule_supported(&rule,false));cases++;
  assert(!airoha_ppe_ct_ingress_dev(&eth,&rule,&lan,&pon,&found,&index,&dsa_port) && found==&pon && index==2);cases++;
  assert(airoha_ppe_ct_pon_rule_supported(&ppe,&rule,&pon,&wired,false));cases++;
  assert(airoha_ppe_ct_pon_rule_supported(&ppe,&up,&wired,&pon,false));cases++;
  assert(airoha_ppe_ct_pon_rule_supported(&ppe,&rule,NULL,&pon,false));cases++;
  for(unsigned flag=0;flag<3;flag++) {
   pon.pon_update_blocked=flag==0;pn.running=flag!=1;pn.carrier=flag!=2;
   assert(!airoha_ppe_ct_pon_rule_supported(&ppe,&rule,&pon,&wired,false));cases++;
   assert(!airoha_ppe_ct_pon_rule_supported(&ppe,&up,&wired,&pon,false));cases++;
  }
  pon.pon_update_blocked=false;pn.running=pn.carrier=true;
  eth.qdma[1].hqos=BIT(31);assert(!airoha_ppe_ct_pon_rule_supported(&ppe,&up,&wired,&pon,false));cases++;
  assert(airoha_ppe_ct_pon_rule_supported(&ppe,&rule,&pon,&wired,false));cases++;eth.qdma[1].hqos=0;
  pon.qdma=&eth.qdma[0];assert(!airoha_ppe_ct_pon_rule_supported(&ppe,&up,&wired,&pon,false));cases++;pon.qdma=&eth.qdma[1];
  assert(!airoha_ppe_ct_pon_rule_supported(&ppe,&rule,&pon,NULL,false));cases++;
  assert(!airoha_ppe_ct_pon_rule_supported(&ppe,&rule,&pon,&pon,false));cases++;
  assert(!airoha_ppe_ct_pon_rule_supported(&ppe,&up,&wired,&pon,true));cases++;
  up.key.meta.ingress_ifindex=42;assert(airoha_ppe_ct_pon_rule_supported(&ppe,&up,&wired,&pon,false));cases++;
  assert(airoha_ppe_ct_pon_rule_supported(&ppe,&up,&wired,&wired,false));cases++;up.key.meta.ingress_ifindex=24;
  for(unsigned key=FLOW_DISSECTOR_KEY_VLAN;key<=FLOW_DISSECTOR_KEY_ENC_CONTROL;key++) {
   dissector.used_keys|=BIT_ULL(key);assert(!airoha_ppe_ct_pon_rule_supported(&ppe,&rule,&pon,&wired,false));cases++;dissector.used_keys&=~BIT_ULL(key);
  }
  for(unsigned bit=0;bit<32;bit++) {
   rule.mask.meta.ingress_ifindex=U32_MAX^BIT(bit);assert(airoha_ppe_ct_ingress_dev(&eth,&rule,&lan,&pon,&found,&index,&dsa_port)==-EOPNOTSUPP);cases++;
  }
  rule.mask.meta.ingress_ifindex=U32_MAX;
  for(unsigned id=0;id<7;id++) {
   rule.key.meta.ingress_ifindex=list[id]->ifindex;
   int err=airoha_ppe_ct_ingress_dev(&eth,&rule,&lan,&pon,&found,&index,&dsa_port);
   if(id==4 || id==5)assert(err==-EOPNOTSUPP);
   else {assert(!err);assert(found==(id==0||id==3?&pon:id==1||id==6?&wired:NULL));}
   cases++;
  }
  rule.key.meta.ingress_ifindex=99;assert(airoha_ppe_ct_ingress_dev(&eth,&rule,&lan,&pon,&found,&index,&dsa_port)==-ENODEV);cases++;
  rule.key.meta.ingress_ifindex=2;assert(airoha_ppe_ct_ingress_dev(&eth,&rule,&foreign,&pon,&found,&index,&dsa_port)==-EOPNOTSUPP);cases++;
  assert(!pn.refs && !lan.refs && !wifi.refs && !foreign.refs && !vlan.refs && !ppp.refs && !dsa.refs);
  struct flow_rule unrelated=rule;unrelated.key.meta.ingress_ifindex=40;
  assert(!airoha_ppe_ct_ingress_dev(&eth,&unrelated,&lan,&wired,&found,&index,&dsa_port) && !found && !index);cases++;
  unrelated.mask.meta.ingress_ifindex=0;
  assert(airoha_ppe_ct_ingress_dev(&eth,&unrelated,&lan,&wired,&found,&index,&dsa_port)==-EOPNOTSUPP);cases++;
  unrelated.key.meta.ingress_ifindex=24;unrelated.mask.meta.ingress_ifindex=U32_MAX;
  assert(!airoha_ppe_ct_ingress_dev(&eth,&unrelated,&lan,&wired,&found,&index,&dsa_port) && !found);cases++;
  for(unsigned bit=0;bit<16;bit++) {
   rule.mask.ports.src=htons(U16_MAX^BIT(bit));assert(!airoha_ppe_ct_pon_rule_supported(&ppe,&rule,&pon,&wired,false));cases++;
  }
  rule.mask.ports.src=htons(U16_MAX);
  struct airoha_flow_table_entry e={.type=FLOW_TYPE_L4,.egress_dev=&wired,.pon_ingress_dev=&pon,.ct_ingress_ifindex=2,.ct_ingress_gdm=&pon,.ct_ingress_dsa_port=-1};
  e.data.ib1=FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE,AIROHA_FOE_STATE_BIND)|FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE,ip?PPE_PKT_TYPE_IPV6_ROUTE_5T:PPE_PKT_TYPE_IPV4_HNAPT)|FIELD_PREP(AIROHA_FOE_IB1_BIND_UDP,udp);
  ppe.ct_pon_qualified=false;
  assert(!run_bind(&ppe,&e,&pn));cases++;
  assert(!run_bind(&ppe,&e,&lan));cases++;
  ppe.ct_pon_qualified=true;
  assert(run_bind(&ppe,&e,&pn)==1);cases++;
  const u16 unsupported_inputs[]={0x8864,0x8100,0x88a8,0x88cc,ip?ETH_P_IP:ETH_P_IPV6};
  for(unsigned n=0;n<ARRAY_SIZE(unsupported_inputs);n++){rx_proto=unsupported_inputs[n];assert(!run_bind(&ppe,&e,&pn));cases++;}
  rx_proto=0;rx_vlan_tag=true;assert(!run_bind(&ppe,&e,&pn));cases++;rx_vlan_tag=false;
  assert(!run_bind(&ppe,&e,&lan));cases++;
  assert(!run_bind(&ppe,&e,&foreign));cases++;
  pon.pon_update_blocked=true;assert(!run_bind(&ppe,&e,&pn));cases++;
  pon.pon_update_blocked=false;pn.carrier=false;assert(!run_bind(&ppe,&e,&pn));cases++;pn.carrier=true;
  e.egress_dev=&pon;e.pon_ingress_dev=NULL;e.ct_ingress_ifindex=24;e.ct_ingress_gdm=&wired;
  ppe.ct_pon_qualified=false;
  assert(!run_bind(&ppe,&e,&lan));cases++;
  assert(!run_bind(&ppe,&e,&pn));cases++;
  e.egress_dev=&wired;assert(run_bind(&ppe,&e,&wifi)==1);cases++;
  e.egress_dev=&pon;ppe.ct_pon_qualified=true;
  assert(run_bind(&ppe,&e,&lan)==1);cases++;
  /* The admitted candidate can outlive the exact WAN encoding it used. */
  assert(airoha_ppe_ct_pon_rule_supported(&ppe,&up,&wired,&pon,false));cases++;
  eth.qdma[1].hqos=BIT(31);assert(!run_bind(&ppe,&e,&lan));cases++;
  eth.qdma[1].hqos=0;pon.qdma=&eth.qdma[0];assert(!run_bind(&ppe,&e,&lan));cases++;
  pon.qdma=NULL;assert(!run_bind(&ppe,&e,&lan));cases++;
  pon.qdma=&eth.qdma[1];eth.qdma[0].hqos=BIT(31);assert(run_bind(&ppe,&e,&lan)==1);cases++;
  eth.qdma[0].hqos=0;
  for(unsigned n=0;n<ARRAY_SIZE(unsupported_inputs);n++){rx_proto=unsupported_inputs[n];assert(!run_bind(&ppe,&e,&lan));cases++;}
  rx_proto=0;rx_vlan_tag=true;assert(!run_bind(&ppe,&e,&lan));cases++;rx_vlan_tag=false;
  if(!ip) {
   e.data.ib1|=AIROHA_FOE_IB1_BIND_PPPOE|FIELD_PREP(AIROHA_FOE_IB1_BIND_VLAN_LAYER,1);
   e.data.ipv4.l2.pppoe_id=7;e.data.ipv4.l2.common.vlan1=100;
   assert(run_bind(&ppe,&e,&lan)==1);cases++;
  }
  assert(!run_bind(&ppe,&e,&wifi));cases++;
  foreign.ifindex=24;assert(!run_bind(&ppe,&e,&foreign));cases++;foreign.ifindex=2;
  pon.pon_update_blocked=true;assert(!run_bind(&ppe,&e,&lan));cases++;
  e.egress_dev=&wired;assert(run_bind(&ppe,&e,&wifi)==1);cases++;pon.pon_update_blocked=false;
  assert(!run_bind(&ppe,&e,&pn));cases++;
  /* DSA learns on the conduit, carrying the hardware source port in dst. */
  e.egress_dev=&pon;e.ct_ingress_ifindex=42;e.ct_ingress_dsa_port=1;
  struct metadata_dst md={.type=METADATA_HW_PORT_MUX,.u.port_info.port_id=1};
  assert(!run_bind(&ppe,&e,&lan));cases++;
  rx_metadata=&md;assert(run_bind(&ppe,&e,&lan)==1);cases++;
  assert(!run_bind(&ppe,&e,&dsa));cases++;
  md.type=0;assert(!run_bind(&ppe,&e,&lan));cases++;md.type=METADATA_HW_PORT_MUX;
  for(unsigned port=0;port<8;port++) {md.u.port_info.port_id=port;assert(run_bind(&ppe,&e,&lan)==(port==1));cases++;}
  rx_metadata=NULL;e.ct_ingress_dsa_port=-1;
  lan.uses_dsa=true;up.key.meta.ingress_ifindex=24;
  assert(airoha_ppe_ct_ingress_dev(&eth,&up,&pn,&pon,&found,&index,&dsa_port)==-EOPNOTSUPP);cases++;
  up.key.meta.ingress_ifindex=42;
  assert(!airoha_ppe_ct_ingress_dev(&eth,&up,&pn,&pon,&found,&index,&dsa_port) && found==&wired && dsa_port==1);cases++;
  dsa.dsa_port=7;assert(airoha_ppe_ct_ingress_dev(&eth,&up,&pn,&pon,&found,&index,&dsa_port)==-EOPNOTSUPP);cases++;dsa.dsa_port=1;
  lan.uses_dsa=false;up.key.meta.ingress_ifindex=24;
  /* WLAN ingress keeps its own physical ifindex rather than a GDM pointer. */
  e.ct_ingress_gdm=NULL;e.ct_ingress_ifindex=30;
  foreign.ifindex=30;assert(!run_bind(&ppe,&e,&foreign));cases++;foreign.ifindex=2;
  assert(run_bind(&ppe,&e,&wifi)==1);cases++;
  assert(!run_bind(&ppe,&e,&lan));cases++;
  eth.ppe=&ppe;ppe.foe_flow[0]=NULL;links=cookies=removed_cookies=0;
  e.egress_dev=&pon;e.pon_ingress_dev=NULL;
  index_error=-ENOMEM;
  assert(airoha_ppe_ct_bridge_publish(&eth,&e)==-ENOMEM && !ppe.foe_flow[0] && !links && !cookies);cases++;
  index_error=0;
  assert(!airoha_ppe_ct_bridge_publish(&eth,&e) && ppe.foe_flow[0]==&e && links==1 && cookies==1);cases++;
  struct airoha_flow_table_entry next=e;
  next.egress_dev=&wired;
  assert(airoha_ppe_ct_bridge_publish(&eth,&next)==-EEXIST && ppe.foe_flow[0]==&e && links==1 && cookies==1 && removed_cookies==1);cases++;
  e.egress_dev=&wired;next.egress_dev=&pon;
  assert(airoha_ppe_ct_bridge_publish(&eth,&next)==-EEXIST && links==1 && cookies==1 && removed_cookies==2);cases++;
  next.egress_dev=&wired;next.pon_ingress_dev=&pon;
  assert(airoha_ppe_ct_bridge_publish(&eth,&next)==-EEXIST && links==1 && cookies==1 && removed_cookies==3);cases++;
  next.data.d[0]^=1;
  assert(!airoha_ppe_ct_bridge_publish(&eth,&next) && links==2 && cookies==2);cases++;
  if (!udp)
   for (u8 band = 0; band < 2; band++) {
    cases += test_wlan_epoch(&ppe, &lan, &pon, ip, band, 1);
    cases += test_wlan_epoch(&ppe, &lan, &pon, ip, band, 150);
   }
 }
 for(unsigned path=0;path<3;path++) {
  struct net_device_path_stack stack={};
  if(path!=1)stack.path[stack.num_paths++]=(struct net_device_path){.type=DEV_PATH_PPPOE,.dev=&ppp,.encap={.id=7,.proto=htons(0x8864)}};
  if(path!=0)stack.path[stack.num_paths++]=(struct net_device_path){.type=DEV_PATH_VLAN,.dev=&vlan,.encap={.id=100,.proto=htons(ETH_P_8021Q)}};
  stack.path[stack.num_paths++]=(struct net_device_path){.type=DEV_PATH_ETHERNET,.dev=&pn};
  struct nft_forward_info info={};struct nf_flowtable ft={.hw=true};unsigned char mac[6]={2};
  assert(!nft_dev_path_info(&stack,&info,mac,&ft) && info.indev==&pn && info.hw_outdev==&pn);
  assert(info.num_encaps==stack.num_paths-1 && info.xmit_type==FLOW_OFFLOAD_XMIT_DIRECT);cases++;
 }
 for(unsigned sport=0;sport<32;sport++) {
  struct airoha_qdma_desc desc={.msg1=FIELD_PREP(QDMA_ETH_RXMSG_SPORT_MASK,sport)};u16 portid=0xffff,devid=0xffff;
  int err=airoha_en7581_get_dev_from_sport(&desc,&portid,&devid);
  if(sport==2)assert(!err && portid==1 && devid==0);
  else if(sport==24)assert(!err && portid==3 && devid==0);
  else if(!err)assert(portid!=1);
  cases++;
 }
 printf("PASS %u production PON admission, actual learn/bind, lower-path and source-port cases\n",cases);
 return 0;
}
