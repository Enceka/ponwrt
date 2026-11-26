#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
typedef uint8_t u8;
typedef uint16_t u16, __u16, __be16;
typedef uint32_t u32;
#define ETH_ALEN 6
#define ETH_P_8021Q 0x8100
#define ETH_P_PPP_SES 0x8864
#define BIT(n) (1u << (n))
#define NFPROTO_IPV4 AF_INET
#define NFPROTO_IPV6 AF_INET6
#undef EOPNOTSUPP
#define EOPNOTSUPP 95
#define READ_ONCE(x) (x)
#define lockdep_assert_held(x) ((void)(x))
#define lockdep_is_held(x) 1
#define rcu_dereference_protected(x, y) (x)
#define WARN_ON_ONCE(x) assert(!(x))
#define AIROHA_PON_QDMA_VALID (1u << 31)
#define AIROHA_PON_QDMA_EPON (1u << 30)
#define AIROHA_PON_QDMA_TCONT_MASK 0x1f0000
#define AIROHA_PON_QDMA_GEM_MASK 0xffff
#define AIROHA_PON_VID_ANY 0xffff
enum flow_offload_xmit_type { FLOW_OFFLOAD_XMIT_DIRECT, FLOW_OFFLOAD_XMIT_XFRM, FLOW_OFFLOAD_XMIT_NEIGH };
enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY };
enum { DEV_PATH_ETHERNET, DEV_PATH_IEEE80211, DEV_PATH_DSA, DEV_PATH_MTK_WDMA, DEV_PATH_VLAN, DEV_PATH_PPPOE, DEV_PATH_BRIDGE };
enum { DEV_PATH_BR_VLAN_UNTAG_HW, DEV_PATH_BR_VLAN_KEEP_HW, DEV_PATH_BR_VLAN_TAG, DEV_PATH_BR_VLAN_UNTAG, DEV_PATH_BR_VLAN_KEEP };
enum { FLOW_ACTION_VLAN_PUSH, FLOW_ACTION_VLAN_POP, FLOW_ACTION_PPPOE_PUSH, FLOW_ACTION_PRIORITY };
struct net_device { int ifindex; u8 dev_addr[6]; struct airoha_gdm_dev *priv; };
struct net_device_path { int type; const struct net_device *dev; struct { u16 id, proto; u8 h_dest[6]; } encap; struct { int vlan_mode; u16 vlan_id, vlan_proto; } bridge; };
struct net_device_path_stack { int num_paths; struct net_device_path path[8]; };
struct nf_flowtable { int unused; };
struct nft_flowtable { struct nf_flowtable data; };
struct net { int unused; };
struct nf_conn { int unused; };
enum ip_conntrack_dir { IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY };
struct dst_entry { int unused; };
struct nf_flow_route { struct { struct dst_entry *dst; struct { int ifindex, num_encaps, ingress_vlans; struct { u16 id, proto; } encap[NF_FLOW_TABLE_ENCAP_MAX]; } in; struct { int ifindex, hw_ifindex, bridge_path, bridge_vlan, port_vlans; u8 h_source[6], h_dest[6]; } out; int xmit_type; } tuple[2]; };
struct flow_offload_tuple { int l3proto, mtu, iifidx, ifidx, dst_cookie, bridge_path, bridge_vlan, port_vlans, encap_num, in_vlan_ingress, xmit_type; struct dst_entry *dst_cache; struct { u16 id, proto; } encap[NF_FLOW_TABLE_ENCAP_MAX]; struct { int ifidx, hw_ifidx; u8 h_dest[6], h_source[6]; } out; };
struct flow_offload { struct { struct flow_offload_tuple tuple; } tuplehash[2]; unsigned priority; };
struct flow_action_entry { int id; union { struct { u16 vid, proto; u8 prio; } vlan; struct { u16 sid; } pppoe; unsigned priority; }; };
struct nf_flow_rule { unsigned count; struct flow_action_entry actions[24]; };
struct airoha_flow_data { struct { u8 h_dest[6]; } eth; struct { struct { u16 id, proto; } hdr[2]; unsigned num; } vlan; struct { u16 sid; unsigned num; } pppoe; };
struct airoha_pon_flow_entry { u16 vlan_id; u8 pbit_mask; u32 tag; };
struct airoha_pon_flow_table { unsigned count; struct airoha_pon_flow_entry entries[4]; };
struct airoha_gdm_dev { u32 pon_qdma_tag; struct airoha_pon_flow_table *pon_flow_table; unsigned long flags; };
struct airoha_ppe { bool ct_host_ppe; };
struct airoha_eth { struct airoha_ppe *ppe; struct airoha_gdm_dev *registered; };
struct flow_rule { struct nf_flow_rule action; unsigned keys; };
enum { FLOW_DISSECTOR_KEY_VLAN, FLOW_DISSECTOR_KEY_CVLAN, FLOW_DISSECTOR_KEY_PPPOE,
       FLOW_DISSECTOR_KEY_ENC_CONTROL, FLOW_DISSECTOR_KEY_IPV6_ADDRS };
#define AIROHA_DEV_F_PON 2
#define U16_MAX UINT16_MAX
#define VLAN_VID_MASK 4095
#define netdev_priv(n) ((n)->priv)
#define test_bit(b, p) (!!(*(p) & BIT(b)))
#define flow_rule_match_key(r, k) (!!((r)->keys & BIT(k)))
#define is_multicast_ether_addr(a) ((a)[0] & 1)
#define flow_action_for_each(i, act, a) for ((i)=0; (unsigned)(i)<(a)->count && ((act)=&(a)->actions[i]); (i)++)
#define airoha_is_valid_gdm_dev(e, d) ((d) == (e)->registered)
static int flow_offload_mutex;
static struct net_device_path_stack active_stack;
static bool is_zero_ether_addr(const u8 *p) { static const u8 zero[6]; return !memcmp(p, zero, 6); }
static bool nf_flowtable_hw_offload(struct nf_flowtable *p) { (void)p; return true; }
static bool nft_is_valid_ether_device(const struct net_device *p) { return p != NULL; }
static int nft_dev_fill_forward_path(struct nf_flow_route *r, const struct dst_entry *d, const struct nf_conn *c, enum ip_conntrack_dir dir, u8 *ha, struct net_device_path_stack *s) { (void)r;(void)d;(void)c;(void)dir;memset(ha,2,6);*s=active_stack;return 0; }
static bool nft_flowtable_find_dev(const struct net_device *d, struct nft_flowtable *f) { (void)f; return d != NULL; }
static struct dst_entry *nft_route_dst_fetch(struct nf_flow_route *r, int d) { return r->tuple[d].dst; }
static unsigned ip_dst_mtu_maybe_forward(struct dst_entry *d,bool f) { (void)d;(void)f;return 1500; }
static unsigned ip6_dst_mtu_maybe_forward(struct dst_entry *d,bool f) { (void)d;(void)f;return 1500; }
static void dst_release(struct dst_entry *d) { (void)d; }
static int flow_offload_dst_cookie(struct flow_offload_tuple *t) { (void)t;return 0; }
static int flow_offload_decap_tunnel(const struct flow_offload *f,int d,struct nf_flow_rule *r) { (void)f;(void)d;(void)r;return 0; }
static int flow_offload_encap_tunnel(const struct flow_offload *f,int d,struct nf_flow_rule *r) { (void)f;(void)d;(void)r;return 0; }
static int flow_offload_eth_src(struct net *n,const struct flow_offload *f,int d,struct nf_flow_rule *r) { (void)n;(void)f;(void)d;(void)r;return 0; }
static int flow_offload_eth_dst(struct net *n,const struct flow_offload *f,int d,struct nf_flow_rule *r) { (void)n;(void)f;(void)d;(void)r;return 0; }
static struct flow_action_entry *flow_action_entry_next(struct nf_flow_rule *r) { return r->count<24 ? &r->actions[r->count++] : NULL; }
