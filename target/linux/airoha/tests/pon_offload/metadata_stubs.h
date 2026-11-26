#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <netinet/in.h>
typedef uint8_t u8;
typedef uint16_t u16, __be16;
typedef uint32_t u32, __be32;
typedef uint64_t u64;
#define BIT(n) (1u << (n))
#define GENMASK(h, l) ((UINT32_MAX >> (31u - (h))) & (UINT32_MAX << (l)))
#define FIELD_PREP(m, v) (((u32)(v) << __builtin_ctz((u32)(m))) & (m))
#define FIELD_GET(m, v) (((u32)(v) & (m)) >> __builtin_ctz((u32)(m)))
#define DECLARE_FLEX_ARRAY(t, n) t n[0]
#define static_assert(x) _Static_assert(x, #x)
#define READ_ONCE(x) (x)
#define lockdep_assert_held(x) ((void)(x))
#define lockdep_is_held(x) 1
#define rcu_dereference_protected(x, y) (x)
#define EOPNOTSUPP 95
#define PPE_ENTRY_SIZE 80
#define AIROHA_NUM_QOS_CHANNELS 4
#define AIROHA_NUM_QOS_QUEUES 8
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_PPP_SES 0x8864
#define AIROHA_PON_VID_ANY 0xffff
struct rcu_head { void *next; void *func; };
struct ethhdr { u8 h_dest[6]; u8 h_source[6]; u16 h_proto; };
/* Hardware FOE/PON types and bit masks are extracted verbatim below. */
#include "production_types.inc"
struct airoha_ppe { bool ct_host_ppe; };
struct airoha_eth { struct airoha_ppe *ppe; };
struct airoha_gdm_port { u8 id; };
struct airoha_gdm_dev {
    struct airoha_gdm_port *port;
    unsigned long flags;
    u32 pon_qdma_tag;
    struct airoha_pon_flow_table *pon_flow_table;
    u8 nbq;
};
struct net_device { struct airoha_gdm_dev *priv; };
struct airoha_wdma_info { unsigned idx, wcid, bss; };
static int flow_offload_mutex;
static int airoha_get_dsa_port(struct net_device **n) { (void)n; return -1; }
static int airoha_ppe_get_wdma_info(struct net_device *n, const u8 *m,
                                  struct airoha_wdma_info *i, bool b)
{ (void)n; (void)m; (void)i; (void)b; return -ENOENT; }
static void *netdev_priv(struct net_device *n) { return n->priv; }
static bool airoha_is_valid_gdm_dev(struct airoha_eth *e, struct airoha_gdm_dev *d)
{ (void)e; return d != NULL; }
static bool airoha_is_lan_gdm_dev(struct airoha_gdm_dev *d) { (void)d; return false; }
static bool test_bit(unsigned b, const unsigned long *p) { return (*p >> b) & 1; }
/* Queue policy is supplied as queue 0; this suite tests bearer metadata. */
static unsigned rt_tos2priority(u8 dsfield) { (void)dsfield; return 0; }
static bool is_multicast_ether_addr(const u8 *m) { return m[0] & 1; }
static u32 get_unaligned_be32(const u8 *p) { return (u32)p[0]<<24 | (u32)p[1]<<16 | (u32)p[2]<<8 | p[3]; }
static u16 get_unaligned_be16(const u8 *p) { return (u16)p[0]<<8 | p[1]; }
