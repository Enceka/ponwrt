
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
typedef uint32_t u32, __le32; typedef uint16_t u16;
#define BIT(n) (1u<<(n))
#define GENMASK(h,l) ((~0u << (l)) & (~0u >> (31-(h))))
#define FIELD_GET(mask,v) (((v)&(mask)) >> __builtin_ctz(mask))
#define FIELD_PREP(mask,v) (((v)<<__builtin_ctz(mask))&(mask))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define WRITE_ONCE(x,v) ((x)=(v))
#undef static_assert
#define static_assert(x) _Static_assert(x, #x)
#define spin_lock_bh(x) ((void)0)
#define spin_unlock_bh(x) ((void)0)
#define cond_resched() ((void)0)
#define dev_err(...) ((void)0)
#define dev_info(...) ((void)0)
#define read_poll_timeout(op,v,cond,delay,timeout,sleep,...) ((v)=op(__VA_ARGS__), (cond)?0:-ETIMEDOUT)
#define PPE_SRAM_NUM_ENTRIES 8
#define AIROHA_FOE_IB1_BIND_STATIC BIT(31)
#define AIROHA_FOE_IB1_BIND_STATE GENMASK(29,28)
#define AIROHA_FOE_IB1_BIND_PACKET_TYPE GENMASK(27,25)
enum { AIROHA_FOE_STATE_INVALID,AIROHA_FOE_STATE_UNBIND,AIROHA_FOE_STATE_BIND,AIROHA_FOE_STATE_FIN };
enum { PPE_PKT_TYPE_IPV4_HNAPT=0,PPE_PKT_TYPE_IPV4_ROUTE=1,PPE_PKT_TYPE_BRIDGE=2,PPE_PKT_TYPE_IPV6_ROUTE_5T=5 };
enum airoha_ct_sram_op { CT_EXPECT_EMPTY, CT_CHECK_OWNED, CT_CLEAR_OWNED };
#define CT_HOST_L2B_LEARN_FLOW BIT(15)
#define CT_HOST_IP_FLOWS (BIT(13)|BIT(12)|BIT(9))
struct airoha_eth { struct { int num_ppe; } *soc; void *dev; };
struct airoha_ppe { struct airoha_eth *eth; bool ct_l2b_learn_only,ct_owns_sram,ct_start_reported,ct_restore_pending,ct_host_ppe; struct { u32 glo,regs[16]; } ct_saved[2]; };
struct airoha_foe_entry { u32 ib1,words[19]; };
static struct airoha_foe_entry rows[16];
static u32 mmio[0x3000/4];
static int broken=-1,writes,clears;
static u32 airoha_fe_rr(struct airoha_eth *e,u32 r) { (void)e; return mmio[r/4]; }
static void airoha_fe_wr(struct airoha_eth *e,u32 r,u32 v) { (void)e; writes++; if ((int)r!=broken) mmio[r/4]=v; }
static void airoha_fe_clear(struct airoha_eth *e,u32 r,u32 m) { airoha_fe_wr(e,r,airoha_fe_rr(e,r)&~m); }
static void airoha_fe_rmw(struct airoha_eth *e,u32 r,u32 m,u32 v) { airoha_fe_wr(e,r,(airoha_fe_rr(e,r)&~m)|v); }
static u32 airoha_ppe_get_total_sram_num_entries(struct airoha_ppe *p) { (void)p; return 16; }
static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *p,u32 h) { (void)p; return rows+h; }
static int airoha_ppe_foe_commit_sram_entry(struct airoha_ppe *p,u32 h) { (void)p; assert(rows[h].ib1==0); clears++; return 0; }
static int airoha_ppe_ct_ifc_stop(struct airoha_ppe *p) { (void)p; return 0; }
static int airoha_ppe_ct_smac_stop(struct airoha_ppe *p) { (void)p; return 0; }
