#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef struct { int held; } spinlock_t;
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x) = (v))
#define U32_MAX UINT32_MAX
#define BIT(n) (1u << (n))
#define GENMASK(h,l) (((~0u) << (l)) & ((~0u) >> (31-(h))))
#define max(a,b) ((a) > (b) ? (a) : (b))
#define rcu_dereference(x) (x)
#define rcu_assign_pointer(x,y) ((x)=(y))
#define msecs_to_jiffies(x) (x)
static void test_log(const char *fmt, ...) { (void)fmt; }
#define pr_err(...) test_log(__VA_ARGS__)
#define dev_err_ratelimited(...) ((void)0)
#define FE_PSE_PORT_CDM1 0
#define FE_PSE_PORT_PPE1 4
#define FE_PSE_PORT_CDM2 5
#define FE_PSE_PORT_PPE2 8
#define FE_PSE_PORT_DROP 15
#define AIROHA_GDM1_IDX 1
#define AIROHA_GDM2_IDX 2
#define AIROHA_GDM4_IDX 4
#define REG_GDM_FWD_CFG(id) ((id) - 1)
#define REG_FE_CSR_IFC_CFG 16
#define FE_IFC_EN_MASK BIT(0)
#define REG_PPE_GLO_CFG(id) (32 + (id))
#define REG_PPE_PPE_FLOW_CFG(id) (40 + (id))
#define PPE_GLO_CFG_EN_MASK BIT(0)
#define PPE_GLO_CFG_BUSY_MASK BIT(1)
#define AIROHA_CT_PAIR_FE_QUIESCE 6
#define AIROHA_CT_PAIR_FLUSH 4
#define cpu_to_le16(v) (v)

struct airoha_eth;
struct airoha_ppe;
struct airoha_ct_pair_msg { u16 op; u32 flags; };
#define cpu_to_le32(x) (x)
#define AIROHA_CT_PAIR_F_CPU_FALLBACK BIT(0)
struct airoha_npu {
    struct { int (*ct_pair_cmd)(struct airoha_npu *, struct airoha_ct_pair_msg *); } ops;
};
struct airoha_qdma { int id; };
struct net_device { bool running; };
struct airoha_gdm_dev {
    struct airoha_qdma *qdma;
    struct net_device netdev;
};
struct airoha_gdm_port { struct airoha_gdm_dev *devs[2]; };
struct airoha_soc { int num_ppe; };
struct airoha_eth {
    spinlock_t ct_route_lock;
    u16 ct_cpu_route_mask[4];
    bool ct_cpu_fallback, ct_cpu_ifc_disabled, ct_cpu_routes_ready, ct_cpu_wlan_gated;
    bool ct_ifc_cpu_port_failed, ct_ordinary_full_test;
    struct airoha_ppe *ppe;
    struct airoha_npu *npu;
    struct airoha_soc *soc;
    struct airoha_qdma qdma[2];
    struct airoha_gdm_port *ports[4];
    u32 regs[64];
};
struct airoha_ppe {
    struct airoha_eth *eth;
    struct { bool cfg_owned; } ct_ifc;
    struct {
        bool active, armed, pending, arm_pending, touched, saved, health_stopping;
        u32 epoch, pending_epoch;
        u64 generation, pending_generation;
        int health_work;
    } ct_fe;
    bool ct_native_pairs, ct_pair_policy_allowed, ct_pair_failed;
    bool ct_bridge_failed, ct_stopping, ct_pair_hw_stopped;
    bool ct_pair_close_pending;
    u32 ct_pair_wired_epoch;
};

static spinlock_t ppe_lock = {1};
static int rcu_depth, reject_reg = -1, close_calls, schedules, restores, snapshots;
static int command_error, commands, close_sequence, sequence;
static int flush_error, gate_error, gate_calls, gate_sequence;
static u32 sent_epoch;
static u64 sent_generation;
static int bank_first_sequence;
static struct airoha_eth eth;
static struct airoha_ppe ppe;
static struct airoha_soc soc = {2};
static struct airoha_gdm_port ports[4];
static struct airoha_gdm_dev devices[4][2];
static struct airoha_npu npu;

static void lockdep_assert_held(spinlock_t *l) { assert(l->held); }
static void spin_lock_bh(spinlock_t *l) { assert(!l->held); l->held=1; }
static void spin_unlock_bh(spinlock_t *l) { assert(l->held); l->held=0; }
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth); rcu_depth--; }
static struct net_device *netdev_from_priv(struct airoha_gdm_dev *d) { return &d->netdev; }
static bool netif_running(struct net_device *d) { return d->running; }
static u32 airoha_fe_rr(struct airoha_eth *e, unsigned int reg) { assert(reg<64); return e->regs[reg]; }
static void airoha_fe_wr(struct airoha_eth *e, unsigned int reg, u32 val)
{
    assert(reg<64);
    sequence++;
    if (reg==REG_PPE_PPE_FLOW_CFG(0) && !bank_first_sequence) bank_first_sequence=sequence;
    if ((int)reg != reject_reg) e->regs[reg]=val;
}
static void airoha_fe_rmw(struct airoha_eth *e, unsigned int reg, u32 mask, u32 val)
{ airoha_fe_wr(e,reg,(airoha_fe_rr(e,reg)&~mask)|val); }
static void airoha_fe_clear(struct airoha_eth *e, unsigned int reg, u32 mask)
{ airoha_fe_rmw(e,reg,mask,0); }
static void schedule_delayed_work(int *work, int delay) { (void)work; assert(delay==(eth.ct_ifc_cpu_port_failed ? 0 : 100)); schedules++; }
static int test_pair_cmd(struct airoha_npu *n, struct airoha_ct_pair_msg *msg)
{
    struct airoha_ppe *p=&ppe;
    assert(n==&npu && msg->op==AIROHA_CT_PAIR_FLUSH && rcu_depth);
    assert(!p->ct_pair_policy_allowed && p->ct_pair_failed && p->ct_stopping);
    assert(p->eth->ct_cpu_fallback);
    if (msg->flags) {
        assert(msg->flags==AIROHA_CT_PAIR_F_CPU_FALLBACK);
        gate_calls++; gate_sequence=++sequence; return gate_error;
    }
    assert(p->eth->ct_cpu_wlan_gated);
    close_calls++; close_sequence=++sequence;
    return flush_error;
}
static int airoha_ct_fe_restore(struct airoha_ppe *p) { (void)p; restores++; return 0; }
static int airoha_ct_fe_snapshot(struct airoha_ppe *p) { (void)p; snapshots++; return 0; }
static int airoha_ct_fe_control(struct airoha_ppe *p, unsigned int op, u64 generation, u32 epoch)
{
    (void)p; assert(op==AIROHA_CT_PAIR_FE_QUIESCE); commands++;
    sent_epoch=epoch; sent_generation=generation;
    return command_error;
}
#define read_poll_timeout_atomic(fn,val,cond,a,b,c,...) \
    ({ (void)(a); (void)(b); (void)(c); (val)=fn(__VA_ARGS__); (cond) ? 0 : -ETIMEDOUT; })

static bool ct_ifc_cpu_port_matches(struct airoha_eth *e) { return !e->ct_ifc_cpu_port_failed; }
#include "airoha_ct_cpu_fallback.h"
#include "cpu_fallback_extracted.inc"

static void reset(void)
{
    memset(&eth,0,sizeof eth); memset(&ppe,0,sizeof ppe);
    memset(ports,0,sizeof ports); memset(devices,0,sizeof devices);
    eth.ppe=&ppe; eth.soc=&soc; ppe.eth=&eth;
    eth.npu=&npu; npu.ops.ct_pair_cmd=test_pair_cmd;
    ppe.ct_native_pairs=true; ppe.ct_pair_policy_allowed=true; ppe.ct_ifc.cfg_owned=true;
    ppe.ct_fe.active=true; ppe.ct_fe.armed=true; ppe.ct_fe.touched=true; ppe.ct_fe.saved=true;
    ppe.ct_fe.epoch=10; ppe.ct_pair_wired_epoch=9; ppe.ct_fe.generation=100;
    for (int i=0;i<4;i++) {
        eth.ports[i]=&ports[i]; ports[i].devs[0]=&devices[i][0];
        devices[i][0].qdma=&eth.qdma[i&1]; devices[i][0].netdev.running=true;
        eth.regs[i]=0x17f08888;
    }
    eth.regs[REG_FE_CSR_IFC_CFG]=0xa5;
    eth.regs[REG_PPE_GLO_CFG(0)]=eth.regs[REG_PPE_GLO_CFG(1)]=1;
    eth.regs[REG_PPE_PPE_FLOW_CFG(0)]=eth.regs[REG_PPE_PPE_FLOW_CFG(1)]=0xff;
    reject_reg=-1; close_calls=schedules=restores=snapshots=commands=0;
    command_error=bank_first_sequence=sequence=close_sequence=flush_error=0;
    gate_error=gate_calls=gate_sequence=0;
    assert(rcu_depth==0 && ppe_lock.held);
}

int main(void)
{
    int cases=0;
    /* Exhaustive selectors: only destinations 4/8 move, including mixed types. */
    for (u32 low=0;low<0x10000;low++) for (int cpu=0;cpu<=5;cpu+=5) {
        u32 out=airoha_ct_cpu_selectors(0xabc00000|low,airoha_ct_ppe_selectors(low),cpu);
        assert((out&0xffff0000)==0xabc00000);
        for (int n=0;n<4;n++) {
            int before=(low>>(n*4))&15,after=(out>>(n*4))&15;
            assert(after==((before==4||before==8)?cpu:before));
        }
    }
    cases++;
    reset(); eth.ct_ordinary_full_test=true;
    for (u32 low=0;low<0x10000;low++) {
        assert(!airoha_gdm_fwd_cfg_update(&eth,2,U32_MAX,0xabcd0000|low));
        u32 expected=0xabcd0000;
        for (int n=0;n<4;n++) {
            u32 p=(low>>(4*n))&15;
            expected|=((p==4||p==8)?5:p)<<(4*n);
        }
        assert(eth.regs[1]==expected);
    }
    assert(!airoha_set_gdm_port_fwd_cfg(&eth,4,4) && (eth.regs[3]&0xffff)==0x8888);
    reject_reg=1; assert(airoha_set_gdm_port_fwd_cfg(&eth,2,8)==-EIO);
    assert(!airoha_ct_ifc_cpu_port_change(&eth,2) && !eth.ct_ifc_cpu_port_failed);
    assert(!airoha_ct_ifc_cpu_port_change(&eth,24) && eth.ct_ifc_cpu_port_failed);
    cases++;
    reset(); eth.regs[1]=0x07f09999; eth.regs[2]=0x17f0f480;
    assert(airoha_ppe_ct_bridge_fail_closed_from(&ppe,"test",1)==0);
    assert(eth.regs[0]==0x17f00000 && eth.regs[1]==0x07f09999);
    assert(eth.regs[2]==0x17f0f000 && eth.regs[3]==0x17f05555);
    assert(eth.regs[REG_FE_CSR_IFC_CFG]==0xa4 && close_calls==1 && schedules==1);
    assert(gate_calls==1 && gate_sequence<close_sequence && close_sequence<bank_first_sequence && ppe.ct_pair_hw_stopped);
    assert(ppe.ct_fe.touched && ppe.ct_fe.saved && ppe.ct_fe.epoch==10);
    cases++;
    /* Reopen and saved PPE-route restoration honor sticky failure. */
    airoha_set_gdm_port_fwd_cfg(&eth,4,FE_PSE_PORT_PPE1);
    assert((eth.regs[3]&0xffff)==0x5555);
    assert(!airoha_gdm_fwd_cfg_update(&eth,4,~0u,0x17f04444));
    assert(eth.regs[3]==0x17f05555);
    assert(ct_ifc_write_reg(&eth,REG_FE_CSR_IFC_CFG,1,1)==-ESHUTDOWN);
    assert(!(eth.regs[REG_FE_CSR_IFC_CFG]&1)); cases++;
    /* A real QDMA publication and route rewrite share the lock. */
    spin_lock_bh(&eth.ct_route_lock);
    rcu_assign_pointer(devices[3][0].qdma,&eth.qdma[0]);
    assert(!airoha_ct_gdm_route_locked(&eth,4,eth.regs[3]));
    spin_unlock_bh(&eth.ct_route_lock);
    assert((eth.regs[3]&0xffff)==0); cases++;
    /* Late migration failure marks routes unready and restarts recovery work. */
    int scheduled_before=schedules;
    reject_reg=3;
    spin_lock_bh(&eth.ct_route_lock);
    rcu_assign_pointer(devices[3][0].qdma,&eth.qdma[1]);
    assert(airoha_ct_gdm_route_locked(&eth,4,eth.regs[3])==-EIO);
    spin_unlock_bh(&eth.ct_route_lock);
    assert(!eth.ct_cpu_routes_ready && schedules==scheduled_before+1);
    reject_reg=-1; assert(!airoha_ct_cpu_fallback(&eth));
    assert(eth.ct_cpu_routes_ready && (eth.regs[3]&0xffff)==0x5555);
    devices[3][0].qdma=&eth.qdma[0]; assert(!airoha_ct_cpu_fallback(&eth)); cases++;
    /* Upper-bit RMW preserves fallback ownership; explicit DROP clears it. */
    assert(!airoha_gdm_fwd_cfg_update(&eth,4,BIT(16),BIT(16)));
    assert(eth.regs[3]==0x17f10000 && eth.ct_cpu_route_mask[3]==0xffff);
    airoha_set_gdm_port_fwd_cfg(&eth,4,15);
    assert((eth.regs[3]&0xffff)==0xffff && !eth.ct_cpu_route_mask[3]); cases++;
    /* One active source wins over an inactive device; conflicting active sources drop. */
    reset(); ports[3].devs[1]=&devices[3][1]; devices[3][1].qdma=&eth.qdma[0];
    assert(!airoha_ct_cpu_fallback(&eth)); assert((eth.regs[3]&0xffff)==0x5555);
    devices[3][1].netdev.running=true;
    assert(airoha_ct_cpu_fallback(&eth)==-EXDEV);
    assert((eth.regs[3]&0xffff)==0xffff && !eth.ct_cpu_routes_ready); cases++;
    /* Failed GDM write retains retry state; retry repairs the route. */
    reset(); reject_reg=3;
    assert(airoha_ct_cpu_fallback(&eth)==-EIO && !eth.ct_cpu_routes_ready);
    reject_reg=-1; assert(!airoha_ct_cpu_fallback(&eth) && eth.ct_cpu_routes_ready); cases++;
    /* Classifier failure leaves producer state retained and blocks fault QUIESCE. */
    reset(); reject_reg=REG_FE_CSR_IFC_CFG;
    assert(airoha_ppe_ct_bridge_fail_closed_from(&ppe,"test",2)==-EIO);
    assert(!eth.ct_cpu_ifc_disabled && ppe.ct_fe.active && ppe.ct_pair_hw_stopped);
    assert(airoha_ct_fe_quiesce(&ppe,100)==-EIO && !commands);
    reject_reg=-1; assert(!airoha_ct_cpu_fallback(&eth)); cases++;
    /* Fault QUIESCE preserves the exact ambiguous epoch and both row shadows. */
    command_error=-ETIMEDOUT;
    assert(airoha_ct_fe_quiesce(&ppe,100)==-ETIMEDOUT);
    assert(restores==0 && snapshots==0 && ppe.ct_fe.pending && !ppe.ct_fe.armed);
    assert(ppe.ct_fe.touched && ppe.ct_fe.saved && sent_epoch==11 && sent_generation==100);
    command_error=0;
    assert(!airoha_ct_fe_quiesce(&ppe,999));
    assert(sent_epoch==11 && sent_generation==100 && !ppe.ct_fe.pending);
    assert(ppe.ct_fe.epoch==11 && ppe.ct_fe.generation==100 && ppe.ct_fe.touched); cases++;
    /* Ordinary revoke uses the unchanged restore/snapshot path and no CPU latch. */
    reset(); assert(!airoha_ct_fe_quiesce(&ppe,100));
    assert(restores==1 && snapshots==1 && !eth.ct_cpu_fallback);
    assert(!ct_ifc_write_reg(&eth,REG_FE_CSR_IFC_CFG,1,1));
    airoha_set_gdm_port_fwd_cfg(&eth,4,4); assert((eth.regs[3]&0xffff)==0x8888); cases++;
    /* Foreign classifier ownership is preserved, and hardware timeout retains stopped=false. */
    reset(); ppe.ct_ifc.cfg_owned=false;
    assert(airoha_ct_cpu_fallback(&eth)==-EIO && eth.regs[16]==0xa5); cases++;
    reset(); eth.regs[REG_PPE_GLO_CFG(1)]|=PPE_GLO_CFG_BUSY_MASK;
    assert(airoha_ppe_ct_bridge_fail_closed_from(&ppe,"test",3)==-ETIMEDOUT);
    assert(!ppe.ct_pair_hw_stopped && ppe.ct_fe.touched && close_calls==1); cases++;
    /* A busy native FLUSH is attempted once, retained, then retried explicitly. */
    reset(); flush_error=-EAGAIN;
    assert(!airoha_ppe_ct_bridge_fail_closed_from(&ppe,"test",4));
    assert(close_calls==1 && ppe.ct_pair_close_pending && ppe.ct_pair_hw_stopped);
    assert(ppe.ct_fe.touched && ppe.ct_fe.saved);
    flush_error=0; airoha_ct_pair_close_once(&ppe);
    assert(close_calls==2 && !ppe.ct_pair_close_pending); cases++;
    /* Gate failure keeps PPE enabled; retry ACK precedes stop and is cached. */
    const int gate_errors[]={-EAGAIN,-ETIMEDOUT,-EIO,-EOPNOTSUPP};
    for(unsigned i=0;i<ARRAY_SIZE(gate_errors);i++) {
        reset(); gate_error=gate_errors[i];
        assert(airoha_ppe_ct_bridge_fail_closed_from(&ppe,"gate",6)==gate_error);
        assert(gate_calls==1 && !close_calls && !bank_first_sequence);
        assert(!eth.ct_cpu_wlan_gated && !ppe.ct_pair_hw_stopped && schedules==1);
        assert((eth.regs[REG_PPE_GLO_CFG(0)]&1) && (eth.regs[REG_PPE_GLO_CFG(1)]&1));
        gate_error=0;
        assert(!airoha_ppe_ct_bridge_fail_closed_from(&ppe,"retry",7));
        assert(gate_calls==2 && close_calls==1 && eth.ct_cpu_wlan_gated && ppe.ct_pair_hw_stopped);
        assert(gate_sequence<close_sequence && close_sequence<bank_first_sequence);
        assert(!airoha_ppe_ct_bridge_fail_closed_from(&ppe,"cached",8));
        assert(gate_calls==2 && close_calls==2); cases++;
    }
    /* The common legacy stop also installs CPU fallback without a native command. */
    reset(); ppe.ct_native_pairs=false;
    assert(!airoha_ppe_ct_bridge_fail_closed_from(&ppe,"test",5));
    assert(eth.ct_cpu_fallback && ppe.ct_bridge_failed && !close_calls);
    assert(!ppe.ct_pair_policy_allowed && ppe.ct_pair_hw_stopped); cases++;
    assert(!rcu_depth && !eth.ct_route_lock.held);
    printf("PASS: %d scenario groups; 131072 selector combinations; extracted production functions\n",cases);
    return 0;
}
