#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "airoha_npu_transaction_core.h"

typedef uint32_t u32;
typedef uint64_t u64;

#include "return_types.h"

static unsigned int checks;
#define CHECK(condition) do { checks++; if (!(condition)) { \
    fprintf(stderr, "CHECK failed: %s at %d\n", #condition, __LINE__); exit(1); } } while (0)
#define U32_MAX UINT32_MAX
#define U64_MAX UINT64_MAX
#define GFP_KERNEL 0
#define PPE_TB_CFG_SEARCH_MISS_MASK 3u
#define PPE_GLO_CFG_BUSY_MASK 2u
#define PPE_GLO_CFG_EN_MASK 1u
#define REG_PPE_PPE_FLOW_CFG(bank) ((bank) * 3)
#define REG_PPE_TB_CFG(bank) ((bank) * 3 + 1)
#define REG_PPE_GLO_CFG(bank) ((bank) * 3 + 2)
#define FIELD_PREP(mask, value) ((value) & (mask))
#define FIELD_GET(mask, value) ((value) & (mask))
#define AIROHA_FOE_IB1_BIND_STATE 3u
#define AIROHA_FOE_IB1_BIND_TIMESTAMP 0xf0u
#define AIROHA_FOE_STATE_BIND 2u
#define PPE_SRAM_NUM_ENTRIES 8192u
#define rcu_read_lock() CHECK(ppe_lock || flow_offload_mutex)
#define rcu_read_unlock() CHECK(ppe_lock || flow_offload_mutex)
#define rcu_dereference(pointer) (pointer)
#define wmb() CHECK(ppe_lock)
#define WRITE_ONCE(target, value) ((target) = (value))
#define rcu_access_pointer(pointer) (pointer)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define PPE1_BASE 0
#define PPE2_BASE 3
#define CT_CHECK_OWNED 0
#define CT_CLEAR_OWNED 1
#define CT_EXPECT_EMPTY 2
#define dev_err(...) ((void)0)
#define dev_info(...) ((void)0)
#define max(left, right) ((left) > (right) ? (left) : (right))
#define lockdep_assert_held(lock) CHECK(*(lock) == 1)
#define lockdep_is_held(lock) (*(lock) == 1)
#define rcu_dereference_protected(pointer, condition) ((condition) ? (pointer) : NULL)
#define read_poll_timeout_atomic(operation, value, condition, delay, timeout, sleep, ...) \
    ((value) = operation(__VA_ARGS__), (condition) ? 0 : -ETIMEDOUT)

struct airoha_npu { int present; };
struct airoha_npu_owner;
struct airoha_eth;
struct airoha_foe_entry { u32 ib1; u32 d[19]; };
struct airoha_ppe {
    struct airoha_eth *eth;
    struct airoha_npu_owner *ct_npu_owner;
    void *foe;
    bool ct_host_ppe, ct_restore_pending;
    bool ct_native_pairs, ct_pair_policy_allowed, ct_stopping, ct_owns_sram, ct_pair_failed;
    bool ct_pair_wired_registered;
    bool ct_pon_ifc_route_owned;
    bool ct_pon_qualified;
    u32 ct_pair_token;
    struct { u32 regs[2], glo; } ct_saved[2];
    u32 ct_pair_wired_epoch;
    struct { const void *owner; u32 epoch; u64 generation;
             bool pending, armed, touched, arm_pending, owner_quiesced, health_stopping; } ct_fe;
};
struct airoha_soc {
    int num_ppe;
    struct { int (*get_sport)(struct airoha_gdm_port *, int); } ops;
};
struct airoha_eth {
    struct airoha_ppe *ppe;
    struct airoha_npu *npu;
    struct airoha_soc *soc;
    int ct_route_lock;
    struct { const void *owner; bool ready, pon_open, revoked; } ct_bank1_routes;
    u32 regs[6];
    void *dev;
    struct airoha_qdma qdma[2];
    struct airoha_gdm_dev *pon;
    bool ct_cpu_fallback, ct_ifc_cpu_port_failed;
    bool ct_cpu_routes_ready, ct_cpu_ifc_disabled;
};

static int flow_offload_mutex = 1, ppe_lock;
static unsigned int allocated, freed, gate_calls[4], auth_calls[8], fe_calls, fe_arm_calls;
static int fail_gate = -1, fail_auth = -1, fail_write = -1;
static bool fail_alloc, fail_route, fail_fe, fail_release, fail_fe_release, busy_fe;
static u32 caps, gate_epoch, gate_generation, auth_epoch, auth_generation;
static u32 published_count, published_enabled;
static bool auth_lose_ack, auth_bad_echo, auth_change_generation;
static bool auth_query_change_generation;
static bool fail_arm, arm_change_generation, gate_change_generation, route_change_generation;
static u64 bridge_generation;
static u32 attempted_epoch;
static u64 attempted_generation;
static unsigned int commits, stats_updates;
static unsigned int revokes, restores;
static int fail_stop;
static bool gate_open_state;
static void (*gate_reply_hook)(struct npu_gate_message *);
static void (*auth_reply_hook)(struct npu_auth_message *);
static void (*route_claim_hook)(struct airoha_eth *);
static void (*before_free_hook)(void *);
static void (*before_spin_lock_hook)(int *);
#ifdef NPU_OWNER_HEALTH_TEST
static int fail_revoke;
static unsigned int route_revokes;
static void (*route_revoke_hook)(struct airoha_eth *);
#endif

static u32 airoha_ppe_get_total_sram_num_entries(struct airoha_ppe *ppe)
{
    return PPE_SRAM_NUM_ENTRIES * 2;
}
static u32 airoha_ppe_get_timestamp(struct airoha_ppe *ppe) { return 0x10; }
static int airoha_ppe_foe_commit_sram_entry(struct airoha_ppe *ppe, u32 hash)
{
    CHECK(ppe_lock);
    commits++;
    return 0;
}
static void airoha_ppe_foe_flow_stats_update(struct airoha_ppe *ppe, struct airoha_npu *npu,
                                           struct airoha_foe_entry *entry, u32 hash)
{
    CHECK(ppe_lock);
    stats_updates++;
}

#include "commit_entry.inc"

static void spin_lock_bh(int *lock)
{
    CHECK(!*lock);
    if (before_spin_lock_hook)
        before_spin_lock_hook(lock);
    CHECK(!*lock);
    *lock = 1;
}
static void spin_unlock_bh(int *lock) { CHECK(*lock == 1); *lock = 0; }
static void mutex_lock(int *lock) { CHECK(!*lock); *lock = 1; }
static void mutex_unlock(int *lock) { CHECK(*lock == 1); *lock = 0; }
#ifdef NPU_OWNER_HEALTH_TEST
static int mutex_trylock(int *lock)
{
    if (*lock)
        return 0;
    *lock = 1;
    return 1;
}
#endif
static void *kzalloc(size_t bytes, int flags)
{
    CHECK(!ppe_lock && flow_offload_mutex);
    if (fail_alloc)
        return NULL;
    allocated++;
    return calloc(1, bytes);
}
static void kfree(void *pointer)
{
    CHECK(!ppe_lock && flow_offload_mutex && pointer);
    if (before_free_hook)
        before_free_hook(pointer);
    freed++;
    free(pointer);
}
static u64 br_flow_offload_generation(void) { return bridge_generation; }
static u32 airoha_fe_rr(struct airoha_eth *eth, unsigned int address)
{
    CHECK(flow_offload_mutex && address < 6);
    return eth->regs[address];
}
static void airoha_fe_wr(struct airoha_eth *eth, unsigned int address, u32 value)
{
    CHECK(flow_offload_mutex && address < 6);
    if ((int)address == fail_write)
        return;
    eth->regs[address] = value;
}
static void airoha_fe_rmw(struct airoha_eth *eth, unsigned int address, u32 mask, u32 value)
{
    if (fail_stop == 6 && address == REG_PPE_GLO_CFG(1))
        return;
    airoha_fe_wr(eth, address, (airoha_fe_rr(eth, address) & ~mask) | value);
}
static int airoha_bank1_routes_claim(struct airoha_eth *eth, const void *owner)
{
    CHECK(flow_offload_mutex && !ppe_lock && owner);
    eth->ct_bank1_routes.owner = owner;
    eth->ct_bank1_routes.ready = !fail_route;
    eth->ct_bank1_routes.pon_open = false;
    eth->ct_bank1_routes.revoked = false;
    if (route_claim_hook)
        route_claim_hook(eth);
    return fail_route ? -EIO : 0;
}
#ifdef NPU_OWNER_HEALTH_TEST
static int airoha_bank1_routes_revoke(struct airoha_eth *eth, const void *owner)
{
    CHECK((ppe_lock || flow_offload_mutex) && !eth->ct_route_lock);
    spin_lock_bh(&eth->ct_route_lock);
    if (eth->ct_bank1_routes.owner != owner) {
        spin_unlock_bh(&eth->ct_route_lock);
        return -ESTALE;
    }
    route_revokes++;
    eth->ct_bank1_routes.pon_open = false;
    eth->ct_bank1_routes.ready = false;
    eth->ct_bank1_routes.revoked = true;
    spin_unlock_bh(&eth->ct_route_lock);
    if (route_revoke_hook)
        route_revoke_hook(eth);
    return fail_revoke;
}
#endif
static int airoha_bank1_routes_release(struct airoha_eth *eth, const void *owner)
{
    CHECK(flow_offload_mutex && !ppe_lock && eth->ct_bank1_routes.owner == owner);
    if (fail_release)
        return -EIO;
    eth->ct_bank1_routes.owner = NULL;
    eth->ct_bank1_routes.ready = false;
    return 0;
}
static int airoha_bank1_routes_open(struct airoha_eth *eth, const void *owner)
{
    CHECK(flow_offload_mutex && !ppe_lock && eth->ct_bank1_routes.owner == owner);
    CHECK(eth->ct_bank1_routes.ready && !eth->ct_bank1_routes.revoked);
    CHECK(eth->regs[REG_PPE_PPE_FLOW_CFG(1)] && gate_calls[GATE_OPEN]);
    if (fail_route)
        return -EIO;
    eth->ct_bank1_routes.pon_open = true;
    if (route_change_generation)
        bridge_generation++;
    return 0;
}
static int airoha_ct_fe_owner_claim(struct airoha_ppe *ppe, const void *owner)
{
    CHECK(ppe_lock && !ppe->ct_fe.owner);
    if (busy_fe)
        return -EBUSY;
    ppe->ct_fe.owner = owner;
    return 0;
}
static int airoha_ct_fe_owner_quiesce(struct airoha_ppe *ppe, const void *owner,
                                      u64 generation, u32 epoch)
{
    CHECK(ppe_lock && ppe->ct_fe.owner == owner);
    if (ppe->ct_fe.pending)
        CHECK(epoch == attempted_epoch && generation == attempted_generation);
    attempted_epoch = epoch;
    attempted_generation = generation;
    ppe->ct_fe.pending = true;
    fe_calls++;
    if (fail_fe)
        return -ETIMEDOUT;
    ppe->ct_fe.epoch = epoch;
    ppe->ct_fe.generation = generation;
    ppe->ct_fe.pending = false;
    ppe->ct_fe.armed = ppe->ct_fe.arm_pending = false;
    ppe->ct_fe.owner_quiesced = true;
    return 0;
}
static int airoha_ct_fe_owner_arm(struct airoha_ppe *ppe, const void *owner,
                                 u64 generation, u32 epoch)
{
    fe_arm_calls++;
    CHECK(ppe_lock && ppe->ct_fe.owner == owner && !ppe->ct_fe.pending);
    CHECK(generation == ppe->ct_fe.generation && epoch == ppe->ct_fe.epoch);
    ppe->ct_fe.owner_quiesced = false;
    ppe->ct_fe.arm_pending = true;
    if (fail_arm)
        return -ETIMEDOUT;
    ppe->ct_fe.arm_pending = false;
    ppe->ct_fe.armed = true;
    if (arm_change_generation)
        bridge_generation++;
    return 0;
}
static int airoha_ct_fe_owner_release(struct airoha_ppe *ppe, const void *owner)
{
    CHECK(ppe_lock && ppe->ct_fe.owner == owner);
    if (fail_fe_release)
        return -EIO;
    ppe->ct_fe.owner = NULL;
    ppe->ct_fe.owner_quiesced = false;
    return 0;
}

#include "return_stubs.inc"
#ifdef NPU_OWNER_BANK1_TEST
#include "bank1_stubs.inc"
#endif
#include "airoha_npu_owner.h"

static const u32 ct_bank0_regs[] = { 0, 1 };
static bool airoha_ppe_ct_requested(struct airoha_eth *eth) { return true; }
static int airoha_ct_native_pair_revoke(struct airoha_ppe *ppe, int band, u32 station)
{
    CHECK(ppe_lock && ppe->ct_fe.owner && !ppe->ct_fe.pending);
    revokes++;
    return (ppe->eth->regs[2] & PPE_GLO_CFG_EN_MASK) ? 0 : -EIO;
}
static int airoha_ct_pair_wlan_gate(struct airoha_ppe *ppe) { return 0; }
static int airoha_ppe_ct_stop_learning(struct airoha_ppe *ppe)
{
    CHECK(flow_offload_mutex);
    ppe->eth->regs[0] = ppe->eth->regs[3] = 0;
    return 0;
}
static int airoha_ppe_ct_quiesce(struct airoha_ppe *ppe)
{
    ppe->eth->regs[2] = 0;
    if (fail_stop == 7)
        return -EIO;
    ppe->eth->regs[5] = 0;
    return 0;
}
static int airoha_ppe_ct_check_sram(struct airoha_ppe *ppe, int operation) { return 0; }
static int airoha_ct_pon_ifc_cpu_stop(struct airoha_ppe *ppe) { return fail_stop == 1 ? -EIO : 0; }
static int airoha_ppe_ct_ifc_stop(struct airoha_ppe *ppe) { return fail_stop == 2 ? -EIO : 0; }
static int airoha_ppe_ct_smac_stop(struct airoha_ppe *ppe) { return fail_stop == 3 ? -EIO : 0; }
static int airoha_ct_pair_gdm_stop(struct airoha_ppe *ppe) { return fail_stop == 4 ? -EIO : 0; }
static void airoha_ppe_ct_regs(struct airoha_ppe *ppe, int bank, bool restore)
{
    CHECK(restore && bank >= 0 && bank < 2);
    restores++;
    if (fail_stop == 5)
        return;
    ppe->eth->regs[bank * 3] = ppe->ct_saved[bank].regs[0];
    ppe->eth->regs[bank * 3 + 1] = ppe->ct_saved[bank].regs[1];
}

#include "stop_entry.inc"
#include "shutdown_entry.inc"

int airoha_npu_gate_command(struct airoha_npu *npu, struct npu_gate_message *message)
{
    unsigned int operation = message->w[GM_ABI_OP] >> 16;
    CHECK(npu && (ppe_lock || flow_offload_mutex) && operation < 4);
#ifdef NPU_OWNER_HEALTH_TEST
    CHECK(operation == GATE_QUERY ? (!ppe_lock && flow_offload_mutex) : ppe_lock);
#else
    CHECK(!ppe_lock && flow_offload_mutex);
#endif
    gate_calls[operation]++;
    if ((int)operation == fail_gate)
        return -ETIMEDOUT;
    if (operation == GATE_QUERY)
        CHECK(!message->w[GM_EPOCH] && !message->w[GM_GENERATION]);
    else {
        gate_epoch = message->w[GM_EPOCH];
        gate_generation = message->w[GM_GENERATION];
    }
    message->w[GM_STATUS] = 0;
    message->w[GM_CAPS] = caps;
    message->w[GM_STATE_EPOCH] = gate_epoch;
    message->w[GM_STATE_GENERATION] = gate_generation;
    message->w[GM_AUTH_EPOCH] = auth_epoch;
    message->w[GM_AUTH_GENERATION] = auth_generation;
    if (operation == GATE_OPEN)
        gate_open_state = true;
    else if (operation != GATE_QUERY)
        gate_open_state = false;
    message->w[GM_CLOSED] = !gate_open_state;
    if (gate_open_state) {
        message->w[GM_CLOSED] = 0;
        message->w[GM_MASK] = GATE_PON2;
        message->w[GM_FE_ENABLED] = 1;
        message->w[GM_ER_FLAGS] = GATE_ER_BOUND;
        message->w[GM_AUTH_ENABLED] = published_enabled;
        if (operation == GATE_OPEN && gate_change_generation)
            bridge_generation++;
    }
    if (operation == GATE_QUIET) {
        CHECK(fe_calls && !fail_fe);
        message->w[GM_QUIET_ACK] = 1;
        message->w[GM_FE_QUIESCED] = 1;
        message->w[GM_DMA_IDLE] = 1;
    }
    if (gate_reply_hook)
        gate_reply_hook(message);
    return 0;
}
int airoha_npu_auth_command(struct airoha_npu *npu, struct npu_auth_message *message)
{
    unsigned int operation = message->w[AM_ABI_OP] >> 16;
    CHECK(npu && !ppe_lock && flow_offload_mutex && operation < 8);
    auth_calls[operation]++;
    if ((int)operation == fail_auth && !auth_lose_ack)
        return -ETIMEDOUT;
    CHECK(gate_calls[GATE_CLOSE]);
    if (operation == AUTH_MBOX_DISARM) {
        CHECK(message->w[AM_EPOCH] == auth_epoch);
        CHECK(message->w[AM_GENERATION] == auth_generation);
        published_enabled = 0;
    } else if (operation == AUTH_MBOX_BEGIN) {
        CHECK(message->w[AM_EPOCH] > auth_epoch);
        auth_epoch = message->w[AM_EPOCH];
        auth_generation = message->w[AM_GENERATION];
        published_count = published_enabled = 0;
    } else if (operation == AUTH_MBOX_ADD) {
        CHECK(message->w[AM_EPOCH] == auth_epoch && !published_enabled);
        CHECK(message->w[AM_GENERATION] == auth_generation);
        published_count++;
    } else if (operation == AUTH_MBOX_ARM) {
        CHECK(message->w[AM_EPOCH] == auth_epoch && published_count);
        CHECK(message->w[AM_GENERATION] == auth_generation);
        published_enabled = 1;
        if (auth_change_generation)
            bridge_generation++;
    } else {
        CHECK(operation == AUTH_MBOX_QUERY);
        if (auth_query_change_generation)
            bridge_generation++;
    }
    if ((int)operation == fail_auth)
        return -ETIMEDOUT;
    message->w[AM_STATUS] = 0;
    message->w[AM_CAPS] = AUTH_MBOX_CAPS;
    message->w[AM_STATE_EPOCH] = auth_epoch;
    message->w[AM_STATE_GENERATION] = auth_generation;
    message->w[AM_COUNT] = published_count;
    message->w[AM_ENABLED] = published_enabled;
    if (auth_bad_echo)
        message->w[AM_RULE + 19] ^= 1;
    if (auth_reply_hook)
        auth_reply_hook(message);
    return 0;
}

static void setup(struct airoha_eth *eth, struct airoha_ppe *ppe,
                  struct airoha_soc *soc, struct airoha_npu *npu)
{
    CHECK(!ppe_lock && allocated == freed);
    *soc = (struct airoha_soc) { .num_ppe = 2 };
    *npu = (struct airoha_npu) { .present = 1 };
    *ppe = (struct airoha_ppe) { .eth = eth, .ct_host_ppe = true,
                               .ct_owns_sram = true,
                               .ct_restore_pending = true, .ct_pair_wired_epoch = 9,
                               .ct_pair_wired_registered = true };
    ppe->ct_fe.epoch = 7;
    ppe->ct_fe.generation = 4;
    *eth = (struct airoha_eth) { .ppe = ppe, .soc = soc, .npu = npu,
                               .regs = { 0x1234, 0x9876, 1, 0xabcd, 0x1234, 1 } };
    fail_gate = fail_auth = fail_write = -1;
    fail_alloc = fail_route = fail_fe = fail_release = fail_fe_release = busy_fe = false;
    memset(gate_calls, 0, sizeof(gate_calls));
    memset(auth_calls, 0, sizeof(auth_calls));
    fe_calls = fe_arm_calls = 0;
    revokes = restores = 0;
    fail_stop = 0;
    caps = GATE_CAPS | GATE_CAP_PON2;
    gate_epoch = 11;
    gate_generation = 4;
    auth_epoch = 21;
    auth_generation = 19;
    bridge_generation = 4;
    published_count = published_enabled = 0;
    auth_lose_ack = auth_bad_echo = auth_change_generation = false;
    auth_query_change_generation = false;
    fail_arm = arm_change_generation = gate_change_generation = route_change_generation = false;
    gate_open_state = false;
    gate_reply_hook = NULL;
    auth_reply_hook = NULL;
    route_claim_hook = NULL;
    before_free_hook = NULL;
    before_spin_lock_hook = NULL;
#ifdef NPU_OWNER_BANK1_TEST
    bank1_retire_calls = bank1_clear_calls = bank1_cleared_rows = 0;
    bank1_clear_start = 0;
    bank1_retire_error = 0;
    bank1_fail_row = -1;
#endif
#ifdef NPU_OWNER_HEALTH_TEST
    fail_revoke = 0;
    route_revokes = 0;
    route_revoke_hook = NULL;
#endif
}

static void check_closed(struct airoha_eth *eth)
{
    struct airoha_npu_owner *owner = eth->ppe->ct_npu_owner;
    CHECK(owner && owner->txn.phase == NPU_TXN_CLOSED);
    CHECK(owner->txn.id.epoch == (auth_epoch == 21 ? 22u : 12u) &&
          owner->txn.id.generation == 4);
    CHECK(owner->bank1_saved && owner->bank1_flow == 0xabcd && owner->bank1_tb == 0x1234);
#ifdef NPU_OWNER_BANK1_TEST
    CHECK(owner->bank1_host_retired && owner->bank1_next_row == PPE_SRAM_NUM_ENTRIES);
#endif
    CHECK(eth->regs[0] == 0x1234 && eth->regs[1] == 0x9876 && eth->regs[2] == 1);
    CHECK(!eth->regs[3] && eth->regs[4] == 0x1236 && eth->regs[5] == 1);
    CHECK(eth->ct_bank1_routes.owner == owner && eth->ppe->ct_fe.owner == owner);
}

#include "return_test.inc"
#include "admission_test.inc"
#include "reopen_test.inc"
#ifdef NPU_OWNER_BANK1_TEST
#include "bank1_test.inc"
#endif
#ifdef NPU_OWNER_HEALTH_TEST
#include "health_test.inc"
#endif

static void check_binding(struct airoha_eth *eth)
{
    struct airoha_ppe *ppe = eth->ppe;
    const u32 hashes[] = { 0, 8191, 8192, 16383, 16384 };
    ppe->foe = calloc(16385, sizeof(struct airoha_foe_entry));
    CHECK(ppe->foe);
    spin_lock_bh(&ppe_lock);
    for (unsigned int index = 0; index < sizeof(hashes) / sizeof(hashes[0]); ++index) {
        for (u32 state = 0; state < 4; ++state) {
            struct airoha_foe_entry entry = { .ib1 = state, .d = { 0x1234 } };
            struct airoha_foe_entry *target = (struct airoha_foe_entry *)ppe->foe + hashes[index];
            struct airoha_foe_entry original;
            bool blocked = ppe->ct_npu_owner && hashes[index] >= 8192 &&
                           hashes[index] < 16384 && state == AIROHA_FOE_STATE_BIND;
            memset(target, 0xa5, sizeof(*target));
            original = *target;
            commits = stats_updates = 0;
            CHECK(airoha_ppe_foe_commit_entry(ppe, &entry, hashes[index], false) ==
                  (blocked ? -EBUSY : 0));
            if (blocked) {
                CHECK(!memcmp(target, &original, sizeof(*target)));
                CHECK(!commits && !stats_updates && entry.ib1 == state);
            } else {
                CHECK(commits == (hashes[index] < 16384 ? 1u : 0u));
                CHECK(stats_updates == 1 && !memcmp(target, &entry, sizeof(*target)));
            }
        }
    }
    spin_unlock_bh(&ppe_lock);
    free(ppe->foe);
    ppe->foe = NULL;
}

int main(void)
{
    struct airoha_eth eth;
    struct airoha_ppe ppe;
    struct airoha_soc soc;
    struct airoha_npu npu;
    const enum airoha_npu_txn_phase phases[] = {
        NPU_TXN_ROUTES_CLOSE, NPU_TXN_GATE_CLOSE, NPU_TXN_AUTH_QUERY,
        NPU_TXN_AUTH_DISARM, NPU_TXN_FE_QUIESCE, NPU_TXN_GATE_QUIET,
        NPU_TXN_PPE_DRAIN, NPU_TXN_PPE_DRAIN, NPU_TXN_PPE_DRAIN,
        NPU_TXN_PPE_DRAIN,
    };

    setup(&eth, &ppe, &soc, &npu);
    check_binding(&eth);
    CHECK(airoha_ppe_npu_owner_close_locked(&eth) == 0);
    CHECK(airoha_npu_owner_retire_locked(&ppe) == 0);
    CHECK(!allocated && !gate_calls[GATE_QUERY]);
    CHECK(airoha_ppe_npu_owner_close_locked(NULL) == -EINVAL);
    CHECK(airoha_ppe_npu_owner_claim_locked(NULL, 4) == -EINVAL);
    CHECK(airoha_ppe_npu_owner_claim_locked(&eth, 0) == -EINVAL);
    CHECK(airoha_ppe_npu_owner_claim_locked(&eth, (u64)U32_MAX + 5) == -EOVERFLOW);
    CHECK(!allocated);

    for (unsigned int scenario = 0; scenario < 15; ++scenario) {
        int expected = -ESTALE;
        setup(&eth, &ppe, &soc, &npu);
        switch (scenario) {
        case 0: fail_alloc = true; expected = -ENOMEM; break;
        case 1: eth.npu = NULL; expected = -ENODEV; break;
        case 2: caps = GATE_CAPS; expected = -EOPNOTSUPP; break;
        case 3: gate_epoch = U32_MAX; expected = -EOVERFLOW; break;
        case 4: ppe.ct_fe.epoch = U32_MAX; expected = -EOVERFLOW; break;
        case 5: ppe.ct_pair_wired_epoch = U32_MAX; expected = -EOVERFLOW; break;
        case 6: ppe.ct_fe.generation = 5; break;
        case 7: bridge_generation = 5; break;
        case 8: fail_gate = GATE_QUERY; expected = -ETIMEDOUT; break;
        case 9: busy_fe = true; expected = -EBUSY; break;
        case 10: ppe.ct_host_ppe = false; expected = -EOPNOTSUPP; break;
        case 11: soc.num_ppe = 1; expected = -EOPNOTSUPP; break;
        case 12: auth_epoch = U32_MAX; expected = -EOVERFLOW; break;
        case 13: ppe.ct_pon_ifc_route_owned = true; expected = -EBUSY; break;
        case 14: eth.ct_bank1_routes.owner = &soc; expected = -EBUSY; break;
        }
        CHECK(airoha_ppe_npu_owner_claim_locked(&eth, 4) == expected);
        CHECK(!ppe.ct_npu_owner && !ppe.ct_fe.owner);
        CHECK(eth.ct_bank1_routes.owner == (scenario == 14 ? &soc : NULL));
        CHECK(allocated == freed && !gate_calls[GATE_CLOSE]);
    }

    for (unsigned int scenario = 0; scenario < sizeof(phases) / sizeof(phases[0]); ++scenario) {
        struct airoha_npu_owner *owner;
        setup(&eth, &ppe, &soc, &npu);
        switch (scenario) {
        case 0: fail_route = true; break;
        case 1: fail_gate = GATE_CLOSE; break;
        case 2: fail_auth = AUTH_MBOX_QUERY; break;
        case 3: fail_auth = AUTH_MBOX_DISARM; break;
        case 4: fail_fe = true; break;
        case 5: fail_gate = GATE_QUIET; break;
        case 6: fail_write = REG_PPE_PPE_FLOW_CFG(1); break;
        case 7: fail_write = REG_PPE_TB_CFG(1); break;
        case 8: eth.regs[5] |= PPE_GLO_CFG_BUSY_MASK; break;
        case 9: eth.regs[5] = 0; break;
        }
        CHECK(airoha_ppe_npu_owner_claim_locked(&eth, 4) < 0);
        owner = ppe.ct_npu_owner;
        CHECK(owner && owner->txn.phase == phases[scenario]);
        CHECK(ppe.ct_fe.owner == owner && allocated == freed + 1);
        CHECK(airoha_npu_owner_retire_locked(&ppe) == -EBUSY);
        CHECK(airoha_ppe_npu_owner_claim_locked(&eth, 5) == -ESTALE);
        CHECK(ppe.ct_npu_owner == owner && owner->txn.phase == phases[scenario]);
        fail_route = fail_fe = false;
        fail_gate = fail_auth = fail_write = -1;
        eth.regs[5] = 1;
        CHECK(airoha_ppe_npu_owner_claim_locked(&eth, 4) == 0);
        check_closed(&eth);
        check_binding(&eth);
        CHECK(gate_calls[GATE_QUERY] == 1);
        CHECK(fe_calls == (scenario == 4 ? 2u : 1u));
        CHECK(gate_calls[GATE_CLOSE] == (scenario == 1 ? 2u : 1u));
        CHECK(airoha_ppe_npu_owner_close_locked(&eth) == 0);
        CHECK(airoha_npu_owner_retire_locked(&ppe) == 0);
        CHECK(!ppe.ct_npu_owner && !ppe.ct_fe.owner && !eth.ct_bank1_routes.owner);
        CHECK(allocated == freed);
    }

    for (unsigned int scenario = 0; scenario < 3; ++scenario) {
        setup(&eth, &ppe, &soc, &npu);
        if (scenario == 2)
            auth_epoch = auth_generation = 0;
        CHECK(airoha_ppe_npu_owner_claim_locked(&eth, 4) == 0);
        check_closed(&eth);
        CHECK(auth_calls[AUTH_MBOX_DISARM] == (scenario == 2 ? 0u : 1u));
        fail_release = scenario == 0;
        fail_fe_release = scenario == 1;
        if (scenario < 2) {
            CHECK(airoha_npu_owner_retire_locked(&ppe) == -EIO);
            CHECK(ppe.ct_npu_owner && ppe.ct_fe.owner && allocated == freed + 1);
            fail_release = fail_fe_release = false;
        }
        CHECK(airoha_npu_owner_retire_locked(&ppe) == 0);
    }
    CHECK(allocated == freed);
    for (unsigned int scenario = 0; scenario < 2; ++scenario) {
        setup(&eth, &ppe, &soc, &npu);
        ppe.ct_native_pairs = ppe.ct_owns_sram = true;
        ppe.ct_pair_token = 100;
        CHECK(airoha_ppe_npu_owner_claim_locked(&eth, 4) == 0);
        fail_release = scenario == 0;
        fail_fe_release = scenario == 1;
        flow_offload_mutex = 0;
        CHECK(airoha_ppe_ct_shutdown(&eth) == -EIO);
        CHECK(ppe.ct_npu_owner && ppe.ct_npu_owner->stop_completed);
        CHECK(!ppe.ct_host_ppe && ppe.ct_restore_pending && ppe.ct_stopping);
        CHECK(!eth.regs[2] && !eth.regs[5] && revokes == 1 && restores == 2);
        fail_release = fail_fe_release = false;
        CHECK(airoha_ppe_ct_shutdown(&eth) == 0);
        CHECK(!ppe.ct_npu_owner && !ppe.ct_restore_pending);
        CHECK(revokes == 1 && restores == 2 && !flow_offload_mutex);
        flow_offload_mutex = 1;
    }
    CHECK(allocated == freed);
    for (int stage = 1; stage <= 7; ++stage) {
        setup(&eth, &ppe, &soc, &npu);
        ppe.ct_native_pairs = ppe.ct_owns_sram = true;
        ppe.ct_pair_token = 100;
        if (stage == 6)
            ppe.ct_saved[1].glo = PPE_GLO_CFG_EN_MASK;
        CHECK(airoha_ppe_npu_owner_claim_locked(&eth, 4) == 0);
        fail_stop = stage;
        flow_offload_mutex = 0;
        CHECK(airoha_ppe_ct_shutdown(&eth) == -EIO);
        CHECK(ppe.ct_npu_owner && ppe.ct_npu_owner->native_stopped &&
              !ppe.ct_npu_owner->stop_completed && ppe.ct_restore_pending);
        CHECK(!eth.regs[2] && revokes == 1);
        fail_stop = 0;
        CHECK(airoha_ppe_ct_shutdown(&eth) == 0);
        CHECK(!ppe.ct_npu_owner && !ppe.ct_restore_pending && revokes == 1);
        CHECK(!flow_offload_mutex);
        flow_offload_mutex = 1;
    }
    CHECK(allocated == freed);
    check_returns();
    check_authorization();
    check_reopen();
#ifdef NPU_OWNER_BANK1_TEST
    check_bank1_retirement();
#endif
#ifdef NPU_OWNER_HEALTH_TEST
    check_health();
#endif
    printf("npu owner: %u checks passed\n", checks);
    return 0;
}
