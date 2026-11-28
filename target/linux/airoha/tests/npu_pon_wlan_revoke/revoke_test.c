#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define BIT(bit) (1u << (bit))
#define GENMASK(high, low) ((UINT32_MAX >> (31 - (high))) & (UINT32_MAX << (low)))
#define FIELD_GET(mask, value) (((value) & (mask)) >> __builtin_ctz(mask))
#define FIELD_PREP(mask, value) (((u32)(value) << __builtin_ctz(mask)) & (mask))
#define DECLARE_FLEX_ARRAY(type, name) type name[0]
#undef static_assert
#define static_assert(condition) _Static_assert(condition, #condition)
#define READ_ONCE(value) (value)
#define U32_MAX UINT32_MAX
#define AIROHA_CT_PAIR_SLOTS 32
#define AIROHA_GDM2_IDX 2
#define AIROHA_DEV_F_PON 2
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))

@FOE_TYPES@

static const char *test_case;
static unsigned cases, checks;
#define CHECK(condition) do { checks++; if (!(condition)) { \
    fprintf(stderr, "FAIL [%s] line %d: %s\n", test_case, __LINE__, #condition); \
    exit(1); } } while (0)

struct list_head { struct list_head *next, *prev; };
struct hlist_node { bool linked; };
struct rhash_head { bool indexed; };
struct airoha_gdm_dev;
struct airoha_ppe;
struct net_device { struct airoha_gdm_dev *priv; bool running, carrier; };
struct port { unsigned id; };
struct device_node { bool diagnostic; };
struct device { struct device_node *of_node; };
struct airoha_qdma { unsigned identity; };
struct airoha_pon_link_ops { unsigned identity; };
struct airoha_flow_table_entry {
    struct airoha_foe_entry data;
    struct airoha_gdm_dev *egress_dev;
    struct { u8 band; u16 wcid; } ct_src;
    bool ct_bridge, freed;
    u32 hash;
    struct hlist_node list;
    struct rhash_head node;
    struct list_head gc_node, ct_bridge_node;
};
struct rhashtable { struct airoha_flow_table_entry *entries[12]; unsigned count; };
struct rhashtable_iter { struct rhashtable *table; unsigned cursor; };
struct airoha_eth {
    struct device *dev;
    struct airoha_qdma qdma[2];
    struct rhashtable flow_table;
    bool ct_cpu_fallback, ct_pon_full, ct_ordinary_full_test;
    bool ct_cpu_routes_ready, ct_cpu_ifc_disabled, ct_cpu_wlan_gated;
};
struct airoha_gdm_dev {
    struct airoha_eth *eth;
    struct port *port;
    unsigned long flags;
    unsigned nbq, pon_qdma_tag;
    bool valid, pon_update_blocked;
    const struct airoha_pon_link_ops *pon_link_ops;
    void *pon_link_priv;
    struct airoha_qdma *qdma;
};
struct airoha_npu_owner {
    struct {
        u64 serial, generation;
        struct net_device *ingress, *egress;
    } production;
    struct net_device *diag_lower;
    const struct airoha_pon_link_ops *production_controller;
    void *production_priv;
    bool retiring, invalidated, close_pending;
};
struct native_pair { bool used; };
struct airoha_ppe {
    struct airoha_eth *eth;
    struct airoha_npu_owner *ct_npu_owner;
    struct native_pair *ct_pairs;
    bool ct_host_ppe, ct_native_pairs, ct_stopping, ct_pon_qualified;
    bool ct_pair_failed, ct_pair_policy_allowed, ct_pair_hw_stopped, ct_bridge_failed;
    struct { bool health_stopping; } ct_fe;
    u32 ct_wlan_epoch[2][151];
    bool ct_wlan_blocked[2][151];
};
struct airoha_ppe_dev { struct airoha_ppe *priv; };

static int flow_offload_mutex, ppe_lock;
static unsigned notify_calls, closed_calls, fail_calls, read_calls, commit_calls, free_calls;
static unsigned walk_calls, bridge_fail_calls;
static int notify_error, closed_error, commit_error, read_error_hash, bridge_error;
static int last_band;
static u16 last_wcid;
static bool flushing;
static u8 flush_band;
static u16 flush_wcid;
static u32 expected_epoch;
static u64 generation;
static struct airoha_ppe ppe;
static struct airoha_eth eth;
static struct airoha_npu_owner owner;
static struct native_pair pairs[AIROHA_CT_PAIR_SLOTS];
static struct airoha_gdm_dev ingress, egress;
static struct net_device ingress_net, egress_net;
static struct port ingress_port, egress_port;
static struct device device;
static struct device_node device_node;
static struct airoha_pon_link_ops controller;
static struct airoha_ppe_dev ppe_dev;
static struct airoha_flow_table_entry entries[8];
static struct airoha_foe_entry hardware[8];
static const int airoha_flow_table_params;

#define lockdep_assert_held(lock) CHECK(*(lock) == 1)
static void mutex_lock(int *lock)
{
    CHECK(!*lock && !ppe_lock);
    *lock = 1;
}
static void mutex_unlock(int *lock)
{
    CHECK(*lock == 1 && !ppe_lock);
    *lock = 0;
}
static void spin_lock_bh(int *lock)
{
    CHECK(!*lock);
    *lock = 1;
}
static void spin_unlock_bh(int *lock)
{
    CHECK(*lock == 1);
    *lock = 0;
}
static u64 br_flow_offload_generation(void) { return generation; }
static bool of_property_read_bool(struct device_node *node, const char *name)
{
    CHECK(!strcmp(name, "airoha,connac2-pon-er-diagnostic"));
    return node->diagnostic;
}
static void *netdev_priv(struct net_device *dev) { return dev->priv; }
static bool airoha_is_valid_gdm_dev(struct airoha_eth *parent, struct airoha_gdm_dev *dev)
{
    return dev && dev->valid && dev->eth == parent;
}
static bool test_bit(unsigned bit, const unsigned long *value) { return !!(*value & BIT(bit)); }
static bool netif_running(struct net_device *dev) { return dev->running; }
static bool netif_carrier_ok(struct net_device *dev) { return dev->carrier; }
#define rcu_access_pointer(pointer) (pointer)

static void list_init(struct list_head *head) { head->next = head->prev = head; }
#define LIST_HEAD(name) struct list_head name = { &(name), &(name) }
static bool list_empty(struct list_head *head) { return head->next == head; }
static void list_add_tail(struct list_head *node, struct list_head *head)
{
    CHECK(list_empty(node));
    node->prev = head->prev;
    node->next = head;
    head->prev->next = node;
    head->prev = node;
}
static void list_del_init(struct list_head *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
    list_init(node);
}
#define list_for_each_entry_safe(entry, next_entry, head, member) \
    for (entry = container_of((head)->next, __typeof__(*entry), member), \
         next_entry = container_of(entry->member.next, __typeof__(*entry), member); \
         &entry->member != (head); \
         entry = next_entry, next_entry = container_of(entry->member.next, __typeof__(*entry), member))
static void hlist_del_init(struct hlist_node *node)
{
    lockdep_assert_held(&ppe_lock);
    node->linked = false;
}
static void check_flush_gate(void)
{
    if (flushing) {
        CHECK(flow_offload_mutex == 1);
        CHECK(ppe.ct_wlan_blocked[flush_band][flush_wcid]);
        CHECK(ppe.ct_wlan_epoch[flush_band][flush_wcid] == expected_epoch);
    }
}
static void rhashtable_walk_enter(struct rhashtable *table, struct rhashtable_iter *iter)
{
    CHECK(!ppe_lock);
    check_flush_gate();
    walk_calls++;
    iter->table = table;
    iter->cursor = 0;
}
static void rhashtable_walk_start(struct rhashtable_iter *iter) { (void)iter; }
static void rhashtable_walk_stop(struct rhashtable_iter *iter) { (void)iter; }
static void rhashtable_walk_exit(struct rhashtable_iter *iter) { (void)iter; }
static struct airoha_flow_table_entry *rhashtable_walk_next(struct rhashtable_iter *iter)
{
    check_flush_gate();
    if (!iter->cursor++)
        return (void *)(intptr_t)-EAGAIN;
    unsigned index = iter->cursor - 2;
    return index < iter->table->count ? iter->table->entries[index] : NULL;
}
#define IS_ERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
static void rhashtable_remove_fast(struct rhashtable *table, struct rhash_head *node, int params)
{
    CHECK(!ppe_lock && flow_offload_mutex);
    CHECK(node->indexed);
    node->indexed = false;
}
static void kfree(struct airoha_flow_table_entry *entry)
{
    CHECK(!entry->freed && !entry->node.indexed && !entry->list.linked);
    CHECK(entry->hash == 0xffff && list_empty(&entry->gc_node));
    if (entry->ct_bridge)
        CHECK(list_empty(&entry->ct_bridge_node));
    entry->freed = true;
    free_calls++;
}
static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *dev, u32 hash)
{
    lockdep_assert_held(&ppe_lock);
    check_flush_gate();
    CHECK(hash < 8);
    read_calls++;
    return (int)hash == read_error_hash ? NULL : &hardware[hash];
}
static int airoha_ppe_foe_commit_entry(struct airoha_ppe *dev, const struct airoha_foe_entry *row,
                                      u32 hash, bool native)
{
    lockdep_assert_held(&ppe_lock);
    check_flush_gate();
    CHECK(hash < 8 && !native);
    CHECK(FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, row->ib1) == AIROHA_FOE_STATE_INVALID);
    commit_calls++;
    if (!commit_error)
        hardware[hash] = *row;
    return commit_error;
}
static int airoha_ppe_ct_bridge_fail_closed(struct airoha_ppe *dev)
{
    lockdep_assert_held(&ppe_lock);
    dev->ct_bridge_failed = true;
    bridge_fail_calls++;
    return bridge_error;
}
static int airoha_npu_owner_notify(struct airoha_ppe *dev, void *info)
{
    lockdep_assert_held(&ppe_lock);
    CHECK(!info);
    notify_calls++;
    if (dev->ct_npu_owner)
        dev->ct_npu_owner->invalidated = true;
    return notify_error;
}
static int airoha_ct_native_pair_revoke_closed(struct airoha_ppe *dev, int band, u16 wcid)
{
    lockdep_assert_held(&ppe_lock);
    CHECK(!dev->ct_host_ppe || notify_calls == 1);
    CHECK(!dev->ct_host_ppe || !dev->ct_npu_owner || dev->ct_npu_owner->invalidated);
    closed_calls++;
    last_band = band;
    last_wcid = wcid;
    return closed_error;
}
static int airoha_ct_pair_fail(struct airoha_ppe *dev, int error)
{
    lockdep_assert_held(&ppe_lock);
    CHECK(error == -EOVERFLOW);
    fail_calls++;
    dev->ct_pair_failed = true;
    if (dev->ct_npu_owner)
        dev->ct_npu_owner->invalidated = true;
    return error;
}

@PRODUCTION_ACTIVE@
@REVOKE@
@PPE_FUNCTIONS@

static void reset(const char *name)
{
    CHECK(!ppe_lock && !flow_offload_mutex);
    test_case = name;
    cases++;
    memset(&ppe, 0, sizeof(ppe));
    memset(&eth, 0, sizeof(eth));
    memset(&owner, 0, sizeof(owner));
    memset(pairs, 0, sizeof(pairs));
    memset(entries, 0, sizeof(entries));
    memset(hardware, 0, sizeof(hardware));
    notify_calls = closed_calls = fail_calls = read_calls = commit_calls = free_calls = 0;
    walk_calls = bridge_fail_calls = 0;
    notify_error = closed_error = commit_error = bridge_error = 0;
    read_error_hash = -1;
    last_band = -99;
    last_wcid = 0;
    flushing = false;
    generation = 71;
    device_node.diagnostic = false;
    device.of_node = &device_node;
    eth.dev = &device;
    eth.ct_pon_full = true;
    ppe.eth = &eth;
    ppe.ct_npu_owner = &owner;
    ppe.ct_pairs = pairs;
    ppe.ct_host_ppe = ppe.ct_native_pairs = true;
    ppe_dev.priv = &ppe;
    ingress_port.id = AIROHA_GDM2_IDX;
    egress_port.id = 4;
    ingress = (struct airoha_gdm_dev) {
        .eth = &eth, .port = &ingress_port, .flags = BIT(AIROHA_DEV_F_PON), .valid = true,
        .pon_link_ops = &controller, .pon_link_priv = &controller, .qdma = &eth.qdma[1],
    };
    egress = (struct airoha_gdm_dev) { .eth = &eth, .port = &egress_port, .valid = true };
    ingress_net = (struct net_device) { &ingress, true, true };
    egress_net = (struct net_device) { &egress, true, true };
    owner.production.serial = 23;
    owner.production.generation = generation;
    owner.production.ingress = &ingress_net;
    owner.production.egress = &egress_net;
    owner.production_controller = &controller;
    owner.production_priv = &controller;
    CHECK(airoha_ppe_npu_production_active(&ppe, &owner));
}
static int revoke(int band, u16 wcid)
{
    spin_lock_bh(&ppe_lock);
    int result = airoha_ct_native_pair_revoke(&ppe, band, wcid);
    spin_unlock_bh(&ppe_lock);
    return result;
}
static int flush(u8 band, u16 wcid)
{
    flush_band = band;
    flush_wcid = wcid;
    expected_epoch = ppe.ct_wlan_epoch[band][wcid] + 1;
    flushing = true;
    int result = airoha_ppe_ct_flush_wlan(&ppe_dev, band, wcid);
    flushing = false;
    CHECK(!ppe_lock && !flow_offload_mutex);
    return result;
}
static struct airoha_flow_table_entry *add_flow(unsigned index, u8 band, u16 wcid,
                                               bool ipv6, bool bound)
{
    struct airoha_flow_table_entry *entry = &entries[index];
    entry->data.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND) |
        FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE, ipv6 ? PPE_PKT_TYPE_IPV6_ROUTE_5T : PPE_PKT_TYPE_IPV4_HNAPT);
    u32 ib2 = FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_GDM3) |
        FIELD_PREP(AIROHA_FOE_IB2_NBQ, band + 2);
    u32 data = FIELD_PREP(AIROHA_FOE_CHANNEL, band + 8);
    if (ipv6) {
        entry->data.ipv6.src_ip[0] = index + 1;
        entry->data.ipv6.ib2 = ib2;
        entry->data.ipv6.data = data;
        entry->data.ipv6.l2.etype = wcid << 6;
    } else {
        entry->data.ipv4.orig_tuple.src_ip = index + 1;
        entry->data.ipv4.ib2 = ib2;
        entry->data.ipv4.data = data;
        entry->data.ipv4.l2.common.etype = wcid << 6;
    }
    entry->hash = bound ? index : 0xffff;
    entry->node.indexed = entry->list.linked = true;
    list_init(&entry->gc_node);
    list_init(&entry->ct_bridge_node);
    hardware[index] = entry->data;
    eth.flow_table.entries[eth.flow_table.count++] = entry;
    return entry;
}

static void test_active_cleanup(void)
{
    for (unsigned band = 0; band < 2; band++) {
        for (unsigned wcid = 1; wcid <= 150; wcid++) {
            reset("active production station cleanup");
            ppe.ct_wlan_epoch[band][wcid] = 7;
            struct airoha_flow_table_entry *bound = add_flow(0, band, wcid, false, true);
            struct airoha_flow_table_entry *pending = add_flow(1, band, wcid, false, false);
            struct airoha_flow_table_entry *ipv6 = add_flow(2, band, wcid, true, true);
            struct airoha_flow_table_entry *bridge = add_flow(3, !band, wcid, false, true);
            bridge->ct_bridge = true;
            bridge->ct_src.band = band;
            bridge->ct_src.wcid = wcid;
            LIST_HEAD(bridges);
            list_add_tail(&bridge->ct_bridge_node, &bridges);
            add_flow(4, !band, wcid, false, true);
            add_flow(5, band, wcid == 150 ? 1 : wcid + 1, false, true);
            add_flow(6, band, wcid, false, true)->egress_dev = &egress;
            struct airoha_foe_entry original[8];
            memcpy(original, hardware, sizeof(original));
            eth.flow_table.entries[eth.flow_table.count++] = bound;
            CHECK(airoha_ppe_ct_wlan_epoch(&ppe_dev, band, wcid) == 8);
            CHECK(flush(band, wcid) == 0);
            CHECK(!notify_calls && !closed_calls && !fail_calls);
            CHECK(!owner.invalidated && airoha_ppe_npu_production_active(&ppe, &owner));
            CHECK(ppe.ct_wlan_epoch[band][wcid] == 8);
            CHECK(airoha_ppe_ct_wlan_epoch(&ppe_dev, band, wcid) == 9);
            CHECK(!ppe.ct_wlan_blocked[band][wcid]);
            CHECK(bound->freed && pending->freed && ipv6->freed && bridge->freed);
            CHECK(free_calls == 4 && commit_calls == 3 && read_calls == 3 && walk_calls == 1);
            CHECK(list_empty(&bridges));
            for (unsigned index = 0; index < 8; index++) {
                if (index == 0 || index == 2 || index == 3)
                    original[index].ib1 &= ~AIROHA_FOE_IB1_BIND_STATE;
                CHECK(!memcmp(&original[index], &hardware[index], sizeof(hardware[index])));
                if (index >= 4 && index <= 6)
                    CHECK(!entries[index].freed && entries[index].node.indexed && entries[index].list.linked);
            }
        }
    }
}

static void test_inactive_barriers(void)
{
    for (unsigned mode = 0; mode < 36; mode++) {
        reset("inactive production uses owner barrier");
        switch (mode) {
        case 0: ppe.ct_npu_owner = NULL; break;
        case 1: owner.production.serial = 0; break;
        case 2: owner.diag_lower = &ingress_net; break;
        case 3: owner.retiring = true; break;
        case 4: owner.invalidated = true; break;
        case 5: owner.close_pending = true; break;
        case 6: ppe.ct_pair_failed = true; break;
        case 7: eth.ct_cpu_fallback = true; break;
        case 8: eth.ct_pon_full = false; break;
        case 9: eth.ct_ordinary_full_test = true; break;
        case 10: ppe.ct_pon_qualified = true; break;
        case 11: ppe.ct_pair_policy_allowed = true; break;
        case 12: ppe.ct_native_pairs = false; break;
        case 13: ppe.ct_pairs = NULL; break;
        case 14: ppe.ct_stopping = true; break;
        case 15: owner.production.ingress = NULL; break;
        case 16: owner.production.egress = NULL; break;
        case 17: owner.production.generation++; break;
        case 18: device_node.diagnostic = true; break;
        case 19: pairs[AIROHA_CT_PAIR_SLOTS - 1].used = true; break;
        case 20: ingress.valid = false; break;
        case 21: egress.valid = false; break;
        case 22: ingress.flags = 0; break;
        case 23: egress.flags = BIT(AIROHA_DEV_F_PON); break;
        case 24: ingress_port.id = 4; break;
        case 25: ingress.nbq = 1; break;
        case 26: ingress.pon_link_ops = NULL; break;
        case 27: ingress.pon_link_priv = NULL; break;
        case 28: ingress.pon_update_blocked = true; break;
        case 29: egress.pon_update_blocked = true; break;
        case 30: ingress_net.running = false; break;
        case 31: ingress_net.carrier = false; break;
        case 32: egress_net.running = false; break;
        case 33: egress_net.carrier = false; break;
        case 34: ingress.pon_qdma_tag = 1; break;
        case 35: ingress.qdma = &eth.qdma[0]; break;
        }
        CHECK(!airoha_ppe_npu_production_active(&ppe, ppe.ct_npu_owner));
        CHECK(revoke(0, 24) == 0);
        CHECK(notify_calls == 1 && closed_calls == 1 && !fail_calls);
        CHECK(last_band == 0 && last_wcid == 24);
    }
    reset("owner token mismatch");
    CHECK(!airoha_ppe_npu_production_active(&ppe, &ppe));
    for (unsigned slot = 0; slot < AIROHA_CT_PAIR_SLOTS; slot++) {
        reset("every occupied native pair excludes production");
        pairs[slot].used = true;
        CHECK(!airoha_ppe_npu_production_active(&ppe, &owner));
        CHECK(revoke(1, 150) == 0);
        CHECK(notify_calls == 1 && closed_calls == 1);
    }
    reset("inactive flush still cleans WLAN rows");
    ppe.ct_pair_policy_allowed = true;
    add_flow(0, 0, 24, false, true);
    CHECK(flush(0, 24) == 0);
    CHECK(notify_calls == 1 && closed_calls == 1 && entries[0].freed);
    CHECK(ppe.ct_wlan_epoch[0][24] == 1 && !ppe.ct_wlan_blocked[0][24]);
}

static void test_barrier_errors(void)
{
    const struct { int band; u16 wcid; } targets[] = {
        { -1, 0 }, { -1, 24 }, { 2, 24 }, { 2, 1 }, { 0, 0 }, { 1, 151 }, { 3, 24 },
    };
    for (unsigned index = 0; index < sizeof(targets) / sizeof(targets[0]); index++) {
        for (unsigned mode = 0; mode < 3; mode++) {
            reset("global LAN1 and invalid station barriers");
            notify_error = mode == 1 ? -EAGAIN : 0;
            closed_error = mode == 2 ? -EIO : 0;
            CHECK(revoke(targets[index].band, targets[index].wcid) ==
                  (notify_error ? notify_error : closed_error));
            CHECK(notify_calls == 1 && closed_calls == (mode != 1));
            CHECK(owner.invalidated && !fail_calls);
            if (mode != 1)
                CHECK(last_band == targets[index].band && last_wcid == targets[index].wcid);
        }
    }
    for (unsigned mode = 0; mode < 2; mode++) {
        reset("inactive flush barrier failure keeps station blocked");
        ppe.ct_pair_policy_allowed = true;
        notify_error = mode ? 0 : -EAGAIN;
        closed_error = mode ? -EIO : 0;
        add_flow(0, 0, 24, false, true);
        CHECK(flush(0, 24) == (mode ? -EIO : -EAGAIN));
        CHECK(ppe.ct_wlan_blocked[0][24] && ppe.ct_wlan_epoch[0][24] == 0);
        CHECK(!walk_calls && !free_calls && !read_calls && !commit_calls);
        CHECK(entries[0].node.indexed && entries[0].list.linked);
    }
    reset("nonhost legacy revoke");
    ppe.ct_host_ppe = false;
    owner.production.serial = 0;
    CHECK(revoke(0, 24) == 0);
    CHECK(!notify_calls && closed_calls == 1);
}

static void test_epoch_exhaustion(void)
{
    for (unsigned band = 0; band < 2; band++) {
        for (unsigned wcid = 1; wcid <= 150; wcid++) {
            reset("exhausted epoch fails closed before cleanup");
            ppe.ct_wlan_epoch[band][wcid] = U32_MAX;
            add_flow(0, band, wcid, false, true);
            CHECK(flush(band, wcid) == -EOVERFLOW);
            CHECK(fail_calls == 1 && !notify_calls && !closed_calls);
            CHECK(owner.invalidated && ppe.ct_pair_failed);
            CHECK(ppe.ct_wlan_epoch[band][wcid] == U32_MAX && ppe.ct_wlan_blocked[band][wcid]);
            CHECK(!walk_calls && !read_calls && !commit_calls && !free_calls);
            CHECK(airoha_ppe_ct_wlan_epoch(&ppe_dev, band, wcid) == 0);
            CHECK(entries[0].node.indexed && entries[0].list.linked);
        }
        reset("last epoch retires without wrap");
        ppe.ct_wlan_epoch[band][150] = U32_MAX - 1;
        CHECK(flush(band, 150) == 0);
        CHECK(ppe.ct_wlan_epoch[band][150] == U32_MAX && !fail_calls);
        CHECK(airoha_ppe_ct_wlan_epoch(&ppe_dev, band, 150) == 0);
        CHECK(flush(band, 150) == -EOVERFLOW);
        CHECK(ppe.ct_wlan_epoch[band][150] == U32_MAX && fail_calls == 1);
    }
}

static void test_row_identity_and_errors(void)
{
    for (unsigned mode = 0; mode < 8; mode++) {
        reset("reused hardware row is preserved");
        struct airoha_flow_table_entry *entry = add_flow(0, 0, 24, mode == 7, true);
        entry->ct_bridge = mode >= 4;
        switch (mode) {
        case 0: hardware[0].ipv4.orig_tuple.src_ip++; break;
        case 1: hardware[0].ib1 ^= AIROHA_FOE_IB1_BIND_UDP; break;
        case 2: hardware[0].ib1 &= ~AIROHA_FOE_IB1_BIND_STATE; break;
        case 3: hardware[0].ipv4.l2.common.etype = 25 << 6; break;
        case 4: hardware[0].ib1 |= AIROHA_FOE_IB1_BIND_TTL; break;
        case 5: hardware[0].ipv4.new_tuple.src_ip++; break;
        case 6: hardware[0].ipv4.l2.src_mac_lo++; break;
        case 7: hardware[0].ipv6.l2.src_mac_hi++; break;
        }
        struct airoha_foe_entry original = hardware[0];
        CHECK(flush(0, 24) == 0);
        CHECK(entry->freed && !commit_calls && read_calls == 1);
        CHECK(!memcmp(&original, &hardware[0], sizeof(original)));
        CHECK(!owner.invalidated);
    }
    for (unsigned mode = 0; mode < 2; mode++) {
        reset("SRAM failure retains cookie for retry");
        add_flow(0, 0, 24, false, true);
        add_flow(1, 0, 24, false, false);
        read_error_hash = mode ? -1 : 0;
        commit_error = mode ? -EIO : 0;
        CHECK(flush(0, 24) == (mode ? -EIO : -ETIMEDOUT));
        CHECK(ppe.ct_wlan_blocked[0][24] && ppe.ct_wlan_epoch[0][24] == 1);
        CHECK(!entries[0].freed && entries[0].node.indexed && !entries[0].list.linked);
        CHECK(entries[0].hash == 0 && list_empty(&entries[0].gc_node));
        CHECK(entries[1].freed && free_calls == 1);
        CHECK(airoha_ppe_ct_wlan_epoch(&ppe_dev, 0, 24) == 0);
        read_error_hash = -1;
        commit_error = 0;
        eth.flow_table.count = 1;
        CHECK(flush(0, 24) == 0);
        CHECK(entries[0].freed && !ppe.ct_wlan_blocked[0][24]);
    }
    reset("bridge SRAM error uses fault-close boundary");
    add_flow(0, 0, 24, false, true)->ct_bridge = true;
    read_error_hash = 0;
    bridge_error = -EIO;
    CHECK(flush(0, 24) == -EIO);
    CHECK(bridge_fail_calls == 1 && !entries[0].freed && ppe.ct_wlan_blocked[0][24]);
}

static void test_flush_guards(void)
{
    const struct { u8 band; u16 wcid; } invalid[] = { { 2, 24 }, { 0, 0 }, { 1, 151 } };
    for (unsigned index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
        reset("invalid flush rejected before locking");
        CHECK(airoha_ppe_ct_flush_wlan(&ppe_dev, invalid[index].band, invalid[index].wcid) == -EINVAL);
        CHECK(!ppe_lock && !flow_offload_mutex && !notify_calls && !closed_calls && !walk_calls);
        CHECK(airoha_ppe_ct_wlan_epoch(&ppe_dev, invalid[index].band, invalid[index].wcid) == 0);
    }
    reset("nonhost flush leaves native state alone");
    ppe.ct_host_ppe = false;
    CHECK(flush(0, 24) == 0);
    CHECK(!notify_calls && !closed_calls && !walk_calls && ppe.ct_wlan_epoch[0][24] == 0);
    for (unsigned mode = 0; mode < 10; mode++) {
        reset("stopped flush requires complete CPU cutover");
        ppe.ct_stopping = ppe.ct_pair_failed = ppe.ct_pair_hw_stopped = true;
        eth.ct_cpu_fallback = eth.ct_cpu_routes_ready = eth.ct_cpu_ifc_disabled = eth.ct_cpu_wlan_gated = true;
        switch (mode) {
        case 1: ppe.ct_host_ppe = false; break;
        case 2: ppe.ct_native_pairs = false; break;
        case 3: ppe.ct_pair_failed = false; break;
        case 4: ppe.ct_fe.health_stopping = true; break;
        case 5: ppe.ct_pair_hw_stopped = false; break;
        case 6: eth.ct_cpu_fallback = false; break;
        case 7: eth.ct_cpu_routes_ready = false; break;
        case 8: eth.ct_cpu_ifc_disabled = false; break;
        case 9: eth.ct_cpu_wlan_gated = false; break;
        }
        CHECK(flush(0, 24) == (mode ? -ESHUTDOWN : 0));
        CHECK(!notify_calls && !closed_calls && !walk_calls && ppe.ct_wlan_epoch[0][24] == 0);
    }
}

int main(void)
{
    test_case = "initial state";
    test_active_cleanup();
    test_inactive_barriers();
    test_barrier_errors();
    test_epoch_exhaustion();
    test_row_identity_and_errors();
    test_flush_guards();
    CHECK(!ppe_lock && !flow_offload_mutex);
    printf("PASS: %u cases, %u checks\n", cases, checks);
    return 0;
}
