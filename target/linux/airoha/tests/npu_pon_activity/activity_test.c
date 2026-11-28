#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "airoha_npu_transaction_core.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define BIT(bit) (1u << (bit))
#define GENMASK(high, low) ((UINT32_MAX >> (31 - (high))) & (UINT32_MAX << (low)))
#define FIELD_GET(mask, value) (((value) & (mask)) >> __builtin_ctz(mask))
#define FIELD_PREP(mask, value) (((u32)(value) << __builtin_ctz(mask)) & (mask))
#define DECLARE_FLEX_ARRAY(type, name) type name[0]
#define static_assert(condition) _Static_assert(condition, #condition)
#define READ_ONCE(value) (value)
#define ETH_ALEN 6
#define AIROHA_GDM2_IDX 2
#define AIROHA_CT_PAIR_SLOTS 4
#define PPE_SRAM_NUM_ENTRIES 8192u
#define HZ 100

struct hlist_node { struct hlist_node *next, **pprev; };
struct hlist_head { struct hlist_node *first; };
struct list_head { struct list_head *next, *prev; };
struct rhash_head { unsigned unused; };
struct rcu_head { unsigned unused; };
struct airoha_gdm_dev;
struct airoha_ppe;
struct airoha_eth;
struct net_device;

@ABI@

struct net_device { struct airoha_gdm_dev *priv; bool running, carrier; int netns; };
struct airoha_pon_link_ops { unsigned identity; };
struct airoha_qdma { unsigned identity; };
struct port { unsigned id; };
struct device_node { bool diagnostic; };
struct device { struct device_node *of_node; };
struct rhashtable { struct airoha_flow_table_entry *entry; };
struct airoha_eth {
	struct airoha_ppe *ppe;
	struct device *dev;
	struct airoha_qdma qdma[2];
	struct rhashtable flow_table;
	bool ct_pon_full, ct_ordinary_full_test, ct_cpu_fallback;
};
struct airoha_gdm_dev {
	struct airoha_eth *eth;
	struct net_device netdev;
	struct port *port;
	unsigned long flags;
	unsigned nbq, pon_qdma_tag;
	bool pon_update_blocked, valid;
	struct airoha_qdma *qdma;
	struct airoha_pon_flow_table *pon_flow_table;
	const struct airoha_pon_link_ops *pon_link_ops;
	void *pon_link_priv;
};
struct airoha_npu_owner;
struct airoha_ppe {
	struct airoha_eth *eth;
	struct airoha_npu_owner *ct_npu_owner;
	bool ct_host_ppe, ct_native_pairs, ct_stopping, ct_pon_qualified;
	bool ct_pair_failed, ct_pair_policy_allowed;
	struct native_pair { bool used; } *ct_pairs;
};
struct airoha_npu_owner {
	struct airoha_ppe *ppe;
	struct airoha_npu_txn txn;
	struct net_device *diag_lower;
	struct airoha_pon_candidate_snapshot production;
	const struct airoha_pon_link_ops *production_controller;
	void *production_priv;
	bool production_bound;
	u32 production_hash;
	struct airoha_foe_entry production_entry;
	bool invalidated, close_pending, closed_ack, retiring;
};
enum { FLOW_CLS_REPLACE, FLOW_CLS_DESTROY, FLOW_CLS_STATS };
struct flow_cls_offload {
	unsigned long cookie;
	unsigned command;
	struct { unsigned long lastused; u64 pkts, bytes; } stats;
};

static const char *test_case;
static unsigned checks, cases;
#define CHECK(condition) do { checks++; if (!(condition)) { \
	fprintf(stderr, "CHECK failed [%s] line %d: %s\n", test_case, __LINE__, #condition); \
	exit(1); } } while (0)

static int flow_offload_mutex = 1, ppe_lock;
static unsigned lock_calls, read_calls, ack_calls, ordinary_idle_calls, counter_calls;
static unsigned trigger_lock;
static void (*at_lock)(void), (*at_read)(void);
static u32 timestamp;
static unsigned long jiffies;
static u64 generation;
static bool read_error, ack_error;
static const int airoha_flow_table_params = 1;

#define lockdep_is_held(lock) (*(lock) == 1)
#define lockdep_assert_held(lock) CHECK(lockdep_is_held(lock))
static void spin_lock_bh(int *lock)
{
	CHECK(lock == &ppe_lock && !*lock && flow_offload_mutex == 1);
	lock_calls++;
	if (at_lock && lock_calls == trigger_lock)
		at_lock();
	*lock = 1;
}
static void spin_unlock_bh(int *lock)
{
	CHECK(lock == &ppe_lock && *lock == 1 && flow_offload_mutex == 1);
	*lock = 0;
}
#define rcu_access_pointer(pointer) (pointer)
#define rcu_dereference_protected(pointer, condition) ((condition) ? (pointer) : (abort(), (pointer)))
#define netdev_from_priv(dev) (&(dev)->netdev)
#define netdev_priv(dev) ((dev)->priv)
#define netif_running(dev) ((dev)->running)
#define netif_carrier_ok(dev) ((dev)->carrier)
#define dev_net(dev) ((dev)->netns)
#define net_eq(first, second) ((first) == (second))
#define test_bit(bit, pointer) (!!(*(pointer) & (1ul << (bit))))

static bool of_property_read_bool(struct device_node *node, const char *name)
{
	CHECK(!strcmp(name, "airoha,connac2-pon-er-diagnostic"));
	return node->diagnostic;
}
static bool airoha_is_valid_gdm_dev(struct airoha_eth *eth, struct airoha_gdm_dev *dev)
{ return dev->valid && dev->eth == eth; }
static u64 br_flow_offload_generation(void) { return generation; }
static struct airoha_flow_table_entry *rhashtable_lookup_fast(struct rhashtable *table,
							     const unsigned long *cookie, int params)
{
	CHECK(flow_offload_mutex == 1 && !ppe_lock && params == airoha_flow_table_params);
	return table->entry && table->entry->cookie == *cookie ? table->entry : NULL;
}
#define rhashtable_lookup rhashtable_lookup_fast

@PRODUCTION_ACTIVE@
@CANDIDATE_FUNCTIONS@
@VALIDATE@

static struct airoha_foe_entry hardware;
static u32 airoha_ppe_get_timestamp(struct airoha_ppe *ppe)
{
	CHECK(ppe_lock == 1);
	return timestamp;
}
static bool airoha_ppe_bank0_hash(u32 hash) { return hash < PPE_SRAM_NUM_ENTRIES; }
static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *ppe, u32 hash)
{
	CHECK(ppe_lock == 1 && ppe->ct_npu_owner && hash == ppe->ct_npu_owner->production_hash);
	read_calls++;
	if (at_read)
		at_read();
	return read_error ? NULL : &hardware;
}
static bool airoha_ppe_ct_sram_ack(struct airoha_eth *eth, u32 hash, bool write)
{
	CHECK(ppe_lock == 1 && !write && hash == eth->ppe->ct_npu_owner->production_hash);
	ack_calls++;
	return !ack_error;
}

@IDLE_TIME@
@ACTIVITY@

static int airoha_ppe_entry_idle_time(struct airoha_ppe *ppe, struct airoha_flow_table_entry *entry)
{
	CHECK(!ppe_lock);
	ordinary_idle_calls++;
	return 12;
}
static u32 airoha_ppe_get_total_num_entries(struct airoha_ppe *ppe)
{ return 2 * PPE_SRAM_NUM_ENTRIES; }
static void airoha_ppe_foe_entry_get_stats(struct airoha_ppe *ppe, u32 hash,
					struct airoha_foe_stats64 *stats)
{
	CHECK(ppe_lock == 1 && hash < 2 * PPE_SRAM_NUM_ENTRIES);
	counter_calls++;
	stats->packets = 50;
	stats->bytes = 5000;
}

@STATS@

static int airoha_ppe_flow_offload_replace(struct airoha_eth *eth, struct flow_cls_offload *f)
{ CHECK(false); return -EOPNOTSUPP; }
static int airoha_ppe_flow_offload_destroy(struct airoha_eth *eth, struct flow_cls_offload *f)
{ CHECK(false); return -EOPNOTSUPP; }

@COMMAND@

static struct airoha_eth eth;
static struct airoha_ppe ppe;
static struct airoha_npu_owner session, replacement;
static struct airoha_flow_table_entry candidate;
static struct airoha_gdm_dev ingress, egress;
static struct airoha_pon_flow_table *mapping;
static struct airoha_pon_link_ops controller, other_controller;
static struct native_pair pairs[AIROHA_CT_PAIR_SLOTS];
static struct port ingress_port = { .id = AIROHA_GDM2_IDX }, egress_port = { .id = 4 };
static struct device_node node;
static struct device device = { .of_node = &node };
static struct flow_cls_offload request;

static void begin(const char *name)
{
	test_case = name;
	cases++;
	CHECK(flow_offload_mutex == 1 && !ppe_lock);
	memset(&eth, 0, sizeof(eth));
	memset(&ppe, 0, sizeof(ppe));
	memset(&session, 0, sizeof(session));
	memset(&candidate, 0, sizeof(candidate));
	memset(&node, 0, sizeof(node));
	memset(pairs, 0, sizeof(pairs));
	memset(mapping, 0, sizeof(*mapping) + 2 * sizeof(mapping->entries[0]));
	read_error = ack_error = false;
	lock_calls = read_calls = ack_calls = ordinary_idle_calls = counter_calls = 0;
	at_lock = at_read = NULL;
	trigger_lock = 2;
	timestamp = 107;
	jiffies = 900000;
	generation = 9;
	eth.ppe = &ppe;
	eth.dev = &device;
	eth.ct_pon_full = true;
	eth.flow_table.entry = &candidate;
	ppe.eth = &eth;
	ppe.ct_npu_owner = &session;
	ppe.ct_host_ppe = ppe.ct_native_pairs = true;
	ppe.ct_pairs = pairs;
	ingress_port.id = AIROHA_GDM2_IDX;
	egress_port.id = 4;
	ingress = (struct airoha_gdm_dev){
		.eth = &eth, .netdev = { .priv = &ingress, .running = true, .carrier = true },
		.port = &ingress_port, .flags = BIT(AIROHA_DEV_F_PON), .valid = true,
		.qdma = &eth.qdma[1], .pon_flow_table = mapping,
		.pon_link_ops = &controller, .pon_link_priv = &controller,
	};
	egress = ingress;
	egress.netdev.priv = &egress;
	egress.port = &egress_port;
	egress.flags = 0;
	mapping->count = 1;
	mapping->entries[0].tag = AIROHA_PON_QDMA_VALID | (3u << 16) | 77;
	mapping->entries[0].vlan_id = 100;
	mapping->entries[0].pbit_mask = 0xff;
	candidate.cookie = 0x12345678;
	candidate.pon_candidate = true;
	candidate.pon_candidate_serial = 42;
	candidate.hash = 0xffff;
	candidate.type = FLOW_TYPE_L4;
	candidate.pon_ingress_seen = true;
	candidate.pon_ingress_service = 77;
	candidate.pon_ingress_dev = &ingress;
	candidate.egress_dev = &egress;
	for (unsigned index = 0; index < 19; index++)
		candidate.pon_ingress_key[index] = 0x10203040 + index;
	candidate.data.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND) |
		AIROHA_FOE_IB1_BIND_UDP | AIROHA_FOE_IB1_BIND_TTL | 3;
	candidate.data.ipv4.orig_tuple = (struct airoha_foe_ipv4_tuple){
		.src_ip = 0xc0000201, .dest_ip = 0xc6336402, .src_port = 1234, .dest_port = 5678,
	};
	candidate.data.ipv4.new_tuple = candidate.data.ipv4.orig_tuple;
	candidate.data.ipv4.new_tuple.dest_ip = 0x0a000001;
	candidate.data.ipv4.new_tuple.dest_port = 9988;
	candidate.data.ipv4.ib2 = 0x123456;
	candidate.data.ipv4.data = 0x3456;
	candidate.data.ipv4.l2.common.vlan1 = 100;
	candidate.data.ipv4.l2.common.dest_mac_hi = 0x00112233;
	candidate.data.ipv4.l2.common.dest_mac_lo = 0x4455;
	candidate.data.ipv4.l2.common.src_mac_hi = 0x66778899;
	candidate.data.ipv4.l2.src_mac_lo = 0xaabb;
	session.ppe = &ppe;
	session.txn.phase = NPU_TXN_OPEN;
	session.txn.id.generation = generation;
	session.production_bound = true;
	session.production_hash = 123;
	session.production_controller = &controller;
	session.production_priv = &controller;
	session.production.cookie = candidate.cookie;
	session.production.serial = candidate.pon_candidate_serial;
	session.production.generation = generation;
	session.production.ingress = &ingress.netdev;
	session.production.egress = &egress.netdev;
	session.production.service = candidate.pon_ingress_service;
	session.production.mapping = mapping->entries[0];
	memcpy(session.production.key, candidate.pon_ingress_key, sizeof(session.production.key));
	session.production.data = candidate.data;
	session.production_entry = candidate.data;
	session.production_entry.ib1 &= ~AIROHA_FOE_IB1_BIND_TIMESTAMP;
	session.production_entry.ib1 |= AIROHA_FOE_IB1_BIND_STATIC | 11;
	hardware = session.production_entry;
	hardware.ib1 &= ~AIROHA_FOE_IB1_BIND_TIMESTAMP;
	hardware.ib1 |= 100;
	request = (struct flow_cls_offload){
		.command = FLOW_CLS_STATS, .cookie = candidate.cookie,
		.stats = { .lastused = 123, .pkts = 7, .bytes = 700 },
	};
}

static void exercise(int expected, u32 idle)
{
	struct airoha_flow_table_entry original = candidate;
	struct airoha_pon_candidate_snapshot snapshot = session.production;
	struct airoha_foe_entry installed = session.production_entry, row = hardware;
	unsigned long previous = request.stats.lastused;
	int error = airoha_ppe_flow_offload_cmd(&eth, &request);

	CHECK(error == expected);
	CHECK(!ppe_lock && flow_offload_mutex == 1);
	CHECK(request.stats.lastused == (error ? previous : jiffies - idle * HZ));
	CHECK(request.stats.pkts == 7 && request.stats.bytes == 700);
	CHECK(!memcmp(&candidate.data, &original.data, sizeof(candidate.data)));
	CHECK(candidate.hash == original.hash);
	CHECK(!memcmp(&candidate.stats, &original.stats, sizeof(candidate.stats)));
	CHECK(!memcmp(&session.production, &snapshot, sizeof(snapshot)));
	CHECK(!memcmp(&session.production_entry, &installed, sizeof(installed)));
	CHECK(!memcmp(&hardware, &row, sizeof(row)));
	CHECK(!ordinary_idle_calls && !counter_calls);
	if (!error) {
		CHECK(read_calls == 1 && ack_calls == 1);
		CHECK(!airoha_ppe_pon_candidate_validate(&ppe, &session.production));
	}
}

#define REJECT(name, change) do { begin(name); change; exercise(-ESTALE, 0); } while (0)

static void stale_states(void)
{
	REJECT("missing owner", ppe.ct_npu_owner = NULL);
	REJECT("wrong owner PPE", session.ppe = NULL);
	REJECT("owner cookie", session.production.cookie++);
	REJECT("candidate serial ABA", candidate.pon_candidate_serial++);
	REJECT("owner zero serial", session.production.serial = 0);
	REJECT("candidate zero serial", candidate.pon_candidate_serial = 0);
	REJECT("transaction generation", session.txn.id.generation++);
	REJECT("bridge generation", generation++);
	REJECT("invalidated", session.invalidated = true);
	REJECT("close pending", session.close_pending = true);
	REJECT("closed ACK", session.closed_ack = true);
	REJECT("retiring", session.retiring = true);
	REJECT("not yet bound", session.production_bound = false);
	REJECT("wrong bank", session.production_hash = PPE_SRAM_NUM_ENTRIES);
	REJECT("invalid hash", session.production_hash = UINT32_MAX);
	REJECT("candidate hash assigned", candidate.hash = 123);
	REJECT("candidate unseen", candidate.pon_ingress_seen = false);
	REJECT("candidate conflict", candidate.pon_ingress_conflict = true);
	REJECT("candidate bridge", candidate.ct_bridge = true);
	REJECT("candidate L2", candidate.type = FLOW_TYPE_L2);
	REJECT("candidate source", candidate.data.ipv4.orig_tuple.src_ip++);
	REJECT("candidate NAT", candidate.data.ipv4.new_tuple.dest_port++);
	REJECT("candidate output", candidate.data.ipv4.ib2++);
	REJECT("candidate MAC", candidate.data.ipv4.l2.src_mac_lo++);
	REJECT("candidate service", candidate.pon_ingress_service++);
	REJECT("candidate key", candidate.pon_ingress_key[18]++);
	REJECT("missing mapping", ingress.pon_flow_table = NULL);
	REJECT("mapping TCONT", mapping->entries[0].tag ^= BIT(16));
	REJECT("mapping VLAN", mapping->entries[0].vlan_id++);
	REJECT("mapping pbit", mapping->entries[0].pbit_mask ^= 1);
	REJECT("duplicate GEM", mapping->entries[1] = mapping->entries[0]; mapping->count = 2);
	REJECT("controller replaced", ingress.pon_link_ops = &other_controller);
	REJECT("private context replaced", ingress.pon_link_priv = &other_controller);
	REJECT("ingress down", ingress.netdev.carrier = false);
	REJECT("egress down", egress.netdev.carrier = false);
	REJECT("egress blocking", egress.pon_update_blocked = true);
	REJECT("wrong QDMA", ingress.qdma = &eth.qdma[0]);
	REJECT("stopping", ppe.ct_stopping = true);
	REJECT("pair failure", ppe.ct_pair_failed = true);
	REJECT("CPU fallback", eth.ct_cpu_fallback = true);
	REJECT("native pair in use", pairs[3].used = true);
	for (unsigned phase = NPU_TXN_IDLE; phase < NPU_TXN_OPEN; phase++) {
		REJECT("non-OPEN phase", session.txn.phase = phase);
	}
}

static void invalidate(void) { session.invalidated = true; }
static void close_pending(void) { session.close_pending = true; }
static void close_ack(void) { session.closed_ack = true; }
static void replace_owner(void) { replacement = session; ppe.ct_npu_owner = &replacement; }
static void remove_owner(void) { ppe.ct_npu_owner = NULL; }
static void conflict(void) { candidate.pon_ingress_conflict = true; }
static void unseen(void) { candidate.pon_ingress_seen = false; }
static void advance_generation(void) { generation++; }
static void block_egress(void) { egress.pon_update_blocked = true; }
static void lose_bound(void) { session.production_bound = false; }
static void close_phase(void) { session.txn.phase = NPU_TXN_CLOSED; }
static void replace_cookie(void) { candidate.cookie++; }
static void replace_serial(void) { candidate.pon_candidate_serial++; }
static void remove_candidate(void) { candidate.pon_candidate = false; }

static void races(void)
{
	void (*const callbacks[])(void) = { invalidate, close_pending, close_ack, replace_owner,
		remove_owner, conflict, unseen, advance_generation, block_egress, lose_bound, close_phase,
		replace_cookie, replace_serial, remove_candidate };
	for (unsigned index = 0; index < sizeof(callbacks) / sizeof(callbacks[0]); index++) {
		begin("state changes between snapshot validation and SRAM lock");
		at_lock = callbacks[index];
		exercise(-ESTALE, 0);
		CHECK(!read_calls && !ack_calls);
	}
	begin("generation changes during SRAM read");
	at_read = advance_generation;
	exercise(-ESTALE, 0);
	CHECK(read_calls == 1 && ack_calls == 1);
	begin("endpoint blocked during SRAM read");
	at_read = block_egress;
	exercise(-ESTALE, 0);
}

static void row_identity(void)
{
	for (unsigned bit = 15; bit < sizeof(hardware) * CHAR_BIT; bit++) {
		begin("each owned row bit except timestamp");
		hardware.data[bit / CHAR_BIT] ^= BIT(bit % CHAR_BIT);
		exercise(-ESTALE, 0);
		CHECK(read_calls == 1 && ack_calls == 1);
	}
	begin("SRAM timeout");
	read_error = true;
	exercise(-ETIMEDOUT, 0);
	CHECK(read_calls == 1 && !ack_calls);
	begin("SRAM ACK mismatch");
	ack_error = true;
	exercise(-EIO, 0);
	CHECK(read_calls == 1 && ack_calls == 1);
}

static void timestamps(void)
{
	const u32 values[] = { 0, 1, 5, 6, 32760, 32767 };

	begin("owned hardware timestamp feeds FLOW_CLS_STATS");
	exercise(0, 7);
	for (unsigned index = 0; index < sizeof(values) / sizeof(values[0]); index++) {
		begin("15-bit timestamp wrap");
		timestamp = 5;
		hardware.ib1 &= ~AIROHA_FOE_IB1_BIND_TIMESTAMP;
		hardware.ib1 |= values[index];
		exercise(0, (timestamp - values[index]) & AIROHA_FOE_IB1_BIND_TIMESTAMP);
	}
	begin("jiffies subtraction wraps naturally");
	jiffies = 100;
	exercise(0, 7);
	begin("jiffies near ULONG_MAX");
	jiffies = ULONG_MAX - 3;
	exercise(0, 7);
	begin("idle row uses old hardware timestamp");
	timestamp = 300;
	exercise(0, 200);
	begin("fresh traffic advances hardware timestamp");
	hardware.ib1 &= ~AIROHA_FOE_IB1_BIND_TIMESTAMP;
	hardware.ib1 |= timestamp;
	exercise(0, 0);
}

static void ordinary(void)
{
	begin("ordinary stats retain idle and counter accounting");
	candidate.pon_candidate = false;
	candidate.hash = 21;
	candidate.stats.packets = 10;
	candidate.stats.bytes = 1000;
	CHECK(!airoha_ppe_flow_offload_cmd(&eth, &request));
	CHECK(request.stats.lastused == jiffies - 12 * HZ);
	CHECK(request.stats.pkts == 47 && request.stats.bytes == 4700);
	CHECK(candidate.stats.packets == 50 && candidate.stats.bytes == 5000);
	CHECK(ordinary_idle_calls == 1 && counter_calls == 1 && !read_calls && !ack_calls);
	CHECK(!ppe_lock);
	begin("ordinary unknown hash keeps ordinary idle behavior");
	candidate.pon_candidate = false;
	CHECK(!airoha_ppe_flow_offload_cmd(&eth, &request));
	CHECK(request.stats.lastused == jiffies - 12 * HZ);
	CHECK(ordinary_idle_calls == 1 && !counter_calls && !read_calls);
	begin("missing cookie");
	request.cookie++;
	exercise(-ENOENT, 0);
	CHECK(!read_calls);
}

int main(void)
{
	mapping = calloc(1, sizeof(*mapping) + 2 * sizeof(mapping->entries[0]));
	if (!mapping)
		return 2;
	timestamps();
	stale_states();
	races();
	row_identity();
	ordinary();
	free(mapping);
	printf("PON activity: %u cases, %u checks\n", cases, checks);
	return 0;
}
