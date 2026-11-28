#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "airoha_npu_transaction_core.h"
#include "airoha_npu_auth_publish.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef unsigned long long u64;
#define BIT(index) (1u << (index))
#define GENMASK(high, low) ((UINT32_MAX >> (31 - (high))) & (UINT32_MAX << (low)))
#define FIELD_GET(mask, value) (((value) & (mask)) >> __builtin_ctz(mask))
#define FIELD_PREP(mask, value) (((value) << __builtin_ctz(mask)) & (mask))
#define DECLARE_FLEX_ARRAY(type, name) type name[0]
#undef static_assert
#define static_assert(condition) _Static_assert(condition, #condition)
#define U32_MAX UINT32_MAX
#define PPE_SRAM_NUM_ENTRIES 8192u
#define AIROHA_CT_PAIR_SLOTS 4
#define ER_SERVICE_VALID BIT(31)
#define READ_ONCE(value) (value)
#define rcu_access_pointer(pointer) (pointer)
#define AIROHA_DEV_F_PON 1
#define AIROHA_GDM2_IDX 2
#define REG_PPE_TB_CFG(bank) ((bank) * 2)
#define REG_PPE_PPE_FLOW_CFG(bank) ((bank) * 2 + 1)
#define IS_ERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#define PTR_ERR(pointer) ((int)(intptr_t)(pointer))
#define ERR_PTR(error) ((void *)(intptr_t)(error))

@FOE_TYPES@

static unsigned int checks, cases;
#define CHECK(condition) do { checks++; if (!(condition)) { \
	fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #condition); exit(1); } } while (0)
static int flow_offload_mutex = 1, ppe_lock, rcu_depth;
#define lockdep_assert_held(lock) CHECK(*(lock) == 1)
static void spin_lock_bh(int *lock) { CHECK(!*lock); *lock = 1; }
static void spin_unlock_bh(int *lock) { CHECK(*lock == 1); *lock = 0; }
static void mutex_lock(int *lock) { CHECK(!ppe_lock && !*lock); *lock = 1; }
static void mutex_unlock(int *lock) { CHECK(!ppe_lock && *lock == 1); *lock = 0; }
static bool mutex_trylock(int *lock) { CHECK(!ppe_lock); if (*lock) return false; *lock = 1; return true; }
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { CHECK(rcu_depth); rcu_depth--; }
struct work_struct { int unused; };
struct delayed_work { struct work_struct work; };
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
#define to_delayed_work(pointer) container_of(pointer, struct delayed_work, work)
#define msecs_to_jiffies(value) (value)
static unsigned int scheduled;
static void schedule_delayed_work(struct delayed_work *work, int delay)
{ CHECK(ppe_lock && delay == 100); scheduled++; }
struct net_device { void *priv; unsigned int refs; bool running, carrier; };
struct airoha_pon_link_ops { int identity; };
struct airoha_qdma { int identity; };
struct airoha_gdm_port { int id; };
struct airoha_gdm_dev {
	const struct airoha_pon_link_ops *pon_link_ops;
	void *pon_link_priv;
	struct airoha_eth *eth;
	struct airoha_qdma *qdma;
	struct airoha_gdm_port *port;
	unsigned long flags;
	unsigned int nbq, pon_qdma_tag;
	bool pon_update_blocked;
};
static void *netdev_priv(struct net_device *dev) { return dev->priv; }
struct airoha_npu_owner;
struct airoha_eth;
struct airoha_ppe {
	struct airoha_eth *eth;
	struct airoha_npu_owner *ct_npu_owner;
	bool ct_host_ppe, ct_native_pairs, ct_pair_policy_allowed, ct_pair_failed, ct_stopping, ct_pon_qualified;
	struct native_pair { bool used; } *ct_pairs;
};
struct airoha_eth {
	struct airoha_ppe *ppe;
	struct device { void *of_node; } *dev;
	struct airoha_qdma qdma[2];
	bool ct_pon_full, ct_ordinary_full_test, ct_cpu_fallback, ct_ifc_cpu_port_failed;
	bool ct_cpu_routes_ready, ct_cpu_ifc_disabled;
	void *pon_update_owner;
	struct { void *owner; } ct_bank1_routes;
	int flow_table;
};
struct airoha_npu_return { int config; };
struct airoha_npu_owner {
	struct airoha_ppe *ppe;
	struct net_device *diag_lower;
	struct airoha_npu_txn txn;
	struct airoha_pon_candidate_snapshot production;
	const struct airoha_pon_link_ops *production_controller;
	void *production_priv;
	bool production_bound;
	u32 production_hash;
	struct airoha_foe_entry production_entry;
	bool bank0_saved, bank0_host_retired, bank1_saved, bank1_host_retired;
	u32 bank0_next_row, bank1_next_row, bank0_tb, bank0_flow, bank1_tb, bank1_flow;
	bool auth_attempted, epoch_dirty, invalidated, close_pending, closed_ack, retiring;
	u32 auth_count;
	u64 invalidation_seq;
	struct { bool saved_valid, dirty, active, pending; } ingress;
	struct airoha_npu_return *return_path;
	struct delayed_work health_work;
};
enum { FLOW_TYPE_L4, FLOW_TYPE_L2, FLOW_TYPE_L2_SUBFLOW };
struct airoha_flow_table_entry {
	unsigned long cookie;
	u64 pon_candidate_serial;
	u32 hash, type;
	bool pon_ingress_seen, eligible;
	int list;
	struct airoha_pon_unbound_event pon_unbound_event;
	struct airoha_foe_entry data;
};
static struct airoha_eth eth;
static struct airoha_ppe ppe;
static struct airoha_npu_owner session;
static struct airoha_npu_return path;
static struct native_pair pairs[AIROHA_CT_PAIR_SLOTS];
static struct airoha_pon_link_ops controller, other_controller;
static int private_context;
static struct airoha_gdm_dev ingress;
static struct airoha_gdm_dev egress;
static struct airoha_gdm_port ingress_port = { .id = 2 }, egress_port = { .id = 4 };
static struct device device;
static u64 current_generation;
static bool diagnostic_property;
static struct net_device lower, upper;
static struct airoha_flow_table_entry candidate, ineligible;
static struct airoha_pon_candidate_snapshot available;
static struct airoha_foe_entry hardware, shadow;
static struct airoha_npu_auth_rule published;
static u32 registers[4], auth_epoch, auth_generation, auth_count, auth_enabled;
static bool fe_enabled, gate_quiet, route_open, binding_ok, removal_in_progress;
static int prepare_error, drain_error, destroy_error, install_error, auth_error_op;
static int health_error, restore_error_register, retire_error;
static unsigned int claims, releases, takes, installs, drains, health_checks, snapshot_puts;
static u32 failed_cursor;

static bool airoha_ct_pon_ifc_busy(struct airoha_ppe *ppe) { return false; }
static bool airoha_ppe_bank0_hash(u32 hash) { return hash < PPE_SRAM_NUM_ENTRIES; }
static u32 airoha_ppe_get_timestamp(struct airoha_ppe *ppe) { return 37; }
static u64 br_flow_offload_generation(void) { return current_generation; }
static bool of_property_read_bool(void *node, const char *name) { return diagnostic_property; }
static bool airoha_is_valid_gdm_dev(struct airoha_eth *eth, struct airoha_gdm_dev *dev)
{ return dev && dev->eth == eth; }
static bool test_bit(unsigned int bit, const unsigned long *flags) { return *flags & (1ul << bit); }
static bool netif_running(struct net_device *dev) { return dev->running; }
static bool netif_carrier_ok(struct net_device *dev) { return dev->carrier; }
@PRODUCTION_ACTIVE@
static int airoha_ppe_pon_candidate_read_locked(struct airoha_ppe *ppe,
	struct airoha_flow_table_entry *entry, struct airoha_pon_candidate_snapshot *snapshot)
{
	CHECK(flow_offload_mutex && ppe_lock);
	if (!entry->eligible || !entry->pon_ingress_seen) return -ESTALE;
	*snapshot = available;
	snapshot->cookie = entry->cookie;
	snapshot->serial = entry->pon_candidate_serial;
	return 0;
}
static int airoha_ppe_pon_candidate_snapshot(struct airoha_ppe *ppe, unsigned long cookie,
	struct airoha_pon_candidate_snapshot *snapshot)
{
	CHECK(flow_offload_mutex && !ppe_lock);
	if (cookie != candidate.cookie) return -ENOENT;
	*snapshot = available; lower.refs++; upper.refs++; return 0;
}
static int airoha_ppe_pon_candidate_validate(struct airoha_ppe *ppe,
	const struct airoha_pon_candidate_snapshot *snapshot)
{
	CHECK(flow_offload_mutex && !ppe_lock);
	return candidate.pon_ingress_seen && candidate.list && candidate.eligible &&
	       !memcmp(snapshot, &available, sizeof(available)) ? 0 : -ESTALE;
}
static void airoha_ppe_pon_candidate_put(struct airoha_pon_candidate_snapshot *snapshot)
{
	CHECK(snapshot->serial && lower.refs && upper.refs);
	lower.refs--; upper.refs--; snapshot_puts++; memset(snapshot, 0, sizeof(*snapshot));
}
static int airoha_ppe_pon_take_unbound(struct airoha_ppe *ppe, unsigned long cookie,
	u64 serial, struct airoha_pon_unbound_event *event)
{
	CHECK(flow_offload_mutex && !ppe_lock && cookie == candidate.cookie && serial == candidate.pon_candidate_serial);
	takes++;
	if (!candidate.pon_unbound_event.serial) return -EAGAIN;
	*event = candidate.pon_unbound_event;
	memset(&candidate.pon_unbound_event, 0, sizeof(candidate.pon_unbound_event));
	return 0;
}
static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *ppe, u32 hash)
{ CHECK(ppe_lock && airoha_ppe_bank0_hash(hash)); shadow = hardware; return &shadow; }
static bool airoha_ppe_ct_sram_ack(struct airoha_eth *eth, u32 hash, bool write)
{ CHECK(ppe_lock); return true; }
static int airoha_ppe_foe_commit_sram_entry(struct airoha_ppe *ppe, u32 hash)
{
	CHECK(ppe_lock && !session.bank0_next_row && gate_quiet);
	hardware = shadow; installs++; return install_error;
}
static void hlist_del_init(int *list) { CHECK(ppe_lock); *list = 0; }
static bool airoha_ppe_ct_pon_row_matches(struct airoha_flow_table_entry *entry,
	const struct airoha_foe_entry *row) { return !memcmp(&entry->data, row, sizeof(*row)); }
static int airoha_ppe_foe_commit_entry(struct airoha_ppe *ppe,
	const struct airoha_foe_entry *row, u32 hash, bool wlan) { hardware = *row; return 0; }
static int airoha_npu_owner_auth(void *ctx, struct npu_auth_message *message)
{
	u32 operation = message->w[AM_ABI_OP] >> 16;
	CHECK(flow_offload_mutex && !ppe_lock);
	if (operation == AUTH_MBOX_BEGIN) {
		auth_epoch = message->w[AM_EPOCH]; auth_generation = message->w[AM_GENERATION];
		auth_count = auth_enabled = 0;
	} else if (operation == AUTH_MBOX_ADD) {
		memcpy(published.raw, message->w + AM_RULE, sizeof(published.raw)); auth_count++;
	} else if (operation == AUTH_MBOX_ARM) auth_enabled = 1;
	else if (operation == AUTH_MBOX_DISARM) auth_enabled = 0;
	message->w[AM_STATUS] = 0; message->w[AM_CAPS] = AUTH_MBOX_CAPS;
	message->w[AM_STATE_EPOCH] = auth_epoch; message->w[AM_STATE_GENERATION] = auth_generation;
	message->w[AM_COUNT] = auth_count; message->w[AM_ENABLED] = auth_enabled;
	if ((int)operation == auth_error_op) { auth_error_op = -1; return -ETIMEDOUT; }
	return 0;
}
static int gate_command(void *ctx, struct npu_gate_message *message)
{
	struct airoha_npu_owner *owner = ctx;
	u32 operation = message->w[GM_ABI_OP] >> 16;
	CHECK(flow_offload_mutex && !ppe_lock);
	if (operation == GATE_QUIET) { CHECK(!auth_enabled && !fe_enabled); gate_quiet = true; }
	if (operation == GATE_OPEN) { CHECK(auth_enabled && fe_enabled && owner->return_path); gate_quiet = false; }
	message->w[GM_STATUS] = 0; message->w[GM_CAPS] = GATE_CAPS | GATE_CAP_PON2;
	message->w[GM_STATE_EPOCH] = message->w[GM_EPOCH];
	message->w[GM_STATE_GENERATION] = message->w[GM_GENERATION];
	message->w[GM_CLOSED] = operation != GATE_OPEN;
	message->w[GM_MASK] = operation == GATE_OPEN ? GATE_PON2 : 0;
	if (operation == GATE_QUIET) {
		message->w[GM_QUIET_ACK] = 1; message->w[GM_FE_QUIESCED] = 1; message->w[GM_DMA_IDLE] = 1;
	}
	if (operation == GATE_OPEN) {
		message->w[GM_FE_ENABLED] = 1; message->w[GM_ER_FLAGS] = GATE_ER_BOUND;
		message->w[GM_AUTH_ENABLED] = 1; message->w[GM_AUTH_EPOCH] = auth_epoch;
		message->w[GM_AUTH_GENERATION] = auth_generation;
	}
	return 0;
}
static int routes_close(void *ctx, const struct airoha_npu_txn_identity *id)
{ CHECK(!ppe_lock); eth.ct_bank1_routes.owner = ctx; route_open = false; return 0; }
static int fe_quiesce(void *ctx, const struct airoha_npu_txn_identity *id)
{ fe_enabled = false; return 0; }
static int airoha_npu_diag_bank0_drain(struct airoha_npu_owner *owner)
{
	CHECK(!ppe_lock && gate_quiet && !auth_enabled && !fe_enabled); drains++;
	if (!owner->bank0_saved) {
		owner->bank0_saved = true; owner->bank0_tb = registers[0]; owner->bank0_flow = registers[1];
	}
	registers[0] = 2; registers[1] = 0; owner->bank0_host_retired = true;
	if (drain_error) { owner->bank0_next_row = 17; return drain_error; }
	failed_cursor = owner->bank0_next_row; owner->bank0_next_row = PPE_SRAM_NUM_ENTRIES;
	memset(&hardware, 0, sizeof(hardware));
	memset(&candidate.pon_unbound_event, 0, sizeof(candidate.pon_unbound_event));
	return 0;
}
static int ppe_drain(void *ctx, const struct airoha_npu_txn_identity *id)
{
	struct airoha_npu_owner *owner = ctx;
	if (!owner->bank1_saved) {
		owner->bank1_saved = true; owner->bank1_tb = registers[2]; owner->bank1_flow = registers[3];
	}
	registers[2] = 2; registers[3] = 0;
	owner->bank1_host_retired = true; owner->bank1_next_row = PPE_SRAM_NUM_ENTRIES;
	return owner->production.serial ? airoha_npu_diag_bank0_drain(owner) : 0;
}
static int airoha_npu_production_install(struct airoha_npu_owner *owner);
static int ready(void *ctx, const struct airoha_npu_txn_identity *id)
{ CHECK(session.return_path && session.auth_count == 1 && auth_enabled); return 0; }
static int ppe_restore(void *ctx, const struct airoha_npu_txn_identity *id)
{
	struct airoha_npu_owner *owner = ctx;
	int error = owner->production_bound ? airoha_npu_production_install(owner) : 0;
	if (!error) { owner->bank0_next_row = 0; registers[0] = 3; registers[1] = BIT(13); }
	return error;
}
static int fe_arm(void *ctx, const struct airoha_npu_txn_identity *id)
{ fe_enabled = true; return 0; }
static int routes_open(void *ctx, const struct airoha_npu_txn_identity *id)
{ route_open = true; return 0; }
static const struct airoha_npu_txn_ops airoha_npu_owner_ops = {
	.gate = gate_command, .auth = airoha_npu_owner_auth, .routes_close = routes_close,
	.fe_quiesce = fe_quiesce, .ppe_drain = ppe_drain, .ready = ready,
	.ppe_restore = ppe_restore, .fe_arm = fe_arm, .routes_open = routes_open,
};
static int airoha_npu_return_destroy(struct airoha_npu_owner *owner)
{
	CHECK(owner->txn.phase == NPU_TXN_CLOSED && !auth_enabled && !fe_enabled);
	if (destroy_error) return destroy_error;
	owner->return_path = NULL; return 0;
}
@OWNER_CLOSE@
static int airoha_ppe_npu_owner_claim_locked(struct airoha_eth *eth, u64 generation)
{
	CHECK(!ppe_lock && !ppe.ct_npu_owner); claims++;
	ppe.ct_npu_owner = &session; session.ppe = &ppe;
	int error = airoha_npu_txn_begin(&session.txn, 10, generation, GATE_PON2);
	return error ?: airoha_ppe_npu_owner_close_locked(eth);
}
static int airoha_npu_owner_invalidate(struct airoha_ppe *ppe)
{
	CHECK(ppe_lock);
	if (removal_in_progress) CHECK(!candidate.pon_ingress_seen && !candidate.list && !candidate.pon_unbound_event.serial);
	session.invalidated = session.close_pending = true; session.invalidation_seq++; route_open = false; return 0;
}
static int airoha_bank1_routes_revoke(struct airoha_eth *eth, const void *owner)
{ route_open = false; return eth->ct_bank1_routes.owner == owner ? 0 : -ESTALE; }
static int airoha_bank1_routes_release(struct airoha_eth *eth, const void *owner)
{ CHECK(!route_open && !registers[3]); eth->ct_bank1_routes.owner = NULL; return 0; }
static u32 airoha_fe_rr(struct airoha_eth *eth, unsigned int address) { return registers[address]; }
static void airoha_fe_wr(struct airoha_eth *eth, unsigned int address, u32 value)
{
	CHECK(ppe_lock);
	if ((int)address == restore_error_register) { restore_error_register = -1; return; }
	registers[address] = value;
}
static int airoha_npu_owner_retire_locked(struct airoha_ppe *ppe)
{
	CHECK(!ppe_lock && session.txn.phase == NPU_TXN_CLOSED && !session.return_path);
	CHECK(!session.epoch_dirty && session.bank0_next_row == PPE_SRAM_NUM_ENTRIES);
	if (retire_error) return retire_error;
	airoha_ppe_pon_candidate_put(&session.production);
	ppe->ct_npu_owner = NULL; releases++; return 0;
}
static int airoha_ppe_npu_return_prepare_locked(struct airoha_eth *eth,
	struct airoha_gdm_dev *dev, u32 count)
{
	CHECK(!ppe_lock && session.txn.phase == NPU_TXN_CLOSED && !session.epoch_dirty);
	if (prepare_error) return prepare_error;
	session.return_path = &path; session.epoch_dirty = true; session.closed_ack = false; return 0;
}
static int airoha_npu_owner_return_ready(struct airoha_npu_owner *owner,
	const struct airoha_npu_txn_identity *id)
{ return owner->return_path && !owner->invalidated ? 0 : -ESTALE; }
static bool airoha_npu_return_binding(struct airoha_npu_return *path, struct net_device *dev,
	const int *config, u32 service)
{ CHECK(rcu_depth && service == (ER_SERVICE_VALID | available.service)); return binding_ok; }
static int airoha_ppe_npu_owner_open_locked(struct airoha_eth *eth)
{ return airoha_npu_txn_open(&session.txn, &airoha_npu_owner_ops, &session); }
@PRODUCTION_CORE@
@REMOVE_FLOW@
static int airoha_ct_cpu_fallback(struct airoha_eth *eth) { return 0; }
static int airoha_npu_owner_health_check(struct airoha_npu_owner *owner)
{ health_checks++; return health_error; }
@HEALTH_WORK@
struct seq_file { void *private; char output[4096]; size_t length; };
static void seq_printf(struct seq_file *stream, const char *format, ...)
{
	CHECK(flow_offload_mutex && !ppe_lock);
	va_list arguments; va_start(arguments, format);
	int count = vsnprintf(stream->output + stream->length, sizeof(stream->output) - stream->length, format, arguments);
	va_end(arguments); CHECK(count >= 0 && (size_t)count < sizeof(stream->output) - stream->length);
	stream->length += count;
}
static void seq_puts(struct seq_file *stream, const char *value) { seq_printf(stream, "%s", value); }
struct rhashtable_iter { unsigned int position; };
static struct airoha_flow_table_entry *walk_entries[8];
static unsigned int walk_active;
static void rhashtable_walk_enter(int *table, struct rhashtable_iter *iter)
{ CHECK(flow_offload_mutex); iter->position = 0; }
static void rhashtable_walk_start(struct rhashtable_iter *iter) { CHECK(!walk_active); walk_active = 1; }
static struct airoha_flow_table_entry *rhashtable_walk_next(struct rhashtable_iter *iter)
{ CHECK(walk_active && iter->position < 8); return walk_entries[iter->position++]; }
static void rhashtable_walk_stop(struct rhashtable_iter *iter) { CHECK(walk_active); walk_active = 0; }
static void rhashtable_walk_exit(struct rhashtable_iter *iter) { CHECK(!walk_active); }
@SHOW@

static void fixture(void)
{
	memset(&eth, 0, sizeof(eth)); memset(&ppe, 0, sizeof(ppe)); memset(&session, 0, sizeof(session));
	memset(&candidate, 0, sizeof(candidate)); memset(&available, 0, sizeof(available));
	memset(&hardware, 0, sizeof(hardware)); memset(pairs, 0, sizeof(pairs));
	memset(walk_entries, 0, sizeof(walk_entries));
	eth.ppe = &ppe; eth.dev = &device; eth.ct_pon_full = true; ppe.eth = &eth;
	ppe.ct_host_ppe = ppe.ct_native_pairs = true; ppe.ct_pairs = pairs;
	ingress = (struct airoha_gdm_dev) { .eth = &eth, .qdma = &eth.qdma[1],
		.port = &ingress_port, .flags = BIT(AIROHA_DEV_F_PON) };
	egress = (struct airoha_gdm_dev) { .eth = &eth, .port = &egress_port };
	ingress.pon_link_ops = &controller; ingress.pon_link_priv = &private_context;
	lower = (struct net_device) { .priv = &ingress, .running = true, .carrier = true };
	upper = (struct net_device) { .priv = &egress, .running = true, .carrier = true };
	current_generation = 7; diagnostic_property = false;
	candidate.cookie = 123; candidate.pon_candidate_serial = 456; candidate.hash = 0xffff;
	candidate.pon_ingress_seen = candidate.eligible = true; candidate.list = 1;
	available.cookie = 123; available.serial = 456; available.generation = 7;
	available.ingress = &lower; available.egress = &upper; available.service = 1025;
	available.key[0] = 4; available.key[1] = 17; available.key[2] = 0xc0000201;
	available.key[6] = 0xc6336402; available.key[10] = 0xc00001bb;
	available.key[16] = 0x02000001; available.key[17] = 0x00020200; available.key[18] = 0x00030004;
	available.data.ib1 = AIROHA_FOE_IB1_BIND_UDP | FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND);
	available.data.ipv4.orig_tuple.src_ip = available.key[2];
	available.data.ipv4.orig_tuple.dest_ip = available.key[6];
	available.data.ipv4.orig_tuple.src_port = 49152; available.data.ipv4.orig_tuple.dest_port = 443;
	available.data.ipv4.new_tuple = available.data.ipv4.orig_tuple;
	available.data.ipv4.new_tuple.dest_ip = 0x0a000002; available.data.ipv4.new_tuple.dest_port = 8443;
	available.data.ipv4.l2.common.dest_mac_hi = 0x02000009;
	candidate.data = available.data; ineligible = candidate; ineligible.cookie = 999; ineligible.eligible = false;
	registers[0] = 8; registers[1] = 16; registers[2] = 9; registers[3] = 32;
	auth_epoch = auth_generation = auth_count = auth_enabled = 0;
	fe_enabled = gate_quiet = route_open = removal_in_progress = false; binding_ok = true;
	prepare_error = drain_error = destroy_error = install_error = health_error = retire_error = 0;
	auth_error_op = restore_error_register = -1;
	claims = releases = takes = installs = drains = health_checks = snapshot_puts = scheduled = 0;
	flow_offload_mutex = 1; CHECK(!ppe_lock && !rcu_depth && !walk_active); cases++;
}
static void start_session(void)
{
	CHECK(!airoha_npu_production_start(&ppe, 123, 456));
	CHECK(session.txn.phase == NPU_TXN_OPEN && !session.production_bound && route_open);
	CHECK(lower.refs == 1 && upper.refs == 1 && claims == 1 && !snapshot_puts);
	CHECK(!published.raw[3] && published.raw[8] == 7 && published.raw[7] == 1025);
	CHECK(!memcmp(published.raw + 9, available.key, sizeof(available.key)));
}
static void unbound_event(void)
{
	candidate.pon_unbound_event = (struct airoha_pon_unbound_event) {
		.serial = 456, .generation = 7, .hardware_hash = 23, .service = 1025 };
	memcpy(candidate.pon_unbound_event.key, available.key, sizeof(available.key));
	hardware = available.data;
	hardware.ib1 = (hardware.ib1 & ~AIROHA_FOE_IB1_BIND_STATE) |
		FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_UNBIND);
}
static void health_tick(void)
{
	flow_offload_mutex = 0; airoha_npu_owner_health_work(&session.health_work.work);
	CHECK(!flow_offload_mutex && !ppe_lock); flow_offload_mutex = 1;
}
static void retained(void)
{ CHECK(ppe.ct_npu_owner == &session && lower.refs == 1 && upper.refs == 1 && !releases && !snapshot_puts); }
static void release_session(void)
{
	CHECK(!airoha_npu_production_release(&ppe));
	CHECK(!ppe.ct_npu_owner && !lower.refs && !upper.refs && releases == 1 && snapshot_puts == 1);
	CHECK(registers[0] == 8 && registers[1] == 16 && registers[2] == 9 && registers[3] == 32);
}
static void test_lifecycle(void)
{
	fixture(); start_session();
	u32 learning_epoch = session.txn.id.epoch;
	health_tick(); CHECK(!session.production_bound && takes == 1 && !installs);
	unbound_event(); health_tick();
	CHECK(health_checks == 2 && scheduled == 2 && session.production_bound && installs == 1);
	CHECK(session.txn.phase == NPU_TXN_OPEN && session.production_hash == 23 && published.raw[4] == 23);
	CHECK(session.txn.id.epoch > learning_epoch && published.raw[1] == session.txn.id.epoch);
	CHECK(!memcmp(&hardware.ipv4, &available.data.ipv4, sizeof(hardware.ipv4)));
	CHECK(hardware.ib1 & AIROHA_FOE_IB1_BIND_STATIC);
	removal_in_progress = true;
	CHECK(!airoha_ppe_ct_remove_pon_flow(&ppe, &candidate));
	CHECK(session.invalidated && session.txn.phase == NPU_TXN_CLOSED && !auth_enabled && !route_open);
	CHECK(!memcmp(&hardware, &(struct airoha_foe_entry){}, sizeof(hardware))); retained();
	unsigned int consumed = takes; unbound_event(); health_tick();
	CHECK(takes == consumed && !session.close_pending && !route_open); retained();
	memset(&candidate.pon_unbound_event, 0, sizeof(candidate.pon_unbound_event));
	release_session();
}
static void test_start_rejection(void)
{
	fixture(); pairs[2].used = true;
	CHECK(airoha_npu_production_start(&ppe, 123, 456) == -EBUSY && !claims);
	pairs[2].used = false; ppe.ct_pair_policy_allowed = true;
	CHECK(airoha_npu_production_start(&ppe, 123, 456) == -EBUSY && !claims);
	ppe.ct_pair_policy_allowed = false;
	CHECK(airoha_npu_production_start(&ppe, 123, 457) == -ESTALE && !claims);
	CHECK(!lower.refs && !upper.refs && snapshot_puts == 1);
}
static void test_authorization_failure(void)
{
	const int operations[] = { AUTH_MBOX_BEGIN, AUTH_MBOX_ADD, AUTH_MBOX_ARM };
	for (unsigned int i = 0; i < sizeof(operations) / sizeof(operations[0]); i++) {
		fixture(); auth_error_op = operations[i];
		CHECK(airoha_npu_production_start(&ppe, 123, 456) == -ETIMEDOUT);
		CHECK(session.invalidated && !auth_enabled && !route_open && session.txn.phase == NPU_TXN_CLOSED);
		retained(); unbound_event(); health_tick(); CHECK(!takes && !installs);
		CHECK(session.txn.last_error == -ETIMEDOUT); release_session();
	}
}
static void test_checked_install_failure(void)
{
	fixture(); start_session(); unbound_event(); install_error = -ETIMEDOUT;
	CHECK(airoha_npu_production_step(&session) == -ETIMEDOUT);
	CHECK(installs == 1 && session.production_bound && session.invalidated && !route_open);
	CHECK(!memcmp(&hardware, &(struct airoha_foe_entry){}, sizeof(hardware)));
	retained(); health_tick(); CHECK(!releases); release_session();
}
static void test_withdraw_retry(void)
{
	fixture(); start_session(); unbound_event(); health_tick();
	drain_error = -EIO; removal_in_progress = true;
	CHECK(airoha_ppe_ct_remove_pon_flow(&ppe, &candidate) == -EIO);
	CHECK(!candidate.list && !candidate.pon_ingress_seen && !candidate.pon_unbound_event.serial);
	CHECK(session.bank0_next_row == 17 && session.txn.phase == NPU_TXN_PPE_DRAIN); retained();
	health_tick(); CHECK(session.close_pending); retained();
	drain_error = 0; health_tick(); CHECK(failed_cursor == 17 && !session.close_pending);
	CHECK(!airoha_ppe_ct_remove_pon_flow(&ppe, &candidate)); retained(); release_session();
}
static void test_stale_identity(void)
{
	fixture(); start_session(); unbound_event(); hardware.ipv4.orig_tuple.dest_port ^= 1;
	CHECK(airoha_npu_production_step(&session) == -ESTALE && !installs); retained(); release_session();
	fixture(); start_session(); ingress.pon_link_ops = &other_controller; health_tick();
	CHECK(session.invalidated && !takes && !route_open); retained(); release_session();
	fixture(); start_session(); candidate.pon_candidate_serial++;
	CHECK(!airoha_npu_production_withdraw(&ppe, &candidate) && !session.invalidated);
	candidate.pon_candidate_serial--; release_session();
}
static void test_release_retry(void)
{
	fixture(); start_session(); destroy_error = -ETIMEDOUT;
	CHECK(airoha_npu_production_release(&ppe) == -ETIMEDOUT); retained();
	CHECK(session.return_path && !session.closed_ack); destroy_error = 0;
	restore_error_register = REG_PPE_TB_CFG(1);
	CHECK(airoha_npu_production_release(&ppe) == -EIO); retained();
	CHECK(!session.return_path && !registers[1] && !registers[3]); release_session();
	for (int reg = 0; reg < 4; reg++) {
		fixture(); start_session(); restore_error_register = reg;
		CHECK(airoha_npu_production_release(&ppe) == -EIO); retained();
		CHECK(!route_open && !registers[1] && !registers[3]); release_session();
	}
	fixture(); start_session(); retire_error = -EAGAIN;
	CHECK(airoha_npu_production_release(&ppe) == -EAGAIN); retained();
	CHECK(!route_open && !registers[1] && !registers[3]);
	retire_error = 0; release_session();
}

static void test_event_identity(void)
{
	for (unsigned int condition = 0; condition < 5; condition++) {
		fixture(); start_session(); unbound_event();
		switch (condition) {
		case 0: candidate.pon_unbound_event.serial++; break;
		case 1: candidate.pon_unbound_event.generation++; break;
		case 2: candidate.pon_unbound_event.service ^= 0x8000; break;
		case 3: candidate.pon_unbound_event.key[18] ^= 1; break;
		case 4: candidate.pon_unbound_event.hardware_hash = PPE_SRAM_NUM_ENTRIES; break;
		}
		CHECK(airoha_npu_production_step(&session) == (condition == 4 ? -EINVAL : -ESTALE));
		CHECK(session.invalidated && !route_open && !installs && takes == 1);
		retained(); release_session();
	}
}

static void test_prepare_and_start_guards(void)
{
	fixture();
	CHECK(airoha_npu_production_start(&ppe, 123, 0) == -EINVAL && !claims);
	CHECK(airoha_npu_production_start(&ppe, 124, 456) == -ENOENT && !claims);
	CHECK(!lower.refs && !upper.refs);
	for (unsigned int condition = 0; condition < 8; condition++) {
		fixture();
		switch (condition) {
		case 0: eth.ct_pon_full = false; break;
		case 1: eth.ct_ordinary_full_test = true; break;
		case 2: ppe.ct_host_ppe = false; break;
		case 3: ppe.ct_native_pairs = false; break;
		case 4: ppe.ct_pair_failed = true; break;
		case 5: eth.ct_cpu_fallback = true; break;
		case 6: eth.ct_ifc_cpu_port_failed = true; break;
		case 7: eth.pon_update_owner = &eth; break;
		}
		CHECK(airoha_npu_production_start(&ppe, 123, 456) == (condition < 4 ? -EOPNOTSUPP : -EBUSY));
		CHECK(!claims && !lower.refs && !upper.refs && !snapshot_puts);
	}
	fixture(); prepare_error = -ENOMEM;
	CHECK(airoha_npu_production_start(&ppe, 123, 456) == -ENOMEM);
	CHECK(!session.return_path && !auth_enabled && !route_open); retained(); release_session();
}
static void test_health_gating(void)
{
	fixture(); start_session(); unbound_event(); health_error = -EIO; health_tick();
	CHECK(!takes && !installs && session.invalidated); retained(); release_session();
	fixture(); start_session(); unbound_event();
	airoha_npu_owner_health_work(&session.health_work.work);
	CHECK(!takes && !health_checks && scheduled == 1 && flow_offload_mutex == 1); release_session();
}
static void test_active_guards(void)
{
	for (unsigned int slot = 0; slot < AIROHA_CT_PAIR_SLOTS; slot++) {
		fixture(); start_session(); CHECK(airoha_ppe_npu_production_active(&ppe, &session));
		pairs[slot].used = true; CHECK(!airoha_ppe_npu_production_active(&ppe, &session));
		CHECK(airoha_npu_production_validate(&session) == -ESTALE); release_session();
	}
	for (unsigned int condition = 0; condition < 10; condition++) {
		fixture(); start_session(); CHECK(!airoha_ppe_npu_production_active(&ppe, &eth));
		switch (condition) {
		case 0: ppe.ct_pair_policy_allowed = true; break;
		case 1: session.invalidated = true; break;
		case 2: session.close_pending = true; break;
		case 3: current_generation++; break;
		case 4: ingress.pon_link_ops = &other_controller; break;
		case 5: ingress.pon_link_priv = &other_controller; break;
		case 6: lower.carrier = false; break;
		case 7: egress.pon_update_blocked = true; break;
		case 8: ingress.pon_qdma_tag = 1; break;
		case 9: ingress.qdma = &eth.qdma[0]; break;
		}
		CHECK(!airoha_ppe_npu_production_active(&ppe, &session));
		CHECK(airoha_npu_production_validate(&session) == -ESTALE); retained(); release_session();
	}
}
static void test_readout(void)
{
	fixture();
	struct seq_file stream = { .private = &ppe };
	walk_entries[0] = ERR_PTR(-EAGAIN); walk_entries[1] = &ineligible; walk_entries[2] = &candidate;
	flow_offload_mutex = 0; CHECK(!airoha_npu_production_show(&stream, NULL));
	CHECK(!flow_offload_mutex && !walk_active && !ppe_lock && !lower.refs && !upper.refs && !snapshot_puts);
	CHECK(strstr(stream.output, "candidate cookie=123 serial=456 service=1025\n"));
	CHECK(!strstr(stream.output, "candidate cookie=999"));
	stream.length = 0; stream.output[0] = 0; walk_entries[0] = ERR_PTR(-EIO);
	CHECK(airoha_npu_production_show(&stream, NULL) == -EIO);
	CHECK(!flow_offload_mutex && !walk_active && !ppe_lock);
	flow_offload_mutex = 1; memset(walk_entries, 0, sizeof(walk_entries)); start_session();
	unbound_event(); health_tick(); stream.length = 0; flow_offload_mutex = 0;
	CHECK(!airoha_npu_production_show(&stream, NULL) && strstr(stream.output, "bound=1"));
	flow_offload_mutex = 1; CHECK(!airoha_npu_production_withdraw(&ppe, &candidate));
	stream.length = 0; flow_offload_mutex = 0;
	CHECK(!airoha_npu_production_show(&stream, NULL) && strstr(stream.output, "bound=0"));
	flow_offload_mutex = 1; CHECK(session.production_bound); release_session();
}
int main(void)
{
	test_lifecycle(); test_start_rejection(); test_authorization_failure();
	test_checked_install_failure(); test_withdraw_retry(); test_stale_identity();
	test_release_retry(); test_health_gating(); test_active_guards(); test_readout();
	test_event_identity(); test_prepare_and_start_guards();
	printf("cases=%u checks=%u passed\n", cases, checks); return 0;
}
