#include <assert.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "airoha_npu_transaction_core.h"
#include "airoha_npu_auth_publish.h"
#include "npu_eth_return_abi.h"

typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t __be32;
typedef uint16_t __be16;
#define BIT(index) (1u << (index))
#define GENMASK(high, low) ((UINT32_MAX >> (31 - (high))) & (UINT32_MAX << (low)))
#define DECLARE_FLEX_ARRAY(type, name) type name[0]
#undef static_assert
#define static_assert(condition) _Static_assert(condition, #condition)
#define fallthrough __attribute__((fallthrough))
#define WARN_ON_ONCE(condition) ((void)(condition))
#define be32_to_cpu(value) ntohl(value)
#define be16_to_cpu(value) ntohs(value)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define U16_MAX UINT16_MAX
#define ETH_ALEN 6
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))
#define rcu_access_pointer(pointer) (pointer)
#define AIROHA_GDM2_IDX 2
#define AIROHA_DEV_F_PON 1
#define LPBK_EN_MASK 1u
#define PPE_GLO_CFG_EN_MASK 1u
#define PPE_GLO_CFG_BUSY_MASK 2u
#define PPE_TB_CFG_SEARCH_MISS_MASK 0x30u
#define PPE_FLOW_CFG_IP4_NAPT_MASK BIT(13)
#define PPE_SRAM_NUM_ENTRIES 8192u
#define FE_PSE_PORT_CDM2 5
#define REG_PPE_PPE_FLOW_CFG(bank) ((bank) * 3)
#define REG_PPE_TB_CFG(bank) ((bank) * 3 + 1)
#define REG_PPE_GLO_CFG(bank) ((bank) * 3 + 2)
#define REG_GDM_LPBK_CFG(port) (6 + (port))
#define REG_PPE_RAM_CTRL(bank) (10 + (bank))
#define FIELD_GET(mask, value) (((value) & (mask)) >> __builtin_ctz(mask))
#define FIELD_PREP(mask, value) (((value) << __builtin_ctz(mask)) & (mask))
#define read_poll_timeout_atomic(operation, value, condition, delay, timeout, sleep, ...) \
	((value) = operation(__VA_ARGS__), (condition) ? 0 : -ETIMEDOUT)

struct ethhdr { u8 h_dest[ETH_ALEN], h_source[ETH_ALEN]; __be16 h_proto; };
#include "foe_types.inc"
#include "sram_masks.inc"

static unsigned int checks, cases;
#define CHECK(condition) do { assert(condition); checks++; } while (0)
static int flow_offload_mutex = 1, ppe_lock;
static unsigned int rcu_depth;
#define lockdep_assert_held(lock) CHECK(*(lock) == 1)
#define rcu_read_lock() do { CHECK(flow_offload_mutex); rcu_depth++; } while (0)
#define rcu_read_unlock() do { CHECK(flow_offload_mutex && rcu_depth); rcu_depth--; } while (0)

enum { ETH_NODE, NAND_NODE, MAC_NODE, HOG_NODE, SNAND_NODE, EXTRA_SNAND, NODE_COUNT };
struct device_node {
	bool present, available, diagnostic, native, hog, high, gpios_present;
	int references;
	int gpios_read_error;
	size_t gpios_bytes;
	u32 gpio, gpio_flags;
};
struct device { struct device *parent; struct device_node *of_node; };
struct net_device {
	struct device dev;
	void *priv;
	int references;
	bool running, carrier;
	u8 dev_addr[ETH_ALEN];
};
struct airoha_pon_link_ops { int identity; };
struct airoha_qdma { int identity; };
struct airoha_gdm_port { int id; };
struct airoha_eth;
struct airoha_ppe;
struct airoha_gdm_dev {
	struct airoha_eth *eth;
	struct airoha_gdm_port *port;
	int nbq, pon_tx_pending;
	unsigned long flags;
	const struct airoha_pon_link_ops *pon_link_ops;
	void *pon_link_priv, *pon_flow_table;
	struct airoha_qdma *qdma;
	u32 pon_qdma_tag;
	bool pon_update_blocked;
};
struct airoha_er_stats { u64 packets, bytes, dropped, polls, empty_polls; u32 consumed, fault; };
struct airoha_er_observation { u32 descriptor[16], produced, consumed, frame_bytes; u8 frame[128]; };
struct airoha_er {
	int observation_lock;
	bool observation_enabled;
	struct airoha_er_observation observation;
	u64 packets, bytes, dropped, polls, empty_polls;
	u32 consumed, fault_reason;
};
struct airoha_npu_return { struct airoha_er *ring; struct airoha_gdm_dev *dev; struct er_config config; };
struct airoha_npu_owner {
	struct airoha_ppe *ppe;
	struct airoha_npu_txn txn;
	struct net_device *diag_lower;
	const struct airoha_pon_link_ops *diag_controller;
	void *diag_priv;
	bool retiring, bank1_saved, bank1_host_retired, closed_ack;
	bool auth_attempted, epoch_dirty, diag_auth, diag_learn;
	bool diag_bound, invalidated;
	bool bank0_saved, bank0_host_retired;
	u32 bank0_next_row, bank0_flow, bank0_tb;
	u32 diag_service, diag_hash;
	struct net_device *diag_egress;
	struct airoha_foe_entry diag_entry;
	u32 auth_count, bank1_next_row, bank1_flow, bank1_tb;
	struct { bool saved_valid, dirty, active, pending; } ingress;
	struct airoha_npu_return *return_path;
	struct airoha_er_stats diag_stats;
	struct airoha_er_observation diag_observation;
	int health_work;
};
struct airoha_bank1_routes { const void *owner; bool ready, revoked, ingress_ready, pon_open; };
struct airoha_ppe {
	struct airoha_eth *eth;
	struct airoha_npu_owner *ct_npu_owner;
	bool ct_pon_qualified, ct_pair_policy_allowed, ct_pair_failed, ct_stopping;
	bool ct_pair_wired_registered, ct_pon_ifc_route_owned;
};
struct airoha_eth {
	struct airoha_ppe *ppe;
	struct device *dev;
	struct airoha_qdma qdma[2];
	struct airoha_bank1_routes ct_bank1_routes;
	bool ct_ordinary_full_test, ct_cpu_fallback, ct_ifc_cpu_port_failed;
	void *pon_update_owner;
	u32 ct_cpu_route_mask[4];
	int ct_route_lock;
};

static struct device_node nodes[NODE_COUNT];
static struct airoha_eth eth, other_eth;
static struct airoha_ppe ppe;
static struct device eth_device;
static struct net_device lower;
static struct airoha_gdm_dev gdm;
static struct airoha_gdm_port port;
static struct net_device lan;
static struct airoha_gdm_dev lan_gdm;
static struct airoha_gdm_port lan_port;
static struct airoha_npu_owner session;
static struct airoha_npu_return path;
static struct airoha_er ring;
static struct airoha_pon_link_ops controller, other_controller;
static int controller_priv, other_priv, init_net;
static u32 registers[12], auth_count, auth_enabled;
static unsigned int claim_calls, close_calls, open_calls, freed, netdev_puts, cancels, writes;
static unsigned int auth_calls[5], observed, route_releases, fe_releases, restores;
static bool machine_ok, have_netdev, valid_gdm, ifc_busy, claim_keeps_owner;
static bool mismatch_controller, binding_valid, closed_postconditions;
static int claim_error, prepare_error, state_error, open_error, close_error;
static int release_error, fe_error, fail_write, fail_auth_op, bad_auth_word;
static int route_write_error, scope_error, cpu_port;
static u32 binding_service;
static unsigned int binding_calls, ready_calls;
static int bad_auth_op, fail_auth_status_op;
static bool fail_ready_after_auth;
static bool open_runs_bank1, trace_mmio, readback_corrupted, fail_state_after_write;
static int fail_readback;
static bool written_regs[12];
static u32 readback_mask;
struct mmio_event {
	bool write;
	unsigned int reg;
	u32 value, next_row;
	int locked;
};
static struct mmio_event mmio_events[64];
static unsigned int mmio_count, scope_calls;
static u32 close_entry_row, close_bank0_row;
static unsigned int clear_calls[2], clear_order[8], clear_count;
static int clear_error[2], retire_error;
static int bank0_retire_error;
static unsigned int bank0_retire_calls;
enum { TRACE_BINDING = 5, TRACE_READY, TRACE_OPEN };
static u32 trace[128], trace_count;
static struct npu_auth_message auth_requests[5];
static bool have_lan, valid_lan, close_clears_rows;
static unsigned int lan_puts, entry_prepare_calls, sram_reads, sram_commits, sram_sequence;
static int entry_prepare_error, fail_sram_read, bad_sram_ack, fail_commit;
static bool commit_takes_effect;
static int corrupt_sram_read, corrupt_sram_byte;
static u32 bad_sram_mask;
static u8 corrupt_sram_mask;
static struct airoha_foe_entry hardware_entry, shadow_entry;
static struct airoha_flow_data prepared_data;
static u32 expected_hash;
enum { TRACE_SRAM_READ = 16, TRACE_SRAM_WRITE, TRACE_CLOSE, TRACE_PREPARE };
struct sram_event { u32 operation, hash, cursor; enum airoha_npu_txn_phase phase; };
static struct sram_event sram_events[16];

static void record_event(u32 event)
{
	CHECK(trace_count < ARRAY_SIZE(trace));
	trace[trace_count++] = event;
}
static void ether_addr_copy(u8 *destination, const u8 *source)
{
	memcpy(destination, source, ETH_ALEN);
}
static u32 get_unaligned_be32(const u8 *bytes)
{
	return (u32)bytes[0] << 24 | (u32)bytes[1] << 16 | (u32)bytes[2] << 8 | bytes[3];
}

static void spin_lock_bh(int *lock) { CHECK(!*lock); *lock = 1; }
static void spin_unlock_bh(int *lock) { CHECK(*lock == 1); *lock = 0; }
static void *netdev_priv(struct net_device *dev) { return dev->priv; }
static struct net_device *netdev_from_priv(struct airoha_gdm_dev *dev) { CHECK(dev == &gdm); return &lower; }
static bool netif_running(struct net_device *dev) { return dev->running; }
static bool netif_carrier_ok(struct net_device *dev) { return dev->carrier; }
static bool test_bit(unsigned int bit, const unsigned long *flags) { return *flags & (1ul << bit); }
static int atomic_read(int *value) { return *value; }
static bool of_machine_is_compatible(const char *name)
{
	CHECK(!strcmp(name, "fiberhome,hg5585f-ct"));
	return machine_ok;
}
static bool of_property_read_bool(struct device_node *node, const char *name)
{
	if (!strcmp(name, "airoha,connac2-pon-er-diagnostic"))
		return node->diagnostic;
	if (!strcmp(name, "airoha,connac2-ram-native-pairs"))
		return node->native;
	if (!strcmp(name, "gpio-hog"))
		return node->hog;
	CHECK(!strcmp(name, "output-high"));
	return node->high;
}
static int of_property_count_u32_elems(const struct device_node *node, const char *name)
{
	CHECK(node == &nodes[HOG_NODE] && !strcmp(name, "gpios"));
	if (!node->gpios_present || node->gpios_bytes % sizeof(u32))
		return -EINVAL;
	return node->gpios_bytes / sizeof(u32);
}
static int of_property_read_u32_array(const struct device_node *node, const char *name,
				    u32 *values, size_t count)
{
	CHECK(node == &nodes[HOG_NODE] && !strcmp(name, "gpios") && count == 2);
	if (!node->gpios_present)
		return -EINVAL;
	if (node->gpios_read_error)
		return node->gpios_read_error;
	if (node->gpios_bytes < count * sizeof(u32))
		return -EOVERFLOW;
	values[0] = node->gpio;
	values[1] = node->gpio_flags;
	return 0;
}
static struct device_node *of_find_node_by_path(const char *name)
{
	unsigned int index;

	if (!strcmp(name, "/soc/nand-controller@1fa11000"))
		index = NAND_NODE;
	else if (!strcmp(name, "/soc/ethernet@1fb64000"))
		index = MAC_NODE;
	else {
		CHECK(!strcmp(name, "/soc/system-controller@1fbf0200/pinctrl/ram-tx-disable-hog"));
		index = HOG_NODE;
	}
	if (!nodes[index].present)
		return NULL;
	nodes[index].references++;
	return &nodes[index];
}
static void of_node_put(struct device_node *node) { if (node) CHECK(--node->references >= 0); }
static bool of_device_is_available(struct device_node *node) { return node->available; }
static struct device_node *of_find_compatible_node(struct device_node *from,
						   const char *type, const char *name)
{
	unsigned int index = from ? (unsigned int)(from - nodes) + 1 : SNAND_NODE;

	CHECK(!type && !strcmp(name, "airoha,en7581-snand"));
	of_node_put(from);
	for (; index < NODE_COUNT; index++) {
		if (nodes[index].present) {
			nodes[index].references++;
			return &nodes[index];
		}
	}
	return NULL;
}
#define for_each_compatible_node(node, type, name) \
	for (node = of_find_compatible_node(NULL, type, name); node; \
	     node = of_find_compatible_node(node, type, name))

static struct net_device *dev_get_by_name(int *net, const char *name)
{
	CHECK(net == &init_net);
	if (!strcmp(name, "lan1")) {
		if (!have_lan)
			return NULL;
		lan.references++;
		return &lan;
	}
	CHECK(!strcmp(name, "pon0"));
	if (!have_netdev)
		return NULL;
	lower.references++;
	return &lower;
}
static void dev_put(struct net_device *dev)
{
	CHECK((dev == &lower || dev == &lan) && --dev->references >= 0);
	if (dev == &lan)
		lan_puts++;
	netdev_puts++;
}
static bool airoha_is_valid_gdm_dev(struct airoha_eth *actual, struct airoha_gdm_dev *dev)
{
	CHECK(actual == &eth && (dev == &gdm || dev == &lan_gdm));
	if (dev == &lan_gdm)
		return valid_lan && dev->eth == actual;
	return valid_gdm;
}
static bool airoha_ct_pon_ifc_busy(struct airoha_ppe *actual) { CHECK(actual == &ppe); return ifc_busy; }
static u64 br_flow_offload_generation(void) { return 19; }
static u32 airoha_fe_rr(struct airoha_eth *actual, unsigned int reg)
{
	u32 value;

	CHECK(actual == &eth && reg < ARRAY_SIZE(registers));
	value = registers[reg];
	if (written_regs[reg] && (int)reg == fail_readback &&
	    !readback_corrupted) {
		value ^= readback_mask;
		readback_corrupted = true;
	}
	if (trace_mmio) {
		CHECK(mmio_count < ARRAY_SIZE(mmio_events));
		mmio_events[mmio_count++] = (struct mmio_event) {
			false, reg, value, session.bank0_next_row, ppe_lock,
		};
	}
	return value;
}
static void airoha_fe_wr(struct airoha_eth *actual, unsigned int reg, u32 value)
{
	CHECK(actual == &eth && reg < ARRAY_SIZE(registers));
	CHECK(ppe_lock);
	writes++;
	written_regs[reg] = true;
	if (trace_mmio) {
		CHECK(mmio_count < ARRAY_SIZE(mmio_events));
		mmio_events[mmio_count++] = (struct mmio_event) {
			true, reg, value, session.bank0_next_row, ppe_lock,
		};
	}
	if ((int)reg != fail_write)
		registers[reg] = value;
}
static void airoha_fe_rmw(struct airoha_eth *actual, unsigned int reg, u32 mask, u32 value)
{
	airoha_fe_wr(actual, reg, (airoha_fe_rr(actual, reg) & ~mask) | value);
}
static int clear_bank(struct airoha_ppe *actual, u32 bank, u32 *cursor)
{
	CHECK(actual == &ppe && !ppe_lock && flow_offload_mutex == 1);
	CHECK(cursor == (bank ? &session.bank1_next_row : &session.bank0_next_row));
	CHECK(bank ? session.bank1_host_retired : session.bank0_host_retired);
	CHECK(!registers[REG_PPE_PPE_FLOW_CFG(bank)]);
	CHECK(FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, registers[REG_PPE_TB_CFG(bank)]) == 2);
	CHECK((registers[REG_PPE_GLO_CFG(bank)] & (PPE_GLO_CFG_EN_MASK | PPE_GLO_CFG_BUSY_MASK)) == PPE_GLO_CFG_EN_MASK);
	CHECK(clear_count < ARRAY_SIZE(clear_order));
	clear_order[clear_count++] = bank;
	clear_calls[bank]++;
	if (clear_error[bank]) {
		*cursor = 17;
		return clear_error[bank];
	}
	*cursor = PPE_SRAM_NUM_ENTRIES;
	if (!bank)
		memset(&hardware_entry, 0, sizeof(hardware_entry));
	return 0;
}
static int airoha_ppe_bank0_clear_rows(struct airoha_ppe *actual, u32 *cursor)
{
	return clear_bank(actual, 0, cursor);
}
static int airoha_ppe_bank1_clear_rows(struct airoha_ppe *actual, u32 *cursor)
{
	return clear_bank(actual, 1, cursor);
}
static int airoha_ppe_bank1_retire_flows(struct airoha_ppe *actual)
{
	CHECK(actual == &ppe && !ppe_lock);
	return retire_error;
}
static int airoha_ppe_bank0_retire_flows(struct airoha_ppe *actual)
{
	CHECK(actual == &ppe && !ppe_lock && flow_offload_mutex == 1);
	CHECK(session.bank0_saved && !session.bank0_host_retired);
	CHECK(!registers[REG_PPE_PPE_FLOW_CFG(0)]);
	CHECK(FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, registers[REG_PPE_TB_CFG(0)]) == 2);
	CHECK((registers[REG_PPE_GLO_CFG(0)] & (PPE_GLO_CFG_EN_MASK | PPE_GLO_CFG_BUSY_MASK)) == PPE_GLO_CFG_EN_MASK);
	bank0_retire_calls++;
	return bank0_retire_error;
}
#include "bank0_drain.inc"
#include "bank1_drain.inc"
static int airoha_npu_owner_return_state(struct airoha_npu_owner *owner,
					const struct airoha_npu_txn_identity *id,
					enum airoha_npu_txn_phase phase)
{
	CHECK(owner == &session && id == &owner->txn.id);
	CHECK(phase >= NPU_TXN_CLOSED);
	if (fail_state_after_write && writes)
		return -ESTALE;
	return state_error;
}
static int airoha_npu_owner_return_ready(struct airoha_npu_owner *owner,
					const struct airoha_npu_txn_identity *id)
{
	ready_calls++;
	record_event(TRACE_READY);
	if (fail_ready_after_auth && auth_calls[AUTH_MBOX_ARM])
		return -ESTALE;
	return airoha_npu_owner_return_state(owner, id, NPU_TXN_READY);
}
static bool airoha_npu_return_binding(struct airoha_npu_return *actual, struct net_device *netdev,
				     const struct er_config *config, u32 service)
{
	CHECK(actual == &path && netdev == &lower && config == &path.config);
	CHECK(rcu_depth);
	binding_calls++;
	record_event(TRACE_BINDING);
	return binding_valid && service == (ER_SERVICE_VALID | binding_service);
}
static int airoha_npu_owner_auth(void *ctx, struct npu_auth_message *message)
{
	struct airoha_npu_owner *owner = ctx;
	u32 operation = message->w[AM_ABI_OP] >> 16;

	CHECK(owner == &session && operation < ARRAY_SIZE(auth_calls));
	CHECK(message->w[AM_MAGIC] == AUTH_MBOX_MAGIC && message->w[AM_BYTES] == AUTH_MBOX_BYTES);
	auth_requests[operation] = *message;
	record_event(operation);
	if (owner->diag_auth && operation != AUTH_MBOX_QUERY)
		CHECK(binding_calls == 1 && owner->auth_attempted && owner->epoch_dirty &&
		      !registers[REG_PPE_PPE_FLOW_CFG(1)]);
	auth_calls[operation]++;
	if ((int)operation == fail_auth_op)
		return -ETIMEDOUT;
	if (operation == AUTH_MBOX_BEGIN)
		auth_count = auth_enabled = 0;
	if (operation == AUTH_MBOX_ADD)
		auth_count++;
	if (operation == AUTH_MBOX_ARM)
		auth_enabled = 1;
	message->w[AM_STATUS] = 0;
	message->w[AM_CAPS] = AUTH_MBOX_CAPS;
	message->w[AM_STATE_EPOCH] = owner->txn.id.epoch;
	message->w[AM_STATE_GENERATION] = owner->txn.id.generation;
	message->w[AM_COUNT] = auth_count;
	message->w[AM_ENABLED] = auth_enabled;
	if ((int)operation == fail_auth_status_op)
		message->w[AM_STATUS] = (u32)-EIO;
	if (bad_auth_word >= 0 && (bad_auth_op < 0 || bad_auth_op == (int)operation))
		message->w[bad_auth_word]++;
	return 0;
}
static int airoha_ppe_npu_owner_claim_locked(struct airoha_eth *actual, u64 generation)
{
	CHECK(actual == &eth && generation == 19 && !ppe.ct_npu_owner);
	claim_calls++;
	if (!claim_error || claim_keeps_owner)
		ppe.ct_npu_owner = &session;
	return claim_error;
}
static int airoha_ppe_npu_return_prepare_locked(struct airoha_eth *actual,
					       struct airoha_gdm_dev *dev, u32 count)
{
	CHECK(actual == &eth && dev == &gdm && count == 8);
	CHECK(session.diag_lower == &lower && lower.references == 1);
	if (session.diag_bound)
		record_event(TRACE_PREPARE);
	if (prepare_error)
		return prepare_error;
	session.return_path = &path;
	path.ring = &ring;
	if (mismatch_controller)
		gdm.pon_link_ops = &other_controller;
	return 0;
}
static int airoha_npu_owner_bank1_restore(void *ctx,
					 const struct airoha_npu_txn_identity *id);
int airoha_bank1_routes_open(struct airoha_eth *actual, const void *owner);
static int airoha_ppe_npu_owner_open_locked(struct airoha_eth *actual)
{
	int error;

	CHECK(actual == &eth && auth_enabled);
	CHECK(session.auth_count == (session.diag_auth ? 1u : 0u));
	CHECK(auth_calls[AUTH_MBOX_ADD] == (session.diag_auth ? 1u : 0u));
	CHECK(session.auth_attempted && session.epoch_dirty);
	CHECK(!registers[REG_PPE_PPE_FLOW_CFG(1)]);
	record_event(TRACE_OPEN);
	open_calls++;
	if (!open_error && open_runs_bank1) {
		if (session.diag_bound)
			session.txn.phase = NPU_TXN_PPE_RESTORE;
		error = airoha_npu_owner_bank1_restore(&session, &session.txn.id);
		if (error)
			return error;
		error = airoha_bank1_routes_open(actual, &session);
		if (!error && session.diag_bound)
			session.txn.phase = NPU_TXN_OPEN;
		return error;
	}
	return open_error;
}
static int airoha_ppe_npu_owner_close_locked(struct airoha_eth *actual)
{
	CHECK(actual == &eth);
	close_calls++;
	record_event(TRACE_CLOSE);
	close_entry_row = session.bank1_next_row;
	close_bank0_row = session.bank0_next_row;
	if (close_error)
		return close_error;
	if (close_clears_rows) {
		int error = airoha_npu_owner_bank1_drain(&session, &session.txn.id);
		if (error)
			return error;
		eth.ct_bank1_routes.pon_open = false;
		close_clears_rows = false;
	}
	if (closed_postconditions) {
		session.return_path = NULL;
		session.txn.phase = NPU_TXN_CLOSED;
		session.epoch_dirty = session.auth_attempted = false;
		session.auth_count = 0;
		session.closed_ack = true;
	}
	return 0;
}
static int airoha_bank1_routes_release(struct airoha_eth *actual, const void *owner)
{
	CHECK(actual == &eth && owner == &session);
	route_releases++;
	if (!release_error)
		eth.ct_bank1_routes.owner = NULL;
	return release_error;
}
static int airoha_ct_fe_owner_release(struct airoha_ppe *actual, struct airoha_npu_owner *owner)
{
	CHECK(actual == &ppe && owner == &session && ppe_lock);
	fe_releases++;
	return fe_error;
}
static void cancel_delayed_work_sync(int *work) { CHECK(work == &session.health_work); cancels++; }
static void kfree(void *owner)
{
	CHECK(owner == &session && !ppe.ct_npu_owner && !lower.references && !lan.references);
	freed++;
}
static int airoha_ct_gdm_cpu_locked(struct airoha_eth *actual, unsigned int port_id)
{
	CHECK(actual == &eth && port_id == 2 && eth.ct_route_lock);
	return cpu_port;
}
static int airoha_bank1_routes_write_all(struct airoha_eth *actual, bool guarded)
{
	CHECK(actual == &eth && guarded && eth.ct_route_lock);
	restores++;
	return route_write_error;
}
static int airoha_bank1_scope_locked(struct airoha_eth *actual, bool enable)
{
	CHECK(actual == &eth && enable && eth.ct_route_lock);
	scope_calls++;
	return scope_error;
}
static int airoha_bank1_routes_revoke_locked(struct airoha_eth *actual)
{
	CHECK(actual == &eth && eth.ct_route_lock);
	eth.ct_bank1_routes.pon_open = false;
	return 0;
}

static bool is_valid_ether_addr(const u8 *address)
{
	static const u8 zero[ETH_ALEN];
	return !(address[0] & 1) && memcmp(address, zero, ETH_ALEN);
}

static int kstrtou32(const char *text, unsigned int base, u32 *value)
{
	char *end;
	unsigned long long parsed;

	if (!*text || *text == '-' || isspace((unsigned char)*text))
		return -EINVAL;
	errno = 0;
	parsed = strtoull(text, &end, base);
	if (errno || parsed > UINT32_MAX)
		return -ERANGE;
	if (*end == '\n')
		end++;
	if (end == text || *end)
		return -EINVAL;
	*value = parsed;
	return 0;
}

static bool mac_pton(const char *text, u8 *address)
{
	if (strlen(text) < 17)
		return false;
	for (unsigned int index = 0; index < ETH_ALEN; ++index) {
		char byte[3] = { text[index * 3], text[index * 3 + 1], 0 };
		if (!isxdigit((unsigned char)byte[0]) || !isxdigit((unsigned char)byte[1]) ||
		    (index < ETH_ALEN - 1 && text[index * 3 + 2] != ':'))
			return false;
		address[index] = strtoul(byte, NULL, 16);
	}
	return true;
}

static bool in4_pton(const char *text, int length, u8 *address, int delimiter, const char **end)
{
	char prefix[16];
	size_t count = strspn(text, "0123456789.");

	CHECK(length == -1 && (delimiter == 0 || delimiter == -1));
	if (count >= sizeof(prefix))
		return false;
	memcpy(prefix, text, count);
	prefix[count] = 0;
	if (end)
		*end = text + count;
	return (!text[count] || delimiter == -1) && inet_pton(AF_INET, prefix, address) == 1;
}

static u32 airoha_ppe_get_timestamp(struct airoha_ppe *actual)
{
	CHECK(actual == &ppe);
	return 0x12345;
}

static int airoha_ppe_foe_entry_prepare(struct airoha_eth *actual,
		struct airoha_foe_entry *entry, struct net_device *netdev, int type,
		struct airoha_flow_data *data, int protocol, u8 dsfield,
		struct airoha_gdm_dev **egress)
{
	CHECK(actual == &eth && netdev == &lan && *egress == &lan_gdm);
	CHECK(type == PPE_PKT_TYPE_IPV4_HNAPT && protocol == IPPROTO_UDP && !dsfield);
	entry_prepare_calls++;
	prepared_data = *data;
	if (entry_prepare_error)
		return entry_prepare_error;
	memset(entry, 0, sizeof(*entry));
	entry->ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND) |
		AIROHA_FOE_IB1_BIND_UDP | AIROHA_FOE_IB1_BIND_TTL;
	entry->ipv4.ib2 = FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, 11) |
		AIROHA_FOE_IB2_FAST_PATH;
	entry->ipv4.l2.common.src_mac_hi = get_unaligned_be32(data->eth.h_source);
	entry->ipv4.l2.src_mac_lo = (u16)data->eth.h_source[4] << 8 | data->eth.h_source[5];
	entry->ipv4.l2.common.dest_mac_hi = get_unaligned_be32(data->eth.h_dest);
	entry->ipv4.l2.common.dest_mac_lo = (u16)data->eth.h_dest[4] << 8 | data->eth.h_dest[5];
	return 0;
}

static void sram_operation(u32 operation, u32 hash)
{
	CHECK(ppe_lock == 1 && flow_offload_mutex == 1 && hash == expected_hash);
	CHECK(sram_sequence < ARRAY_SIZE(sram_events));
	sram_events[sram_sequence++] = (struct sram_event) {
		operation, hash, session.bank0_next_row, session.txn.phase,
	};
	record_event(operation);
	registers[REG_PPE_RAM_CTRL(0)] = FIELD_PREP(PPE_SRAM_CTRL_ENTRY_MASK, hash) |
		PPE_SRAM_CTRL_ACK_MASK | (operation == TRACE_SRAM_WRITE ? PPE_SRAM_CTRL_WR_MASK : 0);
	if ((int)sram_sequence == bad_sram_ack)
		registers[REG_PPE_RAM_CTRL(0)] ^= bad_sram_mask;
}

static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *actual, u32 hash)
{
	CHECK(actual == &ppe);
	sram_operation(TRACE_SRAM_READ, hash);
	sram_reads++;
	if ((int)sram_reads == fail_sram_read)
		return NULL;
	shadow_entry = hardware_entry;
	if ((int)sram_reads == corrupt_sram_read)
		shadow_entry.data[corrupt_sram_byte] ^= corrupt_sram_mask;
	return &shadow_entry;
}

static int airoha_ppe_foe_commit_sram_entry(struct airoha_ppe *actual, u32 hash)
{
	CHECK(actual == &ppe && session.bank0_next_row == 0 && session.bank1_next_row == PPE_SRAM_NUM_ENTRIES);
	CHECK(session.txn.phase == NPU_TXN_PPE_RESTORE && !registers[REG_PPE_PPE_FLOW_CFG(1)]);
	CHECK(FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, registers[REG_PPE_TB_CFG(1)]) == 2);
	CHECK(!registers[REG_PPE_PPE_FLOW_CFG(0)]);
	CHECK(FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, registers[REG_PPE_TB_CFG(0)]) == 2);
	sram_operation(TRACE_SRAM_WRITE, hash);
	sram_commits++;
	if (!fail_commit || commit_takes_effect)
		hardware_entry = shadow_entry;
	return fail_commit;
}

#include "active.inc"
#include "diag_flow.inc"
#include "bank0_owned.inc"
#include "platform.inc"
#include "er_stats.inc"
#include "er_observe.inc"
#include "er_enable.inc"
#include "retire.inc"
#include "snapshot.inc"
#include "diag_authorize.inc"
#include "start_mode.inc"
#include "start.inc"
#include "close.inc"
#include "authorize.inc"
#include "ready.inc"
#include "open_check.inc"
#include "bank0_hash.inc"
#include "sram_ack.inc"
#include "ipv4_tuple.inc"
#include "install.inc"
#include "bind.inc"
#include "bind_command.inc"
#include "restore.inc"
#include "routes.inc"

static void fixture(void)
{
	unsigned int index;

	memset(nodes, 0, sizeof(nodes));
	memset(&eth, 0, sizeof(eth));
	memset(&ppe, 0, sizeof(ppe));
	memset(&session, 0, sizeof(session));
	memset(&lower, 0, sizeof(lower));
	memset(&gdm, 0, sizeof(gdm));
	memset(&path, 0, sizeof(path));
	memset(&ring, 0, sizeof(ring));
	memset(&lan, 0, sizeof(lan));
	memset(&lan_gdm, 0, sizeof(lan_gdm));
	memset(&hardware_entry, 0, sizeof(hardware_entry));
	memset(&shadow_entry, 0, sizeof(shadow_entry));
	memset(&prepared_data, 0, sizeof(prepared_data));
	memset(sram_events, 0, sizeof(sram_events));
	have_lan = valid_lan = true;
	close_clears_rows = commit_takes_effect = false;
	lan_puts = entry_prepare_calls = sram_reads = sram_commits = sram_sequence = 0;
	entry_prepare_error = fail_commit = 0;
	fail_sram_read = bad_sram_ack = corrupt_sram_read = -1;
	corrupt_sram_byte = 0;
	bad_sram_mask = PPE_SRAM_CTRL_ACK_MASK;
	corrupt_sram_mask = 1;
	expected_hash = 0x458;
	memset(clear_calls, 0, sizeof(clear_calls));
	memset(clear_error, 0, sizeof(clear_error));
	clear_count = retire_error = 0;
	bank0_retire_calls = bank0_retire_error = 0;
	memset(registers, 0, sizeof(registers));
	memset(auth_calls, 0, sizeof(auth_calls));
	memset(auth_requests, 0, sizeof(auth_requests));
	memset(trace, 0, sizeof(trace));
	trace_count = binding_calls = ready_calls = 0;
	memset(mmio_events, 0, sizeof(mmio_events));
	mmio_count = scope_calls = 0;
	close_entry_row = close_bank0_row = UINT32_MAX;
	open_runs_bank1 = trace_mmio = readback_corrupted = fail_state_after_write = false;
	fail_readback = -1;
	memset(written_regs, 0, sizeof(written_regs));
	readback_mask = BIT(31);
	binding_service = 0x1001u;
	fail_ready_after_auth = false;
	bad_auth_op = fail_auth_status_op = -1;
	CHECK(!rcu_depth);
	for (index = 0; index < NODE_COUNT; index++)
		nodes[index].present = true;
	nodes[ETH_NODE].diagnostic = nodes[ETH_NODE].native = true;
	nodes[HOG_NODE].available = nodes[HOG_NODE].hog = nodes[HOG_NODE].high = true;
	nodes[HOG_NODE].gpios_present = true;
	nodes[HOG_NODE].gpios_bytes = 2 * sizeof(u32);
	nodes[HOG_NODE].gpio = 38;
	eth_device.of_node = &nodes[ETH_NODE];
	eth.dev = &eth_device;
	eth.ppe = &ppe;
	ppe.eth = &eth;
	ppe.ct_pair_wired_registered = true;
	lower.dev.parent = eth.dev;
	lower.priv = &gdm;
	lower.running = lower.carrier = true;
	memcpy(lower.dev_addr, (const u8[]) { 2, 0x11, 0x22, 0x33, 0x44, 0x55 }, ETH_ALEN);
	gdm.eth = &eth;
	gdm.port = &port;
	port.id = 2;
	lan.dev.parent = eth.dev;
	lan.priv = &lan_gdm;
	lan.running = lan.carrier = true;
	memcpy(lan.dev_addr, (const u8[]) { 2, 0x66, 0x77, 0x88, 0x99, 0xaa }, ETH_ALEN);
	lan_gdm.eth = &eth;
	lan_gdm.port = &lan_port;
	lan_port.id = 4;
	gdm.flags = BIT(AIROHA_DEV_F_PON);
	gdm.pon_link_ops = &controller;
	gdm.pon_link_priv = &controller_priv;
	gdm.pon_flow_table = &path;
	gdm.qdma = &eth.qdma[1];
	session.ppe = &ppe;
	session.txn.id = (struct airoha_npu_txn_identity) { 7, 19, GATE_PON2 };
	session.txn.phase = NPU_TXN_CLOSED;
	session.bank1_saved = session.bank1_host_retired = session.closed_ack = true;
	session.bank1_next_row = PPE_SRAM_NUM_ENTRIES;
	session.bank1_flow = 0x123400;
	session.bank1_tb = 0x456701;
	path.dev = &gdm;
	registers[REG_PPE_GLO_CFG(1)] = PPE_GLO_CFG_EN_MASK;
	registers[REG_PPE_TB_CFG(1)] = FIELD_PREP(PPE_TB_CFG_SEARCH_MISS_MASK, 2);
	registers[REG_GDM_LPBK_CFG(2)] = LPBK_EN_MASK;
	registers[0] = 0xabc001;
	registers[1] = 0xabc002;
	registers[2] = 0xabc001;
	claim_calls = close_calls = open_calls = freed = netdev_puts = cancels = writes = 0;
	observed = route_releases = fe_releases = restores = 0;
	machine_ok = have_netdev = valid_gdm = binding_valid = closed_postconditions = true;
	ifc_busy = claim_keeps_owner = mismatch_controller = false;
	claim_error = prepare_error = state_error = open_error = close_error = 0;
	release_error = fe_error = route_write_error = scope_error = 0;
	fail_write = fail_auth_op = bad_auth_word = -1;
	cpu_port = FE_PSE_PORT_CDM2;
	auth_count = auth_enabled = 0;
	ppe_lock = 0;
}
static void attach(void)
{
	ppe.ct_npu_owner = &session;
	session.diag_lower = &lower;
	session.diag_controller = &controller;
	session.diag_priv = &controller_priv;
	lower.references = 1;
}
static void balanced(void)
{
	unsigned int index;

	for (index = 0; index < NODE_COUNT; index++)
		CHECK(!nodes[index].references);
	CHECK(!ppe_lock && !eth.ct_route_lock && !ring.observation_lock && !rcu_depth);
	if (!session.bank0_saved || !ppe.ct_npu_owner)
		CHECK(registers[0] == 0xabc001 && registers[1] == 0xabc002 && registers[2] == 0xabc001);
	CHECK(lower.references == (ppe.ct_npu_owner && session.diag_lower ? 1 : 0));
	CHECK(lan.references == (ppe.ct_npu_owner && session.diag_egress ? 1 : 0));
	cases++;
}
static void test_platform(void)
{
	unsigned int scenario;

	fixture();
	CHECK(airoha_npu_diag_platform(&ppe));
	balanced();
	for (scenario = 0; scenario < 14; scenario++) {
		fixture();
		switch (scenario) {
		case 0: machine_ok = false; break;
		case 1: nodes[ETH_NODE].diagnostic = false; break;
		case 2: nodes[ETH_NODE].native = false; break;
		case 3: eth.ct_ordinary_full_test = true; break;
		case 4: ppe.ct_pon_qualified = true; break;
		case 5: ppe.ct_pair_policy_allowed = true; break;
		case 6: nodes[NAND_NODE].present = false; break;
		case 7: nodes[NAND_NODE].available = true; break;
		case 8: nodes[MAC_NODE].present = false; break;
		case 9: nodes[MAC_NODE].available = true; break;
		case 10: nodes[HOG_NODE].present = false; break;
		case 11: nodes[HOG_NODE].hog = false; break;
		case 12: nodes[HOG_NODE].high = false; break;
		case 13: nodes[EXTRA_SNAND].available = true; break;
		}
		CHECK(airoha_npu_diag_start(&ppe) == -EPERM);
		CHECK(!claim_calls && !auth_calls[AUTH_MBOX_BEGIN]);
		balanced();
	}
}
enum {
	HOG_DISABLED, HOG_WRONG_GPIO, HOG_ACTIVE_LOW, HOG_MISSING_GPIOS,
	HOG_EMPTY_GPIOS, HOG_SHORT_GPIOS, HOG_LONG_GPIOS, HOG_UNALIGNED_GPIOS,
	HOG_READ_EINVAL, HOG_READ_ENODATA, HOG_READ_EOVERFLOW, HOG_READ_EIO,
	HOG_INVALID_COUNT,
};
static void invalid_hog(unsigned int scenario)
{
	CHECK(scenario < HOG_INVALID_COUNT);
	switch (scenario) {
	case HOG_DISABLED: nodes[HOG_NODE].available = false; break;
	case HOG_WRONG_GPIO: nodes[HOG_NODE].gpio = 37; break;
	case HOG_ACTIVE_LOW: nodes[HOG_NODE].gpio_flags = 1; break;
	case HOG_MISSING_GPIOS: nodes[HOG_NODE].gpios_present = false; break;
	case HOG_EMPTY_GPIOS: nodes[HOG_NODE].gpios_bytes = 0; break;
	case HOG_SHORT_GPIOS: nodes[HOG_NODE].gpios_bytes = sizeof(u32); break;
	case HOG_LONG_GPIOS: nodes[HOG_NODE].gpios_bytes = 3 * sizeof(u32); break;
	case HOG_UNALIGNED_GPIOS: nodes[HOG_NODE].gpios_bytes = 2 * sizeof(u32) - 1; break;
	case HOG_READ_EINVAL: nodes[HOG_NODE].gpios_read_error = -EINVAL; break;
	case HOG_READ_ENODATA: nodes[HOG_NODE].gpios_read_error = -ENODATA; break;
	case HOG_READ_EOVERFLOW: nodes[HOG_NODE].gpios_read_error = -EOVERFLOW; break;
	case HOG_READ_EIO: nodes[HOG_NODE].gpios_read_error = -EIO; break;
	}
}
static void test_hog_admission(void)
{
	unsigned int scenario;

	for (scenario = 0; scenario < HOG_INVALID_COUNT; scenario++) {
		fixture();
		invalid_hog(scenario);
		CHECK(!airoha_npu_diag_platform(&ppe));
		CHECK(airoha_npu_diag_start(&ppe) == -EPERM);
		CHECK(!claim_calls && !open_calls && !netdev_puts && !writes);
		CHECK(!auth_calls[AUTH_MBOX_BEGIN] && !auth_calls[AUTH_MBOX_ARM]);
		balanced();
	}
}
static void test_active(void)
{
	unsigned int scenario;

	fixture();
	attach();
	CHECK(airoha_ppe_npu_diag_active(&ppe, &session));
	CHECK(!airoha_ppe_npu_diag_active(&ppe, &other_eth));
	balanced();
	for (scenario = 0; scenario < 20; scenario++) {
		fixture();
		attach();
		switch (scenario) {
		case 0: ppe.ct_npu_owner = NULL; lower.references = 0; break;
		case 1: session.diag_lower = NULL; lower.references = 0; break;
		case 2: session.retiring = true; break;
		case 3: ppe.ct_pon_qualified = true; break;
		case 4: ppe.ct_pair_policy_allowed = true; break;
		case 5: eth.ct_ordinary_full_test = true; break;
		case 6: session.auth_count = 1; break;
		case 7: gdm.eth = &other_eth; break;
		case 8: port.id = 1; break;
		case 9: gdm.nbq = 1; break;
		case 10: gdm.pon_link_ops = &other_controller; break;
		case 11: gdm.pon_link_priv = &other_priv; break;
		case 12: gdm.pon_link_ops = session.diag_controller = NULL; break;
		case 13: gdm.pon_link_priv = session.diag_priv = NULL; break;
		case 14: gdm.pon_update_blocked = true; break;
		case 15: lower.running = false; break;
		case 16: lower.carrier = false; break;
		case 17: gdm.pon_qdma_tag = 1; break;
		case 18: gdm.qdma = &eth.qdma[0]; break;
		case 19: nodes[ETH_NODE].diagnostic = false; break;
		}
		CHECK(!airoha_ppe_npu_diag_active(&ppe, &session));
		balanced();
	}
}
static void test_start(void)
{
	unsigned int scenario;

	fixture();
	CHECK(!airoha_npu_diag_start(&ppe));
	CHECK(ppe.ct_npu_owner == &session && lower.references == 1 && !netdev_puts);
	CHECK(session.auth_attempted && session.epoch_dirty && !session.auth_count);
	CHECK(auth_calls[AUTH_MBOX_BEGIN] == 1 && auth_calls[AUTH_MBOX_ARM] == 1 &&
	      !auth_calls[AUTH_MBOX_ADD] && open_calls == 1 && ring.observation_enabled);
	CHECK(!writes);
	balanced();
	for (scenario = 0; scenario < 26; scenario++) {
		int expected = -EBUSY;

		fixture();
		switch (scenario) {
		case 0: attach(); break;
		case 1: ppe.ct_pair_failed = true; break;
		case 2: ppe.ct_stopping = true; break;
		case 3: eth.ct_cpu_fallback = true; break;
		case 4: eth.ct_ifc_cpu_port_failed = true; break;
		case 5: eth.pon_update_owner = &session; break;
		case 6: ifc_busy = true; break;
		case 7: have_netdev = false; expected = -ENODEV; break;
		case 8: lower.dev.parent = NULL; expected = -EXDEV; break;
		case 9: valid_gdm = false; break;
		case 10: port.id = 1; break;
		case 11: gdm.nbq = 1; break;
		case 12: gdm.flags = 0; break;
		case 13: gdm.pon_link_ops = NULL; break;
		case 14: gdm.pon_link_priv = NULL; break;
		case 15: lower.running = false; break;
		case 16: lower.carrier = false; break;
		case 17: gdm.pon_update_blocked = true; break;
		case 18: gdm.pon_qdma_tag = 1; break;
		case 19: gdm.pon_flow_table = NULL; break;
		case 20: gdm.qdma = &eth.qdma[0]; break;
		case 21: gdm.pon_tx_pending = 1; break;
		case 22: registers[REG_GDM_LPBK_CFG(2)] = 0; break;
		case 23: claim_error = -EIO; expected = -EIO; break;
		case 24: claim_error = -EIO; claim_keeps_owner = true; expected = -EIO; break;
		case 25: prepare_error = -ETIMEDOUT; expected = -ETIMEDOUT; break;
		}
		CHECK(airoha_npu_diag_start(&ppe) == expected);
		CHECK(!open_calls && !auth_calls[AUTH_MBOX_BEGIN]);
		balanced();
	}
	for (scenario = 0; scenario < 6; scenario++) {
		int expected;

		fixture();
		switch (scenario) {
		case 0: state_error = -ESTALE; expected = -ESTALE; break;
		case 1: mismatch_controller = true; expected = -ESTALE; break;
		case 2: fail_auth_op = AUTH_MBOX_BEGIN; expected = -ETIMEDOUT; break;
		case 3: fail_auth_op = AUTH_MBOX_ARM; expected = -ETIMEDOUT; break;
		case 4: bad_auth_word = AM_COUNT; expected = -EPROTO; break;
		default: open_error = -EIO; expected = -EIO; break;
		}
		CHECK(airoha_npu_diag_start(&ppe) == expected);
		CHECK(ppe.ct_npu_owner == &session && session.txn.last_error == expected);
		CHECK(!freed && !netdev_puts && !auth_calls[AUTH_MBOX_ADD]);
		balanced();
	}
}

static struct airoha_npu_auth_rule valid_rule(void)
{
	return (struct airoha_npu_auth_rule) {
		.raw = { AUTH_MBOX_ABI, 7, 1, 1, 100, 4, 2, 0x1001, 19,
			 4, 6, 0x0a000001, 0, 0, 0, 0x0a000002, 0, 0, 0,
			 0x12345678, 0, 0, 0, 0, 0, 0x02000000, 0x00010200, 2 },
	};
}
static void test_auth_isolation(void)
{
	struct airoha_npu_auth_rule rule = valid_rule();
	unsigned int scenario;

	fixture();
	attach();
	session.return_path = &path;
	CHECK(airoha_ppe_npu_owner_authorize_locked(&eth, &rule, 1) == -EOPNOTSUPP);
	CHECK(!auth_calls[AUTH_MBOX_BEGIN] && !session.auth_attempted);
	CHECK(airoha_npu_owner_ready(&session, &session.txn.id) == -EACCES);
	session.auth_attempted = true;
	auth_enabled = 1;
	CHECK(!airoha_npu_owner_ready(&session, &session.txn.id));
	balanced();
	for (scenario = 0; scenario < 5; scenario++) {
		static const int fields[] = { AM_STATE_EPOCH, AM_STATE_GENERATION,
			AM_COUNT, AM_ENABLED, AM_INFLIGHT };

		fixture();
		attach();
		session.auth_attempted = true;
		auth_enabled = 1;
		bad_auth_word = fields[scenario];
		CHECK(airoha_npu_owner_ready(&session, &session.txn.id) == -ESTALE);
		balanced();
	}
	fixture();
	ppe.ct_npu_owner = &session;
	session.return_path = &path;
	session.auth_attempted = true;
	CHECK(airoha_npu_owner_ready(&session, &session.txn.id) == -EOPNOTSUPP);
	ppe.ct_pon_qualified = true;
	CHECK(airoha_npu_owner_ready(&session, &session.txn.id) == -EACCES);
	session.auth_attempted = false;
	CHECK(!airoha_ppe_npu_owner_authorize_locked(&eth, &rule, 1));
	CHECK(session.auth_count == 1 && auth_calls[AUTH_MBOX_ADD] == 1);
	CHECK(!airoha_npu_owner_ready(&session, &session.txn.id));
	balanced();
}

static void test_auth_mode_active(void)
{
	for (unsigned int mode = 0; mode < 3; ++mode) {
		for (u32 count = 0; count <= 3; ++count) {
			fixture();
			attach();
			session.diag_auth = mode != 0;
			session.diag_learn = mode == 2;
			session.auth_count = count;
			CHECK(airoha_ppe_npu_diag_active(&ppe, &session) == (count <= (mode != 0)));
			balanced();
		}
	}
}

static void auth_retained(int expected, bool attempted)
{
	CHECK(ppe.ct_npu_owner == &session && session.diag_lower == &lower);
	CHECK(lower.references == 1 && session.diag_auth && session.return_path == &path);
	CHECK(session.txn.last_error == expected && session.txn.phase == NPU_TXN_CLOSED);
	CHECK(session.auth_attempted == attempted && session.epoch_dirty == attempted);
	CHECK(!session.auth_count && !open_calls && !freed && !netdev_puts);
	CHECK(writes == (session.diag_learn ? 2u : 0u));
	CHECK(!registers[REG_PPE_PPE_FLOW_CFG(1)] && !ppe.ct_pon_qualified);
}

static void test_auth_start(unsigned int mode)
{
	static const u32 services[] = { 0, 1, 0x8000, 0xffff };
	static const u32 expected_trace[] = {
		TRACE_READY, TRACE_BINDING, AUTH_MBOX_BEGIN, AUTH_MBOX_ADD,
		AUTH_MBOX_ARM, TRACE_READY, TRACE_OPEN,
	};

	for (unsigned int index = 0; index < ARRAY_SIZE(services); ++index) {
		u32 expected_rule[32] = {
			1, 7, 1, 1, 0, 4, 2, services[index], 19,
			4, 17, 0xc0000201, 0, 0, 0, 0xc0000202, 0, 0, 0,
			0xc000c001, 0, 0, 0, 0, 0, 0x02112233,
			0x44550200u + (index << 16), 1, 0, 0, 0, 0,
		};

		fixture();
		binding_service = services[index];
		lower.dev_addr[5] += index;
		CHECK(!airoha_npu_diag_start_mode(&ppe, mode, services[index]));
		CHECK(session.diag_learn == (mode == 2));
		CHECK(session.diag_auth && session.auth_count == 1 && auth_count == 1 && auth_enabled == 1);
		CHECK(auth_calls[AUTH_MBOX_BEGIN] == 1 && auth_calls[AUTH_MBOX_ADD] == 1 &&
		      auth_calls[AUTH_MBOX_ARM] == 1 && open_calls == 1 && binding_calls == 1);
		CHECK(trace_count == ARRAY_SIZE(expected_trace));
		CHECK(!memcmp(trace, expected_trace, sizeof(expected_trace)));
		CHECK(auth_requests[AUTH_MBOX_ADD].w[AM_RULE_COUNT] == 1);
		CHECK(!memcmp(auth_requests[AUTH_MBOX_ADD].w + AM_RULE, expected_rule, sizeof(expected_rule)));
		CHECK(session.auth_attempted && session.epoch_dirty && ring.observation_enabled);
		CHECK(writes == (mode == 2 ? 2u : 0u));
		CHECK(!ppe.ct_pon_qualified && !registers[REG_PPE_PPE_FLOW_CFG(1)]);
		CHECK(airoha_ppe_npu_diag_active(&ppe, &session));
		CHECK(!airoha_npu_owner_ready(&session, &session.txn.id));
		CHECK(airoha_npu_diag_authorize(&session, services[index]) == -EINVAL);
		CHECK(!airoha_npu_diag_close(&ppe, true));
		CHECK(!ppe.ct_npu_owner && freed == 1 && netdev_puts == 1);
		balanced();
	}
}

static void test_auth_admission(void)
{
	static const u32 invalid_services[] = { 0x10000, 0x80000000, UINT32_MAX };
	static const u32 services[] = { 0, 1, 0x8000, 0xffff };

	for (unsigned int mode = 0; mode < 3; ++mode) {
		for (unsigned int index = 0; index < ARRAY_SIZE(invalid_services); ++index) {
			fixture();
			CHECK(airoha_npu_diag_start_mode(&ppe, mode, invalid_services[index]) == -EINVAL);
			CHECK(!claim_calls && !binding_calls && !auth_calls[AUTH_MBOX_BEGIN] && !open_calls);
			CHECK(!ppe.ct_npu_owner && !lower.references && !netdev_puts && !writes);
			balanced();
		}
	}
	for (unsigned int mode = 1; mode < 3; ++mode) {
		for (unsigned int index = 0; index < ARRAY_SIZE(services); ++index) {
			for (unsigned int high = 0; high < 2; ++high) {
				fixture();
				binding_service = services[index] ^ (high ? 0x8000u : 1u);
				CHECK(airoha_npu_diag_start_mode(&ppe, mode, services[index]) == -ESTALE);
				auth_retained(-ESTALE, false);
				CHECK(session.diag_learn == (mode == 2));
				CHECK(binding_calls == 1 && !auth_calls[AUTH_MBOX_BEGIN] && !auth_calls[AUTH_MBOX_ADD]);
				balanced();
			}
		}
	}
	for (unsigned int scenario = 0; scenario < 9; ++scenario) {
		u32 service = 0x1001;

		fixture();
		attach();
		session.diag_auth = true;
		session.return_path = &path;
		switch (scenario) {
		case 0: session.diag_auth = false; break;
		case 1: gdm.pon_link_ops = &other_controller; break;
		case 2: session.txn.phase = NPU_TXN_OPEN; break;
		case 3: session.auth_attempted = true; break;
		case 4: service = 0x10000; break;
		case 5: session.return_path = NULL; break;
		case 6: lower.dev_addr[0] = 1; break;
		case 7: memset(lower.dev_addr, 0, ETH_ALEN); break;
		default: session.auth_count = 2; break;
		}
		CHECK(airoha_npu_diag_authorize(&session, service) == -EINVAL);
		CHECK(!binding_calls && !auth_calls[AUTH_MBOX_BEGIN] && !open_calls);
		CHECK(ppe.ct_npu_owner == &session && !freed && !netdev_puts);
		balanced();
	}
	for (unsigned int mode = 0; mode < 3; ++mode) {
		struct airoha_npu_auth_rule rule = valid_rule();

		fixture();
		attach();
		session.diag_auth = mode != 0;
		session.diag_learn = mode == 2;
		session.return_path = &path;
		CHECK(airoha_ppe_npu_owner_authorize_locked(&eth, &rule, 1) == -EOPNOTSUPP);
		CHECK(!binding_calls && !auth_calls[AUTH_MBOX_BEGIN] && !session.auth_attempted);
		balanced();
	}
}

static void test_auth_failures(unsigned int mode)
{
	static const int fields[] = {
		AM_MAGIC, AM_ABI_OP, AM_BYTES, AM_EPOCH, AM_GENERATION, AM_RULE_COUNT,
		AM_RULE, AM_RULE + 31, AM_STATUS, AM_CAPS, AM_STATE_EPOCH,
		AM_STATE_GENERATION, AM_COUNT, AM_INFLIGHT, AM_ENABLED, AM_RESERVED2,
	};

	for (int operation = AUTH_MBOX_BEGIN; operation <= AUTH_MBOX_ARM; ++operation) {
		fixture();
		fail_auth_op = operation;
		CHECK(airoha_npu_diag_start_mode(&ppe, mode, binding_service) == -ETIMEDOUT);
		auth_retained(-ETIMEDOUT, true);
		CHECK(session.diag_learn == (mode == 2));
		CHECK(auth_calls[operation] == 1);
		if (operation < AUTH_MBOX_ARM)
			CHECK(!auth_calls[operation + 1]);
		balanced();
		for (unsigned int index = 0; index < ARRAY_SIZE(fields); ++index) {
			fixture();
			bad_auth_op = operation;
			bad_auth_word = fields[index];
			CHECK(airoha_npu_diag_start_mode(&ppe, mode, binding_service) == -EPROTO);
			auth_retained(-EPROTO, true);
			CHECK(session.diag_learn == (mode == 2));
			CHECK(auth_calls[operation] == 1);
			if (operation < AUTH_MBOX_ARM)
				CHECK(!auth_calls[operation + 1]);
			balanced();
		}
	}
	fixture();
	fail_auth_status_op = AUTH_MBOX_ADD;
	CHECK(airoha_npu_diag_start_mode(&ppe, mode, binding_service) == -EPROTO);
	auth_retained(-EPROTO, true);
	CHECK(auth_calls[AUTH_MBOX_ADD] == 1 && !auth_calls[AUTH_MBOX_ARM]);
	balanced();
	fixture();
	fail_ready_after_auth = true;
	CHECK(airoha_npu_diag_start_mode(&ppe, mode, binding_service) == -ESTALE);
	auth_retained(-ESTALE, true);
	CHECK(ready_calls == 2 && auth_calls[AUTH_MBOX_ARM] == 1);
	balanced();
}

static void test_auth_bank1(void)
{
	for (unsigned int scenario = 0; scenario < 4; ++scenario) {
		fixture();
		CHECK(!airoha_npu_diag_start_mode(&ppe, true, binding_service));
		eth.ct_bank1_routes.owner = &session;
		eth.ct_bank1_routes.ready = eth.ct_bank1_routes.ingress_ready = true;
		if (scenario == 1)
			registers[3] = 1;
		if (scenario == 2)
			registers[4] = 1;
		if (scenario == 3)
			registers[5] |= PPE_GLO_CFG_BUSY_MASK;
		CHECK(airoha_npu_owner_bank1_restore(&session, &session.txn.id) == (scenario ? -EIO : 0));
		CHECK(airoha_bank1_routes_open(&eth, &session) == (scenario ? -EIO : 0));
		CHECK(!writes && eth.ct_bank1_routes.pon_open == !scenario);
		balanced();
	}
}
static void prepare_close(void)
{
	fixture();
	attach();
	session.return_path = &path;
	path.ring = &ring;
	ring.packets = 3;
	ring.observation.frame_bytes = 2;
	ring.observation.frame[0] = 0xaa;
	eth.ct_bank1_routes.owner = &session;
}
static void test_release(void)
{
	unsigned int scenario;

	fixture();
	CHECK(!airoha_npu_diag_close(&ppe, true));
	CHECK(!close_calls);
	balanced();
	fixture();
	ppe.ct_npu_owner = &session;
	CHECK(airoha_npu_diag_close(&ppe, true) == -EBUSY);
	balanced();
	prepare_close();
	CHECK(!airoha_npu_diag_close(&ppe, false));
	CHECK(ppe.ct_npu_owner == &session && !netdev_puts && !writes && !freed);
	CHECK(session.diag_stats.packets == 3 && session.diag_observation.frame[0] == 0xaa);
	balanced();
	prepare_close();
	CHECK(!airoha_npu_diag_close(&ppe, true));
	CHECK(!ppe.ct_npu_owner && freed == 1 && netdev_puts == 1 && cancels == 1);
	CHECK(registers[3] == session.bank1_flow && registers[4] == session.bank1_tb);
	balanced();
	for (scenario = 0; scenario < 13; scenario++) {
		int expected = -EBUSY;

		prepare_close();
		closed_postconditions = false;
		session.return_path = NULL;
		switch (scenario) {
		case 0: close_error = -ETIMEDOUT; expected = -ETIMEDOUT; break;
		case 1: session.return_path = &path; break;
		case 2: session.closed_ack = false; break;
		case 3: session.bank1_saved = false; break;
		case 4: session.bank1_host_retired = false; break;
		case 5: session.bank1_next_row--; break;
		case 6: session.ingress.saved_valid = true; break;
		case 7: session.ingress.dirty = true; break;
		case 8: session.ingress.active = true; break;
		case 9: session.ingress.pending = true; break;
		case 10: release_error = -EIO; expected = -EIO; break;
		case 11: fail_write = REG_PPE_TB_CFG(1); expected = -EIO; break;
		default: fail_write = REG_PPE_PPE_FLOW_CFG(1); expected = -EIO; break;
		}
		CHECK(airoha_npu_diag_close(&ppe, true) == expected);
		CHECK(ppe.ct_npu_owner == &session && !freed && !netdev_puts && !cancels);
		if (scenario == 11)
			CHECK(writes == 1 && !registers[3]);
		if (scenario >= 11) {
			fail_write = -1;
			CHECK(!airoha_npu_diag_close(&ppe, true));
			CHECK(freed == 1 && netdev_puts == 1 && cancels == 1);
		}
		balanced();
	}
	prepare_close();
	fe_error = -EAGAIN;
	CHECK(airoha_npu_diag_close(&ppe, true) == -EAGAIN);
	CHECK(ppe.ct_npu_owner == &session && !freed && !netdev_puts && !cancels);
	fe_error = 0;
	CHECK(!airoha_npu_diag_close(&ppe, true));
	CHECK(freed == 1 && netdev_puts == 1);
	balanced();
}
static void prepare_open(void)
{
	fixture();
	attach();
	session.auth_attempted = true;
	eth.ct_bank1_routes.owner = &session;
	eth.ct_bank1_routes.ready = eth.ct_bank1_routes.ingress_ready = true;
}
static void test_bank1(void)
{
	unsigned int scenario;

	prepare_open();
	CHECK(!airoha_npu_owner_bank1_restore(&session, &session.txn.id));
	CHECK(!writes && !registers[3]);
	CHECK(!airoha_bank1_routes_open(&eth, &session));
	CHECK(eth.ct_bank1_routes.pon_open && !writes && !registers[3]);
	balanced();
	for (scenario = 0; scenario < 6; scenario++) {
		prepare_open();
		switch (scenario) {
		case 0: registers[3] = 1; break;
		case 1: registers[4] = 1; break;
		case 2: registers[5] = 0; break;
		case 3: registers[5] |= PPE_GLO_CFG_BUSY_MASK; break;
		case 4: session.bank1_next_row--; break;
		case 5: state_error = -ESTALE; break;
		}
		CHECK(airoha_npu_owner_bank1_restore(&session, &session.txn.id) ==
		      (scenario == 5 ? -ESTALE : -EIO));
		CHECK(!writes);
		if (scenario < 4) {
			CHECK(airoha_bank1_routes_open(&eth, &session) == -EIO);
			CHECK(!restores && !eth.ct_bank1_routes.pon_open);
		}
		balanced();
	}
	prepare_open();
	route_write_error = -EIO;
	CHECK(airoha_bank1_routes_open(&eth, &session) == -EIO);
	CHECK(!eth.ct_bank1_routes.pon_open);
	balanced();
	prepare_open();
	scope_error = -EIO;
	CHECK(airoha_bank1_routes_open(&eth, &session) == -EIO);
	CHECK(!eth.ct_bank1_routes.pon_open);
	balanced();
	fixture();
	ppe.ct_npu_owner = &session;
	ppe.ct_pon_qualified = true;
	session.auth_attempted = true;
	session.auth_count = 1;
	CHECK(!airoha_npu_owner_bank1_restore(&session, &session.txn.id));
	CHECK(writes == 2 && registers[3] == session.bank1_flow && registers[4] == session.bank1_tb);
	balanced();
}
static void test_learning_flow(void)
{
	for (unsigned int flags = 0; flags < 4; ++flags) {
		fixture();
		attach();
		session.diag_auth = flags & 1;
		session.diag_learn = flags & 2;
		CHECK(airoha_ppe_npu_diag_flow(&ppe, &session) == (flags == 3 ? BIT(13) : 0));
		CHECK(!writes);
		balanced();
	}
	for (unsigned int scenario = 0; scenario < 8; ++scenario) {
		const void *token = &session;

		fixture();
		attach();
		session.diag_auth = session.diag_learn = true;
		switch (scenario) {
		case 0: ppe.ct_npu_owner = NULL; lower.references = 0; break;
		case 1: token = &path; break;
		case 2: token = NULL; break;
		case 3: session.auth_count = 2; break;
		case 4: session.retiring = true; break;
		case 5: ppe.ct_pon_qualified = true; break;
		case 6: gdm.pon_link_ops = &other_controller; break;
		default: nodes[ETH_NODE].diagnostic = false; break;
		}
		CHECK(!airoha_ppe_npu_diag_flow(&ppe, token));
		CHECK(!writes);
		balanced();
	}
}

static void test_invalid_modes(void)
{
	static const unsigned int modes[] = { 3, 256, 0x10000, UINT32_MAX };
	static const u32 services[] = { 0, 1, 0x8000, 0xffff };

	for (unsigned int mode = 0; mode < ARRAY_SIZE(modes); ++mode) {
		for (unsigned int service = 0; service < ARRAY_SIZE(services); ++service) {
			fixture();
			CHECK(airoha_npu_diag_start_mode(&ppe, modes[mode], services[service]) == -EINVAL);
			CHECK(!claim_calls && !binding_calls && !auth_calls[AUTH_MBOX_BEGIN] && !open_calls);
			CHECK(!ppe.ct_npu_owner && !lower.references && !netdev_puts && !writes);
			balanced();
		}
	}
}

static void prepare_learning_start(void)
{
	fixture();
	eth.ct_bank1_routes.owner = &session;
	eth.ct_bank1_routes.ready = eth.ct_bank1_routes.ingress_ready = true;
	registers[REG_PPE_TB_CFG(1)] = 0xa5a5002bu;
	open_runs_bank1 = trace_mmio = true;
}

static void prepare_learning_restore(void)
{
	prepare_open();
	session.diag_auth = session.diag_learn = session.bank0_saved = true;
	session.bank0_host_retired = true;
	session.auth_count = 1;
	session.bank0_flow = registers[REG_PPE_PPE_FLOW_CFG(0)];
	session.bank0_tb = registers[REG_PPE_TB_CFG(0)];
	session.bank0_next_row = PPE_SRAM_NUM_ENTRIES;
	registers[REG_PPE_PPE_FLOW_CFG(0)] = 0;
	registers[REG_PPE_TB_CFG(0)] = 0xabc022;
	trace_mmio = true;
}

static void check_learning_writes(unsigned int expected_writes, unsigned int preceding)
{
	unsigned int first = 0, skipped = 0;

	CHECK(writes == expected_writes + preceding);
	while (first < mmio_count) {
		if (mmio_events[first].write && skipped++ == preceding)
			break;
		first++;
	}
	CHECK(first >= 3 && first + expected_writes * 2 <= mmio_count);
	CHECK(mmio_events[first - 3].reg == REG_PPE_GLO_CFG(0));
	CHECK(mmio_events[first - 2].reg == REG_PPE_TB_CFG(0));
	CHECK(mmio_events[first - 1].reg == REG_PPE_PPE_FLOW_CFG(0));
	for (unsigned int index = first - 3; index < first; ++index) {
		CHECK(!mmio_events[index].write);
		CHECK(mmio_events[index].next_row == PPE_SRAM_NUM_ENTRIES);
	}
	for (unsigned int index = 0; index < expected_writes; ++index) {
		struct mmio_event *write = &mmio_events[first + index * 2];
		struct mmio_event *readback = write + 1;
		unsigned int reg = index ? REG_PPE_PPE_FLOW_CFG(0) : REG_PPE_TB_CFG(0);

		CHECK(write->write && !readback->write);
		CHECK(write->reg == reg && readback->reg == reg);
		CHECK(write->value == (index ? BIT(13) : 0xabc032u));
		CHECK(write->next_row == 0 && readback->next_row == 0);
		CHECK(write->locked == 1 && readback->locked == 1);
		if (index + 1 < expected_writes)
			CHECK(write->value == readback->value);
	}
}

static void test_learning_start(void)
{
	static const u32 services[] = { 0, 1, 0x8000, 0xffff };

	for (unsigned int mode = 0; mode < 3; ++mode) {
		for (unsigned int index = 0; index < ARRAY_SIZE(services); ++index) {
			prepare_learning_start();
			binding_service = services[index];
			CHECK(!airoha_npu_diag_start_mode(&ppe, mode, binding_service));
			CHECK(session.diag_auth == (mode != 0) && session.diag_learn == (mode == 2));
			CHECK(session.auth_count == (mode != 0) && auth_enabled == 1);
			CHECK(binding_calls == (mode != 0) && auth_calls[AUTH_MBOX_ADD] == (mode != 0));
			CHECK(auth_calls[AUTH_MBOX_BEGIN] == 1 && auth_calls[AUTH_MBOX_ARM] == 1);
			CHECK(open_calls == 1 && restores == 1 && scope_calls == 1);
			CHECK(eth.ct_bank1_routes.pon_open && !ppe.ct_pon_qualified);
			CHECK(!registers[REG_PPE_PPE_FLOW_CFG(1)]);
			CHECK(registers[REG_PPE_TB_CFG(1)] == 0xa5a5002bu);
			CHECK(session.bank1_next_row == PPE_SRAM_NUM_ENTRIES);
			CHECK(session.diag_service == binding_service);
			if (mode == 2) {
				CHECK(session.bank0_saved && !session.bank0_next_row && clear_calls[0] == 1);
				CHECK(session.bank0_flow == 0xabc001 && session.bank0_tb == 0xabc002);
				CHECK(registers[REG_PPE_PPE_FLOW_CFG(0)] == BIT(13));
				CHECK(registers[REG_PPE_TB_CFG(0)] == 0xabc032);
				check_learning_writes(2, 2);
			} else
				CHECK(!writes);
			balanced();
		}
	}
}

static void test_learning_preconditions(void)
{
	for (unsigned int scenario = 0; scenario < 14; ++scenario) {
		u32 initial_row;

		prepare_learning_restore();
		switch (scenario) {
		case 0: registers[REG_PPE_PPE_FLOW_CFG(1)] = BIT(14); break;
		case 1: registers[REG_PPE_TB_CFG(1)] = FIELD_PREP(PPE_TB_CFG_SEARCH_MISS_MASK, 3); break;
		case 2: registers[REG_PPE_GLO_CFG(1)] = 0; break;
		case 3: registers[REG_PPE_GLO_CFG(1)] |= PPE_GLO_CFG_BUSY_MASK; break;
		case 4: session.bank1_next_row = 0; break;
		case 5: session.bank1_next_row = PPE_SRAM_NUM_ENTRIES - 1; break;
		case 6: state_error = -ESTALE; break;
		case 7: session.bank0_saved = false; break;
		case 8: session.bank0_next_row = 0; break;
		case 9: session.bank0_next_row--; break;
		case 10: registers[REG_PPE_GLO_CFG(0)] = 0; break;
		case 11: registers[REG_PPE_GLO_CFG(0)] |= PPE_GLO_CFG_BUSY_MASK; break;
		case 12: registers[REG_PPE_PPE_FLOW_CFG(0)] = BIT(14); break;
		case 13: registers[REG_PPE_TB_CFG(0)] = FIELD_PREP(PPE_TB_CFG_SEARCH_MISS_MASK, 3); break;
		}
		initial_row = session.bank1_next_row;
		CHECK(airoha_npu_owner_bank1_restore(&session, &session.txn.id) ==
		      (scenario == 6 ? -ESTALE : -EIO));
		CHECK(!writes && session.bank1_next_row == initial_row);
		CHECK(!eth.ct_bank1_routes.pon_open && !scope_calls && !restores);
		session.bank0_saved = true;
		balanced();
	}
}

static void test_learning_failures(void)
{
	for (unsigned int scenario = 0; scenario < 7; ++scenario) {
		unsigned int expected_writes = scenario == 0 || scenario == 2 || scenario == 4 ? 1 : 2;
		int expected_error = scenario == 6 ? -ESTALE : -EIO;

		prepare_learning_restore();
		switch (scenario) {
		case 0: fail_write = REG_PPE_TB_CFG(0); break;
		case 1: fail_write = REG_PPE_PPE_FLOW_CFG(0); break;
		case 2: fail_readback = REG_PPE_TB_CFG(0); break;
		case 3: fail_readback = REG_PPE_PPE_FLOW_CFG(0); break;
		case 4: fail_readback = REG_PPE_TB_CFG(0); readback_mask = BIT(4); break;
		case 5: fail_readback = REG_PPE_PPE_FLOW_CFG(0); readback_mask = BIT(13); break;
		default: fail_state_after_write = true; break;
		}
		CHECK(airoha_npu_owner_bank1_restore(&session, &session.txn.id) == expected_error);
		CHECK(session.diag_auth && session.diag_learn && session.auth_count == 1);
		CHECK(ppe.ct_npu_owner == &session);
		CHECK(lower.references == 1 && !freed && !netdev_puts);
		CHECK(session.bank0_next_row == 0 && !ppe.ct_pon_qualified);
		CHECK(session.bank1_next_row == PPE_SRAM_NUM_ENTRIES && !registers[3]);
		CHECK(!eth.ct_bank1_routes.pon_open && !scope_calls && !restores);
		check_learning_writes(expected_writes, 0);
		CHECK(readback_corrupted == (scenario >= 2 && scenario <= 5));
		CHECK(registers[REG_PPE_TB_CFG(0)] == (scenario == 0 ? 0xabc022u : 0xabc032u));
		CHECK(registers[REG_PPE_PPE_FLOW_CFG(0)] ==
		      (scenario == 3 || scenario == 5 || scenario == 6 ? BIT(13) : 0));
		trace_mmio = fail_state_after_write = false;
		fail_write = fail_readback = -1;
		CHECK(airoha_npu_diag_close(&ppe, true) == -EBUSY);
		CHECK(close_bank0_row == 0 && session.bank0_next_row == 0);
		CHECK(writes == expected_writes && !route_releases && !fe_releases);
		CHECK(ppe.ct_npu_owner == &session && !freed && !netdev_puts);
		close_clears_rows = true;
		CHECK(!airoha_npu_diag_close(&ppe, true));
		CHECK(close_entry_row == PPE_SRAM_NUM_ENTRIES && !ppe.ct_npu_owner);
		CHECK(writes == expected_writes + 8 && freed == 1 && netdev_puts == 1);
		CHECK(registers[REG_PPE_PPE_FLOW_CFG(1)] == session.bank1_flow);
		CHECK(registers[REG_PPE_TB_CFG(1)] == session.bank1_tb);
		balanced();
	}
}

static void test_learning_routes(void)
{
	static const u32 flows[] = { 0, BIT(13), BIT(13) | BIT(14), BIT(14) };

	for (unsigned int bank = 0; bank < 2; ++bank) {
		for (unsigned int mode = 0; mode < 3; ++mode) {
			for (unsigned int flow = 0; flow < ARRAY_SIZE(flows); ++flow) {
				for (u32 miss = 0; miss < 4; ++miss) {
					bool allowed = bank ? !flows[flow] && miss == 2 :
						mode != 2 || (flows[flow] == BIT(13) && miss == 3);

					prepare_learning_restore();
					session.diag_auth = mode != 0;
					session.diag_learn = mode == 2;
					session.auth_count = mode != 0;
					registers[REG_PPE_PPE_FLOW_CFG(0)] = BIT(13);
					registers[REG_PPE_TB_CFG(0)] = 0xabc032;
					registers[REG_PPE_PPE_FLOW_CFG(bank)] = flows[flow];
					registers[REG_PPE_TB_CFG(bank)] = 0xa5a5000bu |
						FIELD_PREP(PPE_TB_CFG_SEARCH_MISS_MASK, miss);
					CHECK(airoha_bank1_routes_open(&eth, &session) == (allowed ? 0 : -EIO));
					CHECK(eth.ct_bank1_routes.pon_open == allowed);
					CHECK(scope_calls == allowed && restores == allowed && !writes);
					balanced();
				}
			}
		}
	}
	for (unsigned int scenario = 0; scenario < 6; ++scenario) {
		prepare_learning_restore();
		registers[REG_PPE_PPE_FLOW_CFG(0)] = BIT(13);
		registers[REG_PPE_TB_CFG(0)] = FIELD_PREP(PPE_TB_CFG_SEARCH_MISS_MASK, 3);
		switch (scenario) {
		case 0: registers[REG_PPE_GLO_CFG(1)] = 0; break;
		case 1: registers[REG_PPE_GLO_CFG(1)] |= PPE_GLO_CFG_BUSY_MASK; break;
		case 2: scope_error = -EIO; break;
		case 3: route_write_error = -EIO; break;
		case 4: registers[REG_PPE_GLO_CFG(0)] = 0; break;
		case 5: registers[REG_PPE_GLO_CFG(0)] |= PPE_GLO_CFG_BUSY_MASK; break;
		}
		CHECK(airoha_bank1_routes_open(&eth, &session) == -EIO);
		CHECK(!eth.ct_bank1_routes.pon_open && !writes);
		CHECK(scope_calls == (scenario == 2 || scenario == 3) && restores == (scenario == 3));
		balanced();
	}
}

static void prepare_bound_install(void)
{
	prepare_learning_restore();
	session.diag_auth = session.diag_learn = session.diag_bound = true;
	session.diag_egress = &lan;
	lan.references = 1;
	session.diag_hash = expected_hash;
	session.txn.phase = NPU_TXN_PPE_RESTORE;
	session.diag_entry.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND) |
		AIROHA_FOE_IB1_BIND_STATIC | AIROHA_FOE_IB1_BIND_UDP;
	session.diag_entry.ipv4.orig_tuple.src_ip = 0xc0000201;
	session.diag_entry.ipv4.new_tuple.dest_ip = 0xc0a80178;
}

static void test_bound_install(void)
{
	for (unsigned int scenario = 0; scenario < 15; ++scenario) {
		prepare_bound_install();
		switch (scenario) {
		case 0: session.diag_bound = false; break;
		case 1: session.diag_auth = false; break;
		case 2: session.diag_learn = false; break;
		case 3: session.diag_hash = 0x2000; break;
		case 4: session.diag_hash = 0x4000; break;
		case 5: session.txn.phase = NPU_TXN_OPEN; break;
		case 6: session.bank0_next_row = 0; break;
		case 7: session.diag_entry.ib1 = 0; break;
		case 8: session.invalidated = true; break;
		case 9: lan.running = false; break;
		case 10: lan.carrier = false; break;
		case 11: lan_port.id = 3; break;
		case 12: lan_gdm.nbq = 1; break;
		case 13: valid_lan = false; break;
		case 14: session.bank0_saved = false; break;
		}
		CHECK(airoha_npu_diag_install(&session) < 0);
		CHECK(!sram_reads && !sram_commits && !writes);
		session.bank0_saved = true;
		balanced();
	}
	for (unsigned int scenario = 0; scenario < 9; ++scenario) {
		prepare_bound_install();
		switch (scenario) {
		case 0: fail_sram_read = 1; break;
		case 1: bad_sram_ack = 1; break;
		case 2: hardware_entry.data[79] = 1; break;
		case 3: fail_commit = -ETIMEDOUT; break;
		case 4: fail_commit = -ETIMEDOUT; commit_takes_effect = true; break;
		case 5: bad_sram_ack = 2; break;
		case 6: fail_sram_read = 2; break;
		case 7: bad_sram_ack = 3; break;
		case 8: corrupt_sram_read = 2; corrupt_sram_byte = 79; break;
		}
		CHECK(airoha_npu_diag_install(&session) < 0);
		CHECK(sram_commits == (scenario >= 3));
		CHECK(session.bank0_next_row == (scenario >= 3 ? 0 : PPE_SRAM_NUM_ENTRIES));
		CHECK(session.bank1_next_row == PPE_SRAM_NUM_ENTRIES);
		CHECK(ppe.ct_npu_owner == &session && session.diag_egress == &lan);
		CHECK(!writes && !open_calls && !scope_calls);
		balanced();
	}
	for (unsigned int byte = 0; byte < sizeof(hardware_entry); ++byte) {
		prepare_bound_install();
		corrupt_sram_read = 2;
		corrupt_sram_byte = byte;
		CHECK(airoha_npu_diag_install(&session) == -EIO);
		CHECK(session.bank0_next_row == 0 && sram_commits == 1);
		balanced();
	}
	for (unsigned int operation = 1; operation <= 3; ++operation) {
		static const u32 masks[] = {
			PPE_SRAM_CTRL_ACK_MASK, PPE_SRAM_CTRL_WR_MASK,
			PPE_SRAM_CTRL_REQ_MASK, BIT(8), BIT(23),
		};
		for (unsigned int index = 0; index < ARRAY_SIZE(masks); ++index) {
			prepare_bound_install();
			bad_sram_ack = operation;
			bad_sram_mask = masks[index];
			CHECK(airoha_npu_diag_install(&session) == -EIO);
			CHECK(sram_sequence == operation);
			CHECK(session.bank0_next_row == (operation == 1 ? PPE_SRAM_NUM_ENTRIES : 0));
			CHECK(session.bank1_next_row == PPE_SRAM_NUM_ENTRIES && !writes);
			balanced();
		}
	}
	prepare_bound_install();
	CHECK(!airoha_npu_diag_install(&session));
	CHECK(sram_sequence == 3 && sram_reads == 2 && sram_commits == 1);
	CHECK(sram_events[0].cursor == PPE_SRAM_NUM_ENTRIES &&
	      !sram_events[1].cursor && !sram_events[2].cursor);
	CHECK(!memcmp(&hardware_entry, &session.diag_entry, sizeof(hardware_entry)));
	CHECK(session.bank0_next_row == 0 && session.bank1_next_row == PPE_SRAM_NUM_ENTRIES);
	balanced();
}

static void prepare_bound_learned(void)
{
	prepare_learning_restore();
	session.diag_auth = session.diag_learn = true;
	session.diag_service = binding_service;
	session.txn.phase = NPU_TXN_OPEN;
	session.bank0_next_row = 0;
	session.return_path = &path;
	path.ring = &ring;
	session.auth_count = 1;
	registers[REG_PPE_PPE_FLOW_CFG(0)] = BIT(13);
	registers[REG_PPE_TB_CFG(0)] = 0xabc032;
	close_clears_rows = open_runs_bank1 = true;
	hardware_entry.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_UNBIND) |
		AIROHA_FOE_IB1_BIND_UDP;
	hardware_entry.ipv4.orig_tuple = (struct airoha_foe_ipv4_tuple) {
		.src_ip = 0xc0000201, .dest_ip = 0xc0000202,
		.src_port = 49152, .dest_port = 49153,
	};
}

static void test_bound_lifecycle(void)
{
	const u8 destination_mac[ETH_ALEN] = { 0, 0xe0, 0x4c, 0x68, 0, 0x30 };
	static const u32 expected_trace[] = {
		TRACE_SRAM_READ, TRACE_CLOSE, TRACE_PREPARE,
		TRACE_BINDING, AUTH_MBOX_BEGIN, AUTH_MBOX_ADD, AUTH_MBOX_ARM,
		TRACE_READY, TRACE_OPEN, TRACE_SRAM_READ, TRACE_SRAM_WRITE, TRACE_SRAM_READ,
	};

	for (unsigned int scenario = 0; scenario < 12; ++scenario) {
		prepare_bound_learned();
		switch (scenario) {
		case 0: session.diag_learn = false; break;
		case 1: have_lan = false; break;
		case 2: lan.carrier = false; break;
		case 3: lan.dev.parent = NULL; break;
		case 4: hardware_entry.ib1 &= ~AIROHA_FOE_IB1_BIND_STATE; break;
		case 5: hardware_entry.ipv4.orig_tuple.src_ip++; break;
		case 6: hardware_entry.ipv4.orig_tuple.dest_ip++; break;
		case 7: hardware_entry.ipv4.orig_tuple.src_port++; break;
		case 8: hardware_entry.ipv4.orig_tuple.dest_port++; break;
		case 9: hardware_entry.ib1 ^= AIROHA_FOE_IB1_BIND_UDP; break;
		case 10: fail_sram_read = 1; break;
		case 11: bad_sram_ack = 1; break;
		}
		CHECK(airoha_npu_diag_bind(&ppe, expected_hash, htonl(0xc0a80178), destination_mac) < 0);
		CHECK(!close_calls && !sram_commits && !open_calls && !lan.references);
		balanced();
	}
	prepare_bound_learned();
	CHECK(!airoha_npu_diag_bind(&ppe, expected_hash, htonl(0xc0a80178), destination_mac));
	CHECK(session.diag_bound && session.diag_egress == &lan && lan.references == 1);
	CHECK(close_calls == 1 && open_calls == 1 && sram_reads == 3 && sram_commits == 1);
	CHECK(session.txn.phase == NPU_TXN_OPEN && session.bank0_next_row == 0);
	CHECK(session.bank1_next_row == PPE_SRAM_NUM_ENTRIES && !registers[3]);
	CHECK(FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, registers[4]) == 2);
	CHECK(hardware_entry.ipv4.orig_tuple.src_ip == 0xc0000201 &&
	      hardware_entry.ipv4.orig_tuple.dest_ip == 0xc0000202 &&
	      hardware_entry.ipv4.new_tuple.src_ip == 0xc0000201 &&
	      hardware_entry.ipv4.new_tuple.dest_ip == 0xc0a80178);
	CHECK(hardware_entry.ipv4.new_tuple.src_port == 49152 &&
	      hardware_entry.ipv4.new_tuple.dest_port == 49153);
	CHECK(hardware_entry.ib1 & AIROHA_FOE_IB1_BIND_STATIC);
	CHECK(!memcmp(prepared_data.eth.h_dest, destination_mac, ETH_ALEN));
	CHECK(!memcmp(prepared_data.eth.h_source, lan.dev_addr, ETH_ALEN));
	CHECK(trace_count == ARRAY_SIZE(expected_trace));
	CHECK(!memcmp(trace, expected_trace, sizeof(expected_trace)));
	CHECK(airoha_npu_diag_bind(&ppe, expected_hash, htonl(0xc0a80178), destination_mac) == -EBUSY);
	close_clears_rows = true;
	CHECK(!airoha_npu_diag_close(&ppe, true));
	CHECK(!ppe.ct_npu_owner && freed == 1 && lan_puts == 1 && netdev_puts == 2);
	balanced();
}

static void test_bound_failures(void)
{
	const u8 destination_mac[ETH_ALEN] = { 0, 0xe0, 0x4c, 0x68, 0, 0x30 };

	for (unsigned int scenario = 0; scenario < 11; ++scenario) {
		int expected = -EIO;

		prepare_bound_learned();
		switch (scenario) {
		case 0: entry_prepare_error = expected = -EOPNOTSUPP; break;
		case 1: close_error = -EIO; break;
		case 2: prepare_error = expected = -ENOMEM; break;
		case 3: binding_valid = false; expected = -ESTALE; break;
		case 4: fail_auth_op = AUTH_MBOX_ADD; expected = -ETIMEDOUT; break;
		case 5: open_error = -EIO; break;
		case 6: fail_sram_read = 2; expected = -ETIMEDOUT; break;
		case 7: fail_commit = expected = -ETIMEDOUT; commit_takes_effect = true; break;
		case 8: corrupt_sram_read = 3; corrupt_sram_byte = 79; break;
		case 9: bad_sram_ack = 3; break;
		case 10: bad_sram_ack = 4; break;
		}
		CHECK(airoha_npu_diag_bind(&ppe, expected_hash, htonl(0xc0a80178), destination_mac) == expected);
		CHECK(session.diag_bound == (scenario >= 2));
		CHECK(lan.references == (scenario >= 2) && lan_puts == (scenario < 2));
		CHECK(ppe.ct_npu_owner == &session && lower.references == 1 && !freed);
		CHECK(!scope_calls && !restores && !eth.ct_bank1_routes.pon_open);
		CHECK(!registers[3] && FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, registers[4]) == 2);
		if (scenario >= 2)
			CHECK(session.txn.last_error == expected);
		if (scenario >= 7)
			CHECK(session.bank0_next_row == 0 && sram_commits == 1);
		trace_mmio = false;
		close_error = 0;
		close_clears_rows = true;
		CHECK(!airoha_npu_diag_close(&ppe, true));
		CHECK(!ppe.ct_npu_owner && freed == 1 && lan_puts == 1 && netdev_puts == 2);
		CHECK(registers[3] == session.bank1_flow && registers[4] == session.bank1_tb);
		balanced();
	}
}

static void test_bound_commands(void)
{
	static const char * const invalid[] = {
		"", "1112", "1112 192.168.1.120", "1112 192.168.1.120x 00:e0:4c:68:00:30",
		"1112 192.168.1.120 00:e0:4c:68:00:30x", "1112 192.168.1.120 01:e0:4c:68:00:30",
		"1112 192.168.1.120 00:00:00:00:00:00", "1112 127.0.0.1 00:e0:4c:68:00:30",
		"1112 224.0.0.1 00:e0:4c:68:00:30", "8192 192.168.1.120 00:e0:4c:68:00:30",
		"16384 192.168.1.120 00:e0:4c:68:00:30", "1112 192.168.1.120 00:e0:4c:68:00:30 extra",
		"-1 192.168.1.120 00:e0:4c:68:00:30", "4294967296 192.168.1.120 00:e0:4c:68:00:30",
		"1112 0.1.2.3 00:e0:4c:68:00:30", "1112 255.255.255.255 00:e0:4c:68:00:30",
		"1112  192.168.1.120 00:e0:4c:68:00:30", "1112 192.168.1.120 00:e0:4c:68:00:gg",
	};
	for (unsigned int index = 0; index < ARRAY_SIZE(invalid); ++index) {
		char command[96];
		prepare_bound_learned();
		strcpy(command, invalid[index]);
		CHECK(airoha_npu_diag_bind_command(&ppe, command) == -EINVAL);
		CHECK(!sram_reads && !sram_commits && !close_calls && !lan.references);
		balanced();
	}
	for (unsigned int index = 0; index < 3; ++index) {
		static const u32 hashes[] = { 0, 0x458, PPE_SRAM_NUM_ENTRIES - 1 };
		char command[96];

		prepare_bound_learned();
		expected_hash = hashes[index];
		snprintf(command, sizeof(command), "0x%x 192.168.1.120 00:e0:4c:68:00:30", expected_hash);
		CHECK(!airoha_npu_diag_bind_command(&ppe, command));
		CHECK(session.diag_bound && session.diag_hash == expected_hash);
		CHECK(session.bank0_next_row == 0 && session.bank1_next_row == PPE_SRAM_NUM_ENTRIES);
		close_clears_rows = true;
		CHECK(!airoha_npu_diag_close(&ppe, true));
		balanced();
	}
}

static void test_bank0_drain_failures(void)
{
	for (unsigned int scenario = 0; scenario < 7; ++scenario) {
		int expected = scenario == 2 || scenario == 4 ? -ETIMEDOUT : -EIO;

		fixture();
		switch (scenario) {
		case 0: fail_write = REG_PPE_PPE_FLOW_CFG(0); break;
		case 1: fail_write = REG_PPE_TB_CFG(0); break;
		case 2: registers[REG_PPE_GLO_CFG(0)] |= PPE_GLO_CFG_BUSY_MASK; break;
		case 3: registers[REG_PPE_GLO_CFG(0)] &= ~PPE_GLO_CFG_EN_MASK; break;
		case 4: clear_error[0] = -ETIMEDOUT; break;
		case 5: fail_readback = REG_PPE_PPE_FLOW_CFG(0); break;
		case 6: fail_readback = REG_PPE_TB_CFG(0); readback_mask = BIT(4); break;
		}
		CHECK(airoha_npu_diag_start_mode(&ppe, 2, binding_service) == expected);
		CHECK(session.txn.last_error == expected && ppe.ct_npu_owner == &session);
		CHECK(session.bank0_saved && session.bank0_flow == 0xabc001 && session.bank0_tb == 0xabc002);
		CHECK(session.bank0_next_row == (scenario == 4 ? 17u : 0u));
		CHECK(clear_calls[0] == (scenario == 4) && !clear_calls[1]);
		CHECK(!session.return_path && !binding_calls && !open_calls && !auth_enabled);
		CHECK(writes == 2 && !freed && !netdev_puts);
		CHECK(!registers[3] && FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, registers[4]) == 2);
		fail_write = fail_readback = -1;
		clear_error[0] = 0;
		registers[REG_PPE_GLO_CFG(0)] = 0xabc001;
		close_clears_rows = true;
		CHECK(!airoha_npu_diag_close(&ppe, true));
		CHECK(session.bank0_next_row == PPE_SRAM_NUM_ENTRIES && !ppe.ct_npu_owner);
		CHECK(registers[0] == session.bank0_flow && registers[1] == session.bank0_tb);
		CHECK(registers[3] == session.bank1_flow && registers[4] == session.bank1_tb);
		balanced();
	}
}

static void test_dualbank_drain(void)
{
	for (unsigned int scenario = 0; scenario < 6; ++scenario) {
		prepare_bound_learned();
		switch (scenario) {
		case 0: break;
		case 1: session.diag_learn = false; break;
		case 2: clear_error[0] = -ETIMEDOUT; break;
		case 3: clear_error[1] = -ETIMEDOUT; break;
		case 4: session.bank1_host_retired = false; retire_error = -EIO; break;
		case 5: session.bank0_saved = false; break;
		}
		CHECK(airoha_npu_diag_close(&ppe, false) ==
		      (scenario == 2 || scenario == 3 ? -ETIMEDOUT : scenario == 4 ? -EIO : 0));
		CHECK(clear_calls[1] == (scenario != 4) && clear_calls[0] == (scenario < 3 || scenario == 5));
		if (clear_calls[0])
			CHECK(clear_order[0] == 1 && clear_order[1] == 0);
		CHECK(!registers[3] && FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, registers[4]) == 2);
		if (scenario != 5)
			CHECK(session.bank0_flow == 0xabc001 && session.bank0_tb == 0xabc002);
		if (scenario < 2 || scenario == 5) {
			CHECK(session.bank0_next_row == PPE_SRAM_NUM_ENTRIES);
			CHECK(session.bank1_next_row == PPE_SRAM_NUM_ENTRIES);
			CHECK(!registers[0] && FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, registers[1]) == 2);
		} else {
			CHECK(!freed && !netdev_puts && ppe.ct_npu_owner == &session);
			CHECK(session.bank0_next_row == (scenario == 2 ? 17u : 0u));
			clear_error[0] = clear_error[1] = retire_error = 0;
			CHECK(!airoha_npu_diag_close(&ppe, false));
			CHECK(session.bank0_next_row == PPE_SRAM_NUM_ENTRIES);
			CHECK(session.bank1_next_row == PPE_SRAM_NUM_ENTRIES);
		}
		balanced();
	}
}

static void test_dualbank_release(void)
{
	static const unsigned int order[] = {
		REG_PPE_TB_CFG(1), REG_PPE_PPE_FLOW_CFG(1),
		REG_PPE_TB_CFG(0), REG_PPE_PPE_FLOW_CFG(0),
	};

	prepare_learning_restore();
	CHECK(!airoha_npu_diag_close(&ppe, true));
	CHECK(writes == ARRAY_SIZE(order) && freed == 1 && netdev_puts == 1);
	for (unsigned int index = 0; index < ARRAY_SIZE(order); ++index) {
		CHECK(mmio_events[index * 2].write && !mmio_events[index * 2 + 1].write);
		CHECK(mmio_events[index * 2].reg == order[index]);
		CHECK(mmio_events[index * 2 + 1].reg == order[index]);
		CHECK(mmio_events[index * 2].value == mmio_events[index * 2 + 1].value);
		CHECK(mmio_events[index * 2].locked && mmio_events[index * 2 + 1].locked);
	}
	balanced();
	for (unsigned int scenario = 0; scenario < 8; ++scenario) {
		unsigned int failed = scenario / 2;

		prepare_learning_restore();
		if (scenario & 1)
			fail_readback = order[failed];
		else
			fail_write = order[failed];
		CHECK(airoha_npu_diag_close(&ppe, true) == -EIO);
		CHECK(writes == failed + 1 && ppe.ct_npu_owner == &session);
		CHECK(!freed && !netdev_puts && !cancels && !fe_releases);
		fail_write = fail_readback = -1;
		CHECK(!airoha_npu_diag_close(&ppe, true));
		CHECK(writes == failed + 5 && freed == 1 && netdev_puts == 1);
		CHECK(registers[3] == session.bank1_flow && registers[4] == session.bank1_tb);
		balanced();
	}
	for (unsigned int bank = 0; bank < 2; ++bank) {
		prepare_learning_restore();
		session.auth_attempted = false;
		if (bank)
			session.bank1_next_row = 17;
		else
			session.bank0_next_row = 17;
		CHECK(airoha_npu_owner_retire_locked(&ppe) == -EBUSY);
		CHECK(!writes && !route_releases && !fe_releases && !freed && !netdev_puts);
		CHECK(airoha_npu_diag_close(&ppe, true) == -EBUSY);
		CHECK(!writes && !route_releases && !fe_releases && !freed && !netdev_puts);
		balanced();
	}
}

static bool bank0_owned(void)
{
	bool owned;

	spin_lock_bh(&ppe_lock);
	owned = airoha_ppe_npu_bank0_owned(&ppe);
	spin_unlock_bh(&ppe_lock);
	return owned;
}

static void test_bank0_ownership(void)
{
	for (unsigned int flags = 0; flags < 8; ++flags) {
		fixture();
		if (flags & 1)
			attach();
		session.bank0_saved = flags & 2;
		session.diag_learn = flags & 4;
		CHECK(bank0_owned() == ((flags & 1) && (flags & 6)));
		CHECK(!writes && !open_calls && !close_calls);
		balanced();
	}
	for (unsigned int flags = 1; flags < 4; ++flags) {
		for (unsigned int scenario = 0; scenario < 15; ++scenario) {
			fixture();
			attach();
			session.bank0_saved = flags & 1;
			session.diag_learn = flags & 2;
			session.diag_auth = true;
			switch (scenario) {
			case 0: lower.carrier = false; break;
			case 1: lower.running = false; break;
			case 2: gdm.pon_link_ops = &other_controller; break;
			case 3: gdm.pon_link_priv = &other_priv; break;
			case 4: session.retiring = true; break;
			case 5: nodes[ETH_NODE].diagnostic = false; break;
			case 6: session.diag_auth = false; break;
			case 7: session.invalidated = true; break;
			case 8: session.bank0_next_row = 17; break;
			case 9: session.auth_count = 2; break;
			case 10: ppe.ct_pon_qualified = true; break;
			case 11: ppe.ct_pair_policy_allowed = true; break;
			case 12: gdm.pon_update_blocked = true; break;
			case 13: session.txn.phase = NPU_TXN_PPE_RESTORE; break;
			case 14: session.txn.last_error = -ETIMEDOUT; break;
			}
			CHECK(bank0_owned());
			CHECK(!writes && !freed && !netdev_puts);
			balanced();
		}
	}
	for (unsigned int scenario = 0; scenario < 5; ++scenario) {
		prepare_bound_learned();
		lower.carrier = false;
		CHECK(!airoha_ppe_npu_diag_active(&ppe, &session) && bank0_owned());
		switch (scenario) {
		case 0: clear_error[0] = -ETIMEDOUT; break;
		case 1: clear_error[1] = -ETIMEDOUT; break;
		case 2: close_error = -EIO; break;
		case 3: release_error = -EIO; break;
		case 4: fe_error = -EAGAIN; break;
		}
		CHECK(airoha_npu_diag_close(&ppe, true) ==
		      (scenario < 2 ? -ETIMEDOUT : scenario == 4 ? -EAGAIN : -EIO));
		CHECK(bank0_owned() && ppe.ct_npu_owner == &session && !freed && !netdev_puts);
		clear_error[0] = clear_error[1] = close_error = release_error = fe_error = 0;
		trace_mmio = false;
		CHECK(!airoha_npu_diag_close(&ppe, true));
		CHECK(!bank0_owned() && !ppe.ct_npu_owner && freed == 1 && netdev_puts == 1);
		balanced();
	}
	for (unsigned int reg = 0; reg < 2; ++reg) {
		prepare_learning_restore();
		lower.carrier = false;
		session.diag_learn = false;
		fail_write = reg ? REG_PPE_PPE_FLOW_CFG(0) : REG_PPE_TB_CFG(0);
		CHECK(airoha_npu_diag_close(&ppe, true) == -EIO);
		CHECK(bank0_owned() && !airoha_ppe_npu_diag_active(&ppe, &session));
		CHECK(!freed && !netdev_puts);
		fail_write = -1;
		CHECK(!airoha_npu_diag_close(&ppe, true));
		CHECK(!bank0_owned() && !ppe.ct_npu_owner && freed == 1);
		balanced();
	}
	for (unsigned int scenario = 0; scenario < 4; ++scenario) {
		prepare_bound_install();
		switch (scenario) {
		case 0: lan.carrier = false; break;
		case 1: lan.running = false; break;
		case 2: valid_lan = false; break;
		case 3: lan_port.id = 3; break;
		}
		CHECK(!airoha_ppe_npu_diag_active(&ppe, &session) && bank0_owned());
		CHECK(!airoha_ppe_npu_diag_flow(&ppe, &session));
		CHECK(!writes && !sram_commits);
		close_clears_rows = true;
		CHECK(!airoha_npu_diag_close(&ppe, true));
		CHECK(!bank0_owned() && !ppe.ct_npu_owner && lan_puts == 1 && freed == 1);
		balanced();
	}
}

static void test_bank0_host_retirement(void)
{
	const int errors[] = { -EIO, -ENOMEM, -EINVAL };

	for (unsigned int index = 0; index < ARRAY_SIZE(errors); index++) {
		fixture();
		bank0_retire_error = errors[index];
		CHECK(airoha_npu_diag_start_mode(&ppe, 2, binding_service) == errors[index]);
		CHECK(bank0_retire_calls == 1 && !session.bank0_host_retired);
		CHECK(session.bank0_saved && bank0_owned() && !session.bank0_next_row);
		CHECK(!clear_calls[0] && !open_calls && !binding_calls && !freed);
		CHECK(session.bank0_flow == 0xabc001 && session.bank0_tb == 0xabc002);
		bank0_retire_error = 0;
		clear_error[0] = -ETIMEDOUT;
		close_clears_rows = true;
		CHECK(airoha_npu_diag_close(&ppe, true) == -ETIMEDOUT);
		CHECK(bank0_retire_calls == 2 && session.bank0_host_retired);
		CHECK(session.bank0_next_row == 17 && bank0_owned() && !freed);
		clear_error[0] = 0;
		CHECK(!airoha_npu_diag_close(&ppe, true));
		CHECK(bank0_retire_calls == 2 && session.bank0_host_retired);
		CHECK(!bank0_owned() && freed == 1 && netdev_puts == 1);
		CHECK(registers[0] == 0xabc001 && registers[1] == 0xabc002);
		balanced();
	}
	fixture();
	CHECK(!airoha_npu_diag_start_mode(&ppe, 2, binding_service));
	CHECK(bank0_retire_calls == 1 && session.bank0_host_retired);
	close_clears_rows = true;
	CHECK(!airoha_npu_diag_close(&ppe, false));
	CHECK(!airoha_npu_diag_close(&ppe, false));
	CHECK(bank0_retire_calls == 1 && bank0_owned());
	CHECK(!airoha_npu_diag_close(&ppe, true));
	CHECK(bank0_retire_calls == 1 && !bank0_owned());
	balanced();

	prepare_learning_restore();
	session.bank0_host_retired = false;
	CHECK(airoha_npu_owner_bank1_restore(&session, &session.txn.id) == -EIO);
	CHECK(!writes && !sram_commits);
	balanced();
	prepare_bound_install();
	session.bank0_host_retired = false;
	CHECK(airoha_npu_diag_install(&session) == -EINVAL);
	CHECK(!writes && !sram_reads && !sram_commits);
	balanced();
	prepare_learning_restore();
	session.bank0_host_retired = false;
	session.auth_attempted = false;
	CHECK(airoha_npu_owner_retire_locked(&ppe) == -EBUSY);
	CHECK(airoha_npu_diag_close(&ppe, true) == -EBUSY);
	CHECK(!writes && !route_releases && !fe_releases && !freed && !netdev_puts);
	balanced();
}

static void review_platform(void)
{
	unsigned int scenario, accepted = 0;

	for (scenario = 0; scenario < HOG_INVALID_COUNT; scenario++) {
		fixture();
		invalid_hog(scenario);
		accepted += airoha_npu_diag_platform(&ppe);
		balanced();
	}
	printf("{\"hog_invalid_cases\":%u,\"accepted_invalid_hogs\":%u}\n",
	       (unsigned int)HOG_INVALID_COUNT, accepted);
}
int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--review-platform")) {
		review_platform();
		return 0;
	}
	test_platform();
	test_hog_admission();
	test_active();
	test_start();
	test_auth_isolation();
	test_release();
	test_bank1();
	test_auth_mode_active();
	test_auth_start(1);
	test_auth_start(2);
	test_auth_admission();
	test_auth_failures(1);
	test_auth_failures(2);
	test_auth_bank1();
	test_learning_flow();
	test_invalid_modes();
	test_learning_start();
	test_learning_preconditions();
	test_learning_failures();
	test_learning_routes();
	test_bound_install();
	test_bound_lifecycle();
	test_bound_failures();
	test_bound_commands();
	test_bank0_drain_failures();
	test_dualbank_drain();
	test_dualbank_release();
	test_bank0_ownership();
	test_bank0_host_retirement();
	printf("{\"passed\":true,\"cases\":%u,\"checks\":%u}\n", cases, checks);
	return 0;
}
