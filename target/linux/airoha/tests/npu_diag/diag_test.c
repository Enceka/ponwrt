#include <assert.h>
#include <errno.h>
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
#define BIT(index) (1u << (index))
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define U16_MAX UINT16_MAX
#define ETH_ALEN 6
#define IPPROTO_UDP 17
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))
#define rcu_access_pointer(pointer) (pointer)
#define AIROHA_GDM2_IDX 2
#define AIROHA_DEV_F_PON 1
#define LPBK_EN_MASK 1u
#define PPE_GLO_CFG_EN_MASK 1u
#define PPE_GLO_CFG_BUSY_MASK 2u
#define PPE_TB_CFG_SEARCH_MISS_MASK 3u
#define PPE_SRAM_NUM_ENTRIES 8192u
#define FE_PSE_PORT_CDM2 5
#define REG_PPE_PPE_FLOW_CFG(bank) ((bank) * 3)
#define REG_PPE_TB_CFG(bank) ((bank) * 3 + 1)
#define REG_PPE_GLO_CFG(bank) ((bank) * 3 + 2)
#define REG_GDM_LPBK_CFG(port) (6 + (port))
#define FIELD_GET(mask, value) ((value) & (mask))
#define read_poll_timeout_atomic(operation, value, condition, delay, timeout, sleep, ...) \
	((value) = operation(__VA_ARGS__), (condition) ? 0 : -ETIMEDOUT)

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
	bool auth_attempted, epoch_dirty, diag_auth;
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
enum { TRACE_BINDING = 5, TRACE_READY, TRACE_OPEN };
static u32 trace[128], trace_count;
static struct npu_auth_message auth_requests[5];

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
	CHECK(net == &init_net && !strcmp(name, "pon0"));
	if (!have_netdev)
		return NULL;
	lower.references++;
	return &lower;
}
static void dev_put(struct net_device *dev) { CHECK(dev == &lower && --dev->references >= 0); netdev_puts++; }
static bool airoha_is_valid_gdm_dev(struct airoha_eth *actual, struct airoha_gdm_dev *dev)
{
	CHECK(actual == &eth && dev == &gdm);
	return valid_gdm;
}
static bool airoha_ct_pon_ifc_busy(struct airoha_ppe *actual) { CHECK(actual == &ppe); return ifc_busy; }
static u64 br_flow_offload_generation(void) { return 19; }
static u32 airoha_fe_rr(struct airoha_eth *actual, unsigned int reg)
{
	CHECK(actual == &eth && reg < ARRAY_SIZE(registers));
	return registers[reg];
}
static void airoha_fe_wr(struct airoha_eth *actual, unsigned int reg, u32 value)
{
	CHECK(actual == &eth && reg < ARRAY_SIZE(registers));
	CHECK(ppe_lock);
	writes++;
	if ((int)reg != fail_write)
		registers[reg] = value;
}
static int airoha_npu_owner_return_state(struct airoha_npu_owner *owner,
					const struct airoha_npu_txn_identity *id,
					enum airoha_npu_txn_phase phase)
{
	CHECK(owner == &session && id == &owner->txn.id);
	CHECK(phase >= NPU_TXN_CLOSED);
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
	if (prepare_error)
		return prepare_error;
	session.return_path = &path;
	path.ring = &ring;
	if (mismatch_controller)
		gdm.pon_link_ops = &other_controller;
	return 0;
}
static int airoha_ppe_npu_owner_open_locked(struct airoha_eth *actual)
{
	CHECK(actual == &eth && auth_enabled);
	CHECK(session.auth_count == (session.diag_auth ? 1u : 0u));
	CHECK(auth_calls[AUTH_MBOX_ADD] == (session.diag_auth ? 1u : 0u));
	CHECK(session.auth_attempted && session.epoch_dirty);
	CHECK(!registers[REG_PPE_PPE_FLOW_CFG(1)]);
	record_event(TRACE_OPEN);
	open_calls++;
	return open_error;
}
static int airoha_ppe_npu_owner_close_locked(struct airoha_eth *actual)
{
	CHECK(actual == &eth);
	close_calls++;
	if (close_error)
		return close_error;
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
static void kfree(void *owner) { CHECK(owner == &session && !ppe.ct_npu_owner && !lower.references); freed++; }
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
	return scope_error;
}
static int airoha_bank1_routes_revoke_locked(struct airoha_eth *actual)
{
	CHECK(actual == &eth && eth.ct_route_lock);
	eth.ct_bank1_routes.pon_open = false;
	return 0;
}

#include "active.inc"
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
	memset(registers, 0, sizeof(registers));
	memset(auth_calls, 0, sizeof(auth_calls));
	memset(auth_requests, 0, sizeof(auth_requests));
	memset(trace, 0, sizeof(trace));
	trace_count = binding_calls = ready_calls = 0;
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
	registers[REG_PPE_TB_CFG(1)] = 2;
	registers[REG_GDM_LPBK_CFG(2)] = LPBK_EN_MASK;
	registers[0] = 0xabc001;
	registers[1] = 0xabc002;
	registers[2] = 0xabc003;
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
	CHECK(registers[0] == 0xabc001 && registers[1] == 0xabc002 && registers[2] == 0xabc003);
	CHECK(lower.references == (ppe.ct_npu_owner && session.diag_lower ? 1 : 0));
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
	for (unsigned int mode = 0; mode < 2; ++mode) {
		for (u32 count = 0; count <= 3; ++count) {
			fixture();
			attach();
			session.diag_auth = mode;
			session.auth_count = count;
			CHECK(airoha_ppe_npu_diag_active(&ppe, &session) == (count <= mode));
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
	CHECK(!session.auth_count && !open_calls && !freed && !netdev_puts && !writes);
	CHECK(!registers[REG_PPE_PPE_FLOW_CFG(1)] && !ppe.ct_pon_qualified);
}

static void test_auth_start(void)
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
		CHECK(!airoha_npu_diag_start_mode(&ppe, true, services[index]));
		CHECK(session.diag_auth && session.auth_count == 1 && auth_count == 1 && auth_enabled == 1);
		CHECK(auth_calls[AUTH_MBOX_BEGIN] == 1 && auth_calls[AUTH_MBOX_ADD] == 1 &&
		      auth_calls[AUTH_MBOX_ARM] == 1 && open_calls == 1 && binding_calls == 1);
		CHECK(trace_count == ARRAY_SIZE(expected_trace));
		CHECK(!memcmp(trace, expected_trace, sizeof(expected_trace)));
		CHECK(auth_requests[AUTH_MBOX_ADD].w[AM_RULE_COUNT] == 1);
		CHECK(!memcmp(auth_requests[AUTH_MBOX_ADD].w + AM_RULE, expected_rule, sizeof(expected_rule)));
		CHECK(session.auth_attempted && session.epoch_dirty && !writes && ring.observation_enabled);
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

	for (unsigned int mode = 0; mode < 2; ++mode) {
		for (unsigned int index = 0; index < ARRAY_SIZE(invalid_services); ++index) {
			fixture();
			CHECK(airoha_npu_diag_start_mode(&ppe, mode, invalid_services[index]) == -EINVAL);
			CHECK(!claim_calls && !binding_calls && !auth_calls[AUTH_MBOX_BEGIN] && !open_calls);
			CHECK(!ppe.ct_npu_owner && !lower.references && !netdev_puts && !writes);
			balanced();
		}
	}
	for (unsigned int index = 0; index < ARRAY_SIZE(services); ++index) {
		for (unsigned int high = 0; high < 2; ++high) {
			fixture();
			binding_service = services[index] ^ (high ? 0x8000u : 1u);
			CHECK(airoha_npu_diag_start_mode(&ppe, true, services[index]) == -ESTALE);
			auth_retained(-ESTALE, false);
			CHECK(binding_calls == 1 && !auth_calls[AUTH_MBOX_BEGIN] && !auth_calls[AUTH_MBOX_ADD]);
			balanced();
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
	for (unsigned int mode = 0; mode < 2; ++mode) {
		struct airoha_npu_auth_rule rule = valid_rule();

		fixture();
		attach();
		session.diag_auth = mode;
		session.return_path = &path;
		CHECK(airoha_ppe_npu_owner_authorize_locked(&eth, &rule, 1) == -EOPNOTSUPP);
		CHECK(!binding_calls && !auth_calls[AUTH_MBOX_BEGIN] && !session.auth_attempted);
		balanced();
	}
}

static void test_auth_failures(void)
{
	static const int fields[] = {
		AM_MAGIC, AM_ABI_OP, AM_BYTES, AM_EPOCH, AM_GENERATION, AM_RULE_COUNT,
		AM_RULE, AM_RULE + 31, AM_STATUS, AM_CAPS, AM_STATE_EPOCH,
		AM_STATE_GENERATION, AM_COUNT, AM_INFLIGHT, AM_ENABLED, AM_RESERVED2,
	};

	for (int operation = AUTH_MBOX_BEGIN; operation <= AUTH_MBOX_ARM; ++operation) {
		fixture();
		fail_auth_op = operation;
		CHECK(airoha_npu_diag_start_mode(&ppe, true, binding_service) == -ETIMEDOUT);
		auth_retained(-ETIMEDOUT, true);
		CHECK(auth_calls[operation] == 1);
		if (operation < AUTH_MBOX_ARM)
			CHECK(!auth_calls[operation + 1]);
		balanced();
		for (unsigned int index = 0; index < ARRAY_SIZE(fields); ++index) {
			fixture();
			bad_auth_op = operation;
			bad_auth_word = fields[index];
			CHECK(airoha_npu_diag_start_mode(&ppe, true, binding_service) == -EPROTO);
			auth_retained(-EPROTO, true);
			CHECK(auth_calls[operation] == 1);
			if (operation < AUTH_MBOX_ARM)
				CHECK(!auth_calls[operation + 1]);
			balanced();
		}
	}
	fixture();
	fail_auth_status_op = AUTH_MBOX_ADD;
	CHECK(airoha_npu_diag_start_mode(&ppe, true, binding_service) == -EPROTO);
	auth_retained(-EPROTO, true);
	CHECK(auth_calls[AUTH_MBOX_ADD] == 1 && !auth_calls[AUTH_MBOX_ARM]);
	balanced();
	fixture();
	fail_ready_after_auth = true;
	CHECK(airoha_npu_diag_start_mode(&ppe, true, binding_service) == -ESTALE);
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
	test_auth_start();
	test_auth_admission();
	test_auth_failures();
	test_auth_bank1();
	printf("{\"passed\":true,\"cases\":%u,\"checks\":%u}\n", cases, checks);
	return 0;
}
