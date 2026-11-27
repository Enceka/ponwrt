#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>

#ifndef EUCLEAN
#define EUCLEAN 117
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef struct { bool held; } spinlock_t;
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define READ_ONCE(value) (value)
#define WRITE_ONCE(location, value) ((location) = (value))
#define U32_MAX UINT32_MAX
#define BIT(index) (1u << (index))
#define GENMASK(high, low) ((~0u << (low)) & (~0u >> (31 - (high))))
#define rcu_dereference(value) (value)
#define rcu_assign_pointer(location, value) ((location) = (value))
#define msecs_to_jiffies(value) (value)
#define dev_err_ratelimited(...) ((void)0)
#define FE_PSE_PORT_CDM1 0
#define FE_PSE_PORT_PPE1 4
#define FE_PSE_PORT_CDM2 5
#define FE_PSE_PORT_PPE2 8
#define FE_PSE_PORT_DROP 15
#define AIROHA_GDM1_IDX 1
#define AIROHA_GDM2_IDX 2
#define AIROHA_GDM3_IDX 3
#define AIROHA_GDM4_IDX 4
#define AIROHA_NUM_NETDEV_TX_RINGS 36
#define AIROHA_DEV_F_WAN 1
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
#define bitmap_zero(bitmap, bits) memset(bitmap, 0, (((bits) + 63) / 64) * sizeof(unsigned long))
#define __set_bit(bit, bitmap) ((bitmap)[(bit) / 64] |= 1ul << ((bit) % 64))
#define test_bit(bit, bitmap) (!!((bitmap)[(bit) / 64] & (1ul << ((bit) % 64))))
#define set_bit(bit, bitmap) __set_bit(bit, bitmap)
#define clear_bit(bit, bitmap) ((bitmap)[(bit) / 64] &= ~(1ul << ((bit) % 64)))
#define AIROHA_MAX_NUM_GDM_PORTS 4
#define REG_GDM_FWD_CFG(id) ((id) - 1)
#define REG_FE_CSR_IFC_CFG 16
#define REG_FE_IFC_PORT_EN 17
#define FE_IFC_EN_MASK BIT(0)
#define XSI_ETH_VIP_PORT_MASK BIT(24)
#define REG_PPE_GLO_CFG(bank) (32 + (bank))
#define REG_PPE_PPE_FLOW_CFG(bank) (40 + (bank))
#define PPE_GLO_CFG_EN_MASK BIT(0)
#define PPE_GLO_CFG_BUSY_MASK BIT(1)
#ifdef TEST_PON_COVERED
#define REG_PPE_TB_CFG(bank) (44 + (bank))
#define PPE_TB_CFG_SEARCH_MISS_MASK GENMASK(5, 4)
#define FIELD_GET(mask, value) (((value) & (mask)) >> __builtin_ctz(mask))
#endif
#define REG_CNTR_VAL(index) (index)
#define NETIF_F_LRO BIT(0)
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ASSERT_RTNL() CHECK(rtnl_held)
#define CT_IFC_CONTROL 48
#define CT_IFC_DATA(word) (49 + (word))
#define CT_IFC_DONE BIT(31)
#define read_poll_timeout_atomic(function, value, condition, delay, timeout, before, ...) \
	({ (void)(delay); (void)(timeout); (void)(before); \
	   (value) = function(__VA_ARGS__); (condition) ? 0 : -ETIMEDOUT; })

static unsigned int cases, selector_vectors;
static const char *current_case = "initialization";
#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "%s:%d: case %u (%s): %s\n", __FILE__, __LINE__, \
			cases, current_case, #condition); \
		abort(); \
	} \
} while (0)

#include "route_layout.inc"
#include "airoha_ct_pon_ifc_words.h"

struct airoha_eth;
struct airoha_gdm_port;
struct airoha_qdma {
	unsigned int users;
	bool lro;
	struct { int irq; } irq_banks[1];
};
struct netdev_queue { bool stopped; };
struct net_device {
	bool running;
	unsigned int features, num_tx_queues;
	int irq;
	unsigned char dev_addr[6];
	struct netdev_queue queues[AIROHA_NUM_NETDEV_TX_RINGS];
};
struct airoha_gdm_dev {
	struct airoha_qdma *qdma;
	struct airoha_eth *eth;
	struct airoha_gdm_port *port;
	struct net_device netdev;
	bool lan;
	bool use_flags;
	unsigned long flags;
	unsigned int nbq;
	struct { u32 cpu_tx_packets, fwd_tx_packets; } qos_stats[2];
};
struct airoha_gdm_port { struct airoha_gdm_dev *devs[2]; unsigned int id; };
struct airoha_soc {
	unsigned int num_ppe;
	struct { int (*get_sport)(struct airoha_gdm_port *, unsigned int); } ops;
};
struct airoha_ppe {
	struct airoha_eth *eth;
	struct { bool cfg_owned; } ct_ifc;
	struct { bool health_stopping; int health_work; } ct_fe;
	bool ct_native_pairs, ct_host_ppe, ct_stopping, ct_pon_qualified;
	bool ct_pon_ifc_route_owned, ct_pair_gdm_owned;
	u32 ct_pair_gdm_saved[4];
	u32 ct_pon_ifc_cover;
	struct { bool saved_valid, pending; u32 active; } ct_pon_ifc;
	struct { bool pending; } ct_pon_ifc_pool;
};
struct airoha_eth {
	spinlock_t ct_route_lock;
#ifdef TEST_PON_INGRESS
	spinlock_t ifc_port_lock;
	u32 ifc_port_desired;
#endif
	struct airoha_bank1_routes ct_bank1_routes;
	u16 ct_cpu_route_mask[4];
	bool ct_cpu_fallback, ct_cpu_ifc_disabled, ct_cpu_routes_ready;
	bool ct_ifc_cpu_port_failed, ct_ifc_pon_ready, ct_ordinary_full_test;
	bool ct_ifc_command_pending;
	u32 ct_ifc_port_mask;
	struct airoha_ppe *ppe;
	struct airoha_soc *soc;
	struct airoha_qdma qdma[2];
	struct airoha_gdm_port *ports[4];
	u32 regs[64];
};

enum failure_kind { NO_FAILURE, DROP_WRITE, BAD_READBACK };
struct mmio_event {
	bool write;
	unsigned int reg;
	u32 value;
	bool route_locked, port_locked;
};
struct mmio_fault { enum failure_kind kind; unsigned int reg, write; bool active; };
static struct {
	struct mmio_event events[512];
	size_t length;
	unsigned int writes[64], reads[64], total_writes, total_reads;
	unsigned int failures, schedules, rcu_syncs, wakes;
	struct mmio_fault faults[2];
	int pending_readback;
	u32 readback_mask;
	bool tracing, verify_snapshot;
	u16 snapshot[4];
} host;
static struct airoha_eth eth;
static struct airoha_ppe ppe;
static struct airoha_soc soc;
static struct airoha_gdm_port ports[4];
static struct airoha_gdm_dev devices[4][2];
static struct airoha_qdma foreign_qdma;
static spinlock_t flow_offload_mutex = { true }, ppe_lock;
static unsigned int rcu_depth, legacy_faults;
static bool rtnl_held = true;
static bool loopback_enabled, fail_loopback_restore;
static const char owner_token, other_token;

static void lockdep_assert_held(spinlock_t *lock) { CHECK(lock->held); }
static void spin_lock_bh(spinlock_t *lock)
{
	CHECK(!lock->held);
#ifdef TEST_PON_INGRESS
	if (lock == &eth.ct_route_lock)
		CHECK(!eth.ifc_port_lock.held);
	if (lock == &ppe_lock)
		CHECK(!eth.ct_route_lock.held && !eth.ifc_port_lock.held);
#endif
	lock->held = true;
}
static void spin_unlock_bh(spinlock_t *lock)
{
	CHECK(lock->held);
#ifdef TEST_PON_INGRESS
	if (lock == &eth.ct_route_lock)
		CHECK(!eth.ifc_port_lock.held);
#endif
	lock->held = false;
}
static void rcu_read_lock(void) { ++rcu_depth; }
static void rcu_read_unlock(void) { CHECK(rcu_depth); --rcu_depth; }
static void synchronize_rcu(void) { CHECK(!rcu_depth && !eth.ct_route_lock.held); ++host.rcu_syncs; }
static struct net_device *netdev_from_priv(struct airoha_gdm_dev *dev) { return &dev->netdev; }
static bool netif_running(struct net_device *dev) { return dev->running; }

static void event(bool write, unsigned int reg, u32 value)
{
	if (host.tracing) {
		CHECK(host.length < ARRAY_SIZE(host.events));
		host.events[host.length++] = (struct mmio_event) {
			.write = write, .reg = reg, .value = value,
			.route_locked = eth.ct_route_lock.held,
#ifdef TEST_PON_INGRESS
			.port_locked = eth.ifc_port_lock.held,
#endif
		};
	}
}

static u32 airoha_fe_rr(struct airoha_eth *target, unsigned int reg)
{
	u32 value;

	CHECK(target == &eth && reg < ARRAY_SIZE(eth.regs));
	value = target->regs[reg];
	++host.reads[reg];
	++host.total_reads;
	if ((int)reg == host.pending_readback) {
		value ^= host.readback_mask;
		host.pending_readback = -1;
	}
	event(false, reg, value);
	return value;
}

static void airoha_fe_wr(struct airoha_eth *target, unsigned int reg, u32 value)
{
	unsigned int index;

	CHECK(target == &eth && reg < ARRAY_SIZE(eth.regs));
#ifdef TEST_PON_INGRESS
	if (reg == REG_FE_IFC_PORT_EN)
		CHECK(eth.ifc_port_lock.held);
	else
#endif
		CHECK(reg >= CT_IFC_CONTROL ? ppe_lock.held : eth.ct_route_lock.held);
	if (host.verify_snapshot) {
		CHECK(eth.ct_bank1_routes.owner == &owner_token && !eth.ct_bank1_routes.ready);
		for (index = 0; index < 4; ++index) {
			CHECK(eth.ct_bank1_routes.desired[index] == host.snapshot[index]);
			CHECK(host.reads[index]);
		}
		host.verify_snapshot = false;
	}
	++host.writes[reg];
	++host.total_writes;
	event(true, reg, value);
	for (index = 0; index < ARRAY_SIZE(host.faults); ++index) {
		struct mmio_fault *fault = &host.faults[index];

		if (!fault->active || reg != fault->reg || host.writes[reg] != fault->write)
			continue;
		fault->active = false;
		--host.failures;
		if (fault->kind == DROP_WRITE)
			return;
		CHECK(fault->kind == BAD_READBACK);
		host.pending_readback = (int)reg;
	}
	target->regs[reg] = value;
	if (reg == CT_IFC_CONTROL) {
		struct airoha_ct_pon_ifc_words expected;
		unsigned int bank = (value >> 4) & 15;
		unsigned int row = (value >> 16) & 255;
		unsigned int page = (value >> 8) & 255;
		const u32 *words;

		CHECK((value & 15) == 1 && row >= 56 && row < 60);
		CHECK(bank == 0 || bank == 2);
		CHECK(airoha_ct_pon_ifc_cover_encode(&expected, row < 58 ? 2 : 4, row % 2) == 0);
		words = bank ? expected.action[page] : expected.tcam[page];
		for (index = 0; index < (bank ? 3u : 2u); ++index)
			target->regs[CT_IFC_DATA(index)] = words[index];
		target->regs[reg] |= CT_IFC_DONE;
	}
}

static void airoha_fe_clear(struct airoha_eth *target, unsigned int reg, u32 mask)
{
	airoha_fe_wr(target, reg, airoha_fe_rr(target, reg) & ~mask);
}

static void schedule_delayed_work(int *work, unsigned int delay)
{
	CHECK(work == &ppe.ct_fe.health_work && (delay == 0 || delay == 100));
	++host.schedules;
}

static bool airoha_is_lan_gdm_dev(struct airoha_gdm_dev *dev)
{ return dev->use_flags ? !test_bit(AIROHA_DEV_F_WAN, &dev->flags) : dev->lan; }
static struct airoha_qdma *airoha_qdma_deref(struct airoha_gdm_dev *dev) { return dev->qdma; }
static void netif_tx_stop_all_queues(struct net_device *dev)
{ for (unsigned int index = 0; index < dev->num_tx_queues; ++index) dev->queues[index].stopped = true; }
static void netif_tx_wake_all_queues(struct net_device *dev)
{ for (unsigned int index = 0; index < dev->num_tx_queues; ++index) dev->queues[index].stopped = false; ++host.wakes; }
static void airoha_dev_lro_disable(struct airoha_gdm_dev *dev) { dev->qdma->lro = false; }
static void airoha_dev_lro_enable(struct airoha_gdm_dev *dev) { dev->qdma->lro = true; }
#if defined(TEST_PON_REOPEN) || defined(TEST_PON_INGRESS)
static struct netdev_queue *netdev_get_tx_queue(struct net_device *dev, unsigned int index)
{ CHECK(index < dev->num_tx_queues); return &dev->queues[index]; }
static bool netif_tx_queue_stopped(struct netdev_queue *queue) { return queue->stopped; }
static void netif_tx_wake_queue(struct netdev_queue *queue) { queue->stopped = false; ++host.wakes; }
static bool airoha_fe_lro_is_enabled(struct airoha_eth *target, int index) { return target->qdma[index].lro; }
static struct airoha_gdm_dev *netdev_priv(struct net_device *dev)
{ return (struct airoha_gdm_dev *)((char *)dev - offsetof(struct airoha_gdm_dev, netdev)); }
static int airoha_disable_gdm2_loopback(struct airoha_gdm_dev *dev)
{ loopback_enabled = false; return 0; }
static int airoha_enable_gdm2_loopback(struct airoha_gdm_dev *dev)
{ if (fail_loopback_restore) return -EIO; loopback_enabled = true; return 0; }
static void airoha_dev_set_xmit_frame_size(struct net_device *dev) { (void)dev; }
static int airoha_set_macaddr(struct airoha_gdm_dev *dev, unsigned char *addr) { return 0; }
#endif
static bool airoha_ppe_is_enabled(struct airoha_eth *target, int bank) { return true; }
static int airoha_get_fe_port(struct airoha_gdm_dev *dev) { return dev->lan ? 0 : 5; }
static void airoha_ppe_set_cpu_port(struct airoha_gdm_dev *dev, int bank, int port) { (void)dev; }
static u32 airoha_qdma_rr(struct airoha_qdma *qdma, unsigned int reg) { return reg + 100; }
static void airoha_update_netdev_features(struct airoha_gdm_dev *dev) { (void)dev; }
static int get_sport(struct airoha_gdm_port *port, unsigned int nbq) { return port->id == 2 ? 2 : 24; }

static const unsigned int ct_ifc_action_words[3] = { 1, 3, 1 };
static bool airoha_ct_pon_ifc_route_ready(struct airoha_ppe *target) { return true; }
static bool airoha_ct_pon_ifc_tuple_busy(struct airoha_ppe *target) { return false; }
static int airoha_ct_pon_ifc_dependencies(struct airoha_ppe *target) { return 0; }
static int airoha_ct_pon_ifc_tuple_check(struct airoha_ppe *target) { return 0; }
static void airoha_ct_pon_ifc_fault(struct airoha_ppe *target) { ++legacy_faults; }
#ifdef TEST_PON_COVERED
static bool covered_diagnostic;
static bool airoha_ppe_npu_diag_active(struct airoha_ppe *target, const void *owner)
{ return covered_diagnostic && target == &ppe && owner == &owner_token; }
#endif
#include "airoha_ct_ifc_command.h"
#include "airoha_ct_cpu_fallback.h"
#include "airoha_bank1_routes.h"
#include "route_functions.inc"

static void trace_reset(void)
{
	memset(&host, 0, sizeof(host));
	host.pending_readback = -1;
	host.readback_mask = 1;
	host.tracing = true;
}

static void reset(const char *name)
{
	unsigned int index;
	static const u16 low[] = { 0x84f8, 0x4808, 0xf848, 0x8888 };

	CHECK(!rcu_depth && !eth.ct_route_lock.held && !ppe_lock.held && flow_offload_mutex.held);
#ifdef TEST_PON_INGRESS
	CHECK(!eth.ifc_port_lock.held);
#endif
	current_case = name;
	++cases;
	memset(&eth, 0, sizeof(eth));
	memset(&ppe, 0, sizeof(ppe));
	memset(&soc, 0, sizeof(soc));
	memset(ports, 0, sizeof(ports));
	memset(devices, 0, sizeof(devices));
	trace_reset();
	legacy_faults = 0;
	loopback_enabled = fail_loopback_restore = false;
	eth.ppe = &ppe;
	eth.soc = &soc;
	ppe.eth = &eth;
	ppe.ct_host_ppe = true;
	ppe.ct_native_pairs = true;
	ppe.ct_ifc.cfg_owned = true;
	soc.num_ppe = 2;
	soc.ops.get_sport = get_sport;
	eth.qdma[0].users = eth.qdma[1].users = 2;
	for (index = 0; index < 4; ++index) {
		eth.ports[index] = &ports[index];
		ports[index].id = index + 1;
		ports[index].devs[0] = &devices[index][0];
		devices[index][0].qdma = &eth.qdma[index % 2];
		devices[index][0].eth = &eth;
		devices[index][0].port = &ports[index];
		devices[index][0].lan = !(index % 2);
		devices[index][0].netdev.running = true;
		devices[index][0].netdev.num_tx_queues = 1;
		eth.regs[index] = ((0xa510u + index) << 16) | low[index];
	}
	eth.regs[REG_FE_CSR_IFC_CFG] = 0xa5;
	eth.regs[REG_PPE_GLO_CFG(0)] = eth.regs[REG_PPE_GLO_CFG(1)] = 1;
}

static u32 expected_route(u32 desired, int cpu, bool guard, bool fallback, bool ordinary)
{
	u32 expected = desired & 0xffff0000;
	unsigned int shift;

	for (shift = 0; shift < 16; shift += 4) {
		u32 selector = (desired >> shift) & 15;

		if ((guard && selector == 8) || (fallback && (selector == 4 || selector == 8)))
			selector = cpu < 0 ? 15 : (u32)cpu;
		if (ordinary && (selector == 4 || selector == 8))
			selector = 5;
		expected |= selector << shift;
	}
	return expected;
}

static void assert_routes(const u32 desired[4], bool guard, bool fallback, bool ordinary)
{
	unsigned int index;

	for (index = 0; index < 4; ++index) {
#ifdef TEST_PON_INGRESS
		if (guard && index == AIROHA_GDM2_IDX - 1) {
			CHECK(eth.regs[index] == ((desired[index] & 0xffff0000) | 0x5555));
			continue;
		}
#endif
		CHECK(eth.regs[index] == expected_route(desired[index], index % 2 ? 5 : 0,
			guard, fallback, ordinary && index == 1));
	}
}

static void snapshot(u32 values[4]) { memcpy(values, eth.regs, 4 * sizeof(*values)); }

static void assert_owner(const u32 desired[4], bool ready)
{
	unsigned int index;

	CHECK(eth.ct_bank1_routes.owner == &owner_token && eth.ct_bank1_routes.ready == ready);
	for (index = 0; index < 4; ++index)
		CHECK(eth.ct_bank1_routes.desired[index] == (u16)desired[index]);
}

static void assert_readbacks(void)
{
	size_t index;

	for (index = 0; index < host.length; ++index) {
		if (!host.events[index].write)
			continue;
		CHECK(index + 1 < host.length);
		CHECK(!host.events[index + 1].write && host.events[index + 1].reg == host.events[index].reg);
	}
}

static void claim_ok(void)
{
	CHECK(airoha_bank1_routes_claim(&eth, &owner_token) == 0);
	CHECK(eth.ct_bank1_routes.owner == &owner_token && eth.ct_bank1_routes.ready);
}

static void release_ok(void)
{
	unsigned int index;

	CHECK(airoha_bank1_routes_release(&eth, &owner_token) == 0);
	CHECK(!eth.ct_bank1_routes.owner && !eth.ct_bank1_routes.ready);
	for (index = 0; index < 4; ++index)
		CHECK(eth.ct_bank1_routes.desired[index] == 0);
}

static void inject(enum failure_kind kind, unsigned int reg, unsigned int after_writes)
{
	unsigned int index;

	for (index = 0; index < ARRAY_SIZE(host.faults); ++index) {
		if (!host.faults[index].active) {
			host.faults[index] = (struct mmio_fault) {
				kind, reg, host.writes[reg] + after_writes + 1, true,
			};
			++host.failures;
			return;
		}
	}
	CHECK(false);
}

#ifndef TEST_PON_INGRESS
static void test_basic(void)
{
	u32 desired[4];
	unsigned int index;

	reset("claim snapshots all four GDMs before first write and restores selectors");
	snapshot(desired);
	for (index = 0; index < 4; ++index)
		host.snapshot[index] = desired[index];
	host.verify_snapshot = true;
	claim_ok();
	assert_owner(desired, true);
	assert_routes(desired, true, false, false);
	CHECK(host.total_writes == 4);
	assert_readbacks();
	trace_reset();
	claim_ok();
	CHECK(host.total_writes == 4);
	assert_owner(desired, true);
	assert_readbacks();
	trace_reset();
	release_ok();
	assert_routes(desired, false, false, false);
	CHECK(host.total_writes == 4);
	CHECK(host.reads[REG_PPE_PPE_FLOW_CFG(1)] && host.reads[REG_PPE_GLO_CFG(1)]);
	assert_readbacks();
}

static void test_qdma(void)
{
	u32 desired[4], expected;
	unsigned int index;

	for (index = 0; index < 4; ++index) {
		reset("actual QDMA migration rewrites guarded PPE2 routes to new CPU");
		snapshot(desired);
		claim_ok();
		devices[index][0].lan = !devices[index][0].lan;
		trace_reset();
		CHECK(airoha_dev_set_qdma(&devices[index][0]) == 0);
		CHECK(devices[index][0].qdma == &eth.qdma[!(index % 2)]);
		expected = expected_route(desired[index], index % 2 ? 0 : 5, true, false, false);
		if (eth.regs[index] != expected)
			fprintf(stderr, "QDMA migration GDM%u: actual=%08x expected=%08x desired=%04x\n",
				index + 1, eth.regs[index], expected, eth.ct_bank1_routes.desired[index]);
		CHECK(eth.regs[index] == expected);
		assert_owner(desired, true);
		CHECK(host.writes[index] == 1);
		release_ok();
		CHECK(eth.regs[index] == desired[index]);
	}
}

static void test_native(void)
{
	u32 desired[4], native[4];
	unsigned int index, shift;

	reset("actual native bank start/stop preserves unfiltered guard desired");
	snapshot(desired);
	claim_ok();
	for (index = 0; index < 4; ++index) {
		native[index] = desired[index];
		for (shift = 0; shift < 16; shift += 4)
			if (((native[index] >> shift) & 15) == 4)
				native[index] = (native[index] & ~(15u << shift)) | (8u << shift);
	}
	CHECK(airoha_ct_pair_gdm_start(&ppe) == 0);
	if (eth.ct_bank1_routes.desired[0] != (u16)native[0])
		fprintf(stderr, "native start desired GDM1: actual=%04x expected=%04x saved=%08x\n",
			eth.ct_bank1_routes.desired[0], (u16)native[0], ppe.ct_pair_gdm_saved[0]);
	assert_owner(native, true);
	assert_routes(native, true, false, false);
	CHECK(airoha_ct_pair_gdm_stop(&ppe) == 0 && !ppe.ct_pair_gdm_owned);
	assert_owner(desired, true);
	assert_routes(desired, true, false, false);
	release_ok();
	assert_routes(desired, false, false, false);
}

static void test_fallback(void)
{
	u32 desired[4];
	unsigned int ordinary, index;

	for (ordinary = 0; ordinary < 2; ++ordinary) {
		reset("sticky fallback records desired PPE1/PPE2 while guard already filtered MMIO");
		eth.ct_ordinary_full_test = ordinary;
		snapshot(desired);
		claim_ok();
		CHECK(airoha_ct_cpu_fallback(&eth) == 0);
		CHECK(eth.ct_cpu_fallback && eth.ct_cpu_routes_ready && eth.ct_cpu_ifc_disabled);
		assert_owner(desired, true);
		for (index = 0; index < 4; ++index)
			CHECK(eth.ct_cpu_route_mask[index] == airoha_ct_ppe_selectors(desired[index]));
		assert_routes(desired, true, true, ordinary);
		release_ok();
		assert_routes(desired, false, true, ordinary);
		CHECK(airoha_set_gdm_port_fwd_cfg(&eth, 4, FE_PSE_PORT_PPE1) == 0);
		CHECK((eth.regs[3] & 0xffff) == 0x5555);
	}
	reset("existing sticky fallback remains effective through claim and release");
	snapshot(desired);
	CHECK(airoha_ct_cpu_fallback(&eth) == 0);
	claim_ok();
	CHECK(airoha_gdm_fwd_cfg_update(&eth, 1, 0xffff, 0x8888) == 0);
	CHECK(eth.ct_bank1_routes.desired[0] == 0x8888 && (eth.regs[0] & 0xffff) == 0);
	release_ok();
	CHECK((eth.regs[0] & 0xffff) == 0 && eth.ct_cpu_route_mask[0] == 0xffff);
}

static void test_updates(void)
{
	u32 desired[4];
	unsigned int index;

	reset("partial selector bits and QoS high-bit RMW merge against desired");
	snapshot(desired);
	claim_ok();
	for (index = 0; index < 4; ++index) {
		u32 mask = 1 | BIT(16) | BIT(31);
		u32 value = 1 | BIT(16);

		desired[index] = (desired[index] & ~mask) | value;
		CHECK(airoha_gdm_fwd_cfg_update(&eth, index + 1, mask, value) == 0);
		assert_owner(desired, true);
		CHECK(eth.regs[index] == expected_route(desired[index], index % 2 ? 5 : 0,
			true, false, false));
		CHECK((eth.ct_bank1_routes.desired[index] & 15) == 9);
	}
	CHECK(airoha_set_gdm_port_fwd_cfg(&eth, 4, FE_PSE_PORT_PPE1) == 0);
	desired[3] = (desired[3] & 0xffff0000) | 0x8888;
	assert_owner(desired, true);
	CHECK((eth.regs[3] & 0xffff) == 0x5555);
	CHECK(airoha_set_gdm_port_fwd_cfg(&eth, 3, FE_PSE_PORT_DROP) == 0);
	desired[2] = (desired[2] & 0xffff0000) | 0xffff;
	assert_owner(desired, true);
	CHECK(airoha_gdm_fwd_cfg_update(&eth, 2, 0, 0xffffffff) == 0);
	assert_owner(desired, true);
	release_ok();
	assert_routes(desired, false, false, false);

	reset("direct locked rewrite uses retained desired after receiver remap");
	snapshot(desired);
	claim_ok();
	spin_lock_bh(&eth.ct_route_lock);
	devices[3][0].qdma = &eth.qdma[0];
	CHECK(airoha_ct_gdm_route_locked(&eth, 4, eth.regs[3]) == 0);
	spin_unlock_bh(&eth.ct_route_lock);
	CHECK((eth.regs[3] & 0xffff) == 0);
	assert_owner(desired, true);
}

static void test_mmio_failures(void)
{
	u32 desired[4];
	unsigned int index, phase;
	enum failure_kind kind;

	for (phase = 0; phase < 3; ++phase) {
		for (kind = DROP_WRITE; kind <= BAD_READBACK; ++kind) {
			for (index = 0; index < 4; ++index) {
				reset("each GDM dropped write/readback corruption retains ownership and retries");
				snapshot(desired);
				if (phase)
					claim_ok();
				trace_reset();
				inject(kind, index, 0);
				if (!phase) {
					CHECK(airoha_bank1_routes_claim(&eth, &owner_token) == -EIO);
					CHECK(host.total_writes == 4);
				} else if (phase == 1) {
					CHECK(airoha_bank1_routes_release(&eth, &owner_token) == -EIO);
					CHECK(host.total_writes == 8);
					assert_routes(desired, true, false, false);
				} else {
					desired[index] = (desired[index] & 0xffff0000) | 0xf888;
					CHECK(airoha_gdm_fwd_cfg_update(&eth, index + 1, 0xffff, 0xf888) == -EIO);
					CHECK(host.total_writes == 1);
				}
				CHECK(!host.failures);
				assert_owner(desired, false);
				assert_readbacks();
				trace_reset();
				claim_ok();
				assert_owner(desired, true);
				assert_routes(desired, true, false, false);
				release_ok();
				assert_routes(desired, false, false, false);
			}
		}
	}
	for (kind = DROP_WRITE; kind <= BAD_READBACK; ++kind) {
		for (index = 0; index < 4; ++index) {
			unsigned int first = (index + 1) % 4;

			reset("failed restore followed by failed re-guard retains desired until repair");
			snapshot(desired);
			claim_ok();
			trace_reset();
			inject(DROP_WRITE, first, 0);
			inject(kind, index, 1);
			CHECK(airoha_bank1_routes_release(&eth, &owner_token) == -EIO);
			CHECK(host.total_writes == 8 && !host.failures);
			assert_owner(desired, false);
			assert_readbacks();
			trace_reset();
			claim_ok();
			assert_owner(desired, true);
			assert_routes(desired, true, false, false);
			release_ok();
			assert_routes(desired, false, false, false);
		}
	}
}

static void test_receivers(void)
{
	u32 desired[4];
	unsigned int index, state;

	for (index = 0; index < 4; ++index) {
		for (state = 0; state < 5; ++state) {
			int cpu;

			reset("actual QDMA receiver selection: active, inactive, missing and conflicting");
			snapshot(desired);
			cpu = index % 2 ? 5 : 0;
			if (!state) {
				eth.ports[index] = NULL;
				cpu = -1;
			} else if (state == 1) {
				devices[index][0].qdma = &foreign_qdma;
				cpu = -1;
			} else if (state == 2) {
				devices[index][0].netdev.running = false;
			} else {
				ports[index].devs[1] = &devices[index][1];
				devices[index][1].qdma = &eth.qdma[!(index % 2)];
				devices[index][1].netdev.running = state == 4;
			}
			if (state == 4) {
				CHECK(airoha_bank1_routes_claim(&eth, &owner_token) == -EXDEV);
				cpu = -1;
				assert_owner(desired, false);
			} else {
				claim_ok();
				assert_owner(desired, true);
			}
			CHECK(eth.regs[index] == expected_route(desired[index], cpu, true, false, false));
			ports[index].devs[1] = NULL;
			eth.ports[index] = &ports[index];
			devices[index][0].qdma = &eth.qdma[index % 2];
			claim_ok();
			assert_routes(desired, true, false, false);
			release_ok();
		}
	}
}

static void test_parameters(void)
{
	u32 desired[4];
	unsigned int state;

	reset("invalid pointers, empty owner and foreign owner do not write registers");
	CHECK(airoha_bank1_routes_claim(NULL, &owner_token) == -EINVAL);
	CHECK(airoha_bank1_routes_claim(&eth, NULL) == -EINVAL);
	CHECK(airoha_bank1_routes_release(NULL, &owner_token) == -EINVAL);
	CHECK(airoha_bank1_routes_release(&eth, NULL) == -EINVAL);
	CHECK(airoha_bank1_routes_release(&eth, &owner_token) == -ESTALE);
	CHECK(!host.total_writes);
	snapshot(desired);
	claim_ok();
	trace_reset();
	CHECK(airoha_bank1_routes_claim(&eth, &other_token) == -EBUSY);
	CHECK(airoha_bank1_routes_release(&eth, &other_token) == -ESTALE);
	CHECK(!host.total_writes);
	assert_owner(desired, true);
	CHECK(airoha_gdm_fwd_cfg_update(&eth, 0, 0xffff, 0) == -EINVAL);
	CHECK(airoha_gdm_fwd_cfg_update(&eth, 5, 0xffff, 0) == -EINVAL);
	CHECK(!host.total_writes);
	release_ok();
	for (state = 0; state < 3; ++state) {
		reset("claim requires host PPE and bank1");
		if (state == 0)
			eth.ppe = NULL;
		else if (state == 1)
			ppe.ct_host_ppe = false;
		else
			soc.num_ppe = 1;
		CHECK(airoha_bank1_routes_claim(&eth, &owner_token) == -EOPNOTSUPP);
		CHECK(!eth.ct_bank1_routes.owner && !host.total_writes);
	}
	for (state = 0; state < 3; ++state) {
		reset("release requires bank1 FLOW_CFG zero and BUSY zero");
		snapshot(desired);
		claim_ok();
		trace_reset();
		if (state != 1)
			eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = BIT(31);
		if (state)
			eth.regs[REG_PPE_GLO_CFG(1)] |= PPE_GLO_CFG_BUSY_MASK;
		CHECK(airoha_bank1_routes_release(&eth, &owner_token) == -EBUSY);
		CHECK(!host.total_writes);
		assert_owner(desired, true);
		eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0;
		eth.regs[REG_PPE_GLO_CFG(1)] &= ~PPE_GLO_CFG_BUSY_MASK;
		release_ok();
	}
}

static void test_legacy(void)
{
	u32 desired[4];

	reset("legacy optical route owner blocks guard claim");
	ppe.ct_pon_ifc_route_owned = true;
	CHECK(airoha_bank1_routes_claim(&eth, &owner_token) == -EBUSY);
	CHECK(!eth.ct_bank1_routes.owner && !host.total_writes);
	ppe.ct_pon_ifc_route_owned = false;
	claim_ok();
	ppe.ct_pon_ifc_route_owned = true;
	trace_reset();
	CHECK(airoha_bank1_routes_claim(&eth, &owner_token) == -EBUSY);
	CHECK(!host.total_writes && eth.ct_bank1_routes.owner == &owner_token);

	reset("real optical route_open rejects guard owner with zero register writes");
	ppe.ct_pon_ifc_cover = 3;
	ppe.ct_pon_ifc.saved_valid = true;
	ppe.ct_pon_ifc.active = 15;
	eth.ct_ifc_pon_ready = true;
	eth.ct_ifc_port_mask = XSI_ETH_VIP_PORT_MASK | BIT(2);
	eth.regs[REG_FE_IFC_PORT_EN] = eth.ct_ifc_port_mask;
	snapshot(desired);
	claim_ok();
	trace_reset();
	CHECK(airoha_ct_pon_ifc_route_open(&ppe) == -EBUSY);
	if (host.total_writes)
		fprintf(stderr, "guard-owned legacy route_open wrote %u registers, IFC commands=%u\n",
			host.total_writes, host.writes[CT_IFC_CONTROL]);
	CHECK(!host.total_writes && !ppe.ct_pon_ifc_route_owned && !legacy_faults);
	assert_owner(desired, true);
	release_ok();
	CHECK(airoha_ct_pon_ifc_route_open(&ppe) == 0);
	CHECK(ppe.ct_pon_ifc_route_owned && (eth.regs[1] & 0xffff) == 0x8888);
}

static void test_selectors(void)
{
	u32 low;
	unsigned int ordinary, index;

	for (ordinary = 0; ordinary < 2; ++ordinary) {
		reset("all 65536 selector combinations across four GDMs and ordinary policy");
		eth.ct_ordinary_full_test = ordinary;
		claim_ok();
		host.tracing = false;
		for (low = 0; low < 0x10000; ++low) {
			for (index = 0; index < 4; ++index) {
				u32 request = (0x5a100000u + (index << 16)) | low;

				CHECK(airoha_gdm_fwd_cfg_update(&eth, index + 1, U32_MAX, request) == 0);
				CHECK(eth.ct_bank1_routes.desired[index] == low);
				CHECK(eth.regs[index] == expected_route(request, index % 2 ? 5 : 0,
					true, false, ordinary && index == 1));
				++selector_vectors;
			}
		}
		release_ok();
	}
}

#ifdef TEST_PON_REOPEN
#include "reopen_test.inc"
#endif
#ifdef TEST_OWNER_INVALIDATION
#include "invalidation_test.inc"
#endif
#elif defined(TEST_PON_COVERED)
#include "covered_test.inc"
#else
#include "ingress_test.inc"
#endif

int main(int argc, char **argv)
{
	static const struct { const char *name; void (*run)(void); } groups[] = {
#ifdef TEST_PON_COVERED
		{ "covered-normal", test_covered_normal },
		{ "covered-open-fault", test_covered_open_fault },
		{ "covered-recovery", test_covered_recovery },
		{ "covered-claim-drop", test_covered_claim_drop },
		{ "covered-claim-readback", test_covered_claim_readback },
		{ "covered-revoke-drop", test_covered_revoke_drop },
		{ "covered-revoke-readback", test_covered_revoke_readback },
		{ "covered-fallback-drop", test_covered_fallback_drop },
		{ "covered-fallback-readback", test_covered_fallback_readback },
#elif defined(TEST_PON_INGRESS)
		{ "ingress", test_ingress },
#else
		{ "basic", test_basic }, { "parameters", test_parameters },
		{ "mmio", test_mmio_failures }, { "receivers", test_receivers },
		{ "updates", test_updates }, { "fallback", test_fallback },
		{ "legacy", test_legacy }, { "selectors", test_selectors },
		{ "qdma", test_qdma }, { "native", test_native },
#ifdef TEST_PON_REOPEN
		{ "reopen", test_reopen },
#endif
#ifdef TEST_OWNER_INVALIDATION
		{ "invalidation", test_invalidation },
#endif
#endif
	};
	size_t index;
	bool matched = false;

	CHECK(argc <= 2);
	for (index = 0; index < ARRAY_SIZE(groups); ++index) {
		if (argc == 2 && strcmp(argv[1], groups[index].name))
			continue;
		matched = true;
		groups[index].run();
		CHECK(!eth.ct_route_lock.held && !ppe_lock.held && !rcu_depth);
#ifdef TEST_PON_INGRESS
		CHECK(!eth.ifc_port_lock.held);
#endif
	}
	CHECK(matched);
	printf("PASS %u cases; %u selector vectors; production guard/fallback and extracted driver functions\n",
	       cases, selector_vectors);
	return 0;
}
