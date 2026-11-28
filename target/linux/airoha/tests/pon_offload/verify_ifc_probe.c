#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef EUCLEAN
#define EUCLEAN 117
#endif
#ifndef ESHUTDOWN
#define ESHUTDOWN 108
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define BIT(index) (UINT32_C(1) << (index))
#define U32_MAX UINT32_MAX
#define GENMASK(high, low) ((UINT32_MAX >> (31 - (high))) & (UINT32_MAX << (low)))
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define READ_ONCE(value) (value)
#define WRITE_ONCE(value, next) ((value) = (next))
#define U16_MAX UINT16_MAX
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define AIROHA_GDM1_IDX 1
#define AIROHA_GDM2_IDX 2
#define AIROHA_GDM3_IDX 3
#define AIROHA_GDM4_IDX 4
#define AIROHA_DEV_F_PON 0
#define REG_SP_DFT_CPORT(index) (0x800 + (index) * 4)
#define SP_CPORT_MASK(sport) (0xfU << ((sport) * 4))
#define REG_GDM_FWD_CFG(index) (0x840 + (index) * 4)
#define REG_FE_CSR_IFC_CFG 0x880
#define REG_FE_IFC_PORT_EN 0x884
#define FE_IFC_EN_MASK BIT(0)
#define XSI_ETH_VIP_PORT_MASK BIT(24)
#define __field_get(mask, value) (((value) & (mask)) >> __builtin_ctz(mask))
#define test_bit(bit, address) (!!(*(address) & BIT(bit)))
#define rcu_dereference(value) (value)
#define netdev_from_priv(dev) (dev)
#define netif_running(dev) ((dev)->running)
#define msecs_to_jiffies(value) (value)
#define dev_err_ratelimited(...) ((void)0)

struct iphdr { u8 bytes[20]; };
#include "probe_constants.inc"
#include "airoha_ct_pon_ifc_owner.h"
#if PROBE_HAVE_TUPLE_POOL
#include "airoha_ct_ifc_tuple_pool.h"
#endif

struct lock { bool held; unsigned int rank; };
static struct lock ppe_lock = { .rank = 1 }, flow_offload_mutex;
static struct lock *lock_stack[3];
static unsigned int lock_depth;
static bool rtnl;
static bool worker_context;
static unsigned int rcu_depth;
#define lockdep_assert_held(lock) assert((lock)->held)
#define ASSERT_RTNL() assert(rtnl)
static void spin_lock_bh(struct lock *lock)
{
	assert(!lock->held);
	assert(lock_depth < ARRAY_SIZE(lock_stack));
	assert(!lock_depth || lock_stack[lock_depth - 1]->rank < lock->rank);
	lock_stack[lock_depth++] = lock;
	lock->held = true;
}
static void spin_unlock_bh(struct lock *lock)
{
	assert(lock->held);
	assert(lock_depth && lock_stack[--lock_depth] == lock);
	lock->held = false;
}
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth); rcu_depth--; }
static void rtnl_lock(void) { assert(!rtnl); rtnl = true; }
static void rtnl_unlock(void) { assert(rtnl && !flow_offload_mutex.held); rtnl = false; }
static void mutex_lock(struct lock *lock) { assert((rtnl || worker_context) && !lock->held); lock->held = true; }
static void mutex_unlock(struct lock *lock) { assert((rtnl || worker_context) && lock->held); lock->held = false; }
struct device { struct airoha_eth *data; };
struct device_attribute { unsigned int unused; };
static void *dev_get_drvdata(struct device *dev) { return dev->data; }
static bool sysfs_streq(const char *first, const char *second)
{
	while (*first && *first == *second) {
		first++;
		second++;
	}
	return (!*first || (*first == '\n' && !first[1])) &&
	       (!*second || (*second == '\n' && !second[1]));
}
static int kstrtouint(const char *text, unsigned int base, unsigned int *value)
{
	char *end;
	unsigned long parsed;

	if (*text == '-')
		return -EINVAL;
	errno = 0;
	parsed = strtoul(text, &end, base);
	if (errno == ERANGE || parsed > UINT_MAX)
		return -ERANGE;
	if (end == text || (*end && (*end != '\n' || end[1])))
		return -EINVAL;
	*value = parsed;
	return 0;
}
struct work_struct { unsigned int unused; };
struct work { struct work_struct work; unsigned int scheduled; };
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
#define to_delayed_work(item) container_of(item, struct work, work)
static void schedule_delayed_work(struct work *work, unsigned int delay)
{
	assert(delay == 0 || delay == 100);
	work->scheduled++;
}

struct queue { void *desc, *page_pool; int ndesc; };
struct airoha_qdma { struct queue q_rx[5]; };
struct airoha_gdm_dev { unsigned long flags; unsigned int nbq; struct airoha_qdma *qdma; bool running; };
struct airoha_gdm_port { struct airoha_gdm_dev *devs[2]; unsigned int id; };
struct soc { struct { int (*get_sport)(struct airoha_gdm_port *, int); } ops; };
struct airoha_eth {
	struct airoha_ppe *ppe;
	struct airoha_gdm_port *ports[4];
	struct airoha_qdma qdma[2];
	struct soc *soc;
	struct lock ct_route_lock, ifc_port_lock;
	u32 ct_ifc_port_mask, ifc_port_desired;
	u16 ct_cpu_route_mask[4];
	bool ct_ifc_command_pending, ct_ifc_pon_ready, ct_ifc_cpu_port_failed;
	bool ct_cpu_fallback, ct_cpu_routes_ready, ct_cpu_ifc_disabled, ct_ordinary_full_test, ct_pon_full;
};
struct airoha_ppe {
	struct airoha_eth *eth;
	struct airoha_ct_pon_ifc_owner ct_pon_ifc;
#if PROBE_HAVE_TUPLE_POOL
	struct airoha_ct_ifc_pool ct_pon_ifc_pool;
	struct airoha_ct_ifc_pool_lease ct_pon_ifc_lease[2];
	bool ct_pon_ifc_tuple;
#endif
	struct { bool cfg_owned; struct { u32 lut_index; bool lut_dirty; } rule[2]; } ct_ifc;
	struct { bool health_stopping, active; struct work health_work; } ct_fe;
	struct work ct_pon_ifc_work;
	u16 ct_pon_ifc_services[2];
	u8 ct_pon_ifc_cover;
	bool ct_pon_ifc_route_owned;
	u32 ct_pon_ifc_errors;
	bool ct_host_ppe, ct_stopping, ct_pon_qualified, ct_native_pairs;
	bool ct_pon_ifc_registered, ct_pon_ifc_work_stopping;
	bool ct_pair_policy_allowed;
};
enum fault { NONE, BEFORE, AFTER, DEFERRED, READBACK };
struct simulation {
	u32 table[3][64][9][3], registers[0x900 / 4];
	u32 original[4][2][9][3], command;
	u32 original_lut[32][2];
	struct { u32 command, words[3]; } trace[4096];
	unsigned int trace_count;
	unsigned int commands, data_writes, control_writes, fail_at, port_writes, table_writes;
	unsigned int port_fail_first, port_fail_last, gate_clears;
	unsigned int route_reads;
	unsigned int route_writes, route_fail_at, cpu_acknowledgements, audit_race_at;
	u16 audited[4];
	enum fault route_fault;
	bool route_read_error, cpu_route_stuck, enforce_cpu_before_table, cpu_acknowledged;
	bool audit_route_open, enforce_cpu_before_gate, source_publish;
	bool tuple_watch;
	bool complete_without_done;
	enum fault fault;
	bool busy, release, late, gate_stuck, route_drop, require_gate_closed;
};
struct fixture {
	struct airoha_eth eth;
	struct airoha_ppe ppe;
	struct airoha_gdm_port port;
	struct airoha_gdm_dev dev[2];
	struct soc soc;
};
static struct simulation mock;
static unsigned int cases, transport_faults, blocked_retries, dependency_faults, readback_faults;
static unsigned int scope_cases, fallback_stop_cases, rejected_set_retries;
static unsigned int sport_cases, sport_close_cases;
static unsigned int store_dispatch_cases, store_stop_cases, store_pending_cases;
static unsigned int cover_cases, cover_tamper_cases, cover_route_faults, cover_io_faults;
static unsigned int cover_publish_faults;
static unsigned int source_cases, source_faults;
static unsigned int sif_match_cases;

static bool sif_matches(u32 key, u32 mask, unsigned int sport)
{
	return (key & BIT(sport)) || !(mask & BIT(sport));
}

static unsigned int page_words(unsigned int bank, unsigned int page)
{
	return bank == 2 ? ct_ifc_action_words[page] : 2;
}

static void complete_command(void)
{
	unsigned int bank = (mock.command >> 4) & 3;
	unsigned int row = (mock.command >> 16) & 63;
	unsigned int page = (mock.command >> 8) & 15;
	unsigned int count = page_words(bank, page);

	assert(bank < 3 && page < (bank == 0 ? 9U : bank == 1 ? 1U : 3U));
	if (mock.tuple_watch && bank == 1 && (mock.command & BIT(1))) {
		assert(!(mock.table[2][56][2][0] & BIT(31)));
		assert(!(mock.table[2][57][2][0] & BIT(31)));
	}
	for (unsigned int word = 0; word < count; word++) {
		if (mock.command & BIT(1))
			mock.table[bank][row][page][word] = mock.registers[CT_IFC_DATA(word) / 4];
		else
			mock.registers[CT_IFC_DATA(word) / 4] = mock.table[bank][row][page][word];
	}
	if (mock.command & BIT(1))
		mock.table_writes++;
	else if ((bank == 0 || bank == 2) && row >= 56 && row < 60)
		mock.audited[row - 56] |= BIT(bank == 0 ? page : 9 + page);
	mock.late = false;
}

static u32 airoha_fe_rr(struct airoha_eth *eth, unsigned int address)
{
	(void)eth;
	assert(address / 4 < ARRAY_SIZE(mock.registers));
	if (address == REG_SP_DFT_CPORT(0) && ++mock.route_reads == 2 && mock.route_drop)
		return 0;
	if (address == REG_GDM_FWD_CFG(2)) {
		if (mock.route_read_error) {
			mock.route_read_error = false;
			return mock.registers[address / 4] ^ 1;
		}
		if (mock.route_writes && (mock.registers[address / 4] & 0xffff) ==
		    FE_PSE_PORT_CDM2 * 0x1111U) {
			mock.cpu_acknowledged = true;
			mock.cpu_acknowledgements++;
		}
	}
	if (address == CT_IFC_CONTROL) {
		if (mock.busy && mock.late && mock.complete_without_done) {
			complete_command();
			mock.complete_without_done = false;
		}
		if (mock.busy && mock.release) {
			if (mock.late)
				complete_command();
			mock.busy = false;
		}
		if (mock.audit_race_at && mock.commands == mock.audit_race_at)
			eth->ct_cpu_fallback = true;
		return mock.busy ? 0 : CT_IFC_DONE;
	}
	return mock.registers[address / 4];
}

static void airoha_fe_wr(struct airoha_eth *eth, unsigned int address, u32 value)
{
	assert(address / 4 < ARRAY_SIZE(mock.registers));
	if (address == REG_FE_IFC_PORT_EN) {
		assert(eth->ct_route_lock.held && eth->ifc_port_lock.held);
		mock.port_writes++;
		if (mock.port_writes >= mock.port_fail_first && mock.port_writes <= mock.port_fail_last)
			value ^= BIT(1);
	} else if (address >= CT_IFC_DATA(0) && address <= CT_IFC_DATA(2)) {
		assert(ppe_lock.held && !mock.busy);
		mock.data_writes++;
	} else if (address == CT_IFC_CONTROL) {
		assert(ppe_lock.held && !mock.busy);
		if (mock.source_publish && mock.commands >= 78)
			assert(eth->ppe->ct_pon_ifc_cover == BIT(1));
		if ((value & BIT(1)) && mock.require_gate_closed)
			assert(!(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK));
		if ((value & BIT(1)) && mock.enforce_cpu_before_table) {
			assert(mock.cpu_acknowledged);
			assert((mock.registers[REG_GDM_FWD_CFG(2) / 4] & 0xffff) ==
			       FE_PSE_PORT_CDM2 * 0x1111U);
		}
		mock.commands++;
		assert(mock.trace_count < ARRAY_SIZE(mock.trace));
		mock.trace[mock.trace_count].command = value;
		for (unsigned int word = 0; word < 3; word++)
			mock.trace[mock.trace_count].words[word] = mock.registers[CT_IFC_DATA(word) / 4];
		mock.trace_count++;
		mock.control_writes++;
		mock.command = value;
		if (mock.commands == mock.fail_at) {
			if (mock.fault == READBACK) {
				assert(!(value & BIT(1)));
				complete_command();
				mock.registers[CT_IFC_DATA(((value >> 4) & 3) == 0 ? 1 : 0) / 4] ^= 1;
				return;
			}
			mock.busy = true;
			mock.late = mock.fault == DEFERRED;
			if (mock.fault == AFTER)
				complete_command();
		} else {
			complete_command();
		}
		return;
	} else if (address == REG_GDM_FWD_CFG(2)) {
		assert(eth->ct_route_lock.held);
		mock.route_writes++;
		mock.cpu_acknowledged = false;
		if (mock.audit_route_open && (value & 0xffff) == FE_PSE_PORT_PPE2 * 0x1111U) {
			assert(ppe_lock.held && eth->ppe->ct_pon_ifc_route_owned);
			assert(eth->ppe->ct_pon_ifc_cover && eth->ct_ifc_pon_ready);
			assert(!eth->ct_ifc_command_pending && !eth->ppe->ct_pon_ifc.pending);
			for (unsigned int slot = 0; slot < 2; slot++)
				if (eth->ppe->ct_pon_ifc_cover & BIT(slot)) {
					assert(mock.audited[slot * 2] == 0xfff);
					assert(mock.audited[slot * 2 + 1] == 0xfff);
				}
		} else if (eth->ct_ifc_pon_ready && !eth->ppe->ct_pon_ifc_route_owned &&
			   ((value ^ mock.registers[address / 4]) & 0xffff)) {
			assert(!(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK));
		}
		if (mock.cpu_route_stuck && (value & 0xffff) == FE_PSE_PORT_CDM2 * 0x1111U)
			return;
		if (mock.route_writes == mock.route_fail_at) {
			if (mock.route_fault == BEFORE)
				return;
			assert(mock.route_fault == AFTER);
			mock.route_read_error = true;
		}
	}
	mock.registers[address / 4] = value;
}

static void airoha_fe_clear(struct airoha_eth *eth, unsigned int address, u32 mask)
{
	assert(eth->ct_route_lock.held);
	if (address == REG_FE_CSR_IFC_CFG) {
		if (mock.enforce_cpu_before_gate && eth->ppe->ct_pon_ifc_route_owned) {
			assert(mock.cpu_acknowledged);
			assert((mock.registers[REG_GDM_FWD_CFG(2) / 4] & 0xffff) ==
			       FE_PSE_PORT_CDM2 * 0x1111U);
		}
		mock.gate_clears++;
	}
	if (address != REG_FE_CSR_IFC_CFG || !mock.gate_stuck)
		mock.registers[address / 4] &= ~mask;
}

#define read_poll_timeout_atomic(reader, value, condition, delay, timeout, sleep, eth, address) \
	({ int poll_error = -ETIMEDOUT; \
	   for (unsigned int poll = 0; poll < 3; poll++) { \
		(value) = reader(eth, address); \
		if (condition) { poll_error = 0; break; } \
	   } poll_error; })

#include "probe_production.inc"

static void initialize(struct fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	memset(&mock, 0, sizeof(mock));
	assert(!ppe_lock.held && !rcu_depth && !lock_depth && !worker_context);
	flow_offload_mutex.held = rtnl = true;
	fixture->eth.ppe = &fixture->ppe;
	fixture->eth.ct_route_lock.rank = 2;
	fixture->eth.ifc_port_lock.rank = 3;
	fixture->ppe.eth = &fixture->eth;
	(void)airoha_ct_pon_ifc_repair_work;
	fixture->eth.soc = &fixture->soc;
	fixture->soc.ops.get_sport = airoha_en7581_get_sport;
	fixture->port.id = AIROHA_GDM2_IDX;
	fixture->eth.ports[1] = &fixture->port;
	fixture->port.devs[0] = &fixture->dev[0];
	fixture->dev[0] = (struct airoha_gdm_dev) {
		.flags = BIT(AIROHA_DEV_F_PON), .qdma = &fixture->eth.qdma[1], .running = true,
	};
	for (unsigned int ring = 2; ring <= 4; ring += 2)
		fixture->eth.qdma[1].q_rx[ring] = (struct queue) { fixture, fixture, 64 };
	fixture->eth.ct_ifc_port_mask = XSI_ETH_VIP_PORT_MASK;
	fixture->eth.ifc_port_desired = XSI_ETH_VIP_PORT_MASK | BIT(2);
	mock.registers[REG_FE_IFC_PORT_EN / 4] = XSI_ETH_VIP_PORT_MASK;
	fixture->ppe.ct_host_ppe = fixture->ppe.ct_native_pairs = true;
	fixture->ppe.ct_pon_ifc_registered = fixture->ppe.ct_ifc.cfg_owned = true;
	mock.registers[REG_SP_DFT_CPORT(0) / 4] = FE_PSE_PORT_CDM2 << 8;
	mock.registers[REG_GDM_FWD_CFG(2) / 4] = FE_PSE_PORT_CDM2 * 0x1111;
	mock.registers[REG_FE_CSR_IFC_CFG / 4] = FE_IFC_EN_MASK;
	for (unsigned int family = 0; family < 2; family++) {
		unsigned int lut = 31 - family, row = CT_IFC_RULE(family);

		fixture->ppe.ct_ifc.rule[family].lut_index = lut;
		fixture->ppe.ct_ifc.rule[family].lut_dirty = true;
		mock.registers[CT_IFC_UDF0 / 4] |= (u32)ct_ifc_guard[family].udf << (family * 16);
		mock.table[1][lut][0][0] = (ct_ifc_guard[family].max << 16) | ct_ifc_guard[family].min;
		mock.table[1][lut][0][1] = CT_IFC_LUT1_ENABLE | CT_IFC_LUT1_END | CT_IFC_LUT1_RANGE |
			(CT_IFC_LUT1_UDF0 + family);
		mock.table[0][row][4][0] = mock.table[0][row][4][1] = BIT(lut);
		mock.table[0][row][8][0] = CT_IFC_TCAM_TYPE1 | ct_ifc_guard[family].valid;
		mock.table[0][row][8][1] = CT_IFC_TCAM_TYPE_MASK | ct_ifc_guard[family].valid;
		mock.table[2][row][1][2] = CT_IFC_CPU_RX_RING << 10;
		mock.table[2][row][2][0] = CT_IFC_ACTION_ENABLE | CT_IFC_ACTION_STOP | CT_IFC_ACTION_FORCE_CPU;
	}
	for (unsigned int slot = 0; slot < 32; slot++)
		memcpy(mock.original_lut[slot], mock.table[1][slot][0], sizeof(mock.original_lut[slot]));
	for (unsigned int row = 56; row < 60; row++)
		for (unsigned int bank = 0; bank <= 2; bank += 2)
			for (unsigned int page = 0; page < (bank ? 3U : 9U); page++)
				for (unsigned int word = 0; word < page_words(bank, page); word++) {
					u32 value = 0x12345600 ^ (row << 16) ^ (page << 4) ^ word;
					mock.table[bank][row][page][word] = value;
					mock.original[row - 56][bank / 2][page][word] = value;
				}
}

static void reset_counts(void)
{
	mock.trace_count = 0;
	mock.commands = mock.data_writes = mock.control_writes = mock.table_writes = 0;
	mock.port_writes = mock.fail_at = mock.route_reads = mock.gate_clears = 0;
	mock.fault = NONE;
	mock.release = false;
	mock.route_writes = mock.route_fail_at = mock.cpu_acknowledgements = mock.audit_race_at = 0;
	mock.route_fault = NONE;
	mock.route_read_error = mock.cpu_acknowledged = false;
	memset(mock.audited, 0, sizeof(mock.audited));
}

static void check_shadow(const struct fixture *fixture)
{
	if (!fixture->ppe.ct_pon_ifc.saved_valid)
		return;
	for (unsigned int row = 0; row < 4; row++)
		for (unsigned int page = 0; page < 9; page++) {
			assert(!memcmp(fixture->ppe.ct_pon_ifc.saved[row].tcam[page],
				       mock.original[row][0][page], 2 * sizeof(u32)));
			if (page < 3)
				assert(!memcmp(fixture->ppe.ct_pon_ifc.saved[row].action[page],
					       mock.original[row][1][page], 3 * sizeof(u32)));
		}
}

static void check_restored(const struct fixture *fixture)
{
#if PROBE_HAVE_TUPLE_POOL
	assert(!fixture->ppe.ct_pon_ifc_tuple);
	assert(!fixture->ppe.ct_pon_ifc_pool.pending && !fixture->ppe.ct_pon_ifc_pool.reserved &&
	       !fixture->ppe.ct_pon_ifc_pool.dirty && !fixture->ppe.ct_pon_ifc_pool.leases &&
	       !fixture->ppe.ct_pon_ifc_pool.releasing);
	for (unsigned int family = 0; family < 2; family++) {
		const struct airoha_ct_ifc_pool_lease empty = {};
		assert(!memcmp(&fixture->ppe.ct_pon_ifc_lease[family], &empty, sizeof(empty)));
	}
	for (unsigned int slot = 0; slot < 32; slot++) {
		assert(!fixture->ppe.ct_pon_ifc_pool.refs[slot]);
	}
#endif
	assert(!fixture->ppe.ct_pon_ifc.saved_valid && !fixture->ppe.ct_pon_ifc.dirty &&
	       !fixture->ppe.ct_pon_ifc.active && !fixture->ppe.ct_pon_ifc.pending);
	assert(!fixture->eth.ct_ifc_pon_ready && !fixture->ppe.ct_pon_ifc_services[0] &&
	       !fixture->ppe.ct_pon_ifc_services[1]);
	assert(!fixture->ppe.ct_pon_ifc_cover && !fixture->ppe.ct_pon_ifc_route_owned);
	for (unsigned int row = 0; row < 4; row++) {
		assert(!memcmp(mock.table[0][56 + row], mock.original[row][0], sizeof(mock.original[row][0])));
		assert(!memcmp(mock.table[2][56 + row], mock.original[row][1], sizeof(mock.original[row][1])));
	}
	assert(!ppe_lock.held && !fixture->eth.ct_route_lock.held &&
	       !fixture->eth.ifc_port_lock.held && !rcu_depth && !lock_depth);
}

static void prepare(struct fixture *fixture)
{
	initialize(fixture);
	assert(!airoha_ct_pon_ifc_cpu_set(&fixture->ppe, 0, 0x2134));
	assert(!airoha_ct_pon_ifc_cpu_set(&fixture->ppe, 1, 0xa134));
	assert(fixture->ppe.ct_pon_ifc.active == 15);
	assert(fixture->eth.ct_ifc_port_mask == (XSI_ETH_VIP_PORT_MASK | BIT(2)));
	assert(mock.registers[REG_FE_IFC_PORT_EN / 4] == (XSI_ETH_VIP_PORT_MASK | BIT(2)));
	assert(fixture->eth.ifc_port_desired == (XSI_ETH_VIP_PORT_MASK | BIT(2)));
	assert(airoha_ifc_lan_ports_ready(&fixture->eth));
	reset_counts();
}

static void lifecycle(void)
{
	struct fixture fixture;
	u32 peer[2][2][9][3];

	for (unsigned int slot = 0; slot < 2; slot++) {
		unsigned int other = 1 - slot;

		prepare(&fixture);
		assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, slot,
			fixture.ppe.ct_pon_ifc_services[other]) == -EEXIST);
		assert(!mock.commands);
		for (unsigned int row = 0; row < 2; row++)
			for (unsigned int bank = 0; bank < 2; bank++)
				memcpy(peer[row][bank], mock.table[bank * 2][56 + other * 2 + row], sizeof(peer[row][bank]));
		assert(!airoha_ct_pon_ifc_cpu_clear(&fixture.ppe, slot));
		assert(mock.commands == 52 && !mock.port_writes);
		assert(fixture.ppe.ct_pon_ifc.active == (3 << (other * 2)) &&
		       fixture.ppe.ct_pon_ifc.dirty == (3 << (other * 2)) && fixture.ppe.ct_pon_ifc.saved_valid);
		assert(!fixture.ppe.ct_pon_ifc_services[slot] && fixture.ppe.ct_pon_ifc_services[other]);
		for (unsigned int row = 0; row < 2; row++)
			for (unsigned int bank = 0; bank < 2; bank++)
				assert(!memcmp(peer[row][bank], mock.table[bank * 2][56 + other * 2 + row], sizeof(peer[row][bank])));
		check_shadow(&fixture);
		assert(!airoha_ct_pon_ifc_cpu_clear(&fixture.ppe, other));
		assert(fixture.eth.ct_ifc_port_mask == XSI_ETH_VIP_PORT_MASK);
		assert(mock.registers[REG_FE_IFC_PORT_EN / 4] == XSI_ETH_VIP_PORT_MASK);
		assert(fixture.eth.ifc_port_desired == (XSI_ETH_VIP_PORT_MASK | BIT(2)));
		check_restored(&fixture);
		assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
		cases++;
	}
}

static void route_and_inputs(void)
{
	struct fixture fixture;

	for (unsigned int failure = 0; failure < 18; failure++) {
		initialize(&fixture);
		switch (failure) {
		case 0: fixture.eth.ports[1] = NULL; break;
		case 1: fixture.soc.ops.get_sport = NULL; break;
		case 2: fixture.port.devs[0] = NULL; break;
		case 3: fixture.dev[0].flags = 0; break;
		case 4: fixture.dev[0].nbq = 1; break;
		case 5: fixture.dev[0].qdma = &fixture.eth.qdma[0]; break;
		case 6: fixture.eth.qdma[1].q_rx[2].desc = NULL; break;
		case 7: fixture.eth.qdma[1].q_rx[4].desc = NULL; break;
		case 8: fixture.eth.qdma[1].q_rx[2].page_pool = NULL; break;
		case 9: fixture.eth.qdma[1].q_rx[4].page_pool = NULL; break;
		case 10: fixture.eth.qdma[1].q_rx[2].ndesc = 0; break;
		case 11: fixture.eth.qdma[1].q_rx[4].ndesc = -1; break;
		case 12: mock.registers[REG_SP_DFT_CPORT(0) / 4] = 0; break;
		case 13: mock.registers[REG_GDM_FWD_CFG(2) / 4] ^= 1; break;
		case 14: fixture.port.devs[1] = &fixture.dev[1]; break;
		case 15: fixture.ppe.ct_host_ppe = false; break;
		case 16: fixture.ppe.ct_stopping = true; break;
		case 17: fixture.ppe.ct_pon_qualified = true; break;
		}
		assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, 0, 1) == -ESHUTDOWN);
		assert(!mock.commands && !mock.port_writes && !rcu_depth);
		cases++;
	}
	initialize(&fixture);
	assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, 2, 1) == -EINVAL);
	assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, 0, 0) == -EINVAL);
	assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, 0, 65536) == -EINVAL);
	assert(airoha_ct_pon_ifc_cpu_clear(&fixture.ppe, 0) == -EINVAL);
	mock.registers[REG_FE_IFC_PORT_EN / 4] = 0;
	assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, 0, 1) == -ESHUTDOWN);
	assert(!mock.commands);
	cases++;
}

static void dependency_failures(void)
{
	struct fixture fixture;

	for (unsigned int family = 0; family < 2; family++)
		for (unsigned int failure = 0; failure < 22; failure++) {
			unsigned int row = CT_IFC_RULE(family), lut = 31 - family;

			initialize(&fixture);
			if (failure == 0)
				fixture.ppe.ct_ifc.rule[family].lut_index = 32;
			else if (failure == 1)
				fixture.ppe.ct_ifc.rule[family].lut_dirty = false;
			else if (failure == 2)
				mock.registers[CT_IFC_UDF0 / 4] ^= BIT(family * 16);
			else if (failure < 5)
				mock.table[1][lut][0][failure - 3] ^= 1;
			else if (failure < 14)
				mock.table[0][row][failure - 5][1] ^= 1;
			else if (failure == 14)
				mock.table[0][row][4][0] ^= BIT(lut);
			else if (failure == 15)
				mock.table[0][row][8][0] ^= CT_IFC_TCAM_TYPE1;
			else {
				unsigned int word = failure - 16;
				mock.table[2][row][word < 2 ? 0 : word < 5 ? 1 : 2][word < 2 ? word : word < 5 ? word - 2 : 0] ^= 1;
			}
			spin_lock_bh(&ppe_lock);
			assert(airoha_ct_pon_ifc_dependencies(&fixture.ppe) == -EUCLEAN);
			spin_unlock_bh(&ppe_lock);
			if (failure != 0) {
				assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, 0, 1) == -EUCLEAN);
				assert(fixture.ppe.ct_pon_ifc.saved_valid && !fixture.ppe.ct_pon_ifc.dirty);
				assert(!mock.table_writes && fixture.ppe.ct_pon_ifc_errors == 1);
				assert(fixture.ppe.ct_fe.health_work.scheduled && fixture.ppe.ct_pon_ifc_work.scheduled);
				check_shadow(&fixture);
				assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
				check_restored(&fixture);
			}
			cases++;
			dependency_faults++;
		}
}

enum wrapper { SET_INITIAL, SET_REPLACE, CLEAR, STOP };
static int invoke(struct fixture *fixture, enum wrapper operation, unsigned int slot)
{
	if (operation == SET_INITIAL || operation == SET_REPLACE)
		return airoha_ct_pon_ifc_cpu_set(&fixture->ppe, slot, 0x3456);
	if (operation == CLEAR)
		return airoha_ct_pon_ifc_cpu_clear(&fixture->ppe, slot);
	return airoha_ct_pon_ifc_cpu_stop(&fixture->ppe);
}

static void io_failures(void)
{
	struct fixture fixture;
	unsigned int counts[] = { 126, 78, 52, 104 };

	for (unsigned int operation = 0; operation < 4; operation++)
		for (unsigned int mode = BEFORE; mode <= DEFERRED; mode++)
			for (unsigned int position = 1; position <= counts[operation]; position++) {
				unsigned int slot = position & 1;
				struct airoha_ct_pon_ifc_owner saved;
				u16 services[2];
				unsigned int data_writes, control_writes;

				if (operation == SET_INITIAL)
					initialize(&fixture);
				else
					prepare(&fixture);
				memcpy(services, fixture.ppe.ct_pon_ifc_services, sizeof(services));
				mock.fault = mode;
				mock.fail_at = position;
				assert(invoke(&fixture, operation, slot) == -ETIMEDOUT);
				assert(mock.commands == position && mock.busy && fixture.eth.ct_ifc_command_pending);
				assert(fixture.ppe.ct_pon_ifc.pending && fixture.ppe.ct_pon_ifc_errors == 1);
				assert(!memcmp(services, fixture.ppe.ct_pon_ifc_services, sizeof(services)));
				check_shadow(&fixture);
				saved = fixture.ppe.ct_pon_ifc;
				data_writes = mock.data_writes;
				control_writes = mock.control_writes;
				for (unsigned int attempt = 0; attempt < 2; attempt++) {
					if (operation == SET_INITIAL || operation == SET_REPLACE) {
						assert(invoke(&fixture, operation, slot) == -ESHUTDOWN);
						rejected_set_retries++;
						assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
						assert(airoha_ct_pon_ifc_cpu_stop(&fixture.ppe) == -ETIMEDOUT);
					} else {
						assert(invoke(&fixture, operation, slot) == -ETIMEDOUT);
					}
					assert(mock.data_writes == data_writes && mock.control_writes == control_writes);
					assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
					assert(!memcmp(services, fixture.ppe.ct_pon_ifc_services, sizeof(services)));
					blocked_retries++;
				}
				mock.release = true;
				mock.fail_at = 0;
				if (operation == SET_INITIAL || operation == SET_REPLACE)
					assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
				else
					assert(!invoke(&fixture, operation, slot));
				assert(!fixture.ppe.ct_pon_ifc.pending && !mock.busy);
				assert(!fixture.eth.ct_ifc_command_pending);
				check_shadow(&fixture);
				assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
				check_restored(&fixture);
				cases++;
				transport_faults++;
			}
}

static void readback_failures(void)
{
	struct fixture fixture;
	u32 peer[2][2][9][3];

	for (unsigned int operation = SET_REPLACE; operation <= STOP; operation++)
		for (unsigned int slot = 0; slot < (operation == STOP ? 1U : 2U); slot++)
			for (unsigned int position = 1; position <= (operation == STOP ? 52U : 26U); position++) {
				u16 services[2];
				unsigned int other = 1 - slot;

				prepare(&fixture);
				memcpy(services, fixture.ppe.ct_pon_ifc_services, sizeof(services));
				for (unsigned int row = 0; row < 2; row++)
					for (unsigned int bank = 0; bank < 2; bank++)
						memcpy(peer[row][bank], mock.table[bank * 2][56 + other * 2 + row], sizeof(peer[row][bank]));
				mock.fault = READBACK;
				mock.fail_at = (operation == SET_REPLACE ? 26 : 0) + position * 2;
				assert(invoke(&fixture, operation, slot) == -EIO);
				assert(mock.commands == mock.fail_at && !mock.busy &&
				       !fixture.eth.ct_ifc_command_pending && fixture.ppe.ct_pon_ifc.pending);
				assert(!memcmp(services, fixture.ppe.ct_pon_ifc_services, sizeof(services)));
				if (operation != STOP)
					for (unsigned int row = 0; row < 2; row++)
						for (unsigned int bank = 0; bank < 2; bank++)
							assert(!memcmp(peer[row][bank], mock.table[bank * 2][56 + other * 2 + row], sizeof(peer[row][bank])));
				check_shadow(&fixture);
				mock.fail_at = 0;
				if (operation == SET_REPLACE) {
					unsigned int commands = mock.commands;
					assert(invoke(&fixture, operation, slot) == -ESHUTDOWN);
					rejected_set_retries++;
					assert(mock.commands == commands);
				} else {
					assert(!invoke(&fixture, operation, slot));
				}
				assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
				check_restored(&fixture);
				cases++;
				readback_faults++;
			}
}

static void scope_and_route_failures(void)
{
	struct fixture fixture;
	struct airoha_ct_pon_ifc_owner saved;

	initialize(&fixture);
	mock.route_drop = true;
	assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, 0, 1) == -ESHUTDOWN);
	assert(!mock.port_writes && fixture.ppe.ct_pon_ifc.saved_valid &&
	       fixture.ppe.ct_pon_ifc.active == 3 && fixture.ppe.ct_pon_ifc_services[0] == 1);
	assert(fixture.ppe.ct_pon_ifc_errors == 1 &&
	       !(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK));
	assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
	check_restored(&fixture);
	cases++;
	initialize(&fixture);
	mock.port_fail_first = mock.port_fail_last = 1;
	assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, 0, 1) == -EIO);
	assert(fixture.ppe.ct_pon_ifc.active == 3 && fixture.ppe.ct_pon_ifc.dirty == 3 &&
	       fixture.ppe.ct_pon_ifc.saved_valid && fixture.ppe.ct_pon_ifc_services[0] == 1);
	assert(!(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK));
	assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
	check_restored(&fixture);
	cases++;
	for (unsigned int stopping = 0; stopping < 3; stopping++) {
		prepare(&fixture);
		saved = fixture.ppe.ct_pon_ifc;
		fixture.ppe.ct_stopping = stopping == 1;
		fixture.ppe.ct_host_ppe = stopping != 2;
		mock.port_fail_first = mock.port_fail_last = 1;
		mock.gate_stuck = true;
		assert(airoha_ct_pon_ifc_cpu_stop(&fixture.ppe) == -EIO);
		assert(!mock.commands && !memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
		assert(fixture.eth.ct_ifc_pon_ready && fixture.ppe.ct_pon_ifc_services[0] &&
		       fixture.ppe.ct_pon_ifc_services[1]);
		mock.gate_stuck = false;
		mock.port_fail_first = mock.port_fail_last = 0;
		assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
		check_restored(&fixture);
		cases++;
	}
	prepare(&fixture);
	mock.port_fail_first = 1;
	mock.port_fail_last = 2;
	assert(airoha_ct_pon_ifc_cpu_stop(&fixture.ppe) == -EIO);
	check_restored(&fixture);
	cases++;
	for (unsigned int failed = 0; failed < 2; failed++) {
		prepare(&fixture);
		mock.gate_stuck = failed;
		assert(airoha_ct_ifc_cpu_port_change(&fixture.eth, 2) == (failed ? -EIO : 0));
		assert(fixture.eth.ct_ifc_cpu_port_failed && fixture.ppe.ct_fe.health_work.scheduled);
		assert(!!(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK) == !!failed);
		check_shadow(&fixture);
		mock.gate_stuck = false;
		assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
		check_restored(&fixture);
		prepare(&fixture);
		mock.gate_stuck = failed;
		assert(airoha_gdm_fwd_cfg_update(&fixture.eth, 2, 0xffff, 0x1111) == (failed ? -EIO : 0));
		assert(mock.registers[REG_GDM_FWD_CFG(2) / 4] ==
		       (failed ? FE_PSE_PORT_CDM2 * 0x1111U : 0x1111U));
		assert(fixture.eth.ct_ifc_cpu_port_failed);
		mock.gate_stuck = false;
		assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
		check_restored(&fixture);
		cases += 2;
	}
}

static void shared_transport(void)
{
	struct fixture fixture;
	u32 words[2] = { 0x1234, 0xffff };

	for (unsigned int origin = 0; origin < 2; origin++) {
		initialize(&fixture);
		mock.fail_at = 1;
		mock.fault = DEFERRED;
		if (origin == 0) {
			assert(ct_ifc_access(&fixture.eth, 0, 10, 0, true, words, 2) == -ETIMEDOUT);
			spin_lock_bh(&ppe_lock);
			assert(airoha_ct_fe_table(&fixture.ppe, 0, 11, 0, true, words, 2) == -ETIMEDOUT);
			spin_unlock_bh(&ppe_lock);
		} else {
			spin_lock_bh(&ppe_lock);
			assert(airoha_ct_fe_table(&fixture.ppe, 0, 10, 0, true, words, 2) == -ETIMEDOUT);
			spin_unlock_bh(&ppe_lock);
			assert(ct_ifc_access(&fixture.eth, 0, 11, 0, true, words, 2) == -ETIMEDOUT);
		}
		assert(mock.data_writes == 2 && mock.control_writes == 1 && fixture.eth.ct_ifc_command_pending);
		mock.release = true;
		assert(!ct_ifc_access(&fixture.eth, 0, 11, 0, true, words, 2));
		assert(mock.data_writes == 4 && mock.control_writes == 2 && !fixture.eth.ct_ifc_command_pending);
		assert(!memcmp(mock.table[0][10][0], words, sizeof(words)));
		assert(!memcmp(mock.table[0][11][0], words, sizeof(words)));
		cases++;
	}
}

static void scope_interoperation(void)
{
	struct fixture fixture;
	u32 optical = XSI_ETH_VIP_PORT_MASK | BIT(2);

	for (unsigned int failure = 0; failure < 13; failure++) {
		int expected;
		u32 previous, desired, ports;

		initialize(&fixture);
		fixture.eth.ct_ifc_pon_ready = true;
		switch (failure) {
		case 0: fixture.eth.ct_ifc_port_mask = 0; expected = -ENOENT; break;
		case 1: fixture.eth.ct_ifc_port_mask = optical; expected = -ESTALE; break;
		case 2: fixture.eth.ppe = NULL; expected = -ESHUTDOWN; break;
		case 3: fixture.ppe.ct_ifc.cfg_owned = false; expected = -ESHUTDOWN; break;
		case 4: fixture.ppe.ct_host_ppe = false; expected = -ESHUTDOWN; break;
		case 5: fixture.ppe.ct_stopping = true; expected = -ESHUTDOWN; break;
		case 6: fixture.eth.ct_cpu_fallback = true; expected = -ESHUTDOWN; break;
		case 7: fixture.eth.ct_ifc_cpu_port_failed = true; expected = -ESHUTDOWN; break;
		case 8: mock.registers[REG_FE_CSR_IFC_CFG / 4] = 0; expected = -ESHUTDOWN; break;
		case 9: fixture.eth.ct_ifc_pon_ready = false; expected = -EACCES; break;
		case 10: mock.registers[REG_FE_IFC_PORT_EN / 4] ^= BIT(1); expected = -EUCLEAN; break;
		case 11: fixture.eth.ct_ifc_port_mask |= BIT(1); expected = -EUCLEAN; break;
		case 12: fixture.eth.ct_ifc_port_mask = BIT(2); expected = -EUCLEAN; break;
		default: assert(false); expected = 0;
		}
		previous = fixture.eth.ct_ifc_port_mask;
		desired = fixture.eth.ifc_port_desired;
		ports = mock.registers[REG_FE_IFC_PORT_EN / 4];
		assert(airoha_ifc_scope_update(&fixture.eth,
			failure >= 11 ? previous : XSI_ETH_VIP_PORT_MASK, optical) == expected);
		assert(fixture.eth.ct_ifc_port_mask == previous && fixture.eth.ifc_port_desired == desired);
		assert(mock.registers[REG_FE_IFC_PORT_EN / 4] == ports && !mock.port_writes &&
		       !mock.commands && !mock.gate_clears && !lock_depth);
		cases++;
		scope_cases++;
	}
	for (unsigned int failure = 0; failure < 10; failure++) {
		initialize(&fixture);
		switch (failure) {
		case 0: fixture.eth.ppe = NULL; break;
		case 1: fixture.ppe.ct_ifc.cfg_owned = false; break;
		case 2: fixture.eth.ct_cpu_fallback = true; break;
		case 3: fixture.eth.ct_ifc_cpu_port_failed = true; break;
		case 4: mock.registers[REG_FE_CSR_IFC_CFG / 4] = 0; break;
		case 5: fixture.eth.ct_ifc_port_mask = BIT(2); break;
		case 6: fixture.eth.ct_ifc_port_mask |= BIT(1); break;
		case 7: fixture.eth.ct_ifc_port_mask = optical; break;
		case 8: fixture.eth.ifc_port_desired = BIT(2); break;
		case 9: mock.registers[REG_FE_IFC_PORT_EN / 4] ^= BIT(2); break;
		}
		assert(!airoha_ifc_lan_ports_ready(&fixture.eth));
		assert(!mock.port_writes && !mock.commands && !lock_depth);
		cases++;
		scope_cases++;
	}
	initialize(&fixture);
	assert(airoha_ifc_scope_update(&fixture.eth, XSI_ETH_VIP_PORT_MASK, BIT(2)) == -EINVAL);
	assert(airoha_ifc_scope_update(&fixture.eth, XSI_ETH_VIP_PORT_MASK, optical | BIT(3)) == -EINVAL);
	assert(!mock.port_writes && !lock_depth);
	fixture.eth.ct_ifc_pon_ready = true;
	assert(!airoha_ifc_scope_update(&fixture.eth, XSI_ETH_VIP_PORT_MASK, optical));
	assert(fixture.eth.ct_ifc_port_mask == optical && fixture.eth.ifc_port_desired == optical);
	assert(mock.registers[REG_FE_IFC_PORT_EN / 4] == optical && mock.port_writes == 1);
	assert(airoha_ifc_lan_ports_ready(&fixture.eth));
	assert(!airoha_ifc_scope_update(&fixture.eth, optical, optical) && mock.port_writes == 1);
	assert(!airoha_ifc_scope_update(&fixture.eth, optical, XSI_ETH_VIP_PORT_MASK));
	assert(mock.registers[REG_FE_IFC_PORT_EN / 4] == XSI_ETH_VIP_PORT_MASK && mock.port_writes == 2);
	assert(fixture.eth.ifc_port_desired == optical && airoha_ifc_lan_ports_ready(&fixture.eth));
	cases++;
	scope_cases++;
	for (unsigned int closing = 0; closing < 2; closing++)
		for (unsigned int rollback_failed = 0; rollback_failed < 2; rollback_failed++) {
			u32 previous = closing ? optical : XSI_ETH_VIP_PORT_MASK;
			u32 next = closing ? XSI_ETH_VIP_PORT_MASK : optical;

			initialize(&fixture);
			fixture.eth.ct_ifc_pon_ready = true;
			fixture.eth.ct_ifc_port_mask = previous;
			mock.registers[REG_FE_IFC_PORT_EN / 4] = previous;
			mock.port_fail_first = 1;
			mock.port_fail_last = rollback_failed ? 2 : 1;
			assert(airoha_ifc_scope_update(&fixture.eth, previous, next) == -EIO);
			assert(mock.port_writes == 2 && fixture.eth.ct_ifc_port_mask == previous &&
			       fixture.eth.ifc_port_desired == optical && fixture.eth.ct_ifc_pon_ready);
			assert(mock.registers[REG_FE_IFC_PORT_EN / 4] == (previous ^ (rollback_failed ? BIT(1) : 0)));
			assert(fixture.eth.ct_cpu_fallback == !!rollback_failed &&
			       fixture.eth.ct_ifc_cpu_port_failed == !!rollback_failed);
			assert(!!fixture.ppe.ct_fe.health_work.scheduled == !!rollback_failed);
			assert(!!(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK) == !rollback_failed);
			assert(!mock.commands && !lock_depth);
			cases++;
			scope_cases++;
		}
}

static void fallback_stop(void)
{
	struct fixture fixture;
	struct airoha_ct_pon_ifc_owner saved;
	u16 services[2];

	for (unsigned int failure = 0; failure < 3; failure++) {
		prepare(&fixture);
		saved = fixture.ppe.ct_pon_ifc;
		memcpy(services, fixture.ppe.ct_pon_ifc_services, sizeof(services));
		fixture.eth.ct_cpu_fallback = true;
		mock.gate_stuck = failure == 1;
		assert(airoha_ifc_scope_update(&fixture.eth, fixture.eth.ct_ifc_port_mask,
			XSI_ETH_VIP_PORT_MASK) == -ESHUTDOWN);
		assert(!mock.port_writes && !mock.gate_clears && !mock.commands);
		assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, 0, 1) == -ESHUTDOWN);
		assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
		mock.require_gate_closed = true;
		if (failure == 2) {
			mock.fail_at = 1;
			mock.fault = DEFERRED;
		}
		assert(airoha_ct_pon_ifc_cpu_stop(&fixture.ppe) ==
		       (failure == 2 ? -ETIMEDOUT : failure == 1 ? -EIO : 0));
		assert(mock.gate_clears && !mock.port_writes);
		assert(fixture.eth.ct_ifc_port_mask == (XSI_ETH_VIP_PORT_MASK | BIT(2)));
		assert(fixture.eth.ifc_port_desired == (XSI_ETH_VIP_PORT_MASK | BIT(2)));
		if (failure == 1) {
			assert(!mock.commands && !memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
			assert(!memcmp(services, fixture.ppe.ct_pon_ifc_services, sizeof(services)));
			assert(fixture.eth.ct_ifc_pon_ready && (mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK));
			mock.gate_stuck = false;
			assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
		} else if (failure == 2) {
			assert(mock.commands == 1 && fixture.ppe.ct_pon_ifc.saved_valid &&
			       fixture.ppe.ct_pon_ifc.dirty == 15 && fixture.ppe.ct_pon_ifc.pending);
			assert(!memcmp(services, fixture.ppe.ct_pon_ifc_services, sizeof(services)));
			check_shadow(&fixture);
			assert(airoha_ct_pon_ifc_cpu_stop(&fixture.ppe) == -ETIMEDOUT && mock.commands == 1);
			mock.release = true;
			mock.fail_at = 0;
			assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
		}
		assert(!(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK));
		assert(!airoha_ifc_lan_ports_ready(&fixture.eth));
		check_restored(&fixture);
		assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
		cases++;
		fallback_stop_cases++;
	}
}

static void source_port_mapping(void)
{
	struct fixture fixture;
	int nbqs[] = { INT_MIN, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, INT_MAX };

	initialize(&fixture);
	for (unsigned int port = 0; port <= 5; port++)
		for (unsigned int index = 0; index < ARRAY_SIZE(nbqs); index++) {
			int nbq = nbqs[index], expected = -EINVAL;

			fixture.port.id = port;
			if (port == 2 && nbq == 0)
				expected = 2;
			else if (port == 3 && nbq == 4)
				expected = 22;
			else if (port == 3 && nbq == 5)
				expected = 23;
			else if (port == 4 && nbq == 0)
				expected = 24;
			else if (port == 4 && nbq == 1)
				expected = 25;
			assert(fixture.soc.ops.get_sport(&fixture.port, nbq) == expected);
			sport_cases++;
			cases++;
		}
	for (unsigned int failed = 0; failed < 2; failed++) {
		int sport;

		prepare(&fixture);
		mock.gate_stuck = failed;
		sport = fixture.soc.ops.get_sport(&fixture.port, fixture.dev[0].nbq);
		assert(sport == 2);
		assert(airoha_ct_ifc_cpu_port_change(&fixture.eth, sport) == (failed ? -EIO : 0));
		assert(mock.gate_clears == 1 && fixture.eth.ct_ifc_cpu_port_failed);
		assert(!!(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK) == !!failed);
		assert(fixture.dev[0].qdma == &fixture.eth.qdma[1]);
		check_shadow(&fixture);
		mock.gate_stuck = false;
		assert(!airoha_ct_pon_ifc_cpu_stop(&fixture.ppe));
		check_restored(&fixture);
		sport_close_cases++;
		cases++;
	}
}

static ssize_t store(struct fixture *fixture, const char *command)
{
	struct device dev = { .data = &fixture->eth };
	ssize_t result;

	assert(rtnl && flow_offload_mutex.held && !lock_depth);
	flow_offload_mutex.held = rtnl = false;
	result = ct_pon_cpu_probe_store(&dev, NULL, command, strlen(command));
	assert(!rtnl && !flow_offload_mutex.held && !lock_depth && !rcu_depth);
	flow_offload_mutex.held = rtnl = true;
	return result;
}

static void store_dispatch(void)
{
	const char *commands[] = { "off", "off\n", "set 0 0x2468\n", "clear 0\n" };
	struct fixture fixture;

	for (unsigned int state = 0; state < 8; state++)
		for (unsigned int command = 0; command < ARRAY_SIZE(commands); command++) {
			struct airoha_ct_pon_ifc_owner saved;
			u16 services[2];
			bool rejected;

			prepare(&fixture);
			saved = fixture.ppe.ct_pon_ifc;
			memcpy(services, fixture.ppe.ct_pon_ifc_services, sizeof(services));
			fixture.ppe.ct_pon_ifc_registered = !!(state & BIT(0));
			fixture.ppe.ct_pon_ifc_work_stopping = !!(state & BIT(1));
			fixture.ppe.ct_stopping = !!(state & BIT(2));
			rejected = !(state & BIT(0)) || (state & BIT(1)) ||
				   ((state & BIT(2)) && command >= 2);
			assert(store(&fixture, commands[command]) ==
			       (rejected ? -ESHUTDOWN : (ssize_t)strlen(commands[command])));
			if (rejected) {
				assert(!mock.commands && !mock.data_writes && !mock.control_writes);
				assert(!mock.port_writes && !mock.gate_clears && fixture.eth.ct_ifc_pon_ready);
				assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
				assert(!memcmp(services, fixture.ppe.ct_pon_ifc_services, sizeof(services)));
			} else if (command < 2) {
				check_restored(&fixture);
			} else if (command == 2) {
				assert(fixture.ppe.ct_pon_ifc_services[0] == 0x2468);
				assert(fixture.ppe.ct_pon_ifc_services[1] == 0xa134);
				assert(fixture.ppe.ct_pon_ifc.active == 15);
			} else {
				assert(!fixture.ppe.ct_pon_ifc_services[0]);
				assert(fixture.ppe.ct_pon_ifc_services[1] == 0xa134);
				assert(fixture.ppe.ct_pon_ifc.active == 12);
			}
			store_dispatch_cases++;
			cases++;
		}
}

static void store_stopping_off(void)
{
	struct fixture fixture;

	for (unsigned int host = 0; host < 2; host++)
		for (unsigned int gate = 0; gate < 3; gate++) {
			struct airoha_ct_pon_ifc_owner saved;

			prepare(&fixture);
			saved = fixture.ppe.ct_pon_ifc;
			fixture.ppe.ct_stopping = fixture.eth.ct_cpu_fallback = true;
			fixture.ppe.ct_fe.health_stopping = true;
			fixture.ppe.ct_host_ppe = host;
			mock.registers[REG_FE_CSR_IFC_CFG / 4] = gate ? FE_IFC_EN_MASK : 0;
			mock.gate_stuck = gate == 2;
			mock.require_gate_closed = true;
			assert(store(&fixture, "off\n") == (gate == 2 ? -EIO : 4));
			assert(!mock.port_writes && !fixture.ppe.ct_fe.health_work.scheduled);
			assert(!!mock.gate_clears == !!gate);
			if (gate == 2) {
				assert(!mock.commands && !mock.data_writes && !mock.control_writes);
				assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
				assert(fixture.eth.ct_ifc_pon_ready);
				assert(fixture.ppe.ct_pon_ifc_services[0] == 0x2134 &&
				       fixture.ppe.ct_pon_ifc_services[1] == 0xa134);
				mock.gate_stuck = false;
				assert(store(&fixture, "off\n") == 4);
			}
			assert(mock.commands == 104 && !mock.port_writes);
			assert(!(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK));
			assert(fixture.ppe.ct_stopping && fixture.eth.ct_cpu_fallback);
			assert(!fixture.ppe.ct_fe.health_work.scheduled);
			check_restored(&fixture);
			reset_counts();
			assert(store(&fixture, "off") == 3);
			assert(!mock.commands && !mock.port_writes && !mock.gate_clears);
			store_stop_cases++;
			cases++;
		}
	for (unsigned int shared = 0; shared < 2; shared++)
		for (unsigned int mode = BEFORE; mode <= DEFERRED; mode++) {
			struct airoha_ct_pon_ifc_owner saved;
			unsigned int data_writes, control_writes;
			u32 words[2];

			prepare(&fixture);
			fixture.ppe.ct_stopping = fixture.eth.ct_cpu_fallback = true;
			fixture.ppe.ct_fe.health_stopping = true;
			mock.registers[REG_FE_CSR_IFC_CFG / 4] = 0;
			mock.require_gate_closed = true;
			mock.fault = mode;
			mock.fail_at = 1;
			if (shared) {
				assert(ct_ifc_access(&fixture.eth, 0, 54, 0, false, words, 2) == -ETIMEDOUT);
				assert(fixture.eth.ct_ifc_command_pending && !fixture.ppe.ct_pon_ifc.pending);
			}
			data_writes = mock.data_writes;
			control_writes = mock.control_writes;
			assert(store(&fixture, "off") == -ETIMEDOUT);
			assert(mock.commands == 1 && fixture.eth.ct_ifc_command_pending);
			assert(fixture.ppe.ct_pon_ifc.pending && fixture.ppe.ct_pon_ifc.saved_valid);
			assert(fixture.ppe.ct_pon_ifc.dirty == 15 && !fixture.eth.ct_ifc_pon_ready);
			if (shared)
				assert(mock.data_writes == data_writes && mock.control_writes == control_writes);
			check_shadow(&fixture);
			saved = fixture.ppe.ct_pon_ifc;
			data_writes = mock.data_writes;
			control_writes = mock.control_writes;
			for (unsigned int attempt = 0; attempt < 2; attempt++) {
				assert(store(&fixture, "off\n") == -ETIMEDOUT);
				assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
				assert(mock.data_writes == data_writes && mock.control_writes == control_writes);
				assert(fixture.ppe.ct_pon_ifc_services[0] == 0x2134 &&
				       fixture.ppe.ct_pon_ifc_services[1] == 0xa134);
			}
			mock.fail_at = 0;
			mock.release = true;
			assert(store(&fixture, "off") == 3);
			assert(!fixture.eth.ct_ifc_command_pending && !mock.busy);
			assert(!mock.port_writes);
			assert(!(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK));
			assert(!fixture.ppe.ct_fe.health_work.scheduled);
			check_restored(&fixture);
			store_pending_cases++;
			cases++;
		}
}

static void prepare_cover(struct fixture *fixture, unsigned int slot)
{
	char command[32];

	initialize(fixture);
	mock.registers[REG_GDM_FWD_CFG(2) / 4] |= 0xa5b60000;
	snprintf(command, sizeof(command), "cover %u", slot);
	assert(store(fixture, command) == (ssize_t)strlen(command));
	snprintf(command, sizeof(command), "set %u 0x2134", slot ^ 1);
	assert(store(fixture, command) == (ssize_t)strlen(command));
	assert(fixture->ppe.ct_pon_ifc_cover == BIT(slot));
	assert(fixture->ppe.ct_pon_ifc.active == 15);
	assert(fixture->ppe.ct_pon_ifc_services[slot] == 0);
	assert(fixture->ppe.ct_pon_ifc_services[slot ^ 1] == 0x2134);
	for (unsigned int family = 0; family < 2; family++) {
		unsigned int row = 56 + slot * 2 + family;

		for (unsigned int page = 0; page < 9; page++) {
			assert(mock.table[0][row][page][0] ==
			       (page == 0 ? BIT(2) : page == 8 ? family << 6 : 0));
			assert(mock.table[0][row][page][1] ==
			       (page == 0 ? UINT32_MAX : page == 8 ? 0xc0 : 0));
		}
		for (unsigned int page = 0; page < 3; page++)
			for (unsigned int word = 0; word < page_words(2, page); word++)
				assert(mock.table[2][row][page][word] ==
				       (page == 1 && word == 2 ? (slot ? 4U : 2U) << 10 :
					page == 2 ? 0xd0000000 : 0));
		for (unsigned int type = 0; type < 4; type++)
			assert(!(((type << 6) ^ mock.table[0][row][8][0]) &
				 mock.table[0][row][8][1]) == (type == family));
	}
	check_shadow(fixture);
	reset_counts();
	mock.audit_route_open = true;
	mock.enforce_cpu_before_gate = true;
}

static void open_cover(struct fixture *fixture, unsigned int slot)
{
	prepare_cover(fixture, slot);
	assert(store(fixture, "route") == 5);
	assert(mock.commands == 24 && !mock.table_writes);
	assert(mock.route_writes == 1 && fixture->ppe.ct_pon_ifc_route_owned);
	assert(mock.registers[REG_GDM_FWD_CFG(2) / 4] == 0xa5b68888);
	reset_counts();
	mock.enforce_cpu_before_table = true;
}

static void cover_lifecycle(void)
{
	struct fixture fixture;
	const char *operations[] = { "off", "clear %u", "set %u 0xa134", "cover %u" };
	struct airoha_ct_pon_ifc_words encoded;

	assert(airoha_ct_pon_ifc_cover_encode(NULL, 2, 0) == -EINVAL);
	assert(airoha_ct_pon_ifc_cover_encode(&encoded, 3, 0) == -EINVAL);
	assert(airoha_ct_pon_ifc_cover_encode(&encoded, 2, 2) == -EINVAL);
	for (unsigned int slot = 0; slot < 2; slot++)
		for (unsigned int operation = 0; operation < ARRAY_SIZE(operations); operation++) {
			char command[32];
			u32 peer[2][2][9][3];

			open_cover(&fixture, slot);
			for (unsigned int row = 0; row < 2; row++)
				for (unsigned int bank = 0; bank < 2; bank++)
					memcpy(peer[row][bank], mock.table[bank * 2][56 + (slot ^ 1) * 2 + row],
					       sizeof(peer[row][bank]));
			snprintf(command, sizeof(command), operations[operation], slot);
			assert(store(&fixture, command) == (ssize_t)strlen(command));
			assert(!fixture.ppe.ct_pon_ifc_route_owned && mock.cpu_acknowledgements);
			assert(mock.registers[REG_GDM_FWD_CFG(2) / 4] == 0xa5b65555);
			if (operation) {
				assert(fixture.ppe.ct_pon_ifc_services[slot ^ 1] == 0x2134);
				assert(fixture.ppe.ct_pon_ifc_cover == (operation == 3 ? BIT(slot) : 0));
				for (unsigned int row = 0; row < 2; row++)
					for (unsigned int bank = 0; bank < 2; bank++)
						assert(!memcmp(peer[row][bank], mock.table[bank * 2][56 + (slot ^ 1) * 2 + row],
							       sizeof(peer[row][bank])));
				assert(store(&fixture, "off") == 3);
			}
			check_restored(&fixture);
			assert(store(&fixture, "off") == 3);
			cover_cases++;
			cases++;
		}
	for (unsigned int slot = 0; slot < 2; slot++) {
		char command[32];

		prepare_cover(&fixture, slot);
		snprintf(command, sizeof(command), "cover %u", slot ^ 1);
		assert(store(&fixture, command) == (ssize_t)strlen(command));
		reset_counts();
		assert(store(&fixture, "route") == 5);
		assert(mock.commands == 48 && fixture.ppe.ct_pon_ifc_cover == 3);
		assert(store(&fixture, "off") == 3);
		check_restored(&fixture);
		cover_cases++;
		cases++;
	}
}

static void cover_tampering(void)
{
	struct fixture fixture;

	for (unsigned int slot = 0; slot < 2; slot++)
		for (unsigned int family = 0; family < 2; family++)
			for (unsigned int field = 0; field < 17; field++) {
				unsigned int row = 56 + slot * 2 + family;
				struct airoha_ct_pon_ifc_owner saved;

				prepare_cover(&fixture, slot);
				saved = fixture.ppe.ct_pon_ifc;
				if (field < 9)
					mock.table[0][row][field][1] ^= field == 8 ? 0xc0 : 1;
				else if (field < 11)
					mock.table[0][row][field == 9 ? 0 : 8][0] ^= field == 9 ? BIT(2) : BIT(6);
				else if (field < 13)
					mock.table[2][row][0][field - 11] ^= 1;
				else if (field < 16)
					mock.table[2][row][1][field - 13] ^= 1;
				else
					mock.table[2][row][2][0] ^= BIT(31);
				assert(store(&fixture, "route") == -EUCLEAN);
				assert(!mock.route_writes && !mock.table_writes && !mock.gate_clears);
				assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
				assert(store(&fixture, "off") == 3);
				check_restored(&fixture);
				cover_tamper_cases++;
				cases++;
			}
	for (unsigned int slot = 0; slot < 2; slot++) {
		prepare_cover(&fixture, slot);
		for (unsigned int row = 56 + slot * 2; row < 58 + slot * 2; row++)
			for (unsigned int page = 0; page < 9; page++)
				mock.table[0][row][page][0] ^= ~mock.table[0][row][page][1];
		assert(store(&fixture, "route") == 5);
		assert(store(&fixture, "off") == 3);
		check_restored(&fixture);
		cover_tamper_cases++;
		cases++;
	}
}

static void cover_route_guards(void)
{
	struct fixture fixture;

	for (unsigned int slot = 0; slot < 2; slot++)
		for (unsigned int guard = 0; guard < 18; guard++) {
			prepare_cover(&fixture, slot);
			switch (guard) {
			case 0: fixture.ppe.ct_pon_ifc_cover = 0; break;
			case 1: fixture.ppe.ct_pon_ifc.saved_valid = false; break;
			case 2: fixture.ppe.ct_pon_ifc.pending = true; break;
			case 3: fixture.eth.ct_ifc_command_pending = true; break;
			case 4: fixture.ppe.ct_host_ppe = false; break;
			case 5: fixture.ppe.ct_stopping = true; break;
			case 6: fixture.ppe.ct_pon_qualified = true; break;
			case 7: fixture.ppe.ct_pon_ifc.active &= ~BIT(slot * 2); break;
			case 8: fixture.ppe.ct_ifc.cfg_owned = false; break;
			case 9: fixture.eth.ct_ifc_port_mask &= ~BIT(2); break;
			case 10: fixture.eth.ct_ifc_port_mask |= BIT(3); break;
			case 11: mock.registers[REG_FE_IFC_PORT_EN / 4] &= ~BIT(2); break;
			case 12: mock.registers[REG_FE_CSR_IFC_CFG / 4] = 0; break;
			case 13: fixture.eth.ct_ifc_cpu_port_failed = true; break;
			case 14: fixture.eth.ct_ifc_pon_ready = false; break;
			case 15: mock.audit_race_at = 24; break;
			case 16: mock.route_drop = true; break;
			case 17:
				fixture.ppe.ct_pon_ifc_cover = 3;
				fixture.ppe.ct_pon_ifc.active &= ~BIT((slot ^ 1) * 2);
				if (slot == 1)
					fixture.ppe.ct_pon_ifc.active &= ~BIT(slot * 2);
				break;
			}
			assert(store(&fixture, "route") == -ESHUTDOWN);
			assert(!mock.route_writes && !mock.table_writes && !mock.gate_clears);
			assert(!fixture.ppe.ct_pon_ifc_route_owned);
			cover_cases++;
			cases++;
		}
	for (unsigned int state = 0; state < 8; state++)
		for (unsigned int command = 0; command < 2; command++) {
			const char *text = command ? "route" : "cover 0";
			bool rejected = !(state & 1) || (state & 6);

			prepare_cover(&fixture, 1);
			fixture.ppe.ct_pon_ifc_registered = !!(state & 1);
			fixture.ppe.ct_pon_ifc_work_stopping = !!(state & 2);
			fixture.ppe.ct_stopping = !!(state & 4);
			assert(store(&fixture, text) == (rejected ? -ESHUTDOWN : (ssize_t)strlen(text)));
			if (rejected)
				assert(!mock.commands && !mock.route_writes && !mock.port_writes);
			cover_cases++;
			cases++;
		}
}

static void cover_audit_failures(void)
{
	struct fixture fixture;

	for (unsigned int slot = 0; slot < 2; slot++)
		for (unsigned int mode = BEFORE; mode <= DEFERRED; mode++)
			for (unsigned int failure = 1; failure <= 24; failure++) {
				unsigned int data, control;

				prepare_cover(&fixture, slot);
				mock.fault = mode;
				mock.fail_at = failure;
				assert(store(&fixture, "route") == -ETIMEDOUT);
				assert(fixture.ppe.ct_pon_ifc.saved_valid && fixture.ppe.ct_pon_ifc.active == 15);
				assert(fixture.ppe.ct_pon_ifc_cover == BIT(slot));
				assert(fixture.eth.ct_ifc_command_pending && fixture.ppe.ct_pon_ifc.pending);
				assert(!fixture.ppe.ct_pon_ifc_route_owned && !mock.table_writes);
				data = mock.data_writes;
				control = mock.control_writes;
				assert(store(&fixture, "route") == -ESHUTDOWN);
				assert(store(&fixture, "off") == -ETIMEDOUT);
				assert(mock.data_writes == data && mock.control_writes == control);
				check_shadow(&fixture);
				mock.release = true;
				mock.fail_at = 0;
				assert(store(&fixture, "off") == 3);
				check_restored(&fixture);
				cover_io_faults++;
				cases++;
			}
}

static void cover_route_failures(void)
{
	struct fixture fixture;
	const char *operations[] = { "off", "clear 0", "set 0 0xa134", "cover 0" };

	for (unsigned int slot = 0; slot < 2; slot++)
		for (unsigned int mode = BEFORE; mode <= AFTER; mode++) {
			prepare_cover(&fixture, slot);
			mock.route_fail_at = 1;
			mock.route_fault = mode;
			assert(store(&fixture, "route") == -EIO);
			assert(fixture.ppe.ct_pon_ifc_route_owned && fixture.ppe.ct_pon_ifc.active == 15);
			assert(fixture.ppe.ct_pon_ifc_cover == BIT(slot) && !mock.table_writes);
			assert(fixture.eth.ct_cpu_fallback);
			check_shadow(&fixture);
			assert(store(&fixture, "off") == 3);
			check_restored(&fixture);
			cover_route_faults++;
			cases++;
		}
	for (unsigned int operation = 0; operation < ARRAY_SIZE(operations); operation++)
		for (unsigned int mode = BEFORE; mode <= AFTER; mode++) {
			struct airoha_ct_pon_ifc_owner saved;

			open_cover(&fixture, 0);
			saved = fixture.ppe.ct_pon_ifc;
			mock.route_fail_at = 1;
			mock.route_fault = mode;
			assert(store(&fixture, operations[operation]) == -EIO);
			assert(!mock.commands && !memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
			assert(fixture.ppe.ct_pon_ifc_route_owned && fixture.ppe.ct_pon_ifc_cover == 1);
			assert(fixture.ppe.ct_pon_ifc_services[1] == 0x2134);
			assert(store(&fixture, "off") == 3);
			check_restored(&fixture);
			cover_route_faults++;
			cases++;
		}
}

static void cover_shutdown_order(void)
{
	struct fixture fixture;

	for (unsigned int path = 0; path < 3; path++)
		for (unsigned int mode = NONE; mode <= AFTER; mode++) {
			struct airoha_ct_pon_ifc_owner saved;
			int result;

			open_cover(&fixture, path & 1);
			saved = fixture.ppe.ct_pon_ifc;
			mock.route_fail_at = mode ? 1 : 0;
			mock.route_fault = mode;
			result = path < 2 ? airoha_ct_ifc_cpu_port_change(&fixture.eth, path ? 24 : 2) :
				airoha_gdm_fwd_cfg_update(&fixture.eth, 2, 0xffff,
					(FE_PSE_PORT_PPE1 << 12) | (FE_PSE_PORT_PPE2 << 8) | 0x55);
			assert(result == (mode ? -EIO : 0));
			assert(!mock.commands && !memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
			assert(fixture.ppe.ct_pon_ifc_route_owned);
			if (mode) {
				assert(!mock.gate_clears && !fixture.eth.ct_ifc_cpu_port_failed);
				assert(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK);
				mock.route_fail_at = 0;
				assert(!airoha_ct_ifc_cpu_port_change(&fixture.eth, 2));
			}
			assert(mock.gate_clears == 1 && mock.cpu_acknowledgements);
			assert(mock.registers[REG_GDM_FWD_CFG(2) / 4] == 0xa5b65555);
			assert(!(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK));
			assert(store(&fixture, "off") == 3);
			check_restored(&fixture);
			cover_cases++;
			cases++;
		}
}

static void cover_stuck_shutdown(void)
{
	struct fixture fixture;
	struct airoha_ct_pon_ifc_owner saved;

	open_cover(&fixture, 0);
	saved = fixture.ppe.ct_pon_ifc;
	mock.cpu_route_stuck = true;
	assert(store(&fixture, "off") == -EIO);
	assert(!mock.gate_clears && !mock.commands);
	assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
	assert(fixture.ppe.ct_pon_ifc_route_owned && fixture.ppe.ct_pon_ifc_cover == 1);
	mock.cpu_route_stuck = false;
	assert(store(&fixture, "off") == 3);
	check_restored(&fixture);
	cover_route_faults++;
	cases++;
}

static void cover_publication_failures(void)
{
	struct fixture fixture;
	const unsigned int counts[] = { 126, 78, 78, 52, 104 };

	for (unsigned int operation = 0; operation < ARRAY_SIZE(counts); operation++)
		for (unsigned int slot = 0; slot < 2; slot++)
			for (unsigned int mode = BEFORE; mode <= DEFERRED; mode++)
				for (unsigned int failure = 1; failure <= counts[operation]; failure++) {
					char command[32];
					u16 services[2];
					unsigned int cover, data, control;

					if (!operation)
						initialize(&fixture);
					else if (operation == 1)
						prepare(&fixture);
					else
						open_cover(&fixture, slot);
					memcpy(services, fixture.ppe.ct_pon_ifc_services, sizeof(services));
					cover = fixture.ppe.ct_pon_ifc_cover;
					snprintf(command, sizeof(command), operation < 2 ? "cover %u" :
						 operation == 2 ? "set %u 0xa134" : operation == 3 ? "clear %u" : "off", slot);
					mock.fault = mode;
					mock.fail_at = failure;
					assert(store(&fixture, command) == -ETIMEDOUT);
					assert(mock.commands == failure && fixture.ppe.ct_pon_ifc.pending);
					assert(!fixture.ppe.ct_pon_ifc_route_owned);
					assert(fixture.ppe.ct_pon_ifc_cover == cover);
					assert(!memcmp(services, fixture.ppe.ct_pon_ifc_services, sizeof(services)));
					check_shadow(&fixture);
					data = mock.data_writes;
					control = mock.control_writes;
					assert(store(&fixture, "route") == -ESHUTDOWN);
					assert(store(&fixture, "off") == -ETIMEDOUT);
					assert(mock.data_writes == data && mock.control_writes == control);
					assert(fixture.ppe.ct_pon_ifc_cover == cover);
					mock.release = true;
					mock.fail_at = 0;
					assert(store(&fixture, "off") == 3);
					assert(!fixture.eth.ct_ifc_command_pending && !mock.busy);
					check_restored(&fixture);
					cover_publish_faults++;
					cases++;
				}
	for (unsigned int slot = 0; slot < 2; slot++) {
		char command[32];

		initialize(&fixture);
		mock.port_fail_first = mock.port_fail_last = 1;
		snprintf(command, sizeof(command), "cover %u", slot);
		assert(store(&fixture, command) == -EIO);
		assert(fixture.ppe.ct_pon_ifc_cover == BIT(slot));
		assert(fixture.ppe.ct_pon_ifc.active == (3 << (slot * 2)));
		assert(fixture.ppe.ct_pon_ifc.saved_valid && fixture.eth.ct_cpu_fallback);
		assert(store(&fixture, "route") == -ESHUTDOWN);
		assert(store(&fixture, "off") == 3);
		check_restored(&fixture);
		cover_publish_faults++;
		cases++;
	}
}

static void source_sweep(unsigned int mode)
{
	struct fixture fixture;
	const char *verb = mode == 0 ? "source" : mode == 1 ? "absent" : "only";
	char guarded_command[32];
	const char *invalid[] = { "", " -1", " 32", " 4294967295",
		" 4294967296", " nope", " 0 extra", " 0 1 2", " 0x20", " 1x" };

	snprintf(guarded_command, sizeof(guarded_command), "%s 24", verb);

	for (unsigned int source = 0; source < 32; source++) {
		char command[32];
		u32 peer[2][2][9][3];

		open_cover(&fixture, 1);
		for (unsigned int row = 0; row < 2; row++)
			for (unsigned int bank = 0; bank < 2; bank++)
				memcpy(peer[row][bank], mock.table[bank * 2][58 + row], sizeof(peer[row][bank]));
		mock.source_publish = true;
		snprintf(command, sizeof(command), "%s %u", verb, source);
		assert(store(&fixture, command) == (ssize_t)strlen(command));
		assert(mock.commands == 130 && mock.cpu_acknowledgements);
		assert(!fixture.ppe.ct_pon_ifc_route_owned && fixture.ppe.ct_pon_ifc_cover == 2);
		assert(fixture.ppe.ct_pon_ifc.active == 15 && fixture.ppe.ct_pon_ifc.dirty == 15);
		assert(!fixture.ppe.ct_pon_ifc_services[0] && !fixture.ppe.ct_pon_ifc_services[1]);
		for (unsigned int row = 0; row < 2; row++) {
			for (unsigned int sport = 0; sport < 32; sport++) {
				bool expected = mode == 0 || (mode == 1 ? sport != source : sport == source);

				assert(sif_matches(mock.table[0][56 + row][0][0],
						   mock.table[0][56 + row][0][1], sport) == expected);
				sif_match_cases++;
			}
			for (unsigned int page = 0; page < 9; page++) {
				assert(mock.table[0][56 + row][page][0] ==
				       (page == 0 ? (mode == 1 ? 0 : BIT(source)) : page == 8 ? row << 6 : 0));
				assert(mock.table[0][56 + row][page][1] ==
				       (page == 0 ? (mode == 2 ? UINT32_MAX : BIT(source)) : page == 8 ? 0xc0 : 0));
			}
			for (unsigned int page = 0; page < 3; page++)
				for (unsigned int word = 0; word < page_words(2, page); word++)
					assert(mock.table[2][56 + row][page][word] ==
					       (page == 1 && word == 2 ? 2U << 10 : page == 2 ? 0xd0000000 : 0));
			for (unsigned int bank = 0; bank < 2; bank++)
				assert(!memcmp(peer[row][bank], mock.table[bank * 2][58 + row], sizeof(peer[row][bank])));
		}
		check_shadow(&fixture);
		mock.source_publish = false;
		reset_counts();
		assert(store(&fixture, "route") == 5);
		assert(mock.commands == 24 && mock.audited[0] == 0 && mock.audited[1] == 0);
		assert(store(&fixture, "off") == 3);
		check_restored(&fixture);
		source_cases++;
		cases++;
	}
	for (unsigned int input = 0; input < ARRAY_SIZE(invalid); input++) {
		struct airoha_ct_pon_ifc_owner saved;
		char command[40];

		prepare_cover(&fixture, 1);
		saved = fixture.ppe.ct_pon_ifc;
		snprintf(command, sizeof(command), "%s%s", verb, invalid[input]);
		assert(store(&fixture, command) == -EINVAL);
		assert(!mock.commands && !mock.route_writes && !mock.port_writes);
		assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
		source_cases++;
		cases++;
	}
	for (unsigned int state = 0; state < 8; state++) {
		struct airoha_ct_pon_ifc_owner saved;

		if (state == 1)
			continue;
		open_cover(&fixture, 1);
		saved = fixture.ppe.ct_pon_ifc;
		fixture.ppe.ct_pon_ifc_cover = state & 1 ? 2 : 0;
		fixture.ppe.ct_fe.active = !!(state & 2);
		fixture.ppe.ct_pair_policy_allowed = !!(state & 4);
		assert(store(&fixture, guarded_command) == -EBUSY);
		assert(!mock.commands && !mock.route_writes && !mock.port_writes && !mock.gate_clears);
		assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
		assert(fixture.ppe.ct_pon_ifc_route_owned);
		source_cases++;
		cases++;
	}
	for (unsigned int state = 0; state < 8; state++) {
		if (state == 1)
			continue;
		prepare_cover(&fixture, 1);
		fixture.ppe.ct_pon_ifc_registered = !!(state & 1);
		fixture.ppe.ct_pon_ifc_work_stopping = !!(state & 2);
		fixture.ppe.ct_stopping = !!(state & 4);
		assert(store(&fixture, guarded_command) == -ESHUTDOWN);
		assert(!mock.commands && !mock.route_writes && !mock.port_writes);
		source_cases++;
		cases++;
	}
}

static void optical_sif_matches(void)
{
	struct fixture fixture;

	prepare(&fixture);
	for (unsigned int row = 56; row < 60; row++)
		for (unsigned int sport = 0; sport < 32; sport++) {
			assert(mock.table[0][row][0][1] == UINT32_MAX);
			assert(sif_matches(mock.table[0][row][0][0], mock.table[0][row][0][1], sport) ==
			       (sport == 2));
			sif_match_cases++;
		}
	for (unsigned int slot = 0; slot < 2; slot++) {
		char command[16];

		snprintf(command, sizeof(command), "cover %u", slot);
		assert(store(&fixture, command) == (ssize_t)strlen(command));
	}
	for (unsigned int row = 56; row < 60; row++)
		for (unsigned int sport = 0; sport < 32; sport++) {
			assert(sif_matches(mock.table[0][row][0][0], mock.table[0][row][0][1], sport) ==
			       (sport == 2));
			sif_match_cases++;
		}
	assert(store(&fixture, "off") == 3);
	check_restored(&fixture);
}

static void source_invalid_api(void)
{
	struct fixture fixture;
	const unsigned int sources[] = { 0, 31, 32, UINT_MAX };
	const unsigned int modes[] = { 0, 1, 2, 3, 4, UINT_MAX };

	for (unsigned int source = 0; source < ARRAY_SIZE(sources); source++)
		for (unsigned int mode = 0; mode < ARRAY_SIZE(modes); mode++) {
			struct airoha_ct_pon_ifc_owner saved;

			if (sources[source] <= 31 && modes[mode] <= 2)
				continue;
			open_cover(&fixture, 1);
			saved = fixture.ppe.ct_pon_ifc;
			assert(airoha_ct_pon_ifc_source_set(&fixture.ppe, sources[source], modes[mode]) == -EINVAL);
			assert(!mock.commands && !mock.route_writes && !mock.port_writes && !mock.gate_clears);
			assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
			assert(fixture.ppe.ct_pon_ifc_route_owned && fixture.ppe.ct_pon_ifc_cover == 2);
			source_cases++;
			cases++;
		}
}

static void source_publish_failures(unsigned int encoding)
{
	struct fixture fixture;
	const char *verb = encoding == 0 ? "source" : encoding == 1 ? "absent" : "only";

	for (unsigned int source = 0; source <= 31; source += 31)
		for (unsigned int mode = BEFORE; mode <= DEFERRED; mode++)
			for (unsigned int failure = 1; failure <= 130; failure++) {
				char command[32];
				u32 peer[2][2][9][3];
				unsigned int data, control;

				open_cover(&fixture, 1);
				for (unsigned int row = 0; row < 2; row++)
					for (unsigned int bank = 0; bank < 2; bank++)
						memcpy(peer[row][bank], mock.table[bank * 2][58 + row], sizeof(peer[row][bank]));
				mock.source_publish = true;
				mock.fail_at = failure;
				mock.fault = mode;
				snprintf(command, sizeof(command), "%s %u", verb, source);
				assert(store(&fixture, command) == -ETIMEDOUT);
				assert(mock.commands == failure && fixture.ppe.ct_pon_ifc.pending);
				assert(fixture.ppe.ct_pon_ifc.saved_valid && fixture.ppe.ct_pon_ifc.dirty);
				assert(fixture.ppe.ct_pon_ifc_cover == 2 && !fixture.ppe.ct_pon_ifc_route_owned);
				assert((fixture.ppe.ct_pon_ifc.active & 12) == 12);
				assert(fixture.ppe.ct_pon_ifc_services[0] == (failure <= 78 ? 0x2134 : 0));
				for (unsigned int row = 0; row < 2; row++)
					for (unsigned int bank = 0; bank < 2; bank++)
						assert(!memcmp(peer[row][bank], mock.table[bank * 2][58 + row], sizeof(peer[row][bank])));
				check_shadow(&fixture);
				data = mock.data_writes;
				control = mock.control_writes;
				assert(store(&fixture, command) == -ESHUTDOWN);
				assert(store(&fixture, "off") == -ETIMEDOUT);
				assert(mock.data_writes == data && mock.control_writes == control);
				mock.source_publish = false;
				mock.release = true;
				mock.fail_at = 0;
				assert(store(&fixture, "off") == 3);
				check_restored(&fixture);
				source_faults++;
				cases++;
			}
}

#if PROBE_HAVE_TUPLE
#include "verify_ifc_probe_tuple.c"
#endif

int main(int argc, char **argv)
{
	if (argc == 2) {
#if PROBE_HAVE_TUPLE
		if (!strcmp(argv[1], "tuple")) {
			tuple_tests();
			return 0;
		}
#endif
		assert(!strcmp(argv[1], "stuck-route"));
		cover_stuck_shutdown();
		puts("{\"passed\":true,\"stuck_route_cases\":1}");
		return 0;
	}
	assert(argc == 1);
	source_port_mapping();
	lifecycle();
	route_and_inputs();
	dependency_failures();
	io_failures();
	readback_failures();
	scope_and_route_failures();
	shared_transport();
	scope_interoperation();
	fallback_stop();
	store_dispatch();
	store_stopping_off();
	cover_lifecycle();
	cover_tampering();
	cover_route_guards();
	cover_audit_failures();
	cover_route_failures();
	cover_shutdown_order();
	cover_publication_failures();
	optical_sif_matches();
	source_invalid_api();
	for (unsigned int mode = 0; mode < 3; mode++) {
		source_sweep(mode);
		source_publish_failures(mode);
	}
	printf("{\"passed\":true,\"cases\":%u,\"transport_faults\":%u,\"blocked_retries\":%u,"
	       "\"dependency_faults\":%u,\"readback_faults\":%u,\"scope_cases\":%u,"
	       "\"fallback_stop_cases\":%u,\"rejected_set_retries\":%u,"
	       "\"sport_cases\":%u,\"sport_close_cases\":%u,\"store_dispatch_cases\":%u,"
	       "\"store_stop_cases\":%u,\"store_pending_cases\":%u,"
	       "\"cover_cases\":%u,\"cover_tamper_cases\":%u,\"cover_route_faults\":%u,\"cover_io_faults\":%u,"
	       "\"cover_publish_faults\":%u,\"source_cases\":%u,\"source_faults\":%u,\"sif_match_cases\":%u}\n",
	       cases, transport_faults, blocked_retries, dependency_faults, readback_faults,
	       scope_cases, fallback_stop_cases, rejected_set_retries, sport_cases, sport_close_cases,
	       store_dispatch_cases, store_stop_cases, store_pending_cases,
	       cover_cases, cover_tamper_cases, cover_route_faults, cover_io_faults, cover_publish_faults,
	       source_cases, source_faults, sif_match_cases);
	return 0;
}
