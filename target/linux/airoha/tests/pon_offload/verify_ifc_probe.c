#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
#define FE_PSE_PORT_CDM1 1
#define FE_PSE_PORT_CDM2 2
#define FE_PSE_PORT_PPE1 4
#define FE_PSE_PORT_PPE2 5
#define FE_PSE_PORT_DROP 15
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

struct lock { bool held; unsigned int rank; };
static struct lock ppe_lock = { .rank = 1 }, flow_offload_mutex;
static struct lock *lock_stack[3];
static unsigned int lock_depth;
static bool rtnl;
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
struct work { unsigned int scheduled; };
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
	bool ct_cpu_fallback, ct_cpu_routes_ready, ct_cpu_ifc_disabled, ct_ordinary_full_test;
};
struct airoha_ppe {
	struct airoha_eth *eth;
	struct airoha_ct_pon_ifc_owner ct_pon_ifc;
	struct { bool cfg_owned; struct { u32 lut_index; bool lut_dirty; } rule[2]; } ct_ifc;
	struct { bool health_stopping; struct work health_work; } ct_fe;
	struct work ct_pon_ifc_work;
	u16 ct_pon_ifc_services[2];
	u32 ct_pon_ifc_errors;
	bool ct_host_ppe, ct_stopping, ct_pon_qualified, ct_native_pairs;
	bool ct_pon_ifc_registered, ct_pon_ifc_work_stopping;
};
enum fault { NONE, BEFORE, AFTER, DEFERRED, READBACK };
struct simulation {
	u32 table[3][64][9][3], registers[0x900 / 4];
	u32 original[4][2][9][3], command;
	unsigned int commands, data_writes, control_writes, fail_at, port_writes, table_writes;
	unsigned int port_fail_first, port_fail_last, gate_clears;
	unsigned int route_reads;
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
	for (unsigned int word = 0; word < count; word++) {
		if (mock.command & BIT(1))
			mock.table[bank][row][page][word] = mock.registers[CT_IFC_DATA(word) / 4];
		else
			mock.registers[CT_IFC_DATA(word) / 4] = mock.table[bank][row][page][word];
	}
	if (mock.command & BIT(1))
		mock.table_writes++;
	mock.late = false;
}

static u32 airoha_fe_rr(struct airoha_eth *eth, unsigned int address)
{
	(void)eth;
	assert(address / 4 < ARRAY_SIZE(mock.registers));
	if (address == REG_SP_DFT_CPORT(0) && ++mock.route_reads == 2 && mock.route_drop)
		return 0;
	if (address == CT_IFC_CONTROL) {
		if (mock.busy && mock.release) {
			if (mock.late)
				complete_command();
			mock.busy = false;
		}
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
		if ((value & BIT(1)) && mock.require_gate_closed)
			assert(!(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK));
		mock.commands++;
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
	} else if (address == REG_GDM_FWD_CFG(2) && eth->ct_ifc_pon_ready &&
		   ((value ^ mock.registers[address / 4]) & 0xffff)) {
		assert(!(mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK));
	}
	mock.registers[address / 4] = value;
}

static void airoha_fe_clear(struct airoha_eth *eth, unsigned int address, u32 mask)
{
	assert(eth->ct_route_lock.held);
	if (address == REG_FE_CSR_IFC_CFG)
		mock.gate_clears++;
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
	assert(!ppe_lock.held && !rcu_depth && !lock_depth);
	flow_offload_mutex.held = rtnl = true;
	fixture->eth.ppe = &fixture->ppe;
	fixture->eth.ct_route_lock.rank = 2;
	fixture->eth.ifc_port_lock.rank = 3;
	fixture->ppe.eth = &fixture->eth;
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
	mock.commands = mock.data_writes = mock.control_writes = mock.table_writes = 0;
	mock.port_writes = mock.fail_at = mock.route_reads = mock.gate_clears = 0;
	mock.fault = NONE;
	mock.release = false;
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
	assert(!fixture->ppe.ct_pon_ifc.saved_valid && !fixture->ppe.ct_pon_ifc.dirty &&
	       !fixture->ppe.ct_pon_ifc.active && !fixture->ppe.ct_pon_ifc.pending);
	assert(!fixture->eth.ct_ifc_pon_ready && !fixture->ppe.ct_pon_ifc_services[0] &&
	       !fixture->ppe.ct_pon_ifc_services[1]);
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
				if (operation == SET_INITIAL && position <= 74) {
					u32 words[2];
					assert(fixture.eth.ct_ifc_command_pending);
					assert(!ct_ifc_access(&fixture.eth, 0, 56, 0, false, words, 2));
				}
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
		assert(airoha_ct_pon_ifc_cpu_stop(&fixture.ppe) == (stopping ? 0 : -ESHUTDOWN));
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
		assert(airoha_ct_pon_ifc_cpu_stop(&fixture.ppe) == (failed ? -ESHUTDOWN : 0));
		check_restored(&fixture);
		prepare(&fixture);
		mock.gate_stuck = failed;
		assert(airoha_gdm_fwd_cfg_update(&fixture.eth, 2, 0xffff, 0x1111) == (failed ? -EIO : 0));
		assert(mock.registers[REG_GDM_FWD_CFG(2) / 4] == (failed ? 0x2222U : 0x1111U));
		assert(fixture.eth.ct_ifc_cpu_port_failed);
		mock.gate_stuck = false;
		assert(airoha_ct_pon_ifc_cpu_stop(&fixture.ppe) == (failed ? -ESHUTDOWN : 0));
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
		assert(airoha_ct_pon_ifc_cpu_stop(&fixture.ppe) == (failure == 2 ? -ETIMEDOUT : -ESHUTDOWN));
		assert(mock.gate_clears && !mock.port_writes);
		assert(fixture.eth.ct_ifc_port_mask == (XSI_ETH_VIP_PORT_MASK | BIT(2)));
		assert(fixture.eth.ifc_port_desired == (XSI_ETH_VIP_PORT_MASK | BIT(2)));
		if (failure == 1) {
			assert(!mock.commands && !memcmp(&saved, &fixture.ppe.ct_pon_ifc, sizeof(saved)));
			assert(!memcmp(services, fixture.ppe.ct_pon_ifc_services, sizeof(services)));
			assert(fixture.eth.ct_ifc_pon_ready && (mock.registers[REG_FE_CSR_IFC_CFG / 4] & FE_IFC_EN_MASK));
			mock.gate_stuck = false;
			assert(airoha_ct_pon_ifc_cpu_stop(&fixture.ppe) == -ESHUTDOWN);
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
		assert(airoha_ct_pon_ifc_cpu_stop(&fixture.ppe) == (failed ? -ESHUTDOWN : 0));
		check_restored(&fixture);
		sport_close_cases++;
		cases++;
	}
}

int main(void)
{
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
	printf("{\"passed\":true,\"cases\":%u,\"transport_faults\":%u,\"blocked_retries\":%u,"
	       "\"dependency_faults\":%u,\"readback_faults\":%u,\"scope_cases\":%u,"
	       "\"fallback_stop_cases\":%u,\"rejected_set_retries\":%u,"
	       "\"sport_cases\":%u,\"sport_close_cases\":%u}\n",
	       cases, transport_faults, blocked_retries, dependency_faults, readback_faults,
	       scope_cases, fallback_stop_cases, rejected_set_retries, sport_cases, sport_close_cases);
	return 0;
}
