#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EUCLEAN
#define EUCLEAN 117
#endif
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define BIT(index) (UINT32_C(1) << (index))
#define GENMASK(high, low) ((UINT32_MAX >> (31 - (high))) & (UINT32_MAX << (low)))
#define U32_MAX UINT32_MAX
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ARRAY_SIZE(value) (sizeof(value) / sizeof((value)[0]))
#include "airoha_npu_ingress.h"

static unsigned int checks, scenarios, faults;
#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
		abort(); \
	} \
} while (0)

static unsigned int ppe_lock, flow_offload_mutex = 1;
#define lockdep_assert_held(lock) CHECK(*(lock) == 1)
#define spin_lock_bh(lock) do { CHECK(!*(lock)); ++*(lock); } while (0)
#define spin_unlock_bh(lock) do { CHECK(*(lock) == 1); --*(lock); } while (0)

struct iphdr { u8 bytes[20]; };
#include "guard_constants.inc"

struct airoha_eth {
	bool ct_cpu_fallback, ct_ifc_cpu_port_failed, closed, receiver_ready;
	u32 udf;
};
struct airoha_ppe {
	struct airoha_eth *eth;
	struct airoha_npu_owner *ct_npu_owner;
	bool ct_host_ppe, ct_stopping, legacy_busy;
	struct {
		bool cfg_owned;
		struct { unsigned int lut_index; bool lut_dirty; } rule[2];
	} ct_ifc;
	struct airoha_ct_pon_ifc_owner ct_pon_ifc;
};
struct airoha_npu_owner {
	struct airoha_ppe *ppe;
	struct airoha_ct_pon_ifc_owner ingress;
	bool invalidated;
};
static struct {
	struct airoha_eth eth;
	struct airoha_ppe ppe;
	struct airoha_npu_owner owner;
	u32 tcam[64][9][2], action[64][3][3], lut[32][2];
	unsigned int commands, writes, fail_at, drop_at, corrupt_at;
	bool pending, drain_fails;
} state;

static u32 airoha_fe_rr(struct airoha_eth *eth, unsigned int reg)
{
	CHECK(reg == CT_IFC_UDF0);
	return eth->udf;
}

static int airoha_ct_fe_table(struct airoha_ppe *ppe, unsigned int bank,
			     unsigned int row, unsigned int page, bool write,
			     u32 *words, unsigned int count)
{
	u32 *location;
	bool fail;

	lockdep_assert_held(&ppe_lock);
	CHECK(ppe == &state.ppe && !state.pending && count && count <= 3);
	CHECK(bank <= 2 && row < 64);
	if (!bank) {
		CHECK(page < 9 && count == 2);
		location = state.tcam[row][page];
	} else if (bank == 1) {
		CHECK(row < 32 && !page && count == 2 && !write);
		location = state.lut[row];
	} else {
		CHECK(page < 3 && count == ct_ifc_action_words[page]);
		location = state.action[row][page];
	}
	if (write) {
		CHECK(state.eth.closed && row >= 56 && row < 58);
		CHECK(state.owner.ingress.saved_valid && state.owner.ingress.dirty);
		++state.writes;
	}
	++state.commands;
	fail = state.commands == state.fail_at;
	if (!fail && state.commands != state.drop_at) {
		if (write)
			memcpy(location, words, count * sizeof(u32));
		else {
			memcpy(words, location, count * sizeof(u32));
			if (state.commands == state.corrupt_at)
				words[0] ^= BIT(24);
		}
	}
	if (fail) {
		state.pending = true;
		return -ETIMEDOUT;
	}
	return 0;
}

static int airoha_ct_ifc_command_drain(struct airoha_eth *eth)
{
	lockdep_assert_held(&ppe_lock);
	CHECK(eth == &state.eth);
	if (state.drain_fails)
		return -EAGAIN;
	state.pending = false;
	return 0;
}

static bool airoha_ct_pon_ifc_busy(struct airoha_ppe *ppe)
{
	return ppe->legacy_busy;
}

static bool airoha_ct_pon_ifc_route_ready(struct airoha_ppe *ppe)
{
	return ppe->eth->receiver_ready;
}

static int airoha_bank1_routes_check(struct airoha_eth *eth,
				     const void *owner, bool opened)
{
	CHECK(owner == &state.owner && eth == &state.eth);
	return eth->closed == !opened ? 0 : -ESTALE;
}

#include "guard_dependencies.inc"
#include "airoha_npu_ingress_owner.h"

static void initialize(void)
{
	memset(&state, 0, sizeof(state));
	state.ppe.eth = &state.eth;
	state.owner.ppe = &state.ppe;
	state.ppe.ct_npu_owner = &state.owner;
	state.ppe.ct_host_ppe = state.ppe.ct_ifc.cfg_owned = true;
	state.eth.closed = state.eth.receiver_ready = true;
	for (unsigned int family = 0; family < 2; ++family) {
		unsigned int slot = 31 - family, row = CT_IFC_RULE(family);

		state.ppe.ct_ifc.rule[family].lut_index = slot;
		state.ppe.ct_ifc.rule[family].lut_dirty = true;
		state.eth.udf |= (u32)ct_ifc_guard[family].udf << (family * 16);
		state.lut[slot][0] = ct_ifc_guard[family].max << 16 | ct_ifc_guard[family].min;
		state.lut[slot][1] = CT_IFC_LUT1_ENABLE | CT_IFC_LUT1_END |
			CT_IFC_LUT1_RANGE | (CT_IFC_LUT1_UDF0 + family);
		state.tcam[row][4][0] = state.tcam[row][4][1] = BIT(slot);
		state.tcam[row][8][0] = CT_IFC_TCAM_TYPE1 | ct_ifc_guard[family].valid;
		state.tcam[row][8][1] = CT_IFC_TCAM_TYPE_MASK | ct_ifc_guard[family].valid;
		state.action[row][1][2] = CT_IFC_CPU_RX_RING << 10;
		state.action[row][2][0] = CT_IFC_ACTION_ENABLE | CT_IFC_ACTION_STOP |
			CT_IFC_ACTION_FORCE_CPU;
	}
	for (unsigned int row = 56; row < 60; ++row)
		state.tcam[row][0][0] = row;
	++scenarios;
}

static void restored(void)
{
	CHECK(!airoha_npu_owner_ingress_restore(&state.owner));
	CHECK(!state.owner.ingress.saved_valid && !state.owner.ingress.pending &&
	      !state.owner.ingress.active && !state.owner.ingress.dirty);
	CHECK(!state.ppe.ct_pon_ifc.pending && !state.ppe.ct_pon_ifc.saved_valid);
	for (unsigned int row = 56; row < 60; ++row) {
		CHECK(state.tcam[row][0][0] == row);
		CHECK(!state.action[row][2][0]);
	}
}

static unsigned int prepare_success(void)
{
	CHECK(!airoha_npu_owner_ingress_prepare(&state.owner));
	CHECK(state.owner.ingress.active == 3 && state.owner.ingress.dirty == 3);
	CHECK(!state.owner.ingress.pending && !state.ppe.ct_pon_ifc.pending);
	return state.commands;
}

static void transport_faults(void)
{
	unsigned int prepare_commands, check_commands, restore_commands;

	initialize();
	prepare_commands = prepare_success();
	state.commands = 0;
	CHECK(!airoha_npu_owner_ingress_check(&state.owner));
	check_commands = state.commands;
	state.commands = 0;
	restored();
	restore_commands = state.commands;
	for (unsigned int command = 1; command <= prepare_commands; ++command) {
		initialize();
		state.fail_at = command;
		CHECK(airoha_npu_owner_ingress_prepare(&state.owner) == -ETIMEDOUT);
		CHECK(state.owner.ingress.pending && !state.ppe.ct_pon_ifc.pending);
		state.drain_fails = true;
		CHECK(airoha_npu_owner_ingress_restore(&state.owner) == -EAGAIN);
		CHECK(state.owner.ingress.pending && state.commands == command);
		state.drain_fails = false;
		state.fail_at = 0;
		restored();
		++faults;
	}
	for (unsigned int command = 1; command <= check_commands; ++command) {
		initialize();
		prepare_success();
		state.commands = 0;
		state.fail_at = command;
		state.eth.closed = false;
		CHECK(airoha_npu_owner_ingress_check(&state.owner) == -ETIMEDOUT);
		CHECK(state.owner.ingress.pending && !state.ppe.ct_pon_ifc.pending);
		state.eth.closed = true;
		state.fail_at = 0;
		restored();
		++faults;
	}
	for (unsigned int command = 1; command <= restore_commands; ++command) {
		initialize();
		prepare_success();
		state.commands = 0;
		state.fail_at = command;
		CHECK(airoha_npu_owner_ingress_restore(&state.owner) == -ETIMEDOUT);
		CHECK(state.owner.ingress.saved_valid && state.owner.ingress.pending);
		CHECK(!state.ppe.ct_pon_ifc.pending);
		state.fail_at = 0;
		restored();
		++faults;
	}
}

static void dependency_drift(void)
{
	for (unsigned int family = 0; family < 2; ++family) {
		for (unsigned int field = 0; field < 22; ++field) {
			unsigned int row = CT_IFC_RULE(family), slot = 31 - family;

			initialize();
			prepare_success();
			if (field < 2)
				state.lut[slot][field] ^= 1;
			else if (field < 20)
				state.tcam[row][(field - 2) / 2][(field - 2) % 2] ^=
					(field % 2 ? 1 : state.tcam[row][(field - 2) / 2][1]);
			else if (field == 20)
				state.eth.udf ^= BIT(family * 16);
			else
				state.ppe.ct_ifc.rule[family].lut_dirty = false;
			if (field >= 2 && field < 20 && !(field % 2) &&
			    !state.tcam[row][(field - 2) / 2][1])
				continue;
			CHECK(airoha_npu_owner_ingress_check(&state.owner) == -EUCLEAN);
			restored();
		}
		for (unsigned int page = 0; page < 3; ++page)
			for (unsigned int word = 0; word < ct_ifc_action_words[page]; ++word) {
				initialize();
				prepare_success();
				state.action[CT_IFC_RULE(family)][page][word] ^= 1;
				CHECK(airoha_npu_owner_ingress_check(&state.owner) == -EUCLEAN);
				restored();
			}
	}
}

static void owner_guards(void)
{
	for (unsigned int fault = 0; fault < 10; ++fault) {
		initialize();
		switch (fault) {
		case 0: state.ppe.ct_npu_owner = NULL; break;
		case 1: state.owner.invalidated = true; break;
		case 2: state.ppe.ct_ifc.cfg_owned = false; break;
		case 3: state.ppe.ct_host_ppe = false; break;
		case 4: state.ppe.ct_stopping = true; break;
		case 5: state.eth.ct_cpu_fallback = true; break;
		case 6: state.eth.ct_ifc_cpu_port_failed = true; break;
		case 7: state.ppe.legacy_busy = true; break;
		case 8: state.eth.receiver_ready = false; break;
		case 9: state.eth.closed = false; break;
		}
		CHECK(airoha_npu_owner_ingress_prepare(&state.owner) < 0);
		CHECK(!state.commands && !state.owner.ingress.saved_valid);
	}
	initialize();
	state.ppe.ct_ifc.rule[1].lut_index = 31;
	CHECK(airoha_npu_owner_ingress_prepare(&state.owner) == -EUCLEAN);
	CHECK(!state.commands);
	initialize();
	prepare_success();
	state.owner.invalidated = state.ppe.ct_stopping = state.eth.ct_cpu_fallback = true;
	state.ppe.ct_host_ppe = state.ppe.ct_ifc.cfg_owned = false;
	restored();
}

static void exact_readback(void)
{
	u32 words[2] = { 0, 0 };

	initialize();
	state.owner.ingress.saved_valid = true;
	state.owner.ingress.dirty = 3;
	spin_lock_bh(&ppe_lock);
	state.corrupt_at = 2;
	CHECK(airoha_npu_owner_ingress_put(&state.owner, 0, 56, 0, words, 2) == -EIO);
	CHECK(state.owner.ingress.pending && !state.ppe.ct_pon_ifc.pending);
	spin_unlock_bh(&ppe_lock);
	initialize();
	state.owner.ingress.saved_valid = true;
	state.owner.ingress.dirty = 3;
	state.drop_at = 1;
	spin_lock_bh(&ppe_lock);
	CHECK(airoha_npu_owner_ingress_put(&state.owner, 0, 56, 0, words, 2) == -EIO);
	CHECK(airoha_npu_owner_ingress_put(&state.owner, 0, 56, 0, words, 0) == -EINVAL);
	CHECK(airoha_npu_owner_ingress_put(&state.owner, 0, 56, 0, words, 4) == -EINVAL);
	spin_unlock_bh(&ppe_lock);
}

int main(void)
{
	transport_faults();
	dependency_drift();
	owner_guards();
	exact_readback();
	printf("{\"passed\":true,\"scenarios\":%u,\"checks\":%u,\"transport_faults\":%u}\n",
	       scenarios, checks, faults);
	return 0;
}
