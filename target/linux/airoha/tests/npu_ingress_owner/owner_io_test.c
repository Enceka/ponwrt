#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
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
static unsigned int ignored_key_bits, rejected_key_bits, rejected_mask_bits, rejected_action_bits;
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
	bool selector_cpu;
	void *dev;
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
	void *diag_lower;
	bool invalidated;
};
static struct {
	struct airoha_eth eth;
	struct airoha_ppe ppe;
	struct airoha_npu_owner owner;
	u32 tcam[64][9][3], action[64][3][3], lut[32][2];
	u32 original_tcam[4][9][3], original_action[4][3][3];
	unsigned int commands, writes, fail_at, drop_at, corrupt_at;
	bool pending, drain_fails;
	bool normalize_tcam, allow_tcam_shape;
	u32 unused_key_pattern, read_xor[3];
	unsigned int diagnostic_logs;
} state;

static void dev_err(void *device, const char *format, ...)
	__attribute__((format(printf, 2, 3)));
static void dev_err(void *device, const char *format, ...)
{
	char message[384];
	va_list arguments;

	CHECK(device == state.eth.dev);
	va_start(arguments, format);
	CHECK(vsnprintf(message, sizeof(message), format, arguments) > 0);
	va_end(arguments);
	CHECK(strstr(message, "PON diagnostic IFC mismatch:") != NULL);
	++state.diagnostic_logs;
}

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
		CHECK(page < 9 && (count == 2 || state.allow_tcam_shape));
		location = state.tcam[row][page];
	} else if (bank == 1) {
		CHECK(row < 32 && !page && count == 2 && !write);
		location = state.lut[row];
	} else {
		CHECK(page < 3 && count == ct_ifc_action_words[page]);
		location = state.action[row][page];
	}
	if (write) {
		CHECK(state.eth.closed && row >= 56 && row < 60);
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
			if (!bank && state.normalize_tcam && count == 2)
				words[0] = (words[0] & words[1]) | (state.unused_key_pattern & ~words[1]);
			if (state.commands == state.corrupt_at)
				words[0] ^= BIT(24);
			for (unsigned int word = 0; word < count; ++word)
				words[word] ^= state.read_xor[word];
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

static bool airoha_ct_pon_ifc_receiver_ready(struct airoha_ppe *ppe)
{
	return ppe->eth->receiver_ready;
}

static bool airoha_ct_pon_ifc_route_ready(struct airoha_ppe *ppe)
{
	return airoha_ct_pon_ifc_receiver_ready(ppe) && ppe->eth->selector_cpu;
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
	state.eth.dev = &state.eth;
	state.owner.ppe = &state.ppe;
	state.ppe.ct_npu_owner = &state.owner;
	state.ppe.ct_host_ppe = state.ppe.ct_ifc.cfg_owned = true;
	state.eth.closed = state.eth.receiver_ready = true;
	state.eth.selector_cpu = true;
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
	for (unsigned int row = 56; row < 60; ++row) {
		for (unsigned int page = 0; page < 9; ++page)
			state.tcam[row][page][0] = row << 16 | page;
		for (unsigned int page = 0; page < 3; ++page)
			for (unsigned int word = 0; word < ct_ifc_action_words[page]; ++word)
				state.action[row][page][word] = 0x23450000 | row << 8 | page << 4 | word;
	}
	memcpy(state.original_tcam, &state.tcam[56], sizeof(state.original_tcam));
	memcpy(state.original_action, &state.action[56], sizeof(state.original_action));
	++scenarios;
}

static void restored(void)
{
	CHECK(!airoha_npu_owner_ingress_restore(&state.owner));
	CHECK(!state.owner.ingress.saved_valid && !state.owner.ingress.pending &&
	      !state.owner.ingress.active && !state.owner.ingress.dirty);
	CHECK(!state.ppe.ct_pon_ifc.pending && !state.ppe.ct_pon_ifc.saved_valid);
	CHECK(!memcmp(&state.tcam[56], state.original_tcam, sizeof(state.original_tcam)));
	CHECK(!memcmp(&state.action[56], state.original_action, sizeof(state.original_action)));
}

static unsigned int prepare_success(void)
{
	CHECK(!airoha_npu_owner_ingress_prepare(&state.owner));
	CHECK(state.owner.ingress.active == 15 && state.owner.ingress.dirty == 15);
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

static void receiver_and_cover_health(void)
{
	initialize();
	prepare_success();
	state.eth.closed = state.eth.selector_cpu = false;
	CHECK(!airoha_ct_pon_ifc_route_ready(&state.ppe));
	CHECK(airoha_ct_pon_ifc_receiver_ready(&state.ppe));
	CHECK(!airoha_npu_owner_ingress_check(&state.owner));
	state.eth.receiver_ready = false;
	state.commands = 0;
	CHECK(airoha_npu_owner_ingress_check(&state.owner) == -ESHUTDOWN);
	CHECK(!state.commands && state.owner.ingress.active == 15);
	state.eth.closed = true;
	restored();
	for (unsigned int row = 58; row < 60; ++row)
		for (unsigned int field = 0; field < 8; ++field) {
			initialize();
			prepare_success();
			state.eth.closed = state.eth.selector_cpu = false;
			switch (field) {
			case 0: state.tcam[row][1][0] ^= U32_MAX; break;
			case 1: state.tcam[row][1][1] ^= 1; break;
			case 2: state.tcam[row][0][0] ^= BIT(2); break;
			case 3: state.tcam[row][8][0] ^= BIT(6); break;
			case 4: state.action[row][1][2] ^= BIT(10); break;
			case 5: state.action[row][2][0] ^= BIT(28); break;
			case 6: state.action[row][2][0] ^= BIT(31); break;
			case 7: state.action[row][2][0] ^= BIT(30); break;
			}
			CHECK(airoha_npu_owner_ingress_check(&state.owner) == (field ? -EUCLEAN : 0));
			CHECK(state.owner.ingress.active == 15 && state.owner.ingress.dirty == 15);
			CHECK(!state.owner.ingress.pending && !state.ppe.ct_pon_ifc.pending);
			state.eth.closed = true;
			restored();
		}
}

static void exact_readback(void)
{
	u32 words[2] = { 0, U32_MAX };

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

static void masked_put_readback(void)
{
	const unsigned int short_lut[2] = { 31, 30 };
	struct airoha_ct_pon_ifc_words rows[4];

	CHECK(!airoha_npu_ingress_rows(rows, short_lut));
	airoha_ct_pon_ifc_cover_encode(&rows[2], 4, 0);
	airoha_ct_pon_ifc_cover_encode(&rows[3], 4, 1);
	for (unsigned int row = 0; row < 4; ++row)
		for (unsigned int bank = 0; bank <= 2; bank += 2)
			for (unsigned int page = 0; page < (bank ? 3 : 9); ++page) {
				const u32 *words = bank ? rows[row].action[page] : rows[row].tcam[page];
				unsigned int count = bank ? ct_ifc_action_words[page] : 2;

				for (unsigned int word = 0; word < count; ++word)
					for (unsigned int bit = 0; bit < 32; ++bit) {
						bool significant = bank || word || (words[1] & BIT(bit));

						initialize();
						state.owner.ingress.saved_valid = true;
						state.owner.ingress.dirty = 15;
						state.owner.diag_lower = bit & 1 ? &state : NULL;
						state.read_xor[word] = BIT(bit);
						spin_lock_bh(&ppe_lock);
						CHECK(airoha_npu_owner_ingress_put(&state.owner, bank, 56 + row,
						      page, words, count) == (significant ? -EIO : 0));
						spin_unlock_bh(&ppe_lock);
						CHECK(state.owner.ingress.pending == significant);
						CHECK(!state.ppe.ct_pon_ifc.pending && !state.pending && !ppe_lock);
						CHECK(state.diagnostic_logs == (unsigned int)(significant && (bit & 1)));
						if (bank) ++rejected_action_bits;
						else if (word) ++rejected_mask_bits;
						else if (significant) ++rejected_key_bits;
						else ++ignored_key_bits;
					}
			}
	for (unsigned int count = 0; count <= 4; ++count) {
		u32 words[4] = {};

		if (count == 2)
			continue;
		initialize();
		state.allow_tcam_shape = true;
		state.owner.ingress.saved_valid = true;
		state.owner.ingress.dirty = 3;
		spin_lock_bh(&ppe_lock);
		CHECK(airoha_npu_owner_ingress_put(&state.owner, 0, 56, 1, words, count) ==
		      (!count || count > 3 ? -EINVAL : -EIO));
		spin_unlock_bh(&ppe_lock);
		CHECK(state.commands == (!count || count > 3 ? 0 : 2));
		CHECK(state.owner.ingress.pending == (count == 1 || count == 3));
		CHECK(!state.ppe.ct_pon_ifc.pending && !state.pending);
	}
}

static void normalized_owner_lifecycle(void)
{
	const u32 patterns[] = { U32_MAX, 0, 0xa5a5a5a5 };

	for (unsigned int pattern = 0; pattern < 3; ++pattern) {
		u32 actual[2];

		initialize();
		state.normalize_tcam = true;
		state.unused_key_pattern = patterns[pattern];
		state.owner.diag_lower = &state;
		prepare_success();
		CHECK(!state.tcam[56][1][0] && !state.tcam[56][1][1]);
		spin_lock_bh(&ppe_lock);
		CHECK(!airoha_npu_owner_ingress_read(&state.owner, 0, 56, 1, actual, 2));
		spin_unlock_bh(&ppe_lock);
		CHECK(actual[0] == patterns[pattern] && !actual[1]);
		for (unsigned int row = 0; row < 4; ++row)
			for (unsigned int page = 0; page < 9; ++page) {
				const u32 *words = state.owner.ingress.saved[row].tcam[page];

				CHECK(words[0] == patterns[pattern] && !words[1]);
			}
		state.eth.closed = false;
		CHECK(!airoha_npu_owner_ingress_check(&state.owner));
		state.eth.closed = true;
		prepare_success();
		CHECK(!state.diagnostic_logs && !state.owner.ingress.pending);
		CHECK(!airoha_npu_owner_ingress_restore(&state.owner));
		CHECK(!state.owner.ingress.saved_valid && !state.owner.ingress.dirty &&
		      !state.owner.ingress.active && !state.owner.ingress.pending);
		for (unsigned int row = 56; row < 60; ++row) {
			for (unsigned int page = 0; page < 9; ++page)
				CHECK(state.tcam[row][page][0] == patterns[pattern] && !state.tcam[row][page][1]);
		}
		CHECK(!memcmp(&state.action[56], state.original_action, sizeof(state.original_action)));
		CHECK(!airoha_npu_owner_ingress_restore(&state.owner));
		CHECK(!state.ppe.ct_pon_ifc.pending && !ppe_lock);
	}
}

int main(void)
{
	normalized_owner_lifecycle();
	masked_put_readback();
	transport_faults();
	dependency_drift();
	owner_guards();
	receiver_and_cover_health();
	exact_readback();
	printf("{\"passed\":true,\"scenarios\":%u,\"checks\":%u,\"transport_faults\":%u,"
	       "\"ignored_key_bits\":%u,\"rejected_key_bits\":%u,\"rejected_mask_bits\":%u,"
	       "\"rejected_action_bits\":%u,\"normalization_patterns\":3}\n",
	       scenarios, checks, faults, ignored_key_bits, rejected_key_bits,
	       rejected_mask_bits, rejected_action_bits);
	return 0;
}
