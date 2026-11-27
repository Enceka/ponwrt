#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef EAGAIN
#undef EINPROGRESS
#undef EOPNOTSUPP
#undef EPROTO
#undef ESTALE
#undef EOVERFLOW
#undef ESHUTDOWN
#undef ETIMEDOUT
#define EAGAIN 11
#define EINPROGRESS 115
#define EOPNOTSUPP 95
#define EPROTO 71
#define ESTALE 116
#define EOVERFLOW 75
#define ESHUTDOWN 108
#define ETIMEDOUT 110

typedef uint8_t u8;
typedef uint16_t u16, __le16;
typedef uint32_t u32, __le32;
typedef uint64_t u64, __le64;
typedef int32_t s32;
typedef int64_t ktime_t;
static unsigned checks;
#define CHECK(condition) do { checks++; if (!(condition)) { \
	fprintf(stderr, "CHECK failed: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
	exit(1); } } while (0)
#define __maybe_unused __attribute__((unused))
#ifndef EUCLEAN
#define EUCLEAN 117
#endif
#define U32_MAX UINT32_MAX
#define BIT(shift) (UINT32_C(1) << (shift))
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define READ_ONCE(value) (value)
#define max(left, right) ((left) > (right) ? (left) : (right))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define cpu_to_le16(value) ((u16)(value))
#define cpu_to_le32(value) ((u32)(value))
#define cpu_to_le64(value) ((u64)(value))
#else
#define cpu_to_le16(value) __builtin_bswap16((u16)(value))
#define cpu_to_le32(value) __builtin_bswap32((u32)(value))
#define cpu_to_le64(value) __builtin_bswap64((u64)(value))
#endif
#define le16_to_cpu(value) cpu_to_le16(value)
#define le32_to_cpu(value) cpu_to_le32(value)
#define le64_to_cpu(value) cpu_to_le64(value)
#undef static_assert
#define static_assert(condition) _Static_assert(condition, #condition)
#include "pair_abi.inc"

struct work_struct { int unused; };
struct delayed_work { struct work_struct work; };
struct device { void *of_node; };
struct airoha_npu {
	struct device *dev;
	struct { int (*ct_pair_cmd)(struct airoha_npu *, struct airoha_ct_pair_msg *); } ops;
};
struct airoha_eth {
	struct airoha_npu *npu;
	bool ct_ifc_cpu_port_failed, ct_cpu_fallback, ct_cpu_ifc_disabled;
	bool ct_ifc_command_pending;
};
struct airoha_ppe {
	struct airoha_eth *eth;
	bool ct_pair_failed, ct_stopping, ct_pair_policy_allowed;
	bool *ct_pairs;
	u32 ct_pair_wired_epoch;
	struct { struct { u8 lut_index; } rule[2]; } ct_ifc;
#include "fe_layout.inc"
};
static int ppe_lock, rcu_depth;
#define lockdep_assert_held(lock) CHECK(*(lock) == 1)
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { CHECK(rcu_depth == 1); rcu_depth--; }
#define rcu_dereference(pointer) (pointer)
static ktime_t elapsed_us;
static ktime_t ktime_get(void) { return elapsed_us; }
static ktime_t ktime_add_us(ktime_t current, unsigned delta) { return current + delta; }
static bool ktime_before(ktime_t before, ktime_t after) { return before < after; }
static void udelay(unsigned delta) { elapsed_us += delta; }
static bool airoha_ct_pair_any(struct airoha_ppe *ppe)
{
	lockdep_assert_held(&ppe_lock);
	for (unsigned index = 0; index < AIROHA_CT_PAIR_SLOTS; index++)
		if (ppe->ct_pairs[index])
			return true;
	return false;
}
static void airoha_ct_pair_error_diag(struct airoha_ppe *ppe,
	const struct airoha_ct_pair_msg *message, int error, const char *stage,
	const char *caller, unsigned line, unsigned retries)
{
	lockdep_assert_held(&ppe_lock);
}

#define NPU_CT_NATIVE_PAIRS 1
#define NPU_CT_FE_NATIVE 1
#define NPU_CT_BRIDGE_GUARD 2
#define NPU_CT_SHORT_PAD 1
#define NPU_CT_TDMA_BANK 2
#define NPU_WIFI_POOL_COUNT 64
#define NPU_CT_FE_PIPELINE 0
#include "npu_fe_bridge.h"
volatile struct npu_fe_control npu_fe_control;
volatile struct npu_fe_completion npu_fe_completion;
static bool lock_granted, quiesce_busy;
static int enable_error;
static unsigned enables, disables, firmware_calls;
static uint32_t mailbox[18];
static uint32_t wifi_pool_base;
static struct { uint32_t count; } wifi_rx_rings[2];
static uintptr_t native_lock(uint32_t *granted)
{
	*granted = lock_granted;
	return 1;
}
static void native_unlock(uintptr_t token) { CHECK(token == 1); }
static uint32_t npu_sram_alloc(uint32_t kind, size_t bytes) { return 0; }
static void npu_io_fence(void) { }
static uint32_t npu_mmio_read32(uintptr_t address)
{
	CHECK(address >= 0x10000 && address < 0x10000 + sizeof(mailbox));
	CHECK(!(address & 3));
	return le32_to_cpu(mailbox[(address - 0x10000) / 4]);
}
static void npu_mmio_write32(uintptr_t address, uint32_t value)
{
	CHECK(address >= 0x10000 && address < 0x10000 + sizeof(mailbox));
	CHECK(!(address & 3));
	mailbox[(address - 0x10000) / 4] = cpu_to_le32(value);
}
int npu_fe_fallback_enable(uint32_t enabled)
{
	if (enabled) {
		enables++;
		if (enable_error)
			return enable_error;
	} else {
		disables++;
	}
	npu_fe_control.enabled = enabled;
	npu_fe_control.quiesced = !enabled && !quiesce_busy;
	return 0;
}
#include "native_mailbox.inc"
static struct native_state firmware_state;
static bool ready, ram_profile, accept_before_error;
static int transport_error, reply_status, reply_caps, corrupt_byte, callback_result;
static unsigned sends;
static struct airoha_ct_pair_msg last_request;
#define NPU_OP_SET 1
#define NPU_FUNC_WIFI 0
static bool airoha_npu_wlan_short_guard_ready(struct airoha_npu *npu) { return ready; }
static bool of_property_read_bool(void *node, const char *name)
{
	CHECK(node && !strcmp(name, "airoha,connac2-rebuilt-ram-lab"));
	return ram_profile;
}
static int __airoha_npu_send_msg(struct airoha_npu *npu, int function,
	void *input, size_t input_bytes, void *output, size_t output_bytes)
{
	CHECK(npu && function == NPU_FUNC_WIFI);
	CHECK(input_bytes == sizeof(mailbox) && output_bytes == sizeof(last_request));
	memcpy(mailbox, input, input_bytes);
	CHECK(le32_to_cpu(mailbox[0]) == 16 && le32_to_cpu(mailbox[1]) == 34);
	memcpy(&last_request, mailbox + 2, sizeof(last_request));
	CHECK(le32_to_cpu(last_request.magic) == AIROHA_CT_PAIR_MAGIC);
	CHECK(le16_to_cpu(last_request.abi) == 3);
	CHECK((s32)le32_to_cpu(last_request.status) == -EINPROGRESS && !last_request.caps);
	sends++;
	if (transport_error && !accept_before_error)
		return transport_error;
	CHECK(native_mailbox(34, 0x10000, sizeof(mailbox), NULL) == 1);
	firmware_calls++;
	if (transport_error)
		return transport_error;
	memcpy(output, mailbox + 2, output_bytes);
	struct airoha_ct_pair_msg *reply = output;
	if (reply_status != INT_MIN)
		reply->status = cpu_to_le32(reply_status);
	if (reply_caps >= 0)
		reply->caps = cpu_to_le32(reply_caps);
	if (corrupt_byte >= 0)
		((u8 *)output)[corrupt_byte] ^= 1;
	return 0;
}
#include "pair_transport.inc"
static int callback(struct airoha_npu *npu, struct airoha_ct_pair_msg *message)
{
	if (callback_result != INT_MIN)
		return callback_result;
	return airoha_npu_ct_pair_cmd(npu, message);
}
#include "pair_sender.inc"

#define CT_IFC_DATA(index) (0x210 + 4 * (index))
#define CT_IFC_CONTROL 0x204
#define CT_IFC_DONE BIT(31)
#define CT_IFC_TCAM_BANK 0
#define CT_IFC_ACTION_BANK 2
#define CT_IFC_ACTION_ENABLE BIT(31)
#define CT_IFC_ACTION_STOP BIT(30)
#define REG_FE_CSR_IFC_CFG 0x200
#define FE_IFC_EN_MASK 1
#define XSI_ETH_VIP_PORT_MASK BIT(24)
#define REG_PPE_GLO_CFG(bank) (0x500 + (bank) * 0x100)
#define REG_PPE_PPE_FLOW_CFG(bank) (0x504 + (bank) * 0x100)
#define REG_PPE_TB_CFG(bank) (0x51c + (bank) * 0x100)
#define PPE_TB_CFG_SEARCH_MISS_MASK (3u << 4)
#define PPE_GLO_CFG_BUSY_MASK BIT(31)
#define PPE_GLO_CFG_EN_MASK BIT(0)
#define FIELD_PREP(mask, value) (((u32)(value) << __builtin_ctz(mask)) & (mask))
#define read_poll_timeout_atomic(function, value, condition, delay, timeout, sleep, ...) \
	((value) = function(__VA_ARGS__), (condition) ? 0 : -ETIMEDOUT)
static const u8 ct_ifc_action_words[] = { 2, 3, 1 };
static unsigned mmio_reads, mmio_writes, schedules;
static u32 registers[1024], tables[3][64][9][3];
static bool airoha_ifc_lan_ports_ready(struct airoha_eth *eth) { return true; }
static u32 airoha_fe_rr(struct airoha_eth *eth, u32 offset)
{
	lockdep_assert_held(&ppe_lock);
	CHECK(offset < sizeof(registers));
	mmio_reads++;
	return registers[offset / 4];
}
static void airoha_fe_wr(struct airoha_eth *eth, u32 offset, u32 value)
{
	lockdep_assert_held(&ppe_lock);
	CHECK(offset < sizeof(registers));
	mmio_writes++;
	registers[offset / 4] = value;
	if (offset == CT_IFC_CONTROL) {
		unsigned bank = (value >> 4) & 7;
		unsigned row = (value >> 16) & 255;
		unsigned page = (value >> 8) & 15;
		CHECK((bank == CT_IFC_TCAM_BANK || bank == CT_IFC_ACTION_BANK) &&
		      row >= 54 && row <= 55 && page < 9);
		unsigned count = bank == CT_IFC_ACTION_BANK ? ct_ifc_action_words[page] : 2;
		if (value & 2) {
			memcpy(tables[bank][row][page], registers + CT_IFC_DATA(0) / 4,
			       count * sizeof(u32));
			if (bank == CT_IFC_TCAM_BANK)
				tables[bank][row][page][0] &= tables[bank][row][page][1];
		} else {
			memcpy(registers + CT_IFC_DATA(0) / 4, tables[bank][row][page],
			       count * sizeof(u32));
		}
		registers[offset / 4] |= CT_IFC_DONE;
	}
}
static void airoha_fe_rmw(struct airoha_eth *eth, u32 offset, u32 mask, u32 value)
{
	airoha_fe_wr(eth, offset, (airoha_fe_rr(eth, offset) & ~mask) | value);
}
#define msecs_to_jiffies(value) (value)
static int schedule_delayed_work(struct delayed_work *work, unsigned delay)
{
	schedules++;
	return 0;
}
#include "airoha_ct_fe_native.h"
