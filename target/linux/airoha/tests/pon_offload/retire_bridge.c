/* Execute the candidate header itself with process-local MMIO callbacks. */
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

/* The target is Linux; Darwin assigns ETIMEDOUT a different number. */
#undef ETIMEDOUT
#define ETIMEDOUT 110

typedef uint8_t u8;
typedef uint32_t u32;
#define BIT(n) (1U << (n))
#define GENMASK(h, l) ((~0U << (l)) & (~0U >> (31 - (h))))
#define REG_QUEUE_CLOSE_CFG(n) (0xa0U + ((n) & 0xfcU))
#define REG_GDM_CHN_RLS(n) (0x1520U)
#define REG_GDM_TXCHN_EN(n) (0x1524U)
#define REG_GDM_RXCHN_EN(n) (0x1528U)

struct airoha_qdma { uintptr_t regs; };
struct airoha_eth { uintptr_t fe_regs; struct airoha_qdma qdma[2]; };
static u32 (*read_reg)(u32);
static void (*write_reg)(u32, u32);
static void (*delay_us)(u32);
static u32 rd(uintptr_t base, u32 offset) { return read_reg(base + offset); }
static void wr(uintptr_t base, u32 offset, u32 value)
{
	write_reg(base + offset, value);
}
static u32 rmw(uintptr_t base, u32 offset, u32 mask, u32 value)
{
	value = (rd(base, offset) & ~mask) | value;
	wr(base, offset, value);
	return value;
}
#define airoha_fe_rr(e, o) rd((e)->fe_regs, o)
#define airoha_fe_wr(e, o, v) wr((e)->fe_regs, o, v)
#define airoha_fe_rmw(e, o, m, v) rmw((e)->fe_regs, o, m, v)
#define airoha_qdma_rr(q, o) rd((q)->regs, o)
#define airoha_qdma_rmw(q, o, m, v) rmw((q)->regs, o, m, v)
static void usleep_range(unsigned int min, unsigned int max)
{
	(void)max;
	delay_us(min);
}
#include "airoha_pon_retire.h"

static struct airoha_pon_retirement state;
static struct airoha_eth eth = {
	.fe_regs = 0xbfb50000,
	.qdma = {{0xbfb54000}, {0xbfb56000}},
};

void candidate_reset(u32 (*read)(u32), void (*write)(u32, u32),
		     void (*delay)(u32))
{
	memset(&state, 0, sizeof(state));
	read_reg = read;
	write_reg = write;
	delay_us = delay;
}

int candidate_call(int action, unsigned int channel)
{
	switch (action) {
	case 0: return airoha_pon_channel_close(&eth, &state, channel);
	case 1: return airoha_pon_channel_retire(&eth, &state, channel);
	case 2: return airoha_pon_channel_reopen(&eth, &state, channel);
	default: return -EINVAL;
	}
}

u32 candidate_state(unsigned int field, unsigned int channel)
{
	switch (field) {
	case 0: return state.owned;
	case 1: return state.drained;
	case 2: return state.restore_pending;
	case 3: return state.command_owned;
	case 4: return state.saved_tx;
	case 5: return state.saved_rx;
	case 6: return state.saved_close[channel & 31];
	default: return ~0U;
	}
}
