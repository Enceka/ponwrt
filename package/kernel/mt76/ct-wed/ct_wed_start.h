#ifndef CT_WED_STOCK_START_H
#define CT_WED_STOCK_START_H

#include <linux/errno.h>
#include <linux/types.h>

enum ct_start_window { CT_START_WED, CT_START_WDMA, CT_START_BAR };
enum ct_start_state { CT_START_NEW, CT_START_EXPOSED, CT_START_CONFIGURED, CT_START_ENABLED, CT_START_RETAINED };

enum ct_start_precondition {
	CT_START_OWNED = 1U << 0,
	CT_START_NEVER_EXPOSED = 1U << 1,
	CT_START_INGRESS_ABSENT = 1U << 2,
	CT_START_BUS_READABLE = 1U << 3,
	CT_START_WRITERS_EXCLUDED = 1U << 4,
	CT_START_RADIO_PARKED = 1U << 5,
	CT_START_POOLS_PINNED = 1U << 6,
	CT_START_IRQ_HELD = 1U << 7,
};

#define CT_START_REQUIRED 0xffU
#define CT_START_ENABLE_REQUIRED (CT_START_REQUIRED & ~CT_START_NEVER_EXPOSED)
#define CT_START_DIDX_COUNT 12U

struct ct_start_ring {
	u32 desc, count, cidx, didx;
};

struct ct_start_plan {
	struct ct_start_ring host[3];
	u32 mid[2], rx[2], bm_dma, bar_phys, source_mask;
};

struct ct_start_io {
	void *ctx;
	u32 ready;
	int (*lease_valid)(void *ctx);
	int (*expose)(void *ctx);
	int (*read)(void *ctx, enum ct_start_window window, u32 offset, u32 *value);
	int (*write)(void *ctx, enum ct_start_window window, u32 offset, u32 value);
	u64 (*now)(void *ctx);
	void (*wait)(void *ctx);
};

struct ct_start_result {
	enum ct_start_state state;
	struct ct_start_plan plan;
	void *owner_ctx;
	u64 deadline;
	u32 didx[CT_START_DIDX_COUNT];
	unsigned int writes, verified, didx_count;
	enum ct_start_window last_window;
	u32 last_offset;
	int error;
};

static inline int ct_start_gate(const struct ct_start_io *io,
				 const struct ct_start_result *result)
{
	int err;

	if (io->now(io->ctx) >= result->deadline)
		return -ETIMEDOUT;
	err = io->lease_valid(io->ctx);
	if (err)
		return err;
	return io->now(io->ctx) < result->deadline ? 0 : -ETIMEDOUT;
}

static inline int ct_start_read(const struct ct_start_io *io,
				struct ct_start_result *result,
				enum ct_start_window window, u32 offset, u32 *value)
{
	int err = ct_start_gate(io, result);

	result->last_window = window;
	result->last_offset = offset;
	if (!err)
		err = io->read(io->ctx, window, offset, value);
	return err ?: ct_start_gate(io, result);
}

static inline int ct_start_expect(const struct ct_start_io *io,
				  struct ct_start_result *result,
				  enum ct_start_window window, u32 offset,
				  u32 mask, u32 expected)
{
	u32 value;
	int err = ct_start_read(io, result, window, offset, &value);

	if (err)
		return err;
	return (value & mask) != expected ? -EBUSY : 0;
}

static inline int ct_start_write(const struct ct_start_io *io,
				 struct ct_start_result *result,
				 enum ct_start_window window, u32 offset,
				 u32 value, u32 verify_mask)
{
	u32 actual;
	int err = ct_start_gate(io, result);

	if (err)
		return err;
	result->last_window = window;
	result->last_offset = offset;
	result->writes++;
	err = io->write(io->ctx, window, offset, value);
	if (!err)
		err = ct_start_read(io, result, window, offset, &actual);
	if (!err && (actual & verify_mask) != (value & verify_mask))
		err = -EIO;
	if (!err)
		result->verified++;
	return err;
}

static inline int ct_start_update(const struct ct_start_io *io,
				  struct ct_start_result *result,
				  enum ct_start_window window, u32 offset,
				  u32 keep, u32 set, u32 verify_mask)
{
	u32 value;
	int err = ct_start_read(io, result, window, offset, &value);

	return err ?: ct_start_write(io, result, window, offset,
				     (value & keep) | set, verify_mask);
}

static inline int ct_start_finish(struct ct_start_result *result, int err)
{
	result->error = err;
	if (err && result->state != CT_START_NEW)
		result->state = CT_START_RETAINED;
	return err;
}

static inline int ct_start_plan_valid(const struct ct_start_plan *plan)
{
	u32 addresses[8], sizes[8];
	unsigned int index, other;

	if (!plan || !plan->bar_phys || (plan->bar_phys & 0xfff) ||
	    plan->bar_phys > 0xffffffffU - 0xd7fff ||
	    (plan->source_mask & 0x32) != 0x32)
		return -EINVAL;
	for (index = 0; index < 3; index++) {
		const struct ct_start_ring *ring = &plan->host[index];
		u32 count = index == 2 ? 512 : 2048;

		if (ring->count != count || ring->didx ||
		    ring->cidx != (index == 2 ? count - 1 : 0))
			return -EINVAL;
		addresses[index] = ring->desc;
		sizes[index] = count * 16;
	}
	for (index = 0; index < 2; index++) {
		addresses[3 + index] = plan->mid[index];
		sizes[3 + index] = 2048 * 16;
		addresses[5 + index] = plan->rx[index];
		sizes[5 + index] = 1024 * 16;
	}
	addresses[7] = plan->bm_dma;
	sizes[7] = 8192 * 16;
	for (index = 0; index < 8; index++) {
		if (!addresses[index] || (addresses[index] & 15) ||
		    addresses[index] > 0xffffffffU - sizes[index] + 1)
			return -ERANGE;
		for (other = 0; other < index; other++)
			if ((u64)addresses[index] < (u64)addresses[other] + sizes[other] &&
			    (u64)addresses[other] < (u64)addresses[index] + sizes[index])
				return -EINVAL;
	}
	return 0;
}

static inline int ct_start_inactive(const struct ct_start_io *io,
				    struct ct_start_result *result)
{
	static const struct {
		enum ct_start_window window;
		u32 offset, mask;
	} guards[] = {
		{ CT_START_WED, 8, 0xffffffff },
		{ CT_START_WED, 0xc, 0xf05 },
		{ CT_START_WED, 0x208, 0xf },
		{ CT_START_WED, 0x508, 0xf },
		{ CT_START_WED, 0xa04, 0x0400000f },
		{ CT_START_WDMA, 0x204, 0xf },
		{ CT_START_WED, 0x504, 0xffffffff },
		{ CT_START_WED, 0xa28, 0xffffffff },
		{ CT_START_WDMA, 0x228, 0xffffffff },
		{ CT_START_WDMA, 0x254, 0xffffffff },
	};
	unsigned int index;
	int err;

	for (index = 0; index < sizeof(guards) / sizeof(guards[0]); index++) {
		err = ct_start_expect(io, result, guards[index].window,
				      guards[index].offset, guards[index].mask, 0);
		if (err)
			return err;
	}
	return 0;
}

static inline int ct_start_cold_rings(const struct ct_start_io *io,
				      const struct ct_start_plan *plan,
				      struct ct_start_result *result)
{
	static const u32 wed_csr[] = { 0x300, 0x310, 0x410, 0x600, 0x610, 0x710, 0x900, 0x910 };
	static const u32 bar_csr[] = { 0xd7300, 0xd7310, 0xd7410 };
	unsigned int index, member;
	int err;

	for (index = 0; index < sizeof(wed_csr) / sizeof(wed_csr[0]); index++)
		for (member = 0; member < 4; member++) {
			err = ct_start_expect(io, result, CT_START_WED,
					      wed_csr[index] + member * 4, 0xffffffff, 0);
			if (err)
				return err;
		}
	for (index = 0; index < 2; index++)
		for (member = 0; member < 4; member++) {
			err = ct_start_expect(io, result, CT_START_WDMA,
					      0x100 + index * 16 + member * 4, 0xffffffff, 0);
			if (err)
				return err;
		}
	for (index = 0; index < 3; index++) {
		const struct ct_start_ring *ring = &plan->host[index];
		u32 values[] = { ring->desc, ring->count, ring->cidx, ring->didx };
		bool zero = true, host = true;

		for (member = 0; member < 4; member++) {
			u32 value;

			err = ct_start_read(io, result, CT_START_BAR,
					    bar_csr[index] + member * 4, &value);
			if (err)
				return err;
			zero &= value == 0;
			host &= value == values[member];
		}
		if (!zero && !host)
			return -EBUSY;
	}
	return 0;
}

static inline int ct_start_check_didx(const struct ct_start_io *io,
				      struct ct_start_result *result)
{
	static const struct {
		enum ct_start_window window;
		u32 offset;
	} registers[CT_START_DIDX_COUNT] = {
		{ CT_START_WED, 0x30c }, { CT_START_WED, 0x31c },
		{ CT_START_WED, 0x41c }, { CT_START_WED, 0x60c },
		{ CT_START_WED, 0x61c }, { CT_START_WED, 0x71c },
		{ CT_START_WED, 0x90c }, { CT_START_WED, 0x91c },
		{ CT_START_WDMA, 0x10c }, { CT_START_WDMA, 0x11c },
		{ CT_START_BAR, 0xd730c }, { CT_START_BAR, 0xd731c },
	};
	unsigned int index;
	int err;

	result->didx_count = 0;
	for (index = 0; index < CT_START_DIDX_COUNT; index++) {
		err = ct_start_read(io, result, registers[index].window,
				    registers[index].offset, &result->didx[index]);
		if (err)
			return err;
		result->didx_count++;
		if (result->didx[index])
			return -EBUSY;
	}
	return ct_start_expect(io, result, CT_START_BAR, 0xd741c, 0xffffffff, 0);
}

static inline int ct_start_irq_route(const struct ct_start_io *io,
				     struct ct_start_result *result, u32 enabled)
{
	u32 mask = enabled ? result->plan.source_mask : 0;
	u32 wdma_mask = enabled ? 0x30000 : 0;
	u32 native_extra = ((mask & 0x10) ? 0x40000000 : 0) |
			   ((mask & 0x20) ? 0x80000000 : 0) |
			   ((mask & 0x2) ? 0x4 : 0);
	int err;

	err = ct_start_update(io, result, CT_START_WED, 0xc, ~5U,
			       enabled ? 5 : 0, 5);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x570, 0x01000000, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x564, 0x01800184, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x504, enabled ? 0x32 : 0, 0xffffffff);
	if (!err)
		err = ct_start_update(io, result, CT_START_WED, 0x520, 0xffffffff, 0x00200000, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0xa28, wdma_mask, 0xffffffff);
	if (!err)
		err = ct_start_update(io, result, CT_START_WED, 0xa2c, 0xfffcffff, 0, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WDMA, 0x228, wdma_mask, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WDMA, 0x254, wdma_mask, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x524, mask, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_BAR, 0xd7204,
				     mask, ~(native_extra & ~mask));
	return err;
}

static inline int ct_start_configure(const struct ct_start_io *io,
				     const struct ct_start_plan *plan, u64 deadline,
				     struct ct_start_result *result)
{
	static const u32 host_csr[] = { 0x300, 0x310, 0x410 };
	unsigned int index, member;
	int err;

	if (!result)
		return -EINVAL;
	if (result->state != CT_START_NEW)
		return -EUCLEAN;
	if (!io || !io->read || !io->write || !io->lease_valid || !io->expose ||
	    !io->now || !io->wait)
		return -EINVAL;
	if ((io->ready & CT_START_REQUIRED) != CT_START_REQUIRED)
		return -EAGAIN;
	err = ct_start_plan_valid(plan);
	if (err)
		return err;
	*result = (struct ct_start_result) {
		.state = CT_START_NEW, .plan = *plan,
		.owner_ctx = io->ctx, .deadline = deadline,
	};
	err = ct_start_inactive(io, result);
	if (!err)
		err = ct_start_cold_rings(io, plan, result);
	if (!err)
		err = ct_start_gate(io, result);
	if (err)
		return ct_start_finish(result, err);
	result->state = CT_START_EXPOSED;
	err = io->expose(io->ctx);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x204, 0, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x28, 0, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x560, 0x1fc20000, 0xffffffff);
	if (!err)
		err = ct_start_update(io, result, CT_START_WED, 0x57c, 0xffffffff, 0x00100000, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x580, plan->bar_phys + 0xd7000, 0xffffffff);
	if (!err)
		err = ct_start_update(io, result, CT_START_WED, 0xa04, 0xfc7fdfcf, 0x00210020, 0xffffffff);
	if (!err)
		err = ct_start_update(io, result, CT_START_WDMA, 0x204, 0xffffffff, 0x1c000000, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0xaa0, 0x1fa00000, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0xaa4, 0x66046620, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0xaa8, 0x65006400, 0xffffffff);
	for (index = 0; !err && index < 3; index++) {
		const struct ct_start_ring *ring = &plan->host[index];
		u32 values[] = { ring->desc, ring->count, ring->cidx };

		for (member = 0; !err && member < 3; member++)
			err = ct_start_write(io, result, CT_START_WED,
					     host_csr[index] + 4 * member, values[member], 0xffffffff);
	}
	for (index = 0; !err && index < 2; index++) {
		u32 values[] = { plan->rx[index], 1024, 0 };

		for (member = 0; !err && member < 3; member++)
			err = ct_start_write(io, result, CT_START_WDMA,
					     0x100 + index * 16 + member * 4, values[member], 0xffffffff);
		for (member = 0; !err && member < 2; member++)
			err = ct_start_write(io, result, CT_START_WED,
					     0x900 + index * 16 + member * 4, values[member], 0xffffffff);
	}
	for (index = 0; !err && index < 2; index++) {
		u32 values[] = { plan->mid[index], 2048, 0 };

		for (member = 0; !err && member < 3; member++)
			err = ct_start_write(io, result, CT_START_BAR,
					     0xd7300 + index * 16 + member * 4, values[member], 0xffffffff);
		for (member = 0; !err && member < 3; member++)
			err = ct_start_write(io, result, CT_START_WED,
					     0x600 + index * 16 + member * 4, values[member], 0xffffffff);
	}
	for (member = 0; !err && member < 3; member++) {
		u32 value;

		err = ct_start_read(io, result, CT_START_WED, 0x410 + member * 4, &value);
		if (!err)
			err = ct_start_write(io, result, CT_START_WED, 0x710 + member * 4,
					     value, member == 2 ? 0 : 0xffffffff);
		if (!err)
			err = ct_start_write(io, result, CT_START_BAR, 0xd7410 + member * 4, value, 0xffffffff);
	}
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x80, 0x10080040, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x84, plan->bm_dma, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x88, 0x1fff0000, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x8c, 1900, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0xa0, 0x007f0001, 0xffffffff);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 8, 1, 0);
	while (!err) {
		u32 value;

		err = ct_start_read(io, result, CT_START_WED, 8, &value);
		if (err || !value)
			break;
		io->wait(io->ctx);
	}
	if (!err)
		err = ct_start_irq_route(io, result, 0);
	if (!err)
		err = ct_start_inactive(io, result);
	if (!err)
		err = ct_start_check_didx(io, result);
	if (!err)
		result->state = CT_START_CONFIGURED;
	return ct_start_finish(result, err);
}

static inline int ct_start_enable(const struct ct_start_io *io,
				  const struct ct_start_plan *plan,
				  struct ct_start_result *result)
{
	u32 wed_dma, wpdma_dma, wdma_dma;
	unsigned int index;
	int err;

	if (!result || !io || !io->read || !io->write || !io->lease_valid ||
	    !io->now || !io->wait || !plan)
		return -EINVAL;
	if (result->state != CT_START_CONFIGURED)
		return -EUCLEAN;
	if (io->ctx != result->owner_ctx ||
	    (io->ready & CT_START_ENABLE_REQUIRED) != CT_START_ENABLE_REQUIRED)
		return ct_start_finish(result, -EAGAIN);
	if (plan->bm_dma != result->plan.bm_dma || plan->bar_phys != result->plan.bar_phys ||
	    plan->source_mask != result->plan.source_mask)
		return ct_start_finish(result, -EINVAL);
	for (index = 0; index < 3; index++)
		if (plan->host[index].desc != result->plan.host[index].desc ||
		    plan->host[index].count != result->plan.host[index].count ||
		    plan->host[index].cidx != result->plan.host[index].cidx ||
		    plan->host[index].didx != result->plan.host[index].didx)
			return ct_start_finish(result, -EINVAL);
	for (index = 0; index < 2; index++)
		if (plan->mid[index] != result->plan.mid[index] || plan->rx[index] != result->plan.rx[index])
			return ct_start_finish(result, -EINVAL);
	err = ct_start_inactive(io, result);
	if (!err)
		err = ct_start_check_didx(io, result);
	if (!err)
		err = ct_start_expect(io, result, CT_START_WED, 0x204, 0xffffffff, 0);
	if (!err)
		err = ct_start_expect(io, result, CT_START_WED, 0x28, 0xffffffff, 0);
	if (!err)
		err = ct_start_update(io, result, CT_START_WED, 0xc, 0xffffffff, 0x500, 0x500);
	if (!err)
		err = ct_start_update(io, result, CT_START_WED, 0x80, 0xefffffff, 0, 0xffffffff);
	if (!err)
		err = ct_start_irq_route(io, result, 1);
	if (!err)
		err = ct_start_read(io, result, CT_START_WED, 0x208, &wed_dma);
	if (!err)
		err = ct_start_read(io, result, CT_START_WED, 0x508, &wpdma_dma);
	if (!err)
		err = ct_start_read(io, result, CT_START_WED, 0xa04, &wdma_dma);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x208, (wed_dma & ~5U) | 5, 5);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0xa04, (wdma_dma & ~5U) | 4, 5);
	if (!err)
		err = ct_start_write(io, result, CT_START_WED, 0x508, (wpdma_dma & ~5U) | 5, 5);
	if (!err)
		err = ct_start_expect(io, result, CT_START_WED, 0x204, 0xffffffff, 0);
	if (!err)
		err = ct_start_expect(io, result, CT_START_WED, 0x28, 0xffffffff, 0);
	if (!err)
		err = ct_start_check_didx(io, result);
	if (!err)
		result->state = CT_START_ENABLED;
	return ct_start_finish(result, err);
}

#endif
