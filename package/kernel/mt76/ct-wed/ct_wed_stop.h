#ifndef CT_WED_STOP_H
#define CT_WED_STOP_H

#include <linux/errno.h>
#include <linux/types.h>

enum ct_stop_window { CT_STOP_WED, CT_STOP_WDMA };
enum ct_stop_action { CT_STOP_WRITE, CT_STOP_UPDATE, CT_STOP_POLL };

enum ct_stop_precondition {
	CT_STOP_LEASE_OWNED = 1U << 0,
	CT_STOP_INGRESS_BLOCKED = 1U << 1,
	CT_STOP_RADIO_PARKED = 1U << 2,
	CT_STOP_IRQ_SYNCED = 1U << 3,
};

#define CT_STOP_REQUIRED 0xfU

struct ct_stop_step {
	enum ct_stop_window window;
	enum ct_stop_action action;
	u32 offset, mask, value;
};

struct ct_stop_io {
	void *ctx;
	u32 ready;
	int (*read)(void *ctx, enum ct_stop_window window, u32 offset, u32 *value);
	int (*write)(void *ctx, enum ct_stop_window window, u32 offset, u32 value);
	u64 (*now)(void *ctx);
	void (*wait)(void *ctx);
};

static const struct ct_stop_step ct_stop_steps[] = {
	{ CT_STOP_WED, CT_STOP_UPDATE, 0x208, 0x1, 0 },
	{ CT_STOP_WED, CT_STOP_POLL, 0x208, 0x2, 0 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0x20c, 0, 3 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0x20c, 0, 0 },
	{ CT_STOP_WDMA, CT_STOP_UPDATE, 0x204, 0x4, 0 },
	{ CT_STOP_WDMA, CT_STOP_POLL, 0x204, 0x8, 0 },
	{ CT_STOP_WED, CT_STOP_UPDATE, 0xa04, 0x4, 0x2000 },
	{ CT_STOP_WED, CT_STOP_POLL, 0xa04, 0x8, 0 },
	{ CT_STOP_WDMA, CT_STOP_WRITE, 0x208, 0, 0x30000 },
	{ CT_STOP_WDMA, CT_STOP_WRITE, 0x208, 0, 0 },
	{ CT_STOP_WDMA, CT_STOP_WRITE, 0x108, 0, 0 },
	{ CT_STOP_WDMA, CT_STOP_WRITE, 0x118, 0, 0 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0xa08, 0, 0x3030000 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0xa08, 0, 0 },
	{ CT_STOP_WED, CT_STOP_UPDATE, 0xa04, 0, 0x4000000 },
	{ CT_STOP_WED, CT_STOP_UPDATE, 0xa04, 0x4000000, 0 },
	{ CT_STOP_WED, CT_STOP_UPDATE, 0x00c, 0x400, 0 },
	{ CT_STOP_WED, CT_STOP_POLL, 0x00c, 0x800, 0 },
	{ CT_STOP_WED, CT_STOP_POLL, 0x09c, 0xffff0000, 0x400000 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0x008, 0, 0x10 },
	{ CT_STOP_WED, CT_STOP_POLL, 0x008, 0xffffffff, 0 },
	{ CT_STOP_WED, CT_STOP_UPDATE, 0x00c, 0x100, 0 },
	{ CT_STOP_WED, CT_STOP_POLL, 0x00c, 0x200, 0 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0x008, 0, 1 },
	{ CT_STOP_WED, CT_STOP_POLL, 0x008, 0xffffffff, 0 },
	{ CT_STOP_WED, CT_STOP_UPDATE, 0x508, 0x1, 0 },
	{ CT_STOP_WED, CT_STOP_POLL, 0x508, 0x2, 0 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0x50c, 0, 3 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0x50c, 0, 0 },
	{ CT_STOP_WED, CT_STOP_UPDATE, 0x508, 0x4, 0 },
	{ CT_STOP_WED, CT_STOP_POLL, 0x508, 0x8, 0 },
	{ CT_STOP_WED, CT_STOP_UPDATE, 0x208, 0x4, 0 },
	{ CT_STOP_WED, CT_STOP_POLL, 0x208, 0x8, 0 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0x50c, 0, 0x20000 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0x20c, 0, 0x20000 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0x50c, 0, 0 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0x20c, 0, 0 },
	{ CT_STOP_WED, CT_STOP_WRITE, 0x418, 0, 0 },
};

static inline int ct_stop_run(const struct ct_stop_io *io, u64 deadline,
			      unsigned int *completed)
{
	unsigned int index;
	u32 value;
	int err;

	if (!completed)
		return -EINVAL;
	*completed = 0;
	if (!io || !io->read || !io->write || !io->now || !io->wait)
		return -EINVAL;
	if ((io->ready & CT_STOP_REQUIRED) != CT_STOP_REQUIRED)
		return -EAGAIN;
	for (index = 0; index < sizeof(ct_stop_steps) / sizeof(ct_stop_steps[0]); index++) {
		const struct ct_stop_step *step = &ct_stop_steps[index];

		if (io->now(io->ctx) >= deadline)
			return -ETIMEDOUT;
		if (step->action == CT_STOP_WRITE) {
			err = io->write(io->ctx, step->window, step->offset, step->value);
			if (err)
				return err;
		} else {
			for (;;) {
				err = io->read(io->ctx, step->window, step->offset, &value);
				if (err)
					return err;
				if (io->now(io->ctx) >= deadline)
					return -ETIMEDOUT;
				if (value == 0xffffffff)
					return -EIO;
				if (step->action == CT_STOP_UPDATE) {
					err = io->write(io->ctx, step->window, step->offset,
							(value & ~step->mask) | step->value);
					if (err)
						return err;
					break;
				}
				if ((value & step->mask) == step->value)
					break;
				io->wait(io->ctx);
				if (io->now(io->ctx) >= deadline)
					return -ETIMEDOUT;
			}
		}
		if (io->now(io->ctx) >= deadline)
			return -ETIMEDOUT;
		*completed = index + 1;
	}
	return 0;
}

#endif
