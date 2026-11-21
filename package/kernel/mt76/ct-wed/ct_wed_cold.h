#ifndef CT_WED_COLD_TRANSACTION_H
#define CT_WED_COLD_TRANSACTION_H

#include <linux/errno.h>
#include <linux/types.h>

enum ct_cold_window { CT_COLD_WED, CT_COLD_WDMA };
enum ct_cold_state { CT_COLD_CLEAN, CT_COLD_RETAINED };

enum ct_cold_precondition {
	CT_COLD_OWNED = 1U << 0,
	CT_COLD_NEVER_EXPOSED = 1U << 1,
	CT_COLD_INGRESS_ABSENT = 1U << 2,
	CT_COLD_BUS_READABLE = 1U << 3,
	CT_COLD_WRITERS_EXCLUDED = 1U << 4,
};

#define CT_COLD_REQUIRED 0x1fU
#define CT_COLD_COUNT 5U

struct ct_cold_register {
	enum ct_cold_window window;
	u32 offset, mask, value;
};

struct ct_cold_io {
	void *ctx;
	u32 ready;
	int (*lease_valid)(void *ctx);
	int (*read)(void *ctx, enum ct_cold_window window, u32 offset, u32 *value);
	int (*write)(void *ctx, enum ct_cold_window window, u32 offset, u32 value);
	u64 (*now)(void *ctx);
};

struct ct_cold_result {
	enum ct_cold_state state;
	u32 saved[CT_COLD_COUNT], desired[CT_COLD_COUNT];
	unsigned int saved_count, touched, applied, restored;
	int transaction_error, restore_error;
};

static const struct ct_cold_register ct_cold_config[CT_COLD_COUNT] = {
	{ CT_COLD_WED, 0xa04, 0xfc7fdfcf, 0x00210020 },
	{ CT_COLD_WDMA, 0x204, 0xffffffff, 0x1c000000 },
	{ CT_COLD_WED, 0xaa0, 0, 0x1fa00000 },
	{ CT_COLD_WED, 0xaa4, 0, 0x66046620 },
	{ CT_COLD_WED, 0xaa8, 0, 0x65006400 },
};

static const struct ct_cold_register ct_cold_guards[] = {
	{ CT_COLD_WED, 0x008, 0xffffffff, 0 },
	{ CT_COLD_WED, 0x00c, 0x00000f00, 0 },
	{ CT_COLD_WED, 0x208, 0x0000000f, 0 },
	{ CT_COLD_WED, 0x508, 0x0000000f, 0 },
	{ CT_COLD_WED, 0xa04, 0x0400000f, 0 },
	{ CT_COLD_WDMA, 0x204, 0x0000000f, 0 },
};

static inline int ct_cold_gate(const struct ct_cold_io *io, u64 deadline)
{
	int err;

	if (io->now(io->ctx) >= deadline)
		return -ETIMEDOUT;
	err = io->lease_valid(io->ctx);
	if (err)
		return err;
	return io->now(io->ctx) < deadline ? 0 : -ETIMEDOUT;
}

static inline int ct_cold_read(const struct ct_cold_io *io, u64 deadline,
			       const struct ct_cold_register *reg, u32 *value)
{
	int err = ct_cold_gate(io, deadline);

	if (!err)
		err = io->read(io->ctx, reg->window, reg->offset, value);
	if (!err)
		err = ct_cold_gate(io, deadline);
	return err;
}

static inline int ct_cold_inactive(const struct ct_cold_io *io, u64 deadline)
{
	unsigned int index;
	u32 value;
	int err;

	for (index = 0; index < sizeof(ct_cold_guards) / sizeof(ct_cold_guards[0]); index++) {
		const struct ct_cold_register *reg = &ct_cold_guards[index];

		err = ct_cold_read(io, deadline, reg, &value);
		if (err)
			return err;
		if ((value & reg->mask) != reg->value)
			return -EBUSY;
	}
	return 0;
}

static inline int ct_cold_transaction(const struct ct_cold_io *io, u64 deadline,
				      u64 restore_reserve, struct ct_cold_result *result)
{
	u64 forward_deadline;
	unsigned int index;
	u32 value;
	int err;

	if (!result)
		return -EINVAL;
	*result = (struct ct_cold_result) { .state = CT_COLD_CLEAN };
	if (!io || !io->read || !io->write || !io->lease_valid || !io->now ||
	    !restore_reserve || deadline <= restore_reserve)
		return -EINVAL;
	if ((io->ready & CT_COLD_REQUIRED) != CT_COLD_REQUIRED)
		return -EAGAIN;
	forward_deadline = deadline - restore_reserve;
	err = ct_cold_inactive(io, forward_deadline);
	if (err)
		goto finish;
	for (index = 0; index < CT_COLD_COUNT; index++) {
		const struct ct_cold_register *reg = &ct_cold_config[index];

		err = ct_cold_read(io, forward_deadline, reg, &result->saved[index]);
		if (err)
			goto finish;
		result->saved_count++;
		result->desired[index] = (result->saved[index] & reg->mask) | reg->value;
	}
	for (index = 0; index < CT_COLD_COUNT; index++) {
		const struct ct_cold_register *reg = &ct_cold_config[index];

		err = ct_cold_inactive(io, forward_deadline);
		if (err)
			goto restore;
		err = ct_cold_gate(io, forward_deadline);
		if (err)
			goto restore;
		result->state = CT_COLD_RETAINED;
		result->touched = index + 1;
		err = io->write(io->ctx, reg->window, reg->offset, result->desired[index]);
		if (err)
			goto restore;
		err = ct_cold_read(io, forward_deadline, reg, &value);
		if (!err && value != result->desired[index])
			err = -EIO;
		if (err)
			goto restore;
		result->applied++;
	}
	err = ct_cold_inactive(io, forward_deadline);
restore:
	result->transaction_error = err;
	if (!result->touched)
		goto finish;
	result->restore_error = ct_cold_inactive(io, deadline);
	if (result->restore_error)
		return -EUCLEAN;
	for (index = result->touched; index; index--) {
		const struct ct_cold_register *reg = &ct_cold_config[index - 1];
		int restore_err;

		restore_err = ct_cold_inactive(io, deadline);
		if (restore_err) {
			if (!result->restore_error)
				result->restore_error = restore_err;
			break;
		}
		restore_err = io->write(io->ctx, reg->window, reg->offset,
					result->saved[index - 1]);
		if (!restore_err)
			restore_err = ct_cold_read(io, deadline, reg, &value);
		if (!restore_err && value != result->saved[index - 1])
			restore_err = -EIO;
		if (restore_err) {
			if (!result->restore_error)
				result->restore_error = restore_err;
		} else {
			result->restored++;
		}
	}
	if (!result->restore_error)
		result->restore_error = ct_cold_inactive(io, deadline);
	if (result->restore_error)
		return -EUCLEAN;
	result->state = CT_COLD_CLEAN;
	return result->transaction_error;
finish:
	result->transaction_error = err;
	return err;
}

#endif
