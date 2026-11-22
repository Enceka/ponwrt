#ifndef CT_WED_BM_SNAPSHOT_H
#define CT_WED_BM_SNAPSHOT_H

#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/types.h>

#define CT_BM_SNAPSHOT_WORDS 256U

struct ct_bm_snapshot {
	u32 bitmap[CT_BM_SNAPSHOT_WORDS];
	u32 saved_selector, before, after, bitmap_free;
	unsigned int words;
	int error, restore_error;
	bool counters_stable;
};

struct ct_bm_snapshot_io {
	void *ctx;
	int (*owner_valid)(void *ctx);
	int (*read)(void *ctx, u32 offset, u32 *value);
	int (*write)(void *ctx, u32 offset, u32 value);
	u64 (*now)(void *ctx);
};

static inline int ct_bm_snapshot_gate(const struct ct_bm_snapshot_io *io, u64 deadline)
{
	int err;

	if (io->now(io->ctx) >= deadline)
		return -ETIMEDOUT;
	err = io->owner_valid(io->ctx);
	return err ?: (io->now(io->ctx) >= deadline ? -ETIMEDOUT : 0);
}

static inline int ct_bm_snapshot_read(const struct ct_bm_snapshot_io *io, u64 deadline,
				     u32 offset, u32 *value)
{
	int err = ct_bm_snapshot_gate(io, deadline);

	if (!err)
		err = io->read(io->ctx, offset, value);
	if (!err && offset < 0xc00 && (*value == 0xffffffff || *value == 0xdeadbeef))
		err = -EIO;
	return err ?: ct_bm_snapshot_gate(io, deadline);
}

static inline int ct_bm_snapshot_select(const struct ct_bm_snapshot_io *io, u64 deadline,
				       u32 selector, bool *dirty)
{
	u32 posted;
	int err = ct_bm_snapshot_gate(io, deadline);

	if (!err) {
		*dirty = true;
		err = io->write(io->ctx, 0xbc0, selector);
	}
	if (!err)
		err = ct_bm_snapshot_read(io, deadline, 0xbc0, &posted);
	return err ?: (posted == selector ? 0 : -EIO);
}

static inline int ct_bm_snapshot_run(const struct ct_bm_snapshot_io *io, u64 deadline,
				    struct ct_bm_snapshot *result)
{
	bool dirty = false;
	u32 restored;
	unsigned int index;
	int err, restore = 0;

	if (!result)
		return -EINVAL;
	*result = (struct ct_bm_snapshot) {};
	if (!io || !io->owner_valid || !io->read || !io->write || !io->now)
		return result->error = -EINVAL;
	err = ct_bm_snapshot_read(io, deadline, 0xbc0, &result->saved_selector);
	if (!err)
		err = ct_bm_snapshot_select(io, deadline, 0x14, &dirty);
	if (!err)
		err = ct_bm_snapshot_read(io, deadline, 0xbd4, &result->before);
	if (!err)
		err = ct_bm_snapshot_select(io, deadline, 0x10000000, &dirty);
	for (index = 0; !err && index < CT_BM_SNAPSHOT_WORDS; index++) {
		err = ct_bm_snapshot_read(io, deadline, 0xc00 + index * 4, &result->bitmap[index]);
		if (!err) {
			result->bitmap_free += hweight32(result->bitmap[index]);
			result->words++;
		}
	}
	if (!err)
		err = ct_bm_snapshot_select(io, deadline, 0x14, &dirty);
	if (!err)
		err = ct_bm_snapshot_read(io, deadline, 0xbd4, &result->after);
	if (dirty) {
		restore = io->owner_valid(io->ctx);
		if (!restore)
			restore = io->write(io->ctx, 0xbc0, result->saved_selector);
		if (!restore)
			restore = io->read(io->ctx, 0xbc0, &restored);
		if (!restore && restored != result->saved_selector)
			restore = -EIO;
	}
	result->restore_error = restore;
	result->error = err ?: restore;
	result->counters_stable = !result->error && result->before == result->after;
	return result->error;
}

#endif
