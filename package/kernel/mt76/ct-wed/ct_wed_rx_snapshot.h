#ifndef CT_WED_RX_SNAPSHOT_H
#define CT_WED_RX_SNAPSHOT_H

#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include "ct_wdma_rx.h"

#define CT_RX_SNAPSHOT_FIELDS 7U
#define CT_RX_SNAPSHOT_FRONTIERS 4U
#define CT_RX_SNAPSHOT_DESCS 12U

struct ct_rx_snapshot_desc {
	u32 index, before[4], after[4];
};

struct ct_rx_snapshot_ring {
	u32 before[CT_RX_SNAPSHOT_FIELDS], after[CT_RX_SNAPSHOT_FIELDS];
	struct ct_rx_snapshot_desc desc[CT_RX_SNAPSHOT_DESCS];
	unsigned int count;
};

struct ct_rx_snapshot {
	struct ct_rx_snapshot_ring ring[CT_WDMA_RX_RINGS];
	int error;
	bool before_valid, after_valid, stable;
};

struct ct_rx_snapshot_io {
	void *ctx;
	int (*owner_valid)(void *ctx);
	int (*read)(void *ctx, unsigned int ring, unsigned int field, u32 *value);
	int (*desc_read)(void *ctx, unsigned int ring, unsigned int index, u32 words[4]);
	u64 (*now)(void *ctx);
};

static inline int ct_rx_snapshot_gate(const struct ct_rx_snapshot_io *io, u64 deadline)
{
	int err;

	if (io->now(io->ctx) >= deadline)
		return -ETIMEDOUT;
	err = io->owner_valid(io->ctx);
	return err ?: (io->now(io->ctx) >= deadline ? -ETIMEDOUT : 0);
}

static inline int ct_rx_snapshot_fields(const struct ct_rx_snapshot_io *io, u64 deadline,
				       struct ct_rx_snapshot *result, bool after)
{
	unsigned int ring, field;
	int err;

	for (ring = 0; ring < CT_WDMA_RX_RINGS; ring++) {
		u32 *values = after ? result->ring[ring].after : result->ring[ring].before;

		for (field = 0; field < CT_RX_SNAPSHOT_FIELDS; field++) {
			err = ct_rx_snapshot_gate(io, deadline);
			if (!err)
				err = io->read(io->ctx, ring, field, &values[field]);
			if (!err)
				err = ct_rx_snapshot_gate(io, deadline);
			if (!err && field < CT_RX_SNAPSHOT_FRONTIERS &&
			    (values[field] & 0xffff) >= CT_WDMA_RX_COUNT)
				err = -EIO;
			if (err)
				return err;
		}
	}
	return 0;
}

static inline int ct_rx_snapshot_run(const struct ct_rx_snapshot_io *io, u64 deadline,
				    struct ct_rx_snapshot *result)
{
	unsigned int ring, field, neighbor, found;
	int err;

	if (!result)
		return -EINVAL;
	*result = (struct ct_rx_snapshot) {};
	if (!io || !io->owner_valid || !io->read || !io->desc_read || !io->now)
		return result->error = -EINVAL;
	err = ct_rx_snapshot_fields(io, deadline, result, false);
	if (err)
		goto out;
	result->before_valid = true;
	for (ring = 0; ring < CT_WDMA_RX_RINGS; ring++) {
		struct ct_rx_snapshot_ring *sample = &result->ring[ring];

		for (field = 0; field < CT_RX_SNAPSHOT_FRONTIERS; field++) {
			for (neighbor = 0; neighbor < 3; neighbor++) {
				struct ct_rx_snapshot_desc *desc;
				u32 index = ((sample->before[field] & 0xffff) +
					     CT_WDMA_RX_COUNT + neighbor - 1) % CT_WDMA_RX_COUNT;

				for (found = 0; found < sample->count; found++)
					if (sample->desc[found].index == index)
						break;
				if (found != sample->count)
					continue;
				desc = &sample->desc[sample->count];
				desc->index = index;
				err = ct_rx_snapshot_gate(io, deadline);
				if (!err)
					err = io->desc_read(io->ctx, ring, index, desc->before);
				if (!err)
					err = ct_rx_snapshot_gate(io, deadline);
				if (!err)
					err = io->desc_read(io->ctx, ring, index, desc->after);
				if (!err)
					err = ct_rx_snapshot_gate(io, deadline);
				if (err)
					goto out;
				sample->count++;
			}
		}
	}
	err = ct_rx_snapshot_fields(io, deadline, result, true);
	if (err)
		goto out;
	result->after_valid = true;
	result->stable = true;
	for (ring = 0; ring < CT_WDMA_RX_RINGS; ring++) {
		struct ct_rx_snapshot_ring *sample = &result->ring[ring];

		if (memcmp(sample->before, sample->after, sizeof(sample->before)))
			result->stable = false;
		for (found = 0; found < sample->count; found++)
			if (memcmp(sample->desc[found].before, sample->desc[found].after,
				   sizeof(sample->desc[found].before)))
				result->stable = false;
	}
out:
	result->error = err;
	return err;
}

static inline bool ct_rx_snapshot_seed(const u32 words[4])
{
	return !words[0] && words[1] == 0x80000000 && !words[2] && !words[3];
}

#endif
