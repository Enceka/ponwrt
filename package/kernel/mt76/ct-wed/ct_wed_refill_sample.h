#ifndef CT_WED_REFILL_SAMPLE_H
#define CT_WED_REFILL_SAMPLE_H

#include "ct_wed_live_sample.h"

struct ct_refill_ring_sample {
	u32 index, desc[4];
	bool posted;
};

struct airoha_ct_wed_refill_sample {
	struct airoha_ct_wed_live_sample live;
	struct ct_refill_ring_sample refill[CT_LIVE_RX_RINGS];
};

int airoha_ct_wed_read_refill(struct airoha_ct_wed_lease_v2 *lease,
			     const struct device *radio,
			     const u32 indices[CT_LIVE_RX_RINGS],
			     struct airoha_ct_wed_refill_sample *sample);
int airoha_ct_wed_platform_read_refill(struct airoha_ct_wed *wed,
				      const struct device *radio,
				      const u32 indices[CT_LIVE_RX_RINGS],
				      struct airoha_ct_wed_refill_sample *sample);

static inline int ct_refill_read_desc(const struct ct_live_sample_io *io,
				      struct airoha_ct_wed_refill_sample *sample)
{
	unsigned int index, word;

	for (index = 0; index < CT_LIVE_RX_RINGS; index++) {
		struct ct_refill_ring_sample *refill = &sample->refill[index];

		io->desc(io->ctx, index, refill->index, refill->desc);
		for (word = 0; word < 4; word++)
			if (!ct_live_word_valid(refill->desc[word]))
				return -EIO;
		refill->posted = false;
		if (!refill->desc[0] && refill->desc[1] == 0x80000000U &&
		    !refill->desc[2] && !refill->desc[3])
			continue;
		if (refill->desc[1] != CT_LIVE_RX_POSTED_CTRL ||
		    !io->buffer_pair_valid(io->ctx, refill->desc[0], refill->desc[2]))
			return -EAGAIN;
		refill->posted = true;
	}
	return 0;
}

static inline int ct_refill_sample_read(const struct ct_live_sample_io *io,
					const u32 indices[CT_LIVE_RX_RINGS],
					struct airoha_ct_wed_refill_sample *sample)
{
	struct airoha_ct_wed_refill_sample first = {}, second = {};
	unsigned int index;
	int err;

	if (!sample)
		return -EINVAL;
	*sample = (struct airoha_ct_wed_refill_sample) {};
	if (!io || !io->read || !io->desc || !io->buffer_pair_valid || !indices)
		return -EINVAL;
	for (index = 0; index < CT_LIVE_RX_RINGS; index++) {
		if (indices[index] >= CT_LIVE_RX_COUNT)
			return -EINVAL;
		first.refill[index].index = indices[index];
	}
	err = ct_live_read_fields(io, &first.live);
	if (!err)
		err = ct_live_read_desc(io, &first.live);
	if (!err)
		err = ct_refill_read_desc(io, &first);
	if (!err) {
		second = first;
		err = ct_live_read_desc(io, &second.live);
	}
	if (!err)
		err = ct_refill_read_desc(io, &second);
	if (!err)
		err = ct_live_read_fields(io, &second.live);
	if (err)
		return err;
	if (memcmp(&first, &second, sizeof(first)))
		return -EAGAIN;
	*sample = first;
	return 0;
}

#endif
