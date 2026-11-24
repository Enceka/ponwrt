#ifndef CT_WED_LIVE_SAMPLE_H
#define CT_WED_LIVE_SAMPLE_H

#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

#define CT_LIVE_RX_RINGS 2U
#define CT_LIVE_RX_COUNT 1024U
#define CT_LIVE_RX_POSTED_CTRL 0x076c4080U

struct airoha_ct_wed;
struct airoha_ct_wed_lease_v2;
struct device;

struct ct_live_ring_sample {
	u32 wdma_cidx, wdma_didx, wed_cidx, wed_didx;
	u32 received, processed, recycled, wpdma_tx;
	u32 desc[4];
};

struct airoha_ct_wed_live_sample {
	struct ct_live_ring_sample ring[CT_LIVE_RX_RINGS];
	u32 txfree, wpdma_txfree, wpdma_free_token;
	u32 bm_issued, bm_returned;
};

int airoha_ct_wed_read_live(struct airoha_ct_wed_lease_v2 *lease,
			   const struct device *radio,
			   struct airoha_ct_wed_live_sample *sample);
int airoha_ct_wed_platform_read_live(struct airoha_ct_wed *wed,
				    const struct device *radio,
				    struct airoha_ct_wed_live_sample *sample);

struct ct_live_sample_io {
	void *ctx;
	u32 (*read)(void *ctx, bool wdma, u32 offset);
	void (*desc)(void *ctx, unsigned int ring, unsigned int index, u32 words[4]);
	bool (*buffer_pair_valid)(void *ctx, u32 payload, u32 header);
};

static inline bool ct_live_word_valid(u32 value)
{
	return value != 0xdeadbeefU && value != 0xffffffffU;
}

static inline int ct_live_read_fields(const struct ct_live_sample_io *io,
				      struct airoha_ct_wed_live_sample *sample,
				      u32 shadow[CT_LIVE_RX_RINGS])
{
	unsigned int index;

	for (index = 0; index < CT_LIVE_RX_RINGS; index++) {
		struct ct_live_ring_sample *ring = &sample->ring[index];
		u32 stride = 0x10 * index;
		u32 offset = 4 * index;
		u32 packed;

		ring->wdma_cidx = io->read(io->ctx, true, 0x108 + stride);
		ring->wdma_didx = io->read(io->ctx, true, 0x10c + stride);
		packed = io->read(io->ctx, false, 0x908 + stride);
		ring->wed_cidx = packed & 0xffff;
		shadow[index] = packed >> 16;
		ring->wed_didx = io->read(io->ctx, false, 0x90c + stride);
		ring->received = io->read(io->ctx, false, 0xae0 + offset);
		ring->recycled = io->read(io->ctx, false, 0xae8 + offset);
		ring->processed = io->read(io->ctx, false, 0xaf0 + offset);
		ring->wpdma_tx = io->read(io->ctx, false, 0x5a0 + offset);
		if (ring->wdma_cidx >= CT_LIVE_RX_COUNT ||
		    ring->wdma_didx >= CT_LIVE_RX_COUNT ||
		    ring->wed_cidx >= CT_LIVE_RX_COUNT || shadow[index] >= CT_LIVE_RX_COUNT ||
		    ring->wed_didx >= CT_LIVE_RX_COUNT ||
		    !ct_live_word_valid(ring->received) ||
		    !ct_live_word_valid(ring->recycled) ||
		    !ct_live_word_valid(ring->processed) ||
		    !ct_live_word_valid(ring->wpdma_tx))
			return -EIO;
		if ((shadow[index] && shadow[index] != ring->wed_didx) ||
		    ring->wdma_cidx != ring->wed_cidx ||
		    ring->wdma_didx != ring->wed_didx ||
		    ring->wdma_cidx != (ring->wdma_didx + CT_LIVE_RX_COUNT - 1) %
				      CT_LIVE_RX_COUNT)
			return -EAGAIN;
	}
	sample->txfree = io->read(io->ctx, false, 0x2e4);
	sample->wpdma_txfree = io->read(io->ctx, false, 0x5e4);
	sample->wpdma_free_token = io->read(io->ctx, false, 0x5f8);
	sample->bm_returned = io->read(io->ctx, false, 0x1c0);
	sample->bm_issued = io->read(io->ctx, false, 0x1c4);
	if (!ct_live_word_valid(sample->txfree) || !ct_live_word_valid(sample->wpdma_txfree) ||
	    !ct_live_word_valid(sample->wpdma_free_token) ||
	    !ct_live_word_valid(sample->bm_returned) || !ct_live_word_valid(sample->bm_issued))
		return -EIO;
	return 0;
}

static inline int ct_live_read_desc(const struct ct_live_sample_io *io,
				    struct airoha_ct_wed_live_sample *sample)
{
	unsigned int index, word;

	for (index = 0; index < CT_LIVE_RX_RINGS; index++) {
		struct ct_live_ring_sample *ring = &sample->ring[index];

		io->desc(io->ctx, index, ring->wdma_didx, ring->desc);
		for (word = 0; word < 4; word++)
			if (!ct_live_word_valid(ring->desc[word]))
				return -EIO;
		if (ring->desc[1] != CT_LIVE_RX_POSTED_CTRL ||
		    !io->buffer_pair_valid(io->ctx, ring->desc[0], ring->desc[2]))
			return -EAGAIN;
	}
	return 0;
}

static inline int ct_live_sample_read(const struct ct_live_sample_io *io,
				       struct airoha_ct_wed_live_sample *sample)
{
	struct airoha_ct_wed_live_sample first = {}, second = {};
	u32 first_shadow[CT_LIVE_RX_RINGS], second_shadow[CT_LIVE_RX_RINGS];
	int err;

	*sample = (struct airoha_ct_wed_live_sample) {};
	err = ct_live_read_fields(io, &first, first_shadow);
	if (!err)
		err = ct_live_read_desc(io, &first);
	if (!err) {
		second = first;
		err = ct_live_read_desc(io, &second);
	}
	if (!err)
		err = ct_live_read_fields(io, &second, second_shadow);
	if (err)
		return err;
	if (memcmp(&first, &second, sizeof(first)) ||
	    memcmp(first_shadow, second_shadow, sizeof(first_shadow)))
		return -EAGAIN;
	*sample = first;
	return 0;
}

#endif
