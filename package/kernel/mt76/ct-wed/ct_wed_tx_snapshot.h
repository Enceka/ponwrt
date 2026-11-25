#ifndef CT_WED_TX_SNAPSHOT_H
#define CT_WED_TX_SNAPSHOT_H

#include <linux/errno.h>
#include <linux/types.h>

#include "ct_wed_bm.h"

#define CT_TX_SNAPSHOT_PER_RING 2U
#define CT_TX_SNAPSHOT_HEADER_BYTES 76U
#define CT_TX_SNAPSHOT_PAYLOAD_BYTES 72U

static inline int ct_tx_snapshot_token(u64 base, size_t bytes, u32 address, u32 *token)
{
	u64 delta;

	if (!token || bytes != CT_BM_COUNT * CT_BM_HEADER_SIZE || address < base)
		return -ERANGE;
	delta = address - base;
	if (delta >= bytes || delta % CT_BM_HEADER_SIZE)
		return -ERANGE;
	*token = delta / CT_BM_HEADER_SIZE;
	return 0;
}

static inline int ct_tx_snapshot_payload(u64 base, size_t bytes, u32 token,
					 u32 address, size_t *offset)
{
	size_t position;

	if (!offset || token >= CT_BM_COUNT ||
	    bytes != CT_BM_CHUNK_TOKENS * CT_BM_PAYLOAD_STRIDE)
		return -ERANGE;
	position = token % CT_BM_CHUNK_TOKENS * CT_BM_PAYLOAD_STRIDE;
	if (base + position != address)
		return -ERANGE;
	*offset = position;
	return 0;
}

#endif
