#ifndef CT_WED_BM_H
#define CT_WED_BM_H

#include <linux/types.h>

#define CT_BM_COUNT 8192U
#define CT_BM_HEADER_SIZE 128U
#define CT_BM_PAYLOAD_SIZE 1900U
#define CT_BM_PAYLOAD_STRIDE 2048U
#define CT_BM_CHUNK_TOKENS 256U
#define CT_BM_CHUNKS (CT_BM_COUNT / CT_BM_CHUNK_TOKENS)

struct ct_bm_desc {
	__le32 header, lengths, payload, info;
};

static inline void ct_bm_encode(struct ct_bm_desc *desc, void *header,
			       u32 header_dma, u32 payload_dma, u16 token)
{
	__le32 *words = header;
	u8 *bytes = header;

	*desc = (struct ct_bm_desc) {
		.header = cpu_to_le32(header_dma),
		.lengths = cpu_to_le32((CT_BM_HEADER_SIZE << 16) | 0x4000 | CT_BM_PAYLOAD_SIZE),
		.payload = cpu_to_le32(payload_dma),
	};
	words[0] = cpu_to_le32(32);
	words[1] = cpu_to_le32(0x80000000);
	words[8] = cpu_to_le32((u32)token << 16);
	bytes[39] = 1;
	words[10] = cpu_to_le32(payload_dma);
}

#endif
