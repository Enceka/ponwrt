#ifndef CT_WDMA_RX_H
#define CT_WDMA_RX_H

#include <linux/types.h>

#define CT_WDMA_RX_COUNT 1024U
#define CT_WDMA_RX_RINGS 2U

enum ct_rx_window { CT_RX_WDMA, CT_RX_WED };

struct ct_rx_write {
	enum ct_rx_window window;
	u32 offset, value;
};

struct ct_rx_plan {
	struct ct_rx_write writes[5];
};

static inline struct ct_rx_plan ct_rx_cold_plan(unsigned int ring, u32 dma)
{
	u32 stride = ring * 0x10;

	return (struct ct_rx_plan) { .writes = {
		{ CT_RX_WDMA, 0x100 + stride, dma },
		{ CT_RX_WDMA, 0x104 + stride, CT_WDMA_RX_COUNT },
		{ CT_RX_WDMA, 0x108 + stride, 0 },
		{ CT_RX_WED, 0x900 + stride, dma },
		{ CT_RX_WED, 0x904 + stride, CT_WDMA_RX_COUNT },
	} };
}

#endif
