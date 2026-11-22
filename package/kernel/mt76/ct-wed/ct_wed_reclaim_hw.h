#ifndef CT_WED_RECLAIM_HW_H
#define CT_WED_RECLAIM_HW_H

#include "ct_wed_refill_sample.h"

#define CT_WED_RECLAIM_TX_RINGS 2U

struct ct_wed_reclaim_hw_ring {
	u32 count, cidx, didx, cidx_mirror;
};

struct ct_wed_reclaim_hw_dma {
	struct ct_wed_reclaim_hw_ring host[CT_WED_RECLAIM_TX_RINGS];
	struct ct_wed_reclaim_hw_ring mid[CT_WED_RECLAIM_TX_RINGS];
	struct ct_wed_reclaim_hw_ring bar_tx[CT_WED_RECLAIM_TX_RINGS];
	struct ct_wed_reclaim_hw_ring host_wa, mid_wa, bar_wa;
	u32 wed_dma, wpdma_dma, wdma_driver, wdma_dma, wed_ctrl, bar_dma;
	u32 wed_irq_mask, bar_irq_mask;
};

struct airoha_ct_wed_reclaim_hw {
	struct airoha_ct_wed_refill_sample refill;
	struct ct_wed_reclaim_hw_dma dma;
};

int airoha_ct_wed_read_reclaim_hw(struct airoha_ct_wed_lease_v2 *lease,
				 const struct device *radio,
				 const u32 indices[CT_LIVE_RX_RINGS],
				 struct airoha_ct_wed_reclaim_hw *sample);
int airoha_ct_wed_platform_read_reclaim_hw(struct airoha_ct_wed *wed,
					  const struct device *radio,
					  const u32 indices[CT_LIVE_RX_RINGS],
					  struct airoha_ct_wed_reclaim_hw *sample);

#endif
