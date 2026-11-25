#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/irqdomain.h>
#include <linux/kref.h>
#include <linux/ktime.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/overflow.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/sysfs.h>
#include <linux/unaligned.h>

#include "../ct-wed-provider-abi.h"
#include "ct_wdma_rx.h"
#include "ct_wed_live_sample.h"
#include "ct_wed_refill_sample.h"
#include "ct_wed_reclaim_hw.h"
#include "ct_wed_bm.h"
#include "ct_wed_bm_snapshot.h"
#include "ct_wed_rx_snapshot.h"
#include "ct_wed_tx_snapshot.h"
#include "ct_wed_cold.h"
#include "ct_wed_start.h"

#define CT_TX_COUNT 2048
#define CT_TX_BYTES (CT_TX_COUNT * sizeof(struct ct_txd))

struct ct_txd {
	__le32 buf0, ctrl, buf1, info;
};

struct ct_mid_ring {
	struct ct_txd *desc;
	dma_addr_t dma;
	u32 bar_csr, wed_csr;
	u32 base, count, producer;
};

struct airoha_ct_wed {
	struct kref ref;
	struct device *dev;
	struct pci_dev *radio;
	void __iomem *wed, *wdma, *bar;
	struct resource *region[2];
	int irq[4];
	struct ct_mid_ring mid[2];
	struct {
		struct ct_txd *desc;
		dma_addr_t dma;
		struct ct_rx_plan plan;
	} rx[CT_WDMA_RX_RINGS];
	struct airoha_ct_wed_plan host;
	struct {
		void *cpu;
		dma_addr_t dma;
		size_t bytes;
	} bm[2 + CT_BM_CHUNKS];
	bool prepared;
	bool retained;
	bool irq_ready;
	bool ever_exposed;
	struct ct_cold_result cold;
	struct ct_start_result start;
};

static DEFINE_MUTEX(ct_lock);
static struct airoha_ct_wed *ct_slot;
static bool prepare;
static bool prepare_bm;
static bool inspect;
static bool cold_config;
static bool start_trace;
static bool bm_debug;
module_param(prepare, bool, 0444);
module_param(prepare_bm, bool, 0444);
module_param(inspect, bool, 0444);
module_param(cold_config, bool, 0444);
module_param(start_trace, bool, 0444);
module_param(bm_debug, bool, 0444);
MODULE_PARM_DESC(bm_debug, "Permit owned slot1 BM selector snapshots without writing the bitmap");
MODULE_PARM_DESC(start_trace, "Trace each cold-start MMIO access with a ten-second transaction deadline");
MODULE_PARM_DESC(cold_config, "Test and restore five idle slot1 configuration registers; requires inspect");
MODULE_PARM_DESC(inspect, "Read slot1 state after SCU reset and PCI preflight; never write registers");
MODULE_PARM_DESC(prepare_bm, "Prepare stock hardware token buffers without enabling DMA");
MODULE_PARM_DESC(prepare, "Permit a software-only dual-ring lease; engines stay disabled");

static void ct_release_locked(struct airoha_ct_wed *wed);

static void ct_free(struct kref *ref)
{
	struct airoha_ct_wed *wed = container_of(ref, struct airoha_ct_wed, ref);
	unsigned int idx;

	mutex_lock(&ct_lock);
	ct_release_locked(wed);
	mutex_unlock(&ct_lock);
	if (!IS_ERR_OR_NULL(wed->wed))
		iounmap(wed->wed);
	if (!IS_ERR_OR_NULL(wed->wdma))
		iounmap(wed->wdma);
	if (!IS_ERR_OR_NULL(wed->bar))
		iounmap(wed->bar);
	for (idx = 0; idx < ARRAY_SIZE(wed->region); idx++)
		if (wed->region[idx])
			release_mem_region(wed->region[idx]->start, resource_size(wed->region[idx]));
	put_device(wed->dev);
	kfree(wed);
}

static struct airoha_ct_wed *ct_get(struct device *dev)
{
	struct airoha_ct_wed *result = ERR_PTR(-ENODEV);
	struct device_node *provider;
	struct pci_dev *radio;

	if (!dev || !dev_is_pci(dev) || !prepare)
		return ERR_PTR(-ENODEV);
	radio = to_pci_dev(dev);
	if (pci_domain_nr(radio->bus) != 1 || radio->bus->number != 1 || radio->devfn ||
	    radio->vendor != PCI_VENDOR_ID_MEDIATEK || radio->device != 0x7906)
		return ERR_PTR(-ENODEV);
	provider = of_parse_phandle(dev->of_node, "airoha,wed-provider", 0);
	if (!provider)
		return ERR_PTR(-ENODEV);
	mutex_lock(&ct_lock);
	if (ct_slot && ct_slot->dev->of_node == provider && !ct_slot->radio) {
		result = ct_slot;
		kref_get(&result->ref);
		result->radio = pci_dev_get(radio);
	} else if (ct_slot && ct_slot->dev->of_node == provider) {
		result = ERR_PTR(-EBUSY);
	}
	mutex_unlock(&ct_lock);
	of_node_put(provider);
	return result;
}

static void ct_release_locked(struct airoha_ct_wed *wed)
{
	unsigned int idx;

	lockdep_assert_held(&ct_lock);
	if (wed->retained)
		return;
	for (idx = 0; idx < ARRAY_SIZE(wed->bm); idx++)
		if (wed->bm[idx].cpu)
			dma_free_coherent(wed->dev, wed->bm[idx].bytes,
					  wed->bm[idx].cpu, wed->bm[idx].dma);
	memset(wed->bm, 0, sizeof(wed->bm));
	for (idx = 0; idx < ARRAY_SIZE(wed->rx); idx++) {
		if (wed->rx[idx].desc)
			dma_free_coherent(wed->dev, CT_WDMA_RX_COUNT * sizeof(struct ct_txd),
					  wed->rx[idx].desc, wed->rx[idx].dma);
	}
	memset(wed->rx, 0, sizeof(wed->rx));
	for (idx = 0; idx < ARRAY_SIZE(wed->mid); idx++) {
		struct ct_mid_ring *ring = &wed->mid[idx];

		if (ring->desc)
			dma_free_coherent(wed->dev, CT_TX_BYTES, ring->desc, ring->dma);
		*ring = (struct ct_mid_ring){};
	}
	memset(&wed->host, 0, sizeof(wed->host));
	wed->prepared = false;
}

static void ct_release(struct airoha_ct_wed *wed)
{
	mutex_lock(&ct_lock);
	ct_release_locked(wed);
	mutex_unlock(&ct_lock);
}

static void ct_put(struct airoha_ct_wed *wed)
{
	struct pci_dev *radio;

	mutex_lock(&ct_lock);
	if (wed->retained) {
		mutex_unlock(&ct_lock);
		return;
	}
	ct_release_locked(wed);
	radio = wed->radio;
	wed->radio = NULL;
	mutex_unlock(&ct_lock);
	pci_dev_put(radio);
	kref_put(&wed->ref, ct_free);
}

static bool ct_overlap(u64 first, size_t first_size, u64 second, size_t second_size)
{
	return first < second + second_size && second < first + first_size;
}

static int ct_prepare_rx(struct airoha_ct_wed *wed, const struct airoha_ct_wed_plan *host)
{
	size_t bytes = CT_WDMA_RX_COUNT * sizeof(struct ct_txd);
	unsigned int idx, pos;

	lockdep_assert_held(&ct_lock);
	for (idx = 0; idx < ARRAY_SIZE(wed->rx); idx++) {
		dma_addr_t dma;
		struct ct_txd *desc = dma_alloc_coherent(wed->dev, bytes, &dma, GFP_KERNEL);

		if (!desc)
			return -ENOMEM;
		wed->rx[idx].desc = desc;
		wed->rx[idx].dma = dma;
		if (!dma || dma > U32_MAX - bytes + 1 || !IS_ALIGNED(dma, sizeof(*desc)))
			return -ERANGE;
		for (pos = 0; pos < ARRAY_SIZE(host->ring); pos++)
			if (ct_overlap(dma, bytes, host->ring[pos].desc,
				       host->ring[pos].count * sizeof(*desc)))
				return -EINVAL;
		for (pos = 0; pos < ARRAY_SIZE(wed->mid); pos++)
			if (ct_overlap(dma, bytes, wed->mid[pos].dma, CT_TX_BYTES))
				return -EINVAL;
		for (pos = 0; pos < idx; pos++)
			if (ct_overlap(dma, bytes, wed->rx[pos].dma, bytes))
				return -EINVAL;
		for (pos = 0; pos < CT_WDMA_RX_COUNT; pos++)
			desc[pos] = (struct ct_txd) { .ctrl = cpu_to_le32(BIT(31)) };
		wed->rx[idx].plan = ct_rx_cold_plan(idx, lower_32_bits(dma));
	}
	return 0;
}

static int ct_check_plan(struct airoha_ct_wed *wed, const struct airoha_ct_wed_plan *plan)
{
	unsigned int idx, other;

	if (!plan->host_token_count || plan->host_token_start >= BIT(16) ||
	    plan->host_token_count > BIT(16) - plan->host_token_start ||
	    !(pci_resource_flags(wed->radio, 0) & IORESOURCE_MEM) ||
	    plan->bar != pci_resource_start(wed->radio, 0) ||
	    plan->bar_len != pci_resource_len(wed->radio, 0) || plan->bar_len < 0xd7420)
		return -EINVAL;
	for (idx = 0; idx < AIROHA_CT_WED_RING_COUNT; idx++) {
		const struct airoha_ct_wed_ring *ring = &plan->ring[idx];
		u64 end;

		if (!ring->desc || !IS_ALIGNED(ring->desc, sizeof(struct ct_txd)) ||
		    !is_power_of_2(ring->count) || ring->count > CT_TX_COUNT ||
		    (idx < AIROHA_CT_WED_WA0 && ring->count != CT_TX_COUNT) ||
		    ring->didx >= ring->count || ring->cidx >= ring->count ||
		    check_add_overflow((u64)ring->desc, (u64)ring->count * sizeof(struct ct_txd) - 1, &end) ||
		    end > U32_MAX)
			return -EINVAL;
		for (other = 0; other < idx; other++)
			if (ct_overlap(ring->desc, ring->count * sizeof(struct ct_txd),
				       plan->ring[other].desc, plan->ring[other].count * sizeof(struct ct_txd)))
				return -EINVAL;
	}
	return 0;
}

static int ct_inspect_locked(struct airoha_ct_wed *wed)
{
	static const u16 wed_regs[] = {
		0x000, 0x008, 0x00c, 0x09c, 0x208, 0x508, 0xa04,
		0x504, 0x524, 0x560, 0x57c, 0xaa0, 0xaa4, 0xaa8,
		0x2a0, 0x2a4, 0x5a0, 0x5a4, 0xae0, 0xae4,
		0xae8, 0xaec, 0xaf0, 0xaf4,
		0x300, 0x304, 0x308, 0x30c, 0x310, 0x314, 0x318, 0x31c,
		0x410, 0x414, 0x418, 0x41c, 0x600, 0x604, 0x608, 0x60c,
		0x610, 0x614, 0x618, 0x61c, 0x710, 0x714, 0x718, 0x71c,
		0x900, 0x904, 0x908, 0x90c, 0x910, 0x914, 0x918, 0x91c,
	};
	static const u16 wdma_regs[] = { 0x204, 0x228, 0x100, 0x104, 0x108, 0x10c,
					0x110, 0x114, 0x118, 0x11c };
	struct regmap *scu;
	u32 reset, value;
	u16 command;
	unsigned int index;
	bool busy = false;
	int err;

	lockdep_assert_held(&ct_lock);
	if (!inspect)
		return 0;
	scu = syscon_regmap_lookup_by_compatible("airoha,en7581-scu");
	if (IS_ERR(scu))
		return PTR_ERR(scu);
	err = regmap_read(scu, 0x830, &reset);
	if (err)
		return err;
	if (reset == U32_MAX)
		return -EIO;
	if (reset & (BIT(19) | BIT(21)))
		return -EAGAIN;
	if (wed->radio->current_state != PCI_D0)
		return -EAGAIN;
	err = pcibios_err_to_errno(pci_read_config_word(wed->radio, PCI_COMMAND, &command));
	if (err)
		return err;
	if (command == U16_MAX || (command & (PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER)) !=
				       (PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER))
		return -EIO;
	dev_info(wed->dev, "slot1 read-only preflight SCU+830=%08x PCI=%04x; no reset or clock writes\n",
		 reset, command);
	for (index = 0; index < ARRAY_SIZE(wed_regs); index++) {
		value = readl(wed->wed + wed_regs[index]);
		dev_info(wed->dev, "slot1 snapshot WED+%03x=%08x\n", wed_regs[index], value);
		if (wed_regs[index] == 0 && (!value || value == U32_MAX))
			return -EIO;
		if ((wed_regs[index] == 0x208 || wed_regs[index] == 0x508 ||
		     wed_regs[index] == 0xa04) && (value & 0xf))
			busy = true;
		if (wed_regs[index] == 0x00c && (value & 0xf00))
			busy = true;
	}
	for (index = 0; index < ARRAY_SIZE(wdma_regs); index++) {
		value = readl(wed->wdma + wdma_regs[index]);
		dev_info(wed->dev, "slot1 snapshot WDMA+%03x=%08x\n", wdma_regs[index], value);
		if (wdma_regs[index] == 0x204 && (value & 0xf))
			busy = true;
	}
	return busy ? -EBUSY : 0;
}

static int ct_cold_current(void *ctx)
{
	struct airoha_ct_wed *wed = ctx;

	lockdep_assert_held(&ct_lock);
	return wed == ct_slot && wed->radio && !wed->prepared && !wed->retained ? 0 : -ESTALE;
}

static void __iomem *ct_cold_reg(struct airoha_ct_wed *wed, enum ct_cold_window window,
				u32 offset)
{
	if (!IS_ALIGNED(offset, sizeof(u32)))
		return NULL;
	if (window == CT_COLD_WED && offset <= 0xb00 - sizeof(u32))
		return wed->wed + offset;
	if (window == CT_COLD_WDMA && offset <= 0x400 - sizeof(u32))
		return wed->wdma + offset;
	return NULL;
}

static int ct_cold_mmio_read(void *ctx, enum ct_cold_window window, u32 offset, u32 *value)
{
	void __iomem *reg = ct_cold_reg(ctx, window, offset);

	if (!reg)
		return -EINVAL;
	*value = readl(reg);
	return 0;
}

static int ct_cold_mmio_write(void *ctx, enum ct_cold_window window, u32 offset, u32 value)
{
	void __iomem *reg = ct_cold_reg(ctx, window, offset);

	if (window == CT_COLD_WED) {
		if (offset != 0xa04 && offset != 0xaa0 && offset != 0xaa4 && offset != 0xaa8)
			return -EINVAL;
	} else if (window != CT_COLD_WDMA || offset != 0x204) {
		return -EINVAL;
	}
	if ((window == CT_COLD_WDMA && (value & 0xf)) ||
	    (window == CT_COLD_WED && offset == 0xa04 && (value & 0x0400000f)))
		return -EINVAL;
	if (!reg)
		return -EINVAL;
	writel(value, reg);
	return 0;
}

static u64 ct_cold_now(void *ctx)
{
	return ktime_get_ns();
}

static int ct_test_cold_locked(struct airoha_ct_wed *wed)
{
	struct ct_cold_io io = {
		.ctx = wed, .ready = CT_COLD_REQUIRED, .lease_valid = ct_cold_current,
		.read = ct_cold_mmio_read, .write = ct_cold_mmio_write, .now = ct_cold_now,
	};
	unsigned int index;
	int err;

	lockdep_assert_held(&ct_lock);
	if (wed->retained)
		return -EUCLEAN;
	if (!cold_config)
		return 0;
	if (!inspect)
		return -EINVAL;
	err = ct_cold_transaction(&io, ktime_get_ns() + 250 * NSEC_PER_MSEC,
				  150 * NSEC_PER_MSEC, &wed->cold);
	dev_info(wed->dev, "slot1 cold config applied=%u restored=%u state=%u error=%d/%d; no DMA enable writes\n",
		 wed->cold.applied, wed->cold.restored, wed->cold.state,
		 wed->cold.transaction_error, wed->cold.restore_error);
	for (index = 0; index < wed->cold.saved_count; index++)
		dev_info(wed->dev, "slot1 cold %s+%03x saved=%08x desired=%08x\n",
			 ct_cold_config[index].window == CT_COLD_WED ? "WED" : "WDMA",
			 ct_cold_config[index].offset, wed->cold.saved[index], wed->cold.desired[index]);
	if (wed->cold.state == CT_COLD_RETAINED) {
		wed->retained = true;
		__module_get(THIS_MODULE);
		dev_err(wed->dev, "slot1 cold restore failed; provider, radio reference and MMIO retained until reboot\n");
	}
	return err;
}

static int ct_prepare_bm(struct airoha_ct_wed *wed, const struct airoha_ct_wed_plan *host)
{
	unsigned int idx, pos;

	lockdep_assert_held(&ct_lock);
	static_assert(sizeof(struct ct_bm_desc) == 16);
	if (!prepare_bm)
		return 0;
	if (host->host_token_start != CT_BM_COUNT || host->host_token_count != 4096)
		return -EINVAL;
	for (idx = 0; idx < ARRAY_SIZE(wed->bm); idx++) {
		size_t bytes = idx == 0 ? CT_BM_COUNT * sizeof(struct ct_bm_desc) :
			       idx == 1 ? CT_BM_COUNT * CT_BM_HEADER_SIZE :
			       CT_BM_CHUNK_TOKENS * CT_BM_PAYLOAD_STRIDE;
		dma_addr_t dma;
		void *cpu = dma_alloc_coherent(wed->dev, bytes, &dma, GFP_KERNEL);

		if (!cpu)
			return -ENOMEM;
		wed->bm[idx].cpu = cpu;
		wed->bm[idx].dma = dma;
		wed->bm[idx].bytes = bytes;
		if (!dma || dma > U32_MAX - bytes + 1 || !IS_ALIGNED(dma, 16))
			return -ERANGE;
		for (pos = 0; pos < ARRAY_SIZE(host->ring); pos++)
			if (ct_overlap(dma, bytes, host->ring[pos].desc,
				       host->ring[pos].count * sizeof(struct ct_txd)))
				return -EINVAL;
		for (pos = 0; pos < ARRAY_SIZE(wed->mid); pos++)
			if (ct_overlap(dma, bytes, wed->mid[pos].dma, CT_TX_BYTES))
				return -EINVAL;
		for (pos = 0; pos < ARRAY_SIZE(wed->rx); pos++)
			if (ct_overlap(dma, bytes, wed->rx[pos].dma,
				       CT_WDMA_RX_COUNT * sizeof(struct ct_txd)))
				return -EINVAL;
		for (pos = 0; pos < idx; pos++)
			if (ct_overlap(dma, bytes, wed->bm[pos].dma, wed->bm[pos].bytes))
				return -EINVAL;
		memset(cpu, 0, bytes);
	}
	for (idx = 0; idx < CT_BM_COUNT; idx++) {
		struct ct_bm_desc *desc = wed->bm[0].cpu;
		unsigned int chunk = 2 + idx / CT_BM_CHUNK_TOKENS;
		unsigned int offset = idx % CT_BM_CHUNK_TOKENS * CT_BM_PAYLOAD_STRIDE;

		ct_bm_encode(&desc[idx], wed->bm[1].cpu + idx * CT_BM_HEADER_SIZE,
			     lower_32_bits(wed->bm[1].dma + idx * CT_BM_HEADER_SIZE),
			     lower_32_bits(wed->bm[chunk].dma + offset), idx);
	}
	dev_info(wed->dev, "prepared BM: %u hardware tokens, %u-byte headers, %u-byte payloads; no register writes\n",
		 CT_BM_COUNT, CT_BM_HEADER_SIZE, CT_BM_PAYLOAD_SIZE);
	return 0;
}

static int ct_acquire(struct airoha_ct_wed *wed, const struct airoha_ct_wed_plan *plan,
		      struct airoha_ct_wed_view *view)
{
	static const u16 host_csr[] = { 0x300, 0x310, 0x410 };
	unsigned int idx, pos;
	int err;

	static_assert(sizeof(struct ct_txd) == 16);
	static_assert(ARRAY_SIZE(host_csr) == AIROHA_CT_WED_RING_COUNT);
	if (!view || !plan)
		return -EINVAL;
	memset(view, 0, sizeof(*view));
	mutex_lock(&ct_lock);
	if (wed != ct_slot || !wed->radio) {
		err = -ENODEV;
		goto out;
	}
	if (wed->retained) {
		err = -EUCLEAN;
		goto out;
	}
	if (wed->prepared) {
		err = -EBUSY;
		goto out;
	}
	err = ct_check_plan(wed, plan);
	if (err)
		goto out;
	err = ct_inspect_locked(wed);
	if (err)
		goto out;
	err = ct_test_cold_locked(wed);
	if (err)
		goto out;
	for (idx = 0; idx < ARRAY_SIZE(wed->mid); idx++) {
		struct ct_mid_ring *ring = &wed->mid[idx];

		ring->desc = dma_alloc_coherent(wed->dev, CT_TX_BYTES, &ring->dma, GFP_KERNEL);
		if (!ring->desc) {
			err = -ENOMEM;
			goto unwind;
		}
		if (!ring->dma || (u64)ring->dma > U32_MAX - CT_TX_BYTES + 1 ||
		    !IS_ALIGNED(ring->dma, sizeof(struct ct_txd))) {
			err = -ERANGE;
			goto unwind;
		}
		for (pos = 0; pos < AIROHA_CT_WED_RING_COUNT; pos++) {
			if (!ct_overlap(ring->dma, CT_TX_BYTES, plan->ring[pos].desc,
					plan->ring[pos].count * sizeof(struct ct_txd)))
				continue;
			err = -EINVAL;
			goto unwind;
		}
		for (pos = 0; pos < CT_TX_COUNT; pos++)
			ring->desc[pos] = (struct ct_txd){ .ctrl = cpu_to_le32(BIT(31)) };
		ring->bar_csr = 0xd7300 + 16 * idx;
		ring->wed_csr = 0x600 + 16 * idx;
		ring->base = lower_32_bits(ring->dma);
		ring->count = CT_TX_COUNT;
		ring->producer = 0;
	}
	err = ct_prepare_rx(wed, plan);
	if (err)
		goto unwind;
	err = ct_prepare_bm(wed, plan);
	if (err)
		goto unwind;
	dev_info(wed->dev, "prepared WDMA RX %u/%u, WDMA+%03x/%03x WED+%03x/%03x; no register writes\n",
		 wed->rx[0].plan.writes[1].value, wed->rx[1].plan.writes[1].value,
		 wed->rx[0].plan.writes[0].offset, wed->rx[1].plan.writes[0].offset,
		 wed->rx[0].plan.writes[3].offset, wed->rx[1].plan.writes[3].offset);
	wed->host = *plan;
	wed->prepared = true;
	for (idx = 0; idx < ARRAY_SIZE(host_csr); idx++)
		view->csr[idx] = wed->wed + host_csr[idx];
	view->irq = wed->irq[0];
	dev_info(wed->dev, "prepared on %s: host TX %u/%u WA %u; separate WPDMA rings %u/%u, BAR+%x/%x WED+%x/%x; no DMA or IRQ change\n",
		 pci_name(wed->radio), plan->ring[0].count, plan->ring[1].count,
		 plan->ring[2].count, wed->mid[0].count, wed->mid[1].count,
		 wed->mid[0].bar_csr, wed->mid[1].bar_csr, wed->mid[0].wed_csr, wed->mid[1].wed_csr);
	goto out;
unwind:
	ct_release_locked(wed);
out:
	mutex_unlock(&ct_lock);
	return err;
}

static int ct_start_current(void *ctx)
{
	struct airoha_ct_wed *wed = ctx;

	lockdep_assert_held(&ct_lock);
	return wed == ct_slot && wed->radio && wed->prepared ? 0 : -ESTALE;
}

static int ct_start_expose(void *ctx)
{
	struct airoha_ct_wed *wed = ctx;

	lockdep_assert_held(&ct_lock);
	if (ct_start_current(wed) || wed->ever_exposed || wed->retained)
		return -ESTALE;
	wed->ever_exposed = true;
	wed->retained = true;
	__module_get(THIS_MODULE);
	return 0;
}

static void __iomem *ct_start_reg(struct airoha_ct_wed *wed,
				 enum ct_start_window window, u32 offset)
{
	if (!IS_ALIGNED(offset, sizeof(u32)))
		return NULL;
	if (window == CT_START_WED && offset <= 0xb00 - sizeof(u32))
		return wed->wed + offset;
	if (window == CT_START_WDMA && offset <= 0x400 - sizeof(u32))
		return wed->wdma + offset;
	if (window == CT_START_BAR && wed->bar && offset <= wed->host.bar_len - sizeof(u32))
		return wed->bar + offset;
	return NULL;
}

static int ct_start_mmio_read(void *ctx, enum ct_start_window window, u32 offset, u32 *value)
{
	struct airoha_ct_wed *wed = ctx;
	void __iomem *reg = ct_start_reg(wed, window, offset);

	if (!reg)
		return -EINVAL;
	if (start_trace)
		dev_info(wed->dev, "slot1 start read %u+%05x begin\n", window, offset);
	*value = readl(reg);
	if (start_trace)
		dev_info(wed->dev, "slot1 start read %u+%05x=%08x\n", window, offset, *value);
	return 0;
}

static int ct_start_mmio_write(void *ctx, enum ct_start_window window, u32 offset, u32 value)
{
	static const u16 wed_writes[] = {
		0x008, 0x00c, 0x028, 0x080, 0x084, 0x088, 0x08c, 0x0a0,
		0x204, 0x208, 0x300, 0x304, 0x308, 0x310, 0x314, 0x318,
		0x410, 0x414, 0x418, 0x504, 0x508, 0x520, 0x524,
		0x560, 0x564, 0x570, 0x57c, 0x580,
		0x600, 0x604, 0x608, 0x610, 0x614, 0x618,
		0x710, 0x714, 0x718, 0x900, 0x904, 0x910, 0x914,
		0xa04, 0xa28, 0xa2c, 0xaa0, 0xaa4, 0xaa8,
	};
	static const u16 wdma_writes[] = {
		0x100, 0x104, 0x108, 0x110, 0x114, 0x118, 0x204, 0x228, 0x254,
	};
	static const u32 bar_writes[] = {
		0xd7204, 0xd7300, 0xd7304, 0xd7308, 0xd7310, 0xd7314, 0xd7318,
		0xd7410, 0xd7414, 0xd7418,
	};
	struct airoha_ct_wed *wed = ctx;
	void __iomem *reg = ct_start_reg(wed, window, offset);
	unsigned int index;
	bool allowed = false;

	lockdep_assert_held(&ct_lock);
	if (!wed->ever_exposed || !wed->retained || !reg)
		return -EPERM;
	if (window == CT_START_WED) {
		for (index = 0; index < ARRAY_SIZE(wed_writes); index++)
			allowed |= offset == wed_writes[index];
		if ((offset == 8 && value != 1) || (offset == 0x28 && value) ||
		    (offset == 0x204 && value))
			return -EINVAL;
	} else if (window == CT_START_WDMA) {
		for (index = 0; index < ARRAY_SIZE(wdma_writes); index++)
			allowed |= offset == wdma_writes[index];
		if (offset == 0x204 && (value & 0xf))
			return -EINVAL;
	} else if (window == CT_START_BAR) {
		for (index = 0; index < ARRAY_SIZE(bar_writes); index++)
			allowed |= offset == bar_writes[index];
	}
	if (!allowed)
		return -EINVAL;
	if (start_trace)
		dev_info(wed->dev, "slot1 start write %u+%05x=%08x begin\n", window, offset, value);
	writel(value, reg);
	if (start_trace)
		dev_info(wed->dev, "slot1 start write %u+%05x done\n", window, offset);
	return 0;
}

static void ct_start_wait(void *ctx)
{
	udelay(1);
}

static int ct_start(struct airoha_ct_wed *wed, u32 ready)
{
	struct ct_start_plan plan = {};
	struct ct_start_io io = {
		.ctx = wed, .ready = ready, .lease_valid = ct_start_current,
		.expose = ct_start_expose, .read = ct_start_mmio_read,
		.write = ct_start_mmio_write, .now = ct_cold_now, .wait = ct_start_wait,
	};
	unsigned int index;
	int err;

	mutex_lock(&ct_lock);
	err = -EINVAL;
	if (ct_start_current(wed) || !prepare_bm || !inspect || wed->retained ||
	    wed->ever_exposed || !wed->bm[0].cpu || !wed->host.source_mask ||
	    (ready & CT_START_REQUIRED) != CT_START_REQUIRED)
		goto out;
	for (index = 0; index < ARRAY_SIZE(plan.host); index++) {
		const struct airoha_ct_wed_ring *ring = &wed->host.ring[index];

		plan.host[index] = (struct ct_start_ring) {
			.desc = lower_32_bits(ring->desc), .count = ring->count,
			.cidx = ring->cidx, .didx = ring->didx,
		};
	}
	for (index = 0; index < ARRAY_SIZE(plan.mid); index++) {
		plan.mid[index] = lower_32_bits(wed->mid[index].dma);
		plan.rx[index] = lower_32_bits(wed->rx[index].dma);
	}
	if (upper_32_bits(wed->host.bar))
		goto out;
	plan.bar_phys = lower_32_bits(wed->host.bar);
	plan.bm_dma = lower_32_bits(wed->bm[0].dma);
	plan.source_mask = wed->host.source_mask;
	err = ct_start_plan_valid(&plan);
	if (err)
		goto out;
	if (!wed->bar)
		wed->bar = ioremap(wed->host.bar, wed->host.bar_len);
	if (!wed->bar) {
		err = -ENOMEM;
		goto out;
	}
	dma_wmb();
	err = ct_start_configure(&io, &plan,
		ktime_get_ns() + (start_trace ? 10000 : 500) * NSEC_PER_MSEC, &wed->start);
	if (!err) {
		io.ready &= ~CT_START_NEVER_EXPOSED;
		err = ct_start_enable(&io, &plan, &wed->start);
	}
	if (!err)
		WRITE_ONCE(wed->irq_ready, true);
	dev_info(wed->dev, "slot1 start state=%u writes=%u verified=%u DIDX=%u error=%d last=%u+%03x; runtime IRQ masked\n",
		 wed->start.state, wed->start.writes, wed->start.verified, wed->start.didx_count,
		 err, wed->start.last_window, wed->start.last_offset);
out:
	mutex_unlock(&ct_lock);
	return err;
}

static void ct_stop(struct airoha_ct_wed *wed)
{
	static const u16 wed_regs[] = {
		0x200, 0x204, 0x208, 0x504, 0x508, 0x520, 0x524,
		0x564, 0x570, 0x57c, 0x580,
	};
	static const u32 bar_regs[] = {
		0xd7200, 0xd7204, 0xd4410, 0xd4414, 0xd4418, 0xd441c,
		0xd4500, 0xd4504, 0xd4508, 0xd450c,
	};
	unsigned int index;

	mutex_lock(&ct_lock);
	if (wed->ever_exposed) {
		if (start_trace && wed == ct_slot && READ_ONCE(wed->irq_ready)) {
			for (index = 0; index < ARRAY_SIZE(wed_regs); index++)
				dev_info(wed->dev, "slot1 before park WED+%03x=%08x\n",
					 wed_regs[index], readl(wed->wed + wed_regs[index]));
			for (index = 0; wed->bar && index < ARRAY_SIZE(bar_regs); index++)
				dev_info(wed->dev, "slot1 before park BAR+%05x=%08x\n",
					 bar_regs[index], readl(wed->bar + bar_regs[index]));
		}
		writel(0, wed->wed + 0x204);
		readl(wed->wed + 0x204);
		WRITE_ONCE(wed->irq_ready, false);
		wed->retained = true;
	}
	mutex_unlock(&ct_lock);
}
static void ct_irq_mask(struct airoha_ct_wed *wed, u32 mask)
{
	if (!wed || !READ_ONCE(wed->irq_ready))
		return;
	writel(mask, wed->wed + 0x204);
	readl(wed->wed + 0x204);
}

static u32 ct_irq_ack(struct airoha_ct_wed *wed, u32 mask)
{
	u32 pending;

	if (!wed || !READ_ONCE(wed->irq_ready))
		return 0;
	pending = readl(wed->wed + 0x200) & mask;
	if (pending) {
		writel(pending, wed->wed + 0x200);
		readl(wed->wed + 0x200);
	}
	return pending;
}

static u32 ct_live_platform_read(void *ctx, bool wdma, u32 offset)
{
	struct airoha_ct_wed *wed = ctx;

	return readl((wdma ? wed->wdma : wed->wed) + offset);
}

static void ct_live_platform_desc(void *ctx, unsigned int ring,
				  unsigned int index, u32 words[4])
{
	struct airoha_ct_wed *wed = ctx;
	const struct ct_txd *desc = &wed->rx[ring].desc[index];

	dma_rmb();
	words[0] = le32_to_cpu(READ_ONCE(desc->buf0));
	words[1] = le32_to_cpu(READ_ONCE(desc->ctrl));
	words[2] = le32_to_cpu(READ_ONCE(desc->buf1));
	words[3] = le32_to_cpu(READ_ONCE(desc->info));
}

static bool ct_live_platform_pair(void *ctx, u32 payload, u32 header)
{
	struct airoha_ct_wed *wed = ctx;
	unsigned int payload_chunk, token;
	u64 delta;

	if (!header || !payload || header < wed->bm[1].dma)
		return false;
	delta = header - wed->bm[1].dma;
	if (delta >= wed->bm[1].bytes || delta % CT_BM_HEADER_SIZE)
		return false;
	token = delta / CT_BM_HEADER_SIZE;
	payload_chunk = 2 + token / CT_BM_CHUNK_TOKENS;
	delta = (token % CT_BM_CHUNK_TOKENS) * CT_BM_PAYLOAD_STRIDE;
	return wed->bm[payload_chunk].dma + delta == payload;
}

static int ct_live_platform_ready(const struct airoha_ct_wed *wed, const struct device *radio)
{
	unsigned int index;

	lockdep_assert_held(&ct_lock);
	if (!wed || !radio || wed != ct_slot || !wed->radio || &wed->radio->dev != radio)
		return -ESTALE;
	if (!wed->prepared || !wed->ever_exposed || !wed->retained ||
	    !READ_ONCE(wed->irq_ready) || wed->start.state != CT_START_ENABLED)
		return -ESHUTDOWN;
	if (!wed->wed || !wed->wdma ||
	    !wed->bm[1].cpu || !wed->bm[1].dma ||
	    wed->bm[1].bytes != CT_BM_COUNT * CT_BM_HEADER_SIZE)
		return -EIO;
	for (index = 0; index < CT_WDMA_RX_RINGS; index++)
		if (!wed->rx[index].desc)
			return -EIO;
	for (index = 2; index < ARRAY_SIZE(wed->bm); index++)
		if (!wed->bm[index].cpu || !wed->bm[index].dma ||
		    wed->bm[index].bytes != CT_BM_CHUNK_TOKENS * CT_BM_PAYLOAD_STRIDE)
			return -EIO;
	return 0;
}

int airoha_ct_wed_platform_read_live(struct airoha_ct_wed *wed,
				    const struct device *radio,
				    struct airoha_ct_wed_live_sample *sample)
{
	const struct ct_live_sample_io io = {
		.ctx = wed, .read = ct_live_platform_read, .desc = ct_live_platform_desc,
		.buffer_pair_valid = ct_live_platform_pair,
	};
	int err;

	if (!sample)
		return -EINVAL;
	*sample = (struct airoha_ct_wed_live_sample) {};
	mutex_lock(&ct_lock);
	err = ct_live_platform_ready(wed, radio);
	if (err)
		goto out;
	err = ct_live_sample_read(&io, sample);
out:
	mutex_unlock(&ct_lock);
	return err;
}
EXPORT_SYMBOL_GPL(airoha_ct_wed_platform_read_live);

int airoha_ct_wed_platform_read_refill(struct airoha_ct_wed *wed,
				      const struct device *radio,
				      const u32 indices[CT_LIVE_RX_RINGS],
				      struct airoha_ct_wed_refill_sample *sample)
{
	const struct ct_live_sample_io io = {
		.ctx = wed, .read = ct_live_platform_read, .desc = ct_live_platform_desc,
		.buffer_pair_valid = ct_live_platform_pair,
	};
	u32 selected[CT_LIVE_RX_RINGS];
	unsigned int index;
	int err;

	if (!sample)
		return -EINVAL;
	*sample = (struct airoha_ct_wed_refill_sample) {};
	if (!indices)
		return -EINVAL;
	for (index = 0; index < CT_LIVE_RX_RINGS; index++) {
		selected[index] = READ_ONCE(indices[index]);
		if (selected[index] >= CT_LIVE_RX_COUNT)
			return -EINVAL;
	}
	mutex_lock(&ct_lock);
	err = ct_live_platform_ready(wed, radio);
	if (err)
		goto out;
	err = ct_refill_sample_read(&io, selected, sample);
out:
	mutex_unlock(&ct_lock);
	return err;
}
EXPORT_SYMBOL_GPL(airoha_ct_wed_platform_read_refill);

static int ct_reclaim_hw_read_ring(void __iomem *base, u32 count,
				   struct ct_wed_reclaim_hw_ring *ring)
{
	u32 cpu;

	ring->count = readl(base + 4);
	cpu = readl(base + 8);
	ring->didx = readl(base + 12);
	if (!count || ring->count != count || !ct_live_word_valid(cpu) ||
	    ring->didx >= count)
		return -EIO;
	ring->cidx = cpu & 0xffff;
	ring->cidx_mirror = cpu >> 16;
	if (ring->cidx >= count || ring->cidx_mirror >= count)
		return -EIO;
	return 0;
}

static int ct_reclaim_hw_read_dma(const struct airoha_ct_wed *wed,
				  struct ct_wed_reclaim_hw_dma *dma)
{
	const u32 wa_count = wed->host.ring[AIROHA_CT_WED_WA0].count;
	unsigned int index;
	int err;

	for (index = 0; index < CT_WED_RECLAIM_TX_RINGS; index++) {
		err = ct_reclaim_hw_read_ring(wed->wed + 0x300 + index * 16,
					      wed->host.ring[index].count, &dma->host[index]);
		if (!err)
			err = ct_reclaim_hw_read_ring(wed->wed + wed->mid[index].wed_csr,
						      wed->mid[index].count, &dma->mid[index]);
		if (!err)
			err = ct_reclaim_hw_read_ring(wed->bar + wed->mid[index].bar_csr,
						      wed->mid[index].count, &dma->bar_tx[index]);
		if (err)
			return err;
	}
	err = ct_reclaim_hw_read_ring(wed->wed + 0x410, wa_count, &dma->host_wa);
	if (!err)
		err = ct_reclaim_hw_read_ring(wed->wed + 0x710, wa_count, &dma->mid_wa);
	if (!err)
		err = ct_reclaim_hw_read_ring(wed->bar + 0xd7410, wa_count, &dma->bar_wa);
	if (err)
		return err;

	dma->wed_dma = readl(wed->wed + 0x208);
	dma->wpdma_dma = readl(wed->wed + 0x508);
	dma->wdma_driver = readl(wed->wed + 0xa04);
	dma->wdma_dma = readl(wed->wdma + 0x204);
	dma->wed_ctrl = readl(wed->wed + 0x00c);
	dma->bar_dma = readl(wed->bar + 0xd4208);
	dma->wed_irq_mask = readl(wed->wed + 0x204);
	dma->bar_irq_mask = readl(wed->bar + 0xd7204);
	if (!ct_live_word_valid(dma->wed_dma) || !ct_live_word_valid(dma->wpdma_dma) ||
	    !ct_live_word_valid(dma->wdma_driver) || !ct_live_word_valid(dma->wdma_dma) ||
	    !ct_live_word_valid(dma->wed_ctrl) || !ct_live_word_valid(dma->bar_dma) ||
	    !ct_live_word_valid(dma->wed_irq_mask) || !ct_live_word_valid(dma->bar_irq_mask))
		return -EIO;
	return 0;
}

int airoha_ct_wed_platform_read_reclaim_hw(struct airoha_ct_wed *wed,
					  const struct device *radio,
					  const u32 indices[CT_LIVE_RX_RINGS],
					  struct airoha_ct_wed_reclaim_hw *sample)
{
	const struct ct_live_sample_io io = {
		.ctx = wed, .read = ct_live_platform_read, .desc = ct_live_platform_desc,
		.buffer_pair_valid = ct_live_platform_pair,
	};
	struct airoha_ct_wed_reclaim_hw first = {};
	struct ct_wed_reclaim_hw_dma second = {};
	u32 selected[CT_LIVE_RX_RINGS];
	unsigned int index;
	int err;

	if (!sample)
		return -EINVAL;
	*sample = (struct airoha_ct_wed_reclaim_hw) {};
	if (indices)
		for (index = 0; index < CT_LIVE_RX_RINGS; index++) {
			selected[index] = READ_ONCE(indices[index]);
			if (selected[index] >= CT_LIVE_RX_COUNT)
				return -EINVAL;
		}

	mutex_lock(&ct_lock);
	err = ct_live_platform_ready(wed, radio);
	if (err)
		goto out;
	if (!wed->bar || wed->host.bar_len < 0xd7420) {
		err = -EIO;
		goto out;
	}

	err = ct_reclaim_hw_read_dma(wed, &first.dma);
	if (!err && indices)
		err = ct_refill_sample_read(&io, selected, &first.refill);
	else if (!err)
		err = ct_live_sample_read(&io, &first.refill.live);
	if (!err)
		err = ct_reclaim_hw_read_dma(wed, &second);
	if (!err && memcmp(&first.dma, &second, sizeof(second)))
		err = -EAGAIN;
	if (!err)
		*sample = first;
out:
	mutex_unlock(&ct_lock);
	return err;
}
EXPORT_SYMBOL_GPL(airoha_ct_wed_platform_read_reclaim_hw);

const struct airoha_ct_wed_ops airoha_ct_wed_ops_v1 = {
	.get = ct_get, .put = ct_put, .acquire = ct_acquire, .start = ct_start,
	.stop = ct_stop, .release = ct_release, .irq_mask = ct_irq_mask, .irq_ack = ct_irq_ack,
};
EXPORT_SYMBOL_GPL(airoha_ct_wed_ops_v1);

static void __iomem *ct_map(struct airoha_ct_wed *wed, const struct resource *res,
			   unsigned int index)
{
	wed->region[index] = request_mem_region(res->start, resource_size(res), dev_name(wed->dev));
	if (!wed->region[index])
		return ERR_PTR(-EBUSY);
	return ioremap(res->start, resource_size(res)) ?: ERR_PTR(-ENOMEM);
}

static int ct_probe(struct platform_device *pdev)
{
	static const unsigned int spi[] = { 68, 72, 73, 74 };
	static const char *const names[] = { "wed", "wdma0", "wdma1", "wdma2" };
	struct resource *res, *wdma;
	struct airoha_ct_wed *wed;
	unsigned int idx;
	int err;

	if (!of_machine_is_compatible("fiberhome,hg5585f-ct"))
		return -ENODEV;
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "wed");
	wdma = platform_get_resource_byname(pdev, IORESOURCE_MEM, "wdma");
	if (!res || res->start != 0x1fa03000 ||
	    (resource_size(res) != 0xb00 && resource_size(res) != 0x1000) ||
	    !wdma || wdma->start != 0x1fa06400 || resource_size(wdma) != 0x400)
		return -EINVAL;
	wed = kzalloc(sizeof(*wed), GFP_KERNEL);
	if (!wed)
		return -ENOMEM;
	kref_init(&wed->ref);
	wed->dev = get_device(&pdev->dev);
	wed->wed = ct_map(wed, res, 0);
	wed->wdma = ct_map(wed, wdma, 1);
	if (IS_ERR(wed->wed) || IS_ERR(wed->wdma)) {
		err = IS_ERR(wed->wed) ? PTR_ERR(wed->wed) : PTR_ERR(wed->wdma);
		goto free;
	}
	for (idx = 0; idx < ARRAY_SIZE(spi); idx++) {
		struct of_phandle_args spec;
		struct irq_data *data;

		err = of_irq_parse_one(pdev->dev.of_node, idx, &spec);
		if (err)
			goto free;
		err = spec.args_count == 3 && spec.args[0] == 0 && spec.args[1] == spi[idx] &&
		      spec.args[2] == IRQ_TYPE_LEVEL_HIGH && of_device_is_compatible(spec.np, "arm,gic-v3") ? 0 : -EINVAL;
		of_node_put(spec.np);
		if (err)
			goto free;
		err = platform_get_irq_byname(pdev, names[idx]);
		if (err < 0)
			goto free;
		wed->irq[idx] = err;
		data = irq_get_irq_data(err);
		if (!data || data->hwirq != spi[idx] + 32) {
			err = -EINVAL;
			goto free;
		}
	}
	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	if (err)
		goto free;
	mutex_lock(&ct_lock);
	if (ct_slot) {
		mutex_unlock(&ct_lock);
		err = -EBUSY;
		goto free;
	}
	platform_set_drvdata(pdev, wed);
	ct_slot = wed;
	mutex_unlock(&ct_lock);
	dev_info(wed->dev, "slot1 resources registered, preparation %s, DMA inactive\n", prepare ? "allowed" : "disabled");
	return 0;
free:
	kref_put(&wed->ref, ct_free);
	return err;
}

static void ct_remove(struct platform_device *pdev)
{
	struct airoha_ct_wed *wed = platform_get_drvdata(pdev);

	mutex_lock(&ct_lock);
	if (ct_slot == wed)
		ct_slot = NULL;
	mutex_unlock(&ct_lock);
	kref_put(&wed->ref, ct_free);
}

static ssize_t status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	static const struct {
		const char *name;
		u16 offset;
		bool wdma;
	} registers[] = {
		{ "tx_mib0", 0x2a0 }, { "tx_mib1", 0x2a4 },
		{ "wpdma_tx_mib0", 0x5a0 }, { "wpdma_tx_mib1", 0x5a4 },
		{ "txfree_mib", 0x2e4 }, { "wpdma_txfree_mib", 0x5e4 },
		{ "wpdma_free_token_mib", 0x5f8 },
		{ "tx_bm_state", 0x090 }, { "txfree_to_bm_mib", 0x1c0 },
		{ "txbm_to_wdma_mib", 0x1c4 },
		{ "wdma_rx_mib0", 0xae0 }, { "wdma_rx_mib1", 0xae4 },
		{ "wdma_recycle_mib0", 0xae8 }, { "wdma_recycle_mib1", 0xaec },
		{ "wdma_processed_mib0", 0xaf0 }, { "wdma_processed_mib1", 0xaf4 },
		{ "host_tx0_cidx", 0x308 }, { "host_tx0_didx", 0x30c },
		{ "host_tx1_cidx", 0x318 }, { "host_tx1_didx", 0x31c },
		{ "mid_tx0_cidx", 0x608 }, { "mid_tx0_didx", 0x60c },
		{ "mid_tx1_cidx", 0x618 }, { "mid_tx1_didx", 0x61c },
		{ "host_wa0_cidx", 0x418 }, { "host_wa0_didx", 0x41c },
		{ "mid_wa0_cidx", 0x718 }, { "mid_wa0_didx", 0x71c },
		{ "rx0_cidx", 0x108, true }, { "rx0_didx", 0x10c, true },
		{ "rx1_cidx", 0x118, true }, { "rx1_didx", 0x11c, true },
		{ "rx0_cidx", 0x908 }, { "rx0_didx", 0x90c },
		{ "rx1_cidx", 0x918 }, { "rx1_didx", 0x91c },
		{ "dma_ctrl", 0x208 }, { "wpdma_ctrl", 0x508 },
		{ "wdma_ctrl", 0xa04 }, { "dma_ctrl", 0x204, true },
	};
	struct airoha_ct_wed *wed;
	unsigned int index;
	bool irq_ready;
	ssize_t length;

	mutex_lock(&ct_lock);
	wed = dev_get_drvdata(dev);
	if (!wed) {
		length = -ENODEV;
		goto out;
	}
	irq_ready = READ_ONCE(wed->irq_ready);
	length = sysfs_emit_at(buf, 0,
		"state=%u ever_exposed=%u irq_ready=%u error=%d writes=%u verified=%u retained=%u\n",
		wed->start.state, wed->ever_exposed, irq_ready, wed->start.error,
		wed->start.writes, wed->start.verified, wed->retained);
	if (wed != ct_slot || !irq_ready)
		goto out;
	for (index = 0; index < ARRAY_SIZE(registers); index++) {
		void __iomem *base = registers[index].wdma ? wed->wdma : wed->wed;
		u32 value = readl(base + registers[index].offset);

		length += sysfs_emit_at(buf, length, "%s+%03x %s=%08x\n",
			registers[index].wdma ? "WDMA" : "WED", registers[index].offset,
			registers[index].name, value);
	}
out:
	mutex_unlock(&ct_lock);
	return length;
}
static DEVICE_ATTR_RO(status);

static int ct_bm_debug_current(void *ctx)
{
	struct airoha_ct_wed *wed = ctx;

	lockdep_assert_held(&ct_lock);
	if (!wed || !bm_debug || wed != ct_slot || !wed->ever_exposed ||
	    !READ_ONCE(wed->irq_ready) || wed->start.state != CT_START_ENABLED)
		return -EAGAIN;
	if (!wed->region[0] || resource_size(wed->region[0]) != 0x1000)
		return -EOPNOTSUPP;
	return 0;
}

static int ct_bm_debug_read(void *ctx, u32 offset, u32 *value)
{
	struct airoha_ct_wed *wed = ctx;
	int err = ct_bm_debug_current(ctx);

	if (err)
		return err;
	if (offset != 0xbc0 && offset != 0xbd4 &&
	    (offset < 0xc00 || offset > 0xffc || (offset & 3)))
		return -EINVAL;
	*value = readl(wed->wed + offset);
	return 0;
}

static int ct_bm_debug_write(void *ctx, u32 offset, u32 value)
{
	struct airoha_ct_wed *wed = ctx;
	int err = ct_bm_debug_current(ctx);

	if (err)
		return err;
	if (offset != 0xbc0)
		return -EINVAL;
	writel(value, wed->wed + offset);
	return 0;
}

static ssize_t bm_snapshot_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct ct_bm_snapshot result;
	struct ct_bm_snapshot_io io = {
		.owner_valid = ct_bm_debug_current, .read = ct_bm_debug_read,
		.write = ct_bm_debug_write, .now = ct_cold_now,
	};
	ssize_t length;
	unsigned int index;
	int err;

	mutex_lock(&ct_lock);
	io.ctx = dev_get_drvdata(dev);
	err = ct_bm_snapshot_run(&io, ktime_get_ns() + 50 * NSEC_PER_MSEC, &result);
	length = sysfs_emit(buf,
		"error=%d restore_error=%d words=%u selector=%08x bitmap_free=%u before_free=%u before_usage=%u after_free=%u after_usage=%u counters_stable=%u\n",
		err, result.restore_error, result.words, result.saved_selector, result.bitmap_free,
		result.before >> 16, result.before & 0xffff,
		result.after >> 16, result.after & 0xffff, result.counters_stable);
	for (index = 0; index < result.words; index++) {
		if (!(index % 8))
			length += sysfs_emit_at(buf, length, "bm+%03x", 0xc00 + index * 4);
		length += sysfs_emit_at(buf, length, " %08x", result.bitmap[index]);
		if (index % 8 == 7 || index + 1 == result.words)
			length += sysfs_emit_at(buf, length, "\n");
	}
	mutex_unlock(&ct_lock);
	return length;
}
static DEVICE_ATTR_RO(bm_snapshot);

static int ct_rx_debug_current(void *ctx)
{
	struct airoha_ct_wed *wed = ctx;
	unsigned int index;
	int err = ct_bm_debug_current(ctx);

	if (err)
		return err;
	for (index = 0; index < CT_WDMA_RX_RINGS; index++)
		if (!wed->rx[index].desc)
			return -EAGAIN;
	if (!wed->bm[1].cpu || wed->bm[1].bytes != CT_BM_COUNT * CT_BM_HEADER_SIZE)
		return -EAGAIN;
	for (index = 2; index < ARRAY_SIZE(wed->bm); index++)
		if (!wed->bm[index].cpu ||
		    wed->bm[index].bytes != CT_BM_CHUNK_TOKENS * CT_BM_PAYLOAD_STRIDE)
			return -EAGAIN;
	return 0;
}

static int ct_rx_debug_read(void *ctx, unsigned int ring, unsigned int field, u32 *value)
{
	static const u32 offsets[CT_RX_SNAPSHOT_FIELDS] = {
		0x108, 0x10c, 0x908, 0x90c, 0xae0, 0xae8, 0xaf0,
	};
	struct airoha_ct_wed *wed = ctx;
	u32 offset;
	int err = ct_rx_debug_current(ctx);

	if (err)
		return err;
	if (ring >= CT_WDMA_RX_RINGS || field >= CT_RX_SNAPSHOT_FIELDS)
		return -EINVAL;
	offset = offsets[field] + ring * (field < CT_RX_SNAPSHOT_FRONTIERS ? 0x10 : 4);
	*value = readl((field < 2 ? wed->wdma : wed->wed) + offset);
	return 0;
}

static int ct_rx_debug_desc_read(void *ctx, unsigned int ring, unsigned int index, u32 words[4])
{
	struct airoha_ct_wed *wed = ctx;
	struct ct_txd *desc;
	int err = ct_rx_debug_current(ctx);

	if (err)
		return err;
	if (ring >= CT_WDMA_RX_RINGS || index >= CT_WDMA_RX_COUNT)
		return -EINVAL;
	desc = &wed->rx[ring].desc[index];
	dma_rmb();
	words[0] = le32_to_cpu(READ_ONCE(desc->buf0));
	words[1] = le32_to_cpu(READ_ONCE(desc->ctrl));
	words[2] = le32_to_cpu(READ_ONCE(desc->buf1));
	words[3] = le32_to_cpu(READ_ONCE(desc->info));
	return 0;
}

static ssize_t rx_snapshot_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct ct_rx_snapshot result;
	struct ct_rx_snapshot_io io = {
		.owner_valid = ct_rx_debug_current, .read = ct_rx_debug_read,
		.desc_read = ct_rx_debug_desc_read, .now = ct_cold_now,
	};
	struct airoha_ct_wed *wed;
	unsigned int ring, index;
	ssize_t length;
	int err;

	mutex_lock(&ct_lock);
	wed = dev_get_drvdata(dev);
	io.ctx = wed;
	err = ct_rx_snapshot_run(&io, ktime_get_ns() + 50 * NSEC_PER_MSEC, &result);
	length = sysfs_emit(buf, "error=%d before_valid=%u after_valid=%u stable=%u\n",
			err, result.before_valid, result.after_valid, result.stable);
	if (result.before_valid && !ct_rx_debug_current(wed)) {
		length += sysfs_emit_at(buf, length,
			"bm_header=%08llx/%zx token_count=%u header_stride=%u payload_stride=%u\n",
			(unsigned long long)wed->bm[1].dma, wed->bm[1].bytes,
			CT_BM_COUNT, CT_BM_HEADER_SIZE, CT_BM_PAYLOAD_STRIDE);
		for (index = 0; index < CT_BM_CHUNKS; index++)
			length += sysfs_emit_at(buf, length, "bm_payload%02u=%08llx/%zx\n",
				index, (unsigned long long)wed->bm[2 + index].dma, wed->bm[2 + index].bytes);
	}
	for (ring = 0; ring < CT_WDMA_RX_RINGS; ring++) {
		struct ct_rx_snapshot_ring *sample = &result.ring[ring];

		if (result.before_valid)
			length += sysfs_emit_at(buf, length,
				"rx%u before c=[%08x %08x %08x %08x] mib=[%08x %08x %08x]\n",
				ring, sample->before[0], sample->before[1], sample->before[2], sample->before[3],
				sample->before[4], sample->before[5], sample->before[6]);
		if (result.after_valid)
			length += sysfs_emit_at(buf, length,
				"rx%u after c=[%08x %08x %08x %08x] mib=[%08x %08x %08x]\n",
				ring, sample->after[0], sample->after[1], sample->after[2], sample->after[3],
				sample->after[4], sample->after[5], sample->after[6]);
		for (index = 0; index < sample->count; index++) {
			struct ct_rx_snapshot_desc *desc = &sample->desc[index];

			length += sysfs_emit_at(buf, length,
				"rx%u[%04u] b=%08x,%08x,%08x,%08x a=%08x,%08x,%08x,%08x seed=%u/%u\n",
				ring, desc->index, desc->before[0], desc->before[1], desc->before[2], desc->before[3],
				desc->after[0], desc->after[1], desc->after[2], desc->after[3],
				ct_rx_snapshot_seed(desc->before), ct_rx_snapshot_seed(desc->after));
		}
	}
	mutex_unlock(&ct_lock);
	return length;
}
static DEVICE_ATTR_RO(rx_snapshot);

struct ct_tx_snapshot_entry {
	u32 descriptor[4], token;
	u8 header[CT_TX_SNAPSHOT_HEADER_BYTES];
	u8 payload[CT_TX_SNAPSHOT_PAYLOAD_BYTES];
	int error;
};

static void ct_tx_snapshot_read(struct airoha_ct_wed *wed, unsigned int ring,
			       unsigned int slot, struct ct_tx_snapshot_entry *entry)
{
	const struct ct_txd *descriptor = &wed->mid[ring].desc[slot];
	unsigned int chunk, index;
	const __le32 *words = (const __le32 *)descriptor;
	size_t offset;

	*entry = (struct ct_tx_snapshot_entry) {};
	dma_rmb();
	for (index = 0; index < ARRAY_SIZE(entry->descriptor); index++)
		entry->descriptor[index] = le32_to_cpu(READ_ONCE(words[index]));
	entry->error = ct_tx_snapshot_token(wed->bm[1].dma, wed->bm[1].bytes,
					    entry->descriptor[0], &entry->token);
	if (entry->error)
		return;
	chunk = 2 + entry->token / CT_BM_CHUNK_TOKENS;
	entry->error = ct_tx_snapshot_payload(wed->bm[chunk].dma, wed->bm[chunk].bytes,
					      entry->token, entry->descriptor[2], &offset);
	if (entry->error)
		return;
	dma_rmb();
	for (index = 0; index < sizeof(entry->header); index++)
		entry->header[index] = READ_ONCE(*(u8 *)(wed->bm[1].cpu +
						entry->token * CT_BM_HEADER_SIZE + index));
	for (index = 0; index < sizeof(entry->payload); index++)
		entry->payload[index] = READ_ONCE(*(u8 *)(wed->bm[chunk].cpu + offset + index));
}

static ssize_t tx_snapshot_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct ct_tx_snapshot_entry first[2][CT_TX_SNAPSHOT_PER_RING];
	struct ct_tx_snapshot_entry second[2][CT_TX_SNAPSHOT_PER_RING];
	struct airoha_ct_wed *wed;
	u32 before[2], after[2], issued[2], returned[2];
	unsigned int ring, position;
	bool stable = true;
	ssize_t length;
	int err;

	mutex_lock(&ct_lock);
	wed = dev_get_drvdata(dev);
	err = ct_rx_debug_current(wed);
	if (err)
		goto fail;
	for (ring = 0; ring < ARRAY_SIZE(wed->mid); ring++) {
		if (!wed->mid[ring].desc) {
			err = -EAGAIN;
			goto fail;
		}
		before[ring] = readl(wed->wed + 0x60c + ring * 0x10);
		if (before[ring] >= CT_TX_COUNT) {
			err = -EIO;
			goto fail;
		}
	}
	issued[0] = readl(wed->wed + 0x1c4);
	returned[0] = readl(wed->wed + 0x1c0);
	for (ring = 0; ring < ARRAY_SIZE(wed->mid); ring++)
		for (position = 0; position < CT_TX_SNAPSHOT_PER_RING; position++) {
			unsigned int slot = (before[ring] + CT_TX_COUNT -
					     CT_TX_SNAPSHOT_PER_RING + position) % CT_TX_COUNT;

			ct_tx_snapshot_read(wed, ring, slot, &first[ring][position]);
		}
	dma_rmb();
	for (ring = 0; ring < ARRAY_SIZE(wed->mid); ring++)
		for (position = 0; position < CT_TX_SNAPSHOT_PER_RING; position++) {
			unsigned int slot = (before[ring] + CT_TX_COUNT -
					     CT_TX_SNAPSHOT_PER_RING + position) % CT_TX_COUNT;

			ct_tx_snapshot_read(wed, ring, slot, &second[ring][position]);
		}
	for (ring = 0; ring < ARRAY_SIZE(wed->mid); ring++) {
		after[ring] = readl(wed->wed + 0x60c + ring * 0x10);
		stable &= before[ring] == after[ring];
	}
	issued[1] = readl(wed->wed + 0x1c4);
	returned[1] = readl(wed->wed + 0x1c0);
	stable &= issued[0] == issued[1] && returned[0] == returned[1] &&
		  !memcmp(first, second, sizeof(first));
	length = sysfs_emit(buf,
		"error=0 stable=%u didx=%u,%u/%u,%u issued=%u/%u returned=%u/%u\n",
		stable, before[0], before[1], after[0], after[1],
		issued[0], issued[1], returned[0], returned[1]);
	for (ring = 0; ring < ARRAY_SIZE(wed->mid); ring++)
		for (position = 0; position < CT_TX_SNAPSHOT_PER_RING; position++) {
			const struct ct_tx_snapshot_entry *entry = &first[ring][position];
			unsigned int slot = (before[ring] + CT_TX_COUNT -
					     CT_TX_SNAPSHOT_PER_RING + position) % CT_TX_COUNT;
			u32 control = entry->descriptor[1];

			length += sysfs_emit_at(buf, length,
				"mid%u[%u] error=%d raw=%08x,%08x,%08x,%08x len0=%u len1=%u last0=%u last1=%u done=%u\n",
				ring, slot, entry->error, entry->descriptor[0], control,
				entry->descriptor[2], entry->descriptor[3],
				(control >> 16) & 0x3fff, control & 0x3fff,
				!!(control & BIT(30)), !!(control & BIT(14)), !!(control & BIT(31)));
			if (entry->error)
				continue;
			length += sysfs_emit_at(buf, length,
				"token=%u txp_token=%u nbuf=%u txp_len0=%u txp_buf0=%08x txd=%*phN txp=%*phN payload=%*phN tail=%*phN\n",
				entry->token, get_unaligned_le16(entry->header + 34),
				entry->header[39], get_unaligned_le16(entry->header + 64),
				get_unaligned_le32(entry->header + 40),
				32, entry->header, 44, entry->header + 32,
				64, entry->payload, 8, entry->payload + 64);
		}
	goto out;
fail:
	length = sysfs_emit(buf, "error=%d stable=0\n", err);
out:
	mutex_unlock(&ct_lock);
	return length;
}
static DEVICE_ATTR_RO(tx_snapshot);

static struct attribute *ct_wed_attrs[] = {
	&dev_attr_status.attr,
	&dev_attr_bm_snapshot.attr,
	&dev_attr_rx_snapshot.attr,
	&dev_attr_tx_snapshot.attr,
	NULL,
};
ATTRIBUTE_GROUPS(ct_wed);

static const struct of_device_id ct_wed_ids[] = {
	{ .compatible = "fiberhome,hg5585f-ct-wed-slot1" }, {},
};
MODULE_DEVICE_TABLE(of, ct_wed_ids);

static struct platform_driver ct_wed_driver = {
	.probe = ct_probe, .remove = ct_remove,
	.driver = { .name = "ct-wed-platform", .of_match_table = ct_wed_ids, .dev_groups = ct_wed_groups },
};
module_platform_driver(ct_wed_driver);
MODULE_DESCRIPTION("AN7581 HG5585F-CT wireless offload resource provider");
MODULE_LICENSE("GPL");
