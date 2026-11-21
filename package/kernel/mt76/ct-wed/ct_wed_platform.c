#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/irqdomain.h>
#include <linux/kref.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/overflow.h>
#include <linux/pci.h>
#include <linux/platform_device.h>

#include "../ct-wed-provider-abi.h"
#include "ct_wdma_rx.h"
#include "ct_wed_bm.h"

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
	void __iomem *wed, *wdma;
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
};

static DEFINE_MUTEX(ct_lock);
static struct airoha_ct_wed *ct_slot;
static bool prepare;
static bool prepare_bm;
module_param(prepare, bool, 0444);
module_param(prepare_bm, bool, 0444);
MODULE_PARM_DESC(prepare_bm, "Prepare stock hardware token buffers without enabling DMA");
MODULE_PARM_DESC(prepare, "Permit a software-only dual-ring lease; engines stay disabled");

static void ct_free(struct kref *ref)
{
	struct airoha_ct_wed *wed = container_of(ref, struct airoha_ct_wed, ref);

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
	if (wed->prepared) {
		err = -EBUSY;
		goto out;
	}
	err = ct_check_plan(wed, plan);
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

static int ct_start(struct airoha_ct_wed *wed)
{
	int err;

	mutex_lock(&ct_lock);
	err = wed != ct_slot ? -ENODEV : !wed->prepared ? -EINVAL : -EOPNOTSUPP;
	mutex_unlock(&ct_lock);
	return err;
}

static void ct_stop(struct airoha_ct_wed *wed) {}
static void ct_irq_mask(struct airoha_ct_wed *wed, u32 mask) {}
static u32 ct_irq_ack(struct airoha_ct_wed *wed, u32 mask) { return 0; }

const struct airoha_ct_wed_ops airoha_ct_wed_ops_v1 = {
	.get = ct_get, .put = ct_put, .acquire = ct_acquire, .start = ct_start,
	.stop = ct_stop, .release = ct_release, .irq_mask = ct_irq_mask, .irq_ack = ct_irq_ack,
};
EXPORT_SYMBOL_GPL(airoha_ct_wed_ops_v1);

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
	if (!res || res->start != 0x1fa03000 || resource_size(res) != 0xb00 ||
	    !wdma || wdma->start != 0x1fa06400 || resource_size(wdma) != 0x400)
		return -EINVAL;
	wed = kzalloc(sizeof(*wed), GFP_KERNEL);
	if (!wed)
		return -ENOMEM;
	kref_init(&wed->ref);
	wed->dev = get_device(&pdev->dev);
	wed->wed = devm_ioremap_resource(&pdev->dev, res);
	wed->wdma = devm_ioremap_resource(&pdev->dev, wdma);
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
	ct_slot = NULL;
	ct_release_locked(wed);
	mutex_unlock(&ct_lock);
	kref_put(&wed->ref, ct_free);
}

static const struct of_device_id ct_wed_ids[] = {
	{ .compatible = "fiberhome,hg5585f-ct-wed-slot1" }, {},
};
MODULE_DEVICE_TABLE(of, ct_wed_ids);

static struct platform_driver ct_wed_driver = {
	.probe = ct_probe, .remove = ct_remove,
	.driver = { .name = "ct-wed-platform", .of_match_table = ct_wed_ids },
};
module_platform_driver(ct_wed_driver);
MODULE_DESCRIPTION("AN7581 HG5585F-CT wireless offload resource provider");
MODULE_LICENSE("GPL");
