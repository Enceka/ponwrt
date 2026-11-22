#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#include "../ct-wed-provider-v2.h"
#include "ct_wed_live_sample.h"
#include "ct_wed_refill_sample.h"
#include "ct_wed_reclaim_hw.h"

enum ct_exposure {
	CT_NEVER_EXPOSED,
	CT_EXPOSED,
	CT_RETAINED,
};

struct airoha_ct_wed_lease_v2 {
	struct airoha_ct_wed *provider;
	enum ct_exposure exposure;
};

static DEFINE_MUTEX(ct_v2_lock);
static struct airoha_ct_wed_lease_v2 *ct_v2_owner;

static struct airoha_ct_wed *ct_v2_get(struct device *radio)
{
	return airoha_ct_wed_ops_v1.get(radio);
}

static void ct_v2_put(struct airoha_ct_wed *provider)
{
	mutex_lock(&ct_v2_lock);
	if (!ct_v2_owner || ct_v2_owner->provider != provider)
		airoha_ct_wed_ops_v1.put(provider);
	mutex_unlock(&ct_v2_lock);
}

static int ct_v2_acquire(struct airoha_ct_wed *provider, const struct airoha_ct_wed_plan *plan,
			 struct airoha_ct_wed_view *view, struct airoha_ct_wed_lease_v2 **out)
{
	struct airoha_ct_wed_lease_v2 *lease;
	int err;

	if (!out || !provider || !view || !plan)
		return -EINVAL;
	*out = NULL;
	mutex_lock(&ct_v2_lock);
	err = -EBUSY;
	if (ct_v2_owner)
		goto unlock;
	err = -ENOMEM;
	lease = kzalloc(sizeof(*lease), GFP_KERNEL);
	if (!lease)
		goto unlock;
	err = airoha_ct_wed_ops_v1.acquire(provider, plan, view);
	if (err) {
		kfree(lease);
		goto unlock;
	}
	lease->provider = provider;
	lease->exposure = CT_NEVER_EXPOSED;
	ct_v2_owner = lease;
	*out = lease;
unlock:
	mutex_unlock(&ct_v2_lock);
	return err;
}

static int ct_v2_start_masked(struct airoha_ct_wed_lease_v2 *lease, u32 ready)
{
	int err;

	mutex_lock(&ct_v2_lock);
	if (!lease || lease != ct_v2_owner)
		err = -ESTALE;
	else if (lease->exposure != CT_NEVER_EXPOSED)
		err = -EUCLEAN;
	else {
		WRITE_ONCE(lease->exposure, CT_EXPOSED);
		err = airoha_ct_wed_ops_v1.start(lease->provider, ready);
		if (err)
			WRITE_ONCE(lease->exposure, CT_RETAINED);
	}
	mutex_unlock(&ct_v2_lock);
	return err;
}

static int ct_v2_quiesce(struct airoha_ct_wed_lease_v2 *lease, struct airoha_ct_wed_drain_v2 *result)
{
	int err = -ESTALE;

	if (!result)
		return -EINVAL;
	result->fences = 0;
	mutex_lock(&ct_v2_lock);
	if (lease && lease == ct_v2_owner) {
		if (lease->exposure == CT_NEVER_EXPOSED)
			err = -EALREADY;
		else {
			airoha_ct_wed_ops_v1.stop(lease->provider);
			WRITE_ONCE(lease->exposure, CT_RETAINED);
			err = -EUCLEAN;
		}
	}
	mutex_unlock(&ct_v2_lock);
	return err;
}

static int ct_v2_release(struct airoha_ct_wed_lease_v2 *lease)
{
	int err = -ESTALE;

	mutex_lock(&ct_v2_lock);
	if (lease && lease == ct_v2_owner) {
		err = -EBUSY;
		if (lease->exposure == CT_NEVER_EXPOSED) {
			airoha_ct_wed_ops_v1.release(lease->provider);
			ct_v2_owner = NULL;
			kfree(lease);
			err = 0;
		}
	}
	mutex_unlock(&ct_v2_lock);
	return err;
}

static void ct_v2_irq_mask(struct airoha_ct_wed_lease_v2 *lease, u32 mask)
{
	if (!lease || lease != READ_ONCE(ct_v2_owner) ||
	    READ_ONCE(lease->exposure) != CT_EXPOSED)
		return;
	airoha_ct_wed_ops_v1.irq_mask(lease->provider, mask);
}

static u32 ct_v2_irq_ack(struct airoha_ct_wed_lease_v2 *lease, u32 mask)
{
	if (!lease || lease != READ_ONCE(ct_v2_owner) ||
	    READ_ONCE(lease->exposure) != CT_EXPOSED)
		return 0;
	return airoha_ct_wed_ops_v1.irq_ack(lease->provider, mask);
}

int airoha_ct_wed_read_live(struct airoha_ct_wed_lease_v2 *lease,
			   const struct device *radio,
			   struct airoha_ct_wed_live_sample *sample)
{
	int err = -ESTALE;

	if (!sample)
		return -EINVAL;
	*sample = (struct airoha_ct_wed_live_sample) {};
	mutex_lock(&ct_v2_lock);
	if (!lease || lease != ct_v2_owner)
		goto out;
	if (lease->exposure != CT_EXPOSED) {
		err = -ESHUTDOWN;
		goto out;
	}
	err = airoha_ct_wed_platform_read_live(lease->provider, radio, sample);
out:
	mutex_unlock(&ct_v2_lock);
	return err;
}
EXPORT_SYMBOL_GPL(airoha_ct_wed_read_live);

int airoha_ct_wed_read_refill(struct airoha_ct_wed_lease_v2 *lease,
			     const struct device *radio,
			     const u32 indices[CT_LIVE_RX_RINGS],
			     struct airoha_ct_wed_refill_sample *sample)
{
	u32 selected[CT_LIVE_RX_RINGS];
	unsigned int index;
	int err = -ESTALE;

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
	mutex_lock(&ct_v2_lock);
	if (!lease || lease != ct_v2_owner)
		goto out;
	if (lease->exposure != CT_EXPOSED) {
		err = -ESHUTDOWN;
		goto out;
	}
	err = airoha_ct_wed_platform_read_refill(lease->provider, radio, selected, sample);
out:
	mutex_unlock(&ct_v2_lock);
	return err;
}
EXPORT_SYMBOL_GPL(airoha_ct_wed_read_refill);

int airoha_ct_wed_read_reclaim_hw(struct airoha_ct_wed_lease_v2 *lease,
				 const struct device *radio,
				 const u32 indices[CT_LIVE_RX_RINGS],
				 struct airoha_ct_wed_reclaim_hw *sample)
{
	int err = -ESTALE;

	if (!sample)
		return -EINVAL;
	*sample = (struct airoha_ct_wed_reclaim_hw) {};
	mutex_lock(&ct_v2_lock);
	if (!lease || lease != ct_v2_owner)
		goto out;
	if (lease->exposure != CT_EXPOSED) {
		err = -ESHUTDOWN;
		goto out;
	}
	err = airoha_ct_wed_platform_read_reclaim_hw(lease->provider, radio, indices, sample);
out:
	mutex_unlock(&ct_v2_lock);
	return err;
}
EXPORT_SYMBOL_GPL(airoha_ct_wed_read_reclaim_hw);

const struct airoha_ct_wed_ops_v2 airoha_ct_wed_ops_v2 = {
	.get = ct_v2_get, .put = ct_v2_put, .acquire = ct_v2_acquire,
	.start_masked = ct_v2_start_masked, .quiesce = ct_v2_quiesce, .release = ct_v2_release,
	.irq_mask = ct_v2_irq_mask, .irq_ack = ct_v2_irq_ack,
};
EXPORT_SYMBOL_GPL(airoha_ct_wed_ops_v2);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HG5585F-CT WED v2 cold-start and retained-lease guard");
