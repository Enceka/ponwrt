#include <sys/types.h>

struct device_attribute { int unused; };
static bool policy_hooks_ok;
static unsigned policy_locks, cases;
static u64 nf_generation = 39;
static int owner_one, owner_two;

static void *dev_get_drvdata(struct device *device)
{
	assert(device);
	return &eth;
}

static bool sysfs_streq(const char *left, const char *right)
{
	return !strcmp(left, right);
}

static int nf_native_pair_policy_lock(u64 value)
{
	if (value != nf_generation)
		return -ESTALE;
	policy_locks++;
	return 0;
}

static void nf_native_pair_policy_unlock(void)
{
	assert(policy_locks);
	policy_locks--;
}

static bool airoha_ct_pair_policy_hooks(void)
{
	return policy_hooks_ok;
}

#include "policy_store.inc"

static void reset(void)
{
	base_reset();
	eth.ppe = &ppe;
	ppe.ct_pair_policy_allowed = false;
	memset(registers, 0, sizeof(registers));
	memset(tables, 0, sizeof(tables));
	memset(operation_count, 0, sizeof(operation_count));
	memset(firmware_wlan_epoch, 0, sizeof(firmware_wlan_epoch));
	eth.ct_ifc_cpu_port_failed = eth.ct_cpu_fallback = false;
	eth.ct_cpu_ifc_disabled = eth.ct_cpu_routes_ready = false;
	eth.ct_cpu_wlan_gated = eth.ct_ifc_command_pending = false;
	write_fail_offset = -1;
	registers[REG_FE_CSR_IFC_CFG / 4] = FE_IFC_EN_MASK;
	registers[REG_PPE_GLO_CFG(0) / 4] = PPE_GLO_CFG_EN_MASK;
	registers[REG_PPE_PPE_FLOW_CFG(0) / 4] = 0xb200;
	registers[REG_PPE_TB_CFG(0) / 4] = 0x53;
	registers[REG_PPE_PPE_FLOW_CFG(1) / 4] = 0x3200;
	ppe.ct_ifc.rule[0].lut_index = 31;
	ppe.ct_ifc.rule[1].lut_index = 30;
	mmio_writes = schedules = firmware_applies = policy_locks = 0;
	firmware_epoch = firmware_wired_epoch = 0;
	firmware_generation = 0;
	firmware_armed = firmware_quiesced = accept_before_error = false;
	policy_hooks_ok = true;
}

static int claim(const void *owner)
{
	int error;
	spin_lock_bh(&ppe_lock);
	error = airoha_ct_fe_owner_claim(&ppe, owner);
	spin_unlock_bh(&ppe_lock);
	return error;
}

static int quiesce(const void *owner, u64 value, u32 epoch)
{
	int error;
	spin_lock_bh(&ppe_lock);
	error = airoha_ct_fe_owner_quiesce(&ppe, owner, value, epoch);
	spin_unlock_bh(&ppe_lock);
	return error;
}

static int release(const void *owner)
{
	int error;
	spin_lock_bh(&ppe_lock);
	error = airoha_ct_fe_owner_release(&ppe, owner);
	spin_unlock_bh(&ppe_lock);
	return error;
}

static void check_claim(void)
{
	const size_t busy[] = {
		offsetof(struct airoha_ppe, ct_pair_policy_allowed),
		offsetof(struct airoha_ppe, ct_fe.pending),
		offsetof(struct airoha_ppe, ct_fe.arm_pending),
		offsetof(struct airoha_ppe, ct_fe.armed),
		offsetof(struct airoha_ppe, ct_fe.active),
		offsetof(struct airoha_ppe, ct_fe.touched),
		offsetof(struct airoha_ppe, ct_fe.drain_pending),
	};
	const size_t failed[] = {
		offsetof(struct airoha_ppe, ct_pair_failed),
		offsetof(struct airoha_ppe, ct_stopping),
		offsetof(struct airoha_ppe, ct_fe.health_stopping),
	};

	reset();
	assert(ppe.ct_native_pairs && !claim(&owner_one));
	assert(!claim(&owner_one) && claim(&owner_two) == -EBUSY);
	assert(claim(NULL) == -EINVAL && release(NULL) == -EINVAL);
	assert(release(&owner_two) == -ESTALE && release(&owner_one) == -EBUSY);
	assert(ppe.ct_fe.owner == &owner_one && !calls && !mmio_writes);
	cases++;
	for (unsigned index = 0; index < ARRAY_SIZE(busy); index++) {
		reset();
		*(bool *)((char *)&ppe + busy[index]) = true;
		assert(claim(&owner_one) == -EBUSY && !ppe.ct_fe.owner);
		assert(!calls && !mmio_writes && !failclosed);
		cases++;
	}
	for (unsigned index = 0; index < ARRAY_SIZE(failed); index++) {
		reset();
		*(bool *)((char *)&ppe + failed[index]) = true;
		assert(claim(&owner_one) == -ESHUTDOWN && !ppe.ct_fe.owner);
		cases++;
	}
	for (unsigned index = 0; index < ARRAY_SIZE(pairs); index++) {
		reset();
		pairs[index].used = true;
		assert(claim(&owner_one) == -EBUSY && !ppe.ct_fe.owner && !calls);
		cases++;
	}
	reset();
	eth.ct_ifc_cpu_port_failed = true;
	assert(claim(&owner_one) == -ESHUTDOWN);
	reset();
	eth.ct_cpu_fallback = true;
	assert(claim(&owner_one) == -ESHUTDOWN);
	cases += 2;
	reset();
	ppe.ct_native_pairs = false;
	ppe.ct_pairs = NULL;
	assert(!claim(&owner_one));
	assert(!quiesce(&owner_one, 1, 1) && !release(&owner_one));
	cases++;
}

static void check_identity(void)
{
	u64 value = (UINT64_C(1) << 40) + 123;
	const int failures[] = { -ETIMEDOUT, -EIO, -EAGAIN, -ESTALE, -EPROTO, 1 };

	reset();
	assert(quiesce(&owner_one, value, 8) == -ESTALE);
	assert(!claim(&owner_one));
	assert(quiesce(&owner_one, 0, 8) == -EINVAL);
	assert(quiesce(&owner_one, value, 0) == -EINVAL);
	assert(quiesce(NULL, value, 8) == -EINVAL);
	assert(quiesce(&owner_two, value, 8) == -ESTALE && !calls);
	assert(!quiesce(&owner_one, value, 8));
	assert(ppe.ct_fe.generation == value && ppe.ct_fe.epoch == 8);
	assert(ppe.ct_pair_wired_epoch == 7 && ppe.ct_fe.owner_quiesced);
	assert(le64_to_cpu(lastmsg.generation) == value && firmware_generation == value);
	assert(!ppe.ct_fe.pending && !ppe.ct_fe.armed && !ppe.ct_fe.active && !mmio_writes);
	assert(!quiesce(&owner_one, value, 8));
	assert(!release(&owner_one) && release(&owner_one) == -ESTALE);
	assert(!claim(&owner_two) && release(&owner_two) == -EBUSY);
	assert(!quiesce(&owner_two, value, 8) && !release(&owner_two));
	cases++;
	for (unsigned accepted = 0; accepted < 2; accepted++) {
		for (unsigned index = 0; index < ARRAY_SIZE(failures); index++) {
			reset();
			ppe.ct_fe.epoch = firmware_epoch = 3;
			ppe.ct_pair_wired_epoch = 2;
			firmware_wired_epoch = 3;
			ppe.ct_fe.generation = firmware_generation = value - 1;
			assert(!claim(&owner_one));
			send_error = failures[index];
			accept_before_error = accepted;
			int expected = send_error > 0 ? -EPROTO :
				       send_error == -EAGAIN ? -ETIMEDOUT : send_error;
			assert(quiesce(&owner_one, value, 8) == expected);
			assert(ppe.ct_fe.pending && ppe.ct_fe.pending_epoch == 8);
			assert(ppe.ct_fe.pending_generation == value && !ppe.ct_fe.owner_quiesced);
			assert(ppe.ct_fe.epoch == 3 && ppe.ct_fe.generation == value - 1);
			assert(ppe.ct_pair_wired_epoch == 2 && release(&owner_one) == -EBUSY);
			unsigned sent = calls;
			assert(!claim(&owner_one));
			assert(quiesce(&owner_one, value + 1, 8) == -ESTALE);
			assert(quiesce(&owner_one, value, 9) == -ESTALE);
			assert(quiesce(&owner_two, value, 8) == -ESTALE && calls == sent);
			assert(!revoke(-1, 0) && !revoke(0, 7) && !failclosed && calls == sent);
			send_error = 0;
			accept_before_error = false;
			assert(!quiesce(&owner_one, value, 8));
			assert(ppe.ct_fe.epoch == 8 && ppe.ct_fe.generation == value);
			assert(!release(&owner_one));
			cases++;
		}
	}
	reset();
	ppe.ct_fe.epoch = firmware_epoch = 8;
	ppe.ct_pair_wired_epoch = 7;
	firmware_wired_epoch = 8;
	ppe.ct_fe.generation = firmware_generation = value;
	assert(!claim(&owner_one));
	assert(quiesce(&owner_one, value, 7) == -ESTALE);
	assert(quiesce(&owner_one, value + 1, 8) == -ESTALE);
	assert(quiesce(&owner_one, value - 1, 9) == -ESTALE && !calls);
	assert(!quiesce(&owner_one, UINT64_MAX, UINT32_MAX));
	assert(ppe.ct_fe.generation == UINT64_MAX && ppe.ct_fe.epoch == UINT32_MAX);
	assert(!release(&owner_one));
	cases++;
}

static void check_exclusion(void)
{
	reset();
	assert(!claim(&owner_one));
	spin_lock_bh(&ppe_lock);
	assert(airoha_ct_fe_arm(&ppe, 1) == -EBUSY);
	assert(airoha_ct_fe_quiesce(&ppe, 1) == -EBUSY);
	assert(airoha_ct_fe_control(&ppe, AIROHA_CT_PAIR_FE_ARM, 1, 1) == -EBUSY);
	assert(airoha_ct_fe_control(&ppe, AIROHA_CT_PAIR_FE_QUIESCE, 1, 1) == -EBUSY);
	spin_unlock_bh(&ppe_lock);
	assert(!calls && !mmio_writes && !failclosed);
	assert(ct_native_pair_policy_store(&eth_dev, NULL, "whole-mac-ip 39", 15) == -EBUSY);
	assert(ct_native_pair_policy_store(&eth_dev, NULL, "off", 3) == 3);
	assert(!airoha_ct_pair_policy_event(&ppe.ct_pair_policy_notifier, NF_NATIVE_PAIR_PRE, NULL));
	assert(!ppe.ct_pair_policy_allowed && !calls && !failclosed && !policy_locks);
	frame();
	assert(!calls && !ppe_lock);
	ppe.ct_pair_policy_allowed = true;
	frame();
	test_bind(0x900, NULL);
	assert(!calls && !writes && !failclosed);
	ppe.ct_pair_policy_allowed = false;
	cases++;
	for (unsigned failure = 0; failure < 4; failure++) {
		reset();
		assert(!claim(&owner_one));
		if (failure == 1) {
			send_error = -ETIMEDOUT;
			assert(quiesce(&owner_one, 1, 1) == -ETIMEDOUT);
		} else if (failure == 2) {
			eth.ct_ifc_cpu_port_failed = true;
		} else if (failure == 3) {
			ppe.ct_pair_failed = ppe.ct_pair_close_pending = true;
			ppe.ct_fe.armed = ppe.ct_fe.active = true;
		}
		unsigned sent = calls;
		airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);
		assert(calls == sent && !mmio_writes && !failclosed && !schedules && !ppe_lock);
		cases++;
	}
}

static void check_wired_and_retirement(void)
{
	const unsigned events[] = { NETDEV_GOING_DOWN, NETDEV_DOWN, NETDEV_UNREGISTER,
		NETDEV_PRE_CHANGEADDR, NETDEV_PRECHANGEMTU, NETDEV_PRECHANGEUPPER };
	for (unsigned phase = 0; phase < 3; phase++) {
		reset();
		dst.ieee80211_ptr = NULL;
		dst.running = dst.carrier = true;
		ppe.ct_fe.epoch = firmware_epoch = 5;
		ppe.ct_fe.generation = firmware_generation = 1;
		ppe.ct_pair_wired_epoch = 4;
		firmware_wired_epoch = 5;
		assert(!claim(&owner_one));
		if (phase) {
			send_error = phase == 1 ? -ETIMEDOUT : 0;
			assert(quiesce(&owner_one, 2, 6) == send_error);
		}
		unsigned sent = calls;
		u32 previous_epoch = ppe.ct_pair_wired_epoch;
		u32 previous_firmware_epoch = firmware_wired_epoch;
		for (unsigned index = 0; index < ARRAY_SIZE(events); index++) {
			assert(!wired_event(events[index]) && ppe.ct_pair_wired_blocked);
			assert(!wired_event(NETDEV_UP) && !ppe.ct_pair_wired_blocked);
			assert(calls == sent && ppe.ct_pair_wired_epoch == previous_epoch);
			cases++;
		}
		dst.carrier = false;
		assert(!wired_event(NETDEV_CHANGE) && ppe.ct_pair_wired_blocked);
		assert(!wired_event(NETDEV_UP) && ppe.ct_pair_wired_blocked);
		dst.carrier = true;
		assert(!wired_event(NETDEV_CHANGE) && !ppe.ct_pair_wired_blocked);
		assert(!revoke(AIROHA_CT_PAIR_LAN1_SELECTOR, AIROHA_CT_PAIR_LAN1_ID));
		assert(calls == sent && firmware_wired_epoch == previous_firmware_epoch);
		assert(ppe.ct_pair_wired_epoch == previous_epoch && !failclosed);
		send_error = 0;
		assert(!quiesce(&owner_one, 2, 6));
		assert(!release(&owner_one));
		cases++;
	}
	reset();
	ppe.ct_pair_token = 42;
	assert(!claim(&owner_one) && !quiesce(&owner_one, 1, 1));
	assert(!revoke(-1, 0));
	assert(operation_count[AIROHA_CT_PAIR_FLUSH] == 1 && !failclosed);
	assert(ppe.ct_fe.owner_quiesced && firmware_quiesced && !ppe.ct_fe.drain_pending);
	assert(firmware_epoch == 1 && ppe.ct_pair_wired_epoch == 0);
	assert(registers[REG_PPE_PPE_FLOW_CFG(0) / 4] == 0xb200);
	assert(registers[REG_PPE_PPE_FLOW_CFG(1) / 4] == 0x3200);
	assert(!revoke(0, 7));
	assert(operation_count[AIROHA_CT_PAIR_ENDPOINT_REVOKE] == 1);
	assert(firmware_wlan_epoch[1][7] == 1 && firmware_wired_epoch == 1);
	assert(ppe.ct_fe.owner_quiesced && !failclosed);
	ppe.ct_stopping = true;
	ppe.ct_host_ppe = false;
	assert(!revoke(-1, 0) && !release(&owner_one));
	cases++;
}

static void check_release(void)
{
	const size_t pending[] = {
		offsetof(struct airoha_ppe, ct_fe.pending),
		offsetof(struct airoha_ppe, ct_fe.arm_pending),
		offsetof(struct airoha_ppe, ct_fe.armed),
		offsetof(struct airoha_ppe, ct_fe.active),
		offsetof(struct airoha_ppe, ct_fe.touched),
		offsetof(struct airoha_ppe, ct_fe.drain_pending),
	};
	for (unsigned index = 0; index < ARRAY_SIZE(pending); index++) {
		reset();
		assert(!claim(&owner_one) && !quiesce(&owner_one, 1, 1));
		*(bool *)((char *)&ppe + pending[index]) = true;
		assert(release(&owner_one) == -EBUSY && ppe.ct_fe.owner == &owner_one);
		assert(release(&owner_two) == -ESTALE && ppe.ct_fe.owner == &owner_one);
		*(bool *)((char *)&ppe + pending[index]) = false;
		assert(!release(&owner_one));
		cases++;
	}
}

static void check_native_without_owner(void)
{
	reset();
	assert(ct_native_pair_policy_store(&eth_dev, NULL, "whole-mac-ip 39", 15) == 15);
	assert(ppe.ct_pair_policy_allowed && ppe.ct_fe.armed && ppe.ct_fe.active);
	unsigned sent = calls;
	airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);
	assert(calls == sent + 1 && schedules == 2 && !failclosed);
	frame();
	assert(pairs[0].used && put_count == 1);
	assert(ct_native_pair_policy_store(&eth_dev, NULL, "off", 3) == 3);
	assert(!pairs[0].used && !ppe.ct_pair_policy_allowed && !ppe.ct_fe.active);
	assert(!ppe.ct_fe.pending && !ppe.ct_fe.drain_pending && !failclosed);
	assert(!claim(&owner_one));
	u32 epoch = max(ppe.ct_fe.epoch, ppe.ct_pair_wired_epoch) + 1;
	assert(!quiesce(&owner_one, generation, epoch) && !release(&owner_one));
	assert(ct_native_pair_policy_store(&eth_dev, NULL, "whole-mac-ip 39", 15) == 15);
	assert(ppe.ct_fe.epoch > epoch && ppe.ct_fe.active && !failclosed);
	cases++;
	reset();
	ppe.ct_pair_policy_allowed = true;
	src.ieee80211_ptr = NULL;
	src.running = src.carrier = true;
	wired.netdev = &src;
	frame();
	assert(pairs[0].used && ppe.ct_fe.armed && put_count == 1);
	assert(pairs[0].msg.src_selector == AIROHA_CT_PAIR_LAN1_SELECTOR);
	assert(!airoha_ct_pair_policy_event(&ppe.ct_pair_policy_notifier, NF_NATIVE_PAIR_PRE, NULL));
	assert(!pairs[0].used && !ppe.ct_fe.armed && !failclosed);
	cases++;
	reset();
	dst.ieee80211_ptr = NULL;
	dst.running = dst.carrier = true;
	assert(!wired_event(NETDEV_DOWN));
	assert(ppe.ct_pair_wired_epoch == 1 && ppe.ct_pair_wired_blocked);
	assert(!wired_event(NETDEV_UP) && !ppe.ct_pair_wired_blocked);
	cases++;
}

int main(void)
{
	check_claim();
	check_identity();
	check_exclusion();
	check_wired_and_retirement();
	check_release();
	check_native_without_owner();
	assert(!ppe_lock && !rcu && !policy_locks);
	printf("PASS %u production-C FE owner/native regression cases\n", cases);
	return 0;
}
