#include "stubs.inc"

static struct device device = { .of_node = &device };
static struct airoha_npu npu;
static struct airoha_eth eth;
static struct airoha_ppe ppe;
static bool pairs[AIROHA_CT_PAIR_SLOTS];
static int owner, other_owner;
static unsigned scenarios;
static const u64 generation = (UINT64_C(1) << 40) + 123;
static const u32 epoch = 8;

static void reset(void)
{
	CHECK(!rcu_depth);
	memset(&ppe, 0, sizeof(ppe));
	memset(&eth, 0, sizeof(eth));
	memset(&npu, 0, sizeof(npu));
	memset(pairs, 0, sizeof(pairs));
	memset(&firmware_state, 0, sizeof(firmware_state));
	memset((void *)&npu_fe_control, 0, sizeof(npu_fe_control));
	memset((void *)&npu_fe_completion, 0, sizeof(npu_fe_completion));
	memset(&last_request, 0, sizeof(last_request));
	memset(registers, 0, sizeof(registers));
	memset(tables, 0, sizeof(tables));
	ppe.eth = &eth;
	ppe.ct_pairs = pairs;
	ppe.ct_ifc.rule[0].lut_index = 30;
	ppe.ct_ifc.rule[1].lut_index = 31;
	eth.npu = &npu;
	npu.dev = &device;
	npu.ops.ct_pair_cmd = callback;
	native_state = &firmware_state;
	native_cpu_fallback = 0;
	npu_fe_control.magic = 0x46454731;
	npu_fe_control.quiesced = true;
	ppe_lock = 1;
	lock_granted = ready = ram_profile = true;
	quiesce_busy = accept_before_error = false;
	transport_error = enable_error = 0;
	reply_status = callback_result = INT_MIN;
	reply_caps = corrupt_byte = -1;
	sends = firmware_calls = enables = disables = 0;
	mmio_reads = mmio_writes = schedules = 0;
	elapsed_us = 0;
}

static void quiet(u64 selected_generation, u32 selected_epoch)
{
	reset();
	CHECK(!airoha_ct_fe_owner_claim(&ppe, &owner));
	CHECK(!airoha_ct_fe_owner_quiesce(&ppe, &owner, selected_generation, selected_epoch));
	CHECK(ppe.ct_fe.owner_quiesced && !ppe.ct_fe.pending);
	CHECK(!mmio_reads && !mmio_writes && !schedules);
}

static int arm(void)
{
	return airoha_ct_fe_owner_arm(&ppe, &owner, generation, epoch);
}

static void pending_arm(void)
{
	CHECK(ppe.ct_fe.owner == &owner && ppe.ct_fe.arm_pending);
	CHECK(!ppe.ct_fe.armed && !ppe.ct_fe.owner_quiesced && !ppe.ct_fe.pending);
	CHECK(ppe.ct_fe.epoch == epoch && ppe.ct_fe.generation == generation);
	CHECK(!ppe.ct_fe.active && !ppe.ct_fe.touched);
	CHECK(!mmio_reads && !mmio_writes && !schedules);
	CHECK(airoha_ct_fe_owner_release(&ppe, &owner) == -EBUSY);
}

static void check_success_state(u64 selected_generation, u32 selected_epoch)
{
	CHECK(ppe.ct_fe.owner == &owner && ppe.ct_fe.armed);
	CHECK(!ppe.ct_fe.arm_pending && !ppe.ct_fe.owner_quiesced && !ppe.ct_fe.pending);
	CHECK(ppe.ct_fe.generation == selected_generation && ppe.ct_fe.epoch == selected_epoch);
	CHECK(firmware_state.fe_armed && npu_fe_control.enabled);
	CHECK(firmware_state.fe_epoch == selected_epoch);
	CHECK(firmware_state.fe_generation[0] == (u32)selected_generation);
	CHECK(firmware_state.fe_generation[1] == (u32)(selected_generation >> 32));
	CHECK(le64_to_cpu(last_request.generation) == selected_generation);
	CHECK(le32_to_cpu(last_request.src_epoch) == selected_epoch);
	CHECK(last_request.src_selector == 2 && le16_to_cpu(last_request.src_wcid) == 24);
	CHECK(!last_request.slot && !last_request.token && !last_request.dst_epoch);
	CHECK(!last_request.dst_wcid && !last_request.dst_selector && !last_request.flags);
	CHECK(!ppe.ct_fe.active && !ppe.ct_fe.touched && !mmio_reads && !mmio_writes && !schedules);
}

static void reject_unchanged(const void *selected_owner, u64 selected_generation,
	u32 selected_epoch, int expected)
{
	struct airoha_ppe before = ppe;
	unsigned sent = sends;
	CHECK(airoha_ct_fe_owner_arm(&ppe, selected_owner, selected_generation, selected_epoch) == expected);
	CHECK(!memcmp(&before, &ppe, sizeof(ppe)) && sends == sent);
	CHECK(!mmio_reads && !mmio_writes && !schedules);
	scenarios++;
}

static void check_identity(void)
{
	quiet(generation, epoch);
	reject_unchanged(NULL, generation, epoch, -EINVAL);
	reject_unchanged(&owner, 0, epoch, -EINVAL);
	reject_unchanged(&owner, generation, 0, -EINVAL);
	reject_unchanged(&other_owner, generation, epoch, -ESTALE);
	reject_unchanged(&owner, generation, epoch - 1, -ESTALE);
	reject_unchanged(&owner, generation, epoch + 1, -ESTALE);
	reject_unchanged(&owner, generation + 1, epoch, -ESTALE);
	reject_unchanged(&owner, generation + (UINT64_C(1) << 32), epoch, -ESTALE);
	ppe.ct_fe.owner = NULL;
	reject_unchanged(&owner, generation, epoch, -ESTALE);
	ppe.ct_fe.owner = &owner;
	ppe.ct_fe.owner_quiesced = false;
	reject_unchanged(&owner, generation, epoch, -ESTALE);
	ppe.ct_fe.owner_quiesced = true;
	ppe.ct_pair_wired_epoch = epoch;
	reject_unchanged(&owner, generation, epoch, -ESTALE);
	ppe.ct_pair_wired_epoch = epoch + 1;
	reject_unchanged(&owner, generation, epoch, -ESTALE);
	quiet(generation, UINT32_MAX);
	reject_unchanged(&owner, generation, UINT32_MAX, -EOVERFLOW);
	CHECK(!airoha_ct_fe_owner_release(&ppe, &owner));
}

static void prepare_phase(unsigned phase)
{
	quiet(generation, epoch);
	if (phase == 1) {
		transport_error = -ETIMEDOUT;
		accept_before_error = true;
		CHECK(arm() == -ETIMEDOUT);
		transport_error = 0;
		pending_arm();
	} else if (phase == 2) {
		CHECK(!arm());
		check_success_state(generation, epoch);
	}
}

static void check_blocked_states(void)
{
	const size_t busy[] = {
		offsetof(struct airoha_ppe, ct_fe.pending),
		offsetof(struct airoha_ppe, ct_fe.drain_pending),
		offsetof(struct airoha_ppe, ct_fe.active),
		offsetof(struct airoha_ppe, ct_fe.touched),
		offsetof(struct airoha_ppe, ct_pair_policy_allowed),
	};
	const size_t failed[] = {
		offsetof(struct airoha_ppe, ct_pair_failed),
		offsetof(struct airoha_ppe, ct_stopping),
		offsetof(struct airoha_ppe, ct_fe.health_stopping),
	};
	for (unsigned phase = 0; phase < 3; phase++) {
		for (unsigned index = 0; index < ARRAY_SIZE(busy); index++) {
			prepare_phase(phase);
			*(bool *)((char *)&ppe + busy[index]) = true;
			reject_unchanged(&owner, generation, epoch, -EBUSY);
		}
		for (unsigned index = 0; index < ARRAY_SIZE(failed); index++) {
			prepare_phase(phase);
			*(bool *)((char *)&ppe + failed[index]) = true;
			reject_unchanged(&owner, generation, epoch, -ESHUTDOWN);
		}
		for (unsigned index = 0; index < ARRAY_SIZE(pairs); index++) {
			prepare_phase(phase);
			pairs[index] = true;
			reject_unchanged(&owner, generation, epoch, -EBUSY);
		}
		prepare_phase(phase);
		eth.ct_ifc_cpu_port_failed = true;
		reject_unchanged(&owner, generation, epoch, -ESHUTDOWN);
		eth.ct_ifc_cpu_port_failed = false;
		eth.ct_cpu_fallback = true;
		reject_unchanged(&owner, generation, epoch, -ESHUTDOWN);
	}
}

static void check_success(void)
{
	const u64 generations[] = { 1, UINT32_MAX, UINT64_C(1) << 32, generation, UINT64_MAX };
	const u32 epochs[] = { 1, epoch, UINT32_MAX - 1 };
	for (unsigned gen_index = 0; gen_index < ARRAY_SIZE(generations); gen_index++) {
		for (unsigned epoch_index = 0; epoch_index < ARRAY_SIZE(epochs); epoch_index++) {
			u64 selected_generation = generations[gen_index];
			u32 selected_epoch = epochs[epoch_index];
			quiet(selected_generation, selected_epoch);
			ppe.ct_fe.saved = true;
			ppe.ct_pairs = NULL;
			memset(ppe.ct_fe.tcam, 0x63, sizeof(ppe.ct_fe.tcam));
			memset(ppe.ct_fe.action, 0x91, sizeof(ppe.ct_fe.action));
			struct airoha_ppe before = ppe;
			CHECK(!airoha_ct_fe_owner_arm(&ppe, &owner, selected_generation, selected_epoch));
			check_success_state(selected_generation, selected_epoch);
			CHECK(ppe.ct_fe.saved && !memcmp(before.ct_fe.tcam, ppe.ct_fe.tcam, sizeof(ppe.ct_fe.tcam)));
			CHECK(!memcmp(before.ct_fe.action, ppe.ct_fe.action, sizeof(ppe.ct_fe.action)));
			unsigned sent = sends;
			CHECK(!airoha_ct_fe_owner_arm(&ppe, &owner, selected_generation, selected_epoch));
			CHECK(sends == sent + 1 && enables == 1);
			CHECK(airoha_ct_fe_owner_release(&ppe, &owner) == -EBUSY);
			CHECK(airoha_ct_fe_owner_quiesce(&ppe, &owner, selected_generation, selected_epoch) == -ESTALE);
			CHECK(!ppe.ct_fe.pending);
			CHECK(!airoha_ct_fe_owner_quiesce(&ppe, &owner, selected_generation, selected_epoch + 1));
			CHECK(!firmware_state.fe_armed && !npu_fe_control.enabled);
			CHECK(ppe.ct_fe.owner_quiesced && !ppe.ct_fe.arm_pending && !ppe.ct_fe.armed);
			CHECK(!airoha_ct_fe_owner_release(&ppe, &owner));
			scenarios++;
		}
	}
}

static void check_transport_failures(void)
{
	const int errors[] = { -ETIMEDOUT, -EIO, -EPROTO, -ESTALE, 1 };
	for (unsigned accepted = 0; accepted < 2; accepted++) {
		for (unsigned index = 0; index < ARRAY_SIZE(errors); index++) {
			quiet(generation, epoch);
			transport_error = errors[index];
			accept_before_error = accepted;
			CHECK(arm() == (errors[index] > 0 ? -EPROTO : errors[index]));
			pending_arm();
			CHECK(firmware_state.fe_armed == accepted);
			reject_unchanged(&owner, generation + (UINT64_C(1) << 32), epoch, -ESTALE);
			reject_unchanged(&owner, generation, epoch + 1, -ESTALE);
			reject_unchanged(&other_owner, generation, epoch, -ESTALE);
			unsigned sent = sends;
			CHECK(airoha_ct_fe_owner_quiesce(&ppe, &owner, generation, epoch) == -ESTALE);
			CHECK(!ppe.ct_fe.pending && sends == sent);
			transport_error = 0;
			CHECK(!arm());
			check_success_state(generation, epoch);
			CHECK(enables == 1);
			scenarios++;
		}
	}
	quiet(generation, epoch);
	callback_result = 1;
	CHECK(arm() == -EPROTO);
	pending_arm();
	scenarios++;
}

static void check_replies(void)
{
	for (unsigned operation = 0; operation < 2; operation++) {
		for (int byte = 0; byte < 56; byte++) {
			quiet(generation, epoch);
			corrupt_byte = byte;
			CHECK(arm() == -EPROTO);
			pending_arm();
			CHECK(firmware_state.fe_armed);
			corrupt_byte = -1;
			if (!operation) {
				CHECK(!arm());
				check_success_state(generation, epoch);
			} else {
				corrupt_byte = byte;
				CHECK(airoha_ct_fe_owner_quiesce(&ppe, &owner, generation, epoch + 1) == -EPROTO);
				CHECK(ppe.ct_fe.pending && ppe.ct_fe.arm_pending && !ppe.ct_fe.owner_quiesced);
				CHECK(ppe.ct_fe.pending_epoch == epoch + 1 && ppe.ct_fe.epoch == epoch);
				corrupt_byte = -1;
				CHECK(!airoha_ct_fe_owner_quiesce(&ppe, &owner, generation, epoch + 1));
				CHECK(ppe.ct_fe.owner_quiesced && !ppe.ct_fe.pending && !ppe.ct_fe.arm_pending);
				CHECK(!airoha_ct_fe_owner_release(&ppe, &owner));
			}
			scenarios++;
		}
	}
	for (unsigned bit = 0; bit < 6; bit++) {
		quiet(generation, epoch);
		reply_caps = 63 & ~BIT(bit);
		CHECK(arm() == -EPROTO);
		pending_arm();
		reply_caps = -1;
		CHECK(!arm());
		scenarios++;
	}
	const int statuses[] = { 1, -EINPROGRESS, -EIO, -ESTALE };
	for (unsigned index = 0; index < ARRAY_SIZE(statuses); index++) {
		quiet(generation, epoch);
		reply_status = statuses[index];
		CHECK(arm() == (statuses[index] > 0 ? -EPROTO : statuses[index]));
		pending_arm();
		reply_status = INT_MIN;
		CHECK(!arm());
		scenarios++;
	}
}

static void check_firmware_rejections(void)
{
	for (unsigned reason = 0; reason < 12; reason++) {
		quiet(generation, epoch);
		int expected = -ESTALE;
		switch (reason) {
		case 0: firmware_state.fe_epoch++; break;
		case 1: firmware_state.fe_generation[1]++; break;
		case 2: firmware_state.fe_quiesce_ack = 0; break;
		case 3: firmware_state.endpoints[512].epoch++; break;
		case 4: npu_fe_control.stop_requested = 1; expected = -EIO; break;
		case 5: native_cpu_fallback = 1; expected = -EIO; break;
		case 6: npu_fe_completion.inflight = 1; expected = -ETIMEDOUT; break;
		case 7: lock_granted = false; expected = -ETIMEDOUT; break;
		case 8: enable_error = -EAGAIN; expected = -ETIMEDOUT; break;
		case 9: ready = false; expected = -EOPNOTSUPP; break;
		case 10: ram_profile = false; expected = -EOPNOTSUPP; break;
		case 11: eth.npu = NULL; expected = -EOPNOTSUPP; break;
		}
		CHECK(arm() == expected);
		pending_arm();
		CHECK(!firmware_state.fe_armed);
		if (expected == -ETIMEDOUT)
			CHECK(elapsed_us == 100000 && sends == 10001);
		scenarios++;
	}
	prepare_phase(2);
	firmware_state.fe_armed = 0;
	firmware_state.fe_quiesce_ack = 0;
	CHECK(arm() == -ESTALE);
	pending_arm();
	scenarios++;
}

static void check_close(void)
{
	for (unsigned arm_accepted = 0; arm_accepted < 2; arm_accepted++) {
		for (unsigned close_accepted = 0; close_accepted < 2; close_accepted++) {
			quiet(generation, epoch);
			transport_error = -ETIMEDOUT;
			accept_before_error = arm_accepted;
			CHECK(arm() == -ETIMEDOUT);
			pending_arm();
			CHECK(airoha_ct_fe_owner_quiesce(&ppe, &owner, generation, epoch) == -ESTALE);
			CHECK(!ppe.ct_fe.pending);
			accept_before_error = close_accepted;
			CHECK(airoha_ct_fe_owner_quiesce(&ppe, &owner, generation + 1, epoch + 1) == -ETIMEDOUT);
			CHECK(ppe.ct_fe.pending && ppe.ct_fe.arm_pending && !ppe.ct_fe.owner_quiesced);
			CHECK(ppe.ct_fe.pending_epoch == epoch + 1 && ppe.ct_fe.pending_generation == generation + 1);
			CHECK(ppe.ct_fe.epoch == epoch && ppe.ct_fe.generation == generation);
			unsigned sent = sends;
			reject_unchanged(&owner, generation, epoch, -EBUSY);
			CHECK(airoha_ct_fe_owner_quiesce(&ppe, &owner, generation + 1, epoch + 2) == -ESTALE);
			CHECK(airoha_ct_fe_owner_quiesce(&ppe, &owner, generation + 2, epoch + 1) == -ESTALE);
			CHECK(sends == sent && airoha_ct_fe_owner_release(&ppe, &owner) == -EBUSY);
			transport_error = 0;
			CHECK(!airoha_ct_fe_owner_quiesce(&ppe, &owner, generation + 1, epoch + 1));
			CHECK(!firmware_state.fe_armed && !ppe.ct_fe.armed && !ppe.ct_fe.arm_pending);
			CHECK(!ppe.ct_fe.pending && ppe.ct_fe.owner_quiesced);
			CHECK(!airoha_ct_fe_owner_arm(&ppe, &owner, generation + 1, epoch + 1));
			CHECK(!airoha_ct_fe_owner_quiesce(&ppe, &owner, generation + 1, epoch + 2));
			CHECK(!airoha_ct_fe_owner_release(&ppe, &owner));
			scenarios++;
		}
	}
	prepare_phase(2);
	quiesce_busy = true;
	CHECK(airoha_ct_fe_owner_quiesce(&ppe, &owner, generation, epoch + 1) == -ETIMEDOUT);
	CHECK(ppe.ct_fe.pending && ppe.ct_fe.armed && !ppe.ct_fe.owner_quiesced);
	reject_unchanged(&owner, generation, epoch, -EBUSY);
	quiesce_busy = false;
	CHECK(!airoha_ct_fe_owner_quiesce(&ppe, &owner, generation, epoch + 1));
	CHECK(!airoha_ct_fe_owner_release(&ppe, &owner));
	scenarios++;
}

static void check_exclusion(void)
{
	for (unsigned phase = 0; phase < 3; phase++) {
		prepare_phase(phase);
		struct airoha_ppe before = ppe;
		unsigned sent = sends;
		CHECK(airoha_ct_fe_arm(&ppe, generation) == -EBUSY);
		CHECK(airoha_ct_fe_quiesce(&ppe, generation) == -EBUSY);
		CHECK(airoha_ct_fe_control(&ppe, AIROHA_CT_PAIR_FE_ARM, generation, epoch) == -EBUSY);
		CHECK(airoha_ct_fe_control(&ppe, AIROHA_CT_PAIR_FE_QUIESCE, generation, epoch) == -EBUSY);
		CHECK(!memcmp(&before, &ppe, sizeof(ppe)) && sends == sent);
		CHECK(!mmio_reads && !mmio_writes && !schedules);
		scenarios++;
	}
	quiet(generation, epoch);
	CHECK(!airoha_ct_fe_owner_release(&ppe, &owner));
	CHECK(!airoha_ct_fe_arm(&ppe, generation));
	CHECK(ppe.ct_fe.armed && ppe.ct_fe.active && ppe.ct_fe.touched);
	CHECK(mmio_writes && schedules == 1);
	for (unsigned row = 54; row <= 55; row++)
		CHECK(tables[CT_IFC_ACTION_BANK][row][2][0] & CT_IFC_ACTION_ENABLE);
	CHECK(!airoha_ct_fe_quiesce(&ppe, generation));
	CHECK(!ppe.ct_fe.armed && !ppe.ct_fe.active && !ppe.ct_fe.touched);
	CHECK(!airoha_ct_fe_owner_claim(&ppe, &other_owner));
	CHECK(!airoha_ct_fe_owner_quiesce(&ppe, &other_owner, generation, epoch + 2));
	unsigned writes = mmio_writes;
	CHECK(!airoha_ct_fe_owner_arm(&ppe, &other_owner, generation, epoch + 2));
	CHECK(mmio_writes == writes);
	scenarios++;
}

int main(void)
{
	check_identity();
	check_blocked_states();
	check_success();
	check_transport_failures();
	check_replies();
	check_firmware_rejections();
	check_close();
	check_exclusion();
	CHECK(!rcu_depth);
	printf("PASS %u scenarios, %u checks; real firmware FE mailbox and host transport\n",
	       scenarios, checks);
	return 0;
}
