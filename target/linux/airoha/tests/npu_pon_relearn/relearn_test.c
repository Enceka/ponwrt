static void bound_fixture(void)
{
	fail_read = fail_ack = row_reads = 0;
	timestamp_now = 37;
	fixture();
	start_session();
	unbound_event();
	CHECK(!airoha_npu_production_step(&session));
	CHECK(session.production_bound && installs == 1 && session.txn.phase == NPU_TXN_OPEN);
}

static void test_idle_rebind(void)
{
	struct airoha_pon_candidate_snapshot saved;
	struct airoha_foe_entry expected;
	bound_fixture();
	saved = session.production;
	expected = session.production_entry;
	u32 epoch = session.txn.id.epoch;
	unsigned int closed_drains = drains;
	timestamp_now = 81;
	unbound_event();
	health_tick();
	expected.ib1 &= ~AIROHA_FOE_IB1_BIND_TIMESTAMP;
	expected.ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_TIMESTAMP, timestamp_now);
	CHECK(installs == 2 && drains == closed_drains + 1);
	CHECK(session.txn.id.epoch > epoch && session.txn.phase == NPU_TXN_OPEN);
	CHECK(!session.invalidated && !session.close_pending && route_open && auth_enabled);
	CHECK(published.raw[1] == session.txn.id.epoch && published.raw[4] == 23);
	CHECK(session.production_hash == 23 && !(hardware.ib1 & AIROHA_FOE_IB1_BIND_STATIC));
	CHECK(!memcmp(&hardware, &expected, sizeof(expected)));
	CHECK(!memcmp(&session.production_entry, &expected, sizeof(expected)));
	CHECK(!memcmp(&session.production, &saved, sizeof(saved)));
	CHECK(!memcmp(&available, &saved, sizeof(saved)));
	CHECK(!memcmp(&candidate.data, &saved.data, sizeof(candidate.data)));
	retained();
	epoch = session.txn.id.epoch;
	unsigned int reads = row_reads, consumed = takes;
	CHECK(!airoha_npu_production_step(&session));
	CHECK(takes == consumed + 1 && row_reads == reads && installs == 2);
	CHECK(session.txn.id.epoch == epoch && drains == closed_drains + 1);
	release_session();
}

static void test_queued_event(void)
{
	bound_fixture();
	struct airoha_foe_entry saved = session.production_entry;
	struct airoha_foe_entry active = hardware;
	u32 epoch = session.txn.id.epoch;
	unsigned int closed_drains = drains;
	active.ib1 &= ~AIROHA_FOE_IB1_BIND_TIMESTAMP;
	active.ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_TIMESTAMP, 99);
	unbound_event();
	hardware = active;
	CHECK(!airoha_npu_production_step(&session));
	CHECK(!candidate.pon_unbound_event.serial && takes == 2);
	CHECK(installs == 1 && drains == closed_drains && session.txn.id.epoch == epoch);
	CHECK(!session.invalidated && session.txn.phase == NPU_TXN_OPEN && route_open && auth_enabled);
	CHECK(!memcmp(&hardware, &active, sizeof(active)));
	CHECK(!memcmp(&session.production_entry, &saved, sizeof(saved)));
	retained();
	release_session();
}

static void expect_closed(int expected_error)
{
	CHECK(airoha_npu_production_step(&session) == expected_error);
	CHECK(session.invalidated && session.txn.phase == NPU_TXN_CLOSED);
	CHECK(!route_open && !auth_enabled && session.txn.last_error == expected_error);
	CHECK(!memcmp(&hardware, &(struct airoha_foe_entry){}, sizeof(hardware)));
	retained();
	release_session();
}

static void test_relearn_event_identity(void)
{
	for (unsigned int condition = 0; condition < 6; condition++) {
		bound_fixture();
		unbound_event();
		switch (condition) {
		case 0: candidate.pon_unbound_event.serial++; break;
		case 1: candidate.pon_unbound_event.generation++; break;
		case 2: candidate.pon_unbound_event.service++; break;
		case 3: candidate.pon_unbound_event.key[18] ^= 1; break;
		case 4: candidate.pon_unbound_event.hardware_hash++; break;
		case 5: candidate.pon_unbound_event.hardware_hash = PPE_SRAM_NUM_ENTRIES; break;
		}
		expect_closed(condition == 5 ? -EINVAL : -ESTALE);
		CHECK(installs == 1);
	}
}

static void test_row_conflicts(void)
{
	for (unsigned int condition = 0; condition < 8; condition++) {
		bound_fixture();
		unbound_event();
		if (condition < 5)
			hardware = session.production_entry;
		switch (condition) {
		case 0: hardware.ipv4.new_tuple.dest_ip ^= 1; break;
		case 1: hardware.ipv4.l2.common.dest_mac_hi ^= 1; break;
		case 2: hardware.ib1 ^= AIROHA_FOE_IB1_BIND_STATIC; break;
		case 3: hardware.ib1 ^= AIROHA_FOE_IB1_BIND_UDP; break;
		case 4: ((u8 *)&hardware)[sizeof(hardware) - 1] ^= 1; break;
		case 5: hardware.ipv4.orig_tuple.dest_port ^= 1; break;
		case 6: hardware.ib1 ^= AIROHA_FOE_IB1_BIND_UDP; break;
		case 7: hardware.ib1 &= ~AIROHA_FOE_IB1_BIND_STATE; break;
		}
		expect_closed(-ESTALE);
		CHECK(installs == 1);
	}
}

static void test_sram_failures(void)
{
	for (unsigned int condition = 0; condition < 7; condition++) {
		bound_fixture();
		unbound_event();
		switch (condition) {
		case 0: fail_read = 1; break;
		case 1: fail_ack = 1; break;
		case 2: fail_read = 2; break;
		case 3: fail_ack = 2; break;
		case 4: install_error = -ETIMEDOUT; break;
		case 5: hardware = session.production_entry; fail_ack = 1; break;
		case 6: hardware = session.production_entry; fail_read = 1; break;
		}
		expect_closed(condition == 1 || condition == 3 || condition == 5 ? -EIO : -ETIMEDOUT);
		CHECK(installs == (condition == 4 ? 2u : 1u));
	}
}

static void test_withdraw_no_revival(void)
{
	bound_fixture();
	removal_in_progress = true;
	CHECK(!airoha_ppe_ct_remove_pon_flow(&ppe, &candidate));
	CHECK(session.invalidated && session.txn.phase == NPU_TXN_CLOSED);
	unbound_event();
	unsigned int consumed = takes, installed = installs;
	u32 epoch = session.txn.id.epoch;
	health_tick();
	CHECK(!airoha_npu_production_step(&session));
	CHECK(takes == consumed && installs == installed && session.txn.id.epoch == epoch);
	CHECK(!route_open && !auth_enabled);
	CHECK(FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, hardware.ib1) == AIROHA_FOE_STATE_UNBIND);
	memset(&candidate.pon_unbound_event, 0, sizeof(candidate.pon_unbound_event));
	retained();
	release_session();
}

int main(void)
{
	test_idle_rebind();
	test_queued_event();
	test_relearn_event_identity();
	test_row_conflicts();
	test_sram_failures();
	test_withdraw_no_revival();
	printf("cases=%u checks=%u passed\n", cases, checks);
	return 0;
}
