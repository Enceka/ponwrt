static void test_static_snapshot(void)
{
	struct airoha_pon_candidate_snapshot snapshot;
	struct airoha_foe_entry expected;

	fixture();
	available.data.ib1 &= ~(AIROHA_FOE_IB1_BIND_STATE | AIROHA_FOE_IB1_BIND_TIMESTAMP);
	available.data.ib1 |= AIROHA_FOE_IB1_BIND_STATIC |
		FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_UNBIND) |
		FIELD_PREP(AIROHA_FOE_IB1_BIND_TIMESTAMP, 5);
	candidate.data = available.data;
	snapshot = available;
	expected = available.data;
	expected.ib1 &= ~(AIROHA_FOE_IB1_BIND_STATE | AIROHA_FOE_IB1_BIND_TIMESTAMP |
			  AIROHA_FOE_IB1_BIND_STATIC);
	expected.ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND) |
		FIELD_PREP(AIROHA_FOE_IB1_BIND_TIMESTAMP, 37);
	start_session();
	unbound_event();
	CHECK(!airoha_npu_production_step(&session));
	CHECK(session.production_bound && installs == 1 && session.production_hash == 23);
	CHECK(session.txn.phase == NPU_TXN_OPEN && auth_enabled && route_open);
	CHECK(!(hardware.ib1 & AIROHA_FOE_IB1_BIND_STATIC));
	CHECK(!memcmp(&hardware, &expected, sizeof(expected)));
	CHECK(!memcmp(&session.production_entry, &expected, sizeof(expected)));
	CHECK(!memcmp(&session.production, &snapshot, sizeof(snapshot)));
	CHECK(!memcmp(&available, &snapshot, sizeof(snapshot)));
	CHECK(!memcmp(&candidate.data, &snapshot.data, sizeof(candidate.data)));
	CHECK(!airoha_npu_production_step(&session) && installs == 1 && takes == 1);
	removal_in_progress = true;
	CHECK(!airoha_ppe_ct_remove_pon_flow(&ppe, &candidate));
	CHECK(session.invalidated && session.txn.phase == NPU_TXN_CLOSED && !auth_enabled && !route_open);
	CHECK(!memcmp(&hardware, &(struct airoha_foe_entry){}, sizeof(hardware)));
	CHECK(!memcmp(&session.production, &snapshot, sizeof(snapshot)));
	retained();
	release_session();
}

int main(void)
{
	test_lifecycle();
	test_static_snapshot();
	test_checked_install_failure();
	test_withdraw_retry();
	printf("cases=%u checks=%u passed\n", cases, checks);
	return 0;
}
