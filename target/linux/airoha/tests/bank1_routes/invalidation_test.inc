static void test_invalidation(void)
{
	u16 saved[4];
	unsigned int writes;

	setup_reopen();
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	memcpy(saved, eth.ct_bank1_routes.desired, sizeof(saved));
	writes = host.total_writes;
	CHECK(airoha_bank1_routes_revoke(NULL, &owner_token) == -EINVAL);
	CHECK(airoha_bank1_routes_revoke(&eth, NULL) == -EINVAL);
	CHECK(airoha_bank1_routes_revoke(&eth, &other_token) == -ESTALE);
	CHECK(host.total_writes == writes && eth.ct_bank1_routes.pon_open);
	flow_offload_mutex.held = false;
	spin_lock_bh(&ppe_lock);
	CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
	spin_unlock_bh(&ppe_lock);
	flow_offload_mutex.held = true;
	assert_reopen_closed();
	CHECK(!memcmp(saved, eth.ct_bank1_routes.desired, sizeof(saved)));
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -ESTALE);
	CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
	assert_reopen_closed();
	CHECK(airoha_bank1_routes_claim(&eth, &owner_token) == 0);
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	for (unsigned int kind = DROP_WRITE; kind <= BAD_READBACK; ++kind) {
		for (unsigned int index = 0; index < 4; ++index) {
			setup_reopen();
			CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
			memcpy(saved, eth.ct_bank1_routes.desired, sizeof(saved));
			eth.regs[index] = (eth.regs[index] & 0xffff0000) | 0x8888;
			trace_reset();
			inject(kind, index, 0);
			CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == -EIO);
			CHECK(eth.ct_bank1_routes.revoked && !eth.ct_bank1_routes.pon_open);
			CHECK(!eth.ct_bank1_routes.ready && eth.ct_bank1_routes.owner == &owner_token);
			CHECK(!memcmp(saved, eth.ct_bank1_routes.desired, sizeof(saved)));
			CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -ESTALE);
			trace_reset();
			CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
			assert_reopen_closed();
			assert_readbacks();
		}
	}
}
