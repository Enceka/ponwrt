static void setup_reopen(void)
{
	reset("owned PON reopen");
	claim_ok();
	ppe.ct_pon_qualified = true;
	eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0x1234;
}

static void assert_reopen_closed(void)
{
	CHECK(eth.ct_bank1_routes.owner == &owner_token);
	CHECK(!eth.ct_bank1_routes.pon_open && eth.ct_bank1_routes.revoked);
	CHECK(!eth.ct_bank1_routes.ready);
	for (unsigned int index = 0; index < 4; ++index)
		for (unsigned int shift = 0; shift < 16; shift += 4)
			CHECK(((eth.regs[index] >> shift) & 15) != FE_PSE_PORT_PPE2);
}

static void test_reopen(void)
{
	u16 saved[4];
	unsigned int writes;

	setup_reopen();
	memcpy(saved, eth.ct_bank1_routes.desired, sizeof(saved));
	CHECK(airoha_bank1_routes_open(NULL, &owner_token) == -EINVAL);
	CHECK(airoha_bank1_routes_open(&eth, NULL) == -EINVAL);
	CHECK(airoha_bank1_routes_open(&eth, &other_token) == -ESTALE);
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	CHECK(eth.ct_bank1_routes.pon_open && eth.ct_bank1_routes.ready);
	CHECK(eth.ct_bank1_routes.owner == &owner_token);
	CHECK((eth.regs[1] & 0xffff) == 0x8888);
	CHECK(memcmp(saved, eth.ct_bank1_routes.desired, sizeof(saved)) == 0);
	for (unsigned int index = 0; index < 4; ++index)
		if (index != 1)
			CHECK(eth.regs[index] == expected_route(0xa5100000u + (index << 16) + saved[index],
				index % 2 ? 5 : 0, true, false, false));
	eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0;
	CHECK(airoha_bank1_routes_release(&eth, &owner_token) == -EBUSY);
	eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0x1234;
	CHECK(airoha_gdm_fwd_cfg_update(&eth, 2, 0xffff0000, 0x42aa0000) == 0);
	CHECK(eth.regs[1] == 0x42aa8888 && eth.ct_bank1_routes.pon_open);
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	CHECK(airoha_bank1_routes_claim(&eth, &owner_token) == 0);
	CHECK(!eth.ct_bank1_routes.pon_open && !eth.ct_bank1_routes.revoked);
	CHECK(eth.ct_bank1_routes.ready);
	CHECK(memcmp(saved, eth.ct_bank1_routes.desired, sizeof(saved)) == 0);
	eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0;
	release_ok();

	for (unsigned int scenario = 0; scenario < 13; ++scenario) {
		setup_reopen();
		switch (scenario) {
		case 0: ppe.ct_pon_qualified = false; break;
		case 1: eth.ct_ordinary_full_test = true; break;
		case 2: eth.ct_cpu_fallback = true; break;
		case 3: eth.ct_cpu_route_mask[1] = 0xf; break;
		case 4: ppe.ct_stopping = true; break;
		case 5: ppe.ct_pon_ifc_route_owned = true; break;
		case 6: eth.regs[REG_PPE_GLO_CFG(1)] = 0; break;
		case 7: eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0; break;
		case 8: devices[1][0].qdma = &eth.qdma[0]; break;
		case 9: eth.ports[1] = NULL; break;
		case 10: eth.ct_bank1_routes.revoked = true; break;
		case 11: eth.ct_bank1_routes.ready = false; break;
		case 12:
			ports[1].devs[1] = &devices[1][1];
			devices[1][1].qdma = &eth.qdma[0];
			devices[1][1].netdev.running = true;
			break;
		}
		writes = host.total_writes;
		CHECK(airoha_bank1_routes_open(&eth, &owner_token) < 0);
		CHECK(!eth.ct_bank1_routes.pon_open && host.total_writes == writes);
	}

	for (unsigned int index = 0; index < 4; ++index) {
		setup_reopen();
		CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
		CHECK(airoha_gdm_fwd_cfg_update(&eth, index + 1, 0xf,
			(eth.ct_bank1_routes.desired[index] & 0xf) == 8 ? 5 : 8) == 0);
		assert_reopen_closed();
	}
	setup_reopen();
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	CHECK(airoha_gdm_fwd_cfg_update(&eth, 2, 0xffff, 0x5555) == 0);
	assert_reopen_closed();
	writes = host.total_writes;
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -ESTALE);
	CHECK(host.total_writes == writes);
	claim_ok();
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);

	for (unsigned int kind = DROP_WRITE; kind <= BAD_READBACK; ++kind)
		for (unsigned int index = 0; index < 4; ++index) {
			setup_reopen();
			if (kind == DROP_WRITE && index != 1)
				eth.regs[index] ^= BIT(28);
			inject(kind, index, 0);
			CHECK(airoha_bank1_routes_open(&eth, &owner_token) ==
			      (kind == DROP_WRITE && index != 1 ? 0 : -EIO));
			if (kind != DROP_WRITE || index == 1)
				assert_reopen_closed();
		}

	for (unsigned int index = 0; index < 4; ++index) {
		setup_reopen();
		CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
		inject(BAD_READBACK, index, 0);
		CHECK(airoha_gdm_fwd_cfg_update(&eth, index + 1, BIT(28), 0) == -EIO);
		assert_reopen_closed();
	}

	setup_reopen();
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	CHECK(airoha_ct_cpu_fallback(&eth) == 0);
	assert_reopen_closed();
	CHECK((eth.regs[1] & 0xffff) == 0x5555);
	claim_ok();
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -EBUSY);

	setup_reopen();
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	devices[1][0].lan = true;
	inject(BAD_READBACK, 1, 0);
	CHECK(airoha_dev_set_qdma(&devices[1][0]) == -EIO);
	CHECK(devices[1][0].qdma == &eth.qdma[1]);
	assert_reopen_closed();
	CHECK(airoha_dev_set_qdma(&devices[1][0]) == 0);
	CHECK(devices[1][0].qdma == &eth.qdma[0]);
	assert_reopen_closed();

	setup_reopen();
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	ports[1].devs[1] = &devices[1][1];
	devices[1][1].eth = &eth;
	devices[1][1].port = &ports[1];
	devices[1][1].lan = true;
	devices[1][1].netdev.running = true;
	inject(BAD_READBACK, 1, 0);
	CHECK(airoha_dev_set_qdma(&devices[1][1]) == -EIO);
	CHECK(!devices[1][1].qdma);
	assert_reopen_closed();

	setup_reopen();
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	ports[1].devs[1] = &devices[1][1];
	devices[1][1].qdma = &eth.qdma[0];
	devices[1][1].netdev.running = true;
	CHECK(airoha_gdm_fwd_cfg_update(&eth, 2, BIT(28), 0) == -EXDEV);
	assert_reopen_closed();

	for (unsigned int kind = DROP_WRITE; kind <= BAD_READBACK; ++kind)
		for (unsigned int rollback_fault = 0; rollback_fault < 2; ++rollback_fault) {
			setup_reopen();
			CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
			devices[1][0].lan = true;
			devices[1][0].netdev.irq = 99;
			inject(kind, 1, 1);
			if (rollback_fault)
				inject(BAD_READBACK, 1, 2);
			CHECK(airoha_dev_set_qdma(&devices[1][0]) == -EIO);
			CHECK(devices[1][0].qdma == &eth.qdma[1]);
			CHECK(eth.qdma[0].users == 2 && eth.qdma[1].users == 2);
			CHECK(devices[1][0].netdev.irq == 99 && host.rcu_syncs == 1 && host.wakes == 1);
			assert_reopen_closed();
			CHECK(airoha_dev_set_qdma(&devices[1][0]) == 0);
			CHECK(devices[1][0].qdma == &eth.qdma[0]);
			CHECK(eth.qdma[0].users == 3 && eth.qdma[1].users == 1);
			CHECK(host.rcu_syncs == 2 && host.wakes == 2);
			assert_reopen_closed();
		}

	setup_reopen();
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	ports[1].devs[1] = &devices[1][1];
	devices[1][1].eth = &eth;
	devices[1][1].port = &ports[1];
	devices[1][1].lan = false;
	devices[1][1].netdev.running = true;
	inject(BAD_READBACK, 1, 1);
	CHECK(airoha_dev_set_qdma(&devices[1][1]) == -EIO);
	CHECK(!devices[1][1].qdma && eth.qdma[0].users == 2 && eth.qdma[1].users == 2);
	CHECK(host.rcu_syncs == 1 && !host.wakes);
	assert_reopen_closed();
	CHECK(airoha_dev_set_qdma(&devices[1][1]) == 0);
	CHECK(devices[1][1].qdma == &eth.qdma[1] && eth.qdma[1].users == 3);

	for (unsigned int lro = 0; lro < 2; ++lro) {
		setup_reopen();
		CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
		devices[1][0].lan = true;
		devices[1][0].netdev.num_tx_queues = AIROHA_NUM_NETDEV_TX_RINGS;
		devices[1][0].netdev.queues[0].stopped = true;
		devices[1][0].netdev.queues[35].stopped = true;
		devices[1][0].netdev.features = lro ? 0 : NETIF_F_LRO;
		eth.qdma[1].lro = lro;
		inject(BAD_READBACK, 1, 1);
		CHECK(airoha_dev_set_qdma(&devices[1][0]) == -EIO);
		CHECK(eth.qdma[1].lro == !!lro);
		for (unsigned int index = 0; index < AIROHA_NUM_NETDEV_TX_RINGS; ++index)
			CHECK(devices[1][0].netdev.queues[index].stopped == (index == 0 || index == 35));
	}

	for (unsigned int rollback_fault = 0; rollback_fault < 2; ++rollback_fault) {
		setup_reopen();
		CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
		devices[2][0].use_flags = true;
		set_bit(AIROHA_DEV_F_WAN, &devices[2][0].flags);
		devices[2][0].qdma = &eth.qdma[1];
		loopback_enabled = true;
		fail_loopback_restore = rollback_fault;
		inject(BAD_READBACK, 2, 1);
		CHECK(airoha_disable_qos_for_gdm34(&devices[2][0].netdev) == -EIO);
		CHECK(test_bit(AIROHA_DEV_F_WAN, &devices[2][0].flags));
		CHECK(devices[2][0].qdma == &eth.qdma[1]);
		CHECK(eth.qdma[0].users == 2 && eth.qdma[1].users == 2);
		CHECK(loopback_enabled == !rollback_fault);
		fail_loopback_restore = false;
		CHECK(airoha_disable_qos_for_gdm34(&devices[2][0].netdev) == 0);
		CHECK(!test_bit(AIROHA_DEV_F_WAN, &devices[2][0].flags));
		CHECK(devices[2][0].qdma == &eth.qdma[0] && !loopback_enabled);
	}
}
