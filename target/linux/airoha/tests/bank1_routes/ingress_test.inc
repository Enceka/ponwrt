#include "airoha_npu_ingress.h"

static const unsigned int ingress_short_lut[2] = { 12, 13 };
static struct airoha_ct_pon_ifc_owner ingress_owner;
static struct airoha_ct_pon_ifc_words ingress_rows[AIROHA_CT_PON_IFC_ROW_COUNT];

static int ingress_read(void *context, unsigned int bank, unsigned int row,
			unsigned int page, u32 *words, unsigned int count)
{
	CHECK(context == ingress_rows && row >= AIROHA_CT_PON_IFC_ROW_BASE);
	row -= AIROHA_CT_PON_IFC_ROW_BASE;
	CHECK(row < ARRAY_SIZE(ingress_rows));
	CHECK((bank == 0 && page < 9 && count == 2) ||
	      (bank == 2 && page < 3 && count == airoha_ct_pon_ifc_action_words[page]));
	memcpy(words, bank ? ingress_rows[row].action[page] : ingress_rows[row].tcam[page],
	       count * sizeof(*words));
	return 0;
}

static int ingress_put(void *context, unsigned int bank, unsigned int row,
		       unsigned int page, const u32 *words, unsigned int count)
{
	CHECK(context == ingress_rows && row >= AIROHA_CT_PON_IFC_ROW_BASE);
	row -= AIROHA_CT_PON_IFC_ROW_BASE;
	CHECK(row < ARRAY_SIZE(ingress_rows));
	CHECK((bank == 0 && page < 9 && count == 2) ||
	      (bank == 2 && page < 3 && count == airoha_ct_pon_ifc_action_words[page]));
	memcpy(bank ? ingress_rows[row].action[page] : ingress_rows[row].tcam[page],
	       words, count * sizeof(*words));
	return 0;
}

static int ingress_drain(void *context)
{
	CHECK(context == ingress_rows);
	return 0;
}

static const struct airoha_ct_pon_ifc_io ingress_io = {
	.ctx = ingress_rows, .read = ingress_read, .put = ingress_put, .drain = ingress_drain,
};

static void ingress_reset(const char *name)
{
	reset(name);
	memset(&ingress_owner, 0, sizeof(ingress_owner));
	memset(ingress_rows, 0, sizeof(ingress_rows));
	eth.ct_ifc_port_mask = XSI_ETH_VIP_PORT_MASK;
	eth.ifc_port_desired = XSI_ETH_VIP_PORT_MASK | BIT(2) | BIT(3);
	eth.regs[REG_FE_IFC_PORT_EN] = XSI_ETH_VIP_PORT_MASK;
	ppe.ct_pon_qualified = true;
}

static void ingress_prepare(void)
{
	CHECK(airoha_npu_ingress_prepare(&ingress_owner, &ingress_io, ingress_short_lut) == 0);
	CHECK(airoha_bank1_routes_ingress_ready(&eth, &owner_token) == 0);
	CHECK(eth.ct_bank1_routes.ingress_ready);
	CHECK(!eth.ct_bank1_routes.pon_open && !eth.ct_ifc_pon_ready);
}

static void ingress_open(void)
{
	ingress_prepare();
	eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0x1234;
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	CHECK(airoha_bank1_routes_check(&eth, &owner_token, true) == 0);
	CHECK(eth.ct_bank1_routes.ingress_ready && eth.ct_bank1_routes.pon_open);
	CHECK(eth.ct_ifc_pon_ready);
	CHECK(eth.ct_ifc_port_mask == (XSI_ETH_VIP_PORT_MASK | BIT(2)));
	CHECK(eth.regs[REG_FE_IFC_PORT_EN] == (XSI_ETH_VIP_PORT_MASK | BIT(2)));
	CHECK((eth.regs[1] & 0xffff) == 0x5555);
}

static void ingress_closed(void)
{
	CHECK(eth.ct_bank1_routes.owner == &owner_token);
	CHECK(!eth.ct_bank1_routes.pon_open && !eth.ct_bank1_routes.ingress_ready);
	CHECK(!eth.ct_ifc_pon_ready);
	CHECK(!(eth.ct_ifc_port_mask & BIT(2)));
	CHECK(!(eth.regs[REG_FE_IFC_PORT_EN] & BIT(2)));
	CHECK((eth.regs[1] & 0xffff) == 0x5555);
}

static void ingress_assert_scope_order(bool opening)
{
	unsigned int gdm_writes = 0, scope_writes = 0;

	for (size_t index = 0; index < host.length; ++index) {
		const struct mmio_event *record = &host.events[index];

		if (!record->write)
			continue;
		if (record->reg == REG_FE_IFC_PORT_EN) {
			CHECK(record->route_locked && record->port_locked);
			CHECK(!!(record->value & BIT(2)) == opening);
			CHECK(opening ? gdm_writes == 4 : gdm_writes == 0);
			++scope_writes;
		} else if (record->reg < 4) {
			CHECK(opening ? scope_writes == 0 : scope_writes == 1);
			++gdm_writes;
		}
	}
	CHECK(scope_writes == 1 && gdm_writes == 4);
	assert_readbacks();
}

static void test_ingress_lifecycle(void)
{
	u32 desired[4];
	unsigned int writes;

	ingress_reset("claim closes source2 before GDM writes and preserves all desired selectors");
	snapshot(desired);
	eth.regs[REG_FE_IFC_PORT_EN] |= BIT(2);
	for (unsigned int index = 0; index < 4; ++index)
		host.snapshot[index] = desired[index];
	host.verify_snapshot = true;
	claim_ok();
	assert_owner(desired, true);
	assert_routes(desired, true, false, false);
	ingress_closed();
	ingress_assert_scope_order(false);
	CHECK(airoha_bank1_routes_check(&eth, &owner_token, false) == 0);
	eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0x1234;
	writes = host.total_writes;
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -EACCES);
	CHECK(host.total_writes == writes);
	ingress_prepare();
	eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0x1234;
	trace_reset();
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	ingress_assert_scope_order(true);
	CHECK(airoha_bank1_routes_check(&eth, &owner_token, true) == 0);
	CHECK(airoha_ifc_lan_ports_ready(&eth));
	assert_owner(desired, true);
	assert_routes(desired, true, false, false);
	writes = host.total_writes;
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -EACCES);
	CHECK(airoha_bank1_routes_ingress_ready(&eth, &owner_token) == -ESTALE);
	CHECK(host.total_writes == writes);
	eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0;
	CHECK(airoha_bank1_routes_release(&eth, &owner_token) == -EBUSY);
	trace_reset();
	flow_offload_mutex.held = false;
	spin_lock_bh(&ppe_lock);
	CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
	spin_unlock_bh(&ppe_lock);
	flow_offload_mutex.held = true;
	ingress_assert_scope_order(false);
	ingress_closed();
	CHECK(eth.ct_bank1_routes.revoked && !eth.ct_bank1_routes.ready);
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -ESTALE);
	CHECK(airoha_bank1_routes_ingress_ready(&eth, &owner_token) == -ESTALE);
	claim_ok();
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -EACCES);
	ingress_open();
	trace_reset();
	claim_ok();
	ingress_assert_scope_order(false);
	ingress_closed();
	assert_owner(desired, true);
	CHECK(airoha_npu_ingress_restore(&ingress_owner, &ingress_io) == 0);
	eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0;
	release_ok();
	assert_routes(desired, false, false, false);
}

static void test_ingress_parameters(void)
{
	unsigned int writes;

	ingress_reset("public route interfaces reject invalid and foreign owners without writes");
	claim_ok();
	writes = host.total_writes;
	CHECK(airoha_bank1_routes_ingress_ready(NULL, &owner_token) == -EINVAL);
	CHECK(airoha_bank1_routes_ingress_ready(&eth, NULL) == -EINVAL);
	CHECK(airoha_bank1_routes_ingress_ready(&eth, &other_token) == -ESTALE);
	CHECK(airoha_bank1_routes_check(NULL, &owner_token, false) == -EINVAL);
	CHECK(airoha_bank1_routes_check(&eth, NULL, false) == -EINVAL);
	CHECK(airoha_bank1_routes_check(&eth, &other_token, false) == -ESTALE);
	CHECK(airoha_bank1_routes_check(&eth, &owner_token, true) == -ESTALE);
	CHECK(airoha_bank1_routes_revoke(&eth, &other_token) == -ESTALE);
	CHECK(airoha_bank1_routes_open(&eth, &other_token) == -ESTALE);
	CHECK(airoha_bank1_routes_claim(&eth, &other_token) == -EBUSY);
	CHECK(airoha_bank1_routes_release(&eth, &other_token) == -ESTALE);
	CHECK(airoha_ct_pon_ifc_route_open(&ppe) == -EBUSY);
	CHECK(host.total_writes == writes);

	for (unsigned int scenario = 0; scenario < 15; ++scenario) {
		ingress_reset("open retains existing eligibility and actual CPU receiver checks");
		claim_ok();
		ingress_prepare();
		eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0x1234;
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
		case 13: eth.ct_bank1_routes.ingress_ready = false; break;
		case 14: devices[1][0].qdma = &foreign_qdma; break;
		}
		writes = host.total_writes;
		CHECK(airoha_bank1_routes_open(&eth, &owner_token) < 0);
		CHECK(host.total_writes == writes && !eth.ct_bank1_routes.pon_open);
		CHECK(!(eth.regs[REG_FE_IFC_PORT_EN] & BIT(2)));
	}

	for (unsigned int scenario = 0; scenario < 6; ++scenario) {
		ingress_reset("source2 scope prerequisites fail closed after CPU defaults are checked");
		claim_ok();
		ingress_prepare();
		eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0x1234;
		switch (scenario) {
		case 0: ppe.ct_ifc.cfg_owned = false; break;
		case 1: eth.regs[REG_FE_CSR_IFC_CFG] &= ~FE_IFC_EN_MASK; break;
		case 2: eth.ifc_port_desired &= ~BIT(2); break;
		case 3: eth.ifc_port_desired &= ~XSI_ETH_VIP_PORT_MASK; break;
		case 4: eth.ct_ifc_cpu_port_failed = true; break;
		case 5: eth.regs[REG_FE_IFC_PORT_EN] ^= BIT(3); break;
		}
		CHECK(airoha_bank1_routes_open(&eth, &owner_token) < 0);
		ingress_closed();
		CHECK(eth.ct_bank1_routes.revoked && !eth.ct_bank1_routes.ready);
	}
}

static void test_ingress_checks(void)
{
	for (unsigned int opened = 0; opened < 2; ++opened) {
		for (unsigned int scenario = 0; scenario < (opened ? 10u : 4u); ++scenario) {
			unsigned int writes;

			ingress_reset("route check reads actual receiver, CPU selectors and scope state");
			claim_ok();
			if (opened)
				ingress_open();
			switch (scenario) {
			case 0: eth.regs[1] ^= 1; break;
			case 1: devices[1][0].qdma = &eth.qdma[0]; break;
			case 2: eth.ct_ifc_port_mask ^= BIT(2); break;
			case 3: eth.regs[REG_FE_IFC_PORT_EN] ^= BIT(2); break;
			case 4: eth.ct_bank1_routes.ingress_ready = false; break;
			case 5: eth.ct_ifc_pon_ready = false; break;
			case 6: eth.ifc_port_desired &= ~BIT(2); break;
			case 7: ppe.ct_ifc.cfg_owned = false; break;
			case 8: eth.regs[REG_FE_CSR_IFC_CFG] &= ~FE_IFC_EN_MASK; break;
			case 9: eth.ct_bank1_routes.revoked = true; break;
			}
			writes = host.total_writes;
			CHECK(airoha_bank1_routes_check(&eth, &owner_token, opened) < 0);
			if (!opened)
				CHECK(airoha_bank1_routes_ingress_ready(&eth, &owner_token) < 0);
			CHECK(host.total_writes == writes);
		}
	}
}

static void test_ingress_scope_faults(void)
{
	for (unsigned int kind = DROP_WRITE; kind <= BAD_READBACK; ++kind) {
		for (unsigned int operation = 0; operation < 3; ++operation) {
			u32 desired[4];
			struct airoha_ct_pon_ifc_words saved_rows[AIROHA_CT_PON_IFC_ROW_COUNT];

			ingress_reset("source2 write loss and applied write with bad readback retain owner and rules");
			snapshot(desired);
			claim_ok();
			if (operation != 0)
				ingress_open();
			else
				ingress_prepare();
			memcpy(saved_rows, ingress_rows, sizeof(saved_rows));
			eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0x1234;
			trace_reset();
			host.readback_mask = BIT(2);
			inject(kind, REG_FE_IFC_PORT_EN, 0);
			if (operation == 0)
				CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -EIO);
			else if (operation == 1)
				CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == -EIO);
			else
				CHECK(airoha_bank1_routes_claim(&eth, &owner_token) == -EIO);
			CHECK(!host.failures);
			assert_owner(desired, false);
			CHECK(!eth.ct_bank1_routes.ingress_ready && !eth.ct_bank1_routes.pon_open);
			CHECK(!memcmp(saved_rows, ingress_rows, sizeof(saved_rows)));
			CHECK(ingress_owner.active == 3 && ingress_owner.dirty == 3 && ingress_owner.saved_valid);
			CHECK(ppe.ct_ifc.cfg_owned);
			CHECK(!!(eth.regs[REG_FE_IFC_PORT_EN] & BIT(2)) ==
			      (kind == DROP_WRITE && operation != 0));
			CHECK(airoha_bank1_routes_release(&eth, &owner_token) == -EBUSY);
			CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -ESTALE);
			CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
			ingress_closed();
			claim_ok();
			ingress_open();
		}
	}

	for (unsigned int kind = DROP_WRITE; kind <= BAD_READBACK; ++kind) {
		ingress_reset("failed open and failed closure keep rules for repeated closure and reopening");
		claim_ok();
		ingress_prepare();
		eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0x1234;
		trace_reset();
		host.readback_mask = BIT(2);
		inject(BAD_READBACK, REG_FE_IFC_PORT_EN, 0);
		inject(kind, REG_FE_IFC_PORT_EN, 1);
		CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -EIO);
		CHECK(!host.failures && eth.ct_bank1_routes.owner == &owner_token);
		CHECK(!eth.ct_bank1_routes.ready && !eth.ct_bank1_routes.ingress_ready);
		CHECK(ingress_owner.active == 3 && ingress_owner.saved_valid);
		CHECK(!!(eth.regs[REG_FE_IFC_PORT_EN] & BIT(2)) == (kind == DROP_WRITE));
		CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
		ingress_closed();
		claim_ok();
		ingress_open();
	}

	for (unsigned int stopping = 0; stopping < 2; ++stopping) {
		for (unsigned int kind = DROP_WRITE; kind <= BAD_READBACK; ++kind) {
			ingress_reset("scope closure retries during fallback and stopping without ingress eligibility");
			claim_ok();
			ingress_open();
			ppe.ct_stopping = stopping;
			trace_reset();
			host.readback_mask = BIT(2);
			inject(kind, REG_FE_IFC_PORT_EN, 0);
			CHECK(airoha_ct_cpu_fallback(&eth) == -EIO);
			CHECK(eth.ct_cpu_fallback && !eth.ct_bank1_routes.ingress_ready);
			CHECK(eth.ct_bank1_routes.owner == &owner_token && ingress_owner.active == 3);
			CHECK(!eth.ct_cpu_routes_ready && eth.ct_cpu_ifc_disabled);
			CHECK(airoha_ct_cpu_fallback(&eth) == 0);
			ingress_closed();
			CHECK(eth.ct_cpu_routes_ready);
			CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
			CHECK(airoha_bank1_routes_claim(&eth, &owner_token) == 0);
			ingress_prepare();
			CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -EBUSY);
		}
	}
}

static void test_ingress_route_faults(void)
{
	for (unsigned int kind = DROP_WRITE; kind <= BAD_READBACK; ++kind) {
		for (unsigned int reg = 0; reg < 4; ++reg) {
			for (unsigned int operation = 0; operation < 3; ++operation) {
				u32 desired[4];

				ingress_reset("GDM readback failure retains owner and closes ingress before retry");
				snapshot(desired);
				claim_ok();
				if (operation == 0) {
					ingress_prepare();
					eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0x1234;
				} else if (operation == 1) {
					ingress_open();
				}
				eth.regs[reg] = (eth.regs[reg] & 0xffff0000) | 0x9999;
				trace_reset();
				inject(kind, reg, 0);
				if (operation == 0)
					CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -EIO);
				else if (operation == 1)
					CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == -EIO);
				else
					CHECK(airoha_bank1_routes_release(&eth, &owner_token) == -EIO);
				CHECK(!host.failures);
				assert_owner(desired, false);
				CHECK(!eth.ct_bank1_routes.ingress_ready);
				CHECK(!(eth.regs[REG_FE_IFC_PORT_EN] & BIT(2)));
				CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
				ingress_closed();
				claim_ok();
				eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0;
				release_ok();
				assert_routes(desired, false, false, false);
			}
		}
	}
}

static void test_ingress_writers(void)
{
	for (unsigned int state = 0; state < 3; ++state) {
		unsigned int writes;

		ingress_reset("generic scope update rejects route owner in claimed prepared and opened states");
		claim_ok();
		if (state == 1)
			ingress_prepare();
		else if (state == 2)
			ingress_open();
		eth.ct_ifc_pon_ready = true;
		writes = host.total_writes;
		CHECK(airoha_ifc_scope_update(&eth, eth.ct_ifc_port_mask,
			XSI_ETH_VIP_PORT_MASK | BIT(2)) == -EBUSY);
		CHECK(airoha_ifc_scope_update(&eth, eth.ct_ifc_port_mask,
			XSI_ETH_VIP_PORT_MASK) == -EBUSY);
		CHECK(host.total_writes == writes);
		if (state) {
			eth.regs[REG_FE_CSR_IFC_CFG] &= ~FE_IFC_EN_MASK;
			CHECK(airoha_ifc_scope_ports(&eth, 0) == -EBUSY);
			CHECK(host.total_writes == writes);
		}
		CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
		eth.regs[REG_FE_CSR_IFC_CFG] &= ~FE_IFC_EN_MASK;
		CHECK(airoha_ifc_scope_ports(&eth, 0) == 0);
		CHECK(!eth.ct_ifc_port_mask && eth.ct_bank1_routes.owner == &owner_token);
		CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
	}

	ingress_reset("port writer updates desired map without reopening source2 after a failed closure");
	claim_ok();
	ingress_open();
	inject(DROP_WRITE, REG_FE_IFC_PORT_EN, 0);
	CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == -EIO);
	airoha_ifc_update_ports(&eth, BIT(2) | BIT(3), true);
	ingress_closed();
	CHECK(eth.ifc_port_desired == (XSI_ETH_VIP_PORT_MASK | BIT(2) | BIT(3)));
	airoha_ifc_update_ports(&eth, BIT(2), false);
	CHECK(!(eth.ifc_port_desired & BIT(2)));
	claim_ok();
	ingress_prepare();
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -ESHUTDOWN);
	ingress_closed();
	airoha_ifc_update_ports(&eth, BIT(2), true);
	claim_ok();
	ingress_open();

	ingress_reset("legacy generic scope update remains usable after route ownership ends");
	claim_ok();
	release_ok();
	eth.ct_ifc_pon_ready = true;
	CHECK(airoha_ifc_scope_update(&eth, XSI_ETH_VIP_PORT_MASK,
		XSI_ETH_VIP_PORT_MASK | BIT(2)) == 0);
	CHECK(airoha_ifc_scope_update(&eth, XSI_ETH_VIP_PORT_MASK | BIT(2),
		XSI_ETH_VIP_PORT_MASK) == 0);
}

static void test_ingress_qdma(void)
{
	for (unsigned int kind = DROP_WRITE; kind <= BAD_READBACK; ++kind) {
		ingress_reset("QDMA publication waits for a successful source2 closure");
		claim_ok();
		ingress_open();
		devices[1][0].lan = true;
		devices[1][0].netdev.irq = 99;
		host.readback_mask = BIT(2);
		inject(kind, REG_FE_IFC_PORT_EN, 0);
		CHECK(airoha_dev_set_qdma(&devices[1][0]) == -EIO);
		CHECK(devices[1][0].qdma == &eth.qdma[1]);
		CHECK(eth.qdma[0].users == 2 && eth.qdma[1].users == 2);
		CHECK(devices[1][0].netdev.irq == 99 && !host.rcu_syncs);
		CHECK(eth.ct_bank1_routes.owner == &owner_token && ingress_owner.active == 3);
		CHECK(airoha_dev_set_qdma(&devices[1][0]) == 0);
		CHECK(devices[1][0].qdma == &eth.qdma[0]);
		CHECK((eth.regs[1] & 0xffff) == 0);
		CHECK(!eth.ct_bank1_routes.ingress_ready && !(eth.regs[REG_FE_IFC_PORT_EN] & BIT(2)));
		CHECK(airoha_bank1_routes_check(&eth, &owner_token, false) < 0);
	}

	ingress_reset("native routes and QoS writer retain CPU defaults under ownership");
	claim_ok();
	CHECK(airoha_ct_pair_gdm_start(&ppe) == 0);
	CHECK((eth.regs[1] & 0xffff) == 0x5555);
	CHECK(airoha_ct_pair_gdm_stop(&ppe) == 0);
	CHECK((eth.regs[1] & 0xffff) == 0x5555);
	CHECK(airoha_set_gdm_port_fwd_cfg(&eth, 2, FE_PSE_PORT_PPE1) == 0);
	CHECK(eth.ct_bank1_routes.desired[1] == 0x8888 && (eth.regs[1] & 0xffff) == 0x5555);
	CHECK(airoha_disable_qos_for_gdm34(&devices[2][0].netdev) == 0);
}

static void test_ingress_recovery(void)
{
	for (unsigned int kind = DROP_WRITE; kind <= BAD_READBACK; ++kind) {
		u32 desired[4];

		ingress_reset("failed initial claim retains snapshots for closure retry");
		snapshot(desired);
		eth.regs[REG_FE_IFC_PORT_EN] |= BIT(2);
		host.readback_mask = BIT(2);
		inject(kind, REG_FE_IFC_PORT_EN, 0);
		CHECK(airoha_bank1_routes_claim(&eth, &owner_token) == -EIO);
		assert_owner(desired, false);
		CHECK(!eth.ct_bank1_routes.ingress_ready);
		claim_ok();
		ingress_closed();
		assert_owner(desired, true);
	}

	for (unsigned int stopping = 0; stopping < 2; ++stopping) {
		ingress_reset("existing owner retries claim after host PPE stops");
		claim_ok();
		ingress_open();
		ppe.ct_host_ppe = false;
		ppe.ct_stopping = stopping;
		eth.ct_cpu_fallback = !stopping;
		inject(DROP_WRITE, REG_FE_IFC_PORT_EN, 0);
		CHECK(airoha_bank1_routes_claim(&eth, &owner_token) == -EIO);
		CHECK(eth.ct_bank1_routes.owner == &owner_token && !eth.ct_bank1_routes.ready);
		claim_ok();
		ingress_closed();
	}

	ingress_reset("release retains owner while actual source2 scope remains enabled");
	claim_ok();
	ingress_open();
	inject(DROP_WRITE, REG_FE_IFC_PORT_EN, 0);
	CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == -EIO);
	eth.regs[REG_PPE_PPE_FLOW_CFG(1)] = 0;
	CHECK(airoha_bank1_routes_release(&eth, &owner_token) == -EBUSY);
	CHECK(eth.ct_bank1_routes.owner == &owner_token && ingress_owner.active == 3);
	CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
	CHECK(airoha_npu_ingress_restore(&ingress_owner, &ingress_io) == 0);
	release_ok();

	ingress_reset("closure removes unexpected scope bits and keeps only LAN1");
	claim_ok();
	ingress_open();
	eth.ct_ifc_port_mask |= BIT(3);
	eth.regs[REG_FE_IFC_PORT_EN] |= BIT(3);
	CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
	CHECK(eth.ct_ifc_port_mask == XSI_ETH_VIP_PORT_MASK);
	CHECK(eth.regs[REG_FE_IFC_PORT_EN] == XSI_ETH_VIP_PORT_MASK);
	ingress_closed();

	ingress_reset("new shared scope is rejected until route ownership is released");
	claim_ok();
	CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
	eth.regs[REG_FE_CSR_IFC_CFG] &= ~FE_IFC_EN_MASK;
	CHECK(airoha_ifc_scope_ports(&eth, 0) == 0);
	trace_reset();
	CHECK(airoha_ifc_scope_ports(&eth, XSI_ETH_VIP_PORT_MASK) == -EBUSY);
	CHECK(!host.total_writes && !eth.ct_ifc_port_mask);
	eth.regs[REG_FE_CSR_IFC_CFG] |= FE_IFC_EN_MASK;
	CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == -EIO);
	CHECK(eth.ct_bank1_routes.owner == &owner_token);
	eth.regs[REG_FE_CSR_IFC_CFG] &= ~FE_IFC_EN_MASK;
	CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
	release_ok();
	CHECK(airoha_ifc_scope_ports(&eth, XSI_ETH_VIP_PORT_MASK) == 0);
}

static unsigned int ingress_packet_destination(unsigned int selector, unsigned int source,
					      u16 protocol, bool short_packet)
{
	u32 key[9] = { [0] = BIT(source), [5] = protocol };

	if (short_packet)
		key[4] = BIT(protocol == ETH_P_IP ? ingress_short_lut[0] : ingress_short_lut[1]);
	if ((eth.regs[REG_FE_CSR_IFC_CFG] & FE_IFC_EN_MASK) &&
	    (eth.regs[REG_FE_IFC_PORT_EN] & BIT(source))) {
		for (unsigned int row = 0; row < 2; ++row) {
			bool matches = !!(ingress_rows[row].action[2][0] & BIT(31));

			for (unsigned int page = 0; page < ARRAY_SIZE(key); ++page)
				matches &= !((key[page] ^ ingress_rows[row].tcam[page][0]) &
					     ingress_rows[row].tcam[page][1]);
			if (matches)
				return (ingress_rows[row].action[0][0] >> 8) & 15;
		}
	}
	return (eth.regs[1] >> (selector * 4)) & 15;
}

static void test_ingress_auth_default(void)
{
	ingress_reset("classifier misses use CPU and hits enter NPU before AUTH without a direct PPE2 path");
	claim_ok();
	ingress_open();
	for (unsigned int selector = 0; selector < 4; ++selector) {
		CHECK(ingress_packet_destination(selector, 2, ETH_P_IP, false) == 6);
		CHECK(ingress_packet_destination(selector, 2, ETH_P_IPV6, false) == 6);
		CHECK(ingress_packet_destination(selector, 2, ETH_P_IP, true) == FE_PSE_PORT_CDM2);
		CHECK(ingress_packet_destination(selector, 2, ETH_P_IPV6, true) == FE_PSE_PORT_CDM2);
		CHECK(ingress_packet_destination(selector, 2, 0x0806, false) == FE_PSE_PORT_CDM2);
		CHECK(ingress_packet_destination(selector, 3, ETH_P_IP, false) == FE_PSE_PORT_CDM2);
	}
	CHECK(airoha_bank1_routes_revoke(&eth, &owner_token) == 0);
	for (unsigned int selector = 0; selector < 4; ++selector)
		CHECK(ingress_packet_destination(selector, 2, ETH_P_IP, false) == FE_PSE_PORT_CDM2);
}

static void test_ingress_selectors(void)
{
	for (unsigned int ordinary = 0; ordinary < 2; ++ordinary) {
		ingress_reset("all selector requests retain actual CPU defaults on GDM2 and guard other GDMs");
		eth.ct_ordinary_full_test = ordinary;
		claim_ok();
		host.tracing = false;
		for (u32 low = 0; low < 0x10000; ++low) {
			for (unsigned int index = 0; index < 4; ++index) {
				u32 request = 0x5a100000u + (index << 16) + low;
				u32 expected = index == 1 ? (request & 0xffff0000) | 0x5555 :
					expected_route(request, index % 2 ? 5 : 0, true, false, false);

				CHECK(airoha_gdm_fwd_cfg_update(&eth, index + 1, U32_MAX, request) == 0);
				CHECK(eth.ct_bank1_routes.desired[index] == low);
				CHECK(eth.regs[index] == expected);
				++selector_vectors;
			}
		}
		release_ok();
	}
	for (unsigned int receiver = 0; receiver < 2; ++receiver) {
		ingress_reset("all GDM2 selectors follow actual CPU while closed or ingress opened");
		devices[1][0].qdma = &eth.qdma[receiver];
		claim_ok();
		if (receiver)
			ingress_open();
		host.tracing = false;
		spin_lock_bh(&eth.ct_route_lock);
		for (u32 low = 0; low < 0x10000; ++low) {
			CHECK(airoha_ct_gdm_route_write_locked(&eth, 2, 0x42aa0000 | low, true) == 0);
			CHECK(eth.regs[1] == (0x42aa0000 | (receiver ? 0x5555 : 0)));
			CHECK(eth.ct_bank1_routes.pon_open == !!receiver);
			++selector_vectors;
		}
		spin_unlock_bh(&eth.ct_route_lock);
	}
}

static void test_ingress(void)
{
	test_ingress_lifecycle();
	test_ingress_parameters();
	test_ingress_checks();
	test_ingress_scope_faults();
	test_ingress_route_faults();
	test_ingress_writers();
	test_ingress_qdma();
	test_ingress_recovery();
	test_ingress_auth_default();
	test_ingress_selectors();
}
