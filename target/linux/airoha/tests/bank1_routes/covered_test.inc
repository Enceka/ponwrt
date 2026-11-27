static void covered_reset(const char *name)
{
	reset(name);
	covered_diagnostic = true;
	eth.ct_ifc_port_mask = XSI_ETH_VIP_PORT_MASK;
	eth.ifc_port_desired = XSI_ETH_VIP_PORT_MASK | BIT(2);
	eth.regs[REG_FE_IFC_PORT_EN] = XSI_ETH_VIP_PORT_MASK;
	eth.regs[REG_PPE_TB_CFG(1)] = 2 << 4;
}

static void covered_open(void)
{
	claim_ok();
	CHECK(airoha_bank1_routes_ingress_ready(&eth, &owner_token) == 0);
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
	CHECK(airoha_bank1_routes_check(&eth, &owner_token, true) == 0);
	CHECK((eth.regs[1] & 0xffff) == 0x8888);
	CHECK(!ppe.ct_pon_qualified && !eth.regs[REG_PPE_PPE_FLOW_CFG(1)]);
}

static void covered_order(bool opening)
{
	bool scope_read = false, route_read = false;
	unsigned int scope_writes = 0, route_writes = 0;

	for (size_t index = 0; index < host.length; ++index) {
		const struct mmio_event *record = &host.events[index];

		if (record->reg == REG_FE_IFC_PORT_EN) {
			if (record->write) {
				CHECK(record->route_locked && record->port_locked);
				CHECK(!!(record->value & BIT(2)) == opening);
				CHECK(opening || route_read);
				++scope_writes;
			} else if (scope_writes)
				scope_read = true;
		} else if (record->reg == REG_GDM_FWD_CFG(2)) {
			if (record->write) {
				CHECK(record->route_locked);
				CHECK((record->value & 0xffff) == (opening ? 0x8888 : 0x5555));
				CHECK(!opening || scope_read);
				++route_writes;
			} else if (route_writes)
				route_read = true;
		}
	}
	CHECK(scope_writes == 1 && route_writes == 1);
	CHECK(scope_read && route_read);
	assert_readbacks();
}

static void covered_closed(void)
{
	CHECK((eth.regs[1] & 0xffff) == 0x5555);
	CHECK(!(eth.regs[REG_FE_IFC_PORT_EN] & BIT(2)));
	CHECK(!(eth.ct_ifc_port_mask & BIT(2)));
	CHECK(!eth.ct_bank1_routes.pon_open && !eth.ct_bank1_routes.ingress_ready);
	CHECK(!eth.ct_ifc_pon_ready);
	CHECK(eth.ct_bank1_routes.owner == &owner_token);
}

static void covered_fault_state(void)
{
	fprintf(stderr, "fault-state gdm2=%08x ports=%08x scope=%08x ifc=%08x "
		"owner=%u ready=%u revoked=%u cpu_ready=%u ifc_disabled=%u\n",
		eth.regs[REG_GDM_FWD_CFG(2)], eth.regs[REG_FE_IFC_PORT_EN],
		eth.ct_ifc_port_mask, eth.regs[REG_FE_CSR_IFC_CFG],
		(unsigned int)(eth.ct_bank1_routes.owner == &owner_token),
		(unsigned int)eth.ct_bank1_routes.ready, (unsigned int)eth.ct_bank1_routes.revoked,
		(unsigned int)eth.ct_cpu_routes_ready, (unsigned int)eth.ct_cpu_ifc_disabled);
}

static void test_covered_normal(void)
{
	u32 desired[4];

	for (unsigned int revoke = 0; revoke < 2; ++revoke) {
		covered_reset("scope readback precedes PPE2; CPU readback precedes scope close");
		snapshot(desired);
		claim_ok();
		covered_closed();
		CHECK(airoha_bank1_routes_ingress_ready(&eth, &owner_token) == 0);
		trace_reset();
		CHECK(airoha_bank1_routes_open(&eth, &owner_token) == 0);
		covered_order(true);
		CHECK(airoha_bank1_routes_check(&eth, &owner_token, true) == 0);
		assert_owner(desired, true);
		CHECK(airoha_bank1_routes_release(&eth, &owner_token) == -EBUSY);
		CHECK(airoha_gdm_fwd_cfg_update(&eth, 2, 0xffff0000, 0x12340000) == 0);
		CHECK(eth.regs[1] == 0x12348888);
		CHECK(eth.ct_bank1_routes.desired[1] == (u16)desired[1]);
		trace_reset();
		CHECK((revoke ? airoha_bank1_routes_revoke(&eth, &owner_token) :
			airoha_bank1_routes_claim(&eth, &owner_token)) == 0);
		covered_order(false);
		covered_closed();
		release_ok();
		CHECK(eth.regs[1] == (0x12340000 | (u16)desired[1]));
	}
	covered_reset("fallback success closes CPU route and scope before disabling IFC");
	covered_open();
	trace_reset();
	CHECK(airoha_ct_cpu_fallback(&eth) == 0);
	covered_closed();
	CHECK(!(eth.regs[REG_FE_CSR_IFC_CFG] & FE_IFC_EN_MASK));
	CHECK(eth.ct_cpu_routes_ready && eth.ct_cpu_ifc_disabled);
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) != 0);
	release_ok();
	covered_reset("foreign owner, unqualified production and missing receiver reject open");
	claim_ok();
	CHECK(airoha_bank1_routes_ingress_ready(&eth, &owner_token) == 0);
	CHECK(airoha_bank1_routes_open(&eth, &other_token) == -ESTALE);
	covered_diagnostic = false;
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -EOPNOTSUPP);
	covered_diagnostic = true;
	devices[1][0].qdma = &foreign_qdma;
	CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -ENODEV);
	devices[1][0].qdma = &eth.qdma[1];
	claim_ok();
	release_ok();
}

static void test_covered_open_fault(void)
{
	for (unsigned int scope = 0; scope < 2; ++scope) {
		for (enum failure_kind kind = DROP_WRITE; kind <= BAD_READBACK; ++kind) {
			covered_reset("failed open retains owner and closes CPU before scope");
			claim_ok();
			CHECK(airoha_bank1_routes_ingress_ready(&eth, &owner_token) == 0);
			trace_reset();
			inject(kind, scope ? REG_FE_IFC_PORT_EN : REG_GDM_FWD_CFG(2), 0);
			CHECK(airoha_bank1_routes_open(&eth, &owner_token) == -EIO);
			CHECK(!host.failures);
			covered_closed();
			CHECK(!eth.ct_bank1_routes.ready && eth.ct_bank1_routes.revoked);
			claim_ok();
			release_ok();
		}
	}
}

static void covered_close_fault(bool revoke, enum failure_kind kind)
{
	u16 desired;
	int result;

	covered_reset(revoke ? "revoke CPU readback failure must retain scope" :
		      "claim CPU readback failure must retain scope");
	covered_open();
	desired = eth.ct_bank1_routes.desired[1];
	trace_reset();
	inject(kind, REG_GDM_FWD_CFG(2), 0);
	result = revoke ? airoha_bank1_routes_revoke(&eth, &owner_token) :
		airoha_bank1_routes_claim(&eth, &owner_token);
	covered_fault_state();
	CHECK(result == -EIO && !host.failures);
	CHECK(eth.ct_bank1_routes.owner == &owner_token);
	CHECK(eth.ct_bank1_routes.desired[1] == desired && !eth.ct_bank1_routes.ready);
	CHECK(eth.regs[REG_FE_CSR_IFC_CFG] & FE_IFC_EN_MASK);
	CHECK(eth.regs[REG_FE_IFC_PORT_EN] & BIT(2));
	CHECK(eth.ct_ifc_port_mask & BIT(2));
	CHECK(host.writes[REG_FE_IFC_PORT_EN] == 0);
	if (kind == DROP_WRITE)
		CHECK((eth.regs[1] & 0xffff) == 0x8888);
	trace_reset();
	claim_ok();
	covered_order(false);
	covered_closed();
	release_ok();
}

static void covered_fallback_fault(enum failure_kind kind)
{
	u16 desired;

	covered_reset("repeated fallback CPU readback failure must retain global IFC and scope");
	covered_open();
	desired = eth.ct_bank1_routes.desired[1];
	trace_reset();
	inject(kind, REG_GDM_FWD_CFG(2), 0);
	inject(kind, REG_GDM_FWD_CFG(2), 1);
	int result = airoha_ct_cpu_fallback(&eth);

	covered_fault_state();
	CHECK(result == -EIO && !host.failures);
	CHECK(eth.ct_bank1_routes.owner == &owner_token);
	CHECK(eth.ct_bank1_routes.desired[1] == desired && !eth.ct_bank1_routes.ready);
	CHECK(!eth.ct_cpu_routes_ready);
	CHECK(eth.regs[REG_FE_CSR_IFC_CFG] & FE_IFC_EN_MASK);
	CHECK(eth.regs[REG_FE_IFC_PORT_EN] & BIT(2));
	CHECK(!eth.ct_cpu_ifc_disabled);
	CHECK(host.writes[REG_FE_IFC_PORT_EN] == 0);
	if (kind == DROP_WRITE)
		CHECK((eth.regs[1] & 0xffff) == 0x8888);
	trace_reset();
	CHECK(airoha_ct_cpu_fallback(&eth) == 0);
	covered_closed();
	CHECK(eth.ct_cpu_routes_ready && eth.ct_cpu_ifc_disabled);
	release_ok();
}

static void test_covered_recovery(void)
{
	for (unsigned int operation = 0; operation < 3; ++operation) {
		for (enum failure_kind kind = DROP_WRITE; kind <= BAD_READBACK; ++kind) {
			u16 desired;
			int result;

			covered_reset("failed claim/revoke/fallback retains owner for retry and release");
			covered_open();
			desired = eth.ct_bank1_routes.desired[1];
			trace_reset();
			inject(kind, REG_GDM_FWD_CFG(2), 0);
			if (operation == 2)
				inject(kind, REG_GDM_FWD_CFG(2), 1);
			result = operation == 2 ? airoha_ct_cpu_fallback(&eth) :
				operation == 1 ? airoha_bank1_routes_revoke(&eth, &owner_token) :
				airoha_bank1_routes_claim(&eth, &owner_token);
			CHECK(result == -EIO && !host.failures);
			CHECK(eth.ct_bank1_routes.owner == &owner_token);
			CHECK(eth.ct_bank1_routes.desired[1] == desired && !eth.ct_bank1_routes.ready);
			trace_reset();
			if (operation == 2) {
				CHECK(airoha_ct_cpu_fallback(&eth) == 0);
				CHECK(eth.ct_cpu_routes_ready && eth.ct_cpu_ifc_disabled);
				CHECK(!(eth.regs[REG_FE_CSR_IFC_CFG] & FE_IFC_EN_MASK));
			} else {
				claim_ok();
				covered_order(false);
			}
			covered_closed();
			release_ok();
		}
	}
}

static void test_covered_claim_drop(void) { covered_close_fault(false, DROP_WRITE); }
static void test_covered_claim_readback(void) { covered_close_fault(false, BAD_READBACK); }
static void test_covered_revoke_drop(void) { covered_close_fault(true, DROP_WRITE); }
static void test_covered_revoke_readback(void) { covered_close_fault(true, BAD_READBACK); }
static void test_covered_fallback_drop(void) { covered_fallback_fault(DROP_WRITE); }
static void test_covered_fallback_readback(void) { covered_fallback_fault(BAD_READBACK); }
