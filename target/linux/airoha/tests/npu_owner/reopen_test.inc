static struct airoha_npu_owner *setup_reopen(struct return_fixture *fixture)
{
    struct airoha_npu_owner *owner;
    struct airoha_npu_auth_rule rule;

    setup_return(fixture);
    owner = fixture->ppe.ct_npu_owner;
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture->eth, &fixture->dev, 8) == 0);
    rule = admission_rule(owner);
    CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture->eth, &rule, 1) == 0);
    fixture->ppe.ct_pon_qualified = true;
    return owner;
}

static void check_reopen(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;
    u32 epoch, bank0[3];
    unsigned int calls;
    static const enum airoha_npu_txn_phase stages[] = {
        NPU_TXN_PPE_RESTORE, NPU_TXN_PPE_RESTORE, NPU_TXN_FE_ARM,
        NPU_TXN_GATE_OPEN, NPU_TXN_ROUTES_OPEN,
    };

    owner = setup_reopen(&fixture);
    epoch = owner->txn.id.epoch;
    memcpy(bank0, fixture.eth.regs, sizeof(bank0));
    CHECK(airoha_ppe_npu_owner_open_locked(NULL) == -EINVAL);
    CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == 0);
    CHECK(owner->txn.phase == NPU_TXN_OPEN && owner->txn.id.epoch == epoch);
    CHECK(fixture.eth.ct_bank1_routes.owner == owner && fixture.eth.ct_bank1_routes.pon_open);
    CHECK(fixture.ppe.ct_fe.armed && !fixture.ppe.ct_fe.owner_quiesced);
    CHECK(owner->bank1_saved && owner->return_path && owner->epoch_dirty);
    CHECK(fixture.eth.regs[3] == owner->bank1_flow && fixture.eth.regs[4] == owner->bank1_tb);
    CHECK(memcmp(bank0, fixture.eth.regs, sizeof(bank0)) == 0);
    CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == 0);
    release_return(&fixture);

    for (unsigned int stage = 0; stage < ARRAY_SIZE(stages); ++stage) {
        owner = setup_reopen(&fixture);
        epoch = owner->txn.id.epoch;
        memcpy(bank0, fixture.eth.regs, sizeof(bank0));
        if (stage < 2)
            fail_write = stage ? 3 : 4;
        else if (stage == 2)
            fail_arm = true;
        else if (stage == 3)
            fail_gate = GATE_OPEN;
        else
            fail_route = true;
        CHECK(airoha_npu_txn_open(&owner->txn, &airoha_npu_owner_ops, owner) < 0);
        CHECK(owner->txn.phase == stages[stage]);
        CHECK(owner->return_path && owner->txn.id.epoch == epoch && owner->bank1_saved);
        CHECK(!fixture.eth.ct_bank1_routes.pon_open);
        CHECK(memcmp(bank0, fixture.eth.regs, sizeof(bank0)) == 0);
        fail_write = fail_gate = -1;
        fail_arm = fail_route = false;
        calls = gate_calls[GATE_OPEN];
        bridge_generation++;
        CHECK(airoha_npu_txn_open(&owner->txn, &airoha_npu_owner_ops, owner) == -ESTALE);
        CHECK(gate_calls[GATE_OPEN] == calls && !fixture.eth.ct_bank1_routes.pon_open);
        bridge_generation--;
        if (stage == 4) {
            CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == -ESTALE);
            CHECK(owner->txn.phase == NPU_TXN_CLOSED && !owner->return_path);
        } else {
            CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == 0);
            CHECK(owner->txn.phase == NPU_TXN_OPEN && fixture.eth.ct_bank1_routes.pon_open);
        }
        release_return(&fixture);
    }

    for (unsigned int scenario = 0; scenario < 8; ++scenario) {
        owner = setup_reopen(&fixture);
        epoch = owner->txn.id.epoch;
        switch (scenario) {
        case 0: fixture.ppe.ct_pon_qualified = false; break;
        case 1: arm_change_generation = true; break;
        case 2: gate_change_generation = true; break;
        case 3: route_change_generation = true; break;
        case 4: fixture.eth.ct_bank1_routes.revoked = true; break;
        case 5: fixture.dev.pon_update_blocked = true; break;
        case 6: fail_arm = true; break;
        case 7: fail_gate = GATE_OPEN; break;
        }
        CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) < 0);
        CHECK(owner->txn.phase == NPU_TXN_CLOSED && owner->txn.id.epoch == epoch + 1);
        CHECK(!fixture.eth.ct_bank1_routes.pon_open && !owner->return_path);
        CHECK(!owner->auth_count && !owner->auth_attempted && !owner->epoch_dirty);
        CHECK(!fixture.ppe.ct_fe.armed && !fixture.ppe.ct_fe.arm_pending);
        arm_change_generation = gate_change_generation = route_change_generation = false;
        fail_arm = false;
        fail_gate = -1;
        release_return(&fixture);
    }

    for (unsigned int boundary = 0; boundary < 3; ++boundary) {
        owner = setup_reopen(&fixture);
        if (boundary == 0)
            arm_change_generation = true;
        else if (boundary == 1)
            gate_change_generation = true;
        else
            route_change_generation = true;
        CHECK(airoha_npu_txn_open(&owner->txn, &airoha_npu_owner_ops, owner) == -ESTALE);
        CHECK(owner->txn.phase == (boundary == 0 ? NPU_TXN_FE_ARM :
              boundary == 1 ? NPU_TXN_GATE_OPEN : NPU_TXN_ROUTES_OPEN));
        CHECK(!fixture.eth.ct_bank1_routes.pon_open);
        arm_change_generation = gate_change_generation = route_change_generation = false;
        release_return(&fixture);
    }

    owner = setup_reopen(&fixture);
    fail_gate = GATE_OPEN;
    er_failure = ER_STOP;
    epoch = owner->txn.id.epoch;
    CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == -ETIMEDOUT);
    CHECK(owner->txn.phase == NPU_TXN_CLOSED && owner->txn.id.epoch == epoch + 1);
    CHECK(owner->return_path && !owner->return_path->bound && !owner->auth_count);
    CHECK(!fixture.eth.ct_bank1_routes.pon_open && er_bound);
    er_failure = fail_gate = -1;
    release_return(&fixture);

    for (unsigned int scenario = 0; scenario < 3; ++scenario) {
        owner = setup_reopen(&fixture);
        if (scenario == 0)
            fixture.eth.regs[5] = PPE_GLO_CFG_EN_MASK | PPE_GLO_CFG_BUSY_MASK;
        else if (scenario == 1)
            fixture.eth.regs[5] = 0;
        else
            owner->bank1_flow = 0;
        CHECK(airoha_npu_owner_bank1_restore(owner, &owner->txn.id) < 0);
        CHECK(!fixture.eth.regs[3] && !fixture.ppe.ct_fe.armed);
        fixture.eth.regs[5] = PPE_GLO_CFG_EN_MASK;
        owner->bank1_flow = 0xabcd;
        release_return(&fixture);
    }
}
