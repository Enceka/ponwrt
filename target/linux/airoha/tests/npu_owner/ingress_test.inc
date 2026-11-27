static struct return_fixture *ingress_fixture;
static enum ingress_event ingress_race_event;
static unsigned int ingress_races;

static void ingress_trace_reset(void)
{
    ingress_event_count = 0;
    memset(ingress_calls, 0, sizeof(ingress_calls));
}

static unsigned int ingress_event_position(enum ingress_event event)
{
    for (unsigned int index = 0; index < ingress_event_count; ++index)
        if (ingress_events[index] == event)
            return index;
    CHECK(false);
    return 0;
}

static void check_ingress_empty(struct airoha_npu_owner *owner)
{
    CHECK(!owner->ingress.saved_valid && !owner->ingress.dirty &&
          !owner->ingress.active && !owner->ingress.pending);
}

static void check_ingress_closed(struct return_fixture *fixture)
{
    struct airoha_npu_owner *owner = fixture->ppe.ct_npu_owner;

    CHECK(owner->txn.phase == NPU_TXN_CLOSED && owner->closed_ack);
    CHECK(!owner->return_path && !owner->epoch_dirty && !owner->auth_count);
    CHECK(!er_bound && !gate_open_state && !fixture->dev.netdev.references);
    CHECK(!fixture->eth.ct_bank1_routes.pon_open &&
          !fixture->eth.ct_bank1_routes.ingress_ready && !fixture->eth.ct_ifc_pon_ready);
    CHECK(!(fixture->eth.regs[REG_FE_IFC_PORT_EN] & BIT(2)));
    check_ingress_empty(owner);
}

static void check_ingress_order(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner = setup_reopen(&fixture);
    unsigned int prepares, restores;
    u32 epoch = owner->txn.id.epoch;

    ingress_trace_reset();
    CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == 0);
    CHECK(owner->ingress.saved_valid && owner->ingress.active == 3 && owner->ingress.dirty == 3);
    CHECK(ingress_calls[INGRESS_PREPARE] == 1 && ingress_calls[INGRESS_CHECK] == 1);
    CHECK(ingress_event_position(INGRESS_PREPARE) < ingress_event_position(INGRESS_CHECK));
    CHECK(ingress_event_position(INGRESS_CHECK) < ingress_event_position(INGRESS_READY));
    CHECK(ingress_event_position(INGRESS_READY) < ingress_event_position(INGRESS_ROUTES_OPEN));
    CHECK(ingress_events[ingress_event_position(INGRESS_CHECK) - 1] == INGRESS_GATE_OPEN);
    CHECK(fixture.eth.ct_ifc_port_mask & BIT(2));
    prepares = ingress_calls[INGRESS_PREPARE];
    CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == 0);
    CHECK(ingress_calls[INGRESS_PREPARE] == prepares && owner->txn.id.epoch == epoch);
    ingress_trace_reset();
    CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
    check_ingress_closed(&fixture);
    CHECK(owner->txn.id.epoch == epoch + 1);
    CHECK(ingress_event_position(INGRESS_ROUTES_CLAIM) < ingress_event_position(INGRESS_RESTORE));
    CHECK(ingress_event_position(INGRESS_RESTORE) < ingress_event_position(INGRESS_GATE_CLOSE));
    CHECK(ingress_event_position(INGRESS_GATE_CLOSE) < ingress_event_position(INGRESS_ER_STOP));
    CHECK(ingress_event_position(INGRESS_ER_STOP) < ingress_event_position(INGRESS_ER_UNBIND));
    restores = ingress_calls[INGRESS_RESTORE];
    CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
    CHECK(ingress_calls[INGRESS_RESTORE] == restores && owner->txn.id.epoch == epoch + 1);
    release_return(&fixture);
}

static void check_ingress_failures(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;
    u32 epoch;

    for (unsigned int scenario = 0; scenario < 7; ++scenario) {
        owner = setup_reopen(&fixture);
        epoch = owner->txn.id.epoch;
        ingress_trace_reset();
        if (scenario < 4) {
            ingress_prepare_error = -EUCLEAN;
            ingress_prepare_partial = scenario;
        } else if (scenario == 4)
            ingress_check_error = -EUCLEAN;
        else if (scenario == 5)
            ingress_ready_error = -EUCLEAN;
        else
            ingress_routes_check_error = -EUCLEAN;
        CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == -EUCLEAN);
        CHECK(owner->txn.id.epoch == epoch + 1 && owner->txn.last_error == -EUCLEAN);
        CHECK(!ingress_calls[INGRESS_ROUTES_OPEN]);
        CHECK(ingress_calls[INGRESS_PREPARE] == 1 && ingress_calls[INGRESS_RESTORE] == 1);
        check_ingress_closed(&fixture);
        ingress_prepare_error = ingress_check_error = ingress_ready_error = 0;
        ingress_routes_check_error = 0;
        release_return(&fixture);
    }

    for (unsigned int scenario = 0; scenario < 4; ++scenario) {
        owner = setup_reopen(&fixture);
        epoch = owner->txn.id.epoch;
        ingress_prepare_error = -EUCLEAN;
        ingress_prepare_partial = scenario;
        ingress_restore_error = -ETIMEDOUT;
        CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == -ETIMEDOUT);
        CHECK(owner->txn.phase == NPU_TXN_ROUTES_CLOSE && owner->txn.id.epoch == epoch);
        CHECK(owner->txn.renew_epoch);
        CHECK(owner->return_path && er_bound && !owner->closed_ack);
        CHECK(owner->ingress.pending && owner->ingress.saved_valid == (scenario != 0));
        CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == -EBUSY);
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == -ETIMEDOUT);
        CHECK(owner->txn.id.epoch == epoch && owner->return_path && er_bound);
        ingress_prepare_error = ingress_restore_error = 0;
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
        check_ingress_closed(&fixture);
        CHECK(owner->txn.id.epoch == epoch + 1);
        release_return(&fixture);
    }
}

static void check_ingress_restore_retry(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;
    struct airoha_ct_pon_ifc_words saved[AIROHA_CT_PON_IFC_ROW_COUNT];
    unsigned int restores;
    u32 epoch;

    for (unsigned int scenario = 0; scenario < 3; ++scenario) {
        owner = setup_health(&fixture);
        epoch = owner->txn.id.epoch;
        memcpy(saved, owner->ingress.saved, sizeof(saved));
        ingress_trace_reset();
        if (scenario == 0)
            fail_route = true;
        else if (scenario == 1)
            ingress_claim_scope_stuck = true;
        else
            ingress_restore_error = -EIO;
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == -EIO);
        CHECK(owner->txn.phase == NPU_TXN_ROUTES_CLOSE && owner->return_path && er_bound);
        CHECK(owner->ingress.saved_valid && owner->ingress.dirty == 3);
        CHECK(!memcmp(saved, owner->ingress.saved, sizeof(saved)));
        CHECK(!ingress_calls[INGRESS_GATE_CLOSE] && !ingress_calls[INGRESS_ER_STOP]);
        CHECK(ingress_calls[INGRESS_RESTORE] == (scenario == 2 ? 1u : 0u));
        restores = ingress_calls[INGRESS_RESTORE];
        CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == -EBUSY);
        CHECK(ingress_calls[INGRESS_RESTORE] == restores);
        fail_route = ingress_claim_scope_stuck = false;
        ingress_restore_error = 0;
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
        CHECK(owner->txn.id.epoch == epoch + 1);
        check_ingress_closed(&fixture);
        release_return(&fixture);
    }
}

static void ingress_invalidate_event(enum ingress_event event)
{
    if (event != ingress_race_event || !ingress_calls[INGRESS_PREPARE])
        return;
    ingress_event_hook = NULL;
    ingress_races++;
    CHECK(!ppe_lock);
    CHECK(health_invalidate(ingress_fixture) == 0);
}

static void ingress_invalidate_before_open(int *lock)
{
    if (lock != &ppe_lock || !ingress_calls[INGRESS_CHECK])
        return;
    before_spin_lock_hook = NULL;
    ingress_races++;
    CHECK(health_invalidate(ingress_fixture) == 0);
}

static void check_ingress_races(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;

    for (unsigned int scenario = 0; scenario < 3; ++scenario) {
        owner = setup_reopen(&fixture);
        ingress_fixture = &fixture;
        ingress_races = 0;
        ingress_trace_reset();
        if (scenario < 2) {
            ingress_race_event = scenario ? INGRESS_CHECK : INGRESS_PREPARE;
            ingress_event_hook = ingress_invalidate_event;
        } else
            before_spin_lock_hook = ingress_invalidate_before_open;
        CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == -ESTALE);
        CHECK(ingress_races == 1 && owner->invalidated);
        CHECK(!ingress_calls[INGRESS_READY] && !ingress_calls[INGRESS_ROUTES_OPEN]);
        check_ingress_closed(&fixture);
        release_return(&fixture);
    }
}

static void check_ingress_health(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner = setup_health(&fixture);
    unsigned int opens = gate_calls[GATE_OPEN];

    ingress_trace_reset();
    health_tick(owner);
    CHECK(ingress_calls[INGRESS_CHECK] == 1 && ingress_calls[INGRESS_ROUTES_CHECK] == 1);
    CHECK(ingress_event_position(INGRESS_CHECK) < ingress_event_position(INGRESS_GATE_QUERY));
    CHECK(ingress_event_position(INGRESS_ROUTES_CHECK) < ingress_event_position(INGRESS_GATE_QUERY));
    CHECK(!ingress_calls[INGRESS_PREPARE] && !ingress_calls[INGRESS_RESTORE]);
    CHECK(gate_calls[GATE_OPEN] == opens && owner->txn.phase == NPU_TXN_OPEN);
    release_return(&fixture);
    for (unsigned int scenario = 0; scenario < 7; ++scenario) {
        owner = setup_health(&fixture);
        ingress_trace_reset();
        switch (scenario) {
        case 0: ingress_check_error = -EUCLEAN; break;
        case 1: ingress_check_error = -ETIMEDOUT; break;
        case 2: ingress_routes_check_error = -EXDEV; break;
        case 3: fixture.eth.regs[REG_FE_IFC_PORT_EN] &= ~BIT(2); break;
        case 4: fixture.eth.ct_ifc_port_mask &= ~BIT(2); break;
        case 5: fixture.eth.ct_ifc_pon_ready = false; break;
        case 6: fixture.eth.ct_bank1_routes.ingress_ready = false; break;
        }
        health_tick(owner);
        CHECK(!ingress_calls[INGRESS_GATE_QUERY] && !ingress_calls[INGRESS_ROUTES_OPEN]);
        check_health_closed(&fixture);
        check_ingress_closed(&fixture);
        ingress_check_error = ingress_routes_check_error = 0;
        release_return(&fixture);
    }
    owner = setup_health(&fixture);
    ingress_check_error = -EUCLEAN;
    ingress_restore_error = -EIO;
    health_tick(owner);
    CHECK(owner->invalidated && owner->close_pending && !owner->closed_ack);
    CHECK(owner->return_path && owner->ingress.saved_valid && owner->ingress.dirty == 3);
    CHECK(owner->txn.phase == NPU_TXN_ROUTES_CLOSE && owner->txn.last_error == -EIO);
    ingress_restore_error = ingress_check_error = 0;
    health_tick(owner);
    check_health_closed(&fixture);
    check_ingress_closed(&fixture);
    release_return(&fixture);
}

static void check_ingress_claim_retire(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;

    for (unsigned int state = 0; state < 7; ++state) {
        setup(&fixture.eth, &fixture.ppe, &fixture.soc, &fixture.npu);
        switch (state) {
        case 0: fixture.ppe.ct_pon_ifc.saved_valid = true; break;
        case 1: fixture.ppe.ct_pon_ifc.dirty = 1; break;
        case 2: fixture.ppe.ct_pon_ifc.active = 1; break;
        case 3: fixture.ppe.ct_pon_ifc.pending = true; break;
        case 4: fixture.ppe.ct_pon_ifc_route_owned = true; break;
        case 5: fixture.ppe.ct_pon_ifc_tuple = true; break;
        case 6: ingress_probe_busy = true; break;
        }
        CHECK(airoha_ppe_npu_owner_claim_locked(&fixture.eth, 4) == -EBUSY);
        CHECK(!fixture.ppe.ct_npu_owner && !fixture.ppe.ct_fe.owner && allocated == freed);
        CHECK(!ingress_calls[INGRESS_PREPARE] && !ingress_calls[INGRESS_RESTORE]);
    }
    for (unsigned int state = 0; state < 4; ++state) {
        setup_return(&fixture);
        owner = fixture.ppe.ct_npu_owner;
        ingress_trace_reset();
        switch (state) {
        case 0: owner->ingress.saved_valid = true; break;
        case 1: owner->ingress.dirty = 1; break;
        case 2: owner->ingress.active = 1; break;
        case 3: owner->ingress.pending = true; break;
        }
        CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == -EBUSY);
        CHECK(fixture.ppe.ct_npu_owner == owner && owner->health_work.pending);
        CHECK(!ingress_calls[INGRESS_ROUTES_RELEASE]);
        memset(&owner->ingress, 0, sizeof(owner->ingress));
        release_return(&fixture);
    }
}

static void check_ingress_legacy_probes(void)
{
    static const char *commands[] = {
        "off", "route", "cover 0", "source 2", "absent 2", "only 2",
        "set 0 4097", "tuple 0 4097", "clear 0",
    };
    struct return_fixture fixture;
    struct device dev = { .eth = &fixture.eth };

    for (unsigned int state = 0; state < 2; ++state) {
        if (state)
            setup_health(&fixture);
        else
            setup_return(&fixture);
        fixture.ppe.ct_pon_ifc_registered = true;
        ingress_trace_reset();
        for (unsigned int index = 0; index < ARRAY_SIZE(commands); ++index) {
            flow_offload_mutex = 0;
            CHECK(ct_pon_cpu_probe_store(&dev, NULL, commands[index], strlen(commands[index])) == -EBUSY);
            CHECK(!flow_offload_mutex && !ingress_rtnl_locked);
            flow_offload_mutex = 1;
            CHECK(!ingress_probe_operations && !ingress_event_count);
        }
        release_return(&fixture);
    }
}

static void check_ingress(void)
{
    check_ingress_order();
    check_ingress_failures();
    check_ingress_restore_retry();
    check_ingress_races();
    check_ingress_health();
    check_ingress_claim_retire();
    check_ingress_legacy_probes();
}
