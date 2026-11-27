static struct return_fixture *health_fixture;
static int health_gate_word, health_auth_word, health_gate_operation;
static u32 health_reply_value;
static unsigned int health_lock_countdown, health_races, health_owner_frees;

static struct airoha_npu_owner *setup_health(struct return_fixture *fixture)
{
    struct airoha_npu_owner *owner = setup_reopen(fixture);

    health_fixture = fixture;
    health_gate_word = health_auth_word = -1;
    health_races = health_owner_frees = 0;
    CHECK(owner->health_work.pending && owner->health_work.delay == 100);
    CHECK(airoha_ppe_npu_owner_open_locked(&fixture->eth) == 0);
    CHECK(!owner->invalidated && !owner->close_pending && !owner->closed_ack);
    return owner;
}

static void health_tick(struct airoha_npu_owner *owner)
{
    CHECK(flow_offload_mutex && !ppe_lock);
    flow_offload_mutex = 0;
    test_run_delayed_work(&owner->health_work);
    CHECK(!flow_offload_mutex && !ppe_lock);
    flow_offload_mutex = 1;
    CHECK(owner->health_work.pending && owner->health_work.delay == 100);
}

static int health_invalidate(struct return_fixture *fixture)
{
    int error;

    CHECK(!ppe_lock);
    spin_lock_bh(&ppe_lock);
    error = airoha_npu_owner_invalidate(&fixture->ppe);
    spin_unlock_bh(&ppe_lock);
    return error;
}

static void check_health_closed(struct return_fixture *fixture)
{
    struct airoha_npu_owner *owner = fixture->ppe.ct_npu_owner;

    CHECK(owner && owner->invalidated && !owner->close_pending && owner->closed_ack);
    CHECK(owner->txn.phase == NPU_TXN_CLOSED && !owner->return_path);
    CHECK(!owner->epoch_dirty && !owner->auth_count && !owner->auth_attempted);
    CHECK(!fixture->dev.netdev.references && !er_bound && !gate_open_state);
    CHECK(!fixture->eth.ct_bank1_routes.pon_open && fixture->eth.ct_bank1_routes.revoked);
    CHECK(!fixture->eth.ct_bank1_routes.ready && fixture->eth.ct_bank1_routes.owner == owner);
    CHECK(!fixture->ppe.ct_fe.armed && !fixture->ppe.ct_fe.arm_pending);
    CHECK(owner->health_work.pending && owner->health_work.delay == 100);
}

static void health_corrupt_gate(struct npu_gate_message *message)
{
    if (message->w[GM_ABI_OP] >> 16 == GATE_QUERY)
        message->w[health_gate_word] = health_reply_value;
}

static void health_corrupt_auth(struct npu_auth_message *message)
{
    if (message->w[AM_ABI_OP] >> 16 == AUTH_MBOX_QUERY)
        message->w[health_auth_word] = health_reply_value;
}

static void health_invalidate_gate(struct npu_gate_message *message)
{
    if (message->w[GM_ABI_OP] >> 16 != (u32)health_gate_operation)
        return;
    gate_reply_hook = NULL;
    health_races++;
    if (ppe_lock)
        CHECK(airoha_npu_owner_invalidate(&health_fixture->ppe) == 0);
    else
        CHECK(health_invalidate(health_fixture) == 0);
}

static void health_invalidate_auth(struct npu_auth_message *message)
{
    if (message->w[AM_ABI_OP] >> 16 != AUTH_MBOX_QUERY)
        return;
    auth_reply_hook = NULL;
    health_races++;
    CHECK(health_invalidate(health_fixture) == 0);
}

static void health_invalidate_er(struct er_message *message)
{
    if (message->w[1] >> 16 != ER_BIND)
        return;
    er_reply_hook = NULL;
    health_races++;
    CHECK(health_invalidate(health_fixture) == 0);
}

static void health_invalidate_er_query(struct er_message *message)
{
    if (message->w[1] >> 16 != ER_QUERY)
        return;
    er_reply_hook = NULL;
    health_races++;
    CHECK(health_invalidate(health_fixture) == 0);
}

static void health_withdraw_policy(struct npu_auth_message *message)
{
    if (message->w[AM_ABI_OP] >> 16 != AUTH_MBOX_QUERY)
        return;
    auth_reply_hook = NULL;
    if (health_reply_value)
        health_fixture->ppe.ct_pon_qualified = false;
    else
        health_fixture->ppe.ct_pair_wired_registered = false;
}

static void health_invalidate_claim(struct airoha_eth *eth)
{
    route_claim_hook = NULL;
    health_races++;
    CHECK(eth == &health_fixture->eth);
    CHECK(health_invalidate(health_fixture) == 0);
}

static void health_invalidate_lock(int *lock)
{
    if (lock != &ppe_lock || --health_lock_countdown)
        return;
    before_spin_lock_hook = NULL;
    health_races++;
    CHECK(health_invalidate(health_fixture) == 0);
}

static void health_fail_next_close(struct npu_gate_message *message)
{
    if (message->w[GM_ABI_OP] >> 16 != GATE_CLOSE)
        return;
    gate_reply_hook = NULL;
    fail_gate = GATE_CLOSE;
}

static void check_health_queries(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner = setup_health(&fixture);
    unsigned int gates[4], auth[8], arms = fe_arm_calls;
    u32 bank0[3];

    memcpy(bank0, fixture.eth.regs, sizeof(bank0));
    memcpy(gates, gate_calls, sizeof(gates));
    memcpy(auth, auth_calls, sizeof(auth));
    test_run_delayed_work(&owner->health_work);
    CHECK(flow_offload_mutex && owner->health_work.pending && owner->health_work.delay == 100);
    CHECK(!memcmp(gates, gate_calls, sizeof(gates)) && !memcmp(auth, auth_calls, sizeof(auth)));
    for (unsigned int tick = 0; tick < 5; ++tick) {
        health_tick(owner);
        CHECK(owner->txn.phase == NPU_TXN_OPEN && !owner->invalidated);
        CHECK(fixture.eth.ct_bank1_routes.pon_open && owner->return_path && er_bound);
    }
    CHECK(gate_calls[GATE_QUERY] == gates[GATE_QUERY] + 5);
    CHECK(auth_calls[AUTH_MBOX_QUERY] == auth[AUTH_MBOX_QUERY] + 5);
    CHECK(gate_calls[GATE_OPEN] == gates[GATE_OPEN] && gate_calls[GATE_CLOSE] == gates[GATE_CLOSE]);
    CHECK(fe_arm_calls == arms && !memcmp(bank0, fixture.eth.regs, sizeof(bank0)));
    CHECK(!route_revokes && !owner->invalidation_seq);
    release_return(&fixture);

    setup_return(&fixture);
    owner = fixture.ppe.ct_npu_owner;
    memcpy(gates, gate_calls, sizeof(gates));
    health_tick(owner);
    CHECK(owner->txn.phase == NPU_TXN_CLOSED && owner->closed_ack && !owner->invalidated);
    CHECK(!memcmp(gates, gate_calls, sizeof(gates)));
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
    health_tick(owner);
    CHECK(owner->return_path && !owner->invalidated && !owner->closed_ack);
    CHECK(!memcmp(gates, gate_calls, sizeof(gates)));
    release_return(&fixture);

    owner = setup_reopen(&fixture);
    fixture.ppe.ct_pair_wired_registered = false;
    CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == -EOPNOTSUPP);
    CHECK(owner->txn.phase == NPU_TXN_CLOSED && !owner->return_path);
    CHECK(!fe_arm_calls && !gate_calls[GATE_OPEN]);
    release_return(&fixture);
}

static void check_health_firmware_faults(void)
{
    static const struct { int word; u32 value; } gate_faults[] = {
        { GM_STATE_EPOCH, 0 }, { GM_STATE_GENERATION, 0 }, { GM_MASK, GATE_FE24 },
        { GM_CLOSED, 1 }, { GM_QUIET_ACK, 1 }, { GM_FAULT, 1 },
        { GM_FE_ENABLED, 0 }, { GM_FE_QUIESCED, 1 }, { GM_ER_STATE, ER_FAULT },
        { GM_ER_FLAGS, 0 }, { GM_AUTH_EPOCH, 0 }, { GM_AUTH_GENERATION, 0 },
        { GM_AUTH_ENABLED, 0 },
    };
    static const struct { int word; u32 value; } auth_faults[] = {
        { AM_STATE_EPOCH, 0 }, { AM_STATE_GENERATION, 0 },
        { AM_COUNT, 0 }, { AM_ENABLED, 0 },
    };
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;

    for (unsigned int index = 0; index < ARRAY_SIZE(gate_faults); ++index) {
        owner = setup_health(&fixture);
        health_gate_word = gate_faults[index].word;
        health_reply_value = gate_faults[index].value;
        gate_reply_hook = health_corrupt_gate;
        CHECK(airoha_npu_owner_health_check(owner) == -ESTALE);
        health_tick(owner);
        check_health_closed(&fixture);
        CHECK(owner->invalidation_seq == 1);
        gate_reply_hook = NULL;
        release_return(&fixture);
    }
    for (unsigned int index = 0; index < ARRAY_SIZE(auth_faults); ++index) {
        owner = setup_health(&fixture);
        health_auth_word = auth_faults[index].word;
        health_reply_value = auth_faults[index].value;
        auth_reply_hook = health_corrupt_auth;
        CHECK(airoha_npu_owner_health_check(owner) == -ESTALE);
        auth_reply_hook = NULL;
        health_tick(owner);
        CHECK(!owner->invalidated);
        auth_reply_hook = health_corrupt_auth;
        health_tick(owner);
        auth_reply_hook = NULL;
        if (owner->close_pending)
            health_tick(owner);
        check_health_closed(&fixture);
        release_return(&fixture);
    }
    for (unsigned int operation = 0; operation < 2; ++operation) {
        owner = setup_health(&fixture);
        if (operation)
            fail_auth = AUTH_MBOX_QUERY;
        else
            fail_gate = GATE_QUERY;
        CHECK(airoha_npu_owner_health_check(owner) == -ETIMEDOUT);
        health_tick(owner);
        CHECK(owner->invalidated && !fixture.eth.ct_bank1_routes.pon_open);
        fail_gate = fail_auth = -1;
        if (owner->close_pending)
            health_tick(owner);
        check_health_closed(&fixture);
        release_return(&fixture);
    }
}

static void check_health_mapping_faults(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;
    struct airoha_pon_flow_table replacement;

    for (unsigned int state = 0; state < 21; ++state) {
        owner = setup_health(&fixture);
        replacement = fixture.table;
        switch (state) {
        case 0: bridge_generation++; break;
        case 1: fixture.dev.pon_flow_table = &replacement; break;
        case 2: fixture.dev.pon_update_blocked = true; break;
        case 3: fixture.dev.qdma = &fixture.eth.qdma[0]; break;
        case 4: fixture.dev.flags = 0; break;
        case 5: fixture.dev.pon_qdma_tag = AIROHA_PON_QDMA_VALID; break;
        case 6: fixture.dev.netdev.running = false; break;
        case 7: fixture.dev.netdev.carrier = false; break;
        case 8: fixture.eth.ct_cpu_fallback = true; break;
        case 9: fixture.ppe.ct_pair_failed = true; break;
        case 10: fixture.ppe.ct_fe.health_stopping = true; break;
        case 11: fixture.eth.ct_ifc_cpu_port_failed = true; break;
        case 12: fixture.eth.ct_bank1_routes.revoked = true; break;
        case 13: fixture.eth.ct_bank1_routes.pon_open = false; break;
        case 14: fixture.eth.ct_bank1_routes.ready = false; break;
        case 15: fixture.ppe.ct_fe.epoch++; break;
        case 16: fixture.ppe.ct_fe.generation += (u64)U32_MAX + 1; break;
        case 17: owner->return_path->fault = 1; break;
        case 18: fixture.ppe.ct_fe.armed = false; break;
        case 19: fixture.ppe.ct_pair_wired_registered = false; break;
        case 20: fixture.ppe.ct_pon_qualified = false; break;
        }
        CHECK(airoha_npu_owner_health_check(owner) < 0);
        health_tick(owner);
        check_health_closed(&fixture);
        CHECK(fixture.eth.regs[0] == 0x1234 && fixture.eth.regs[1] == 0x9876);
        release_return(&fixture);
    }
}

static void check_health_close_retries(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;
    struct airoha_npu_return *path;
    unsigned int gates[4], auth[8], revokes_before;
    u32 epoch;

    for (unsigned int stage = 0; stage < 12; ++stage) {
        owner = setup_health(&fixture);
        path = owner->return_path;
        epoch = owner->txn.id.epoch;
        flow_offload_mutex = 0;
        CHECK(health_invalidate(&fixture) == 0);
        CHECK(!gate_open_state && owner->txn.phase == NPU_TXN_OPEN);
        CHECK(owner->return_path == path && er_bound && owner->txn.id.epoch == epoch);
        flow_offload_mutex = 1;
        switch (stage) {
        case 0: fail_route = true; break;
        case 1: fail_gate = GATE_CLOSE; break;
        case 2: fail_auth = AUTH_MBOX_QUERY; break;
        case 3: fail_auth = AUTH_MBOX_DISARM; break;
        case 4: fail_fe = true; break;
        case 5: fail_gate = GATE_QUIET; break;
        case 6: fail_write = REG_PPE_PPE_FLOW_CFG(1); break;
        case 7: fail_write = REG_PPE_TB_CFG(1); break;
        case 8: fixture.eth.regs[5] |= PPE_GLO_CFG_BUSY_MASK; break;
        case 9: er_failure = ER_STOP; break;
        case 10: er_failure = ER_UNBIND; break;
        case 11: fail_revoke = -EIO; break;
        }
        for (unsigned int attempt = 0; attempt < 2; ++attempt) {
            health_tick(owner);
            CHECK(owner->invalidated && owner->close_pending && owner->txn.last_error < 0);
            CHECK(owner->invalidation_seq == 1 && owner->txn.id.epoch == epoch + (stage > 1));
            CHECK(!fixture.eth.ct_bank1_routes.pon_open && fixture.eth.ct_bank1_routes.revoked);
            CHECK(!fixture.eth.ct_bank1_routes.ready && fixture.ppe.ct_npu_owner == owner);
            if (stage < 11) {
                CHECK(owner->return_path == path && path->ring && !er_frees);
                CHECK(fixture.dev.netdev.references == 1 && !owner->closed_ack);
                CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == -EBUSY);
            }
        }
        fail_route = fail_fe = false;
        fail_gate = fail_auth = fail_write = er_failure = -1;
        fail_revoke = 0;
        fixture.eth.regs[5] = PPE_GLO_CFG_EN_MASK;
        health_tick(owner);
        check_health_closed(&fixture);
        CHECK(owner->txn.id.epoch == epoch + 1 && owner->invalidation_seq == 1);
        memcpy(gates, gate_calls, sizeof(gates));
        memcpy(auth, auth_calls, sizeof(auth));
        revokes_before = route_revokes;
        health_tick(owner);
        CHECK(!memcmp(gates, gate_calls, sizeof(gates)) && !memcmp(auth, auth_calls, sizeof(auth)));
        CHECK(route_revokes == revokes_before);
        release_return(&fixture);
    }
}

static void check_health_sequence_races(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;

    for (unsigned int boundary = 0; boundary < 2; ++boundary) {
        owner = setup_health(&fixture);
        if (boundary) {
            auth_reply_hook = health_invalidate_auth;
        } else {
            health_gate_operation = GATE_QUERY;
            gate_reply_hook = health_invalidate_gate;
        }
        CHECK(airoha_npu_owner_health_check(owner) == -ESTALE);
        CHECK(health_races == 1 && owner->invalidated && owner->close_pending);
        health_tick(owner);
        check_health_closed(&fixture);
        release_return(&fixture);
    }

    for (unsigned int policy = 0; policy < 2; ++policy) {
        owner = setup_health(&fixture);
        health_reply_value = policy;
        auth_reply_hook = health_withdraw_policy;
        CHECK(airoha_npu_owner_health_check(owner) == -EOPNOTSUPP);
        health_tick(owner);
        check_health_closed(&fixture);
        release_return(&fixture);
    }

    owner = setup_health(&fixture);
    CHECK(health_invalidate(&fixture) == 0);
    health_gate_operation = GATE_CLOSE;
    gate_reply_hook = health_invalidate_gate;
    health_tick(owner);
    CHECK(health_races == 1 && owner->invalidation_seq == 2);
    CHECK(owner->closed_ack && owner->invalidated && owner->close_pending);
    health_tick(owner);
    check_health_closed(&fixture);
    release_return(&fixture);

    for (unsigned int boundary = 0; boundary < 2; ++boundary) {
        owner = setup_health(&fixture);
        CHECK(health_invalidate(&fixture) == 0);
        if (boundary)
            route_claim_hook = health_invalidate_claim;
        else {
            health_gate_operation = GATE_CLOSE;
            gate_reply_hook = health_invalidate_gate;
        }
        CHECK(airoha_ppe_npu_owner_renew_locked(&fixture.eth, 4) == -ESTALE);
        CHECK(health_races == 1 && owner->invalidated && owner->close_pending);
        CHECK(owner->invalidation_seq == 2 && !fixture.eth.ct_bank1_routes.pon_open);
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == -ESTALE);
        CHECK(airoha_ppe_npu_owner_renew_locked(&fixture.eth, 4) == 0);
        CHECK(!owner->invalidated && !owner->close_pending && owner->closed_ack);
        CHECK(fixture.eth.ct_bank1_routes.ready && !fixture.eth.ct_bank1_routes.revoked);
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
        release_return(&fixture);
    }

    owner = setup_health(&fixture);
    owner->invalidation_seq = U64_MAX - 1;
    CHECK(health_invalidate(&fixture) == 0 && owner->invalidation_seq == U64_MAX);
    CHECK(health_invalidate(&fixture) == 0 && owner->invalidation_seq == U64_MAX);
    health_tick(owner);
    CHECK(airoha_ppe_npu_owner_renew_locked(&fixture.eth, 4) == -ESTALE);
    CHECK(owner->invalidated && owner->invalidation_seq == U64_MAX);
    release_return(&fixture);
}

static void check_health_binding(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner = setup_health(&fixture);
    struct airoha_npu_return *path = owner->return_path;
    struct er_config config = path->config;
    struct airoha_npu_auth_rule rule = admission_rule(owner);
    unsigned int closes = gate_calls[GATE_CLOSE];

    for (unsigned int field = 0; field < 6; ++field) {
        u32 *words = (u32 *)&config;
        words[field] ^= 1;
        CHECK(!airoha_npu_return_binding(path, &fixture.dev.netdev, &config, ER_SERVICE_VALID));
        CHECK(!owner->invalidated && !owner->invalidation_seq && gate_open_state);
        words[field] ^= 1;
    }
    CHECK(!airoha_npu_return_binding(path, &fixture.dev.netdev, &config, 0x1001));
    CHECK(!airoha_npu_return_binding(path, &fixture.dev.netdev, &config, ER_SERVICE_VALID | 0x10000));
    CHECK(!airoha_npu_return_binding(path, &fixture.dev.netdev, &config, ER_SERVICE_VALID | 0x1234));
    CHECK(!owner->invalidated && !route_revokes && gate_calls[GATE_CLOSE] == closes);
    fixture.dev.netdev.carrier = false;
    flow_offload_mutex = 0;
    CHECK(!airoha_npu_return_binding(path, &fixture.dev.netdev, &config, ER_SERVICE_VALID));
    CHECK(owner->invalidated && owner->close_pending && owner->invalidation_seq == 1);
    CHECK(!gate_open_state && gate_calls[GATE_CLOSE] == closes + 1);
    CHECK(path == owner->return_path && path->ring && er_bound && fixture.dev.netdev.references == 1);
    flow_offload_mutex = 1;
    fixture.dev.netdev.carrier = true;
    CHECK(!airoha_npu_return_mapping(path, &fixture.dev.netdev));
    CHECK(!airoha_npu_return_binding(path, &fixture.dev.netdev, &config, ER_SERVICE_VALID));
    CHECK(owner->invalidation_seq == 1);
    CHECK(airoha_bank1_routes_claim(&fixture.eth, owner) == 0);
    CHECK(airoha_npu_owner_return_state(owner, &owner->txn.id, NPU_TXN_ROUTES_OPEN) < 0);
    CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture.eth, &rule, 1) < 0);
    health_tick(owner);
    check_health_closed(&fixture);
    CHECK(airoha_ppe_npu_owner_renew_locked(&fixture.eth, 4) == 0);
    CHECK(!owner->invalidated && !owner->close_pending && owner->invalidation_seq == 1);
    CHECK(fixture.eth.ct_bank1_routes.ready && !fixture.eth.ct_bank1_routes.revoked);
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
    rule = admission_rule(owner);
    CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture.eth, &rule, 1) == 0);
    CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == 0);
    CHECK(owner->txn.phase == NPU_TXN_OPEN && gate_open_state && er_bound);
    release_return(&fixture);

    setup_return(&fixture);
    health_fixture = &fixture;
    health_races = 0;
    owner = fixture.ppe.ct_npu_owner;
    er_reply_hook = health_invalidate_er_query;
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == -ESTALE);
    CHECK(health_races == 1 && owner->invalidated && !owner->return_path);
    CHECK(!er_calls[ER_BIND] && !er_bound && owner->closed_ack && !owner->epoch_dirty);
    health_tick(owner);
    check_health_closed(&fixture);
    release_return(&fixture);

    setup_return(&fixture);
    health_fixture = &fixture;
    health_races = 0;
    owner = fixture.ppe.ct_npu_owner;
    er_reply_hook = health_invalidate_er;
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == -ESTALE);
    CHECK(health_races == 1 && owner->return_path && owner->return_path->ring);
    CHECK(owner->invalidated && !owner->return_path->bound && !owner->closed_ack);
    CHECK(er_bound && owner->epoch_dirty && fixture.dev.netdev.references == 1);
    health_tick(owner);
    check_health_closed(&fixture);
    release_return(&fixture);

    owner = setup_reopen(&fixture);
    health_fixture = &fixture;
    health_races = 0;
    health_lock_countdown = 2;
    before_spin_lock_hook = health_invalidate_lock;
    CHECK(airoha_npu_owner_fe_arm(owner, &owner->txn.id) == -ESTALE);
    CHECK(health_races == 1 && !fe_arm_calls && !fixture.ppe.ct_fe.armed);
    CHECK(owner->invalidated && owner->return_path && er_bound);
    release_return(&fixture);

    owner = setup_reopen(&fixture);
    health_fixture = &fixture;
    health_races = 0;
    fail_gate = GATE_OPEN;
    CHECK(airoha_npu_txn_open(&owner->txn, &airoha_npu_owner_ops, owner) == -ETIMEDOUT);
    CHECK(owner->txn.phase == NPU_TXN_GATE_OPEN && fixture.ppe.ct_fe.armed);
    fail_gate = -1;
    closes = gate_calls[GATE_OPEN];
    health_lock_countdown = 2;
    before_spin_lock_hook = health_invalidate_lock;
    CHECK(airoha_npu_txn_gate(&owner->txn, &airoha_npu_owner_ops, owner, GATE_OPEN) == -ESTALE);
    CHECK(health_races == 1 && gate_calls[GATE_OPEN] == closes && !gate_open_state);
    health_tick(owner);
    check_health_closed(&fixture);
    release_return(&fixture);
}

static void health_cancel_race(struct delayed_work *work)
{
    struct airoha_npu_owner *owner;

    CHECK(!health_fixture->ppe.ct_fe.owner);
    if (work->function != airoha_npu_owner_health_work)
        return;
    owner = container_of(work, struct airoha_npu_owner, health_work);
    CHECK(owner->retiring && !health_fixture->ppe.ct_npu_owner && flow_offload_mutex);
    if (work->pending)
        test_run_delayed_work(work);
    CHECK(!work->pending && !work->running);
}

static void health_free_check(void *pointer)
{
    struct airoha_npu_owner *owner = pointer;

    CHECK(owner->retiring && !owner->health_work.pending && !owner->health_work.running);
    CHECK(owner->health_work.cancelled == 1 && !health_fixture->ppe.ct_npu_owner);
    health_owner_frees++;
}

static void check_health_retire(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;

    for (unsigned int failure = 0; failure < 2; ++failure) {
        owner = setup_health(&fixture);
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
        fail_release = failure == 0;
        fail_fe_release = failure == 1;
        CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == -EIO);
        CHECK(fixture.ppe.ct_npu_owner == owner && !owner->retiring);
        CHECK(owner->health_work.pending && !owner->health_work.cancelled);
        fail_release = fail_fe_release = false;
        work_cancel_hook = health_cancel_race;
        before_free_hook = health_free_check;
        CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == 0);
        CHECK(health_owner_frees == 1 && allocated == freed);
        work_cancel_hook = NULL;
        before_free_hook = NULL;
        CHECK(health_invalidate(&fixture) == 0);
    }
}

static void check_health_notify(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner = setup_health(&fixture);
    struct net_device unrelated = { true, true, 0 };
    u32 epoch = owner->txn.id.epoch;

    flow_offload_mutex = 0;
    spin_lock_bh(&ppe_lock);
    CHECK(airoha_npu_owner_notify(&fixture.ppe, &unrelated) == 0);
    CHECK(!owner->invalidated && gate_open_state);
    CHECK(airoha_npu_owner_notify(&fixture.ppe, &fixture.dev.netdev) == -EAGAIN);
    CHECK(owner->invalidated && !gate_open_state && !owner->closed_ack);
    CHECK(owner->gate_id.epoch == epoch && gate_epoch == epoch);
    CHECK(owner->txn.phase == NPU_TXN_OPEN && owner->return_path && er_bound);
    spin_unlock_bh(&ppe_lock);
    flow_offload_mutex = 1;
    health_tick(owner);
    check_health_closed(&fixture);
    spin_lock_bh(&ppe_lock);
    CHECK(airoha_npu_owner_notify(&fixture.ppe, NULL) == 0);
    spin_unlock_bh(&ppe_lock);
    CHECK(owner->closed_ack && owner->invalidated && owner->close_pending);
    release_return(&fixture);

    for (unsigned int failure = 0; failure < 3; ++failure) {
        owner = setup_health(&fixture);
        if (failure == 0)
            fail_revoke = -EIO;
        else if (failure == 1)
            fail_gate = GATE_CLOSE;
        else
            fixture.eth.npu = NULL;
        flow_offload_mutex = 0;
        spin_lock_bh(&ppe_lock);
        CHECK(airoha_npu_owner_notify(&fixture.ppe, NULL) ==
              (failure == 0 ? -EIO : failure == 1 ? -ETIMEDOUT : -ENODEV));
        CHECK(owner->invalidated && owner->close_pending && !owner->closed_ack);
        CHECK(!fixture.eth.ct_bank1_routes.pon_open && fixture.eth.ct_bank1_routes.revoked);
        CHECK(owner->return_path && er_bound && fixture.dev.netdev.references == 1);
        spin_unlock_bh(&ppe_lock);
        flow_offload_mutex = 1;
        fail_revoke = 0;
        fail_gate = -1;
        fixture.eth.npu = &fixture.npu;
        health_tick(owner);
        check_health_closed(&fixture);
        release_return(&fixture);
    }

    owner = setup_health(&fixture);
    epoch = owner->txn.id.epoch;
    gate_reply_hook = health_fail_next_close;
    CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == -ETIMEDOUT);
    CHECK(owner->txn.phase == NPU_TXN_GATE_CLOSE && owner->txn.id.epoch == epoch + 1);
    CHECK(owner->gate_id.epoch == epoch + 1 && gate_epoch == epoch && !owner->closed_ack);
    fail_gate = -1;
    flow_offload_mutex = 0;
    spin_lock_bh(&ppe_lock);
    CHECK(airoha_npu_owner_notify(&fixture.ppe, NULL) == -EAGAIN);
    CHECK(gate_epoch == owner->gate_id.epoch && gate_generation == owner->gate_id.generation);
    spin_unlock_bh(&ppe_lock);
    flow_offload_mutex = 1;
    health_tick(owner);
    check_health_closed(&fixture);
    release_return(&fixture);

    owner = setup_health(&fixture);
    epoch = owner->txn.id.epoch;
    owner->txn.id.epoch++;
    flow_offload_mutex = 0;
    CHECK(health_invalidate(&fixture) == 0);
    CHECK(gate_epoch == epoch && owner->gate_id.epoch == epoch);
    flow_offload_mutex = 1;
    owner->txn.id.epoch = epoch;
    health_tick(owner);
    check_health_closed(&fixture);
    release_return(&fixture);
}

static void check_health_cpu_fallback(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;
    unsigned int gates[4], auth[8], revokes_before;

    for (unsigned int partial = 0; partial < 3; ++partial) {
        setup_return(&fixture);
        owner = fixture.ppe.ct_npu_owner;
        CHECK(owner->closed_ack && !owner->return_path);
        fixture.eth.ct_cpu_fallback = true;
        fixture.eth.ct_cpu_routes_ready = partial == 1;
        fixture.eth.ct_cpu_ifc_disabled = partial == 2;
        er_fallback_error = -EIO;
        CHECK(airoha_npu_owner_health_check(owner) == -EIO);
        for (unsigned int attempt = 0; attempt < 2; ++attempt) {
            health_tick(owner);
            CHECK(er_fallbacks == attempt + 1);
            CHECK(fixture.eth.ct_cpu_routes_ready == (partial == 1));
            CHECK(fixture.eth.ct_cpu_ifc_disabled == (partial == 2));
            CHECK(owner->invalidated && !owner->return_path && owner->closed_ack);
            CHECK(owner->txn.phase == NPU_TXN_CLOSED && owner->invalidation_seq == 1);
        }
        er_fallback_error = 0;
        health_tick(owner);
        CHECK(er_fallbacks == 3 && fixture.eth.ct_cpu_routes_ready && fixture.eth.ct_cpu_ifc_disabled);
        CHECK(fixture.eth.ct_cpu_fallback && owner->invalidated && !owner->close_pending);
        memcpy(gates, gate_calls, sizeof(gates));
        memcpy(auth, auth_calls, sizeof(auth));
        revokes_before = route_revokes;
        for (unsigned int tick = 0; tick < 3; ++tick)
            health_tick(owner);
        CHECK(er_fallbacks == 3 && route_revokes == revokes_before);
        CHECK(!memcmp(gates, gate_calls, sizeof(gates)) && !memcmp(auth, auth_calls, sizeof(auth)));
        release_return(&fixture);
    }
}

static void check_health(void)
{
    check_health_queries();
    check_health_firmware_faults();
    check_health_mapping_faults();
    check_health_close_retries();
    check_health_sequence_races();
    check_health_binding();
    check_health_retire();
    check_health_notify();
    check_health_cpu_fallback();
    CHECK(allocated == freed && !ppe_lock && flow_offload_mutex);
}
