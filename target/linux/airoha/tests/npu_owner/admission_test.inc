static struct airoha_npu_auth_rule admission_rule(struct airoha_npu_owner *owner)
{
    return (struct airoha_npu_auth_rule) {
        .raw = { AUTH_MBOX_ABI, owner->txn.id.epoch, 1, 1, 100,
                 4, ER_PON, 0x1001, owner->txn.id.generation,
                 4, 6, 0x0a000001, 0, 0, 0, 0x0a000002, 0, 0, 0,
                 0x12345678, 0, 0, 0, 0, 0, 0x02000000, 0x00010200, 0x00000002 },
    };
}

static void check_authorization(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;
    struct airoha_npu_auth_rule rule;
    unsigned int begin_count;
    u32 epoch;

    setup_return(&fixture);
    owner = fixture.ppe.ct_npu_owner;
    rule = admission_rule(owner);
    CHECK(airoha_ppe_npu_owner_authorize_locked(NULL, &rule, 1) == -EINVAL);
    CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture.eth, &rule, 1) == -EBUSY);
    CHECK(!auth_calls[AUTH_MBOX_BEGIN] && !owner->auth_attempted);
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
    for (unsigned int scenario = 0; scenario < 9; ++scenario) {
        switch (scenario) {
        case 0: rule.raw[7] = 1; break;
        case 1: rule.raw[3] = 0; break;
        case 2: fixture.eth.ct_bank1_routes.ready = false; break;
        case 3: fixture.ppe.ct_fe.owner_quiesced = false; break;
        case 4: fixture.dev.pon_update_blocked = true; break;
        case 5: fixture.ppe.ct_fe.pending = true; break;
        case 6: fixture.ppe.ct_fe.epoch++; break;
        case 7: fixture.eth.ct_cpu_fallback = true; break;
        case 8: owner->return_path->epoch++; break;
        }
        CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture.eth, &rule, 1) < 0);
        CHECK(!owner->auth_attempted && !owner->auth_count && !auth_calls[AUTH_MBOX_BEGIN]);
        rule = admission_rule(owner);
        fixture.eth.ct_bank1_routes.ready = true;
        fixture.ppe.ct_fe.owner_quiesced = true;
        fixture.dev.pon_update_blocked = fixture.ppe.ct_fe.pending = false;
        fixture.ppe.ct_fe.epoch = owner->txn.id.epoch;
        fixture.eth.ct_cpu_fallback = false;
        owner->return_path->epoch = owner->txn.id.epoch;
    }
    CHECK(airoha_npu_owner_ready(owner, &owner->txn.id) == -EOPNOTSUPP);
    fixture.ppe.ct_pon_qualified = true;
    CHECK(airoha_npu_owner_ready(owner, &owner->txn.id) == -EACCES);
    CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture.eth, &rule, 1) == 0);
    CHECK(owner->auth_attempted && owner->auth_count == 1 && published_enabled);
    CHECK(auth_calls[AUTH_MBOX_BEGIN] == 1 && auth_calls[AUTH_MBOX_ADD] == 1 &&
          auth_calls[AUTH_MBOX_ARM] == 1 && !gate_calls[GATE_OPEN]);
    CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture.eth, &rule, 1) == -EBUSY);
    CHECK(airoha_npu_owner_ready(owner, &owner->txn.id) == 0);
    auth_query_change_generation = true;
    CHECK(airoha_npu_owner_ready(owner, &owner->txn.id) == -ESTALE);
    auth_query_change_generation = false;
    bridge_generation = 4;
    published_count++;
    CHECK(airoha_npu_owner_ready(owner, &owner->txn.id) == -ESTALE);
    published_count--;
    published_enabled = 0;
    CHECK(airoha_npu_owner_ready(owner, &owner->txn.id) == -ESTALE);
    published_enabled = 1;
    CHECK(airoha_npu_txn_open(&owner->txn, &airoha_npu_owner_ops, owner) == -EOPNOTSUPP);
    CHECK(owner->txn.phase == NPU_TXN_PPE_RESTORE && !gate_calls[GATE_OPEN]);
    epoch = owner->txn.id.epoch;
    CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
    CHECK(owner->txn.id.epoch == epoch + 1 && !owner->auth_attempted && !owner->auth_count);
    CHECK(!published_enabled && !owner->return_path);
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
    rule = admission_rule(owner);
    CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture.eth, &rule, 1) == 0);
    release_return(&fixture);

    for (unsigned int scenario = 0; scenario < 8; ++scenario) {
        setup_return(&fixture);
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
        owner = fixture.ppe.ct_npu_owner;
        rule = admission_rule(owner);
        epoch = owner->txn.id.epoch;
        if (scenario < 6) {
            fail_auth = AUTH_MBOX_BEGIN + scenario / 2;
            auth_lose_ack = scenario & 1;
        } else if (scenario == 6)
            auth_bad_echo = true;
        else
            auth_change_generation = true;
        CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture.eth, &rule, 1) ==
              (scenario < 6 ? -ETIMEDOUT : scenario == 6 ? -EPROTO : -ESTALE));
        CHECK(owner->auth_attempted && !owner->auth_count && owner->epoch_dirty);
        begin_count = auth_calls[AUTH_MBOX_BEGIN];
        CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture.eth, &rule, 1) == -EBUSY);
        CHECK(auth_calls[AUTH_MBOX_BEGIN] == begin_count && owner->return_path);
        fail_auth = -1;
        auth_lose_ack = auth_bad_echo = auth_change_generation = false;
        bridge_generation = 4;
        fail_gate = GATE_CLOSE;
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == -ETIMEDOUT);
        CHECK(owner->auth_attempted && !owner->auth_count && owner->return_path);
        fail_gate = -1;
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
        CHECK(owner->txn.id.epoch == epoch + 1 && !owner->auth_attempted);
        CHECK(!published_enabled && !owner->return_path && !owner->auth_count);
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
        rule = admission_rule(owner);
        CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture.eth, &rule, 1) == 0);
        release_return(&fixture);
    }

    for (unsigned int scenario = 0; scenario < 4; ++scenario) {
        setup_return(&fixture);
        owner = fixture.ppe.ct_npu_owner;
        epoch = owner->txn.id.epoch;
        if (scenario < 3) {
            CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
            rule = admission_rule(owner);
            CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture.eth, &rule, 1) == 0);
        }
        bridge_generation = 5;
        if (scenario == 1)
            er_failure = ER_STOP;
        if (scenario == 2)
            fail_fe = true;
        if (scenario == 3)
            fail_gate = GATE_CLOSE;
        if (scenario) {
            CHECK(airoha_ppe_npu_owner_renew_locked(&fixture.eth, 5) == -ETIMEDOUT);
            CHECK(owner->txn.id.generation == (scenario == 3 ? 5u : 4u));
            CHECK(owner->txn.id.epoch == epoch + 1);
            CHECK(!!owner->return_path == (scenario < 3));
            er_failure = fail_gate = -1;
            fail_fe = false;
        }
        CHECK(airoha_ppe_npu_owner_renew_locked(&fixture.eth, 5) == 0);
        CHECK(owner->txn.id.generation == 5 && owner->txn.phase == NPU_TXN_CLOSED);
        CHECK(owner->txn.id.epoch == epoch + (scenario < 3 ? 2u : 1u));
        CHECK(!owner->return_path && !owner->auth_attempted && !owner->epoch_dirty);
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
        rule = admission_rule(owner);
        CHECK(airoha_ppe_npu_owner_authorize_locked(&fixture.eth, &rule, 1) == 0);
        CHECK(owner->auth_count == 1 && published_enabled);
        release_return(&fixture);
    }

    setup_return(&fixture);
    owner = fixture.ppe.ct_npu_owner;
    epoch = owner->txn.id.epoch;
    begin_count = gate_calls[GATE_CLOSE];
    CHECK(airoha_ppe_npu_owner_renew_locked(NULL, 4) == -EINVAL);
    CHECK(airoha_ppe_npu_owner_renew_locked(&fixture.eth, 0) == -EINVAL);
    CHECK(airoha_ppe_npu_owner_renew_locked(&fixture.eth, (u64)U32_MAX + 1) == -EOVERFLOW);
    CHECK(airoha_ppe_npu_owner_renew_locked(&fixture.eth, 3) == -ESTALE);
    CHECK(airoha_ppe_npu_owner_renew_locked(&fixture.eth, 5) == -ESTALE);
    CHECK(owner->txn.id.epoch == epoch && gate_calls[GATE_CLOSE] == begin_count);
    CHECK(airoha_ppe_npu_owner_renew_locked(&fixture.eth, 4) == 0);
    CHECK(owner->txn.id.epoch == epoch);
    owner->txn.id.epoch = U32_MAX;
    bridge_generation = 5;
    CHECK(airoha_ppe_npu_owner_renew_locked(&fixture.eth, 5) == -EOVERFLOW);
    CHECK(owner->txn.id.generation == 4 && owner->txn.id.epoch == U32_MAX);
    release_return(&fixture);
}
