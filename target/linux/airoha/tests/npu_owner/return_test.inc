struct return_fixture {
    struct airoha_eth eth;
    struct airoha_ppe ppe;
    struct airoha_soc soc;
    struct airoha_npu npu;
    struct airoha_gdm_dev dev;
    struct airoha_gdm_port port;
    struct airoha_pon_flow_table table;
};

static void setup_return(struct return_fixture *fixture)
{
    CHECK(!er_bound);
    memset(fixture, 0, sizeof(*fixture));
    setup(&fixture->eth, &fixture->ppe, &fixture->soc, &fixture->npu);
    fixture->soc.ops.get_sport = er_get_sport;
    fixture->port = (struct airoha_gdm_port) { AIROHA_GDM2_IDX, ER_PON };
    fixture->table.count = 3;
    fixture->table.entries[0].tag = AIROHA_PON_QDMA_VALID;
    fixture->table.entries[1].tag = AIROHA_PON_QDMA_VALID | 0x1001;
    fixture->table.entries[2].tag = AIROHA_PON_QDMA_VALID | 0xffff;
    fixture->dev = (struct airoha_gdm_dev) {
        .eth = &fixture->eth, .port = &fixture->port, .qdma = &fixture->eth.qdma[1],
        .pon_flow_table = &fixture->table, .netdev = { true, true, 0 },
        .flags = 1UL << AIROHA_DEV_F_PON,
    };
    fixture->eth.pon = &fixture->dev;
    er_failure = -1;
    er_fallback_error = 0;
    er_allocation_failure = er_lose_ack = false;
    er_caps = ER_CAPS | ER_CAP_SOURCES;
    er_state = er_fault = er_last_epoch = 0;
    er_frees = er_fallbacks = er_cancels = 0;
    er_reply_hook = NULL;
    work_cancel_hook = NULL;
    memset(er_calls, 0, sizeof(er_calls));
    CHECK(airoha_ppe_npu_owner_claim_locked(&fixture->eth, 4) == 0);
}

static void release_return(struct return_fixture *fixture)
{
    CHECK(airoha_ppe_npu_owner_close_locked(&fixture->eth) == 0);
    CHECK(!fixture->ppe.ct_npu_owner->return_path);
    CHECK(!fixture->dev.netdev.references && !er_bound);
    CHECK(airoha_npu_owner_retire_locked(&fixture->ppe) == 0);
    CHECK(allocated == freed);
}

static void check_return_binding(struct return_fixture *fixture)
{
    struct airoha_npu_return *path = fixture->ppe.ct_npu_owner->return_path;
    struct er_config config = path->ring->config;
    struct net_device *lower = netdev_from_priv(&fixture->dev);
    struct net_device other = *lower;
    struct airoha_pon_flow_table replacement = fixture->table;

    for (u32 service = 0; service <= 0xffff; ++service)
        CHECK(airoha_npu_return_binding(path, lower, &config, ER_SERVICE_VALID | service) ==
              (service == 0 || service == 0x1001 || service == 0xffff));
    CHECK(!airoha_npu_return_binding(path, lower, &config, 0x1001));
    CHECK(!airoha_npu_return_binding(path, lower, &config, ER_SERVICE_VALID | 0x10001));
    for (unsigned int field = 0; field < 6; ++field) {
        u32 *words = (u32 *)&config;
        words[field] ^= 1;
        CHECK(!airoha_npu_return_binding(path, lower, &config, ER_SERVICE_VALID));
        words[field] ^= 1;
    }
    CHECK(!airoha_npu_return_binding(path, &other, &config, ER_SERVICE_VALID));
#ifdef NPU_OWNER_HEALTH_TEST
    CHECK(path->owner->invalidated);
    CHECK(airoha_ppe_npu_owner_renew_locked(&fixture->eth, 4) == 0);
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture->eth, &fixture->dev, 8) == 0);
    path = fixture->ppe.ct_npu_owner->return_path;
    config = path->config;
#endif
    for (unsigned int state = 0; state < 9; ++state) {
        switch (state) {
        case 0: fixture->dev.pon_update_blocked = true; break;
        case 1: fixture->dev.qdma = &fixture->eth.qdma[0]; break;
        case 2: fixture->dev.pon_flow_table = &replacement; break;
        case 3: fixture->dev.flags = 0; break;
        case 4: fixture->dev.pon_qdma_tag = AIROHA_PON_QDMA_VALID; break;
        case 5: lower->running = false; break;
        case 6: lower->carrier = false; break;
        case 7: bridge_generation++; break;
        case 8: fixture->eth.ct_cpu_fallback = true; break;
        }
        CHECK(!airoha_npu_return_binding(path, lower, &config, ER_SERVICE_VALID));
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture->eth, &fixture->dev, 8) < 0);
        fixture->dev.pon_update_blocked = false;
        fixture->dev.qdma = &fixture->eth.qdma[1];
        fixture->dev.pon_flow_table = &fixture->table;
        fixture->dev.flags = 1UL << AIROHA_DEV_F_PON;
        fixture->dev.pon_qdma_tag = 0;
        lower->running = lower->carrier = true;
        bridge_generation = 4;
        fixture->eth.ct_cpu_fallback = false;
#ifdef NPU_OWNER_HEALTH_TEST
        CHECK(airoha_ppe_npu_owner_renew_locked(&fixture->eth, 4) == 0);
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture->eth, &fixture->dev, 8) == 0);
        path = fixture->ppe.ct_npu_owner->return_path;
        config = path->config;
#endif
    }
    CHECK(airoha_npu_return_binding(path, lower, &config, ER_SERVICE_VALID));
}

static void check_returns(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;
    struct airoha_npu_return *path;
    u32 epoch;
    unsigned int binding_binds, binding_stops, binding_unbinds, binding_frees, binding_cancels;

    for (unsigned int scenario = 0; scenario < 20; ++scenario) {
        int expected = -EOPNOTSUPP;
        setup_return(&fixture);
        switch (scenario) {
        case 0: fixture.eth.pon = NULL; break;
        case 1: fixture.dev.flags = 0; break;
        case 2: fixture.port.id = 1; break;
        case 3: fixture.port.sport = ER_LAN1; break;
        case 4: fixture.dev.pon_flow_table = NULL; break;
        case 5: fixture.table.count = 0; break;
        case 6: fixture.table.count = 33; break;
        case 7: fixture.dev.pon_qdma_tag = AIROHA_PON_QDMA_VALID | AIROHA_PON_QDMA_EPON; break;
        case 8: fixture.table.entries[0].tag = 0; expected = -EINVAL; break;
        case 9: fixture.dev.pon_update_blocked = true; expected = -ESTALE; break;
        case 10: fixture.dev.qdma = &fixture.eth.qdma[0]; expected = -ESTALE; break;
        case 11: fixture.dev.netdev.running = false; expected = -ESTALE; break;
        case 12: bridge_generation++; expected = -ESTALE; break;
        case 13: fail_alloc = true; expected = -ENOMEM; break;
        case 14: er_caps = ER_CAPS; break;
        case 15: er_state = ER_QUEUED; expected = -EBUSY; break;
        case 16: er_fault = 1; expected = -EBUSY; break;
        case 17: er_failure = ER_QUERY; expected = -ETIMEDOUT; break;
        case 18: fixture.eth.ct_cpu_fallback = true; expected = -EIO; break;
        case 19: fixture.ppe.ct_npu_owner->native_stopped = true; expected = -EBUSY; break;
        }
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == expected);
        CHECK(!fixture.ppe.ct_npu_owner->return_path && !er_calls[ER_BIND]);
        fail_alloc = false;
        er_failure = -1;
        release_return(&fixture);
    }

    setup_return(&fixture);
    CHECK(airoha_ppe_npu_return_prepare_locked(NULL, &fixture.dev, 8) == -EINVAL);
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, NULL, 8) == -EINVAL);
    for (u32 count = 0; count <= 513; ++count)
        if (count < 8 || count > 512 || (count & (count - 1)))
            CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, count) == -EINVAL);
    CHECK(!er_calls[ER_QUERY]);
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
    owner = fixture.ppe.ct_npu_owner;
    path = owner->return_path;
    CHECK(path && path->bound && owner->epoch_dirty && er_bound);
    CHECK(fixture.dev.netdev.references == 1 && er_calls[ER_BIND] == 1);
    CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == -EBUSY);
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 16) == -ESTALE);
    CHECK(er_calls[ER_BIND] == 1);
    check_return_binding(&fixture);
    binding_binds = er_calls[ER_BIND];
    binding_stops = er_calls[ER_STOP];
    binding_unbinds = er_calls[ER_UNBIND];
    binding_frees = er_frees;
    binding_cancels = er_cancels;
    epoch = owner->txn.id.epoch;
    CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
    CHECK(owner->txn.id.epoch == epoch + 1 && !owner->epoch_dirty);
    CHECK(er_calls[ER_STOP] == binding_stops + 1 &&
          er_calls[ER_UNBIND] == binding_unbinds + 1 && er_frees == binding_frees + 1);
    CHECK(er_cancels == binding_cancels + 1 && !owner->return_path);
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
    CHECK(owner->return_path->epoch == epoch + 1 && er_calls[ER_BIND] == binding_binds + 1);
    release_return(&fixture);

    for (unsigned int scenario = 0; scenario < 3; ++scenario) {
        setup_return(&fixture);
        owner = fixture.ppe.ct_npu_owner;
        epoch = owner->txn.id.epoch;
        er_allocation_failure = scenario == 0;
        er_failure = scenario ? ER_BIND : -1;
        er_lose_ack = scenario == 2;
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) ==
              (scenario ? -ETIMEDOUT : -ENOMEM));
        CHECK(owner->epoch_dirty);
        CHECK(!!owner->return_path == !!scenario);
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == -EBUSY);
        CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == -EBUSY);
        er_allocation_failure = false;
        er_failure = -1;
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
        CHECK(owner->txn.id.epoch == epoch + 1 && !owner->epoch_dirty);
        CHECK(!owner->return_path && !er_bound && !fixture.dev.netdev.references);
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
        release_return(&fixture);
    }

    for (unsigned int scenario = 0; scenario < 9; ++scenario) {
        unsigned int closes;
        setup_return(&fixture);
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
        owner = fixture.ppe.ct_npu_owner;
        path = owner->return_path;
        epoch = owner->txn.id.epoch;
        switch (scenario) {
        case 0: fail_gate = GATE_CLOSE; break;
        case 1: fail_auth = AUTH_MBOX_QUERY; break;
        case 2: fail_auth = AUTH_MBOX_DISARM; break;
        case 3: fail_fe = true; break;
        case 4: fail_gate = GATE_QUIET; break;
        case 5: er_failure = ER_STOP; break;
        case 6: er_failure = ER_UNBIND; break;
        case 7: er_failure = ER_UNBIND; er_lose_ack = true; break;
        case 8: fail_write = REG_PPE_PPE_FLOW_CFG(1); fixture.eth.regs[3] = 1; break;
        }
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) < 0);
        CHECK(owner->return_path == path && path->ring && !er_frees && !er_cancels);
        CHECK(fixture.dev.netdev.references == 1 && fixture.eth.regs[2] == 1);
        CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == -EBUSY);
        CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) < 0);
        CHECK(owner->txn.id.epoch == epoch + 1);
        closes = gate_calls[GATE_CLOSE];
        fail_gate = fail_auth = fail_write = er_failure = -1;
        fail_fe = false;
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
        CHECK(owner->txn.id.epoch == epoch + 1);
        CHECK(gate_calls[GATE_CLOSE] == closes + (scenario == 0));
        CHECK(!owner->return_path && er_frees == 1 && er_cancels == 1);
        release_return(&fixture);
    }

    setup_return(&fixture);
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
    owner = fixture.ppe.ct_npu_owner;
    path = owner->return_path;
    er_fallback_error = -EIO;
    path->ring->ops->fault(path, &path->ring->config, 2);
    CHECK(path->fault == 2 && path->route_error == -EIO && path->fault_work.pending);
    CHECK(fixture.eth.ct_cpu_fallback && er_fallbacks == 1);
    CHECK(!airoha_npu_return_binding(path, &fixture.dev.netdev, &path->ring->config,
                                    ER_SERVICE_VALID));
    er_fallback_error = 0;
    path->fault_work.pending = false;
    path->fault_work.function(&path->fault_work.work);
    CHECK(er_fallbacks == 2 && !path->route_error && !path->fault_work.pending);
    release_return(&fixture);

    setup_return(&fixture);
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
    owner = fixture.ppe.ct_npu_owner;
    epoch = owner->txn.id.epoch;
    owner->txn.id.epoch = U32_MAX;
    CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == -EOVERFLOW);
    CHECK(owner->return_path && er_bound && !er_calls[ER_STOP]);
    owner->txn.id.epoch = epoch;
    er_failure = ER_STOP;
    flow_offload_mutex = 0;
    CHECK(airoha_ppe_ct_shutdown(&fixture.eth) == -ETIMEDOUT);
    CHECK(owner->return_path && !owner->stop_completed && !owner->native_stopped);
    CHECK(fixture.eth.regs[2] == 1 && !restores);
    er_failure = -1;
    CHECK(airoha_ppe_ct_shutdown(&fixture.eth) == 0);
    CHECK(!fixture.ppe.ct_npu_owner && !er_bound && !fixture.dev.netdev.references);
    CHECK(er_frees == 1 && er_cancels == 1);
    flow_offload_mutex = 1;
    CHECK(allocated == freed);

    setup_return(&fixture);
    owner = fixture.ppe.ct_npu_owner;
    owner->txn.id.epoch = U32_MAX - 1;
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == 0);
    CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
    CHECK(owner->txn.id.epoch == U32_MAX && !owner->epoch_dirty && !owner->return_path);
    CHECK(airoha_ppe_npu_return_prepare_locked(&fixture.eth, &fixture.dev, 8) == -EOVERFLOW);
    CHECK(!owner->epoch_dirty && !owner->return_path && er_calls[ER_BIND] == 1);
    release_return(&fixture);
}
