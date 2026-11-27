static void check_bank1_retirement(void)
{
    struct return_fixture fixture;
    struct airoha_npu_owner *owner;
    const int failed_rows[] = { 0, 4096, 8191 };
    unsigned int clears, retired, cleared_rows;
    u32 epoch;

    setup(&fixture.eth, &fixture.ppe, &fixture.soc, &fixture.npu);
    fixture.ppe.ct_owns_sram = false;
    CHECK(airoha_ppe_npu_owner_claim_locked(&fixture.eth, 4) == -EOPNOTSUPP);
    CHECK(!fixture.ppe.ct_npu_owner && !bank1_retire_calls && !bank1_clear_calls);

    setup(&fixture.eth, &fixture.ppe, &fixture.soc, &fixture.npu);
    bank1_retire_error = -EIO;
    CHECK(airoha_ppe_npu_owner_claim_locked(&fixture.eth, 4) == -EIO);
    owner = fixture.ppe.ct_npu_owner;
    CHECK(owner && owner->txn.phase == NPU_TXN_PPE_DRAIN);
    CHECK(!owner->closed_ack && !owner->bank1_host_retired && !owner->bank1_next_row);
    CHECK(bank1_retire_calls == 1 && !bank1_clear_calls);
    CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == -EBUSY);
    bank1_retire_error = 0;
    CHECK(airoha_ppe_npu_owner_claim_locked(&fixture.eth, 4) == 0);
    check_closed(&fixture.eth);
    CHECK(bank1_retire_calls == 2 && bank1_clear_calls == 1);
    CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
    CHECK(bank1_retire_calls == 2 && bank1_clear_calls == 1);
    CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == 0);

    for (unsigned int index = 0; index < ARRAY_SIZE(failed_rows); ++index) {
        setup(&fixture.eth, &fixture.ppe, &fixture.soc, &fixture.npu);
        bank1_fail_row = failed_rows[index];
        CHECK(airoha_ppe_npu_owner_claim_locked(&fixture.eth, 4) == -ETIMEDOUT);
        owner = fixture.ppe.ct_npu_owner;
        epoch = owner->txn.id.epoch;
        CHECK(owner->txn.phase == NPU_TXN_PPE_DRAIN && !owner->closed_ack);
        CHECK(owner->bank1_host_retired && owner->bank1_next_row == (u32)failed_rows[index]);
        CHECK(bank1_retire_calls == 1 && bank1_clear_calls == 1);
        CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == -EBUSY);
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == -ETIMEDOUT);
        CHECK(bank1_clear_start == (u32)failed_rows[index] && bank1_retire_calls == 1);
        bank1_fail_row = -1;
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
        check_closed(&fixture.eth);
        CHECK(owner->txn.id.epoch == epoch && owner->closed_ack);
        CHECK(bank1_clear_start == (u32)failed_rows[index] && bank1_retire_calls == 1);
        CHECK(bank1_clear_calls == 3);
        owner->bank1_next_row--;
        CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == -EBUSY);
        owner->bank1_next_row++;
        CHECK(airoha_npu_owner_retire_locked(&fixture.ppe) == 0);
    }

    owner = setup_reopen(&fixture);
    owner->bank1_host_retired = false;
    CHECK(airoha_npu_owner_open_check(owner, &owner->txn.id, NPU_TXN_CLOSED) == -EACCES);
    owner->bank1_host_retired = true;
    clears = bank1_clear_calls;
    retired = bank1_retire_calls;
    cleared_rows = bank1_cleared_rows;
    CHECK(airoha_ppe_npu_owner_open_locked(&fixture.eth) == 0);
    CHECK(!owner->bank1_next_row);
    bank1_fail_row = 4096;
    CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == -ETIMEDOUT);
    CHECK(owner->txn.phase == NPU_TXN_PPE_DRAIN && owner->bank1_next_row == 4096);
    CHECK(owner->return_path && !owner->closed_ack && bank1_retire_calls == retired);
    CHECK(bank1_clear_start == 0 && bank1_clear_calls == clears + 1);
    bank1_fail_row = -1;
    CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
    CHECK(owner->closed_ack && !owner->return_path && bank1_clear_start == 4096);
    CHECK(bank1_cleared_rows == cleared_rows + 4096 && bank1_retire_calls == retired);
    release_return(&fixture);

    for (unsigned int stage = 0; stage < 2; ++stage) {
        owner = setup_reopen(&fixture);
        fail_write = stage ? REG_PPE_PPE_FLOW_CFG(1) : REG_PPE_TB_CFG(1);
        CHECK(airoha_npu_txn_open(&owner->txn, &airoha_npu_owner_ops, owner) == -EIO);
        CHECK(owner->txn.phase == NPU_TXN_PPE_RESTORE && !owner->bank1_next_row);
        fail_write = -1;
        clears = bank1_clear_calls;
        cleared_rows = bank1_cleared_rows;
        CHECK(airoha_ppe_npu_owner_close_locked(&fixture.eth) == 0);
        CHECK(bank1_clear_start == 0 && bank1_clear_calls == clears + 1);
        CHECK(bank1_cleared_rows == cleared_rows + PPE_SRAM_NUM_ENTRIES);
        release_return(&fixture);
    }
}
