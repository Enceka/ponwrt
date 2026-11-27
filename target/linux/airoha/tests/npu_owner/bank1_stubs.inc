#define AIROHA_NPU_BANK1_H

static unsigned int bank1_retire_calls, bank1_clear_calls, bank1_cleared_rows;
static u32 bank1_clear_start;
static int bank1_retire_error, bank1_fail_row = -1;

static void check_bank1_quiet(struct airoha_ppe *ppe)
{
    CHECK(flow_offload_mutex && !ppe_lock && ppe->ct_npu_owner);
    CHECK(gate_calls[GATE_QUIET] && !gate_open_state && ppe->ct_fe.owner_quiesced);
    CHECK(!ppe->eth->regs[REG_PPE_PPE_FLOW_CFG(1)]);
    CHECK((ppe->eth->regs[REG_PPE_TB_CFG(1)] & PPE_TB_CFG_SEARCH_MISS_MASK) == 2);
    CHECK(ppe->eth->regs[REG_PPE_GLO_CFG(1)] == PPE_GLO_CFG_EN_MASK);
}

static int airoha_ppe_bank1_retire_flows(struct airoha_ppe *ppe)
{
    check_bank1_quiet(ppe);
    bank1_retire_calls++;
    return bank1_retire_error;
}

static int airoha_ppe_bank1_clear_rows(struct airoha_ppe *ppe, u32 *next_row)
{
    check_bank1_quiet(ppe);
    CHECK(ppe->ct_owns_sram && bank1_retire_calls && !bank1_retire_error);
    CHECK(*next_row <= PPE_SRAM_NUM_ENTRIES);
    bank1_clear_calls++;
    bank1_clear_start = *next_row;
    if (bank1_fail_row >= 0 && (u32)bank1_fail_row >= *next_row) {
        *next_row = bank1_fail_row;
        return -ETIMEDOUT;
    }
    bank1_cleared_rows += PPE_SRAM_NUM_ENTRIES - *next_row;
    *next_row = PPE_SRAM_NUM_ENTRIES;
    return 0;
}
