#define AIROHA_NPU_INGRESS_OWNER_H

enum ingress_event {
    INGRESS_ROUTES_CLAIM,
    INGRESS_ROUTES_REVOKE,
    INGRESS_ROUTES_RELEASE,
    INGRESS_PREPARE,
    INGRESS_CHECK,
    INGRESS_RESTORE,
    INGRESS_ROUTES_OPEN,
    INGRESS_ROUTES_CHECK,
    INGRESS_READY,
    INGRESS_GATE_OPEN,
    INGRESS_GATE_CLOSE,
    INGRESS_GATE_QUERY,
    INGRESS_AUTH_QUERY,
    INGRESS_FE_ARM,
    INGRESS_ER_STOP,
    INGRESS_ER_UNBIND,
    INGRESS_EVENT_COUNT,
};

static enum ingress_event ingress_events[2048];
static unsigned int ingress_event_count, ingress_calls[INGRESS_EVENT_COUNT];
static int ingress_prepare_error, ingress_check_error, ingress_restore_error;
static int ingress_routes_check_error, ingress_ready_error;
static unsigned int ingress_probe_operations;
static unsigned int ingress_prepare_partial;
static bool ingress_claim_scope_stuck, ingress_probe_busy;
static void (*ingress_event_hook)(enum ingress_event);

static int airoha_npu_owner_ingress_prepare(struct airoha_npu_owner *owner);
static int airoha_npu_owner_ingress_check(struct airoha_npu_owner *owner);
static int airoha_npu_owner_ingress_restore(struct airoha_npu_owner *owner);

static void ingress_note(enum ingress_event event)
{
    CHECK(event < INGRESS_EVENT_COUNT);
    CHECK(ingress_event_count < ARRAY_SIZE(ingress_events));
    ingress_events[ingress_event_count++] = event;
    ingress_calls[event]++;
    if (ingress_event_hook)
        ingress_event_hook(event);
}

static void ingress_reset(struct airoha_eth *eth)
{
    ingress_event_count = 0;
    memset(ingress_calls, 0, sizeof(ingress_calls));
    ingress_prepare_error = ingress_check_error = ingress_restore_error = 0;
    ingress_routes_check_error = ingress_ready_error = 0;
    ingress_probe_operations = 0;
    ingress_prepare_partial = 0;
    ingress_claim_scope_stuck = ingress_probe_busy = false;
    ingress_event_hook = NULL;
    eth->ct_ifc_port_mask = XSI_ETH_VIP_PORT_MASK;
    eth->regs[REG_FE_IFC_PORT_EN] = XSI_ETH_VIP_PORT_MASK;
    eth->regs[REG_FE_CSR_IFC_CFG] = FE_IFC_EN_MASK;
}

static bool airoha_ct_pon_ifc_tuple_busy(struct airoha_ppe *ppe)
{
    return ingress_probe_busy || ppe->ct_pon_ifc_tuple;
}

#include "ingress_busy.inc"

static int airoha_bank1_routes_check(struct airoha_eth *eth, const void *owner, bool opened)
{
    u32 scope = XSI_ETH_VIP_PORT_MASK | (opened ? BIT(2) : 0);

    CHECK(flow_offload_mutex && owner);
    ingress_note(INGRESS_ROUTES_CHECK);
    if (ingress_routes_check_error)
        return ingress_routes_check_error;
    if (eth->ct_bank1_routes.owner != owner || !eth->ct_bank1_routes.ready ||
        eth->ct_bank1_routes.revoked || eth->ct_bank1_routes.pon_open != opened)
        return -ESTALE;
    if (eth->ct_ifc_port_mask != scope || eth->regs[REG_FE_IFC_PORT_EN] != scope ||
        (opened && (!eth->ct_bank1_routes.ingress_ready || !eth->ct_ifc_pon_ready)))
        return -EUCLEAN;
    return 0;
}

static int airoha_bank1_routes_ingress_ready(struct airoha_eth *eth, const void *owner)
{
    int error;

    CHECK(flow_offload_mutex && ppe_lock);
    ingress_note(INGRESS_READY);
    if (ingress_ready_error)
        return ingress_ready_error;
    error = airoha_bank1_routes_check(eth, owner, false);
    if (!error)
        eth->ct_bank1_routes.ingress_ready = true;
    return error;
}
