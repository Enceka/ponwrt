static int airoha_npu_owner_ingress_prepare(struct airoha_npu_owner *owner)
{
    struct airoha_ct_pon_ifc_owner *ingress = &owner->ingress;
    struct airoha_eth *eth = owner->ppe->eth;

    CHECK(flow_offload_mutex && !ppe_lock);
    CHECK(!eth->ct_bank1_routes.pon_open);
    CHECK(!(eth->regs[REG_FE_IFC_PORT_EN] & BIT(2)));
    ingress_note(INGRESS_PREPARE);
    if (ingress_prepare_error && !ingress_prepare_partial)
        return ingress_prepare_error;
    if (!ingress->saved_valid) {
        memset(ingress->saved, 0xa5, sizeof(ingress->saved));
        ingress->saved_valid = true;
    }
    ingress->pending = ingress_prepare_error != 0;
    ingress->dirty = ingress_prepare_partial == 1 ? 0 : 3;
    ingress->active = ingress_prepare_partial == 2 ? 0 : ingress->dirty;
    return ingress_prepare_error;
}

static int airoha_npu_owner_ingress_check(struct airoha_npu_owner *owner)
{
    CHECK(flow_offload_mutex && !ppe_lock);
    ingress_note(INGRESS_CHECK);
    if (ingress_check_error)
        return ingress_check_error;
    return owner->ingress.saved_valid && !owner->ingress.pending &&
           owner->ingress.active == 3 && owner->ingress.dirty == 3 ? 0 : -ESTALE;
}

static int airoha_npu_owner_ingress_restore(struct airoha_npu_owner *owner)
{
    struct airoha_eth *eth = owner->ppe->eth;

    CHECK(flow_offload_mutex && !ppe_lock);
    CHECK(!eth->ct_bank1_routes.pon_open);
    CHECK(!(eth->regs[REG_FE_IFC_PORT_EN] & BIT(2)));
    CHECK(ingress_calls[INGRESS_ROUTES_CLAIM]);
    ingress_note(INGRESS_RESTORE);
    if (ingress_restore_error) {
        owner->ingress.pending = true;
        return ingress_restore_error;
    }
    memset(&owner->ingress, 0, sizeof(owner->ingress));
    return 0;
}
