#include "metadata_stubs.h"
#include "production_functions.inc"

int main(void)
{
    unsigned kind, vn, v0, v1, pn, sid, ds, proto, fixed, present, count;
    while (scanf("%u %u %u %u %u %u %u %u %u %u %u", &kind, &vn, &v0, &v1,
                 &pn, &sid, &ds, &proto, &fixed, &present, &count) == 11) {
        assert(count <= 32 && vn <= 2 && pn <= 1 && ds <= 255);
        struct airoha_pon_flow_table *table = calloc(1, sizeof(*table) + count * sizeof(table->entries[0]));
        assert(table);
        table->count = count;
        for (unsigned i = 0; i < count; i++) {
            unsigned vid, mask, tag;
            assert(scanf("%u %u %u", &vid, &mask, &tag) == 3);
            table->entries[i] = (struct airoha_pon_flow_entry){ .tag=tag, .vlan_id=vid, .pbit_mask=mask };
        }
        struct airoha_gdm_port port = { .id=2 };
        struct airoha_gdm_dev dev = { .port=&port, .flags=BIT(AIROHA_DEV_F_PON),
            .pon_qdma_tag=fixed, .pon_flow_table=present ? table : NULL };
        struct net_device netdev = { .priv=&dev };
        struct airoha_ppe ppe = { .ct_host_ppe=true };
        struct airoha_eth eth = { .ppe=&ppe };
        struct airoha_flow_data data = { .eth={{0x02,1,2,3,4,5}, {0x02,6,7,8,9,10}, 0},
            .vlan={.hdr={{v0,0x8100},{v1,0x88a8}},.num=vn}, .pppoe={.sid=sid,.num=pn} };
        u32 selected = 0x55aa55aa;
        struct airoha_foe_entry hwe;
        struct airoha_gdm_dev *egress = NULL;
        int select_result = airoha_ppe_pon_select_flow(&dev, &data, &selected);
        int prepare_result = airoha_ppe_foe_entry_prepare(&eth, &hwe, &netdev,
                                                        kind, &data, proto, ds, &egress);
        printf("%d %u %d %d", select_result, selected, prepare_result, egress == &dev);
        for (unsigned pbit = 0; pbit < 8; pbit++)
            printf(" %u", airoha_ppe_pon_lookup_tag(table, vn ? (vn == 1 ? v0 : v1) : AIROHA_PON_VID_ANY, pbit));
        putchar(' ');
        for (unsigned i = 0; i < sizeof(hwe); i++) printf("%02x", hwe.data[i]);
        putchar('\n');
        free(table);
    }
    return ferror(stdin) ? 1 : 0;
}
