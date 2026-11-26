#include "encap_max.inc"
#include "path_stubs.h"
#include "path_functions.inc"

static unsigned cases;
static unsigned ingress_cases;

static void check_ingress(struct flow_offload_tuple *tuple, unsigned vlans, bool ppp)
{
    struct nf_flow_match match = {0};
    struct airoha_gdm_dev dev = {0};
    struct net_device physical = {.priv = &dev};
    struct airoha_ppe ppe = {0};
    struct airoha_eth eth = {.ppe = &ppe, .registered = &dev};
    struct airoha_flow_data data = {0};
    struct flow_rule rule = {0};

    if (tuple->l3proto == AF_INET6) {
        tuple->src_v6.s6_addr[15] = 1;
        tuple->dst_v6.s6_addr[15] = 2;
    } else {
        tuple->src_v4.s_addr = htonl(0xc0000201);
        tuple->dst_v4.s_addr = htonl(0xc0000202);
    }
    tuple->src_port = htons(53001);
    tuple->dst_port = htons(443);
    for (unsigned proto = 0; proto < 2; proto++) {
        tuple->l4proto = proto ? IPPROTO_TCP : IPPROTO_UDP;
        memset(&match, 0, sizeof(match));
        assert(!nf_flow_rule_match(&match, tuple, NULL));
        bool ipv6 = tuple->l3proto == AF_INET6;
        assert(match.key.basic.n_proto == htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP));
        assert(match.key.basic.ip_proto == tuple->l4proto);
        assert(match.key.tp.src == tuple->src_port && match.key.tp.dst == tuple->dst_port);
        assert(!!(match.dissector.used_keys & BIT_ULL(FLOW_DISSECTOR_KEY_VLAN)) == !!vlans);
        assert(!!(match.dissector.used_keys & BIT_ULL(FLOW_DISSECTOR_KEY_CVLAN)) == (vlans == 2));
        assert(!!(match.dissector.used_keys & BIT_ULL(FLOW_DISSECTOR_KEY_PPPOE)) == ppp);
        if (vlans) assert(match.key.vlan.vlan_id == tuple->encap[0].id);
        if (vlans == 2) assert(match.key.cvlan.vlan_id == tuple->encap[1].id);
        if (ppp) {
            struct flow_offload_tuple second = *tuple;
            struct nf_flow_match other = {0};
            assert(match.dissector.offset[FLOW_DISSECTOR_KEY_PPPOE] == offsetof(struct nf_flow_key, pppoe));
            assert(match.key.pppoe.session_id == htons(tuple->encap[vlans].id));
            assert(match.key.pppoe.type == htons(ETH_P_PPP_SES));
            assert(match.key.pppoe.ppp_proto == htons(ipv6 ? PPP_IPV6 : PPP_IP));
            assert(match.mask.pppoe.session_id == htons(U16_MAX));
            assert(match.mask.pppoe.type == htons(U16_MAX) && match.mask.pppoe.ppp_proto == htons(U16_MAX));
            second.encap[vlans].id ^= 0x8000;
            assert(!nf_flow_rule_match(&other, &second, NULL));
            assert(other.key.pppoe.session_id == htons(second.encap[vlans].id));
            assert((other.key.pppoe.session_id ^ match.key.pppoe.session_id) & match.mask.pppoe.session_id);
            other.key.pppoe.session_id = match.key.pppoe.session_id;
            assert(!memcmp(&other, &match, sizeof(match)));
        }
        rule.keys = match.dissector.used_keys;
        for (unsigned ct = 0; ct < 2; ct++) {
            ppe.ct_host_ppe = ct;
            int rc = project_output_gate(&eth, &physical, false, match.key.control.addr_type, &rule, data);
            assert(rc == (ppp || (ct && ipv6 && vlans) ? -EOPNOTSUPP : 0));
        }
        ingress_cases++;
    }
}

static void check_invalid_stacks(int family)
{
    struct flow_offload_tuple tuple = {.l3proto = family, .l4proto = IPPROTO_TCP};
    struct nf_flow_match match;
    const u16 session = htons(ETH_P_PPP_SES), vlan = htons(ETH_P_8021Q);
    const struct { unsigned count; u16 proto[2], id[2]; unsigned flags; } stacks[] = {
        {1, {session}, {0}, 0}, {1, {session}, {U16_MAX}, 0},
        {2, {vlan, session}, {100, 0}, 0}, {2, {vlan, session}, {100, U16_MAX}, 0},
        {2, {session, vlan}, {7, 100}, 0}, {2, {session, session}, {7, 8}, 0},
        {2, {htons(0x88a8), session}, {100, 7}, 0}, {1, {session}, {7}, BIT(0)},
        {2, {vlan, session}, {100, 7}, BIT(1)}, {3, {vlan, session}, {100, 7}, 0},
    };
    for (unsigned index = 0; index < ARRAY_SIZE(stacks); index++) {
        tuple.encap_num = stacks[index].count;
        tuple.in_vlan_ingress = stacks[index].flags;
        for (unsigned layer = 0; layer < ARRAY_SIZE(tuple.encap); layer++) {
            tuple.encap[layer].proto = stacks[index].proto[layer];
            tuple.encap[layer].id = stacks[index].id[layer];
        }
        memset(&match, 0, sizeof(match));
        assert(nf_flow_rule_match(&match, &tuple, NULL) == -EOPNOTSUPP);
        ingress_cases++;
    }
    tuple.encap_num = 2;
    tuple.in_vlan_ingress = BIT(0);
    tuple.encap[0].proto = vlan;
    tuple.encap[0].id = 100;
    tuple.encap[1].proto = session;
    for (unsigned bound = 0; bound < 2; bound++) {
        tuple.encap[1].id = bound ? U16_MAX - 1 : 1;
        memset(&match, 0, sizeof(match));
        assert(!nf_flow_rule_match(&match, &tuple, NULL));
        assert(match.dissector.used_keys & BIT_ULL(FLOW_DISSECTOR_KEY_PPPOE));
        assert(!(match.dissector.used_keys & BIT_ULL(FLOW_DISSECTOR_KEY_VLAN)));
        assert(match.key.pppoe.session_id == htons(tuple.encap[1].id));
        ingress_cases++;
    }
}

static void run_case(int family, int direction, unsigned vlans, bool ppp,
                     u16 outer, u16 inner, bool split_outer)
{
    struct net_device physical={.ifindex=40,.dev_addr={2,1,2,3,4,5}}, upper={.ifindex=41,.dev_addr={2,1,2,3,4,6}};
    struct nft_flowtable ft={}; struct nf_conn ct={}; struct nf_flow_route route={};
    struct flow_offload flow={}; struct nf_flow_rule rule={}; struct net net={};
    struct airoha_pon_flow_table map={.count=4,.entries={
        {.vlan_id=outer,.pbit_mask=0xff,.tag=AIROHA_PON_QDMA_VALID|(7u<<16)|101},
        {.vlan_id=inner,.pbit_mask=0xff,.tag=AIROHA_PON_QDMA_VALID|(11u<<16)|202},
        {.vlan_id=AIROHA_PON_VID_ANY,.pbit_mask=0xff,.tag=AIROHA_PON_QDMA_VALID|(3u<<16)|303},
        {.vlan_id=outer,.pbit_mask=0x80,.tag=AIROHA_PON_QDMA_VALID|(13u<<16)|404}}};
    if (split_outer) map.entries[0].pbit_mask=0x7f;
    struct airoha_gdm_dev dev={.pon_flow_table=&map};
    struct airoha_flow_data data={}; u32 tag=0;
    memset(&active_stack,0,sizeof(active_stack));
    if(ppp) active_stack.path[active_stack.num_paths++]=(struct net_device_path){.type=DEV_PATH_PPPOE,.dev=&upper,.encap={.id=0x4321,.proto=htons(ETH_P_PPP_SES)}};
    if(vlans==2) active_stack.path[active_stack.num_paths++]=(struct net_device_path){.type=DEV_PATH_VLAN,.dev=&upper,.encap={.id=inner,.proto=htons(ETH_P_8021Q)}};
    if(vlans) active_stack.path[active_stack.num_paths++]=(struct net_device_path){.type=DEV_PATH_VLAN,.dev=&upper,.encap={.id=outer,.proto=htons(ETH_P_8021Q)}};
    active_stack.path[active_stack.num_paths++]=(struct net_device_path){.type=DEV_PATH_ETHERNET,.dev=&physical};
    int result=nft_dev_forward_path(&route,&ct,direction,&ft);
    cases++;
    if(vlans+ppp>NF_FLOW_TABLE_ENCAP_MAX) { assert(result==-ENOENT); printf("family=%d direction=%d PPP+QinQ rejected at production path capacity\n",family,direction); return; }
    assert(result==0);
    int reverse=!direction;
    flow.tuplehash[reverse].tuple.l3proto=family;
    route.tuple[reverse].xmit_type=FLOW_OFFLOAD_XMIT_DIRECT;
    assert(flow_offload_fill_route(&flow,&route,reverse)==0);
    struct flow_offload_tuple *tuple=&flow.tuplehash[reverse].tuple;
    assert(tuple->iifidx==physical.ifindex);
    assert(tuple->encap_num==(int)(vlans+ppp));
    if(vlans) assert(tuple->encap[0].id==outer);
    if(vlans==2) assert(tuple->encap[1].id==inner);
    if(ppp) assert(tuple->encap[vlans].id==0x4321);
    check_ingress(tuple, vlans, ppp);
    assert(nf_flow_rule_route_common(&net,&flow,direction,&rule)==0);
    assert(rule.count==vlans+ppp);
    assert(project_production_actions(&rule,&data)==0);
    assert(data.vlan.num==vlans && data.pppoe.num==ppp);
    if (family == AF_INET6 && (vlans || ppp)) {
        struct flow_rule parsed = {.action=rule};
        struct airoha_ppe ppe = {.ct_host_ppe=true};
        struct airoha_eth eth = {.ppe=&ppe, .registered=&dev};
        physical.priv = &dev;
        dev.flags = BIT(AIROHA_DEV_F_PON);
#define GATE(out, bridge) project_output_gate(&eth, out, bridge, FLOW_DISSECTOR_KEY_IPV6_ADDRS, &parsed, data)
        assert(GATE(&physical, false) == 0);
        parsed.action.actions[parsed.action.count++].id = FLOW_ACTION_VLAN_POP;
        assert(GATE(&physical, false) == -EOPNOTSUPP);
        parsed.action.count--;
        assert(GATE(&physical, true) == -EOPNOTSUPP);
        assert(GATE(&upper, false) == -EOPNOTSUPP);
        dev.flags = 0;
        assert(GATE(&physical, false) == -EOPNOTSUPP);
        dev.flags = BIT(AIROHA_DEV_F_PON);
        for (int key=FLOW_DISSECTOR_KEY_VLAN; key<=FLOW_DISSECTOR_KEY_ENC_CONTROL; key++) {
            parsed.keys = BIT(key);
            assert(GATE(&physical, false) == -EOPNOTSUPP);
        }
        parsed.keys = 0;
        if (vlans) {
            struct flow_action_entry *tag = &parsed.action.actions[0];
            assert(tag->id == FLOW_ACTION_VLAN_PUSH);
            tag->vlan.prio = 5;
            assert(GATE(&physical, false) == -EOPNOTSUPP);
            tag->vlan.prio = 0; tag->vlan.vid = VLAN_VID_MASK;
            assert(GATE(&physical, false) == -EOPNOTSUPP);
            tag->vlan.vid = outer;
        }
        if (ppp) {
            data.pppoe.sid = 0; assert(GATE(&physical, false) == -EOPNOTSUPP);
            data.pppoe.sid = U16_MAX; assert(GATE(&physical, false) == -EOPNOTSUPP);
            data.pppoe.sid = 0x4321;
        }
#undef GATE
    }
    if(vlans) assert(data.vlan.hdr[0].id==outer);
    if(vlans==2) assert(data.vlan.hdr[1].id==inner);
    if(ppp) assert(data.pppoe.sid==0x4321);
    result=airoha_ppe_pon_select_flow(&dev,&data,&tag);
    if(split_outer && vlans) assert(result==-EOPNOTSUPP);
    else { assert(result==0); assert((tag&0xffff)==(vlans?101:303)); assert(((tag>>16)&31)==(vlans?7:3)); }
    printf("family=%d direction=%d VLANs=%u PPP=%u outer=%u inner=%u split=%d result=%d gem=%u\n",family,direction,vlans,ppp,outer,inner,split_outer,result,tag&0xffff);
}
int main(void)
{
    for(int family=0;family<2;family++) for(int direction=0;direction<2;direction++)
      for(unsigned vlans=0;vlans<=2;vlans++) for(unsigned ppp=0;ppp<2;ppp++)
        for(unsigned swap=0;swap<2;swap++) for(unsigned split=0;split<2;split++)
          run_case(family?AF_INET6:AF_INET,direction,vlans,ppp,swap?200:100,swap?100:200,split);
    check_invalid_stacks(AF_INET);
    check_invalid_stacks(AF_INET6);
    printf("PASS: %u production path-to-selector and %u ingress-match scenarios\n", cases, ingress_cases);
    return 0;
}
