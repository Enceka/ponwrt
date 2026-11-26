#!/usr/bin/env python3
"""Execute extracted production PON admission, learn and lower-path functions."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import subprocess

def function(text, signature):
    start = text.index(signature)
    pos = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[pos] == '{') - (text[pos] == '}')
        pos += 1
    return text[start:pos] + '\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = args.source.resolve()
    driver = source / 'drivers/net/ethernet/airoha'
    ppe = (driver/'airoha_ppe.c').read_text()
    eth = (driver/'airoha_eth.c').read_text()
    header = (driver/'airoha_eth.h').read_text()
    path = (source/'net/netfilter/nf_flow_table_path.c').read_text()
    begin = header.index('enum {\n\tAIROHA_FOE_STATE_INVALID,')
    end = header.index('static_assert(sizeof(struct airoha_foe_entry) == PPE_ENTRY_SIZE);', begin)
    end += len('static_assert(sizeof(struct airoha_foe_entry) == PPE_ENTRY_SIZE);')
    (out/'foe_types.inc').write_text(header[begin:end])
    functions = function(eth, 'bool airoha_is_valid_gdm_dev(')
    signatures = (
        'static bool airoha_ppe_ct_pon_flow(',
        'static bool airoha_ppe_ct_pon_dev_ready(',
        'static bool airoha_ppe_ct_pon_queue_ready(',
        'static bool airoha_ppe_ct_pon_flow_current(',
        'static bool airoha_ppe_foe_compare_entry(',
        'static void airoha_ppe_foe_insert_entry(',
        'static int airoha_ppe_foe_flow_commit_entry(',
        'static int airoha_ppe_ct_bridge_publish(',
        'static bool airoha_ppe_ct_ip_rule_supported(',
        'static int airoha_ppe_ct_ingress_dev(',
        'static bool airoha_ppe_ct_pon_rule_supported(',
    )
    functions += ''.join(function(ppe, name) for name in signatures)
    functions += function(path, 'struct nft_forward_info {') + ';\n'
    functions += function(path, 'static bool nft_is_valid_ether_device(')
    functions += function(path, 'static int nft_dev_path_info(')
    functions += function(eth, 'static int airoha_en7581_get_dev_from_sport(')
    template = (Path(__file__).parent/'admission_test.c').read_text()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    def run(label, content, expected):
        (out/'admission_production.inc').write_text(content)
        c = out/(label+'.c'); c.write_text(template)
        exe = out/label
        build = subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                                '-Wno-unused-but-set-variable', '-Wno-sign-compare', '-fsanitize=address,undefined', str(c), '-o', str(exe)],
                               capture_output=True, text=True)
        (out/(label+'.build.log')).write_text(build.stdout+build.stderr)
        assert build.returncode == 0, build.stderr
        result = subprocess.run([str(exe)], capture_output=True, text=True)
        (out/(label+'.log')).write_text(result.stdout+result.stderr)
        assert (result.returncode == 0) == expected, (label, result.returncode, result.stdout, result.stderr)
        return result.stdout.strip()
    result = run('admission', functions, True)
    mutations = {
        'omit-bind-gate': ('ppe->ct_host_ppe && !airoha_ppe_ct_pon_flow_current(ppe, e, skb)',
                           'ppe->ct_host_ppe && (airoha_ppe_ct_pon_flow_current(ppe, e, skb), false)'),
        'omit-carrier-check': ('netif_running(netdev) && netif_carrier_ok(netdev)',
                              '(netif_running(netdev), netif_carrier_ok(netdev), true)'),
        'permit-partial-meta': ('meta.mask->ingress_ifindex != U32_MAX ||\n\t    meta.mask->ingress_iftype', 'meta.mask->ingress_iftype'),
        'allow-hqos': ('!(airoha_qdma_rr(wan, AIROHA_PON_QDMA_HQOS_CFG) & AIROHA_PON_QDMA_HQOS_EN)',
                      '(airoha_qdma_rr(wan, AIROHA_PON_QDMA_HQOS_CFG), true)'),
        'omit-bind-queue-mode': ('!airoha_ppe_ct_pon_queue_ready(egress) ||', ''),
        'omit-input-device-check': ('skb->dev != netdev_from_priv(ingress)', 'false'),
        'omit-output-namespace-check': ('!net_eq(dev_net(skb->dev), dev_net(netdev_from_priv(egress)))',
                                        '(net_eq(dev_net(skb->dev), dev_net(netdev_from_priv(egress))), false)'),
        'omit-input-pon-admission-gate': ('!airoha_ppe_ct_pon_dev_ready(ingress) || !egress', '!egress'),
        'restrict-unrelated-flows': ('if (!pon)\n\t\treturn 0;', 'if (!pon) { /* deliberately apply PON restrictions */ }'),
        'permit-encapsulated-input': ('eth_hdr(skb)->h_proto != protocol', '((void)eth_hdr(skb)->h_proto, (void)protocol, false)'),
        'permit-stripped-vlan': ('skb_vlan_tag_present(skb) ||', '(skb_vlan_tag_present(skb), false) ||'),
        'ignore-unowned-pon-source': ('ingress != actual', 'false'),
        'omit-dsa-source-port': ('md->u.port_info.port_id != e->ct_ingress_dsa_port', 'false'),
        'omit-dsa-metadata-type': ('md->type != METADATA_HW_PORT_MUX ||', ''),
        'omit-gdm-source-device': ('skb->dev != netdev_from_priv(e->ct_ingress_gdm)', 'false'),
        'permit-pon-tuple-collision': ('airoha_ppe_ct_pon_flow(e) || airoha_ppe_ct_pon_flow(prev)', '(airoha_ppe_ct_pon_flow(e), airoha_ppe_ct_pon_flow(prev), false)'),
        'mix-pon-lan1-source': ('*port = sport - 1;', '*port = sport == 2 ? 3 : sport - 1;'),
    }
    for signature, label in ((
            'static bool airoha_ppe_ct_pon_rule_supported(', 'omit-hardware-admission-qualifier'),
            ('static bool airoha_ppe_ct_pon_flow_current(', 'omit-hardware-bind-qualifier')):
        original = function(ppe, signature)
        broken = original.replace('if (!READ_ONCE(ppe->ct_pon_qualified))',
                                  'if (((void)READ_ONCE(ppe->ct_pon_qualified), false))')
        assert original != broken
        mutations[label] = (original, broken)
    publisher = function(ppe, 'static int airoha_ppe_ct_bridge_publish(')
    broken_publisher = publisher[:publisher.index('{')] + '''{
        int err;
        lockdep_assert_held(&flow_offload_mutex);
        (void)rhashtable_remove_fast;
        err = airoha_ppe_foe_flow_commit_entry(eth->ppe, e);
        if (err)
            return err;
        return rhashtable_insert_fast(&eth->flow_table, &e->node,
                                     airoha_flow_table_params);
    }
'''
    mutations['learn-before-cookie'] = (publisher, broken_publisher)
    for label, (old, new) in mutations.items():
        assert functions.count(old) == 1, (label, functions.count(old))
        run(label, functions.replace(old, new), False)
    (out/'admission_production.inc').write_text(functions)
    report = dict(passed=True, result=result, negative_controls=list(mutations),
                  sanitizers=['address','undefined'], source=str(source),
                  source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in (driver/'airoha_ppe.c',driver/'airoha_eth.c',driver/'airoha_eth.h',source/'net/netfilter/nf_flow_table_path.c')})
    (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(result)
    print('PASS', len(mutations), 'runtime-caught negative controls')

if __name__ == '__main__':
    main()
