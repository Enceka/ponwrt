#!/usr/bin/env python3
"""Execute extracted production PON admission, learn and lower-path functions."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import signal
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[4]
sys.path.insert(0, str(HERE.parent / 'npu_ingress'))
from source_binding import SourceBinding, exact_hunks, HUNK

PATCH = '999-zz3-net-airoha-admit-observed-pon-software-candidates.patch'


def reverse_section(section):
    lines = section.splitlines(True)
    result = [lines[0].replace('--- a/', '--- b/', 1),
              lines[1].replace('+++ b/', '+++ a/', 1)]
    for line in lines[2:]:
        match = HUNK.match(line)
        if match:
            line = '@@ -' + match[3] + ',' + (match[4] or '1') + ' +' + match[1] + ',' + (match[2] or '1') + ' @@\n'
        elif line.startswith('+'):
            line = '-' + line[1:]
        elif line.startswith('-'):
            line = '+' + line[1:]
        result.append(line)
    return ''.join(result)

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
    parser.add_argument('--path-source', type=Path,
                        help='nf_flow_table_path.c when the driver snapshot omits netfilter')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = args.source.resolve()
    driver = source / 'drivers/net/ethernet/airoha'
    ppe = (driver/'airoha_ppe.c').read_text()
    eth = (driver/'airoha_eth.c').read_text()
    header = (driver/'airoha_eth.h').read_text()
    path_source = (args.path_source or source/'net/netfilter/nf_flow_table_path.c').resolve()
    path = path_source.read_text()
    binding = SourceBinding(REPOSITORY/'target/linux/airoha/patches-6.18', out, PATCH)
    headers = ('airoha_npu_auth_publish.h', 'airoha_npu_flow_key.h',
               'airoha_npu_flow_observe.h', 'npu_auth_mailbox_abi.h')
    binding.bind(driver, headers)
    for name in headers:
        (out/name).write_bytes((driver/name).read_bytes())
    replay = out/'replay'
    replay_driver = replay/'drivers/net/ethernet/airoha'
    replay_driver.mkdir(parents=True)
    sections = list(binding.sections(binding.snapshot[PATCH], ('airoha_ppe.c', 'airoha_eth.h')))
    assert {name for name, added, section in sections} == {'airoha_ppe.c', 'airoha_eth.h'}
    for name, added, section in sections:
        assert not added
        data = (driver/name).read_bytes()
        exact_hunks(data, reverse_section(section))
        (replay_driver/name).write_bytes(data)
    for label, reverse in (('reverse', True), ('forward', False)):
        selected = ''.join(reverse_section(section) if reverse else section
                           for name, added, section in sections)
        for name, added, section in sections:
            exact_hunks((replay_driver/name).read_bytes(), reverse_section(section) if reverse else section)
        result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1'],
                                input=selected, cwd=replay, capture_output=True, text=True)
        log = result.stdout + result.stderr
        (out/('zz3-' + label + '.log')).write_text(log)
        assert not result.returncode and not any(word in log.lower() for word in ('fuzz', 'offset', 'failed')), log
    for name, added, section in sections:
        assert (replay_driver/name).read_bytes() == (driver/name).read_bytes()
    begin = header.index('enum {\n\tAIROHA_FOE_STATE_INVALID,')
    end = header.index('static_assert(sizeof(struct airoha_foe_entry) == PPE_ENTRY_SIZE);', begin)
    end += len('static_assert(sizeof(struct airoha_foe_entry) == PPE_ENTRY_SIZE);')
    (out/'foe_types.inc').write_text(header[begin:end])
    functions = function(eth, 'bool airoha_is_valid_gdm_dev(')
    signatures = (
        'static bool airoha_ppe_ct_pon_flow(',
        'static bool airoha_ppe_ct_pon_dev_ready(',
        'static bool airoha_ppe_ct_pon_queue_ready(',
        'static bool airoha_ppe_ct_wlan_dest(',
        'static u32 airoha_ppe_ct_epoch_locked(',
        'static u32 airoha_ppe_ct_route_wlan_epoch(',
        'static bool airoha_ppe_ct_pon_flow_current(',
        'static bool airoha_ppe_ct_flow_bank_matches(',
        'static bool airoha_ppe_foe_compare_entry(',
        'static void airoha_ppe_foe_insert_entry(',
        'static int airoha_ppe_foe_flow_commit_entry(',
        'static int airoha_ppe_ct_bridge_publish(',
        'static bool airoha_ppe_ct_ip_rule_supported(',
        'static int airoha_ppe_ct_ingress_dev(',
        'static bool airoha_ppe_ct_pon_rule_supported(',
    )
    signatures = signatures[:-1] + ('static bool airoha_ppe_ct_pon_candidate_supported(',) + signatures[-1:]
    functions += ''.join(function(ppe, name) for name in signatures)
    functions += function(ppe, 'void airoha_ppe_pon_observe_frame(')
    replace = function(ppe, 'static int airoha_ppe_flow_offload_replace(')
    fields = replace[replace.index('\te->egress_dev = egress_dev;'):replace.index('\te->ct_bridge_generation =')]
    publication = replace[replace.index('\tif (bridge || (eth->ppe->ct_host_ppe && airoha_ppe_ct_pon_flow(e)))'):replace.index('\n\terr = airoha_ppe_foe_flow_commit_entry(eth->ppe, e);')]
    functions += '''static int candidate_publish(struct airoha_eth *eth,
        struct airoha_flow_table_entry *e, struct airoha_gdm_dev *ingress_dev,
        struct airoha_gdm_dev *egress_dev, bool bridge)
{
    int ingress_ifindex = ingress_dev ? ingress_dev->netdev->ifindex : 0;
    int ingress_dsa_port = -1, err;
''' + fields + publication + '''
    return -EOPNOTSUPP;
free_entry:
    return err;
}
'''
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
                                '-Wno-unused-but-set-variable', '-Wno-sign-compare', '-Wno-address', '-fsanitize=address,undefined',
                                '-I', str(Path(__file__).parent), str(c), '-o', str(exe)],
                               capture_output=True, text=True)
        (out/(label+'.build.log')).write_text(build.stdout+build.stderr)
        assert build.returncode == 0, build.stderr
        result = subprocess.run([str(exe)], capture_output=True, text=True)
        (out/(label+'.log')).write_text(result.stdout+result.stderr)
        assert (result.returncode == 0) == expected, (label, result.returncode, result.stdout, result.stderr)
        if not expected:
            assert result.returncode == -signal.SIGABRT and 'assert' in result.stderr.lower(), (label, result.returncode, result.stderr)
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
        'accept-reused-wcid': ('e->ct_dest.epoch != airoha_ppe_ct_route_wlan_epoch(ppe, &e->data)',
                               '!airoha_ppe_ct_route_wlan_epoch(ppe, &e->data)'),
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
        'learn-owned-bank': ('(ppe->ct_npu_owner &&\n\t      (hash >= PPE_SRAM_NUM_ENTRIES ||\n\t       airoha_ppe_npu_bank0_owned(ppe)))', '(airoha_ppe_npu_bank0_owned(ppe), false)'),
        'learn-outside-sram': ('hash >= airoha_ppe_get_total_sram_num_entries(ppe)',
                              '((void)airoha_ppe_get_total_sram_num_entries(ppe), false)'),
        'ignore-physical-bank': ('bank != (rx_wlan ? 0 : 1)', '((void)bank, false)'),
        'bridge-from-wired': ('if (entry->ct_bridge)\n\t\treturn rx_wlan;',
                             'if (entry->ct_bridge)\n\t\treturn true;'),
        'ignore-pon-source-class': ('return wired != rx_wlan;', '(void)wired; return true;'),
        'accept-unspecified-pon-source': ('!entry->pon_ingress_dev && !entry->ct_ingress_ifindex', 'false'),
        'skip-bank-check-at-bind': ('!airoha_ppe_ct_flow_bank_matches(ppe, e, hash, rx_wlan)',
                                   '(airoha_ppe_ct_flow_bank_matches(ppe, e, hash, rx_wlan), false)'),
        'retire-another-subflow': ('if (e->hash != hash)', 'if (false)'),
        'ct-l2-fallback': ('l2_lookup:\n\tif (ppe->ct_host_ppe)\n\t\tgoto unlock;', 'l2_lookup:'),
    }
    for signature, label in ((
            'static bool airoha_ppe_ct_pon_rule_supported(', 'omit-hardware-admission-qualifier'),
            ('static bool airoha_ppe_ct_pon_flow_current(', 'omit-hardware-bind-qualifier')):
        original = function(ppe, signature)
        broken = original.replace('!READ_ONCE(ppe->ct_pon_qualified)',
                                  '((void)READ_ONCE(ppe->ct_pon_qualified), false)')
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
    candidate = function(ppe, 'static bool airoha_ppe_ct_pon_candidate_supported(')
    for label, old, new in (
        ('candidate-profile', '!ppe->eth->ct_pon_full ||', ''),
        ('candidate-host', '!ppe->ct_host_ppe ||', ''),
        ('candidate-native', '!ppe->ct_native_pairs ||', ''),
        ('candidate-stopping', 'READ_ONCE(ppe->ct_stopping) ||', ''),
        ('candidate-bridge', 'bridge ||', '(bridge && false) ||'),
        ('candidate-ingress-local', '!airoha_is_valid_gdm_dev(ppe->eth, ingress) ||', ''),
        ('candidate-egress-local', '!airoha_is_valid_gdm_dev(ppe->eth, egress) ||', ''),
        ('candidate-input-pon', '!test_bit(AIROHA_DEV_F_PON, &ingress->flags) ||', ''),
        ('candidate-output-pon', 'test_bit(AIROHA_DEV_F_PON, &egress->flags) ||', ''),
        ('candidate-gdm2', 'ingress->port->id != AIROHA_GDM2_IDX ||', ''),
        ('candidate-nbq', 'ingress->nbq ||', ''),
        ('candidate-link-ops', '!ingress->pon_link_ops ||', ''),
        ('candidate-link-private', '!ingress->pon_link_priv ||', ''),
        ('candidate-wan', '!airoha_ppe_ct_pon_queue_ready(ingress) ||', ''),
        ('candidate-output-running', '!netif_running(netdev_from_priv(egress)) ||', ''),
        ('candidate-output-carrier', '!netif_carrier_ok(netdev_from_priv(egress)) ||', ''),
        ('candidate-namespace', '!net_eq(dev_net(netdev_from_priv(ingress)), dev_net(netdev_from_priv(egress))) ||', ''),
        ('candidate-ipv6', 'control.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS', 'true'),
        ('candidate-masks', '!airoha_ppe_ct_ip_rule_supported(rule, false)', 'false'),
    ):
        assert candidate.count(old) == 1, label
        mutations[label] = (candidate, candidate.replace(old, new))
    mutations['candidate-flag'] = ('e->pon_candidate = eth->ct_pon_full && e->pon_ingress_dev;',
                                   'e->pon_candidate = false;')
    mutations['candidate-current-gate'] = ('e->pon_candidate || !READ_ONCE(ppe->ct_pon_qualified)',
                                         '!READ_ONCE(ppe->ct_pon_qualified)')
    mutations['candidate-bank-gate'] = ('if (entry->pon_candidate)\n\t\treturn false;', '')
    mutations['candidate-nat-observation'] = ('tuple.ipv4.orig_tuple.src_ip = identity.source_ip;',
                                            'tuple.ipv4.new_tuple.src_ip = identity.source_ip;')
    mutations['candidate-conflict'] = ('entry->pon_ingress_conflict = true;',
                                      'entry->pon_ingress_conflict = false;')
    for label, (old, new) in mutations.items():
        assert functions.count(old) == 1, (label, functions.count(old))
        run(label, functions.replace(old, new), False)
    (out/'admission_production.inc').write_text(functions)
    binding.verify_unchanged()
    assert binding.read_patches()[PATCH] == binding.snapshot[PATCH]
    report = dict(passed=True, result=result, negative_controls=list(mutations),
                  source_binding=binding.report(), zz3_reverse_replay=dict(passed=True, fuzz=0, offset=0),
                  zz3_sha256=hashlib.sha256(binding.snapshot[PATCH]).hexdigest(), path_source=str(path_source),
                  extracted_functions_sha256=hashlib.sha256(functions.encode()).hexdigest(),
                  sanitizers=['address','undefined'], source=str(source),
                  source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in (driver/'airoha_ppe.c',driver/'airoha_eth.c',driver/'airoha_eth.h',path_source)},
                  test_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in (Path(__file__), Path(__file__).with_name('admission_test.c'),
                                         Path(__file__).with_name('learning_isolation_test.inc'))})
    (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(result)
    print('PASS', len(mutations), 'runtime-caught negative controls')

if __name__ == '__main__':
    main()
