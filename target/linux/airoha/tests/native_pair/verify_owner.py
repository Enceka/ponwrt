"""Run the applied legacy bridge owner guard with the real cfg80211 helper."""
from pathlib import Path
import hashlib
import json
import subprocess

R = Path(__file__).resolve().parent
K = (R / 'candidate').resolve() if (R / 'candidate').exists() else R.parent / 'candidate'
B = R / 'build-owner'
B.mkdir(exist_ok=True)

def function(text, signature):
    a = text.index(signature)
    brace = text.index('{', a)
    depth = 0
    for z in range(brace, len(text)):
        depth += (text[z] == '{') - (text[z] == '}')
        if not depth:
            return text[a:z + 1]
    raise AssertionError(signature)

cfg = function((K / 'include/net/cfg80211.h').read_text(), 'static inline struct device *wiphy_dev(')
legacy = function((K / 'drivers/net/ethernet/airoha/airoha_ppe.c').read_text(), 'static int airoha_ppe_ct_bridge_paths(')
pre = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
typedef uint8_t u8;typedef uint16_t u16;
#define BR_STATE_FORWARDING 3
#define BR_ISOLATED 1
#define BR_PORT_LOCKED 2
#define BR_HAIRPIN_MODE 4
struct device {struct device *parent;};
struct wiphy {struct device dev;};
struct wireless_dev {struct wiphy *wiphy;};
struct net_device {struct wireless_dev *ieee80211_ptr;};
struct airoha_wdma_info {u8 idx,bss;u16 wcid;};
struct ethhdr {u8 h_source[6],h_dest[6];};
struct airoha_npu {struct {bool (*wlan_short_guard_ready)(struct airoha_npu*);}ops;};
struct airoha_eth {struct airoha_npu*npu;};
struct mac_key {u8 src[6],dst[6];};struct meta_key {int ingress_ifindex;};
struct flow_rule {struct mac_key mac;struct meta_key meta;};
struct flow_match_eth_addrs {struct mac_key*key;};struct flow_match_meta {struct meta_key*key;};
static struct net_device src,dst,master;
static int flow_offload_mutex=1,rcu,refs;
#define lockdep_assert_held(l) assert(*(l))
#define lockdep_is_held(l) (*(l))
#define rcu_dereference_protected(p,c) (assert(c),p)
static void rcu_read_lock(void){rcu++;}static void rcu_read_unlock(void){assert(rcu);rcu--;}
static void flow_rule_match_eth_addrs(struct flow_rule*r,struct flow_match_eth_addrs*m){m->key=&r->mac;}
static void flow_rule_match_meta(struct flow_rule*r,struct flow_match_meta*m){m->key=&r->meta;}
static bool ether_addr_equal(const u8*a,const u8*b){return !memcmp(a,b,6);}
static int dev_net(struct net_device*d){assert(d);return 1;}
static struct net_device*dev_get_by_index(int n,int i){assert(n==1&&i==1);refs++;return &src;}
static void dev_put(struct net_device*d){assert(d==&src&&refs);refs--;}
static struct net_device*netdev_master_upper_dev_get_rcu(struct net_device*d){assert(d&&rcu);return &master;}
static bool netif_is_bridge_master(struct net_device*d){return d==&master;}
static bool br_vlan_enabled(struct net_device*d){assert(d==&master);return false;}
static int br_port_get_stp_state(struct net_device*d){assert(d);return BR_STATE_FORWARDING;}
static bool br_port_flag_is_set(struct net_device*d,int f){assert(d&&f);return false;}
static int airoha_ppe_get_wdma_info(struct net_device*d,const u8*a,struct airoha_wdma_info*w,bool bridge){assert(a&&bridge);*w=(struct airoha_wdma_info){.idx=d==&src?0:1,.bss=1,.wcid=1};return 0;}
static bool ready(struct airoha_npu*n){return !!n;}
'''
main = r'''
int main(void){
 struct device bus1={},bus2={},radio1={.parent=&bus1},radio2={.parent=&bus1};
 struct wiphy phy1={.dev.parent=&radio1},phy2={.dev.parent=&radio1};
 struct wireless_dev wd1={.wiphy=&phy1},wd2={.wiphy=&phy2};
 struct airoha_npu npu={.ops.wlan_short_guard_ready=ready};struct airoha_eth eth={.npu=&npu};
 struct ethhdr hdr={.h_source={2},.h_dest={4}};
 struct flow_rule rule={.mac={.src={2},.dst={4}},.meta.ingress_ifindex=1};
 struct airoha_wdma_info a,b;
 src.ieee80211_ptr=&wd1;dst.ieee80211_ptr=&wd1;
 assert(airoha_ppe_ct_bridge_paths(&eth,&rule,&dst,&hdr,&a,&b)==0);
 dst.ieee80211_ptr=&wd2;
 assert(airoha_ppe_ct_bridge_paths(&eth,&rule,&dst,&hdr,&a,&b)==0);
 phy2.dev.parent=&radio2;
 assert(airoha_ppe_ct_bridge_paths(&eth,&rule,&dst,&hdr,&a,&b)==-EOPNOTSUPP);
 radio2.parent=&bus2;
 assert(airoha_ppe_ct_bridge_paths(&eth,&rule,&dst,&hdr,&a,&b)==-EOPNOTSUPP);
 assert(!rcu&&!refs);
 puts("PASS 4 actual legacy bridge physical-radio identity cases");
}
'''
source = pre + cfg + '\n' + legacy + '\n' + main
(B / 'verify_owner.c').write_text(source)
subprocess.run(['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                str(B / 'verify_owner.c'), '-o', str(B / 'verify_owner')], check=True)
p = subprocess.run([str(B / 'verify_owner')], capture_output=True, text=True, check=True)
(B / 'verification.json').write_text(json.dumps(dict(passed=True, cases=4, result=p.stdout,
    cfg80211_helper_sha256=hashlib.sha256(cfg.encode()).hexdigest(),
    bridge_paths_sha256=hashlib.sha256(legacy.encode()).hexdigest(),
    sanitizers=['address','undefined']), indent=2)+'\n')
print(p.stdout, end='')
