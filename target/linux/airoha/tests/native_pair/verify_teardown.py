"""Exercise extracted cleanup/remove ordering and fixed-DT provider publication."""
from pathlib import Path
import json
import subprocess

root = Path(__file__).resolve().parent
sources = root / 'candidate/drivers/net/ethernet/airoha'
eth = (sources / 'airoha_eth.c').read_text()
ppe = (sources / 'airoha_ppe.c').read_text()
npu = (sources / 'airoha_npu.c').read_text()

def function(text, name):
    pos = text.index(name + '(')
    start = text.rfind('\nstatic ', 0, pos) + 1
    begin = text.index('{', pos)
    end, depth = begin + 1, 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

pre = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#define WARN_ON(x) (x)
#define dev_err(...) ((void)0)
struct net_device {struct {void*of_node;}dev;};
struct airoha_qdma {int id;};
struct airoha_gdm_dev {struct net_device netdev;void*phylink;};
struct airoha_gdm_port {struct airoha_gdm_dev*devs[2];};
struct airoha_eth {struct airoha_qdma qdma[2];struct airoha_gdm_port*ports[4];void*napi_dev;void*dev;};
struct platform_device {struct airoha_eth*eth;};
static int shutdown_error,deinit_error,preflights,deinits,cleaned,stopped,tx,unregistered,metadata,freed;
static bool allow_cleanup;
static int airoha_ppe_ct_shutdown(struct airoha_eth*e){assert(e);preflights++;return shutdown_error;}
static int airoha_ppe_deinit(struct airoha_eth*e){assert(e);deinits++;if(deinit_error)return deinit_error;allow_cleanup=true;return 0;}
static void airoha_qdma_cleanup(struct airoha_eth*e,struct airoha_qdma*q){assert(e&&q&&allow_cleanup);cleaned++;}
static struct airoha_eth*platform_get_drvdata(struct platform_device*p){return p->eth;}
static void platform_set_drvdata(struct platform_device*p,void*v){assert(!v);p->eth=v;}
static void airoha_qdma_stop_napi(struct airoha_qdma*q){assert(q&&preflights&&!shutdown_error);stopped++;}
static void airoha_qdma_tx_cleanup(struct airoha_qdma*q){assert(q&&preflights&&!shutdown_error);tx++;}
static struct net_device*netdev_from_priv(struct airoha_gdm_dev*d){return &d->netdev;}
static void unregister_netdev(struct net_device*n){assert(n&&preflights&&!shutdown_error);unregistered++;}
static void phylink_destroy(void*p){assert(p);}
static void of_node_put(void*p){(void)p;}
static void airoha_metadata_dst_free(struct airoha_gdm_port*p){assert(p&&preflights&&!shutdown_error);metadata++;}
static void free_netdev(void*p){assert(p&&allow_cleanup&&cleaned==2);freed++;}
static void reset(void){shutdown_error=deinit_error=preflights=deinits=cleaned=stopped=tx=unregistered=metadata=freed=0;allow_cleanup=false;}
'''
main = r'''
int main(void){
 unsigned cases=0;struct airoha_eth e={.napi_dev=(void*)1};struct platform_device p={.eth=&e};
 struct airoha_gdm_dev dev={0};struct airoha_gdm_port port={.devs={&dev,NULL}};e.ports[0]=&port;
 const int errors[]={-EAGAIN,-ETIMEDOUT,-EIO,-EOPNOTSUPP};
 for(unsigned i=0;i<4;i++){
  reset();deinit_error=errors[i];assert(airoha_hw_cleanup(&e)==errors[i]&&deinits==1&&!cleaned&&!allow_cleanup);cases++;
  reset();shutdown_error=errors[i];airoha_remove(&p);
  assert(preflights==1&&!deinits&&!cleaned&&!stopped&&!tx&&!unregistered&&!metadata&&!freed&&p.eth==&e);cases++;
 }
 reset();assert(!airoha_hw_cleanup(&e)&&deinits==1&&cleaned==2);cases++;
 reset();airoha_remove(&p);assert(preflights==1&&deinits==1&&stopped==2&&tx==2&&cleaned==2&&unregistered==1&&metadata==1&&freed==1&&!p.eth);cases++;
 printf("PASS %u extracted cleanup and remove ordering cases\n",cases);
}
'''
build = root / 'build/teardown'
build.mkdir(exist_ok=True)
(build / 'test.c').write_text(pre + function(eth, 'airoha_hw_cleanup') + function(eth, 'airoha_remove') + main)
subprocess.run(['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-sign-compare', '-fsanitize=address,undefined',
                str(build / 'test.c'), '-o', str(build / 'test')], check=True)
result = subprocess.check_output([str(build / 'test')], text=True)
assert '.suppress_bind_attrs = true' in eth and '.suppress_bind_attrs = true' in npu
probe = function(eth, 'airoha_probe')
assert probe.index('airoha_register_gdm_devices(eth)') < probe.index('airoha_ppe_ct_prepare(eth)')
setup = function(ppe, 'airoha_ppe_offload_setup')
assert setup.index('DEV_STATE_REGISTERED') < setup.index('airoha_ppe_npu_get(eth)')
get = ppe[ppe.index('struct airoha_ppe_dev *airoha_ppe_get_dev('):ppe.index('EXPORT_SYMBOL_GPL(airoha_ppe_get_dev)')]
assert '!test_bit(DEV_STATE_REGISTERED, &eth->state)' in get and 'err = -EPROBE_DEFER;' in get
(root / 'build/teardown-verification.json').write_text(json.dumps(dict(passed=True, cases=10,
    result=result.strip(), provider_contract_checks=4, sanitizers=['address', 'undefined']), indent=2) + '\n')
print(result, end='')
