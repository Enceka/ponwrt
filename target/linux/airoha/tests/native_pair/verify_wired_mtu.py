from pathlib import Path
import json
import subprocess

r = Path(__file__).resolve().parent
source = (r / 'candidate/drivers/net/ethernet/airoha/airoha_ppe.c').read_text()
start = source.index('void airoha_ppe_set_xmit_frame_size(')
end = source.index('\nstatic void airoha_ppe_hw_init', start)
pre = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef uint32_t u32;
#define ARRAY_SIZE(a) ((int)(sizeof(a)/sizeof((a)[0])))
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define VLAN_ETH_HLEN 18
#define AIROHA_GDM4_IDX 4
#define REG_PPE_MTU(bank,index) ((bank)*16+(index))
#define FP_EGRESS_MTU_MASK(index) 0xffff
#define __field_prep(mask,value) ((value)&(mask))
struct net_device {u32 mtu;bool running;};
struct airoha_gdm_dev;
struct airoha_gdm_port {int id;struct airoha_gdm_dev*devs[3];};
struct airoha_ppe {bool ct_native_pairs;};
struct airoha_eth {struct airoha_ppe*ppe;bool enabled;};
struct airoha_qdma {int id;};
struct airoha_gdm_dev {struct airoha_eth*eth;struct airoha_gdm_port*port;struct airoha_qdma*qdma;struct net_device*netdev;int nbq;bool lan;};
static struct airoha_qdma*airoha_qdma_deref(struct airoha_gdm_dev*d){return d->qdma;}
static struct net_device*netdev_from_priv(struct airoha_gdm_dev*d){return d->netdev;}
static bool netif_running(struct net_device*d){return d->running;}
static bool airoha_is_lan_gdm_dev(struct airoha_gdm_dev*d){return d->lan;}
static bool airoha_ppe_is_enabled(struct airoha_eth*e,int b){assert(b==1);return e->enabled;}
static unsigned written[32],values[32];
static void airoha_fe_rmw(struct airoha_eth*e,unsigned reg,u32 mask,u32 value){assert(e&&mask==0xffff&&reg<32);written[reg]++;values[reg]=value;}
'''
main = r'''
int main(void){unsigned cases=0;struct airoha_ppe p={0};struct airoha_eth e={.ppe=&p};struct airoha_qdma q[2]={{0},{1}};struct airoha_gdm_port port={0};struct net_device n[3]={{1500,true},{9000,true},{9200,true}};struct airoha_gdm_dev d[3];
 for(int i=0;i<3;i++){d[i]=(struct airoha_gdm_dev){.eth=&e,.port=&port,.qdma=&q[i==2],.netdev=&n[i],.nbq=i,.lan=true};port.devs[i]=&d[i];}
 for(unsigned native=0;native<2;native++)for(unsigned enabled=0;enabled<2;enabled++)for(unsigned id=1;id<=4;id++)for(unsigned nbq=0;nbq<2;nbq++)for(unsigned running=0;running<2;running++)for(unsigned mtu=1280;mtu<=1500;mtu+=220){
  for(unsigned i=0;i<32;i++)written[i]=values[i]=0;
  p.ct_native_pairs=native;e.enabled=enabled;port.id=id;d[0].nbq=nbq;n[0].running=running;n[0].mtu=mtu;
  airoha_ppe_set_xmit_frame_size(&d[0]);unsigned bank=native&&enabled,index=id==4?7:id;
  assert(written[bank*16+index]==1&&values[bank*16+index]==9018);
  unsigned extra=native&&enabled&&id==4&&!nbq;
  if(extra)assert(written[index]==1&&values[index]==18+(running?mtu:0));
  unsigned count=0;for(unsigned i=0;i<32;i++)count+=written[i];assert(count==1+extra);cases++;
 }
 /* A live shrink followed by newly admitted small packets keeps the native
  * bank threshold at the new LAN1 MTU, even with another NBQ at 9000. */
 p.ct_native_pairs=e.enabled=true;port.id=4;d[0].nbq=0;n[0].running=true;
 for(unsigned mtu=1500;mtu>=1280;mtu-=220){n[0].mtu=mtu;airoha_ppe_set_xmit_frame_size(&d[0]);assert(values[7]==mtu+18&&values[23]==9018);cases++;}
 printf("PASS %u actual native wired MTU bank selection, shrink, open/stop and sibling-NBQ cases\n",cases);
}
'''
(r / 'build/verify_wired_mtu.c').write_text(pre + source[start:end] + main)
subprocess.run(['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                '-fsanitize=address,undefined', str(r / 'build/verify_wired_mtu.c'),
                '-o', str(r / 'build/verify_wired_mtu')], check=True)
p = subprocess.run([str(r / 'build/verify_wired_mtu')], capture_output=True, text=True, check=True)
print(p.stdout)
(r / 'build/wired-mtu-verification.json').write_text(json.dumps(
    dict(passed=True, result=p.stdout, sanitizers=['address', 'undefined']), indent=2) + '\n')
