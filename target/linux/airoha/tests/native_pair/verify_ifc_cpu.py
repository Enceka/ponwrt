#!/usr/bin/env python3
"""Compile actual IFC lifecycle and CPU guards against fault-injected MMIO."""
import argparse, hashlib, json, shutil, signal, subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--host',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
h=a.host.resolve();b=a.output.resolve();b.mkdir(parents=True,exist_ok=True)
def function(s,sig):
 start=s.index(sig);brace=s.index('{',start);depth=0
 for end in range(brace,len(s)):
  depth+=(s[end]=='{')-(s[end]=='}')
  if not depth:return s[start:end+1]
eth=(h/'airoha_eth.h').read_text()
rule=eth[eth.index('#define AIROHA_CT_IFC_CPU_RULES'):eth.index('struct airoha_ct_native_pair;')]
ifc=eth[eth.index('\tstruct {\n\t\tu32 udf, udf_owned;'):eth.index('\tbool ct_host_ppe;')]
pre=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1u<<(n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define GENMASK(h,l) ((~0u>>(31-(h)))&(~0u<<(l)))
#define U16_MAX UINT16_MAX
#define U32_MAX UINT32_MAX
#define WRITE_ONCE(x,v) ((x)=(v))
#define READ_ONCE(x) (x)
#define __field_get(m,v) (((v)&(m))>>__builtin_ctz(m))
#define fls(v) (32-__builtin_clz(v))
#define dev_warn(...) ((void)0)
#define dev_err(...) ((void)0)
#define REG_FE_CSR_IFC_CFG 0x200
#define REG_FE_IFC_PORT_EN 0x1f4
#define REG_SP_DFT_CPORT(n) (0x20e0+((n)<<2))
#define SP_CPORT_DFT_MASK GENMASK(2,0)
#define SP_CPORT_MASK(n) GENMASK(3+((n)<<2),(n)<<2)
#define FE_IFC_EN_MASK 1
#define XSI_ETH_VIP_PORT_MASK BIT(24)
#define AIROHA_GDM4_IDX 4
#define AIROHA_GDM1_IDX 1
#define AIROHA_GDM2_IDX 2
#define FE_PSE_PORT_CDM1 0
#define FE_PSE_PORT_CDM2 5
#define FE_PSE_PORT_PPE1 4
#define FE_PSE_PORT_PPE2 8
#define FE_PSE_PORT_DROP 15
#define REG_GDM_FWD_CFG(id) (0x700+4*(id))
#define dev_err_ratelimited(...) ((void)0)
#define msecs_to_jiffies(x) (x)
#define ETH_P_IP 0x800
#define ETH_P_IPV6 0x86dd
#define FLOW_DISSECTOR_KEY_VLAN 1
#define FLOW_DISSECTOR_KEY_CVLAN 2
#define FLOW_DISSECTOR_KEY_PPPOE 3
#define FLOW_DISSECTOR_KEY_ENC_CONTROL 4
struct iphdr {u8 bytes[20];};
struct airoha_gdm_dev;
struct net_device {int ifindex; struct airoha_gdm_dev *priv;bool running;};
struct airoha_qdma {int id;};
struct airoha_gdm_port {unsigned id;struct airoha_gdm_dev*devs[4];};
struct airoha_gdm_dev {unsigned nbq;struct airoha_gdm_port*port;struct airoha_qdma*qdma;struct net_device*netdev;};
struct airoha_soc {struct {u32(*get_vip_port)(struct airoha_gdm_port*,unsigned);int(*get_sport)(struct airoha_gdm_port*,unsigned);}ops;};
struct airoha_ppe;
struct airoha_eth {struct airoha_gdm_port *ports[4];struct airoha_soc*soc;struct airoha_qdma qdma[2];struct airoha_ppe*ppe;void*dev;
 int ct_route_lock,ifc_port_lock;bool ct_cpu_fallback,ct_ifc_cpu_port_failed,ct_ifc_pon_ready,ct_ifc_command_pending;
 bool ct_ordinary_full_test,ct_cpu_routes_ready,ct_cpu_ifc_disabled;
 u16 ct_cpu_route_mask[4];u32 ct_ifc_port_mask,ifc_port_desired;};
static int flow_offload_mutex=1,ppe_lock,rcu;
static int *route_lock,*port_lock;
#define lockdep_assert_held(p) assert(*(p))
static void spin_lock_bh(int*p){assert(!*p);if(p==route_lock)assert(!*port_lock);*p=1;}
static void spin_unlock_bh(int*p){assert(*p);if(p==route_lock)assert(!*port_lock);*p=0;}
static void rcu_read_lock(void){rcu++;}
static void rcu_read_unlock(void){assert(rcu);rcu--;}
#define rcu_dereference(x) (assert(rcu),x)
static struct net_device*netdev_from_priv(struct airoha_gdm_dev*d){return d->netdev;}
static struct airoha_gdm_dev*netdev_priv(struct net_device*d){return d->priv;}
static bool netif_running(struct net_device*d){return d->running;}
static void*dev_net(struct net_device*d){return NULL;}
static bool net_eq(void*a,void*b){return a==b;}
struct flow_rule {int encap;u16 proto,proto_mask;u32 ingress,ingress_mask;};
struct basic {u16 n_proto;};struct meta {u32 ingress_ifindex;};
struct flow_match_basic {struct basic*mask,*key;};struct flow_match_meta {struct meta*mask,*key;};
static bool flow_rule_match_key(struct flow_rule*r,int k){return r->encap==k;}
static void flow_rule_match_basic(struct flow_rule*r,struct flow_match_basic*m){static struct basic a,b;a.n_proto=r->proto_mask;b.n_proto=r->proto;m->mask=&a;m->key=&b;}
static void flow_rule_match_meta(struct flow_rule*r,struct flow_match_meta*m){static struct meta a,b;a.ingress_ifindex=r->ingress_mask;b.ingress_ifindex=r->ingress;m->mask=&a;m->key=&b;}
'''
pre+=rule+'\nstruct airoha_ppe {struct airoha_eth *eth;bool ct_host_ppe,ct_stopping,ct_native_pairs;struct {bool health_stopping;int health_work;} ct_fe;'+ifc+'};\n'
pre+=r'''
static u32 regs[0x10000/4],table[3][64][9][3],saved[3][64][9][3];
static unsigned writes,reads,fail_write,fail_read,fail_mode,fail_from,reg_failure,reg_errors;
static unsigned port_writes,port_faults,port_fault_mode,gate_faults,schedules;
static int schedule_delayed_work(int*work,unsigned ticks){assert(work&&!ticks&&!*route_lock&&!*port_lock);schedules++;return 0;}
static u32 airoha_fe_rr(struct airoha_eth*e,u32 reg){assert(reg<sizeof regs);return regs[reg/4];}
static void airoha_fe_wr(struct airoha_eth*e,u32 reg,u32 value){
 assert(reg<sizeof regs);
 if(reg==REG_FE_IFC_PORT_EN){
  assert(e->ifc_port_lock);port_writes++;
  if(port_faults){port_faults--;if(port_fault_mode)regs[reg/4]=value^BIT(2);return;}
 }
 if(reg==REG_FE_CSR_IFC_CFG){assert(e->ct_route_lock);if(gate_faults){gate_faults--;return;}}
 if(reg_failure==reg){reg_failure=0;reg_errors++;return;}
 regs[reg/4]=value;
 if(reg!=0x204)return;
 unsigned bank=(value>>4)&7,row=(value>>16)&255,page=(value>>8)&15,n=bank==2?(page==0?2:page==1?3:1):2;
 assert(bank<3&&row<64&&page<9);
 if(value&2){
  writes++;bool fail=writes==fail_write||(fail_from&&writes>=fail_from);
  if(fail&&fail_mode==0)return;
  memcpy(table[bank][row][page],&regs[0x210/4],n*4);
  if(fail&&fail_mode==1)return;
  if(fail&&fail_mode==2)table[bank][row][page][bank==0?1:0]^=1;
 }else{
  reads++;if(reads==fail_read)return;
  memcpy(&regs[0x210/4],table[bank][row][page],n*4);
 }
 regs[reg/4]|=BIT(31);
}
static void airoha_fe_rmw(struct airoha_eth*e,u32 reg,u32 mask,u32 value){airoha_fe_wr(e,reg,(airoha_fe_rr(e,reg)&~mask)|value);}
static void airoha_fe_clear(struct airoha_eth*e,u32 reg,u32 mask){airoha_fe_rmw(e,reg,mask,0);}
#define read_poll_timeout(op,val,cond,delay,timeout,sleep,e,reg) ({(val)=op(e,reg);(cond)?0:-ETIMEDOUT;})
#define read_poll_timeout_atomic read_poll_timeout
'''
pre+='#include "airoha_ct_cpu_fallback.h"\n'
s=(h/'airoha_eth.c').read_text();pre+=function(s,'static void airoha_ifc_update_ports(')+'\n'+function(s,'int airoha_ifc_scope_ports(')+'\n'
pre+=function(s,'int airoha_ifc_scope_update(')+'\n'
pre+=function(s,'bool airoha_ifc_lan_ports_ready(')+'\n'
pre+='#include "airoha_ct_ifc.h"\n'
main=r'''
static struct airoha_eth eth;static struct airoha_ppe ppe;static struct airoha_gdm_port port;static struct airoha_gdm_dev gdm;static struct net_device netdev;
static u32 vip(struct airoha_gdm_port*p,unsigned q){return BIT(24);}
static int sport(struct airoha_gdm_port*p,unsigned q){return 24;}
static struct airoha_soc soc={.ops={.get_vip_port=vip,.get_sport=sport}};
static unsigned long cases,classifier_cases;
static void reset(void){
 assert(!ppe_lock&&flow_offload_mutex==1);
 memset(&eth,0,sizeof eth);memset(&ppe,0,sizeof ppe);memset(&port,0,sizeof port);memset(regs,0,sizeof regs);
 route_lock=&eth.ct_route_lock;port_lock=&eth.ifc_port_lock;
 eth.soc=&soc;eth.ppe=&ppe;eth.ports[3]=&port;port.id=4;port.devs[0]=&gdm;
 netdev=(struct net_device){.ifindex=7,.priv=&gdm};gdm=(struct airoha_gdm_dev){.port=&port,.qdma=&eth.qdma[0],.netdev=&netdev};
 ppe.eth=&eth;ppe.ct_host_ppe=true;regs[0x1f4/4]=0xf7ffffff;regs[0x220/4]=0xaabbccdd;
 for(unsigned b=0;b<3;b++)for(unsigned r=0;r<64;r++)for(unsigned p=0;p<9;p++)for(unsigned w=0;w<3;w++)table[b][r][p][w]=0x1234+(b<<16)+(r<<8)+p*3+w;
 for(unsigned r=0;r<64;r++)table[2][r][2][0]&=~BIT(31);
 for(unsigned r=0;r<32;r++)table[1][r][0][1]&=~BIT(15);
 memcpy(saved,table,sizeof table);writes=reads=fail_write=fail_read=fail_from=fail_mode=reg_failure=reg_errors=0;
 port_writes=port_faults=port_fault_mode=gate_faults=schedules=0;assert(!rcu);
}
static bool lan_covers(void){
 struct flow_rule rule={.proto=htons(ETH_P_IP),.proto_mask=htons(U16_MAX),.ingress=7,.ingress_mask=U32_MAX};
 return airoha_ppe_ct_ifc_covers(&ppe,&rule,&netdev);
}
static void scope_start(void){
 reset();airoha_ppe_ct_ifc_start(&ppe);
 assert(ppe.ct_ifc.cfg_owned&&eth.ct_ifc_port_mask==BIT(24)&&!eth.ct_ifc_pon_ready);
 assert(airoha_ifc_lan_ports_ready(&eth)&&lan_covers());
}
static void scope_tests(void){
 const u32 lan=BIT(24),both=BIT(24)|BIT(2),desired=0xf7ffffff;
 scope_start();unsigned old_writes=writes;
 assert(airoha_ifc_scope_update(&eth,lan,both)==-EACCES);
 assert(eth.ct_ifc_port_mask==lan&&regs[0x1f4/4]==lan&&!schedules);cases++;
 for(unsigned bit=0;bit<32;bit++){
  if(bit==24||bit==2)continue;
  scope_start();assert(airoha_ifc_scope_ports(&eth,lan|BIT(bit))==-EINVAL);
  assert(airoha_ifc_scope_update(&eth,lan,lan|BIT(bit))==-EINVAL);
  eth.ct_ifc_port_mask|=BIT(bit);regs[0x1f4/4]=eth.ifc_port_desired&eth.ct_ifc_port_mask;
  assert(!airoha_ifc_lan_ports_ready(&eth)&&!lan_covers());cases++;
 }
 for(unsigned invalid=0;invalid<2;invalid++){
  scope_start();assert(airoha_ifc_scope_update(&eth,lan,invalid?BIT(2):0)==-EINVAL);
  assert(airoha_ifc_scope_ports(&eth,both)==-EINVAL);cases++;
 }
 scope_start();eth.ct_ifc_pon_ready=true;
 assert(!airoha_ifc_scope_update(&eth,lan,both));
 assert(eth.ct_ifc_port_mask==both&&eth.ifc_port_desired==desired&&regs[0x1f4/4]==both);
 assert(writes==old_writes&&airoha_ifc_lan_ports_ready(&eth)&&lan_covers());
 assert(airoha_ifc_scope_update(&eth,lan,lan)==-ESTALE);
 unsigned previous_writes=port_writes;
 assert(!airoha_ifc_scope_update(&eth,both,both)&&port_writes==previous_writes);
 assert(!airoha_ifc_scope_update(&eth,both,lan)&&lan_covers());
 assert(eth.ifc_port_desired==desired&&writes==old_writes);cases++;
 for(unsigned bad=0;bad<9;bad++){
  scope_start();eth.ct_ifc_pon_ready=true;
  int expected=-ESHUTDOWN;
  switch(bad){
   case 0:eth.ppe=NULL;break;
   case 1:ppe.ct_ifc.cfg_owned=false;break;
   case 2:ppe.ct_host_ppe=false;break;
   case 3:ppe.ct_stopping=true;break;
   case 4:eth.ct_cpu_fallback=true;break;
   case 5:eth.ct_ifc_cpu_port_failed=true;break;
   case 6:regs[0x200/4]&=~FE_IFC_EN_MASK;break;
   case 7:eth.ct_ifc_port_mask=0;expected=-ENOENT;break;
   case 8:eth.ct_ifc_port_mask=both|BIT(3);expected=-EUCLEAN;break;
  }
  u32 before=eth.ct_ifc_port_mask;unsigned before_writes=port_writes;
  assert(airoha_ifc_scope_update(&eth,before,both)==expected);
  assert(eth.ct_ifc_port_mask==before&&port_writes==before_writes);
  if(bad!=2&&bad!=3)assert(!airoha_ifc_lan_ports_ready(&eth)&&!lan_covers());
  cases++;
 }
 for(unsigned bit=0;bit<32;bit++){
  scope_start();eth.ct_ifc_pon_ready=true;regs[0x1f4/4]^=BIT(bit);
  assert(airoha_ifc_scope_update(&eth,lan,both)==-EUCLEAN);
  assert(!airoha_ifc_lan_ports_ready(&eth)&&!lan_covers());cases++;
 }
 scope_start();eth.ct_ifc_pon_ready=true;assert(!airoha_ifc_scope_update(&eth,lan,both));
 eth.ct_ifc_pon_ready=false;assert(!airoha_ifc_lan_ports_ready(&eth)&&!lan_covers());
 assert(airoha_ifc_scope_update(&eth,both,both)==-EACCES);
 assert(!airoha_ifc_scope_update(&eth,both,lan)&&lan_covers());cases++;
 scope_start();eth.ct_ifc_pon_ready=true;assert(!airoha_ifc_scope_update(&eth,lan,both));
 for(unsigned bit=0;bit<32;bit++){
  u32 mask=BIT(bit);
  airoha_ifc_update_ports(&eth,mask,false);
  assert(eth.ifc_port_desired==(desired&~mask)&&regs[0x1f4/4]==((desired&~mask)&both));
  assert(lan_covers()==(bit!=24));
  airoha_ifc_update_ports(&eth,mask,true);
  assert(eth.ifc_port_desired==(desired|mask)&&regs[0x1f4/4]==((desired|mask)&both));
  airoha_ifc_update_ports(&eth,mask,!!(desired&mask));cases++;
 }
 airoha_ifc_update_ports(&eth,lan,false);assert(!airoha_ifc_scope_update(&eth,both,lan));
 assert(!regs[0x1f4/4]&&!airoha_ifc_lan_ports_ready(&eth));
 airoha_ifc_update_ports(&eth,lan,true);
 assert(regs[0x1f4/4]==lan&&lan_covers());cases++;
 for(unsigned shrink=0;shrink<2;shrink++)for(unsigned mode=0;mode<2;mode++){
  scope_start();eth.ct_ifc_pon_ready=true;
  if(shrink)assert(!airoha_ifc_scope_update(&eth,lan,both));
  u32 before=eth.ct_ifc_port_mask;port_faults=1;port_fault_mode=mode;
  assert(airoha_ifc_scope_update(&eth,before,shrink?lan:both)==-EIO);
  assert(regs[0x1f4/4]==before&&eth.ct_ifc_port_mask==before&&eth.ifc_port_desired==desired);
  assert(!eth.ct_cpu_fallback&&!eth.ct_ifc_cpu_port_failed&&!schedules&&lan_covers());cases++;
 }
 for(unsigned shrink=0;shrink<2;shrink++)for(unsigned worker=0;worker<3;worker++)for(unsigned gate=0;gate<2;gate++){
  scope_start();eth.ct_ifc_pon_ready=true;
  if(shrink)assert(!airoha_ifc_scope_update(&eth,lan,both));
  u32 before=eth.ct_ifc_port_mask;
  ppe.ct_native_pairs=worker!=0;ppe.ct_fe.health_stopping=worker==2;
  port_faults=2;port_fault_mode=1;gate_faults=gate;
  assert(airoha_ifc_scope_update(&eth,before,shrink?lan:both)==-EIO);
  assert(eth.ct_ifc_port_mask==before&&eth.ifc_port_desired==desired&&ppe.ct_ifc.cfg_owned);
  assert(eth.ct_ifc_cpu_port_failed&&eth.ct_cpu_fallback&&schedules==(worker==1));
  assert(!!(regs[0x200/4]&FE_IFC_EN_MASK)==!!gate);
  assert(!airoha_ifc_lan_ports_ready(&eth)&&!lan_covers());
  assert(airoha_ifc_scope_update(&eth,before,lan)==-ESHUTDOWN);
  assert(!eth.ct_route_lock&&!eth.ifc_port_lock);
  assert(!airoha_ppe_ct_ifc_stop(&ppe));
  assert(!eth.ct_ifc_port_mask&&!eth.ct_ifc_pon_ready&&regs[0x1f4/4]==desired);cases++;
 }
 scope_start();unsigned before_writes=port_writes;
 assert(airoha_ifc_scope_ports(&eth,0)==-EBUSY);
 assert(airoha_ifc_scope_ports(&eth,lan)==-EBUSY&&port_writes==before_writes);cases++;
 scope_start();assert(!airoha_ppe_ct_ifc_stop(&ppe));
 assert(!airoha_ifc_scope_ports(&eth,0));cases++;
 reset();regs[0x200/4]=FE_IFC_EN_MASK;
 assert(airoha_ifc_scope_ports(&eth,lan)==-EBUSY&&!eth.ct_ifc_port_mask);cases++;
 scope_start();eth.ct_ifc_pon_ready=true;assert(!airoha_ifc_scope_update(&eth,lan,both));
 assert(!ct_ifc_write_reg(&eth,REG_FE_CSR_IFC_CFG,FE_IFC_EN_MASK,0));
 port_faults=1;assert(airoha_ifc_scope_ports(&eth,0)==-EIO);
 assert(eth.ct_ifc_port_mask==both&&eth.ct_ifc_pon_ready&&eth.ifc_port_desired==desired);
 airoha_ifc_update_ports(&eth,BIT(7),false);
 assert(!airoha_ifc_scope_ports(&eth,0));
 assert(!eth.ct_ifc_port_mask&&!eth.ct_ifc_pon_ready&&regs[0x1f4/4]==(desired&~BIT(7)));cases++;
 scope_start();flow_offload_mutex=0;spin_lock_bh(&ppe_lock);
 assert(airoha_ifc_lan_ports_ready(&eth));
 spin_unlock_bh(&ppe_lock);flow_offload_mutex=1;cases++;
}
static void restored(void){
 assert(!ct_ifc_pending(&ppe));assert(regs[0x200/4]==0&&regs[0x1f4/4]==0xf7ffffff&&regs[0x220/4]==0xaabbccdd);
 assert(!memcmp(table,saved,sizeof table));assert(!eth.ct_route_lock&&!eth.ifc_port_lock&&!rcu);
}
static bool matches(unsigned row,u32*words){
 if(!(table[2][row][2][0]&BIT(31)))return false;
 for(unsigned p=0;p<9;p++)if((words[p]^table[0][row][p][0])&table[0][row][p][1])return false;
 return true;
}
static void classifier(void){
 for(unsigned et=0;et<65536;et++)for(unsigned enc=0;enc<8;enc++){
  u32 words[9]={BIT(24),0,0,0,0,et,0,((enc&1)?BIT(5):0)|((enc&2)?BIT(4):0)|((enc&4)?BIT(10):0),0};
  bool cpu=false;for(unsigned r=32;r<=50;r++)cpu|=matches(r,words);
  bool native=(et==0x800||et==0x86dd)&&!enc;
  assert(cpu==!native);classifier_cases++;
 }
 for(unsigned source=0;source<32;source++)for(unsigned et=0;et<65536;et+=257){
  u32 words[9]={BIT(source),0,0,0,0,et,0,BIT(5)|BIT(4)|BIT(10),0};
  bool cpu=false;for(unsigned r=32;r<=50;r++)cpu|=matches(r,words);assert(cpu==(source==24));classifier_cases++;
 }
 for(unsigned typ=1;typ<4;typ++)for(unsigned enc=0;enc<8;enc++)for(unsigned et=0;et<65536;et+=257){
  u32 words[9]={BIT(24),0,0,0,0,et,0,((enc&1)?BIT(5):0)|((enc&2)?BIT(4):0)|((enc&4)?BIT(10):0),typ<<6};
  for(unsigned r=32;r<=50;r++)assert(!matches(r,words));classifier_cases++;
 }
 for(unsigned r=32;r<=50;r++){
  assert(table[2][r][0][0]==0&&table[2][r][0][1]==0);
  assert(table[2][r][1][0]==0&&table[2][r][1][1]==0&&table[2][r][1][2]==0x400);
  assert(table[2][r][2][0]==0xd0000000);
 }
}
int main(int argc,char**argv){
 if(argc==2){
  reset();flow_offload_mutex=0;
  if(!strcmp(argv[1],"claim-without-flow-lock"))airoha_ifc_scope_ports(&eth,BIT(24));
  else airoha_ifc_scope_update(&eth,BIT(24),BIT(24));
  return 0;
 }
 reset();airoha_ppe_ct_ifc_start(&ppe);assert(ppe.ct_ifc.cfg_owned&&regs[0x200/4]==1);unsigned install_writes=writes,install_reads=reads;
 assert(install_writes==254);classifier();assert(!airoha_ppe_ct_ifc_stop(&ppe));unsigned restore_writes=writes-install_writes;restored();cases++;
 for(unsigned mode=0;mode<3;mode++)for(unsigned at=1;at<=install_writes;at++){
  reset();fail_write=at;fail_mode=mode;airoha_ppe_ct_ifc_start(&ppe);assert(!ppe.ct_ifc.cfg_owned);
  regs[0x204/4]|=BIT(31);fail_write=0;assert(!airoha_ppe_ct_ifc_stop(&ppe));restored();cases++;
 }
 for(unsigned at=1;at<=install_reads;at++){
  reset();fail_read=at;airoha_ppe_ct_ifc_start(&ppe);assert(!ppe.ct_ifc.cfg_owned);
  regs[0x204/4]|=BIT(31);fail_read=0;assert(!airoha_ppe_ct_ifc_stop(&ppe));restored();cases++;
 }
 for(unsigned mode=0;mode<3;mode++)for(unsigned at=1;at<=restore_writes;at++){
  reset();airoha_ppe_ct_ifc_start(&ppe);fail_write=writes+at;fail_mode=mode;assert(airoha_ppe_ct_ifc_stop(&ppe)<0);assert(ct_ifc_pending(&ppe)&&!regs[0x200/4]);
  fail_write=0;regs[0x204/4]|=BIT(31);assert(!airoha_ppe_ct_ifc_stop(&ppe));restored();cases++;
 }
 for(unsigned at=1;at<=install_writes;at++){
  reset();fail_from=at;fail_mode=1;airoha_ppe_ct_ifc_start(&ppe);assert(!ppe.ct_ifc.cfg_owned&&!regs[0x200/4]&&ct_ifc_pending(&ppe));
  fail_from=0;regs[0x204/4]|=BIT(31);assert(!airoha_ppe_ct_ifc_stop(&ppe));restored();cases++;
 }
 for(unsigned at=0;at<64;at++){
  reset();table[2][at][2][0]|=BIT(31);airoha_ppe_ct_ifc_start(&ppe);assert(!writes&&!ppe.ct_ifc.cfg_owned&&!ct_ifc_pending(&ppe));cases++;
 }
 reset();airoha_ppe_ct_ifc_start(&ppe);reg_failure=0x200;unsigned old_writes=writes;assert(airoha_ppe_ct_ifc_stop(&ppe)<0&&ppe.ct_ifc.cfg_owned&&writes==old_writes&&regs[0x200/4]);assert(!airoha_ppe_ct_ifc_stop(&ppe));restored();cases++;
 for(unsigned q=0;q<2;q++)for(unsigned cpu=0;cpu<16;cpu++){
  reset();gdm.qdma=&eth.qdma[q];regs[REG_SP_DFT_CPORT(3)/4]=cpu;airoha_ppe_ct_ifc_start(&ppe);assert(ppe.ct_ifc.cfg_owned==(cpu==(q?5:0)));assert(!airoha_ppe_ct_ifc_stop(&ppe));restored();cases++;
 }
 reset();gdm.qdma=NULL;airoha_ppe_ct_ifc_start(&ppe);restored();cases++;
 reset();eth.ct_cpu_fallback=true;airoha_ppe_ct_ifc_start(&ppe);restored();cases++;
 reset();eth.ct_ifc_cpu_port_failed=true;airoha_ppe_ct_ifc_start(&ppe);restored();cases++;
 reset();airoha_ppe_ct_ifc_start(&ppe);airoha_ifc_update_ports(&eth,BIT(1),false);assert(regs[0x1f4/4]==BIT(24));assert(!airoha_ppe_ct_ifc_stop(&ppe));assert(regs[0x1f4/4]==(0xf7ffffff&~BIT(1)));cases++;
 for(unsigned reg=0;reg<3;reg++){
  reset();reg_failure=reg==0?0x220:reg==1?0x1f4:0x200;airoha_ppe_ct_ifc_start(&ppe);assert(reg_errors&&!ppe.ct_ifc.cfg_owned);restored();cases++;
 }
 unsigned long lifecycle_cases=cases;scope_tests();
 printf("{\"passed\":true,\"lifecycle_cases\":%lu,\"scope_cases\":%lu,\"classifier_cases\":%lu,\"install_writes\":%u,\"install_reads\":%u,\"restore_writes\":%u}\n",lifecycle_cases,cases-lifecycle_cases,classifier_cases,install_writes,install_reads,restore_writes);
}
'''
for name in ('airoha_ct_ifc.h','airoha_ct_ifc_cpu.h','airoha_ct_cpu_fallback.h','airoha_ct_ifc_command.h'):shutil.copy(h/name,b/name)
(b/'test.c').write_text(pre+main)
subprocess.run(['clang','-O1','-g','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-fsanitize=address,undefined','-I'+str(b),str(b/'test.c'),'-o',str(b/'test')],check=True)
r=subprocess.run([str(b/'test')],capture_output=True,text=True);(b/'stdout.txt').write_text(r.stdout);(b/'stderr.txt').write_text(r.stderr)
(b/'exit-status.json').write_text(json.dumps({'returncode':r.returncode})+'\n');r.check_returncode()
lock_checks=[]
for mode in ('claim-without-flow-lock','update-without-flow-lock'):
 tested=subprocess.run([str(b/'test'),mode],capture_output=True,text=True)
 (b/(mode+'.stderr.txt')).write_text(tested.stderr)
 assert tested.returncode==-signal.SIGABRT and 'flow_offload_mutex' in tested.stderr,(mode,tested.returncode,tested.stderr)
 lock_checks.append(mode)
report=json.loads(r.stdout);report.update(lock_assertions=lock_checks,sanitizers=['address','undefined'],sources={n:hashlib.sha256((h/n).read_bytes()).hexdigest() for n in ('airoha_ct_ifc.h','airoha_ct_ifc_cpu.h','airoha_ct_cpu_fallback.h','airoha_eth.h','airoha_eth.c')});(b/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
