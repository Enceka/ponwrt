#!/usr/bin/env python3
"""Compile actual IFC lifecycle and CPU guards against fault-injected MMIO."""
import argparse, hashlib, json, shutil, subprocess
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
#define FE_PSE_PORT_CDM1 0
#define FE_PSE_PORT_CDM2 5
#define ETH_P_IP 0x800
#define ETH_P_IPV6 0x86dd
#define FLOW_DISSECTOR_KEY_VLAN 1
#define FLOW_DISSECTOR_KEY_CVLAN 2
#define FLOW_DISSECTOR_KEY_PPPOE 3
#define FLOW_DISSECTOR_KEY_ENC_CONTROL 4
struct iphdr {u8 bytes[20];};
struct airoha_gdm_dev;
struct net_device {int ifindex; struct airoha_gdm_dev *priv;};
struct airoha_qdma {int id;};
struct airoha_gdm_port {unsigned id;struct airoha_gdm_dev*devs[4];};
struct airoha_gdm_dev {unsigned nbq;struct airoha_gdm_port*port;struct airoha_qdma*qdma;struct net_device*netdev;};
struct airoha_soc {struct {u32(*get_vip_port)(struct airoha_gdm_port*,unsigned);int(*get_sport)(struct airoha_gdm_port*,unsigned);}ops;};
struct airoha_ppe;
struct airoha_eth {struct airoha_gdm_port *ports[4];struct airoha_soc*soc;struct airoha_qdma qdma[2];struct airoha_ppe*ppe;void*dev;
 int ct_route_lock,ifc_port_lock;bool ct_cpu_fallback,ct_ifc_cpu_port_failed;u32 ct_ifc_port_mask,ifc_port_desired;};
static int flow_offload_mutex=1,rcu;
#define lockdep_assert_held(p) assert(*(p))
static void spin_lock_bh(int*p){assert(!*p);*p=1;}
static void spin_unlock_bh(int*p){assert(*p);*p=0;}
static void rcu_read_lock(void){rcu++;}
static void rcu_read_unlock(void){assert(rcu);rcu--;}
#define rcu_dereference(x) (assert(rcu),x)
static struct net_device*netdev_from_priv(struct airoha_gdm_dev*d){return d->netdev;}
static struct airoha_gdm_dev*netdev_priv(struct net_device*d){return d->priv;}
static void*dev_net(struct net_device*d){return NULL;}
static bool net_eq(void*a,void*b){return a==b;}
struct flow_rule {int unused;};
struct basic {u16 n_proto;};struct meta {u32 ingress_ifindex;};
struct flow_match_basic {struct basic*mask,*key;};struct flow_match_meta {struct meta*mask,*key;};
static bool flow_rule_match_key(struct flow_rule*r,int k){return false;}
static void flow_rule_match_basic(struct flow_rule*r,struct flow_match_basic*m){static struct basic a,b;m->mask=&a;m->key=&b;}
static void flow_rule_match_meta(struct flow_rule*r,struct flow_match_meta*m){static struct meta a,b;m->mask=&a;m->key=&b;}
'''
pre+=rule+'\nstruct airoha_ppe {struct airoha_eth *eth;bool ct_host_ppe;'+ifc+'};\n'
pre+=r'''
static u32 regs[0x10000/4],table[3][64][9][3],saved[3][64][9][3];
static unsigned writes,reads,fail_write,fail_read,fail_mode,fail_from,reg_failure,reg_errors;
static u32 airoha_fe_rr(struct airoha_eth*e,u32 reg){assert(reg<sizeof regs);return regs[reg/4];}
static void airoha_fe_wr(struct airoha_eth*e,u32 reg,u32 value){
 assert(reg<sizeof regs);
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
#define read_poll_timeout(op,val,cond,delay,timeout,sleep,e,reg) ({(val)=op(e,reg);(cond)?0:-ETIMEDOUT;})
'''
s=(h/'airoha_eth.c').read_text();pre+=function(s,'static void airoha_ifc_update_ports(')+'\n'+function(s,'int airoha_ifc_scope_ports(')+'\n'
pre+='#include "airoha_ct_ifc.h"\n'
main=r'''
static struct airoha_eth eth;static struct airoha_ppe ppe;static struct airoha_gdm_port port;static struct airoha_gdm_dev gdm;static struct net_device netdev;
static u32 vip(struct airoha_gdm_port*p,unsigned q){return BIT(24);}
static int sport(struct airoha_gdm_port*p,unsigned q){return 24;}
static struct airoha_soc soc={.ops={.get_vip_port=vip,.get_sport=sport}};
static unsigned long cases,classifier_cases;
static void reset(void){
 memset(&eth,0,sizeof eth);memset(&ppe,0,sizeof ppe);memset(&port,0,sizeof port);memset(regs,0,sizeof regs);
 eth.soc=&soc;eth.ppe=&ppe;eth.ports[3]=&port;port.id=4;port.devs[0]=&gdm;
 netdev=(struct net_device){.ifindex=7,.priv=&gdm};gdm=(struct airoha_gdm_dev){.port=&port,.qdma=&eth.qdma[0],.netdev=&netdev};
 ppe.eth=&eth;ppe.ct_host_ppe=true;regs[0x1f4/4]=0xf7ffffff;regs[0x220/4]=0xaabbccdd;
 for(unsigned b=0;b<3;b++)for(unsigned r=0;r<64;r++)for(unsigned p=0;p<9;p++)for(unsigned w=0;w<3;w++)table[b][r][p][w]=0x1234+(b<<16)+(r<<8)+p*3+w;
 for(unsigned r=0;r<64;r++)table[2][r][2][0]&=~BIT(31);
 for(unsigned r=0;r<32;r++)table[1][r][0][1]&=~BIT(15);
 memcpy(saved,table,sizeof table);writes=reads=fail_write=fail_read=fail_from=fail_mode=reg_failure=reg_errors=0;assert(!rcu);
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
int main(void){
 reset();airoha_ppe_ct_ifc_start(&ppe);assert(ppe.ct_ifc.cfg_owned&&regs[0x200/4]==1);unsigned install_writes=writes,install_reads=reads;
 assert(install_writes==254);classifier();assert(!airoha_ppe_ct_ifc_stop(&ppe));unsigned restore_writes=writes-install_writes;restored();cases++;
 for(unsigned mode=0;mode<3;mode++)for(unsigned at=1;at<=install_writes;at++){
  reset();fail_write=at;fail_mode=mode;airoha_ppe_ct_ifc_start(&ppe);assert(!ppe.ct_ifc.cfg_owned);restored();cases++;
 }
 for(unsigned at=1;at<=install_reads;at++){
  reset();fail_read=at;airoha_ppe_ct_ifc_start(&ppe);assert(!ppe.ct_ifc.cfg_owned);restored();cases++;
 }
 for(unsigned mode=0;mode<3;mode++)for(unsigned at=1;at<=restore_writes;at++){
  reset();airoha_ppe_ct_ifc_start(&ppe);fail_write=writes+at;fail_mode=mode;assert(airoha_ppe_ct_ifc_stop(&ppe)<0);assert(ct_ifc_pending(&ppe)&&!regs[0x200/4]);
  fail_write=0;assert(!airoha_ppe_ct_ifc_stop(&ppe));restored();cases++;
 }
 for(unsigned at=1;at<=install_writes;at++){
  reset();fail_from=at;fail_mode=1;airoha_ppe_ct_ifc_start(&ppe);assert(!ppe.ct_ifc.cfg_owned&&!regs[0x200/4]&&ct_ifc_pending(&ppe));
  fail_from=0;assert(!airoha_ppe_ct_ifc_stop(&ppe));restored();cases++;
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
 printf("{\"passed\":true,\"lifecycle_cases\":%lu,\"classifier_cases\":%lu,\"install_writes\":%u,\"install_reads\":%u,\"restore_writes\":%u}\n",cases,classifier_cases,install_writes,install_reads,restore_writes);
}
'''
for name in ('airoha_ct_ifc.h','airoha_ct_ifc_cpu.h'):shutil.copy(h/name,b/name)
(b/'test.c').write_text(pre+main)
subprocess.run(['clang','-O1','-g','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-fsanitize=address,undefined','-I'+str(b),str(b/'test.c'),'-o',str(b/'test')],check=True)
r=subprocess.run([str(b/'test')],capture_output=True,text=True);(b/'stdout.txt').write_text(r.stdout);(b/'stderr.txt').write_text(r.stderr);r.check_returncode()
report=json.loads(r.stdout);report.update(sanitizers=['address','undefined'],sources={n:hashlib.sha256((h/n).read_bytes()).hexdigest() for n in ('airoha_ct_ifc.h','airoha_ct_ifc_cpu.h','airoha_eth.h','airoha_eth.c')});(b/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
