#!/usr/bin/env python3
"""Compile actual ABI3 native header plus IFC table/owner lifetime under ASan."""
import hashlib
import json
from pathlib import Path
import shutil
import signal
import subprocess

import argparse
ap=argparse.ArgumentParser()
ap.add_argument('--fixtures',type=Path,default=Path(__file__).resolve().parent)
ap.add_argument('--kernel',type=Path,required=True)
ap.add_argument('--header',type=Path)
ap.add_argument('--output',type=Path,required=True)
a=ap.parse_args()
if a.header is None: a.header=a.kernel/'drivers/net/ethernet/airoha/airoha_ct_fe_native.h'
R=a.fixtures.resolve();B=a.output.resolve();B.mkdir(parents=True,exist_ok=True);K=a.kernel.resolve()
H = K / 'drivers/net/ethernet/airoha'
old = (R / 'verify_pair.c').read_text()
pre = 'struct work_struct {int unused;}; struct delayed_work {struct work_struct work;};\n' + old[:old.index('#include "airoha_ct_native_pair.h"')]
fixture = old[old.index('static struct airoha_ct_native_pair pairs[32];'):old.index('int main(void)')]
pre = pre.replace('u32 ct_pair_token,ct_wlan_epoch', '''struct { u32 tcam[2][9][2],action[2][3][3],epoch,pending_epoch,drain_flow,drain_tb;
 u64 generation,pending_generation; bool saved,touched,active,armed,pending,arm_pending,health_stopping,drain_pending; struct delayed_work health_work; } ct_fe;
 struct {bool cfg_owned;struct {u8 lut_index;} rule[2];} ct_ifc;
 u32 ct_pair_token,ct_wlan_epoch''')
pre = pre.replace('struct airoha_eth {', 'struct airoha_ppe; struct airoha_qdma {int id;}; struct airoha_soc {int num_ppe;}; struct airoha_eth {struct airoha_ppe*ppe; struct airoha_soc*soc;struct airoha_qdma qdma[2];int ct_route_lock,ifc_port_lock;u32 ct_ifc_port_mask,ifc_port_desired;u16 ct_cpu_route_mask[4];bool ct_ifc_cpu_port_failed,ct_ifc_pon_ready,ct_ordinary_full_test;bool ct_cpu_fallback,ct_cpu_ifc_disabled,ct_cpu_routes_ready,ct_cpu_wlan_gated;')
pre = pre.replace('struct airoha_eth {', 'struct airoha_eth {bool ct_ifc_command_pending,ct_pon_full;')
pre = pre.replace('bool ct_native_pairs,', 'bool ct_pon_qualified;bool ct_native_pairs,')
pre = pre.replace('struct airoha_gdm_dev {', 'struct airoha_gdm_dev {struct airoha_qdma*qdma;')
pre = pre.replace('bool ct_native_pairs,', 'bool ct_pon_ifc_route_owned;bool ct_bridge_failed;bool ct_native_pairs,')
pre = pre.replace('bool ct_native_pairs,', 'bool ct_pair_close_pending;bool ct_native_pairs,')
pre = pre.replace('static int mock_send(', 'static int original_mock_send(')
pre = pre.replace('static int airoha_ppe_ct_bridge_fail_closed(struct airoha_ppe*p){assert(ppe_lock);p->ct_stopping=true;failclosed++;return stop_error;}', '')
pre = pre.replace('static int airoha_ppe_foe_commit_entry(', 'static void verify_drain(struct airoha_ppe*);\nstatic int airoha_ppe_foe_commit_entry(')
pre = pre.replace('assert(barrier_complete);writes++;', '{assert(barrier_complete);verify_drain(p);}writes++;')
pre += r'''
#define EUCLEAN 117
#define AIROHA_CT_PAIR_F_CPU_FALLBACK BIT(0)
#define WRITE_ONCE(x,v) ((x)=(v))
#define FE_PSE_PORT_CDM1 0
#define FE_PSE_PORT_CDM2 5
#define FE_PSE_PORT_PPE1 4
#define FE_PSE_PORT_PPE2 8
#define FE_PSE_PORT_DROP 15
#define AIROHA_GDM1_IDX 1
#define AIROHA_GDM2_IDX 2
#define REG_GDM_FWD_CFG(id) (0x700+4*(id))
static void test_log(const char*fmt,...){(void)fmt;}
#define pr_err(...) test_log(__VA_ARGS__)
#define dev_err_ratelimited(...) ((void)0)
static struct airoha_soc test_soc={.num_ppe=2};
#define to_delayed_work(w) container_of(w,struct delayed_work,work)
#define msecs_to_jiffies(x) (x)
static unsigned schedules;
static int schedule_delayed_work(struct delayed_work*w,unsigned ticks){assert(w&&(ticks==100||ticks==0));schedules++;return 0;}
#define max(a,b) ((a)>(b)?(a):(b))
#define CT_IFC_DATA(x) (0x210+4*(x))
#define CT_IFC_CONTROL 0x204
#define CT_IFC_DONE BIT(31)
#define CT_IFC_TCAM_BANK 0
#define CT_IFC_ACTION_BANK 2
#define CT_IFC_ACTION_ENABLE BIT(31)
#define CT_IFC_ACTION_STOP BIT(30)
#define REG_FE_CSR_IFC_CFG 0x200
#define REG_FE_IFC_PORT_EN 0x1f4
#define FE_IFC_EN_MASK 1
#define XSI_ETH_VIP_PORT_MASK BIT(24)
#define REG_PPE_GLO_CFG(n) (0x500+(n)*0x100)
#define REG_PPE_PPE_FLOW_CFG(n) (0x504+(n)*0x100)
#define REG_PPE_TB_CFG(n) (0x51c+(n)*0x100)
#define PPE_TB_CFG_SEARCH_MISS_MASK GENMASK(5,4)
#define PPE_GLO_CFG_BUSY_MASK BIT(31)
#define PPE_GLO_CFG_EN_MASK BIT(0)
#define read_poll_timeout_atomic(fn,val,cond,delay,timeout,sleep,args...) ((val)=fn(args),(cond)?0:-ETIMEDOUT)
static const u8 ct_ifc_action_words[]={2,3,1};
static u32 ifc_regs[1024],ifc_table[3][64][9][3],ifc_backup[3][64][9][3];
static unsigned table_writes,table_fail,table_fail_from,control_fail,control_fail_op,ops[16384],nops;
static unsigned ppe_writes,ppe_write_fail,flush_ack_count,ppe_busy_reads;
static bool ppe_drain_seen,flush_since_put;
static bool close_test,fw_admission;
static unsigned close_attempts,close_calls_at_stop,fw_busy_refs,fw_lock_retries;
static int close_transport_error,gate_error;
static unsigned gate_calls;static bool cpu_gate_fail;
static void verify_close_before_stop(struct airoha_ppe*p){
 assert(p->ct_pair_failed&&!p->ct_pair_policy_allowed&&p->eth->ct_cpu_fallback&&p->eth->ct_cpu_wlan_gated);
 if(close_test){assert(close_attempts>close_calls_at_stop);close_calls_at_stop=close_attempts;}
}
static u32 airoha_fe_rr(struct airoha_eth*e,u32 offset){assert(e&&offset<4096);if(offset==REG_PPE_GLO_CFG(0))ppe_busy_reads++;return ifc_regs[offset/4];}
static void airoha_fe_wr(struct airoha_eth*e,u32 offset,u32 value){
 assert(e&&(ppe_lock||(e->ct_route_lock&&offset==REG_FE_CSR_IFC_CFG))&&(offset==0x204||(offset>=0x210&&offset<=0x218)||offset==REG_PPE_TB_CFG(0)||offset==REG_PPE_PPE_FLOW_CFG(0)||offset==REG_PPE_PPE_FLOW_CFG(1)||offset==REG_PPE_GLO_CFG(0)||offset==REG_PPE_GLO_CFG(1)||offset==REG_FE_CSR_IFC_CFG||(offset>=REG_GDM_FWD_CFG(1)&&offset<=REG_GDM_FWD_CFG(4))));
 if(e->ct_cpu_fallback&&offset==REG_PPE_PPE_FLOW_CFG(0))verify_close_before_stop(e->ppe);
 if(!e->ct_cpu_fallback&&(offset==REG_PPE_TB_CFG(0)||offset==REG_PPE_PPE_FLOW_CFG(0))){
  assert(flush_ack_count&&flush_since_put&&!(ifc_table[2][54][2][0]&BIT(31))&&!(ifc_table[2][55][2][0]&BIT(31)));
  ppe_writes++;if(ppe_writes==ppe_write_fail)return;
  if(offset==REG_PPE_PPE_FLOW_CFG(0)&&!value)ppe_drain_seen=true;
 }
 if(offset==REG_FE_CSR_IFC_CFG&&cpu_gate_fail)return;
 ifc_regs[offset/4]=value;
 if(offset==0x204){unsigned bank=(value>>4)&7,index=(value>>16)&255,page=(value>>8)&15;
  assert(bank==0||bank==2);assert(index==54||index==55);assert(page<9);
  unsigned count=bank==2?ct_ifc_action_words[page]:2;
  if(value&2){table_writes++;if(table_writes==table_fail||(table_fail_from&&table_writes>=table_fail_from))return;
   memcpy(ifc_table[bank][index][page],ifc_regs+0x210/4,count*4);
   if(bank==0)ifc_table[bank][index][page][0]&=ifc_table[bank][index][page][1];
  }else memcpy(ifc_regs+0x210/4,ifc_table[bank][index][page],count*4);
  ifc_regs[offset/4]|=BIT(31);
 }
}
static void airoha_fe_rmw(struct airoha_eth*e,u32 offset,u32 clear,u32 set){airoha_fe_wr(e,offset,(airoha_fe_rr(e,offset)&~clear)|set);}
static void airoha_fe_clear(struct airoha_eth*e,u32 offset,u32 mask){airoha_fe_rmw(e,offset,mask,0);}
static void verify_drain(struct airoha_ppe*p){
 if(p->ct_fe.epoch){assert(flush_ack_count&&flush_since_put&&ppe_drain_seen&&p->ct_fe.drain_pending&&ppe_busy_reads);
  assert(ifc_regs[REG_PPE_GLO_CFG(0)/4]==PPE_GLO_CFG_EN_MASK);
  assert(!ifc_regs[REG_PPE_PPE_FLOW_CFG(0)/4]);
  assert(FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK,ifc_regs[REG_PPE_TB_CFG(0)/4])==2);
 }
}
static int mock_send(struct airoha_npu*n,struct airoha_ct_pair_msg*m){
 assert(nops<ARRAY_SIZE(ops));ops[nops++]=m->op;
 if(m->op==AIROHA_CT_PAIR_FLUSH&&m->flags){assert(m->flags==AIROHA_CT_PAIR_F_CPU_FALLBACK);gate_calls++;return gate_error;}
 if(close_test&&m->op==AIROHA_CT_PAIR_FLUSH){
  assert(ppe_lock&&rcu);close_attempts++;
  if(close_transport_error)return close_transport_error;
  if(fw_lock_retries){fw_lock_retries--;return -EAGAIN;}
  fw_admission=false;
  if(fw_busy_refs)return -EAGAIN;
 }
 if(m->op==AIROHA_CT_PAIR_FE_QUIESCE||m->op==AIROHA_CT_PAIR_FE_ARM){
  assert(!m->slot&&!m->token&&!m->dst_epoch&&!m->dst_wcid&&!m->dst_selector&&!m->src_bss&&!m->dst_bss&&!m->flags);
  assert(!memcmp(m->smac,"\0\0\0\0\0\0",6)&&!memcmp(m->dmac,"\0\0\0\0\0\0",6));
  assert(m->src_selector==2&&m->src_wcid==24&&m->src_epoch&&m->generation);
  if(m->op==AIROHA_CT_PAIR_FE_QUIESCE&&!(ifc_regs[REG_FE_CSR_IFC_CFG/4]&FE_IFC_EN_MASK)){
   /* Fault retirement closes the global producer gate and retains row shadows. */
  }else if(m->op==AIROHA_CT_PAIR_FE_QUIESCE||!(ifc_table[2][54][2][0]&BIT(31)))assert(!(ifc_table[2][54][2][0]&BIT(31))&&!(ifc_table[2][55][2][0]&BIT(31)));
  if(m->op==control_fail_op&&control_fail)return -EIO;
 }
 int result=original_mock_send(n,m);if(!result&&m->op==AIROHA_CT_PAIR_FLUSH){flush_ack_count++;flush_since_put=true;}
 if(!result&&m->op==AIROHA_CT_PAIR_PUT){flush_since_put=false;ppe_drain_seen=false;ppe_busy_reads=0;}return result;
}
static void mmio_reset(void){
 cpu_gate_fail=false;
 memset(ifc_regs,0,sizeof ifc_regs);memset(ifc_table,0,sizeof ifc_table);
 for(unsigned b=0;b<3;b++)for(unsigned r=0;r<64;r++)for(unsigned p=0;p<9;p++)for(unsigned w=0;w<3;w++)
  ifc_table[b][r][p][w]=0x1234+(b<<16)+(r<<8)+p*3+w;
 ifc_regs[0x200/4]=1;ifc_regs[0x1f4/4]=BIT(24);ifc_regs[0x220/4]=0xaabbccdd;
 for(unsigned bank=0;bank<2;bank++){ifc_regs[REG_PPE_GLO_CFG(bank)/4]=PPE_GLO_CFG_EN_MASK;ifc_regs[REG_PPE_PPE_FLOW_CFG(bank)/4]=0x89abcdef; ifc_regs[REG_PPE_TB_CFG(bank)/4]=0x9876543f;}
 ppe_writes=ppe_write_fail=flush_ack_count=ppe_busy_reads=0;ppe_drain_seen=flush_since_put=false;
 close_test=fw_admission=false;close_attempts=close_calls_at_stop=fw_busy_refs=fw_lock_retries=0;close_transport_error=gate_error=gate_calls=0;
 memcpy(ifc_backup,ifc_table,sizeof ifc_table);table_writes=table_fail=table_fail_from=control_fail=control_fail_op=nops=0;
}
static void fault_contained(void){
 assert(!ifc_regs[REG_FE_CSR_IFC_CFG/4]);
 for(unsigned bank=0;bank<2;bank++)assert(!(ifc_regs[REG_PPE_GLO_CFG(bank)/4]&PPE_GLO_CFG_EN_MASK)&&!ifc_regs[REG_PPE_PPE_FLOW_CFG(bank)/4]);
}
static void tables_restored(void){
 for(unsigned b=0;b<3;b++)for(unsigned r=0;r<64;r++)for(unsigned p=0;p<9;p++)for(unsigned w=0;w<3;w++){
  u32 mask=b==0&&(r==54||r==55)&&w==0?ifc_backup[b][r][p][1]:U32_MAX;
  assert(!((ifc_table[b][r][p][w]^ifc_backup[b][r][p][w])&mask));
 }
 assert(ifc_regs[0x200/4]==1&&ifc_regs[0x1f4/4]==BIT(24)&&ifc_regs[0x220/4]==0xaabbccdd);
 for(unsigned bank=0;bank<2;bank++)assert(ifc_regs[REG_PPE_GLO_CFG(bank)/4]==PPE_GLO_CFG_EN_MASK&&ifc_regs[REG_PPE_PPE_FLOW_CFG(bank)/4]==0x89abcdef&&ifc_regs[REG_PPE_TB_CFG(bank)/4]==0x9876543f);
}
'''
fixture = fixture.replace('ppe_lock=rcu=0;', 'eth.ppe=&ppe;eth.soc=&test_soc;eth.ct_ifc_cpu_port_failed=false;eth.ct_cpu_fallback=eth.ct_cpu_ifc_disabled=eth.ct_cpu_routes_ready=eth.ct_cpu_wlan_gated=false;eth.ct_route_lock=eth.ifc_port_lock=0;eth.ct_ifc_port_mask=eth.ifc_port_desired=BIT(24);eth.ct_ifc_pon_ready=eth.ct_ordinary_full_test=false;memset(eth.ct_cpu_route_mask,0,sizeof eth.ct_cpu_route_mask);schedules=0;ppe.ct_ifc.cfg_owned=true;ppe.ct_ifc.rule[0].lut_index=31;ppe.ct_ifc.rule[1].lut_index=30;mmio_reset();ppe_lock=rcu=0;')
fixture = fixture.replace('wired=(struct airoha_gdm_dev){', 'wired=(struct airoha_gdm_dev){.qdma=&eth.qdma[1],')
fixture = fixture.replace('mmio_reset();', 'eth.ct_ifc_command_pending=eth.ct_pon_full=false;mmio_reset();')
body = '''#include "airoha_ct_cpu_fallback.h"\nstatic int airoha_ct_pair_fault_close(struct airoha_ppe *ppe);\n#include "fail_closed.inc"\n#define airoha_ppe_ct_bridge_fail_closed(ppe) airoha_ppe_ct_bridge_fail_closed_from(ppe,__func__,__LINE__)\n#include "airoha_ct_native_pair.h"\n#include "pair_policy_event.inc"\n'''
main = r'''
static unsigned classifier_cases;
static bool matches(unsigned r,unsigned source,unsigned family,unsigned encap,unsigned short_hit){
 u32 words[9]={};words[0]=BIT(source);words[4]=short_hit?BIT(31-r):0;words[5]=family==4?0x800:family==6?0x86dd:0x806;
 words[7]=((encap&1)?BIT(5):0)|((encap&2)?BIT(4):0)|((encap&4)?BIT(10):0);
 if(!(ifc_table[0][54+r][0][0]&BIT(source))&&(ifc_table[0][54+r][0][1]&BIT(source)))return false;
 for(unsigned p=1;p<9;p++)if((words[p]^ifc_table[0][54+r][p][0])&ifc_table[0][54+r][p][1])return false;
 return true;
}
static void classifier_verify(void){
 for(unsigned r=0;r<2;r++)for(unsigned srcid=0;srcid<32;srcid++)for(unsigned family=0;family<3;family++)for(unsigned encap=0;encap<8;encap++)for(unsigned sh=0;sh<2;sh++){
  unsigned ip=family==0?4:family==1?6:0;
  bool expected=srcid==24&&ip==(r?6:4)&&!encap&&!sh;
  assert(matches(r,srcid,ip,encap,sh)==expected);classifier_cases++;
 }
}
static void source_reset(void){reset();src.ieee80211_ptr=NULL;src.running=src.carrier=true;wired.netdev=&src;}
static void cpu_bind(unsigned hash){struct net_device*egress=skb.dev;skb.dev=&src;napi=true;test_bind(hash,NULL);napi=false;skb.dev=egress;}
static int stop_fe(void){int err;spin_lock_bh(&ppe_lock);err=airoha_ct_fe_quiesce(&ppe,generation);spin_unlock_bh(&ppe_lock);return err;}
int main(void){unsigned cases=0;
 for(unsigned mode=0;mode<10;mode++){
  source_reset();
  eth.ct_ifc_port_mask=eth.ifc_port_desired=BIT(24)|BIT(2);
  eth.ct_ifc_pon_ready=true;ifc_regs[REG_FE_IFC_PORT_EN/4]=eth.ct_ifc_port_mask;
  switch(mode){
   case 1:eth.ct_ifc_pon_ready=false;break;
   case 2:eth.ct_ifc_port_mask|=BIT(3);eth.ifc_port_desired|=BIT(3);ifc_regs[REG_FE_IFC_PORT_EN/4]|=BIT(3);break;
   case 3:ifc_regs[REG_FE_IFC_PORT_EN/4]|=BIT(5);break;
   case 4:ifc_regs[REG_FE_IFC_PORT_EN/4]&=~BIT(2);break;
   case 5:eth.ct_cpu_fallback=true;break;
   case 6:eth.ct_ifc_cpu_port_failed=true;break;
   case 7:ifc_regs[REG_FE_CSR_IFC_CFG/4]&=~FE_IFC_EN_MASK;break;
   case 8:ppe.ct_ifc.cfg_owned=false;break;
   case 9:eth.ifc_port_desired&=~BIT(24);ifc_regs[REG_FE_IFC_PORT_EN/4]&=~BIT(24);break;
  }
  spin_lock_bh(&ppe_lock);
  assert(airoha_ct_fe_snapshot(&ppe)==(mode?-EINVAL:0));
  spin_unlock_bh(&ppe_lock);
  assert(ppe.ct_fe.saved==(mode==0)&&!eth.ct_route_lock&&!eth.ifc_port_lock&&!table_writes);cases++;
 }
 reset();struct airoha_ct_pair_msg cap={.op=AIROHA_CT_PAIR_CAP};retries=5;assert(!airoha_ct_pair_exchange(&npu,&cap)&&calls==6&&!ppe_lock&&!rcu);cases++;
 reset();retries=20000;assert(airoha_ct_pair_exchange(&npu,&cap)==-ETIMEDOUT&&!ppe_lock&&!rcu);cases++;
 reset();assert(airoha_ct_pair_exchange(NULL,&cap)==-EOPNOTSUPP&&!calls);cases++;

 source_reset();frame();assert(put_count==1&&ppe.ct_fe.armed&&ppe.ct_fe.active&&ppe.ct_fe.epoch==1);
 classifier_verify();
 assert(nops==4&&ops[0]==AIROHA_CT_PAIR_FLUSH&&ops[1]==AIROHA_CT_PAIR_FE_QUIESCE&&ops[2]==AIROHA_CT_PAIR_FE_ARM&&ops[3]==AIROHA_CT_PAIR_PUT);
 assert(pairs[0].msg.src_selector==2&&pairs[0].msg.src_wcid==24&&!pairs[0].msg.src_bss&&pairs[0].msg.src_epoch==1);
 learned(0x268);cpu_bind(0x268);assert(writes==1&&FIELD_GET(AIROHA_FOE_IB2_PSE_PORT,rows[0x268].l2b.ib2)==3&&FIELD_GET(AIROHA_FOE_CHANNEL,rows[0x268].l2b.data)==9&&rows[0x268].l2b.etype==(8<<6|3));
 assert(!revoke(-1,0)&&!ppe.ct_fe.armed&&!ppe.ct_fe.active&&!pairs[0].used&&writes==2);tables_restored();cases++;
 for(unsigned mode=0;mode<19;mode++){
  source_reset();switch(mode){case 1:src.running=false;break;case 2:src.carrier=false;break;case 3:ppe.ct_pair_wired_blocked=true;break;
   case 4:master.vlan=true;break;case 5:src.flags=BR_ISOLATED;break;case 6:dst.flags=BR_PORT_LOCKED;break;case 7:fdbsrc=&dst;break;case 8:fdbdst=&src;break;
   case 9:src.state=0;break;case 10:dst.state=0;break;case 11:dst.wdma.wcid=151;break;case 12:dst.wdma_err=-1;break;case 13:phandle=NULL;break;
   case 14:eth.ports[3]=NULL;break;case 15:dst.ieee80211_ptr=NULL;break;case 16:ppe.ct_pair_policy_allowed=false;break;case 17:skb.vlan=true;break;case 18:skb.hdr.h_proto=htons(0x806);break;}
  frame();assert(put_count==(mode==0));cases++;
 }
 for(unsigned mode=0;mode<22;mode++){
  source_reset();frame();learned(0x268);
  switch(mode){case 1:ppe.ct_fe.armed=false;break;case 2:ppe.ct_fe.active=false;break;case 3:ppe.ct_fe.epoch++;break;case 4:generation++;break;
   case 5:src.carrier=false;break;case 6:src.running=false;break;case 7:ppe.ct_pair_wired_blocked=true;break;case 8:fdbsrc=&dst;break;case 9:fdbdst=&src;break;
   case 10:dst.wdma.wcid++;break;case 11:dst.wdma.bss++;break;case 12:dst.state=0;break;case 13:master.vlan=true;break;case 14:phandle=NULL;break;
   case 15:rows[0x268].l2b.src_mac_hi++;break;case 16:rows[0x268].l2b.ingress_vlan=1;break;case 17:rows[0x268].ib1|=AIROHA_FOE_IB1_BIND_STATIC;break;
   case 18:ppe.ct_pair_policy_allowed=false;break;case 19:ppe.ct_wlan_epoch[1][8]++;break;case 20:skb.vlan=true;break;case 21:skb.hdr.h_proto=htons(0x806);break;}
  cpu_bind(0x268);assert(writes==(mode==0));cases++;
 }
 source_reset();frame();learned(0x268);struct airoha_ct_bridge_peer spoof={.band=2,.wcid=24,.epoch=1};test_bind(0x268,&spoof);assert(!writes);cases++;
 source_reset();frame();learned(0x268);test_bind(0x268,NULL);assert(!writes);cases++;
 source_reset();frame();learned(0x268);cpu_bind(0x268);rows[0x268].l2b.ib2^=1;assert(!revoke(-1,0)&&writes==1&&!pairs[0].used);cases++;
 source_reset();frame();learned(0x268);cpu_bind(0x268);assert(!revoke(1,8)&&writes==2&&!pairs[0].used&&ppe.ct_fe.epoch==2);tables_restored();cases++;
 source_reset();frame();learned(0x268);cpu_bind(0x268);generation=0;assert(!revoke(-1,0)&&writes==2&&!pairs[0].used&&ppe.ct_fe.generation==1);generation=3;frame();assert(put_count==2&&ppe.ct_fe.generation==3&&pairs[0].msg.src_epoch==3);cases++;
 source_reset();frame();learned(0x268);cpu_bind(0x268);assert(!airoha_ct_pair_policy_event(&ppe.ct_pair_policy_notifier,NF_NATIVE_PAIR_PRE,NULL));assert(!ppe.ct_pair_policy_allowed&&!ppe.ct_fe.active&&!pairs[0].used&&writes==2);assert(!airoha_ct_pair_policy_event(&ppe.ct_pair_policy_notifier,NF_NATIVE_PAIR_POST,NULL));tables_restored();cases++;
 source_reset();frame();learned(0x268);cpu_bind(0x268);assert(!airoha_ct_pair_wired_event(&ppe.ct_pair_wired_notifier,NETDEV_GOING_DOWN,&src));assert(ppe.ct_pair_wired_blocked&&!pairs[0].used&&ppe.ct_fe.epoch==2&&ppe.ct_pair_wired_epoch==1);assert(!airoha_ct_pair_wired_event(&ppe.ct_pair_wired_notifier,NETDEV_UP,&src));frame();assert(put_count==2&&pairs[0].msg.src_epoch==2);cases++;
 wired_reset();frame();assert(put_count==1&&pairs[0].msg.dst_selector==2);struct airoha_ct_bridge_peer peer={.epoch=1,.band=0,.bss=2,.wcid=7};learned(0x268);test_bind(0x268,&peer);assert(writes==1);assert(!wired_event(NETDEV_DOWN)&&!pairs[0].used&&writes==2);tables_restored();cases++;
 reset();frame();learned(0x268);test_bind(0x268,&peer);assert(writes==1);assert(!revoke(-1,0)&&writes==2);cases++;
 for(unsigned at=1;at<=24;at++){
  source_reset();table_fail=at;frame();assert(!put_count&&ppe.ct_pair_failed&&!ppe.ct_pair_policy_allowed&&!ppe.ct_fe.active&&eth.ct_cpu_fallback);table_fail=0;
  bool retained=ppe.ct_fe.touched;assert(!stop_fe()&&ppe.ct_fe.touched==retained&&!ppe.ct_fe.armed);fault_contained();cases++;
 }
 for(unsigned at=1;at<=26;at++){
  source_reset();frame();learned(0x268);cpu_bind(0x268);table_fail=table_writes+at;
  assert(revoke(-1,0)==-ETIMEDOUT&&ppe.ct_pair_failed&&!ppe.ct_pair_policy_allowed&&pairs[0].used);
  table_fail=0;unsigned fault_writes=table_writes;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(pairs[0].used&&!ppe.ct_fe.active&&!ppe.ct_fe.armed&&writes==1&&table_writes==fault_writes);fault_contained();cases++;
 }
 source_reset();frame();u32 epoch=ppe.ct_fe.epoch;control_fail_op=AIROHA_CT_PAIR_FE_QUIESCE;control_fail=1;assert(stop_fe()==-EIO&&ppe.ct_fe.pending&&!ppe.ct_fe.armed);u32 pending=ppe.ct_fe.pending_epoch;
 control_fail=0;assert(!stop_fe()&&!ppe.ct_fe.pending&&ppe.ct_fe.epoch==pending&&pending==epoch+1);cases++;
 source_reset();frame();ppe.ct_fe.epoch=U32_MAX;assert(revoke(-1,0)==-EOVERFLOW&&ppe.ct_pair_failed&&!ppe.ct_fe.active);cases++;
 source_reset();frame();assert(!airoha_ct_pair_wired_event(&ppe.ct_pair_wired_notifier,NETDEV_GOING_DOWN,&src));assert(!airoha_ct_pair_wired_event(&ppe.ct_pair_wired_notifier,NETDEV_DOWN,&src));assert(!airoha_ct_pair_wired_event(&ppe.ct_pair_wired_notifier,NETDEV_UP,&src));frame();assert(put_count==2&&ppe.ct_fe.epoch==3&&pairs[0].msg.src_epoch==3);cases++;
 source_reset();retries=5;frame();assert(put_count==1&&ppe.ct_fe.active);cases++;
 source_reset();control_fail_op=AIROHA_CT_PAIR_FE_ARM;control_fail=1;frame();assert(!put_count&&ppe.ct_pair_failed&&!ppe.ct_fe.active&&ppe.ct_fe.arm_pending);airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(!ppe.ct_fe.arm_pending);fault_contained();cases++;
 source_reset();frame();unsigned schedule_before=schedules;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(!ppe.ct_pair_failed&&ppe.ct_fe.active&&schedules==schedule_before+1);cases++;
 source_reset();frame();control_fail_op=AIROHA_CT_PAIR_FE_ARM;control_fail=1;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(ppe.ct_pair_failed&&!ppe.ct_fe.active&&ppe.ct_fe.armed&&!ppe.ct_pair_policy_allowed);airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(!ppe.ct_fe.armed&&ppe.ct_fe.touched);fault_contained();cases++;
 source_reset();frame();table_fail_from=table_writes+1;assert(revoke(-1,0)==-ETIMEDOUT&&ppe.ct_pair_failed&&!ppe.ct_pair_policy_allowed&&ppe.ct_fe.touched);unsigned before_retry=schedules;unsigned retained_writes=table_writes;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(ppe.ct_fe.touched&&schedules==before_retry&&table_writes==retained_writes);table_fail_from=0;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(ppe.ct_fe.touched&&!ppe.ct_fe.active&&!ppe.ct_fe.armed&&!ppe.ct_fe.pending&&!ppe.ct_fe.arm_pending&&!ppe.ct_pair_policy_allowed);fault_contained();cases++;
 source_reset();frame();ppe.ct_fe.health_stopping=true;schedule_before=schedules;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(schedules==schedule_before);cases++;
 source_reset();ppe.ct_ifc.cfg_owned=false;frame();assert(!put_count&&ppe.ct_pair_failed&&!table_writes);cases++;
 source_reset();ifc_table[2][54][2][0]|=BIT(31);frame();assert(!put_count&&ppe.ct_pair_failed&&!table_writes);cases++;
 for(unsigned mode=0;mode<6;mode++){
  source_reset();frame();learned(0x268);cpu_bind(0x268);
  if(mode<4)ppe_write_fail=mode+1;
  else if(mode==4)ifc_regs[REG_PPE_GLO_CFG(0)/4]|=PPE_GLO_CFG_BUSY_MASK;
  else ifc_regs[REG_PPE_GLO_CFG(0)/4]=0;
  assert(revoke(-1,0)==(mode==4?-ETIMEDOUT:-EIO));
  assert(ppe.ct_pair_failed&&!ppe.ct_pair_policy_allowed&&!ppe.ct_fe.armed&&!ppe.ct_fe.active&&ppe.ct_fe.drain_pending);
  assert(writes==(mode>=2&&mode<4?2:1));assert(pairs[0].used==!(mode>=2&&mode<4));
  unsigned oldops=nops;spin_lock_bh(&ppe_lock);assert(airoha_ct_fe_arm(&ppe,generation)==-ESTALE);spin_unlock_bh(&ppe_lock);assert(nops==oldops);
  assert(!ifc_regs[REG_PPE_PPE_FLOW_CFG(1)/4]&&ifc_regs[REG_PPE_TB_CFG(1)/4]==0x9876543f);cases++;
 }
 source_reset();frame();learned(0x268);cpu_bind(0x268);pairs[1]=pairs[0];pairs[1].msg.src_selector=1;pairs[1].msg.src_wcid=7;pairs[1].hashes[0]=0x900;rows[0x900]=rows[0x268];
 assert(!revoke(1,8)&&!pairs[0].used&&!pairs[1].used&&writes==3&&lastmsg.op==AIROHA_CT_PAIR_ENDPOINT_REVOKE&&lastmsg.src_selector==0&&lastmsg.src_wcid==8);
 assert(!ppe.ct_fe.drain_pending&&ppe_writes==4);tables_restored();cases++;
 source_reset();frame();ppe.ct_fe.drain_pending=true;assert(!stop_fe());unsigned oldops=nops;spin_lock_bh(&ppe_lock);assert(airoha_ct_fe_arm(&ppe,generation)==-ESTALE);spin_unlock_bh(&ppe_lock);assert(nops==oldops);cases++;
 source_reset();frame();control_fail_op=AIROHA_CT_PAIR_FE_QUIESCE;control_fail=1;assert(revoke(-1,0)==-EIO&&ppe.ct_pair_failed&&ppe.ct_fe.pending);u32 retry_epoch=ppe.ct_fe.pending_epoch;unsigned oldschedule=schedules;
 airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(ppe.ct_fe.pending&&ppe.ct_fe.pending_epoch==retry_epoch&&schedules>oldschedule);
 control_fail=0;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(!ppe.ct_fe.pending&&!ppe.ct_fe.armed&&!ppe.ct_fe.arm_pending&&!ppe.ct_fe.touched&&ppe.ct_fe.epoch==retry_epoch&&!ppe.ct_pair_policy_allowed);fault_contained();cases++;
 const int gate_errors[]={-EAGAIN,-ETIMEDOUT,-EIO,-EOPNOTSUPP};
 for(unsigned g=0;g<ARRAY_SIZE(gate_errors);g++){
  source_reset();frame();gate_error=gate_errors[g];
  spin_lock_bh(&ppe_lock);assert(airoha_ct_pair_fail(&ppe,-EIO)==gate_error);spin_unlock_bh(&ppe_lock);
  assert(gate_calls==1&&!eth.ct_cpu_wlan_gated&&!ppe.ct_pair_hw_stopped&&schedules);
  for(unsigned b=0;b<2;b++)assert(ifc_regs[REG_PPE_GLO_CFG(b)/4]&PPE_GLO_CFG_EN_MASK);
  unsigned before=schedules;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);
  assert(gate_calls==2&&!eth.ct_cpu_wlan_gated&&!ppe.ct_pair_hw_stopped&&schedules>before);
  gate_error=0;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);
  assert(gate_calls==3&&eth.ct_cpu_wlan_gated&&ppe.ct_pair_hw_stopped);fault_contained();
  airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(gate_calls==3);cases++;
 }
 for(unsigned mode=0;mode<5;mode++){
  source_reset();frame();learned(0x268);cpu_bind(0x268);close_test=fw_admission=true;fw_busy_refs=163;
  if(mode==1)fw_lock_retries=1;
  if(mode==2)close_transport_error=-ETIMEDOUT;
  if(mode==3)close_transport_error=-EIO;
  if(mode==4)fw_busy_refs=0;
  spin_lock_bh(&ppe_lock);assert(airoha_ct_pair_fail(&ppe,-EIO)==-EIO);spin_unlock_bh(&ppe_lock);
  assert(close_attempts==1&&close_calls_at_stop==1&&ppe.ct_stopping&&ppe.ct_pair_failed&&!ppe.ct_pair_policy_allowed&&pairs[0].used&&writes==1);
  assert(fw_admission==(mode>=1&&mode<=3));assert(ppe.ct_pair_close_pending==(mode!=4));
  assert(ppe.ct_fe.armed&&!ppe.ct_fe.active&&!ppe.ct_fe.pending&&ppe.ct_fe.touched&&!ppe.ct_fe.arm_pending);
  assert(fw_busy_refs==(mode==4?0:163));unsigned before=schedules;
  close_transport_error=0;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);
  assert(!fw_admission&&pairs[0].used&&writes==1&&fw_busy_refs==(mode==4?0:163));
  assert(close_attempts==(mode==4?1:2)&&ppe.ct_pair_close_pending==(mode!=4));
  assert(schedules==before+(mode!=4));
  if(mode!=4){fw_busy_refs=0;before=schedules;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(!ppe.ct_pair_close_pending&&schedules==before&&pairs[0].used&&writes==1);}
  cases++;
 }
 source_reset();frame();close_test=fw_admission=true;fw_busy_refs=163;control_fail_op=AIROHA_CT_PAIR_FE_QUIESCE;control_fail=1;
 spin_lock_bh(&ppe_lock);assert(airoha_ct_pair_fail(&ppe,-ETIMEDOUT)==-ETIMEDOUT);spin_unlock_bh(&ppe_lock);
 assert(close_attempts==1&&!fw_admission&&ppe.ct_pair_close_pending&&ppe.ct_fe.armed&&!ppe.ct_fe.pending&&fw_busy_refs==163);
 airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(close_attempts==2&&ppe.ct_fe.pending&&ppe.ct_pair_close_pending);u32 fault_pending=ppe.ct_fe.pending_epoch;control_fail=0;
 airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(close_attempts==3&&!ppe.ct_fe.pending&&ppe.ct_fe.epoch==fault_pending&&ppe.ct_pair_close_pending&&fw_busy_refs==163);cases++;
 source_reset();frame();close_test=fw_admission=true;fw_busy_refs=163;spin_lock_bh(&ppe_lock);assert(airoha_ct_pair_fail(&ppe,-EIO)==-EIO);spin_unlock_bh(&ppe_lock);
 ppe.ct_fe.health_stopping=true;before_retry=schedules;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(close_attempts==1&&schedules==before_retry&&ppe.ct_pair_close_pending);cases++;

 source_reset();frame();unsigned before_map=schedules;assert(!airoha_ct_ifc_cpu_port_change(&eth,24));assert(eth.ct_ifc_cpu_port_failed&&!ifc_regs[REG_FE_CSR_IFC_CFG/4]&&schedules==before_map+1);airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(ppe.ct_pair_failed&&eth.ct_cpu_fallback);cases++;
 source_reset();frame();cpu_gate_fail=true;before_map=schedules;assert(airoha_ct_ifc_cpu_port_change(&eth,24)==-EIO);assert(eth.ct_ifc_cpu_port_failed&&ifc_regs[REG_FE_CSR_IFC_CFG/4]&&schedules==before_map+1);cpu_gate_fail=false;airoha_ct_fe_health_work(&ppe.ct_fe.health_work.work);assert(ppe.ct_pair_failed&&eth.ct_cpu_fallback&&!ifc_regs[REG_FE_CSR_IFC_CFG/4]);cases++;
 source_reset();frame();before_map=schedules;assert(!airoha_ct_ifc_cpu_port_change(&eth,23));assert(!eth.ct_ifc_cpu_port_failed&&ifc_regs[REG_FE_CSR_IFC_CFG/4]&&schedules==before_map);cases++;
 source_reset();frame();ppe.ct_ifc.cfg_owned=false;assert(!airoha_ct_ifc_cpu_port_change(&eth,24)&&!eth.ct_ifc_cpu_port_failed&&ifc_regs[REG_FE_CSR_IFC_CFG/4]);cases++;
 source_reset();frame();ppe.ct_fe.health_stopping=true;before_map=schedules;assert(!airoha_ct_ifc_cpu_port_change(&eth,24)&&eth.ct_ifc_cpu_port_failed&&!ifc_regs[REG_FE_CSR_IFC_CFG/4]&&schedules==before_map);cases++;
 source_reset();frame();eth.ct_ifc_cpu_port_failed=true;spin_lock_bh(&ppe_lock);assert(airoha_ct_fe_arm(&ppe,generation)==-ESTALE);spin_unlock_bh(&ppe_lock);cases++;
 cases+=classifier_cases;
 printf("{\"passed\":true,\"cases\":%u,\"install_failure_positions\":24,\"restore_failure_positions\":26,\"actual_native_and_ifc_headers\":true}\n",cases);
}
'''

def function(text, signature):
    start = text.index(signature); brace = text.index('{', start); depth = 0
    for end in range(brace, len(text)):
        depth += (text[end] == '{') - (text[end] == '}')
        if depth == 0:
            return text[start:end + 1]
    raise AssertionError(signature)

# Check each actual map writer and pointer publication rejects a failed gate
# before its first receiver modification; the helper above runs under ASan.
eth_c = (H/'airoha_eth.c').read_text()
for sig in ('static int __airoha_enable_gdm2_loopback(', 'static int __airoha_disable_gdm2_loopback('):
    body_check = function(eth_c, sig)
    gate = body_check.index('err = airoha_ct_ifc_cpu_port_change(eth, src_port);')
    assert gate < body_check.index('REG_SP_DFT_CPORT(')
    assert body_check[gate:].startswith('err = airoha_ct_ifc_cpu_port_change(eth, src_port);\n\tif (err)\n\t\treturn err;')
body_check = function(eth_c, 'static int airoha_dev_set_qdma(')
gate = body_check.index('err = airoha_ct_ifc_cpu_port_change(')
assert gate < body_check.index('rcu_assign_pointer(dev->qdma, qdma);')
assert '\n\t\tif (err)\n\t\t\treturn err;' in body_check[gate:body_check.index('rcu_assign_pointer')]
eth = (H/'airoha_eth.h').read_text()
(B/'foe_layout.inc').write_text(eth[eth.index('enum {\n\tAIROHA_FOE_STATE_INVALID,'):eth.index('struct airoha_foe_stats {')])
abi = (K/'include/linux/soc/airoha/airoha_offload.h').read_text()
(B/'pair_abi.inc').write_text(abi[abi.index('/* Native endpoint pair ABI'):abi.index('struct airoha_npu {')])
cfg = (K/'include/net/cfg80211.h').read_text()
(B/'wiphy_dev.inc').write_text(function(cfg, 'static inline struct device *wiphy_dev('))
bridge = (K/'net/bridge/br_switchdev.c').read_text()
(B/'bridge_fdb_lookup.inc').write_text(function(bridge, 'static bool br_switchdev_fdb_notifies(') + '\n' + function(bridge, 'struct net_device *br_switchdev_fdb_find_port('))
forward = (K/'net/bridge/br_forward.c').read_text()
(B/'bridge_frame_notify.inc').write_text(forward[forward.index('\tif (netif_is_bridge_port(skb->dev) && skb->skb_iif &&'):forward.index('\tdev_queue_xmit(skb);')])
policy = (H/'airoha_ct_pair_policy.h').read_text()
(B/'pair_policy_event.inc').write_text(function(policy, 'static int airoha_ct_pair_policy_event('))
(B/'fail_closed.inc').write_text(function((H/'airoha_ppe.c').read_text(), 'static int airoha_ppe_ct_bridge_fail_closed_from('))
for name in ('airoha_ct_native_pair.h', 'airoha_ct_fe_native.h', 'airoha_ct_cpu_fallback.h', 'airoha_ct_ifc_command.h'):
    shutil.copyfile(a.header if name=="airoha_ct_fe_native.h" else H/name, B/name)
legacy_modes = old[old.index(' for(unsigned mode=0;mode<24;mode++){'):old.index(' reset();frame();frame();assert(put_count==1')]
legacy_bind = old[old.index(' for(unsigned mode=0;mode<14;mode++){'):old.index(' reset();frame();learned(0x268);test_bind(8192')]
main = main.replace(' source_reset();frame();assert(put_count==1', legacy_modes + '\n source_reset();frame();assert(put_count==1', 1)
main = main.replace(' source_reset();frame();learned(0x268);struct airoha_ct_bridge_peer spoof=', '{ struct airoha_ct_bridge_peer peer={.epoch=1,.band=0,.bss=2,.wcid=7};\n' + legacy_bind + '\n}\n source_reset();frame();learned(0x268);struct airoha_ct_bridge_peer spoof=', 1)
policy_store = function(policy, 'static ssize_t ct_native_pair_policy_store(')
policy_pre = r'''
#include <sys/types.h>
struct device_attribute {int unused;};
static bool policy_hooks_ok=true;
static unsigned policy_locks;
static u64 nf_generation=39;
static void*dev_get_drvdata(struct device*d){assert(d);return &eth;}
static bool sysfs_streq(const char*a,const char*b){return !strcmp(a,b);}
static int nf_native_pair_policy_lock(u64 g){if(g!=nf_generation)return -ESTALE;policy_locks++;return 0;}
static void nf_native_pair_policy_unlock(void){assert(policy_locks);policy_locks--;}
static bool airoha_ct_pair_policy_hooks(void){return policy_hooks_ok;}
'''
main = main.replace(' printf("{', r'''
 source_reset();ppe.ct_pair_policy_allowed=false;assert(ct_native_pair_policy_store(&eth_dev,NULL,"whole-mac-ip 39",15)==15);assert(ppe.ct_fe.armed&&ppe.ct_fe.active&&ppe.ct_fe.generation==1&&ppe.ct_pair_policy_allowed&&!policy_locks);cases++;
 assert(ct_native_pair_policy_store(&eth_dev,NULL,"off",3)==3&&!ppe.ct_fe.armed&&!ppe.ct_fe.active&&!ppe.ct_pair_policy_allowed);tables_restored();cases++;
 source_reset();assert(ct_native_pair_policy_store(&eth_dev,NULL,"whole-mac-ip 38",15)==-ESTALE&&!nops&&!policy_locks);cases++;
 source_reset();policy_hooks_ok=false;assert(ct_native_pair_policy_store(&eth_dev,NULL,"whole-mac-ip 39",15)==-EOPNOTSUPP&&!nops&&!policy_locks);policy_hooks_ok=true;cases++;
 printf("{''')
ports_ready = function((H/'airoha_eth.c').read_text(), 'bool airoha_ifc_lan_ports_ready(')
(B/'test.c').write_text(pre + ports_ready + '\n' + body + fixture + policy_pre + policy_store + main)
subprocess.run(['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                '-fsanitize=address,undefined', '-I'+str(B), str(B/'test.c'), '-o', str(B/'test')], check=True)
p = subprocess.run([str(B/'test')], capture_output=True, text=True)
(B/'stdout.txt').write_text(p.stdout); (B/'stderr.txt').write_text(p.stderr)
(B/'exit-status.json').write_text(json.dumps({'returncode':p.returncode})+'\n')
p.check_returncode()
report = json.loads(p.stdout)
mutations = []
native = (B/'airoha_ct_fe_native.h').read_text()
for name, previous, replacement in (
        ('native_partial_sif_mask', 'tcam[0][1] = U32_MAX;',
         'tcam[0][1] = XSI_ETH_VIP_PORT_MASK;'),
        ('native_wrong_source', 'tcam[0][0] = XSI_ETH_VIP_PORT_MASK;',
         'tcam[0][0] = BIT(2);')):
    assert previous in native, name
    directory = B/'mutations'/name
    directory.mkdir(parents=True, exist_ok=True)
    for artifact in B.iterdir():
        if artifact.is_file() and artifact.suffix in ('.h', '.inc', '.c'):
            shutil.copyfile(artifact, directory/artifact.name)
    (directory/'airoha_ct_fe_native.h').write_text(native.replace(previous, replacement, 1))
    subprocess.run(['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-I'+str(directory), str(directory/'test.c'), '-o', str(directory/'test')], check=True)
    tested = subprocess.run([str(directory/'test')], capture_output=True, text=True)
    (directory/'stderr.txt').write_text(tested.stderr)
    assert tested.returncode == -signal.SIGABRT and 'assert' in tested.stderr.lower(), (name, tested.stderr)
    assert not any(marker in tested.stderr for marker in ('AddressSanitizer', 'runtime error:')), tested.stderr
    mutations.append(dict(name=name, caught_runtime=True, assertion=tested.stderr.strip()))
report.update(sif_match_model='SPORT-indexed key/mask bit', sif_mutations=mutations)
report.update(sanitizers=['address', 'undefined'], source_sha256={name: hashlib.sha256((a.header if name=='airoha_ct_fe_native.h' else H/name).read_bytes()).hexdigest() for name in ('airoha_ct_native_pair.h', 'airoha_ct_fe_native.h', 'airoha_ct_pair_policy.h', 'airoha_ct_cpu_fallback.h', 'airoha_eth.c', 'airoha_ppe.c')})
(B/'source3-verification.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
