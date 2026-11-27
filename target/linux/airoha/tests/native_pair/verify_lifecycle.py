from pathlib import Path
import subprocess,json
r=Path(__file__).resolve().parent;src=(r/'candidate/drivers/net/ethernet/airoha/airoha_ppe.c').read_text()
def func(name):
 a=src.index(name+'(');a=src.rfind('\nstatic ',0,a)+1;o=src.index('{',a);z=o+1;d=1
 while d:d+=(src[z]=='{')-(src[z]=='}');z+=1
 return src[a:z]
pre=(r/'fixtures/host_mmio_stubs.inc').read_text()
pre=pre.replace('bool ct_l2b_learn_only,ct_owns_sram','struct {bool armed,touched,pending,arm_pending;} ct_fe; bool ct_native_pairs,ct_pair_policy_allowed,ct_pair_gdm_owned,ct_owns_sram').replace('struct { u32 glo,regs[16]; } ct_saved[2];','u32 ct_pair_token,ct_pair_gdm_saved[4]; struct { u32 glo,regs[16]; } ct_saved[2];')
pre=pre.replace('struct airoha_eth {', 'struct airoha_eth {void*npu;')
pre+='\n#define rcu_access_pointer(x) (x)\n'
pre=pre.replace('static u32 mmio[0x3000/4];','static u32 mmio[0x3000/4];\nstatic bool drained; static int revoke_error;\nstatic int airoha_ct_native_pair_revoke(struct airoha_ppe*p,int b,u16 w){assert(p&&b==-1&&w==0);if(revoke_error)return revoke_error;drained=true;return 0;}')
pre=pre.replace('clears++; return 0;', 'assert(drained); clears++; return 0;')
pre=pre.replace('static int airoha_ppe_ct_ifc_stop(struct airoha_ppe *p) { (void)p; return 0; }', r'''
static int optical_error,global_ifc_error;
static unsigned optical_stops,global_ifc_stops,smac_stops;
static bool optical_saved,optical_pending,global_ifc_saved;
static int airoha_ct_pon_ifc_cpu_stop(struct airoha_ppe *ppe){
 assert(ppe&&!ppe->ct_host_ppe&&!ppe->ct_pair_policy_allowed);
 optical_stops++;
 if(optical_error){optical_pending=true;return optical_error;}
 optical_saved=optical_pending=false;return 0;
}
static int airoha_ppe_ct_ifc_stop(struct airoha_ppe *ppe){
 assert(ppe&&optical_stops&&!optical_saved&&!optical_pending);
 global_ifc_stops++;if(global_ifc_error)return global_ifc_error;
 global_ifc_saved=false;return 0;
}
''')
pre=pre.replace('static int airoha_ppe_ct_smac_stop(struct airoha_ppe *p) { (void)p; return 0; }',
 'static int airoha_ppe_ct_smac_stop(struct airoha_ppe *p) { assert(p&&global_ifc_stops&&!global_ifc_saved); smac_stops++; return 0; }')
pre+='\nstatic int gate_error;static unsigned gate_calls;static int airoha_ct_pair_wlan_gate(struct airoha_ppe*p){assert(p&&drained);gate_calls++;return gate_error;}\n'
pre+='''\n#define FE_PSE_PORT_PPE1 4\n#define FE_PSE_PORT_PPE2 8\n#define AIROHA_GDM1_IDX 1\n#define AIROHA_GDM4_IDX 4\n'''
regs=(r/'candidate/drivers/net/ethernet/airoha/airoha_regs.h').read_text().replace('#include <linux/types.h>','')
arr=src[src.index('static const u16 ct_bank0_regs[]'):src.index('static bool airoha_ppe_ct_learning_init')]
funcs='\n'.join(func(n) for n in ['airoha_ppe_ct_check_sram','airoha_ppe_ct_regs','airoha_ppe_ct_quiesce','airoha_ppe_ct_stop_learning','airoha_ppe_ct_stop'])
main=r'''
int main(void){
 struct {int num_ppe;} soc={2};struct airoha_eth eth={.soc=(void*)&soc,.npu=(void*)1};struct airoha_ppe p={.eth=&eth};unsigned cases=0;
 for(int active=0;active<2;active++)for(int owns=0;owns<2;owns++)for(int bank=0;bank<2;bank++)for(int state=1;state<4;state++)for(int stat=0;stat<2;stat++)for(int op=0;op<3;op++){
  memset(rows,0,sizeof rows);p.ct_native_pairs=active;p.ct_owns_sram=owns;drained=true;clears=0;
  rows[bank*8].ib1=FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE,2)|FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE,state)|(stat?BIT(31):0);
  bool allowed=active&&owns&&!bank&&state==1&&!stat&&op!=0;
  assert(airoha_ppe_ct_check_sram(&p,op)==(allowed?0:-EBUSY));assert(clears==(allowed&&op==2));cases++;
 }
 p.ct_native_pairs=true;assert(airoha_ct_pair_flow_mask(&p,0)==0xb200&&airoha_ct_pair_flow_mask(&p,1)==0x3200);cases++;
 for(int q=0;q<4;q++)for(int value=0;value<16;value++){
  u32 original=0xa5a50000|(value<<(q*4));u32 actual=airoha_ct_pair_gdm_route(original);
  assert(actual==(value==4?((original&~(0xf<<(q*4)))|(8<<(q*4))):original));cases++;
 }
 for(int bad=-1;bad<4;bad++){
  memset(mmio,0,sizeof mmio);broken=-1;p.ct_pair_gdm_owned=false;
  for(int i=1;i<=4;i++)mmio[REG_GDM_FWD_CFG(i)/4]=0xa5a50000|(i==2?0x9999:0x4444);
  if(bad>=0)broken=REG_GDM_FWD_CFG(bad+1);
  int expected=bad<0||bad==1?0:-EIO;assert(airoha_ct_pair_gdm_start(&p)==expected);
  assert(p.ct_pair_gdm_owned);assert(mmio[REG_GDM_FWD_CFG(2)/4]==0xa5a59999);
  broken=-1;assert(!airoha_ct_pair_gdm_stop(&p)&&!p.ct_pair_gdm_owned);
  for(int i=1;i<=4;i++)assert(mmio[REG_GDM_FWD_CFG(i)/4]==(0xa5a50000|(i==2?0x9999:0x4444)));cases++;
 }
 for(int bad=-1;bad<9;bad++){
  optical_stops=global_ifc_stops=smac_stops=0;optical_saved=global_ifc_saved=true;optical_pending=false;
  memset(mmio,0,sizeof mmio);memset(rows,0,sizeof rows);memset(p.ct_saved,0,sizeof p.ct_saved);broken=-1;
  p.ct_native_pairs=true;p.ct_host_ppe=true;p.ct_owns_sram=true;p.ct_restore_pending=true;p.ct_pair_policy_allowed=true;p.ct_pair_token=1;p.ct_pair_gdm_owned=true;
  drained=false;revoke_error=bad==0?-ETIMEDOUT:0;gate_error=bad==8?-EAGAIN:0;gate_calls=0;
  for(int b=0;b<2;b++){mmio[REG_PPE_GLO_CFG(b)/4]=1;mmio[REG_PPE_PPE_FLOW_CFG(b)/4]=airoha_ct_pair_flow_mask(&p,b);p.ct_saved[b].regs[5]=123;}
  for(int i=0;i<4;i++)p.ct_pair_gdm_saved[i]=0xa5a54444;
  rows[0].ib1=FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE,2)|FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE,1);
  if(bad==1||bad==2)broken=REG_PPE_HASH_SEED(bad-1);
  if(bad>=3&&bad<=6)broken=REG_GDM_FWD_CFG(bad-2);
  if(bad==7)broken=REG_PPE_PPE_FLOW_CFG(0);
  int result=airoha_ppe_ct_stop(&p);
  assert(result==(bad<0?0:bad==0?-ETIMEDOUT:bad==7?-EBUSY:bad==8?-EAGAIN:-EIO));assert(!p.ct_pair_policy_allowed&&!p.ct_host_ppe);
  if(bad==8){
   for(unsigned retry=0;retry<3;retry++){
    assert(airoha_ppe_ct_stop(&p)==-EAGAIN&&gate_calls==retry+2);
    assert(!p.ct_host_ppe&&p.ct_owns_sram&&p.ct_restore_pending&&rows[0].ib1);
    assert(mmio[REG_PPE_GLO_CFG(0)/4]&1);assert(mmio[REG_PPE_GLO_CFG(1)/4]&1);
   }
   gate_error=0;assert(!airoha_ppe_ct_stop(&p)&&gate_calls==5&&!p.ct_restore_pending&&!rows[0].ib1);
   cases++;continue;
  }
  assert(p.ct_restore_pending==(bad>=0));assert(gate_calls==(bad==0?0:1));if(bad==8)assert(mmio[REG_PPE_GLO_CFG(0)/4]&1);if(bad!=0&&bad!=7&&bad!=8)assert(!rows[0].ib1);cases++;
 }
 const int errors[]={-EAGAIN,-ETIMEDOUT,-EIO,-EOPNOTSUPP};
 for(unsigned failure=0;failure<ARRAY_SIZE(errors);failure++)for(unsigned target=0;target<2;target++){
  memset(mmio,0,sizeof mmio);memset(rows,0,sizeof rows);memset(p.ct_saved,0,sizeof p.ct_saved);broken=-1;
  p.ct_native_pairs=true;p.ct_host_ppe=true;p.ct_owns_sram=true;p.ct_restore_pending=true;
  p.ct_pair_policy_allowed=true;p.ct_pair_token=1;p.ct_pair_gdm_owned=true;
  drained=false;revoke_error=gate_error=0;gate_calls=0;
  optical_stops=global_ifc_stops=smac_stops=0;optical_saved=global_ifc_saved=true;optical_pending=false;
  optical_error=target==0?errors[failure]:0;global_ifc_error=target==1?errors[failure]:0;
  for(unsigned bank=0;bank<2;bank++){
   mmio[REG_PPE_GLO_CFG(bank)/4]=1;
   mmio[REG_PPE_PPE_FLOW_CFG(bank)/4]=airoha_ct_pair_flow_mask(&p,bank);
   p.ct_saved[bank].regs[5]=123;
  }
  for(unsigned port=0;port<4;port++){p.ct_pair_gdm_saved[port]=0xa5a54444;mmio[REG_GDM_FWD_CFG(port+1)/4]=0xa5a58888;}
  rows[0].ib1=FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE,2)|FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE,1);
  for(unsigned retry=0;retry<3;retry++){
   assert(airoha_ppe_ct_stop(&p)==errors[failure]);
   assert(optical_stops==retry+1&&global_ifc_stops==(target?retry+1:0)&&!smac_stops);
   assert(optical_saved==!target&&optical_pending==!target&&global_ifc_saved);
   assert(p.ct_restore_pending&&p.ct_pair_gdm_owned&&!p.ct_host_ppe&&!p.ct_pair_policy_allowed);
   assert(!p.ct_owns_sram&&!rows[0].ib1);
   for(unsigned bank=0;bank<2;bank++)assert(!(mmio[REG_PPE_GLO_CFG(bank)/4]&1)&&p.ct_saved[bank].regs[5]==123);
   for(unsigned port=0;port<4;port++)assert(p.ct_pair_gdm_saved[port]==0xa5a54444&&mmio[REG_GDM_FWD_CFG(port+1)/4]==0xa5a58888);
  }
  optical_error=global_ifc_error=0;assert(!airoha_ppe_ct_stop(&p));
  assert(optical_stops==4&&global_ifc_stops==(target?4:1)&&smac_stops==1);
  assert(!optical_saved&&!optical_pending&&!global_ifc_saved&&!p.ct_restore_pending&&!p.ct_pair_gdm_owned);
  for(unsigned port=0;port<4;port++)assert(mmio[REG_GDM_FWD_CFG(port+1)/4]==0xa5a54444);
  cases++;
 }
 printf("PASS %u native bank isolation, selector preservation, owned SRAM, barrier ordering and restore failure cases\n",cases);
}
'''
route_stub='''
#define U32_MAX UINT32_MAX
static int airoha_gdm_fwd_cfg_update(struct airoha_eth*eth,unsigned id,u32 mask,u32 value){
 u32 cfg=(airoha_fe_rr(eth,REG_GDM_FWD_CFG(id))&~mask)|(value&mask);
 airoha_fe_wr(eth,REG_GDM_FWD_CFG(id),cfg);
 return airoha_fe_rr(eth,REG_GDM_FWD_CFG(id))==cfg?0:-EIO;
}
'''
(r/'build/verify_lifecycle.c').write_text(pre+'\n'+regs+'\n'+route_stub+'\n'+(r/'airoha_ct_pair_banks.h').read_text()+'\n'+arr+'\n'+funcs+'\n'+main)
subprocess.run(['clang','-std=gnu11','-O2','-Wall','-Werror','-Wno-unused-but-set-variable','-Wno-unused-variable','-fsanitize=address,undefined',str(r/'build/verify_lifecycle.c'),'-o',str(r/'build/verify_lifecycle')],check=True)
p=subprocess.run([str(r/'build/verify_lifecycle')],check=True,capture_output=True,text=True);print(p.stdout)
(r/'build/lifecycle-verification.json').write_text(json.dumps({'passed':True,'cases':int(p.stdout.split()[1]),'result':p.stdout,'sanitizers':['address','undefined']},indent=2)+'\n')
