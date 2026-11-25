from pathlib import Path
import subprocess,json
r=Path(__file__).resolve().parent;src=(r/'candidate/drivers/net/ethernet/airoha/airoha_ppe.c').read_text()
def func(name):
 a=src.index(name+'(');a=src.rfind('\nstatic ',0,a)+1;o=src.index('{',a);z=o+1;d=1
 while d:d+=(src[z]=='{')-(src[z]=='}');z+=1
 return src[a:z]
pre=(r/'fixtures/host_mmio_stubs.inc').read_text()
pre=pre.replace('bool ct_l2b_learn_only,ct_owns_sram','bool ct_native_pairs,ct_pair_policy_allowed,ct_pair_gdm_owned,ct_owns_sram').replace('struct { u32 glo,regs[16]; } ct_saved[2];','u32 ct_pair_token,ct_pair_gdm_saved[4]; struct { u32 glo,regs[16]; } ct_saved[2];')
pre=pre.replace('static u32 mmio[0x3000/4];','static u32 mmio[0x3000/4];\nstatic bool drained; static int revoke_error;\nstatic int airoha_ct_native_pair_revoke(struct airoha_ppe*p,int b,u16 w){assert(p&&b==-1&&w==0);if(revoke_error)return revoke_error;drained=true;return 0;}')
pre=pre.replace('clears++; return 0;', 'assert(drained); clears++; return 0;')
pre+='''\n#define FE_PSE_PORT_PPE1 4\n#define FE_PSE_PORT_PPE2 8\n#define AIROHA_GDM1_IDX 1\n#define AIROHA_GDM4_IDX 4\n'''
regs=(r/'candidate/drivers/net/ethernet/airoha/airoha_regs.h').read_text().replace('#include <linux/types.h>','')
arr=src[src.index('static const u16 ct_bank0_regs[]'):src.index('static bool airoha_ppe_ct_learning_init')]
funcs='\n'.join(func(n) for n in ['airoha_ppe_ct_check_sram','airoha_ppe_ct_regs','airoha_ppe_ct_quiesce','airoha_ppe_ct_stop_learning','airoha_ppe_ct_stop'])
main=r'''
int main(void){
 struct {int num_ppe;} soc={2};struct airoha_eth eth={.soc=(void*)&soc};struct airoha_ppe p={.eth=&eth};unsigned cases=0;
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
 for(int bad=-1;bad<8;bad++){
  memset(mmio,0,sizeof mmio);memset(rows,0,sizeof rows);memset(p.ct_saved,0,sizeof p.ct_saved);broken=-1;
  p.ct_native_pairs=true;p.ct_host_ppe=true;p.ct_owns_sram=true;p.ct_restore_pending=true;p.ct_pair_policy_allowed=true;p.ct_pair_token=1;p.ct_pair_gdm_owned=true;
  drained=false;revoke_error=bad==0?-ETIMEDOUT:0;
  for(int b=0;b<2;b++){mmio[REG_PPE_GLO_CFG(b)/4]=1;mmio[REG_PPE_PPE_FLOW_CFG(b)/4]=airoha_ct_pair_flow_mask(&p,b);p.ct_saved[b].regs[5]=123;}
  for(int i=0;i<4;i++)p.ct_pair_gdm_saved[i]=0xa5a54444;
  rows[0].ib1=FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE,2)|FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE,1);
  if(bad==1||bad==2)broken=REG_PPE_HASH_SEED(bad-1);
  if(bad>=3&&bad<=6)broken=REG_GDM_FWD_CFG(bad-2);
  if(bad==7)broken=REG_PPE_PPE_FLOW_CFG(0);
  int result=airoha_ppe_ct_stop(&p);
  assert(result==(bad<0?0:bad==0?-ETIMEDOUT:bad==7?-EBUSY:-EIO));assert(!p.ct_pair_policy_allowed&&!p.ct_host_ppe);
  assert(p.ct_restore_pending==(bad>=0));if(bad!=0&&bad!=7)assert(!rows[0].ib1);cases++;
 }
 printf("PASS %u native bank isolation, selector preservation, owned SRAM, barrier ordering and restore failure cases\n",cases);
}
'''
(r/'build/verify_lifecycle.c').write_text(pre+'\n'+regs+'\n'+(r/'airoha_ct_pair_banks.h').read_text()+'\n'+arr+'\n'+funcs+'\n'+main)
subprocess.run(['clang','-std=gnu11','-O2','-Wall','-Werror','-Wno-unused-but-set-variable','-Wno-unused-variable','-fsanitize=address,undefined',str(r/'build/verify_lifecycle.c'),'-o',str(r/'build/verify_lifecycle')],check=True)
p=subprocess.run([str(r/'build/verify_lifecycle')],check=True,capture_output=True,text=True);print(p.stdout)
(r/'build/lifecycle-verification.json').write_text(json.dumps({'passed':True,'result':p.stdout,'sanitizers':['address','undefined']},indent=2)+'\n')
