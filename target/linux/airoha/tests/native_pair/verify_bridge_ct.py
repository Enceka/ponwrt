from pathlib import Path
import hashlib,json,re,subprocess
r=Path(__file__).resolve().parent
header=(r/'candidate/include/linux/netfilter.h').read_text()
enum=re.search(r'enum nf_hook_ops_type \{.*?\n\};',header,re.S)[0]
policy=(r/'airoha_ct_pair_policy.h').read_text()
logic=policy[policy.index('static bool airoha_ct_pair_bridge_ct_hook'):policy.index('static bool airoha_ct_pair_policy_hooks')]
bridge=(r/'candidate/net/bridge/netfilter/nf_conntrack_bridge.c').read_text()
ops=re.search(r'static struct nf_hook_ops nf_ct_bridge_hook_ops\[\].*?\n\};',bridge,re.S)[0]
pre=r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#define __read_mostly
#define NFPROTO_BRIDGE 7
#define NF_BR_PRE_ROUTING 0
#define NF_BR_LOCAL_IN 1
#define NF_BR_FORWARD 2
#define NF_BR_LOCAL_OUT 3
#define NF_BR_POST_ROUTING 4
#define NF_IP_PRI_CONNTRACK (-200)
#define NF_IP_PRI_CONNTRACK_CONFIRM 2147483647
static void nf_ct_bridge_pre(void) {}
static void nf_ct_bridge_in(void) {}
static void nf_ct_bridge_post(void) {}
'''
structs=r'''
struct nf_hook_ops {
 void (*hook)(void); void *dev,*priv; unsigned char pf;
 enum nf_hook_ops_type hook_ops_type:8; unsigned int hooknum; int priority;
};
struct nf_hook_entries { unsigned int num_hook_entries; struct nf_hook_ops **ops; };
static struct nf_hook_ops **nf_hook_entries_get_hook_ops(struct nf_hook_entries *e) { return e->ops; }
_Static_assert(NF_HOOK_OP_UNDEFINED==0 && NF_HOOK_OP_NF_TABLES==1 && NF_HOOK_OP_BPF==2 && NF_HOOK_OP_NFT_FT==3 && NF_HOOK_OP_BRIDGE_CT==4,"enum ABI");
'''
main=r'''
int main(void) {
 unsigned int cases=0;
 assert(airoha_ct_pair_nft_hooks(NULL,-1)); cases++;
 for(int i=0;i<3;i++) {
  struct nf_hook_ops valid=nf_ct_bridge_hook_ops[i], item=valid;
  struct nf_hook_ops *list[]={&item};struct nf_hook_entries entries={1,list};
  assert(airoha_ct_pair_nft_hooks(&entries,valid.hooknum));cases++;
  for(int head=-1;head<=5;head++) {
   assert(airoha_ct_pair_nft_hooks(&entries,head)==(head==(int)valid.hooknum));cases++;
  }
  for(int pf=0;pf<16;pf++) {
   item=valid;item.pf=pf;
   assert(airoha_ct_pair_nft_hooks(&entries,valid.hooknum)==(pf==NFPROTO_BRIDGE));cases++;
  }
  for(int hook=0;hook<=5;hook++) {
   item=valid;item.hooknum=hook;
   assert(airoha_ct_pair_nft_hooks(&entries,valid.hooknum)==(hook==(int)valid.hooknum));cases++;
  }
  const int priorities[]={-300,-201,-200,-199,0,200,2147483646,2147483647};
  for(unsigned int n=0;n<sizeof priorities/sizeof priorities[0];n++) {
   item=valid;item.priority=priorities[n];
   assert(airoha_ct_pair_nft_hooks(&entries,valid.hooknum)==(priorities[n]==valid.priority));cases++;
  }
  for(int n=0;n<3;n++) {
   item=valid;if(n==0)item.dev=&item;if(n==1)item.priv=&item;if(n==2)item.hook=NULL;
   assert(!airoha_ct_pair_nft_hooks(&entries,valid.hooknum));cases++;
  }
  for(int type=0;type<8;type++)for(int head=-1;head<=5;head++) {
   item=valid;item.hook_ops_type=type;
   bool allowed=type==NF_HOOK_OP_NF_TABLES || type==NF_HOOK_OP_NFT_FT ||
       (type==NF_HOOK_OP_BRIDGE_CT && head==(int)valid.hooknum);
   assert(airoha_ct_pair_nft_hooks(&entries,head)==allowed);cases++;
  }
  struct nf_hook_ops nft={.hook_ops_type=NF_HOOK_OP_NF_TABLES},unknown={.hook_ops_type=NF_HOOK_OP_UNDEFINED};
  struct nf_hook_ops *mixed[]={&nft,&item,&unknown};
  item=valid;entries=(struct nf_hook_entries){2,mixed};
  assert(airoha_ct_pair_nft_hooks(&entries,valid.hooknum));cases++;
  entries.num_hook_entries=3;assert(!airoha_ct_pair_nft_hooks(&entries,valid.hooknum));cases++;
 }
 printf("PASS %u actual C bridge conntrack hook identity, head, priority and unknown-hook rejection cases\n",cases);
}
'''
source=pre+enum+structs+ops+logic+main
p=r/'build/verify_bridge_ct.c';p.write_text(source)
exe=r/'build/verify_bridge_ct'
subprocess.run(['clang','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p),'-o',str(exe)],check=True)
result=subprocess.check_output([str(exe)],text=True)
report={'passed':True,'cases':int(result.split()[1]),'result':result.strip(),'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'sanitizers':['address','undefined'],'extracted_actual_source':['nf_hook_ops_type','nf_ct_bridge_hook_ops','airoha_ct_pair_bridge_ct_hook','airoha_ct_pair_nft_hooks']}
(r/'build/bridge-ct-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(result,end='')
