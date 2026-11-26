#!/usr/bin/env python3
"""Exercise the production TX gate and descriptor ownership blocks."""
import argparse,hashlib,json,resource,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
s=(a.source/'drivers/net/ethernet/airoha/airoha_eth.c').read_text();o=a.output.resolve();o.mkdir(parents=True,exist_ok=False)
def between(text,start,end):
 i=text.index(start);j=text.index(end,i);return text[i:j]
x=s[s.index('static netdev_tx_t airoha_dev_xmit_common('):]
gate=between(x,'\trcu_read_lock();','\tqdma = rcu_dereference(dev->qdma);')
owner=between(x,'\t\te->skb = i == nr_frags - 1 ? skb : NULL;','\t\te->dma_addr = addr;')
submit=between(x,'\tq->queued += i;','\tif (pon_data) {')
complete=between(s[s.index('static int airoha_qdma_tx_napi_poll'):],'\t\tif (e->pon_owner) {','\n\n\t\tairoha_unmap_xmit_buf')
cleanup=between(s[s.index('static void airoha_qdma_tx_cleanup'):],'\t\t\tif (e->pon_owner) {','\t\t\tairoha_unmap_xmit_buf')
# Queue ownership is cleared on every partial DMA-map rollback before reuse.
rollback=between(x,'\tlist_for_each_entry(e, &tx_list, list) {','\tlist_splice(&tx_list, &q->tx_list);')
pre=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define NETDEV_TX_BUSY 1
#define unlikely(x) (x)
#define smp_load_acquire(p) (*(p))
struct net_device { bool stopped; };
struct airoha_gdm_dev { bool pon_update_blocked; int pon_tx_pending; void *eth; };
struct sk_buff { int unused; };
struct airoha_queue_entry { struct sk_buff *skb; struct airoha_gdm_dev *pon_owner; };
struct queue { int queued; };
static int readers,unmaps;
static void rcu_read_lock(void){readers++;}
static void rcu_read_unlock(void){assert(readers);readers--;}
static void atomic_inc(int *v){++*v;}
static void atomic_dec(int *v){assert(*v>0);--*v;}
static void netif_tx_stop_queue(struct net_device *n){n->stopped=true;}
static struct net_device *skb_get_tx_queue(struct net_device *n,struct sk_buff *s){(void)s;return n;}
static void airoha_unmap_xmit_buf(void *eth,struct airoha_queue_entry *e){(void)eth;(void)e;unmaps++;}
static int enter(bool pon,struct airoha_gdm_dev *dev,struct net_device *owner_netdev,struct sk_buff *skb){
'''
body=pre+gate+'rcu_read_unlock();return 0;}\n'
body+='static void assign(struct airoha_queue_entry *e,bool pon,struct airoha_gdm_dev *dev,struct sk_buff *skb,int i,int nr_frags){\n'+owner+'}\n'
body+='static void submit(struct queue *q,int i,bool pon,struct airoha_gdm_dev *dev){\n'+submit+'}\n'
body+='static void complete(struct airoha_queue_entry *e){\n'+complete+'}\n'
body+='static void cleanup(struct airoha_queue_entry *e){\n'+cleanup+'}\n'
body+='''#define list_for_each_entry(e,head,list) for(int _n=0;_n<count && ((e)=&entries[_n],1);_n++)
static void rollback(struct airoha_queue_entry *entries,int count,struct airoha_gdm_dev *dev){struct airoha_queue_entry *e;\n'''+rollback+'}\n'
body+=r'''
int main(void){
 unsigned int cases=0;
 for(int frags=1;frags<=18;frags++){
  struct airoha_gdm_dev d={0};struct net_device owner={0};struct sk_buff skb={0};struct queue q={0};
  struct airoha_queue_entry entries[18]={0};
  assert(!enter(true,&d,&owner,&skb)&&!readers);
  for(int i=0;i<frags;i++)assign(&entries[i],true,&d,&skb,i,frags);
  submit(&q,frags,true,&d);assert(d.pon_tx_pending==1&&q.queued==frags);
  d.pon_update_blocked=true;
  assert(enter(true,&d,&owner,&skb)==NETDEV_TX_BUSY&&owner.stopped&&!readers);
  for(int i=0;i<frags-1;i++)complete(&entries[i]);
  assert(d.pon_tx_pending==1);complete(&entries[frags-1]);assert(!d.pon_tx_pending);
  cleanup(&entries[frags-1]);assert(!d.pon_tx_pending);
  d.pon_update_blocked=false;assert(!enter(true,&d,&owner,&skb));
  for(int i=0;i<frags;i++)assign(&entries[i],true,&d,&skb,i,frags);
  submit(&q,frags,true,&d);for(int i=0;i<frags;i++)cleanup(&entries[i]);assert(!d.pon_tx_pending);
  /* DMA-map failure before publication: rollback clears stale ownership. */
  for(int i=0;i<frags;i++)assign(&entries[i],true,&d,&skb,i,frags);
  unmaps=0;rollback(entries,frags,&d);assert(unmaps==frags&&!d.pon_tx_pending);
  for(int i=0;i<frags;i++){assert(!entries[i].skb&&!entries[i].pon_owner);cleanup(&entries[i]);}
  cases++;
 }
 struct airoha_gdm_dev d={.pon_update_blocked=true};struct net_device owner={0};struct sk_buff skb={0};struct queue q={0};struct airoha_queue_entry e={0};
 assert(!enter(false,&d,&owner,&skb)&&!owner.stopped);
 assign(&e,false,&d,&skb,0,1);submit(&q,1,false,&d);assert(!e.pon_owner&&!d.pon_tx_pending);complete(&e);
 assert(!readers);printf("PASS %u TX ownership scenarios and non-PON regression\n",cases);return 0;
}
'''
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def run(label,text,fail=False):
 c=o/(label+'.c');c.write_text(text);exe=o/label
 b=subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=address,undefined',str(c),'-o',str(exe)],text=True,capture_output=True)
 (o/(label+'.build.log')).write_text(b.stdout+b.stderr);assert not b.returncode,b.stderr
 r=subprocess.run([str(exe)],text=True,capture_output=True);(o/(label+'.log')).write_text(r.stdout+r.stderr);assert bool(r.returncode)==fail,(label,r.stdout,r.stderr);return r.stdout.strip()
result=run('tx',body)
mutations={
 'forget_ownership':('e->pon_owner = pon && e->skb ? dev : NULL;','e->pon_owner = pon && e->skb && false ? dev : NULL;'),
 'ignore_gate':('pon && unlikely(smp_load_acquire(&dev->pon_update_blocked))','pon && unlikely(smp_load_acquire(&dev->pon_update_blocked)) && false'),
 'leave_cleanup_owner':('e->pon_owner = NULL;','/* retain owner */'),
}
for label,(old,new) in mutations.items():
 assert old in body;run(label,body.replace(old,new),True)
report={'passed':True,'result':result,'negative_controls':list(mutations),'source_sha256':hashlib.sha256(s.encode()).hexdigest()}
(o/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
