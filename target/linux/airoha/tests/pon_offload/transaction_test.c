/* Production headers run against deterministic MMIO and kernel API faults. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#undef ETIMEDOUT
#define ETIMEDOUT 110
#define BIT(n) (1U << (n))
#define GENMASK(h,l) ((~0U << (l)) & (~0U >> (31-(h))))
#define FIELD_GET(mask,value) (((value) & (mask)) >> __builtin_ctz(mask))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define smp_store_release(p,v) (*(p)=(v))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define EXPORT_SYMBOL_GPL(x)
#define rcu_dereference_protected(p,c) (assert(c),(p))
#define rcu_replace_pointer(p,n,c) (assert(c),replace_table(&(p),(n)))
#define REG_QUEUE_CLOSE_CFG(n) (0xa0+((n)&~3U))
#define REG_GDM_CHN_RLS(n) 0x1520
#define REG_GDM_TXCHN_EN(n) 0x1524
#define REG_GDM_RXCHN_EN(n) 0x1528
#define AIROHA_DEV_F_PON 2
#define AIROHA_PON_QDMA_VALID BIT(31)
#define AIROHA_PON_QDMA_TCONT_MASK GENMASK(20,16)
typedef uint8_t u8;
typedef uint32_t u32;
typedef int atomic_t;
struct mutex { int held; };
static struct mutex flow_offload_mutex;
static unsigned int calls, writes, fail_write, syncs, retired, reopened, revoke_calls;
static int revoke_error, pending_error, late_submit, completions;
static bool bad_order;
#ifdef AIROHA_TEST_NPU_OWNER
static unsigned int owner_calls;
static int owner_error;
#endif
static u32 fe[0x2000/4], qdma_regs[0x2000/4];
static const u32 age = (3U<<25)|(3U<<17);
static struct airoha_gdm_dev *current;
static const int airoha_netdev_ops = 1;
struct airoha_qdma { int unused; };
struct airoha_eth {
 struct mutex pon_config_lock;
 struct airoha_gdm_dev *pon_update_owner;
 struct airoha_qdma qdma[2];
};
struct airoha_pon_flow_entry { u32 tag; };
struct airoha_pon_flow_table { unsigned int count; struct airoha_pon_flow_entry entries[32]; };
struct net_device { const void *netdev_ops; struct airoha_gdm_dev *priv; bool stopped,running,carrier; int wakes; };
struct airoha_gdm_dev {
 struct airoha_eth *eth;
 unsigned long flags;
 struct airoha_pon_retirement *pon_retirement;
 bool pon_update_blocked,pon_update_ready;
 u32 pon_update_channels,pon_qdma_tag;
 atomic_t pon_tx_pending;
 struct airoha_pon_flow_table *pon_flow_table;
};
static void mutex_lock(struct mutex *m) { assert(!m->held); if(m!=&flow_offload_mutex) assert(flow_offload_mutex.held); m->held=1; }
static void mutex_unlock(struct mutex *m) { assert(m->held); m->held=0; }
#define lockdep_assert_held(m) assert((m)->held)
#define lockdep_is_held(m) ((m)->held)
static bool test_bit(unsigned int n, const unsigned long *p) { return *p & BIT(n); }
static struct airoha_gdm_dev *netdev_priv(struct net_device *n) { return n->priv; }
static bool netif_running(struct net_device *n) { return n->running; }
static bool netif_carrier_ok(struct net_device *n) { return n->carrier; }
static void netif_tx_disable(struct net_device *n) { assert(n->priv->pon_update_blocked); n->stopped=true; }
static void netif_tx_wake_all_queues(struct net_device *n) { assert(!n->priv->pon_update_blocked); n->wakes++; n->stopped=false; }
static void synchronize_net(void) {
 syncs++;
 /* A submitter that read the old gate finishes before the grace period. */
 if(late_submit) { current->pon_tx_pending++; late_submit=0; }
}
static int atomic_read(atomic_t *p) {
 if(completions) { assert(*p>0); --*p; --completions; }
 return *p;
}
#define read_poll_timeout(fn,val,cond,delay,timeout,first,arg) ({ \
 int _ret=-ETIMEDOUT; (void)(delay);(void)(timeout);(void)(first); \
 for(int _i=0;_i<4;_i++){ (val)=fn(arg); if((cond)&&!pending_error){_ret=0;break;} } _ret; })
#ifdef AIROHA_TEST_NPU_OWNER
static int airoha_ppe_npu_owner_close_locked(struct airoha_eth *ethernet) {
 assert(ethernet==current->eth && flow_offload_mutex.held && ethernet->pon_config_lock.held);
 assert(current->pon_update_blocked && !current->pon_tx_pending && syncs);
 owner_calls++; return owner_error;
}
#endif
static int airoha_ppe_remove_egress_flows(struct airoha_gdm_dev *d) {
 assert(d->pon_update_blocked && !d->pon_tx_pending && syncs);
 assert(flow_offload_mutex.held && d->eth->pon_config_lock.held);
#ifdef AIROHA_TEST_NPU_OWNER
 assert(owner_calls && !owner_error);
#endif
 revoke_calls++; return revoke_error;
}
static struct airoha_pon_flow_table *replace_table(struct airoha_pon_flow_table **p,struct airoha_pon_flow_table *n) {
 struct airoha_pon_flow_table *old=*p; *p=n; return old;
}
static void kfree(void *p) { free(p); }
static u32 rd(bool q,u32 a) {
 assert(a<0x2000 && !(a&3));
 u32 value=(q?qdma_regs:fe)[a/4];
 if(!q && a==0x1520 && (value&1)) value|=2;
 return value;
}
static void wr(bool q,u32 a,u32 v) {
 assert(a<0x2000 && !(a&3));
 assert(current->pon_update_blocked && !current->pon_tx_pending);
 assert(flow_offload_mutex.held && current->eth->pon_config_lock.held);
 if(!revoke_calls) bad_order=true;
 writes++;
 if(writes==fail_write) return;
 (q?qdma_regs:fe)[a/4]=v;
 if(!q && a==0x1520 && (v&1)) retired++;
 if(q && a>=0xa0 && a<0xc0 && v!=UINT32_MAX) reopened++;
}
static u32 rmw(bool q,u32 a,u32 m,u32 v) { v=(rd(q,a)&~m)|v;wr(q,a,v);return v; }
#define airoha_fe_rr(e,a) ((void)(e),rd(false,a))
#define airoha_fe_wr(e,a,v) ((void)(e),wr(false,a,v))
#define airoha_fe_rmw(e,a,m,v) ((void)(e),rmw(false,a,m,v))
#define airoha_qdma_rr(q,a) ((void)(q),rd(true,a))
#define airoha_qdma_rmw(q,a,m,v) ((void)(q),rmw(true,a,m,v))
static void usleep_range(unsigned int a,unsigned int b) { assert(a==1000 && b==1100); }
#include "airoha_pon_retire.h"
#include "airoha_pon_transaction.h"
#include "commit.inc"
static struct airoha_eth eth;
static struct airoha_gdm_dev dev;
static struct airoha_pon_retirement state;
static struct net_device net;
static void reset(void) {
 free(dev.pon_flow_table);
 memset(&eth,0,sizeof(eth));memset(&dev,0,sizeof(dev));memset(&state,0,sizeof(state));
 memset(&net,0,sizeof(net));memset(fe,0,sizeof(fe));memset(qdma_regs,0,sizeof(qdma_regs));
 flow_offload_mutex.held=0;writes=fail_write=syncs=retired=reopened=revoke_calls=0;
 revoke_error=pending_error=late_submit=completions=0;bad_order=false;
#ifdef AIROHA_TEST_NPU_OWNER
 owner_calls=0;owner_error=0;
#endif
 dev.eth=&eth;dev.flags=BIT(AIROHA_DEV_F_PON);dev.pon_retirement=&state;
 net.netdev_ops=&airoha_netdev_ops;net.priv=&dev;net.running=net.carrier=true;current=&dev;
 fe[0x1520/4]=age;fe[0x1524/4]=0x5555aaaa;fe[0x1528/4]=0xaaaa5555;
 for(unsigned int i=0;i<8;i++)qdma_regs[(0xa0+4*i)/4]=0x12345678;
}
static void check_closed(u32 mask) {
 assert(dev.pon_update_blocked && eth.pon_update_owner==&dev && net.stopped);
 for(unsigned int i=0;i<32;i++)if(mask&BIT(i))assert(((qdma_regs[REG_QUEUE_CLOSE_CFG(i)/4]>>((i&3)*8))&0xff)==0xff);
}
static void check_end(void) {
 assert(!bad_order && !dev.pon_update_blocked && !dev.pon_update_ready && !eth.pon_update_owner);
 assert(!state.owned && !state.restore_pending && !dev.pon_update_channels);
 assert(fe[0x1520/4]==age && fe[0x1524/4]==0x5555aaaa && fe[0x1528/4]==0xaaaa5555);
 for(unsigned int i=0;i<8;i++)assert(qdma_regs[(0xa0+4*i)/4]==0x12345678);
 calls++;
}
static struct airoha_pon_flow_table *table(unsigned int ch) {
 struct airoha_pon_flow_table *t=calloc(1,sizeof(*t));assert(t);t->count=1;t->entries[0].tag=AIROHA_PON_QDMA_VALID|(ch<<16);return t;
}
int main(void) {
 reset(); assert(airoha_eth_pon_update_begin(NULL,1)==-EINVAL);
 net.netdev_ops=NULL;assert(airoha_eth_pon_update_begin(&net,1)==-EINVAL);net.netdev_ops=&airoha_netdev_ops;
 dev.flags=0;assert(airoha_eth_pon_update_begin(&net,1)==-EOPNOTSUPP);dev.flags=BIT(AIROHA_DEV_F_PON);
 assert(airoha_eth_pon_update_end(&net)==-EBUSY && !writes);calls+=4;
 for(unsigned int ch=0;ch<32;ch++) {
  reset();dev.pon_flow_table=table(ch);dev.pon_qdma_tag=AIROHA_PON_QDMA_VALID|(((ch+1)%32)<<16);
  u32 mask=BIT(ch)|BIT((ch+1)%32)|BIT((ch+2)%32);
  assert(!airoha_eth_pon_update_begin(&net,BIT((ch+2)%32)));check_closed(mask);
  assert(dev.pon_update_channels==mask && state.drained==mask);
  assert(!airoha_eth_pon_commit_config(&dev,NULL,0));
  assert(!airoha_eth_pon_update_end(&net));check_end();
 }
 reset(); late_submit=1;completions=1;
 assert(!airoha_eth_pon_update_begin(&net,1)); assert(!dev.pon_tx_pending && !late_submit && !completions);
 assert(!airoha_eth_pon_update_end(&net));check_end();
 for(int ctrl=0;ctrl<2;ctrl++) {
  reset();dev.pon_tx_pending=1;assert(airoha_eth_pon_update_begin(&net,1)==-ETIMEDOUT);
  assert(dev.pon_update_blocked&&!writes&&!revoke_calls&&!dev.pon_update_ready);
#ifdef AIROHA_TEST_NPU_OWNER
  assert(!owner_calls);
#endif
  assert(airoha_eth_pon_update_end(&net)==-EBUSY);
  completions=1;assert(!airoha_eth_pon_update_begin(&net,1));assert(!airoha_eth_pon_update_end(&net));check_end();
 }
#ifdef AIROHA_TEST_NPU_OWNER
 reset();owner_error=-ETIMEDOUT;dev.pon_flow_table=table(7);
 assert(airoha_eth_pon_update_begin(&net,1)==-ETIMEDOUT);
 assert(owner_calls==1 && !writes && !revoke_calls && !dev.pon_update_ready);
 assert(dev.pon_update_blocked && dev.pon_flow_table && eth.pon_update_owner==&dev);
 assert(airoha_eth_pon_update_end(&net)==-EBUSY);
 owner_error=0;assert(!airoha_eth_pon_update_begin(&net,1));
 assert(owner_calls==2 && revoke_calls==1);
 assert(!airoha_eth_pon_update_end(&net));check_end();
#endif
 reset();revoke_error=-ETIMEDOUT;dev.pon_flow_table=table(7);
 assert(airoha_eth_pon_update_begin(&net,1)==-ETIMEDOUT);
 assert(!writes&&dev.pon_flow_table&&dev.pon_update_blocked);
 revoke_error=0;assert(!airoha_eth_pon_update_begin(&net,1));assert(!airoha_eth_pon_update_end(&net));check_end();
 reset();assert(airoha_eth_pon_commit_config(&dev,NULL,0)==-EBUSY);calls++;
 reset();assert(!airoha_eth_pon_update_begin(&net,1));
 struct airoha_pon_flow_table *new=table(31);
 assert(airoha_eth_pon_commit_config(&dev,new,0)==-EINVAL&&!dev.pon_flow_table);free(new);
 assert(!airoha_eth_pon_update_begin(&net,BIT(31)));new=table(31);
 assert(!airoha_eth_pon_commit_config(&dev,new,0));assert(dev.pon_flow_table==new);
 assert(!airoha_eth_pon_update_end(&net));check_end();
 reset();assert(!airoha_eth_pon_update_begin(&net,1));
 revoke_error=-EIO;new=table(0);assert(airoha_eth_pon_commit_config(&dev,new,0)==-EIO&&!dev.pon_flow_table);free(new);
 revoke_error=0;assert(!airoha_eth_pon_update_begin(&net,1));assert(!airoha_eth_pon_update_end(&net));check_end();
 /* Every MMIO write in a three-channel transaction can fail once. */
 reset();assert(!airoha_eth_pon_update_begin(&net,BIT(0)|BIT(17)|BIT(31)));assert(!airoha_eth_pon_update_end(&net));unsigned int total=writes;
 for(unsigned int fail=1;fail<=total;fail++) {
  reset();fail_write=fail;
  int ret=airoha_eth_pon_update_begin(&net,BIT(0)|BIT(17)|BIT(31));
  if(!ret)ret=airoha_eth_pon_update_end(&net);
  /* A duplicate idempotent close can absorb a dropped write. */
  if(ret) {
   assert(ret==-EIO&&dev.pon_update_blocked&&eth.pon_update_owner==&dev);
   fail_write=0;assert(!airoha_eth_pon_update_begin(&net,0));
   assert(!airoha_eth_pon_update_end(&net));
  }
  check_end();
 }
 reset();assert(!airoha_eth_pon_update_begin(&net,0));assert(!airoha_eth_pon_update_end(&net));check_end();
 reset();net.carrier=false;assert(!airoha_eth_pon_update_begin(&net,1));assert(!airoha_eth_pon_update_end(&net));assert(!net.wakes);check_end();
 reset();struct airoha_gdm_dev other={0};eth.pon_update_owner=&other;
 assert(airoha_eth_pon_update_begin(&net,1)==-EBUSY&&!writes&&!dev.pon_update_blocked);calls++;
 printf("PASS %u transaction scenarios, including %u MMIO fault positions\n",calls,total);
 reset();return 0;
}
