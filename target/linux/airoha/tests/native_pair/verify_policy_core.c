#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
typedef uint64_t u64;
typedef int atomic_t;
#define ATOMIC_INIT(x) (x)
#define atomic_read(p) (*(p))
#define atomic_inc(p) (++*(p))
#define atomic_dec(p) (--*(p))
#define U64_MAX UINT64_MAX
#define READ_ONCE(x) (x)
#define DEFINE_MUTEX(n) pthread_mutex_t n=PTHREAD_MUTEX_INITIALIZER
#define BLOCKING_NOTIFIER_HEAD(n) struct notifier_block*n
#define EXPORT_SYMBOL_GPL(x)
#define mutex_trylock(x) (!pthread_mutex_trylock(x))
#define mutex_lock(x) assert(!pthread_mutex_lock(x))
#define mutex_unlock(x) assert(!pthread_mutex_unlock(x))
#define lockdep_assert_held(x) assert(pthread_mutex_trylock(x)==EBUSY)
#define notifier_to_errno(x) (x)
enum {NF_NATIVE_PAIR_PRE=1,NF_NATIVE_PAIR_POST};
struct notifier_block {int(*call)(unsigned long);};
static int blocking_notifier_chain_register(struct notifier_block**c,struct notifier_block*n){assert(!*c);*c=n;return 0;}
static void blocking_notifier_chain_unregister(struct notifier_block**c,struct notifier_block*n){assert(*c==n);*c=NULL;}
static int blocking_notifier_call_chain(struct notifier_block**c,unsigned long e,void*p){assert(!p);return *c?(*c)->call(e):0;}
#include "nf_native_pair_core.inc"
static unsigned pre,post;static int revoke_err;
static int event(unsigned long e){if(e==NF_NATIVE_PAIR_PRE){pre++;return revoke_err;}assert(e==NF_NATIVE_PAIR_POST);post++;return 0;}
static struct notifier_block nb={.call=event};
static pthread_mutex_t signal_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t signal_cond=PTHREAD_COND_INITIALIZER;
static bool attempting;static int lock_result;
static void*authorize(void*unused){(void)unused;mutex_lock(&signal_mutex);attempting=true;pthread_cond_signal(&signal_cond);mutex_unlock(&signal_mutex);lock_result=nf_native_pair_policy_lock(1);if(!lock_result)nf_native_pair_policy_unlock();return NULL;}
int main(void){
 unsigned cases=0;assert(!nf_native_pair_register(&nb));
 assert(nf_native_pair_policy_generation()==1);assert(nf_native_pair_policy_lock(0)==-ESTALE);assert(nf_native_pair_policy_lock(2)==-ESTALE);assert(!nf_native_pair_policy_lock(1));nf_native_pair_policy_unlock();cases+=4;
 assert(!nf_native_pair_policy_begin());assert(pre==1&&post==0&&nf_native_pair_policy_generation()==2);
 pthread_t thread;assert(!pthread_create(&thread,NULL,authorize,NULL));mutex_lock(&signal_mutex);while(!attempting)assert(!pthread_cond_wait(&signal_cond,&signal_mutex));mutex_unlock(&signal_mutex);
 nf_native_pair_policy_end();assert(!pthread_join(thread,NULL));assert(lock_result==-ESTALE&&post==1&&nf_native_pair_policy_generation()==3);cases++;
 for(unsigned i=0;i<3;i++){revoke_err=i==0?-ETIMEDOUT:i==1?-EAGAIN:-EIO;u64 g=nf_native_pair_policy_generation();assert(nf_native_pair_policy_begin()==revoke_err);assert(nf_native_pair_policy_generation()==g+2&&pre==post);assert(!nf_native_pair_policy_lock(g+2));nf_native_pair_policy_unlock();cases++;}
 nf_native_pair_generation=U64_MAX-1;assert(nf_native_pair_policy_begin()==-EOVERFLOW);assert(!nf_native_pair_policy_lock(U64_MAX-1));nf_native_pair_policy_unlock();cases++;
 assert(nf_native_pair_bpf_begin()==-EOPNOTSUPP);cases++;
 nf_native_pair_unregister(&nb);assert(!nf_native_pair_bpf_begin());assert(nf_native_pair_register(&nb)==-EBUSY);nf_native_pair_bpf_end();assert(!nf_native_pair_register(&nb));nf_native_pair_unregister(&nb);cases++;printf("PASS %u policy generation, begin/end error pairing and concurrent stale authorization cases\n",cases);
}
