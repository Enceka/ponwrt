#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define BIT(n) (UINT32_C(1) << (n))
#define GENMASK(h, l) ((UINT32_MAX >> (31-(h))) & (UINT32_MAX << (l)))
#define FIELD_GET(m, v) (((v) & (m)) >> __builtin_ctz(m))
#define FIELD_PREP(m, v) (((u32)(v) << __builtin_ctz(m)) & (m))
#define DECLARE_FLEX_ARRAY(t, n) t n[0]
#define PPE_ENTRY_SIZE 80
#undef static_assert
#define static_assert(expr) _Static_assert(expr, #expr)
#include "foe_types.inc"

struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &(n), &(n) }
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
static void list_init(struct list_head *p) { p->next=p->prev=p; }
static bool list_empty(const struct list_head *p) { return p->next==p; }
static void list_add_tail(struct list_head *p, struct list_head *h) {
    assert(list_empty(p)); p->prev=h->prev; p->next=h; h->prev->next=p; h->prev=p;
}
static void list_del_init(struct list_head *p) {
    p->prev->next=p->next; p->next->prev=p->prev; list_init(p);
}
#define FIRST(h,t,m) (list_empty(h) ? NULL : container_of((h)->next,t,m))
#define NEXT(p,h,t,m) ((p)->m.next==(h) ? NULL : container_of((p)->m.next,t,m))
#define list_for_each_entry_safe(p,n,h,m) \
    for ((p)=FIRST(h,__typeof__(*(p)),m), (n)=(p)?NEXT(p,h,__typeof__(*(p)),m):NULL; \
         (p); (p)=(n), (n)=(p)?NEXT(p,h,__typeof__(*(p)),m):NULL)
struct hlist_node { bool linked; };
static void hlist_del_init(struct hlist_node *p) { p->linked=false; }
enum { FLOW_TYPE_L4, FLOW_TYPE_L2, FLOW_TYPE_L2_SUBFLOW };
struct airoha_pon_flow_table { int generation; };
struct airoha_gdm_dev;
struct airoha_flow_table_entry {
    int type, node; unsigned long cookie;
    u16 hash;
    bool freed;
    struct hlist_node list;
    struct list_head gc_node;
    struct airoha_gdm_dev *egress_dev, *pon_ingress_dev;
    struct airoha_foe_entry data;
};
struct airoha_ppe { bool ct_host_ppe; };
struct airoha_eth { int flow_table; struct airoha_ppe *ppe; };
struct airoha_gdm_dev { unsigned long flags; struct airoha_eth *eth; struct airoha_pon_flow_table *pon_flow_table; u32 pon_qdma_tag; };
struct rhashtable_iter { unsigned index; };
static int flow_offload_mutex, ppe_lock, airoha_flow_table_params;
static struct airoha_ppe ppe;
static struct airoha_eth eth;
static struct airoha_gdm_dev pon, other;
static struct airoha_pon_flow_table old_table, next_table;
static struct airoha_flow_table_entry entries[4];
static struct airoha_foe_entry rows[4];
static void *walk[12];
static unsigned walk_count, reads, writes, frees, syncs, table_frees, legacy_removes;
static int read_fail, write_fail;
static bool write_applies_on_error;
#define READ_ONCE(v) (v)
#define WRITE_ONCE(v,n) ((v)=(n))
#define lockdep_assert_held(p) assert(*(p))
#define rcu_replace_pointer(p,v,held) ((void)assert(held), replace_table(&(p),(v)))
#define lockdep_is_held(p) (*(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
static void spin_lock_bh(int *p) { assert(!*p); *p=1; }
static void spin_unlock_bh(int *p) { assert(*p); *p=0; }
static void mutex_lock(int *p) { assert(!*p && !ppe_lock); *p=1; }
static void mutex_unlock(int *p) { assert(*p && !ppe_lock); *p=0; }
static void synchronize_net(void) { assert(!flow_offload_mutex && !ppe_lock); syncs++; }
static void kfree(void *p) {
    if (!p) return;
    if (p==&old_table) { assert(syncs && !flow_offload_mutex); table_frees++; return; }
    for (unsigned i=0;i<4;i++) if (p==&entries[i]) {
        assert(!entries[i].freed && list_empty(&entries[i].gc_node));
        entries[i].freed=true; frees++; return;
    }
    assert(false);
}
static void rhashtable_walk_enter(int *t, struct rhashtable_iter *i) { (void)t; assert(flow_offload_mutex); i->index=0; }
static void rhashtable_walk_start(struct rhashtable_iter *i) { assert(i); }
static void *rhashtable_walk_next(struct rhashtable_iter *i) { return i->index<walk_count ? walk[i->index++] : NULL; }
static void rhashtable_walk_stop(struct rhashtable_iter *i) { assert(i); }
static void rhashtable_walk_exit(struct rhashtable_iter *i) { assert(i); }
static void rhashtable_remove_fast(int *t, int *n, int p) { (void)t;(void)n;(void)p; assert(flow_offload_mutex); }
static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *p, u32 hash) {
    assert(p==&ppe && ppe_lock && hash<4); reads++; return (int)hash==read_fail ? NULL : &rows[hash];
}
static int airoha_ppe_foe_commit_entry(struct airoha_ppe *p, struct airoha_foe_entry *h, u32 hash, bool wlan) {
    assert(p==&ppe && ppe_lock && hash<4 && !wlan); writes++;
    if ((int)hash!=write_fail || write_applies_on_error) rows[hash]=*h;
    return (int)hash==write_fail ? -EIO : 0;
}
static void airoha_ppe_foe_flow_remove_entry(struct airoha_ppe *p, struct airoha_flow_table_entry *e) {
    assert(p==&ppe && !ppe_lock); legacy_removes++; e->hash=0xffff; e->list.linked=false;
}
#define AIROHA_DEV_F_PON 1
struct flow_cls_offload { unsigned long cookie; };
static bool test_bit(unsigned bit,unsigned long *v) {return !!(*v & (1UL<<bit));}
static struct airoha_flow_table_entry *rhashtable_lookup(int *t,unsigned long *cookie,int params) {
    (void)t;(void)params;assert(flow_offload_mutex);
    for(unsigned i=0;i<4;i++)if(!entries[i].freed && entries[i].cookie==*cookie)return &entries[i];
    return NULL;
}
static int airoha_ppe_ct_remove_wlan_flow(struct airoha_ppe *p,struct airoha_flow_table_entry *e) {
    (void)p;(void)e;assert(false);return 0;
}
#include "production.inc"
static int destroy(unsigned id) {
    struct flow_cls_offload f={.cookie=entries[id].cookie};int err;
    mutex_lock(&flow_offload_mutex);err=airoha_ppe_flow_offload_destroy(&eth,&f);mutex_unlock(&flow_offload_mutex);return err;
}

static void reset(unsigned type) {
    assert(!ppe_lock && !flow_offload_mutex);
    ppe=(struct airoha_ppe){.ct_host_ppe=true}; eth=(struct airoha_eth){.ppe=&ppe};
    pon=(struct airoha_gdm_dev){.flags=1<<AIROHA_DEV_F_PON,.eth=&eth,.pon_flow_table=&old_table,.pon_qdma_tag=0x12345678};
    other=(struct airoha_gdm_dev){.eth=&eth};
    memset(entries,0,sizeof entries); memset(rows,0,sizeof rows); memset(walk,0,sizeof walk);
    reads=writes=frees=syncs=table_frees=legacy_removes=walk_count=0;
    read_fail=write_fail=-1; write_applies_on_error=false;
    for (unsigned i=0;i<4;i++) {
        struct airoha_flow_table_entry *e=&entries[i];
        e->cookie=100+i;e->type=FLOW_TYPE_L4;e->hash=i;e->egress_dev=i==3?&other:&pon;e->list.linked=true;list_init(&e->gc_node);
        e->data.ib1=FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE,AIROHA_FOE_STATE_BIND)|FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE,type)|AIROHA_FOE_IB1_BIND_TTL|3;
        if (type==PPE_PKT_TYPE_IPV4_HNAPT) {
            e->data.ipv4.orig_tuple.src_ip=0x0a000001+i; e->data.ipv4.orig_tuple.dest_ip=0x0a000011;
            e->data.ipv4.new_tuple=e->data.ipv4.orig_tuple;
            e->data.ipv4.ib2=FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT,2)|i;
            e->data.ipv4.data=FIELD_PREP(AIROHA_FOE_CHANNEL,31-i);
            e->data.ipv4.l2.common.etype=0xfffe - i;
        } else {
            e->data.ipv6.src_ip[0]=0x20010000+i;e->data.ipv6.dest_ip[0]=0x2001abcd;
            e->data.ipv6.ib2=FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT,2)|i;
            e->data.ipv6.data=FIELD_PREP(AIROHA_FOE_CHANNEL,31-i);
            e->data.ipv6.l2.etype=0xfffe - i;
        }
        rows[i]=e->data;
    }
}
/* Driver publication is exercised separately by verify_transaction.py.
 * This wrapper records success only after the production PPE retirement.
 */
static int replace(void) {
    int err;
    mutex_lock(&flow_offload_mutex);
    err=airoha_ppe_remove_egress_flows(&pon);
    if(!err) {pon.pon_flow_table=&next_table;pon.pon_qdma_tag=0x87654321;}
    mutex_unlock(&flow_offload_mutex);
    if(!err) {synchronize_net();kfree(&old_table);}
    return err;
}
static void retained(void) {
    assert(pon.pon_flow_table==&old_table && pon.pon_qdma_tag==0x12345678);
    assert(!syncs && !table_frees && !ppe_lock && !flow_offload_mutex);
    for (unsigned i=0;i<4;i++) assert(list_empty(&entries[i].gc_node));
}
int main(void) {
    unsigned cases=0;
    const unsigned types[]={PPE_PKT_TYPE_IPV4_HNAPT,PPE_PKT_TYPE_IPV6_ROUTE_5T};
    for (unsigned t=0;t<2;t++) {
        unsigned type=types[t];
        reset(type);walk[0]=&entries[0];walk[1]=(void*)(intptr_t)-EAGAIN;walk[2]=&entries[0];walk[3]=&entries[1];walk[4]=&entries[3];walk_count=5;
        assert(!replace() && reads==2 && writes==2 && frees==2 && !entries[3].freed);
        assert(pon.pon_flow_table==&next_table && pon.pon_qdma_tag==0x87654321 && syncs==1 && table_frees==1);cases++;
        for (unsigned failure=0;failure<3;failure++) {
            reset(type);walk[0]=&entries[0];walk[1]=&entries[1];walk[2]=&entries[2];walk_count=3;
            if (!failure) read_fail=1; else {write_fail=1;write_applies_on_error=failure==2;}
            assert(replace()==(!failure?-ETIMEDOUT:-EIO));retained();
            assert(entries[0].freed && !entries[1].freed && !entries[2].freed && entries[1].hash==1 && !entries[1].list.linked);
            assert(entries[2].hash==2 && entries[2].list.linked);
            read_fail=write_fail=-1;walk[0]=&entries[1];walk[1]=&entries[2];walk_count=2;
            assert(!replace() && frees==3 && syncs==1 && table_frees==1);cases++;
        }
        for (unsigned mutation=0;mutation<7;mutation++) {
            reset(type);walk[0]=&entries[0];walk_count=1;
            if (mutation==0) rows[0].ib1^=AIROHA_FOE_IB1_BIND_UDP;
            else if (mutation==1) rows[0].ib1^=AIROHA_FOE_IB1_BIND_TTL;
            else if (mutation==2) rows[0].d[0]^=1;
            else if (type==PPE_PKT_TYPE_IPV4_HNAPT) {
                if (mutation==3) rows[0].ipv4.l2.common.etype^=1;
                if (mutation==4) rows[0].ipv4.data^=1<<11;
                if (mutation==5) rows[0].ipv4.ib2^=1;
                if (mutation==6) rows[0].ipv4.new_tuple.dest_ip^=1;
            } else {
                if (mutation==3) rows[0].ipv6.l2.etype^=1;
                if (mutation==4) rows[0].ipv6.data^=1<<11;
                if (mutation==5) rows[0].ipv6.ib2^=1;
                if (mutation==6) rows[0].ipv6.l2.src_mac_hi^=1;
            }
            struct airoha_foe_entry saved=rows[0];
            assert(!replace() && !writes && frees==1 && !memcmp(&saved,&rows[0],sizeof saved));cases++;
        }
        for (unsigned state=0;state<4;state++) {
            reset(type);walk[0]=&entries[0];walk_count=1;
            rows[0].ib1=(rows[0].ib1 & ~(AIROHA_FOE_IB1_BIND_STATE|AIROHA_FOE_IB1_BIND_TIMESTAMP))|FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE,state)|99;
            assert(!replace() && writes==(state>=AIROHA_FOE_STATE_BIND) && entries[0].freed);cases++;
        }
        reset(type);walk[0]=&entries[0];walk[1]=(void*)(intptr_t)-EIO;walk_count=2;
        assert(replace()==-EIO && !reads && !writes && !frees);retained();cases++;
        reset(type);entries[0].hash=0xffff;walk[0]=&entries[0];walk_count=1;
        assert(!replace() && !reads && !writes && frees==1);cases++;
        reset(type);entries[0].type=FLOW_TYPE_L2;walk[0]=&entries[0];walk_count=1;
        assert(replace()==-EOPNOTSUPP && !frees && !reads);retained();cases++;
        reset(type);ppe.ct_host_ppe=false;walk[0]=&entries[0];walk_count=1;
        assert(!replace() && !reads && !writes && frees==1 && legacy_removes==1);cases++;
    }
    for (unsigned t=0;t<2;t++) {
        unsigned type=types[t];
        for(unsigned failure=0;failure<4;failure++) {
            reset(type);
            /* Downstream owns a wired egress and the same retiring PON ingress. */
            entries[1].egress_dev=&other; entries[1].pon_ingress_dev=&pon;
            if(type==PPE_PKT_TYPE_IPV4_HNAPT) entries[1].data.ipv4.ib2=FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT,4);
            else entries[1].data.ipv6.ib2=FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT,4);
            rows[1]=entries[1].data;
            walk[0]=&entries[0];walk[1]=&entries[1];walk[2]=(void*)(intptr_t)-EAGAIN;walk[3]=&entries[1];walk[4]=&entries[3];walk_count=5;
            if(failure==1) read_fail=1;
            if(failure>=2) {write_fail=1;write_applies_on_error=failure==3;}
            if(failure) {
                assert(replace()==(failure==1?-ETIMEDOUT:-EIO));retained();
                assert(entries[0].freed && !entries[1].freed && entries[1].hash==1 && !entries[1].list.linked);
                assert(!entries[3].freed);
                read_fail=write_fail=-1;walk[0]=&entries[1];walk[1]=&entries[3];walk_count=2;
            }
            assert(!replace() && entries[0].freed && entries[1].freed && !entries[3].freed);
            assert(frees==2 && !entries[3].freed);
            assert(FIELD_GET(AIROHA_FOE_IB1_BIND_STATE,rows[1].ib1)==AIROHA_FOE_STATE_INVALID);
            cases++;
        }
    }
    for(unsigned t=0;t<2;t++)for(unsigned downstream=0;downstream<2;downstream++)for(unsigned failure=0;failure<4;failure++) {
        reset(types[t]);
        if(downstream) {entries[0].egress_dev=&other;entries[0].pon_ingress_dev=&pon;}
        if(failure==1) read_fail=0;
        if(failure>=2) {write_fail=0;write_applies_on_error=failure==3;}
        if(failure) {
            assert(destroy(0)==(failure==1?-ETIMEDOUT:-EIO) && !entries[0].freed && entries[0].hash==0 && !entries[0].list.linked);
            read_fail=write_fail=-1;
        }
        assert(!destroy(0) && entries[0].freed && frees==1 && !entries[1].freed);
        assert(destroy(0)==-ENOENT);cases++;
    }
    printf("PASS %u bidirectional PON retirement, destroy, mapping publication, collision, resize and retry scenarios\n",cases);
    return 0;
}
