#ifndef PON_CANDIDATE_HOST_STUBS_H
#define PON_CANDIDATE_HOST_STUBS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define BIT(bit) (1u << (bit))
#define GENMASK(high, low) ((UINT32_MAX >> (31 - (high))) & (UINT32_MAX << (low)))
#define FIELD_GET(mask, value) (((value) & (mask)) >> __builtin_ctz(mask))
#define FIELD_PREP(mask, value) (((u32)(value) << __builtin_ctz(mask)) & (mask))
#define U64_MAX UINT64_MAX
#define ETH_ALEN 6
#define AIROHA_GDM2_IDX 2
#define DECLARE_FLEX_ARRAY(type, name) struct {} __empty_ ## name; type name[]
#define static_assert(condition) _Static_assert(condition, #condition)
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
#define READ_ONCE(value) (value)
#define test_bit(bit, pointer) (!!(*(pointer) & (1ul << (bit))))

struct task_struct;
struct task_struct *get_current(void);
#define current get_current()

static const char *test_case;
static unsigned checks, cases;
#define CHECK(condition) do { \
	checks++; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed [%s] line %d: %s\n", test_case, __LINE__, #condition); \
		exit(1); \
	} \
} while (0)

struct hlist_node { struct hlist_node *next, **pprev; };
struct hlist_head { struct hlist_node *first; };
struct list_head { struct list_head *next, *prev; };
struct rhash_head { unsigned unused; };
struct rcu_head { unsigned unused; };
struct airoha_gdm_dev;
struct airoha_ppe;
struct net_device;
#include "production_abi.h"

struct net_device { bool running, carrier; int refs, netns; };
struct airoha_qdma { unsigned unused; };
struct port { unsigned id; };
struct device_node { bool diagnostic; };
struct device { struct device_node *of_node; };
struct rhashtable { struct airoha_flow_table_entry *entries[8]; };
struct airoha_eth {
	struct airoha_ppe *ppe;
	struct device *dev;
	struct airoha_qdma qdma[2];
	struct rhashtable flow_table;
	bool ct_pon_full, ct_ordinary_full_test, ct_cpu_fallback;
};
struct airoha_gdm_dev {
	struct airoha_eth *eth;
	struct net_device netdev;
	struct port *port;
	unsigned long flags;
	unsigned nbq;
	bool pon_update_blocked, valid;
	struct airoha_qdma *qdma;
	struct airoha_pon_flow_table *pon_flow_table;
	void *pon_link_ops, *pon_link_priv;
};
struct airoha_ppe {
	struct airoha_eth *eth;
	bool ct_host_ppe, ct_native_pairs, ct_stopping, ct_bridge_failed, ct_pon_qualified;
	u64 pon_candidate_serial;
	struct hlist_head *foe_flow;
	struct list_head ct_bridge_flows;
};
struct flow_cls_offload { unsigned long cookie; };

static int flow_offload_mutex, ppe_lock, mutex_depth, spin_depth;
static unsigned holds, ref_puts, lookups, spin_calls;
static int insert_error;
static u64 generation = 9;
static void (*before_spin)(void);
static const int airoha_flow_table_params = 1;

static bool lockdep_is_held(int *lock)
{
	return lock == &flow_offload_mutex ? mutex_depth == 1 :
	       lock == &ppe_lock && spin_depth == 1;
}
#define lockdep_assert_held(lock) CHECK(lockdep_is_held(lock))

static void mutex_lock(int *lock)
{
	CHECK(lock == &flow_offload_mutex && !mutex_depth && !spin_depth);
	mutex_depth++;
}

static void mutex_unlock(int *lock)
{
	CHECK(lock == &flow_offload_mutex && mutex_depth == 1 && !spin_depth);
	mutex_depth--;
}

static void spin_lock_bh(int *lock)
{
	CHECK(lock == &ppe_lock && !spin_depth && mutex_depth == 1);
	if (before_spin) {
		void (*callback)(void) = before_spin;

		before_spin = NULL;
		callback();
	}
	spin_depth++;
	spin_calls++;
}

static void spin_unlock_bh(int *lock)
{
	CHECK(lock == &ppe_lock && spin_depth == 1 && mutex_depth == 1);
	spin_depth--;
}

#define rcu_access_pointer(pointer) (pointer)
#define rcu_dereference_protected(pointer, condition) ((condition) ? (pointer) : (abort(), (pointer)))
#define netdev_from_priv(dev) (&(dev)->netdev)
#define netif_running(dev) ((dev)->running)
#define netif_carrier_ok(dev) ((dev)->carrier)
#define dev_net(dev) ((dev)->netns)
#define net_eq(first, second) ((first) == (second))

static bool of_property_read_bool(struct device_node *node, const char *name)
{
	CHECK(!strcmp(name, "airoha,connac2-pon-er-diagnostic"));
	return node->diagnostic;
}

static bool airoha_is_valid_gdm_dev(struct airoha_eth *eth, struct airoha_gdm_dev *dev)
{
	return dev->valid && dev->eth == eth;
}

static u64 br_flow_offload_generation(void)
{
	CHECK(mutex_depth == 1 && spin_depth == 1);
	return generation;
}

static void dev_hold(struct net_device *dev)
{
	CHECK(mutex_depth == 1 && spin_depth == 1 && dev->refs > 0);
	dev->refs++;
	holds++;
}

static void dev_put(struct net_device *dev)
{
	CHECK(!spin_depth && dev->refs > 1);
	dev->refs--;
	ref_puts++;
}

static struct airoha_flow_table_entry *rhashtable_lookup_fast(struct rhashtable *table,
							     const unsigned long *cookie, int params)
{
	CHECK(mutex_depth == 1 && !spin_depth && params == airoha_flow_table_params);
	lookups++;
	for (unsigned index = 0; index < 8; index++)
		if (table->entries[index] && table->entries[index]->cookie == *cookie)
			return table->entries[index];
	return NULL;
}
#define rhashtable_lookup rhashtable_lookup_fast

static int rhashtable_insert_fast(struct rhashtable *table, struct rhash_head *node, int params)
{
	struct airoha_flow_table_entry *entry = container_of(node, struct airoha_flow_table_entry, node);

	CHECK(mutex_depth == 1 && !spin_depth && params == airoha_flow_table_params);
	if (insert_error)
		return insert_error;
	if (rhashtable_lookup_fast(table, &entry->cookie, params))
		return -EEXIST;
	for (unsigned index = 0; index < 8; index++) {
		if (table->entries[index])
			continue;
		table->entries[index] = entry;
		return 0;
	}
	return -ENOMEM;
}

static int rhashtable_remove_fast(struct rhashtable *table, struct rhash_head *node, int params)
{
	CHECK(mutex_depth == 1 && !spin_depth && params == airoha_flow_table_params);
	for (unsigned index = 0; index < 8; index++) {
		if (!table->entries[index] || &table->entries[index]->node != node)
			continue;
		table->entries[index] = NULL;
		return 0;
	}
	return -ENOENT;
}

static void hlist_add_head(struct hlist_node *node, struct hlist_head *head)
{
	struct airoha_flow_table_entry *entry = container_of(node, struct airoha_flow_table_entry, list);

	CHECK(spin_depth == 1);
	if (entry->pon_candidate)
		CHECK(entry->pon_candidate_serial && entry->pon_candidate_serial == entry->pon_ingress_dev->eth->ppe->pon_candidate_serial);
	node->next = head->first;
	if (node->next)
		node->next->pprev = &node->next;
	node->pprev = &head->first;
	head->first = node;
}

static void hlist_del_init(struct hlist_node *node)
{
	CHECK(spin_depth == 1);
	if (node->pprev) {
		*node->pprev = node->next;
		if (node->next)
			node->next->pprev = node->pprev;
	}
	node->pprev = NULL;
	node->next = NULL;
}

#define hlist_for_each_entry(entry, head, member) \
	for (struct hlist_node *cursor = (head)->first; \
	     cursor && ((entry) = container_of(cursor, struct airoha_flow_table_entry, member), true); \
	     cursor = cursor->next)

static void list_add_tail(struct list_head *node, struct list_head *head)
{
	(void)node;
	(void)head;
	CHECK(spin_depth == 1);
}

static u32 airoha_ppe_foe_get_entry_hash(struct airoha_ppe *ppe, struct airoha_foe_entry *entry)
{
	CHECK(ppe && entry && !spin_depth);
	return 0;
}

static int airoha_ppe_foe_l2_flow_commit_entry(struct airoha_ppe *ppe, struct airoha_flow_table_entry *entry)
{
	(void)ppe;
	(void)entry;
	CHECK(false);
	return -EOPNOTSUPP;
}

static u32 airoha_ppe_ct_route_wlan_epoch(struct airoha_ppe *ppe, struct airoha_foe_entry *entry)
{
	(void)ppe;
	(void)entry;
	CHECK(false);
	return 0;
}

static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *ppe, u32 hash)
{
	(void)ppe;
	(void)hash;
	CHECK(false);
	return NULL;
}

static int airoha_ppe_foe_commit_entry(struct airoha_ppe *ppe, struct airoha_foe_entry *entry, u32 hash, bool wlan)
{
	(void)ppe;
	(void)entry;
	(void)hash;
	(void)wlan;
	CHECK(false);
	return -EIO;
}

static int airoha_ppe_ct_remove_wlan_flow(struct airoha_ppe *ppe, struct airoha_flow_table_entry *entry)
{
	(void)ppe;
	(void)entry;
	CHECK(false);
	return -EIO;
}

static void airoha_ppe_foe_flow_remove_entry(struct airoha_ppe *ppe, struct airoha_flow_table_entry *entry)
{
	(void)ppe;
	(void)entry;
	CHECK(false);
}

static void kfree(void *pointer)
{
	CHECK(mutex_depth == 1 && !spin_depth);
	free(pointer);
}

#include "production.inc"
#endif
