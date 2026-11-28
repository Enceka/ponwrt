#ifndef FLOW_OBSERVE_HOST_STUBS_H
#define FLOW_OBSERVE_HOST_STUBS_H

#include <stddef.h>
#include "frame_fixture.h"

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
#define BIT(bit) (1u << (bit))
#define GENMASK(high, low) ((UINT32_MAX >> (31 - (high))) & (UINT32_MAX << (low)))
#define FIELD_GET(mask, value) (((value) & (mask)) >> __builtin_ctz(mask))
#define FIELD_PREP(mask, value) (((u32)(value) << __builtin_ctz(mask)) & (mask))
#define DECLARE_FLEX_ARRAY(type, name) type name[1]
#define static_assert(condition) _Static_assert(condition, #condition)
#include "production_abi.h"

#define AIROHA_GDM2_IDX 2
#define IPPROTO_UDP 17
#define ETH_HLEN 14
#define READ_ONCE(value) (value)
#define smp_load_acquire(pointer) (*(pointer))
#define rcu_dereference(pointer) (CHECK_RCU(), (pointer))
#define WARN_ON_ONCE(condition) CHECK(!(condition))
#define test_bit(bit, pointer) (!!(*(pointer) & (1ul << (bit))))
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))

struct hlist_node {
	struct hlist_node *next, **pprev;
};
struct hlist_head { struct hlist_node *first; };
struct airoha_gdm_dev;
struct airoha_flow_table_entry {
	struct hlist_node list;
	u32 hash;
	unsigned long cookie;
	enum airoha_flow_entry_type type;
	struct airoha_gdm_dev *pon_ingress_dev;
	u32 pon_ingress_key[19], pon_ingress_service;
	bool pon_ingress_seen, pon_ingress_conflict, ct_bridge;
	struct airoha_foe_entry data;
};
struct airoha_ppe {
	bool ct_host_ppe, ct_stopping;
	struct hlist_head *foe_flow;
};
struct airoha_qdma { unsigned id; };
struct airoha_eth {
	struct airoha_ppe *ppe;
	struct airoha_qdma qdma[2];
};
struct net_device { bool running, carrier; };
struct port { unsigned id; };
struct airoha_pon_flow_entry { u32 tag; };
struct airoha_pon_flow_table {
	unsigned count;
	struct airoha_pon_flow_entry entries[4];
};
struct airoha_gdm_dev {
	struct airoha_eth *eth;
	struct port *port;
	struct net_device netdev;
	unsigned long flags;
	unsigned nbq;
	bool pon_update_blocked;
	u32 pon_qdma_tag;
	struct airoha_pon_flow_table *pon_flow_table;
};
struct sk_buff {
	struct net_device *dev;
	unsigned char *head, *data, *mac;
	unsigned len;
	bool nonlinear, vlan_present, mac_set;
};

static int ppe_lock, lock_depth, rcu_depth;
static unsigned lock_calls, rcu_calls, row_reads, row_writes;
static struct airoha_flow_table_entry *retiring;
static bool row_missing, row_matches;
static int commit_error;
static struct airoha_foe_entry hardware_row;

static void CHECK_RCU(void)
{
	CHECK(rcu_depth == 1);
}

static void spin_lock_bh(int *lock)
{
	CHECK(lock == &ppe_lock && !lock_depth);
	++lock_depth;
	++lock_calls;
}

static void spin_unlock_bh(int *lock)
{
	CHECK(lock == &ppe_lock && lock_depth == 1);
	--lock_depth;
}

static void rcu_read_lock(void)
{
	CHECK(!rcu_depth);
	++rcu_depth;
	++rcu_calls;
}

static void rcu_read_unlock(void)
{
	CHECK(rcu_depth == 1 && !lock_depth);
	--rcu_depth;
}

static void hlist_add_head(struct hlist_node *node, struct hlist_head *head)
{
	node->next = head->first;
	if (node->next)
		node->next->pprev = &node->next;
	node->pprev = &head->first;
	head->first = node;
}

static void hlist_del_init(struct hlist_node *node)
{
	struct airoha_flow_table_entry *entry = container_of(node, struct airoha_flow_table_entry, list);
	CHECK(lock_depth == 1 && !entry->pon_ingress_seen);
	if (node->pprev) {
		*node->pprev = node->next;
		if (node->next)
			node->next->pprev = node->pprev;
	}
	node->next = NULL;
	node->pprev = NULL;
}

#define hlist_for_each_entry(entry, head, member) \
	for (struct hlist_node *cursor = (head)->first; \
	     cursor && ((entry) = container_of(cursor, struct airoha_flow_table_entry, member), true); \
	     cursor = cursor->next)
#define netdev_from_priv(dev) (&(dev)->netdev)
#define netif_running(dev) ((dev)->running)
#define netif_carrier_ok(dev) ((dev)->carrier)
#define skb_is_nonlinear(skb) ((skb)->nonlinear)
#define skb_vlan_tag_present(skb) ((skb)->vlan_present)
#define skb_mac_header_was_set(skb) ((skb)->mac_set)
#define skb_mac_header(skb) ((skb)->mac)

static u32 airoha_ppe_get_total_num_entries(struct airoha_ppe *ppe)
{
	CHECK(ppe);
	return 16;
}

static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *ppe, u32 hash)
{
	CHECK(ppe && retiring && lock_depth == 1 && !retiring->pon_ingress_seen);
	CHECK(!retiring->list.pprev && hash == retiring->hash);
	++row_reads;
	return row_missing ? NULL : &hardware_row;
}

static bool airoha_ppe_ct_pon_row_matches(struct airoha_flow_table_entry *entry,
				       struct airoha_foe_entry *row)
{
	CHECK(entry == retiring && row == &hardware_row && lock_depth == 1);
	CHECK(!entry->pon_ingress_seen && !entry->list.pprev);
	return row_matches;
}

static int airoha_ppe_foe_commit_entry(struct airoha_ppe *ppe,
				    struct airoha_foe_entry *row, u32 hash, bool rx_wlan)
{
	CHECK(ppe && retiring && hash == retiring->hash && !rx_wlan);
	CHECK(lock_depth == 1 && !retiring->pon_ingress_seen && !retiring->list.pprev);
	CHECK(!FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, row->ib1));
	++row_writes;
	if (!commit_error)
		hardware_row = *row;
	return commit_error;
}

#include "production.inc"
#endif
