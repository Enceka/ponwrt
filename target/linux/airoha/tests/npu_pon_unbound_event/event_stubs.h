#ifndef PON_EVENT_STUBS_H
#define PON_EVENT_STUBS_H

#include "airoha_npu_flow_observe.h"
#define IPPROTO_UDP 17
#define ETH_HLEN 14
#define smp_load_acquire(pointer) (*(pointer))
#define rcu_read_lock_held() (rcu_depth == 1)
#define RCU_LOCKDEP_WARN(condition, message) CHECK(!(condition))
#define rcu_dereference(pointer) (check_rcu(), (pointer))

struct sk_buff {
	struct net_device *dev;
	unsigned char *head, *data, *mac;
	unsigned len;
	bool nonlinear, gso, vlan, mac_set;
};
struct airoha_queue {
	struct airoha_qdma *qdma;
	struct sk_buff *skb;
	bool lro;
};

static unsigned generic_learns;
static struct airoha_flow_table_entry *generic_candidate;
static bool airoha_ppe_ct_flow_bank_matches(struct airoha_ppe *ppe,
			struct airoha_flow_table_entry *entry, u32 hash, bool rx_wlan);

static void check_rcu(void)
{
	CHECK(rcu_depth == 1);
}

static void rcu_read_lock(void)
{
	CHECK(!rcu_depth && !spin_depth && !mutex_depth);
	rcu_depth++;
}

static void rcu_read_unlock(void)
{
	CHECK(rcu_depth == 1 && !spin_depth && !mutex_depth);
	rcu_depth--;
}

#define skb_is_nonlinear(skb) ((skb)->nonlinear)
#define skb_is_gso(skb) ((skb)->gso)
#define skb_vlan_tag_present(skb) ((skb)->vlan)
#define skb_mac_header_was_set(skb) ((skb)->mac_set)
#define skb_mac_header(skb) ((skb)->mac)
#define airoha_qdma_is_lro_queue(queue) ((queue)->lro)

static void airoha_ppe_check_skb(struct airoha_ppe_dev *dev, struct sk_buff *skb,
			      u32 hash, bool rx_wlan)
{
	struct airoha_ppe *ppe = container_of(dev, struct airoha_ppe, dev);

	CHECK(skb && !mutex_depth && !spin_depth);
	CHECK(!airoha_ppe_ct_flow_bank_matches(ppe, generic_candidate, hash, rx_wlan));
	generic_learns++;
}

#define hlist_for_each_entry_safe(entry, next_node, head, member) \
	for (struct hlist_node *cursor = (head)->first; \
	     cursor && ((entry) = container_of(cursor, struct airoha_flow_table_entry, member), \
	                (next_node) = cursor->next, true); cursor = (next_node))

static void list_del_init(struct list_head *node)
{
	(void)node;
	CHECK(false);
}

#endif
