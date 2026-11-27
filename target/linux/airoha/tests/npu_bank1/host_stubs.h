#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#undef EAGAIN
#undef ETIMEDOUT
#define EAGAIN 11
#define ETIMEDOUT 110
#define BIT(number) (UINT32_C(1) << (number))
#define GENMASK(high, low) ((UINT32_MAX >> (31 - (high))) & (UINT32_MAX << (low)))
#define FIELD_GET(mask, value) (((value) & (mask)) >> __builtin_ctz(mask))
#define FIELD_PREP(mask, value) (((u32)(value) << __builtin_ctz(mask)) & (mask))
#define DECLARE_FLEX_ARRAY(type, name) type name[0]
#define ETH_ALEN 6
#define static_assert(expression) _Static_assert(expression, #expression)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define READ_ONCE(value) (value)
#define WRITE_ONCE(value, replacement) ((value) = (replacement))
#define IS_ERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#define PTR_ERR(pointer) ((int)(intptr_t)(pointer))
#define ERR_PTR(error) ((void *)(intptr_t)(error))

static unsigned long checks;
static unsigned scenarios;
static const char *scenario;
#define CHECK(expression) do { \
	checks++; \
	if (!(expression)) { \
		fprintf(stderr, "CHECK failed: %s:%d: %s [%s]\n", \
			__FILE__, __LINE__, #expression, scenario); \
		exit(1); \
	} \
} while (0)

struct list_head { struct list_head *next, *prev; };
struct hlist_node { struct hlist_node *next, **pprev; };
struct hlist_head { struct hlist_node *first; };
struct rhash_head { void *next; };
#define container_of(pointer, type, member) \
	((type *)((char *)(pointer) - offsetof(type, member)))
#define LIST_HEAD(name) struct list_head name = { &(name), &(name) }

static int flow_offload_mutex, ppe_lock;
static bool fixture_setup, walk_entered, walk_active;
static unsigned spin_acquires, spin_releases, reschedules;
static unsigned walk_starts, walk_stops, walk_exits, walk_calls;
enum operation { IDLE, RETIRE, CLEAR, REUSE };
static enum operation operation;
static u32 *active_cursor, locked_cursor;
static unsigned transaction_stage;
static bool transaction_failed;

static void list_init(struct list_head *node)
{
	node->next = node->prev = node;
}

static bool list_empty(const struct list_head *node)
{
	return node->next == node;
}

static void list_add_tail(struct list_head *node, struct list_head *head)
{
	CHECK(fixture_setup || (flow_offload_mutex && !ppe_lock));
	CHECK(list_empty(node));
	node->prev = head->prev;
	node->next = head;
	head->prev->next = node;
	head->prev = node;
}

static void list_del_init(struct list_head *node)
{
	CHECK(flow_offload_mutex && !walk_entered);
	CHECK((operation == RETIRE && !ppe_lock) || (operation == REUSE && ppe_lock));
	CHECK(node->next->prev == node && node->prev->next == node);
	node->prev->next = node->next;
	node->next->prev = node->prev;
	list_init(node);
}

#define LIST_FIRST(head, type, member) \
	(list_empty(head) ? NULL : container_of((head)->next, type, member))
#define LIST_NEXT(entry, head, type, member) \
	((entry)->member.next == (head) ? NULL : container_of((entry)->member.next, type, member))
#define list_for_each_entry_safe(entry, next_entry, head, member) \
	for ((entry) = LIST_FIRST(head, __typeof__(*(entry)), member), \
	     (next_entry) = (entry) ? LIST_NEXT(entry, head, __typeof__(*(entry)), member) : NULL; \
	     (entry); (entry) = (next_entry), \
	     (next_entry) = (entry) ? LIST_NEXT(entry, head, __typeof__(*(entry)), member) : NULL)

static void hlist_add_head(struct hlist_node *node, struct hlist_head *head)
{
	CHECK(fixture_setup && !node->pprev);
	node->next = head->first;
	if (node->next)
		node->next->pprev = &node->next;
	head->first = node;
	node->pprev = &head->first;
}

static void hlist_del_init(struct hlist_node *node)
{
	CHECK(flow_offload_mutex && ppe_lock && !walk_entered);
	CHECK(operation == RETIRE || operation == REUSE);
	if (!node->pprev)
		return;
	CHECK(*node->pprev == node);
	*node->pprev = node->next;
	if (node->next)
		node->next->pprev = node->pprev;
	node->next = NULL;
	node->pprev = NULL;
}

#define HLIST_ENTRY(node, type, member) \
	((node) ? container_of(node, type, member) : NULL)
#define hlist_for_each_entry_safe(entry, next_node, head, member) \
	for ((entry) = HLIST_ENTRY((head)->first, __typeof__(*(entry)), member); \
	     (entry) && ((next_node) = (entry)->member.next, true); \
	     (entry) = HLIST_ENTRY(next_node, __typeof__(*(entry)), member))

#include "production_types.inc"

struct airoha_eth { int flow_table; struct airoha_ppe *ppe; };
struct airoha_ppe {
	struct airoha_eth *eth;
	void *foe;
	bool ct_owns_sram;
	bool ct_host_ppe, ct_stopping, ct_bridge_failed;
	int l2_flows;
};
struct airoha_gdm_dev { unsigned long flags; };
struct rhashtable_iter { unsigned index; };
static struct airoha_eth eth;
static struct airoha_ppe ppe;
static struct airoha_foe_entry shadow[2 * PPE_SRAM_NUM_ENTRIES];
static struct airoha_foe_entry hardware[2 * PPE_SRAM_NUM_ENTRIES];
static struct airoha_foe_entry bank0_shadow[PPE_SRAM_NUM_ENTRIES];
static struct airoha_foe_entry bank0_hardware[PPE_SRAM_NUM_ENTRIES];
static const struct airoha_foe_entry zero_entry;
static void *walk_items[128];
static unsigned walk_count;
static struct {
	struct airoha_flow_table_entry *entry;
	bool freed;
	bool removed, l2_removed;
} allocated[64];
static unsigned allocation_count, frees;
static unsigned reuse_reads, reuse_writes, reuse_stats, removed_cookies, removed_l2;
static struct hlist_head candidates;
static struct list_head bridges;

static void mutex_lock(int *lock)
{
	CHECK(lock == &flow_offload_mutex && !*lock && !ppe_lock);
	*lock = 1;
}

static void mutex_unlock(int *lock)
{
	CHECK(lock == &flow_offload_mutex && *lock && !ppe_lock && !walk_entered);
	*lock = 0;
}

#define lockdep_assert_held(lock) CHECK(*(lock))

static void spin_lock_bh(int *lock)
{
	CHECK(lock == &ppe_lock && !*lock && flow_offload_mutex && !walk_entered);
	CHECK(operation == RETIRE || operation == CLEAR || operation == REUSE);
	if (operation == CLEAR) {
		locked_cursor = *active_cursor;
		transaction_stage = 0;
		transaction_failed = false;
	}
	*lock = 1;
	spin_acquires++;
}

static void spin_unlock_bh(int *lock)
{
	CHECK(lock == &ppe_lock && *lock && flow_offload_mutex);
	if (operation == CLEAR) {
		CHECK(*active_cursor == locked_cursor);
		CHECK(transaction_failed || transaction_stage == 4);
	}
	*lock = 0;
	spin_releases++;
}

static void cond_resched(void)
{
	CHECK(flow_offload_mutex && !ppe_lock && !walk_entered);
	CHECK(spin_acquires == spin_releases);
	if (operation == CLEAR) {
		CHECK(!transaction_failed && transaction_stage == 4);
		CHECK(*active_cursor == locked_cursor + 1);
	}
	reschedules++;
}

static void rhashtable_walk_enter(int *table, struct rhashtable_iter *iter)
{
	CHECK(table == &eth.flow_table && flow_offload_mutex && !ppe_lock);
	CHECK(!walk_entered && !walk_active && operation == RETIRE);
	walk_entered = true;
	iter->index = 0;
}

static void rhashtable_walk_start(struct rhashtable_iter *iter)
{
	CHECK(iter && walk_entered && !walk_active && !ppe_lock);
	walk_active = true;
	walk_starts++;
}

static void *rhashtable_walk_next(struct rhashtable_iter *iter)
{
	CHECK(flow_offload_mutex && !ppe_lock && walk_entered && walk_active);
	CHECK(++walk_calls <= 512);
	return iter->index < walk_count ? walk_items[iter->index++] : NULL;
}

static void rhashtable_walk_stop(struct rhashtable_iter *iter)
{
	CHECK(iter && walk_entered && walk_active && !ppe_lock);
	walk_active = false;
	walk_stops++;
}

static void rhashtable_walk_exit(struct rhashtable_iter *iter)
{
	CHECK(iter && walk_entered && !walk_active && !ppe_lock);
	walk_entered = false;
	walk_exits++;
}

static void kfree(void *pointer)
{
	CHECK(flow_offload_mutex && !walk_entered);
	CHECK(operation == RETIRE || operation == REUSE);
	for (unsigned index = 0; index < allocation_count; index++) {
		struct airoha_flow_table_entry *entry = allocated[index].entry;
		if (entry != pointer)
			continue;
		CHECK(!allocated[index].freed);
		if (operation == RETIRE) {
			CHECK(ppe_lock && entry->type == FLOW_TYPE_L2_SUBFLOW);
			CHECK(entry->hash >= PPE_SRAM_NUM_ENTRIES && entry->hash < 2 * PPE_SRAM_NUM_ENTRIES);
		} else if (entry->type == FLOW_TYPE_L2_SUBFLOW) {
			CHECK(ppe_lock && entry->hash == 0xffff);
		} else {
			CHECK(!ppe_lock && allocated[index].removed);
		}
		if (entry->type == FLOW_TYPE_L2)
			CHECK(!entry->l2_flows.first && allocated[index].l2_removed);
		else
			CHECK(!entry->list.pprev && !entry->l2_subflow_node.pprev);
		CHECK(list_empty(&entry->gc_node));
		allocated[index].entry = NULL;
		allocated[index].freed = true;
		frees++;
		free(pointer);
		return;
	}
	CHECK(false);
}

enum fault_kind {
	NO_FAULT, WRITE_ERROR, WRITE_TIMEOUT, LOST_WRITE_ACK_APPLIED,
	WRITE_ACK_MISSING, WRITE_ACK_WRONG_ROW, WRITE_ACK_WRONG_DIRECTION,
	WRITE_ACK_REQUEST_SET, READ_TIMEOUT, READ_ACK_MISSING,
	READ_ACK_WRONG_ROW, READ_ACK_WRONG_DIRECTION, READ_ACK_REQUEST_SET,
	READBACK_CORRUPT, WRITE_DROPPED_ACKED, FAULT_COUNT
};
static enum fault_kind fault;
static u32 fault_row, corrupt_byte, control_value;
static unsigned writes, reads, write_acks, read_acks;
static unsigned row_writes[PPE_SRAM_NUM_ENTRIES], row_reads[PPE_SRAM_NUM_ENTRIES];
static bool ack_unrelated_bits;

static void check_access(struct airoha_ppe *target, u32 hash)
{
	CHECK(target == &ppe && operation == CLEAR && flow_offload_mutex && ppe_lock);
	CHECK(hash >= PPE_SRAM_NUM_ENTRIES && hash < 2 * PPE_SRAM_NUM_ENTRIES);
	CHECK(hash == PPE_SRAM_NUM_ENTRIES + locked_cursor);
	CHECK(*active_cursor == locked_cursor);
}

static u32 make_ack(u32 hash, bool write)
{
	u32 control = FIELD_PREP(PPE_SRAM_CTRL_ENTRY_MASK, hash) | PPE_SRAM_CTRL_ACK_MASK;
	if (write)
		control |= PPE_SRAM_CTRL_WR_MASK;
	if (ack_unrelated_bits)
		control |= PPE_SRAM_CTRL_DUAL_SUCESS_MASK | PPE_SRAM_WR_DUAL_DIRECTION_MASK;
	if (hash != PPE_SRAM_NUM_ENTRIES + fault_row)
		return control;
	if ((write && (fault == WRITE_ACK_MISSING || fault == LOST_WRITE_ACK_APPLIED)) ||
	    (!write && fault == READ_ACK_MISSING))
		control &= ~PPE_SRAM_CTRL_ACK_MASK;
	if ((write && fault == WRITE_ACK_WRONG_ROW) || (!write && fault == READ_ACK_WRONG_ROW))
		control ^= FIELD_PREP(PPE_SRAM_CTRL_ENTRY_MASK, 1);
	if ((write && fault == WRITE_ACK_WRONG_DIRECTION) || (!write && fault == READ_ACK_WRONG_DIRECTION))
		control ^= PPE_SRAM_CTRL_WR_MASK;
	if ((write && fault == WRITE_ACK_REQUEST_SET) || (!write && fault == READ_ACK_REQUEST_SET))
		control |= PPE_SRAM_CTRL_REQ_MASK;
	return control;
}

static int airoha_ppe_foe_commit_sram_entry(struct airoha_ppe *target, u32 hash)
{
	check_access(target, hash);
	CHECK(transaction_stage == 0);
	CHECK(!memcmp(&shadow[hash], &zero_entry, sizeof(zero_entry)));
	transaction_stage = 1;
	writes++;
	row_writes[hash - PPE_SRAM_NUM_ENTRIES]++;
	bool fail = hash == PPE_SRAM_NUM_ENTRIES + fault_row;
	if (!fail || (fault != WRITE_ERROR && fault != WRITE_TIMEOUT && fault != WRITE_DROPPED_ACKED))
		hardware[hash] = shadow[hash];
	control_value = make_ack(hash, true);
	if (fail && (fault == WRITE_ERROR || fault == WRITE_TIMEOUT || fault == LOST_WRITE_ACK_APPLIED)) {
		transaction_failed = true;
		return fault == WRITE_ERROR ? -EIO : -ETIMEDOUT;
	}
	return 0;
}

static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *target, u32 hash)
{
	if (operation == REUSE) {
		CHECK(target == &ppe && flow_offload_mutex && ppe_lock);
		CHECK(hash < PPE_SRAM_NUM_ENTRIES);
		reuse_reads++;
		shadow[hash] = hardware[hash];
		return &shadow[hash];
	}
	check_access(target, hash);
	CHECK(transaction_stage == 2 && !transaction_failed);
	transaction_stage = 3;
	reads++;
	row_reads[hash - PPE_SRAM_NUM_ENTRIES]++;
	if (hash == PPE_SRAM_NUM_ENTRIES + fault_row && fault == READ_TIMEOUT) {
		transaction_failed = true;
		return NULL;
	}
	shadow[hash] = hardware[hash];
	if (hash == PPE_SRAM_NUM_ENTRIES + fault_row && fault == READBACK_CORRUPT)
		shadow[hash].data[corrupt_byte] ^= 0x80;
	control_value = make_ack(hash, false);
	return &shadow[hash];
}

static u32 airoha_fe_rr(struct airoha_eth *target, u32 reg)
{
	CHECK(target == &eth && reg == REG_PPE_RAM_CTRL(1));
	check_access(&ppe, PPE_SRAM_NUM_ENTRIES + locked_cursor);
	CHECK(transaction_stage == 1 || transaction_stage == 3);
	bool write = transaction_stage == 1;
	if (write)
		write_acks++;
	else
		read_acks++;
	u32 expected = FIELD_PREP(PPE_SRAM_CTRL_ENTRY_MASK, PPE_SRAM_NUM_ENTRIES + locked_cursor) |
		       PPE_SRAM_CTRL_ACK_MASK | (write ? PPE_SRAM_CTRL_WR_MASK : 0);
	u32 mask = PPE_SRAM_CTRL_ENTRY_MASK | PPE_SRAM_CTRL_ACK_MASK |
		   PPE_SRAM_CTRL_WR_MASK | PPE_SRAM_CTRL_REQ_MASK;
	transaction_failed = (control_value & mask) != expected;
	if (!write && memcmp(&shadow[PPE_SRAM_NUM_ENTRIES + locked_cursor], &zero_entry, sizeof(zero_entry)))
		transaction_failed = true;
	transaction_stage++;
	return control_value;
}

#include "production_ack.inc"
#include "airoha_npu_bank1.h"

struct flow_cls_offload {
	unsigned long cookie;
	struct { u64 pkts, bytes, lastused; } stats;
};
static const unsigned long jiffies = 1234567;
#define HZ 100
static int airoha_flow_table_params, airoha_l2_flow_table_params;

static bool test_bit(unsigned bit, const unsigned long *value)
{
	return (*value & (1UL << bit)) != 0;
}

static void *rhashtable_lookup(int *table, const unsigned long *cookie, int params)
{
	CHECK(table == &eth.flow_table && params == airoha_flow_table_params);
	CHECK(operation == REUSE && flow_offload_mutex && !ppe_lock);
	for (unsigned index = 0; index < allocation_count; index++) {
		struct airoha_flow_table_entry *entry = allocated[index].entry;
		if (entry && !allocated[index].removed && entry->type != FLOW_TYPE_L2_SUBFLOW && entry->cookie == *cookie)
			return entry;
	}
	return NULL;
}

static void rhashtable_remove_fast(int *table, struct rhash_head *node, int params)
{
	CHECK(operation == REUSE && flow_offload_mutex);
	for (unsigned index = 0; index < allocation_count; index++) {
		struct airoha_flow_table_entry *entry = allocated[index].entry;
		if (!entry)
			continue;
		if (table == &eth.flow_table && node == &entry->node) {
			CHECK(!ppe_lock && params == airoha_flow_table_params && !allocated[index].removed);
			allocated[index].removed = true;
			removed_cookies++;
			return;
		}
		if (table == &ppe.l2_flows && node == &entry->l2_node) {
			CHECK(ppe_lock && params == airoha_l2_flow_table_params && !allocated[index].l2_removed);
			allocated[index].l2_removed = true;
			removed_l2++;
			return;
		}
	}
	CHECK(false);
}

static int airoha_ppe_foe_commit_entry(struct airoha_ppe *target,
				    struct airoha_foe_entry *entry, u32 hash, bool wlan)
{
	CHECK(target == &ppe && operation == REUSE && flow_offload_mutex && ppe_lock && !wlan);
	CHECK(hash < PPE_SRAM_NUM_ENTRIES);
	reuse_writes++;
	hardware[hash] = shadow[hash] = *entry;
	return 0;
}

static u32 airoha_ppe_get_total_num_entries(struct airoha_ppe *target)
{
	CHECK(target == &ppe);
	return 2 * PPE_SRAM_NUM_ENTRIES + PPE_DRAM_NUM_ENTRIES;
}

static u32 airoha_ppe_get_timestamp(struct airoha_ppe *target)
{
	CHECK(target == &ppe && flow_offload_mutex);
	return 0x600;
}

static void airoha_ppe_foe_entry_get_stats(struct airoha_ppe *target, u32 hash,
					struct airoha_foe_stats64 *stats)
{
	CHECK(target == &ppe && operation == REUSE && flow_offload_mutex && ppe_lock);
	CHECK(hash < PPE_SRAM_NUM_ENTRIES);
	reuse_stats++;
	*stats = (struct airoha_foe_stats64){ .bytes = 1000, .packets = 10 };
}

static int airoha_ppe_ct_bridge_fail_closed(struct airoha_ppe *target)
{
	CHECK(target == &ppe);
	CHECK(false);
	return -EIO;
}

#include "production_reuse.inc"
