#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef uint16_t __be16;
typedef uint64_t u64;
typedef int32_t __s32;
static unsigned checks, cases;
static const char *test_name;
#define CHECK(condition) do { checks++; if (!(condition)) { \
	fprintf(stderr, "CHECK failed [%s] line %d: %s\n", test_name, __LINE__, #condition); \
	exit(1); } } while (0)
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
#define EXPORT_SYMBOL_GPL(name)
#define WARN_ON_ONCE(value) CHECK(!(value))
#define GFP_ATOMIC 0
#define GFP_KERNEL_ACCOUNT 0
#define HZ 100
#define ETH_P_ALL 3
#define NFPROTO_BRIDGE 7
#define NFPROTO_NETDEV 5
#define NF_HOOK_OP_NFT_FT 4
#define NF_FLOWTABLE_COUNTER 1
#define TC_SETUP_FT 1
#define TC_SETUP_CLSFLOWER 2
#define FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS 1
#define NETDEV_UNREGISTER 1
#define NETDEV_REGISTER 2
#define smp_mb__before_atomic() ((void)0)
#define max_t(type, left, right) ((type)(left) > (type)(right) ? (type)(left) : (type)(right))
#define read_pnet(pointer) (*(pointer))
#define kfree(pointer) free(pointer)
#define kfree_rcu(pointer, member) free(pointer)
#define NF_FLOW_TABLE_STAT_INC_ATOMIC(net, member) ((net)->member++)
#define NF_FLOW_TABLE_STAT_DEC_ATOMIC(net, member) CHECK((net)->member-- > 0)

enum flow_cls_command { FLOW_CLS_REPLACE, FLOW_CLS_DESTROY, FLOW_CLS_STATS };
enum flow_block_command { FLOW_BLOCK_BIND, FLOW_BLOCK_UNBIND };
enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY, FLOW_OFFLOAD_DIR_MAX };
enum { NF_FLOW_PENDING, NF_FLOW_TEARDOWN, NF_FLOW_HW, NF_FLOW_HW_DYING,
       NF_FLOW_HW_DEAD, NF_FLOW_CLOSING, NF_FLOW_BRIDGE, NF_FLOW_HW_BIDIRECTIONAL };
enum { IPS_OFFLOAD_BIT, IPS_HW_OFFLOAD_BIT };

struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(name) struct list_head name = { &(name), &(name) }
static void INIT_LIST_HEAD(struct list_head *head) { head->next = head->prev = head; }
static bool list_empty(const struct list_head *head) { return head->next == head; }
static void list_add_tail(struct list_head *entry, struct list_head *head)
{
	entry->prev = head->prev; entry->next = head;
	head->prev->next = entry; head->prev = entry;
}
#define list_add_tail_rcu list_add_tail
static void list_del(struct list_head *entry)
{
	entry->prev->next = entry->next; entry->next->prev = entry->prev;
}
#define list_del_rcu list_del
static void list_splice(struct list_head *source, struct list_head *target)
{
	if (list_empty(source)) return;
	struct list_head *first = source->next, *last = source->prev, *next = target->next;
	target->next = first; first->prev = target; last->next = next; next->prev = last;
}
#define list_entry(pointer, type, member) container_of(pointer, type, member)
#define list_for_each_entry(entry, head, member) \
	for (entry = list_entry((head)->next, __typeof__(*entry), member); \
	     &entry->member != (head); \
	     entry = list_entry(entry->member.next, __typeof__(*entry), member))
#define list_for_each_entry_rcu list_for_each_entry
#define list_for_each_entry_safe(entry, next_entry, head, member) \
	for (entry = list_entry((head)->next, __typeof__(*entry), member), \
	     next_entry = list_entry(entry->member.next, __typeof__(*entry), member); \
	     &entry->member != (head); \
	     entry = next_entry, next_entry = list_entry(entry->member.next, __typeof__(*entry), member))

static bool test_bit(unsigned bit, const unsigned long *flags) { return !!(*flags & (1ul << bit)); }
static void set_bit(unsigned bit, unsigned long *flags) { *flags |= 1ul << bit; }
static void clear_bit(unsigned bit, unsigned long *flags) { *flags &= ~(1ul << bit); }
static bool test_and_set_bit(unsigned bit, unsigned long *flags)
{ bool previous = test_bit(bit, flags); set_bit(bit, flags); return previous; }

struct net { int id, count_wq_add, count_wq_del, count_wq_stats; };
struct nf_conn { struct net *net; unsigned long status; bool dying; };
struct rw_semaphore { unsigned readers; bool writer; };
struct work_struct { void (*function)(struct work_struct *); struct work_struct *next; };
struct delayed_work { struct work_struct work; bool queued, running, rerun, cancelled; };
struct workqueue_struct { struct work_struct *first, *last; };
struct nf_flowtable;
struct flow_block_offload;
struct net_device;
struct netlink_ext_ack { int unused; };
struct flow_rule { int unused; };
struct nf_flow_rule { struct flow_rule *rule; };
struct flow_stats { u64 lastused, pkts, bytes; };
struct flow_cls_offload {
	struct { __be16 protocol; int prio; struct netlink_ext_ack *extack; } common;
	enum flow_cls_command command; unsigned long cookie; bool bridge;
	u64 bridge_generation; struct flow_rule *rule; struct flow_stats stats;
};
struct flow_offload_tuple { int iifidx; unsigned dir; };
struct flow_offload {
	struct { struct flow_offload_tuple tuple; } tuplehash[FLOW_OFFLOAD_DIR_MAX];
	unsigned long flags; struct nf_conn *ct; u64 bridge_generation, timeout;
	bool alive, installed[2]; unsigned adds, deletes, stats, fixups;
};
struct flow_block_cb {
	struct list_head list, driver_list;
	int (*cb)(int, void *, void *); void *cb_priv; unsigned refs, group;
	struct { void *data; struct net_device *dev; } indr;
};
struct flow_block { struct list_head cb_list; };
struct nf_flowtable_type {
	unsigned family; int (*setup)(struct nf_flowtable *, struct net_device *, enum flow_block_command);
	void (*hook)(void);
};
struct nf_flowtable {
	struct net *net; struct nf_flowtable_type *type; struct delayed_work gc_work;
	struct flow_block flow_block; struct rw_semaphore flow_block_lock;
	struct list_head list; bool hw; int priority, flags;
	struct flow_offload *flows[24]; unsigned count, gc_runs; int rhashtable;
};
struct flow_block_offload {
	struct net *net; struct flow_block *block; enum flow_block_command command;
	int binder_type; struct netlink_ext_ack *extack;
	struct list_head *cb_list_head; struct list_head cb_list;
};
struct net_device_ops { int (*ndo_setup_tc)(struct net_device *, int, struct flow_block_offload *); };
struct net_device {
	struct net *net; struct net_device_ops *netdev_ops; int ifindex;
	unsigned group; char name[16]; bool hook_registered;
};
struct nf_hook_ops {
	struct list_head list; int rcu, pf, hooknum, priority, hook_ops_type;
	void *priv; void (*hook)(void); struct net_device *dev;
};
struct nft_hook { struct list_head list, ops_list; char ifname[16]; unsigned ifnamelen; };
struct nft_trans_hook { struct list_head list; struct nft_hook *hook; };
struct nft_flowtable { struct nf_flowtable data; struct list_head hook_list; int hooknum; };
struct flow_offload_work {
	struct list_head list; enum flow_cls_command cmd; struct nf_flowtable *flowtable;
	struct flow_offload *flow; struct work_struct work;
};

static struct workqueue_struct add_queue, del_queue, stats_queue, gc_queue;
static struct workqueue_struct *nf_flow_offload_add_wq = &add_queue;
static struct workqueue_struct *nf_flow_offload_del_wq = &del_queue;
static struct workqueue_struct *nf_flow_offload_stats_wq = &stats_queue;
static struct workqueue_struct *system_power_efficient_wq = &gc_queue;
static struct nft_flowtable table;
static struct nf_flowtable_type table_type;
static struct net networks[2];
static struct net_device devices[4];
static struct flow_offload flows[24];
static struct nf_conn connections[24];
static LIST_HEAD(driver_callbacks);
static LIST_HEAD(all_tables);
static int flowtable_lock;
static unsigned frees, unbinds, syncs, xdp_calls, indirect_calls, clock_now;
static bool fail_destroy_alloc, fail_driver_destroy, check_discovery;
static unsigned deferred_admission_sync, deferred_refresh_sync;
static struct flow_offload *refresh_flow;
static struct net_device *removing_device;
static bool deliver_refresh_at_unbind;
static int setup_error;
static u64 generation = 9;

@DECLARATIONS@

static struct net *dev_net(const struct net_device *dev) { return dev->net; }
static struct net *nf_ct_net(const struct nf_conn *ct) { return ct->net; }
static bool net_eq(const struct net *left, const struct net *right) { return left == right; }
static bool nf_flowtable_hw_offload(const struct nf_flowtable *flowtable) { return flowtable->hw; }
static bool nf_ct_is_dying(const struct nf_conn *ct) { return ct->dying; }
static bool nf_flow_has_expired(const struct flow_offload *flow) { return false; }
static bool nf_flow_dst_valid(struct nf_flowtable *flowtable, struct flow_offload *flow, int direction) { return true; }
static bool nf_flow_custom_gc(struct nf_flowtable *flowtable, struct flow_offload *flow) { return false; }
static void nf_flow_table_extend_ct_timeout(struct nf_conn *ct) {}
static void flow_offload_fixup_ct(struct flow_offload *flow) { flow->fixups++; }
static unsigned long flow_offload_get_timeout(struct flow_offload *flow) { return 30 * HZ; }
static __s32 nf_flow_timeout_delta(u64 timeout) { return (__s32)(timeout - clock_now); }
static void nf_ct_acct_add(struct nf_conn *ct, int direction, u64 packets, u64 bytes) {}
static u64 br_flow_offload_generation(void) { return generation; }
static void *kmalloc(size_t bytes, int flags) { return fail_destroy_alloc ? NULL : calloc(1, bytes); }
static void *kzalloc(size_t bytes, int flags) { return calloc(1, bytes); }
static void mutex_lock(int *lock) { CHECK(!*lock); *lock = 1; }
static void mutex_unlock(int *lock) { CHECK(*lock == 1); *lock = 0; }
static void down_read(struct rw_semaphore *lock) { CHECK(!lock->writer); lock->readers++; }
static void up_read(struct rw_semaphore *lock) { CHECK(lock->readers); lock->readers--; }
static void down_write(struct rw_semaphore *lock) { CHECK(!lock->writer && !lock->readers); lock->writer = true; }
static void up_write(struct rw_semaphore *lock) { CHECK(lock->writer); lock->writer = false; }
#define INIT_WORK(work, handler) ((work)->function = (handler))

static void queue_work(struct workqueue_struct *queue, struct work_struct *work)
{
	work->next = NULL;
	if (queue->last) queue->last->next = work; else queue->first = work;
	queue->last = work;
}
static void flush_workqueue(struct workqueue_struct *queue)
{
	CHECK(!table.data.flow_block_lock.writer);
	while (queue->first) {
		struct work_struct *work = queue->first;
		queue->first = work->next;
		if (!queue->first) queue->last = NULL;
		work->function(work);
	}
}
static bool queue_delayed_work(struct workqueue_struct *queue, struct delayed_work *work, unsigned delay)
{
	CHECK(queue == system_power_efficient_wq && !work->cancelled);
	if (work->queued || work->rerun) return false;
	work->queued = true;
	return true;
}
static bool mod_delayed_work(struct workqueue_struct *queue, struct delayed_work *work, unsigned delay)
{
	CHECK(queue == system_power_efficient_wq && !delay && !work->cancelled);
	bool was_pending = work->queued;
	if (work->running) work->rerun = true; else work->queued = true;
	return was_pending;
}
static bool flush_delayed_work(struct delayed_work *work)
{
	CHECK(!table.data.flow_block_lock.writer);
	if (work->running) {
		work->running = false;
		if (!work->rerun) { work->queued = true; return true; }
		work->queued = true; work->rerun = false;
	}
	if (!work->queued) return false;
	work->queued = false; work->running = true;
	work->work.function(&work->work);
	work->running = false;
	return true;
}
static void cancel_delayed_work_sync(struct delayed_work *work)
{
	CHECK(!table.data.flow_block_lock.writer);
	work->running = work->queued = work->rerun = false; work->cancelled = true;
}

static int nf_flow_table_iterate(struct nf_flowtable *flowtable,
	void (*iterator)(struct nf_flowtable *, struct flow_offload *, void *), void *data)
{
	if (iterator == nf_flow_offload_gc_step) {
		CHECK(flowtable->gc_work.running || flowtable->gc_work.cancelled);
		flowtable->gc_runs++;
	}
	for (unsigned index = 0; index < flowtable->count; index++)
		if (flowtable->flows[index]->alive) iterator(flowtable, flowtable->flows[index], data);
	return 0;
}
static void flow_offload_del(struct nf_flowtable *flowtable, struct flow_offload *flow)
{
	CHECK(flow->alive && !test_bit(NF_FLOW_PENDING, &flow->flags));
	flow->alive = false;
}
static void rhashtable_destroy(int *hash)
{
	for (unsigned index = 0; index < table.data.count; index++) CHECK(!flows[index].alive);
}
static struct flow_offload *flow_from_cookie(unsigned long cookie, unsigned *direction)
{
	for (unsigned index = 0; index < table.data.count; index++)
		for (unsigned side = 0; side < 2; side++)
			if ((unsigned long)&flows[index].tuplehash[side].tuple == cookie) {
				*direction = side; return &flows[index];
			}
	CHECK(false); return NULL;
}
static int hardware_callback(int type, void *data, void *private)
{
	struct flow_cls_offload *request = data;
	unsigned direction;
	struct flow_offload *flow = flow_from_cookie(request->cookie, &direction);
	CHECK(type == TC_SETUP_CLSFLOWER && table.data.flow_block_lock.readers);
	CHECK(flow->alive);
	switch (request->command) {
	case FLOW_CLS_REPLACE:
		flow->installed[direction] = true; flow->adds++; break;
	case FLOW_CLS_DESTROY:
		flow->deletes++;
		if (fail_driver_destroy) return -EIO;
		flow->installed[direction] = false; break;
	case FLOW_CLS_STATS:
		flow->stats++; request->stats.lastused = clock_now; break;
	}
	return 0;
}
static int nf_flow_offload_alloc(struct flow_offload_work *work, struct nf_flow_rule **rules)
{
	static struct flow_rule action; static struct nf_flow_rule rule = { &action };
	rules[0] = rules[1] = &rule; return 0;
}
static void nf_flow_offload_destroy(struct nf_flow_rule **rules) {}

static struct flow_block_cb *find_callback(struct flow_block *block, unsigned group)
{
	struct flow_block_cb *callback;
	list_for_each_entry(callback, &block->cb_list, list)
		if (callback->group == group) return callback;
	return NULL;
}
static void flow_block_cb_free(struct flow_block_cb *callback) { CHECK(!callback->refs); frees++; free(callback); }
static void deliver_refresh(void)
{
	CHECK(refresh_flow && refresh_flow->alive);
	nf_flow_offload_add(&table.data, refresh_flow);
	refresh_flow = NULL; deferred_refresh_sync = 0; deliver_refresh_at_unbind = false;
}
static int mock_setup_tc(struct net_device *dev, int type, struct flow_block_offload *block)
{
	CHECK(type == TC_SETUP_FT);
	CHECK(table.data.flow_block_lock.writer || !dev->netdev_ops->ndo_setup_tc);
	if (setup_error) return setup_error;
	struct flow_block_cb *callback = find_callback(block->block, dev->group);
	if (block->command == FLOW_BLOCK_BIND) {
		if (callback) { callback->refs++; return 0; }
		callback = calloc(1, sizeof(*callback)); CHECK(callback);
		callback->group = dev->group; callback->refs = 1; callback->cb = hardware_callback;
		callback->indr.data = &table.data; callback->indr.dev = dev;
		list_add_tail(&callback->list, &block->cb_list);
		list_add_tail(&callback->driver_list, &driver_callbacks);
		return 0;
	}
	unbinds++;
	if (deliver_refresh_at_unbind && refresh_flow) deliver_refresh();
	for (unsigned index = 0; index < table.data.count; index++) {
		struct flow_offload *flow = table.data.flows[index];
		if (flow->ct->net != dev->net ||
		    (flow->tuplehash[0].tuple.iifidx != dev->ifindex &&
		     flow->tuplehash[1].tuple.iifidx != dev->ifindex)) continue;
		CHECK(!flow->installed[0] && !flow->installed[1]);
		CHECK(!test_bit(NF_FLOW_PENDING, &flow->flags));
	}
	if (!callback) return -ENOENT;
	CHECK(callback->refs);
	if (!--callback->refs) {
		list_del(&callback->list); list_add_tail(&callback->list, &block->cb_list);
		list_del(&callback->driver_list);
	}
	return 0;
}
static int flow_indr_dev_setup_offload(struct net_device *dev, void *queue, int type,
	void *data, struct flow_block_offload *block, void (*cleanup)(struct flow_block_cb *))
{ indirect_calls++; return mock_setup_tc(dev, type, block); }
static int nf_flow_offload_xdp_setup(struct nf_flowtable *flowtable, struct net_device *dev, enum flow_block_command command)
{ xdp_calls++; return 0; }

static struct flow_offload *add_flow(int input, int reply, unsigned namespace, bool hardware)
{
	unsigned index = table.data.count++; CHECK(index < 24);
	struct flow_offload *flow = &flows[index];
	flow->ct = &connections[index]; flow->ct->net = &networks[namespace];
	flow->tuplehash[0].tuple.iifidx = input; flow->tuplehash[1].tuple.iifidx = reply;
	flow->tuplehash[1].tuple.dir = 1; flow->alive = true;
	flow->timeout = clock_now + HZ;
	set_bit(IPS_OFFLOAD_BIT, &flow->ct->status);
	set_bit(NF_FLOW_HW_BIDIRECTIONAL, &flow->flags);
	if (hardware) {
		set_bit(NF_FLOW_HW, &flow->flags);
		flow->installed[0] = flow->installed[1] = true;
	}
	table.data.flows[index] = flow;
	return flow;
}
static void synchronize_net(void)
{
	CHECK(!table.data.flow_block_lock.writer && !table.data.flow_block_lock.readers);
	syncs++;
	if (check_discovery) CHECK(!nft_flowtable_find_dev(removing_device, &table));
	if (deferred_admission_sync == syncs) {
		struct flow_offload *flow = add_flow(devices[0].ifindex, devices[1].ifindex, 0, true);
		flow->installed[0] = flow->installed[1] = false;
		nf_flow_offload_add(&table.data, flow); deferred_admission_sync = 0;
	}
	if (deferred_refresh_sync == syncs) deliver_refresh();
}

static void nft_netdev_hook_free_rcu(struct nft_hook *hook)
{
	struct nf_hook_ops *ops, *next;
	list_for_each_entry_safe(ops, next, &hook->ops_list, list) { list_del(&ops->list); free(ops); }
	free(hook);
}
static void nft_netdev_hook_unlink_free_rcu(struct nft_hook *hook)
{ list_del_rcu(&hook->list); nft_netdev_hook_free_rcu(hook); }
static void nft_trans_hook_destroy(struct nft_trans_hook *hook) { list_del(&hook->list); free(hook); }
static void nf_unregister_net_hook(struct net *net, struct nf_hook_ops *ops)
{ CHECK(net == dev_net(ops->dev)); ops->dev->hook_registered = false; }
static int nft_register_flowtable_ops(struct net *net, struct nft_flowtable *flowtable, struct nf_hook_ops *ops)
{
	ops->dev->hook_registered = true;
	return flowtable->data.type->setup(&flowtable->data, ops->dev, FLOW_BLOCK_BIND);
}

@DEFINITIONS@

static struct net_device_ops direct_ops = { mock_setup_tc }, indirect_ops;
static void fixture(const char *name, bool hardware)
{
	test_name = name; cases++;
	CHECK(!add_queue.first && !del_queue.first && !stats_queue.first);
	CHECK(list_empty(&driver_callbacks) && list_empty(&all_tables));
	memset(&table, 0, sizeof(table)); memset(flows, 0, sizeof(flows));
	memset(connections, 0, sizeof(connections)); memset(networks, 0, sizeof(networks));
	memset(devices, 0, sizeof(devices));
	table_type = (struct nf_flowtable_type){ .family = 2, .setup = nf_flow_table_offload_setup };
	table.data.type = &table_type; table.data.net = &networks[0]; table.data.hw = hardware;
	INIT_LIST_HEAD(&table.data.flow_block.cb_list); INIT_LIST_HEAD(&table.hook_list);
	INIT_LIST_HEAD(&table.data.list); list_add_tail(&table.data.list, &all_tables);
	INIT_WORK(&table.data.gc_work.work, nf_flow_offload_work_gc); table.data.gc_work.queued = true;
	for (unsigned index = 0; index < 4; index++) {
		devices[index].net = &networks[0]; devices[index].netdev_ops = &direct_ops;
		devices[index].ifindex = (int)index + 1; devices[index].group = index;
		snprintf(devices[index].name, sizeof(devices[index].name), "dev%u", index);
	}
	frees = unbinds = syncs = xdp_calls = indirect_calls = 0; clock_now = 10000;
	fail_destroy_alloc = fail_driver_destroy = check_discovery = false;
	deferred_admission_sync = deferred_refresh_sync = 0;
	refresh_flow = NULL; removing_device = NULL; deliver_refresh_at_unbind = false; setup_error = 0;
}
static struct nft_hook *bind_device(unsigned index)
{
	struct nft_hook *hook = calloc(1, sizeof(*hook));
	struct nf_hook_ops *ops = calloc(1, sizeof(*ops)); CHECK(hook && ops);
	INIT_LIST_HEAD(&hook->ops_list); ops->dev = &devices[index];
	memcpy(hook->ifname, devices[index].name, sizeof(hook->ifname));
	hook->ifnamelen = (unsigned)strlen(hook->ifname);
	list_add_tail(&ops->list, &hook->ops_list); list_add_tail(&hook->list, &table.hook_list);
	CHECK(!nft_register_flowtable_ops(dev_net(ops->dev), &table, ops));
	return hook;
}
static void assert_removed(struct flow_offload *flow)
{
	CHECK(!flow->installed[0] && !flow->installed[1]);
	CHECK(test_bit(NF_FLOW_TEARDOWN, &flow->flags));
	CHECK(!test_bit(NF_FLOW_PENDING, &flow->flags));
	if (test_bit(NF_FLOW_HW, &flow->flags)) CHECK(test_bit(NF_FLOW_HW_DEAD, &flow->flags));
}
static void finish(void)
{
	check_discovery = false; fail_destroy_alloc = fail_driver_destroy = false; setup_error = 0;
	nft_unregister_flowtable_net_hooks(&networks[0], &table, &table.hook_list);
	nf_flow_table_free(&table.data);
	for (unsigned index = 0; index < table.data.count; index++) {
		CHECK(!flows[index].alive); CHECK(!flows[index].installed[0] && !flows[index].installed[1]);
	}
	struct nft_hook *hook, *next;
	list_for_each_entry_safe(hook, next, &table.hook_list, list) nft_netdev_hook_unlink_free_rcu(hook);
	CHECK(list_empty(&table.data.flow_block.cb_list) && list_empty(&driver_callbacks));
	CHECK(!networks[0].count_wq_add && !networks[0].count_wq_del && !networks[0].count_wq_stats);
}
static void pending_flow(struct flow_offload *flow, unsigned pending)
{
	switch (pending) {
	case 0: break;
	case 1: flow->installed[0] = flow->installed[1] = false; nf_flow_offload_add(&table.data, flow); break;
	case 2: nf_flow_offload_stats(&table.data, flow); break;
	case 3: nf_flow_offload_del(&table.data, flow); break;
	case 4: flow_offload_teardown(flow); nf_flow_offload_del(&table.data, flow); break;
	}
	if (pending) CHECK(test_bit(NF_FLOW_PENDING, &flow->flags));
}
static void delete_cases(unsigned pending, bool running, bool indirect, bool shared, bool namespace_exit)
{
	fixture(running ? "running GC and unbind" : "delete table with pending work", true);
	if (indirect) devices[0].netdev_ops = &indirect_ops;
	if (shared) devices[1].group = devices[0].group;
	bind_device(0); bind_device(1);
	struct flow_offload *flow = add_flow(1, 2, 0, true);
	pending_flow(flow, pending);
	table.data.gc_work.running = running; table.data.gc_work.queued = !running;
	if (namespace_exit)
		__nft_unregister_flowtable_net_hooks(&networks[0], &table, &table.hook_list, true);
	else
		nft_unregister_flowtable_net_hooks(&networks[0], &table, &table.hook_list);
	assert_removed(flow); CHECK(unbinds == 2 && frees == (shared ? 1u : 2u));
	if (indirect) CHECK(indirect_calls == 2);
	finish();
}
static void single_hook_case(bool shared, unsigned pending, bool reverse)
{
	fixture("single hook with retained unrelated flows", true);
	if (shared) devices[1].group = devices[0].group;
	struct nft_hook *hook = bind_device(0); bind_device(1); bind_device(2);
	struct flow_offload *removed = add_flow(reverse ? 2 : 1, reverse ? 1 : 2, 0, true);
	struct flow_offload *retained = add_flow(2, 3, 0, true);
	pending_flow(removed, pending);
	LIST_HEAD(transactions);
	struct nft_trans_hook *transaction = calloc(1, sizeof(*transaction)); CHECK(transaction);
	transaction->hook = hook; list_add_tail(&transaction->list, &transactions);
	check_discovery = true; removing_device = &devices[0];
	nft_flowtable_unregister_trans_hook(&networks[0], &table, &transactions);
	assert_removed(removed); CHECK(list_empty(&transactions));
	CHECK(retained->alive && retained->installed[0] && retained->installed[1]);
	CHECK(!retained->deletes && !test_bit(NF_FLOW_TEARDOWN, &retained->flags));
	CHECK(!nft_flowtable_find_dev(&devices[0], &table) && nft_flowtable_find_dev(&devices[1], &table));
	if (shared) CHECK(find_callback(&table.data.flow_block, 0)->refs == 1 && frees == 0);
	else CHECK(frees == 1);
	finish();
}
static void deferred_case(bool admission)
{
	fixture(admission ? "old packet admits a flow before cleanup" : "old reader refreshes after teardown", true);
	bind_device(0);
	if (admission) deferred_admission_sync = 1;
	else {
		refresh_flow = add_flow(1, 2, 0, true);
		deferred_refresh_sync = 2; deliver_refresh_at_unbind = true;
	}
	nft_unregister_flowtable_net_hooks(&networks[0], &table, &table.hook_list);
	CHECK(table.data.count == 1); assert_removed(&flows[0]);
	CHECK(!deferred_admission_sync && !deferred_refresh_sync && !refresh_flow);
	CHECK(!add_queue.first && !del_queue.first && !stats_queue.first);
	finish();
}
static void netdev_cases(void)
{
	fixture("netdevice unregister hides ops before cleanup", true);
	bind_device(0); bind_device(1);
	struct flow_offload *flow = add_flow(2, 1, 0, true);
	removing_device = &devices[0]; check_discovery = true;
	CHECK(!nft_flowtable_event(NETDEV_UNREGISTER, &devices[0], &table, false));
	assert_removed(flow); CHECK(!nft_flowtable_find_dev(&devices[0], &table)); finish();

	fixture("matching device rename keeps callback", true); bind_device(0);
	flow = add_flow(1, 2, 0, true);
	CHECK(!nft_flowtable_event(NETDEV_UNREGISTER, &devices[0], &table, true));
	CHECK(!unbinds && flow->installed[0] && !test_bit(NF_FLOW_TEARDOWN, &flow->flags)); finish();
}
static void scope_cases(void)
{
	fixture("same ifindex in another namespace is untouched", true); bind_device(0);
	struct flow_offload *flow = add_flow(1, 2, 1, true);
	nf_flow_table_gc_cleanup(&table.data, &devices[0]);
	CHECK(!test_bit(NF_FLOW_TEARDOWN, &flow->flags) && !flow->deletes && flow->installed[0]);
	flow->ct->net = &networks[0]; finish();

	fixture("NULL cleanup selects entire table", true); bind_device(0);
	flow = add_flow(3, 4, 0, true);
	nf_flow_table_gc_cleanup(&table.data, NULL); assert_removed(flow); finish();

	fixture("software table preserves XDP dispatch", false); bind_device(0);
	flow = add_flow(1, 2, 0, false);
	CHECK(!nf_flow_table_offload_setup(&table.data, &devices[0], FLOW_BLOCK_UNBIND));
	CHECK(xdp_calls == 2 && !syncs && flow->alive); finish();

	fixture("no callback and no flows", true);
	CHECK(nf_flow_table_offload_setup(&table.data, &devices[0], FLOW_BLOCK_UNBIND) == -ENOENT); finish();

	fixture("driver unbind failure retains callback after drain", true); bind_device(0);
	flow = add_flow(1, 2, 0, true); setup_error = -EBUSY;
	CHECK(nf_flow_table_offload_setup(&table.data, &devices[0], FLOW_BLOCK_UNBIND) == -EBUSY);
	assert_removed(flow); CHECK(!frees && find_callback(&table.data.flow_block, 0)); finish();

	fixture("indirect cleanup uses the same pending drain", true); devices[0].netdev_ops = &indirect_ops;
	struct nft_hook *hook = bind_device(0); flow = add_flow(1, 2, 0, true); pending_flow(flow, 2);
	struct flow_block_cb *callback = find_callback(&table.data.flow_block, 0);
	callback->refs = 0; nf_flow_table_indr_cleanup(callback);
	assert_removed(flow); nft_netdev_hook_unlink_free_rcu(hook); finish();
}
static void mixed_cases(void)
{
	for (unsigned bidirectional = 0; bidirectional < 2; bidirectional++) {
		fixture("mixed ADD STATS DEL and software flows", true);
		bind_device(0);
		for (unsigned pending = 1; pending <= 3; pending++) {
			struct flow_offload *flow = add_flow(1, 2, 0, true);
			if (!bidirectional) {
				clear_bit(NF_FLOW_HW_BIDIRECTIONAL, &flow->flags); flow->installed[1] = false;
			}
			pending_flow(flow, pending);
		}
		add_flow(1, 2, 0, false);
		CHECK(!nf_flow_table_offload_setup(&table.data, &devices[0], FLOW_BLOCK_UNBIND));
		for (unsigned index = 0; index < 4; index++) assert_removed(&flows[index]);
		for (unsigned index = 0; index < 3; index++) CHECK(flows[index].deletes == bidirectional + 1);
		CHECK(!flows[3].alive); finish();
	}

	fixture("idle GC gets queued for cleanup", true); bind_device(0);
	struct flow_offload *flow = add_flow(1, 2, 0, true);
	table.data.gc_work.queued = false;
	CHECK(!nf_flow_table_offload_setup(&table.data, &devices[0], FLOW_BLOCK_UNBIND));
	assert_removed(flow); CHECK(table.data.gc_work.queued); finish();
}
static void failure_cases(void)
{
	fixture("existing destroy allocation failure needs later retry", true); bind_device(0);
	struct flow_offload *flow = add_flow(1, 2, 0, true); fail_destroy_alloc = true;
	nf_flow_table_gc_cleanup(&table.data, &devices[0]);
	CHECK(flow->installed[0] && !flow->deletes && !test_bit(NF_FLOW_HW_DYING, &flow->flags));
	fail_destroy_alloc = false; nf_flow_table_gc_cleanup(&table.data, &devices[0]); assert_removed(flow); finish();

	fixture("existing driver destroy error still sets hardware dead", true); bind_device(0);
	flow = add_flow(1, 2, 0, true); fail_driver_destroy = true;
	nf_flow_table_gc_cleanup(&table.data, &devices[0]);
	CHECK(flow->installed[0] && flow->deletes && test_bit(NF_FLOW_HW_DEAD, &flow->flags));
	fail_driver_destroy = false;
	flow->installed[0] = flow->installed[1] = false; finish();
}
int main(int argc, char **argv)
{
	if (argc == 2) {
		if (!strcmp(argv[1], "delete")) delete_cases(0, false, false, false, false);
		else if (!strcmp(argv[1], "pending")) delete_cases(2, false, false, false, false);
		else if (!strcmp(argv[1], "running")) {
			fixture("GC already scanned before cleanup", true); bind_device(0);
			struct flow_offload *flow = add_flow(1, 2, 0, true);
			table.data.gc_work.queued = false; table.data.gc_work.running = true;
			CHECK(!nf_flow_table_offload_setup(&table.data, &devices[0], FLOW_BLOCK_UNBIND));
			assert_removed(flow); finish();
		} else if (!strcmp(argv[1], "hook")) single_hook_case(true, 0, false);
		else if (!strcmp(argv[1], "admission")) deferred_case(true);
		else if (!strcmp(argv[1], "reader")) deferred_case(false);
		else if (!strcmp(argv[1], "scope")) scope_cases();
		else if (!strcmp(argv[1], "netdev")) netdev_cases();
		else CHECK(false);
	} else {
		for (unsigned pending = 0; pending < 5; pending++)
			for (unsigned flags = 0; flags < 16; flags++)
				delete_cases(pending, flags & 1, flags & 2, flags & 4, flags & 8);
		for (unsigned pending = 0; pending < 5; pending++)
			for (unsigned flags = 0; flags < 4; flags++) single_hook_case(flags & 1, pending, flags & 2);
		deferred_case(true); deferred_case(false); netdev_cases(); scope_cases(); mixed_cases(); failure_cases();
	}
	printf("%u cases / %u checks\n", cases, checks);
	return 0;
}
