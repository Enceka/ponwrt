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

#define U16_MAX UINT16_MAX
#define U32_MAX UINT32_MAX
#define AIROHA_CT_PAIR_SLOTS 2
#define CT_PAIR_ROWS 2
#define AIROHA_CT_PAIR_LAN1_SELECTOR 2
#define AIROHA_CT_PAIR_LAN1_ID 151
#define AIROHA_CT_PAIR_FLUSH 1
#define AIROHA_CT_PAIR_ENDPOINT_REVOKE 2
#define AIROHA_FOE_IB1_BIND_STATE 3
#define NOTIFY_DONE 0
#define cpu_to_le16(value) ((u16)(value))
#define cpu_to_le32(value) ((u32)(value))
#define le16_to_cpu(value) ((u16)(value))
#define max(left, right) ((left) > (right) ? (left) : (right))
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
#define list_for_each_entry(entry, head, member) \
	for ((entry) = (head)->first; (entry); (entry) = (entry)->next)

enum {
	NETDEV_GOING_DOWN = 1, NETDEV_DOWN, NETDEV_UNREGISTER,
	NETDEV_PRE_CHANGEADDR, NETDEV_PRECHANGEMTU, NETDEV_PRECHANGEUPPER,
	NETDEV_CHANGE, NETDEV_UP, NETDEV_CHANGEADDR, NETDEV_CHANGEMTU,
	NETDEV_CHANGEUPPER,
	SWITCHDEV_BRIDGE_NATIVE_PAIR_FRAME = 100,
	SWITCHDEV_BRIDGE_FWD_PRE_CHANGE,
	SWITCHDEV_BRIDGE_FWD_POST_CHANGE,
};

struct notifier_block { unsigned int identity; };
struct net_device { bool running, carrier; };
struct sk_buff { unsigned int identity; };
struct switchdev_notifier_bridge_fwd_info { int err; };
struct switchdev_notifier_native_pair_info { struct sk_buff *skb; };
struct hlist_node { bool linked; };
struct airoha_flow_table_entry {
	struct airoha_flow_table_entry *next;
	struct hlist_node list;
	bool ct_bridge_dead;
	u16 hash;
	unsigned int index;
};
struct list_head { struct airoha_flow_table_entry *first; };
struct airoha_foe_entry { u32 ib1; };
struct airoha_ct_pair_msg {
	u16 op, src_wcid, dst_wcid;
	u8 src_selector, dst_selector;
	u32 src_epoch;
};
struct airoha_ct_native_pair {
	bool used;
	struct airoha_ct_pair_msg msg;
	u16 hashes[CT_PAIR_ROWS];
	struct airoha_foe_entry rows[CT_PAIR_ROWS];
};
struct airoha_ppe {
	struct notifier_block ct_bridge_notifier, ct_pair_wired_notifier;
	struct list_head ct_bridge_flows;
	struct airoha_ct_native_pair ct_pairs[AIROHA_CT_PAIR_SLOTS];
	bool ct_host_ppe, ct_native_pairs, ct_bridge_failed, ct_stopping;
	bool ct_pair_wired_blocked, npu_owner, closed_ack, invalidated;
	u32 ct_pair_wired_epoch, ct_wlan_epoch[2][151];
	struct {
		const void *owner;
		bool owner_quiesced, pending, arm_pending, armed, active, touched;
		u32 epoch;
		u64 generation;
	} ct_fe;
};

static unsigned int checks, scenarios;
static const char *scenario;
static int ppe_lock;
static struct airoha_ppe device;
static struct net_device lan, pon, unrelated;
static struct airoha_flow_table_entry flows[3];
static struct airoha_foe_entry rows[4];
static struct net_device *last_notify_dev;
static unsigned int notify_calls, notify_matches, native_sends, native_writes;
static unsigned int remove_calls, fail_calls, drain_calls, resume_calls, frame_calls;
static int notify_error, native_error, fail_error, remove_error_index;

#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed: %s:%d: %s\n", scenario, __LINE__, #condition); \
		exit(1); \
	} \
} while (0)

static void spin_lock_bh(int *lock) { CHECK(!*lock); *lock = 1; }
static void spin_unlock_bh(int *lock) { CHECK(*lock); *lock = 0; }
static void lockdep_assert_held(int *lock) { CHECK(*lock); }
static void hlist_del_init(struct hlist_node *node) { node->linked = false; }
static int notifier_from_errno(int error) { return error; }
static struct net_device *netdev_notifier_info_to_dev(void *info) { return info; }
static bool netif_running(struct net_device *netdev) { return netdev->running; }
static bool netif_carrier_ok(struct net_device *netdev) { return netdev->carrier; }
static struct net_device *airoha_ct_pair_lan1(struct airoha_ppe *ppe) { return &lan; }
static u64 br_flow_offload_generation(void) { return 0; }

static int airoha_npu_owner_notify(struct airoha_ppe *ppe, struct net_device *netdev)
{
	lockdep_assert_held(&ppe_lock);
	++notify_calls;
	last_notify_dev = netdev;
	if (!ppe->npu_owner || (netdev && netdev != &pon))
		return 0;
	++notify_matches;
	ppe->invalidated = true;
	return notify_error ?: (ppe->closed_ack ? 0 : -EAGAIN);
}

static int airoha_ppe_ct_bridge_fail_closed(struct airoha_ppe *ppe)
{
	lockdep_assert_held(&ppe_lock);
	++fail_calls;
	ppe->ct_bridge_failed = true;
	ppe->ct_stopping = true;
	return fail_error;
}

static int airoha_ct_pair_fail(struct airoha_ppe *ppe, int error)
{
	int result = airoha_ppe_ct_bridge_fail_closed(ppe);
	return result ?: error;
}

static int airoha_ct_fe_quiesce(struct airoha_ppe *ppe, u64 generation)
{
	lockdep_assert_held(&ppe_lock);
	ppe->ct_fe.armed = false;
	ppe->ct_fe.touched = false;
	ppe->ct_fe.pending = false;
	ppe->ct_fe.arm_pending = false;
	return 0;
}

static int airoha_ct_pair_send(struct airoha_ppe *ppe, struct airoha_ct_pair_msg *message)
{
	lockdep_assert_held(&ppe_lock);
	CHECK(message->op == AIROHA_CT_PAIR_FLUSH || message->op == AIROHA_CT_PAIR_ENDPOINT_REVOKE);
	++native_sends;
	return native_error;
}

static int airoha_ct_fe_ppe_drain(struct airoha_ppe *ppe)
{
	lockdep_assert_held(&ppe_lock);
	++drain_calls;
	return 0;
}

static int airoha_ct_fe_ppe_resume(struct airoha_ppe *ppe)
{
	lockdep_assert_held(&ppe_lock);
	++resume_calls;
	return 0;
}

static struct airoha_foe_entry *airoha_ppe_foe_get_entry_locked(struct airoha_ppe *ppe, u16 hash)
{
	lockdep_assert_held(&ppe_lock);
	CHECK(hash < 4);
	return &rows[hash];
}

static bool airoha_ct_pair_row_owned(const struct airoha_foe_entry *row,
				    const struct airoha_foe_entry *saved)
{
	return row->ib1 == saved->ib1;
}

static int airoha_ppe_foe_commit_entry(struct airoha_ppe *ppe,
				     const struct airoha_foe_entry *entry, u16 hash, bool force)
{
	lockdep_assert_held(&ppe_lock);
	CHECK(hash < 4);
	rows[hash] = *entry;
	++native_writes;
	return 0;
}

static int airoha_ppe_ct_remove_wlan_flow_locked(struct airoha_ppe *ppe,
					       struct airoha_flow_table_entry *entry)
{
	lockdep_assert_held(&ppe_lock);
	CHECK(!ppe->ct_bridge_failed && !ppe->ct_stopping);
	++remove_calls;
	hlist_del_init(&entry->list);
	if ((int)entry->index == remove_error_index)
		return -EIO;
	entry->hash = U16_MAX;
	return 0;
}

static void airoha_ct_native_pair_frame(struct airoha_ppe *ppe, struct sk_buff *skb)
{
	CHECK(!ppe_lock);
	++frame_calls;
}

#include "events.inc"

static void reset(const char *name)
{
	scenario = name;
	++scenarios;
	CHECK(!ppe_lock);
	memset(&device, 0, sizeof(device));
	memset(flows, 0, sizeof(flows));
	memset(rows, 0, sizeof(rows));
	lan = pon = unrelated = (struct net_device) { true, true };
	device.ct_host_ppe = true;
	device.ct_native_pairs = true;
	device.npu_owner = true;
	device.ct_fe.owner = &device;
	device.ct_fe.armed = true;
	device.ct_bridge_flows.first = flows;
	for (unsigned int index = 0; index < 3; ++index) {
		flows[index].index = index;
		flows[index].hash = index;
		flows[index].list.linked = true;
		if (index + 1 < 3)
			flows[index].next = &flows[index + 1];
	}
	for (unsigned int slot = 0; slot < AIROHA_CT_PAIR_SLOTS; ++slot)
		for (unsigned int row = 0; row < CT_PAIR_ROWS; ++row)
			device.ct_pairs[slot].hashes[row] = U16_MAX;
	notify_calls = notify_matches = native_sends = native_writes = 0;
	remove_calls = fail_calls = drain_calls = resume_calls = frame_calls = 0;
	notify_error = native_error = fail_error = 0;
	remove_error_index = -1;
	last_notify_dev = &unrelated;
}

static void no_owner(void)
{
	device.npu_owner = false;
	device.ct_fe.owner = NULL;
	device.ct_fe.armed = false;
}

static void closed_owner(void)
{
	device.closed_ack = true;
	device.ct_fe.armed = false;
	device.ct_fe.owner_quiesced = true;
}

static void expect_dead(void)
{
	for (unsigned int index = 0; index < 3; ++index) {
		CHECK(flows[index].ct_bridge_dead);
		CHECK(!flows[index].list.linked);
	}
}

static int bridge(int prior_error)
{
	struct switchdev_notifier_bridge_fwd_info info = { .err = prior_error };
	CHECK(airoha_ppe_ct_bridge_event(&device.ct_bridge_notifier,
		SWITCHDEV_BRIDGE_FWD_PRE_CHANGE, &info) == NOTIFY_DONE);
	CHECK(!ppe_lock);
	return info.err;
}

static int native(int band, u16 wcid)
{
	int error;
	spin_lock_bh(&ppe_lock);
	error = airoha_ct_native_pair_revoke(&device, band, wcid);
	spin_unlock_bh(&ppe_lock);
	return error;
}

static void test_bridge(void)
{
	reset("owner EAGAIN keeps bridge cleanup");
	CHECK(bridge(0) == -EAGAIN);
	expect_dead();
	CHECK(remove_calls == 3 && native_sends == 0 && fail_calls == 0);
	CHECK(notify_calls == 1 && notify_matches == 1);
	for (unsigned int index = 0; index < 3; ++index)
		CHECK(flows[index].hash == U16_MAX);

	reset("earlier notifier error survives");
	CHECK(bridge(-ENOSPC) == -ENOSPC);
	expect_dead();
	CHECK(remove_calls == 3);

	reset("owner error precedes row error");
	remove_error_index = 0;
	CHECK(bridge(0) == -EAGAIN);
	expect_dead();
	CHECK(remove_calls == 1 && fail_calls == 1);

	reset("native mailbox failure stops hardware cleanup");
	no_owner();
	native_error = -ETIMEDOUT;
	CHECK(bridge(0) == -ETIMEDOUT);
	expect_dead();
	CHECK(remove_calls == 0 && fail_calls == 1);

	reset("generic FE owner refusal invokes failclose");
	device.npu_owner = false;
	CHECK(bridge(0) == -EAGAIN);
	expect_dead();
	CHECK(remove_calls == 0 && fail_calls == 1 && native_sends == 0);

	reset("row failure retains remaining cookies and skips later MMIO");
	no_owner();
	remove_error_index = 1;
	CHECK(bridge(0) == -EIO);
	expect_dead();
	CHECK(remove_calls == 2 && fail_calls == 1);
	CHECK(flows[0].hash == U16_MAX && flows[1].hash == 1 && flows[2].hash == 2);

	reset("preexisting bridge fault preserves owner first error");
	device.ct_bridge_failed = true;
	fail_error = -EIO;
	CHECK(bridge(0) == -EAGAIN);
	expect_dead();
	CHECK(remove_calls == 0 && fail_calls == 1);

	reset("POST does not reopen or notify");
	struct switchdev_notifier_bridge_fwd_info info = {};
	CHECK(airoha_ppe_ct_bridge_event(&device.ct_bridge_notifier,
		SWITCHDEV_BRIDGE_FWD_POST_CHANGE, &info) == NOTIFY_DONE);
	CHECK(notify_calls == 0 && remove_calls == 0 && !device.invalidated);

	reset("stopped host bridge has no owner callback");
	device.ct_host_ppe = false;
	CHECK(bridge(0) == 0);
	CHECK(notify_calls == 0 && remove_calls == 0);

	reset("owner route or gate error remains first");
	notify_error = -EIO;
	CHECK(bridge(0) == -EIO);
	expect_dead();
	CHECK(remove_calls == 3 && notify_calls == 1);
}

static void test_native(void)
{
	reset("FE quiet before complete close still waits");
	device.ct_fe.armed = false;
	device.ct_fe.owner_quiesced = true;
	CHECK(native(0, 1) == -EAGAIN);
	CHECK(native_sends == 0 && notify_matches == 1);

	for (unsigned int state = 0; state < 6; ++state) {
		reset("generic FE owner guard");
		closed_owner();
		device.npu_owner = false;
		switch (state) {
		case 0: device.ct_fe.owner_quiesced = false; break;
		case 1: device.ct_fe.pending = true; break;
		case 2: device.ct_fe.arm_pending = true; break;
		case 3: device.ct_fe.armed = true; break;
		case 4: device.ct_fe.active = true; break;
		case 5: device.ct_fe.touched = true; break;
		}
		CHECK(native(-1, 0) == -EAGAIN);
		CHECK(native_sends == 0 && fail_calls == 0);
	}

	reset("completed owner preserves native row retirement on repeated revoke");
	closed_owner();
	device.ct_pairs[0].used = true;
	device.ct_pairs[0].hashes[0] = 0;
	device.ct_pairs[0].rows[0].ib1 = rows[0].ib1 = AIROHA_FOE_IB1_BIND_STATE;
	CHECK(native(-1, 0) == 0);
	CHECK(!device.ct_pairs[0].used && rows[0].ib1 == 0);
	CHECK(native(-1, 0) == 0);
	CHECK(native_writes == 1 && native_sends == 2 && notify_matches == 2);

	reset("internal shutdown skips owner invalidation");
	closed_owner();
	device.ct_host_ppe = false;
	CHECK(native(-1, 0) == 0);
	CHECK(notify_calls == 0 && !device.invalidated && native_sends == 1);

	reset("internal shutdown keeps generic FE guard");
	device.ct_host_ppe = false;
	CHECK(native(-1, 0) == -EAGAIN);
	CHECK(notify_calls == 0 && native_sends == 0);

	reset("endpoint revoke keeps bank0 drain and resume");
	closed_owner();
	device.ct_fe.epoch = 1;
	CHECK(native(0, 1) == 0);
	CHECK(native_sends == 2 && drain_calls == 1 && resume_calls == 1);
}

static void test_netdev(void)
{
	const unsigned long revoke_events[] = {
		NETDEV_GOING_DOWN, NETDEV_DOWN, NETDEV_UNREGISTER,
		NETDEV_PRE_CHANGEADDR, NETDEV_PRECHANGEMTU,
		NETDEV_PRECHANGEUPPER, NETDEV_CHANGE,
	};
	for (unsigned int index = 0; index < sizeof(revoke_events) / sizeof(revoke_events[0]); ++index) {
		reset("PON event reaches owner before LAN1 filter");
		CHECK(airoha_ct_pair_wired_event(&device.ct_pair_wired_notifier,
			revoke_events[index], &pon) == -EAGAIN);
		CHECK(notify_calls == 1 && notify_matches == 1 && last_notify_dev == &pon);
		CHECK(!device.ct_pair_wired_blocked && native_sends == 0 && !ppe_lock);
	}

	reset("LAN1 event passes NULL and keeps block during incomplete close");
	CHECK(airoha_ct_pair_wired_event(&device.ct_pair_wired_notifier,
		NETDEV_CHANGE, &lan) == -EAGAIN);
	CHECK(last_notify_dev == NULL && device.ct_pair_wired_blocked);
	CHECK(notify_matches == 1 && native_sends == 0 && !ppe_lock);

	reset("unrelated netdev does not invalidate owner");
	CHECK(airoha_ct_pair_wired_event(&device.ct_pair_wired_notifier,
		NETDEV_DOWN, &unrelated) == 0);
	CHECK(notify_matches == 0 && !device.invalidated && !device.ct_pair_wired_blocked);

	reset("PON UP does not clear invalidation");
	device.invalidated = true;
	CHECK(airoha_ct_pair_wired_event(&device.ct_pair_wired_notifier,
		NETDEV_UP, &pon) == 0);
	CHECK(notify_calls == 0 && device.invalidated);

	reset("stopped host netdev has no owner callback");
	device.ct_host_ppe = false;
	CHECK(airoha_ct_pair_wired_event(&device.ct_pair_wired_notifier,
		NETDEV_DOWN, &pon) == 0);
	CHECK(notify_calls == 0 && !device.invalidated);

	reset("PON gate failure reaches notifier caller");
	notify_error = -ETIMEDOUT;
	CHECK(airoha_ct_pair_wired_event(&device.ct_pair_wired_notifier,
		NETDEV_PRECHANGEMTU, &pon) == -ETIMEDOUT);
	CHECK(notify_matches == 1 && !ppe_lock);

	reset("original LAN native cleanup remains usable");
	no_owner();
	device.ct_pairs[0].used = true;
	device.ct_pairs[0].msg.src_selector = AIROHA_CT_PAIR_LAN1_SELECTOR;
	device.ct_pairs[0].msg.src_wcid = AIROHA_CT_PAIR_LAN1_ID;
	CHECK(airoha_ct_pair_wired_event(&device.ct_pair_wired_notifier,
		NETDEV_DOWN, &lan) == 0);
	CHECK(native_sends == 1 && !device.ct_pairs[0].used);
	CHECK(device.ct_pair_wired_blocked && device.ct_pair_wired_epoch == 1);
}

int main(void)
{
	test_bridge();
	test_native();
	test_netdev();
	printf("{\"scenarios\":%u,\"checks\":%u}\n", scenarios, checks);
	return 0;
}
