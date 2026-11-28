#include "host_stubs.h"
#include "airoha_eth_return.c"

#define main er_baseline_main
#define eth_type_trans fixture_eth_type_trans
#define napi_alloc_skb fixture_napi_alloc_skb
#include "consumer_fixture.inc"
#undef main
#undef eth_type_trans
#undef napi_alloc_skb

#include "airoha_npu_flow_observe.h"

#define smp_load_acquire(pointer) (*(pointer))
#define test_bit(bit, pointer) (!!(*(pointer) & (1ul << (bit))))
#define rcu_dereference(pointer) (assert(host.rcu_depth == 1), (pointer))
#define FIELD_GET(mask, value) ((value) & (mask))
#define AIROHA_DEV_F_PON 0
#define AIROHA_PON_QDMA_VALID (1u << 31)
#define AIROHA_PON_QDMA_EPON (1u << 30)
#define AIROHA_PON_QDMA_GEM_MASK 0xffffu
#define NPU_TXN_OPEN 16

struct device_node { bool diagnostic; };
struct config_device { struct device_node *of_node; };
struct work_struct { int unused; };
struct delayed_work { struct work_struct work; };
struct airoha_qdma { int unused; };
struct airoha_pon_flow_table { unsigned count; struct { u32 tag; } entries[2]; };
struct airoha_bank1_routes {
	const void *owner;
	bool ready, pon_open, revoked, ingress_ready;
};
struct airoha_eth {
	struct config_device *dev;
	struct airoha_qdma qdma[2];
	bool ct_pon_full, ct_ordinary_full_test, ct_cpu_fallback;
	struct airoha_bank1_routes ct_bank1_routes;
};
struct airoha_ppe { struct airoha_eth *eth; bool ct_pon_qualified, ct_stopping; };
struct airoha_npu_owner {
	struct airoha_ppe *ppe;
	bool invalidated, retiring, close_pending;
	struct net_device *diag_lower;
	struct { int phase; } txn;
};
struct airoha_gdm_dev {
	struct net_device *netdev;
	unsigned long flags;
	bool pon_update_blocked;
	struct airoha_qdma *qdma;
	struct airoha_pon_flow_table *pon_flow_table;
	u32 pon_qdma_tag;
};

static spinlock_t ppe_lock;
static struct device_node node;
static struct config_device config_dev = { &node };
static struct airoha_eth eth;
static struct airoha_ppe ppe;
static struct airoha_npu_owner owner;
static struct airoha_gdm_dev dev;
static struct airoha_pon_flow_table table, replacement;
static bool running, carrier, observing;
static u32 generation;
static unsigned calls, callbacks, conversions, invalidations, owner_cases;
static void (*allocation_transition)(void);
static struct sk_buff *active_skb;
static u8 expected_frame[ER_BUFFER];
static u32 expected_bytes, expected_service;
static struct airoha_npu_ipv4_identity expected_identity;

static struct net_device *netdev_from_priv(struct airoha_gdm_dev *target) { return target->netdev; }
static bool netif_running(struct net_device *target) { CHECK(target); return running; }
static bool netif_carrier_ok(struct net_device *target) { CHECK(target); return carrier; }
static u32 br_flow_offload_generation(void) { return generation; }
static bool of_property_read_bool(struct device_node *target, const char *name)
{
	CHECK(target == &node && !strcmp(name, "airoha,connac2-pon-er-diagnostic"));
	return target->diagnostic;
}
static int airoha_npu_owner_invalidate(struct airoha_ppe *target)
{
	CHECK(target == &ppe && ppe_lock.held);
	owner.invalidated = true;
	++invalidations;
	return 0;
}
static void airoha_ppe_pon_observe_frame(struct airoha_gdm_dev *target,
					const unsigned char *frame, u32 bytes, u32 service)
{
	struct airoha_npu_ipv4_identity actual;

	CHECK(target == &dev && host.rcu_depth == 1 && !ppe_lock.held);
	CHECK(active_skb && active_skb->data == active_skb->head + NET_IP_ALIGN);
	CHECK(active_skb->len == bytes && active_skb->protocol == 0);
	CHECK(bytes == expected_bytes && service == expected_service);
	CHECK(!memcmp(frame, expected_frame, bytes));
	CHECK(!memcmp(active_skb->data, expected_frame, bytes));
	CHECK(!airoha_npu_ingress_parse_ipv4(frame, bytes, service, &actual));
	CHECK(!memcmp(&actual, &expected_identity, sizeof(actual)));
	++calls;
}

#include "owner.inc"
static struct airoha_npu_return path;

struct sk_buff *napi_alloc_skb(struct napi_struct *napi, unsigned int bytes)
{
	struct sk_buff *skb = fixture_napi_alloc_skb(napi, bytes);

	if (observing) {
		active_skb = skb;
		if (allocation_transition)
			allocation_transition();
	}
	return skb;
}

u16 eth_type_trans(struct sk_buff *skb, struct net_device *lower)
{
	if (observing) {
		CHECK(skb == active_skb && host.rcu_depth == 1);
		++conversions;
	}
	return fixture_eth_type_trans(skb, lower);
}

static bool owner_binding(void *ctx, struct net_device *lower,
			   const struct er_config *config, u32 service)
{
	struct fixture *fixture = ctx;

	CHECK(host.rcu_depth == 1 && fixture->ring->lower == lower);
	return airoha_npu_return_binding(&path, lower, config, service);
}

static void observe(void *ctx, struct net_device *lower, const struct er_config *config,
		     u32 service, const unsigned char *frame, u32 bytes)
{
	struct fixture *fixture = ctx;

	CHECK(host.rcu_depth == 1 && fixture->ring->lower == lower);
	CHECK(active_skb && active_skb->len == bytes && conversions == 0);
	++callbacks;
	airoha_npu_return_observe(&path, lower, config, service, frame, bytes);
}

static void prepare(struct fixture *fixture, u32 service)
{
	begin("ER authorized production observation");
	setup(fixture, ER_PON);
	memset(&eth, 0, sizeof(eth));
	memset(&ppe, 0, sizeof(ppe));
	memset(&owner, 0, sizeof(owner));
	memset(&dev, 0, sizeof(dev));
	memset(&path, 0, sizeof(path));
	memset(&table, 0, sizeof(table));
	node.diagnostic = false;
	eth.dev = &config_dev;
	eth.ct_pon_full = true;
	ppe.eth = &eth;
	ppe.ct_pon_qualified = false;
	owner.ppe = &ppe;
	owner.txn.phase = NPU_TXN_OPEN;
	eth.ct_bank1_routes = (struct airoha_bank1_routes) { &owner, true, true, false, true };
	dev.netdev = &fixture->lower;
	dev.flags = 1ul << AIROHA_DEV_F_PON;
	dev.qdma = &eth.qdma[1];
	dev.pon_flow_table = &table;
	table.count = 1;
	table.entries[0].tag = AIROHA_PON_QDMA_VALID | service;
	path.owner = &owner;
	path.dev = &dev;
	path.config = fixture->ring->config;
	path.table = &table;
	path.bound = true;
	path.generation = generation = fixture->ring->config.generation;
	running = carrier = observing = true;
	fixture->ops.binding_matches = owner_binding;
	fixture->ops.observe = observe;
	fixture->live_service = ER_SERVICE_VALID | service;
	calls = callbacks = conversions = invalidations = 0;
	allocation_transition = NULL;
	active_skb = NULL;
	++owner_cases;
}

static void put16(u8 *bytes, u32 value) { bytes[0] = value >> 8; bytes[1] = value; }
static void put32(u8 *bytes, u32 value) { put16(bytes, value >> 16); put16(bytes + 2, value); }

static void frame(struct fixture *fixture, bool tagged)
{
	u32 offset = tagged ? 30 : 14;
	u32 size = offset + 20 + 8 + 256;
	u8 *payload = expected_frame;

	memset(payload, 0, sizeof(expected_frame));
	memcpy(payload, "\x02\x11\x22\x33\x44\x55\x82\x66\x77\x88\x99\xaa", 12);
	if (tagged) {
		put32(payload + 12, 0x88a8f123);
		put32(payload + 16, 0x8100b456);
		put16(payload + 20, 0x8864);
		payload[22] = 0x11;
		put16(payload + 24, 0xbeef);
		put16(payload + 26, size - 28);
		put16(payload + 28, 0x21);
	} else {
		put16(payload + 12, 0x0800);
	}
	payload[offset] = 0x45;
	put16(payload + offset + 2, size - offset);
	payload[offset + 9] = 17;
	put32(payload + offset + 12, 0xc0000201);
	put32(payload + offset + 16, 0xc6336402);
	put16(payload + offset + 20, 0x1234);
	put16(payload + offset + 22, 0xabcd);
	put16(payload + offset + 24, size - offset - 20);
	for (u32 index = offset + 28; index < size; ++index)
		payload[index] = index;
	expected_bytes = size;
	expected_service = fixture->live_service & 0xffff;
	CHECK(!airoha_npu_ingress_parse_ipv4(payload, size, expected_service, &expected_identity));
	publish(fixture, 1, size, fixture->live_service);
	memcpy(payload_for(fixture->ring, 1), payload, size);
}

static void finish(struct fixture *fixture, bool faulted)
{
	CHECK(!host.rcu_depth && !ppe_lock.held);
	observing = false;
	active_skb = NULL;
	if (faulted)
		reset_release(fixture);
	else
		destroy(fixture);
}

static void positives(void)
{
	for (unsigned variant = 0; variant < 8; ++variant) {
		struct fixture fixture;

		prepare(&fixture, variant & 2 ? 0xffff : 0);
		ppe.ct_pon_qualified = !!(variant & 4);
		frame(&fixture, variant & 1);
		CHECK(poll_ring(&fixture, 8) == 1);
		CHECK(calls == 1 && callbacks == 1 && conversions == 1);
		CHECK(fixture.ring->packets == 1 && !fixture.ring->dropped);
		CHECK(!memcmp(host.deliveries[0].payload, expected_frame, expected_bytes));
		CHECK(poll_ring(&fixture, 8) == 0 && calls == 1);
		finish(&fixture, false);
	}
}

static void binding_failures(void)
{
	for (unsigned variant = 0; variant < 17; ++variant) {
		struct fixture fixture;

		prepare(&fixture, 0x1234);
		frame(&fixture, true);
		switch (variant) {
		case 0: path.bound = false; break;
		case 1: path.fault = 1; break;
		case 2: eth.ct_cpu_fallback = true; break;
		case 3: path.config.epoch++; break;
		case 4: owner.invalidated = true; break;
		case 5: dev.netdev = &fixture.replacement; break;
		case 6: dev.flags = 0; break;
		case 7: dev.pon_update_blocked = true; break;
		case 8: running = false; break;
		case 9: carrier = false; break;
		case 10: dev.qdma = &eth.qdma[0]; break;
		case 11: dev.pon_flow_table = &replacement; break;
		case 12: dev.pon_qdma_tag = 1; break;
		case 13: generation++; break;
		case 14: table.entries[0].tag ^= 1; break;
		case 15: table.entries[0].tag |= AIROHA_PON_QDMA_EPON; break;
		case 16: table.count = 0; break;
		}
		CHECK(poll_ring(&fixture, 8) == 1);
		CHECK(!calls && !callbacks && !conversions && !host.skb_attempts);
		CHECK(fixture.ring->dropped == 1);
		finish(&fixture, false);
	}
}

static void closed_or_diagnostic(void)
{
	for (unsigned variant = 0; variant < 14; ++variant) {
		struct fixture fixture;

		prepare(&fixture, 0x1234);
		frame(&fixture, true);
		switch (variant) {
		case 0: eth.ct_pon_full = false; break;
		case 1: eth.ct_ordinary_full_test = true; break;
		case 2: owner.diag_lower = &fixture.lower; break;
		case 3: node.diagnostic = true; break;
		case 4: ppe.ct_stopping = true; break;
		case 5: path.stopping = true; break;
		case 6: owner.retiring = true; break;
		case 7: owner.close_pending = true; break;
		case 8: owner.txn.phase = 0; break;
		case 9: eth.ct_bank1_routes.owner = NULL; break;
		case 10: eth.ct_bank1_routes.ready = false; break;
		case 11: eth.ct_bank1_routes.pon_open = false; break;
		case 12: eth.ct_bank1_routes.revoked = true; break;
		case 13: eth.ct_bank1_routes.ingress_ready = false; break;
		}
		CHECK(poll_ring(&fixture, 8) == 1);
		CHECK(!calls && callbacks == 1 && conversions == 1);
		finish(&fixture, false);
	}
}

static void changed_service(void) { table.entries[0].tag ^= 1; }
static void changed_mapping(void) { dev.pon_flow_table = &replacement; }
static void closed_route(void) { eth.ct_bank1_routes.pon_open = false; }

static void allocation_and_optional(void)
{
	for (unsigned variant = 0; variant < 5; ++variant) {
		struct fixture fixture;

		prepare(&fixture, 0x1234);
		frame(&fixture, true);
		if (!variant)
			host.fail_skb = true;
		else if (variant == 1)
			fixture.ops.observe = NULL;
		else
			allocation_transition = variant == 2 ? changed_service :
				variant == 3 ? changed_mapping : closed_route;
		CHECK(poll_ring(&fixture, 8) == 1);
		CHECK(!calls && callbacks == (variant > 1) && conversions == !!variant);
		finish(&fixture, false);
	}
}

static void descriptors(void)
{
	for (unsigned variant = 0; variant < 16; ++variant) {
		struct fixture fixture;
		__le32 *descriptor;

		prepare(&fixture, 0x1234);
		frame(&fixture, true);
		descriptor = slot_for(fixture.ring, 1);
		switch (variant) {
		case 0: descriptor[0] &= cpu_to_le32(~ER_DONE); break;
		case 1: descriptor[0] |= cpu_to_le32(1u << 20); break;
		case 2: descriptor[1] ^= cpu_to_le32(1); break;
		case 3: descriptor[2] ^= cpu_to_le32(1); break;
		case 4: descriptor[3] ^= cpu_to_le32(1); break;
		case 5: descriptor[4] ^= cpu_to_le32(1); break;
		case 6: descriptor[5] ^= cpu_to_le32(ER_SERVICE_VALID); break;
		case 7: descriptor[5] ^= cpu_to_le32(1); break;
		case 8: descriptor[6] ^= cpu_to_le32(1); break;
		case 9: descriptor[7] ^= cpu_to_le32(1); break;
		case 10: descriptor[8] ^= cpu_to_le32(1); break;
		case 11: descriptor[10] ^= cpu_to_le32(1); break;
		case 12: descriptor[13] = 0; break;
		case 13: descriptor[14] ^= cpu_to_le32(1); break;
		case 14: descriptor[5] |= cpu_to_le32(1u << 16); break;
		case 15: descriptor[9] ^= cpu_to_le32(1); break;
		}
		CHECK(poll_ring(&fixture, 8) == 0);
		CHECK(!calls && !callbacks && !conversions && !host.skb_attempts);
		CHECK(fixture.ring->protocol_error);
		finish(&fixture, true);
	}
}

int main(void)
{
	CHECK(er_baseline_main() == 0);
	positives();
	binding_failures();
	closed_or_diagnostic();
	allocation_and_optional();
	descriptors();
	printf("PASS %u ER owner observation cases: full frame, service, RCU, ordering, revalidation and optional ops\n", owner_cases);
	return 0;
}
