#include "airoha_npu_flow_observe.h"
#include "host_stubs.h"
#include "fixture.inc"

static unsigned char frame[1536];
static struct sk_buff packet;
static struct airoha_queue queue;
static u32 msg0, msg1;
static unsigned frame_bytes;
static unsigned events_taken;

static void setup(const char *name)
{
	struct airoha_npu_ipv4_identity identity;

	begin(name);
	generic_candidate = flow;
	frame_bytes = make_frame(frame, 0, false, false, 8, 5);
	CHECK(!airoha_npu_ingress_parse_ipv4(frame, frame_bytes, 77, &identity));
	flow->data.ipv4.orig_tuple.src_ip = identity.source_ip;
	flow->data.ipv4.orig_tuple.dest_ip = identity.destination_ip;
	flow->data.ipv4.orig_tuple.src_port = identity.source_port;
	flow->data.ipv4.orig_tuple.dest_port = identity.destination_port;
	flow->pon_ingress_seen = false;
	memset(flow->pon_ingress_key, 0, sizeof(flow->pon_ingress_key));
	packet = (struct sk_buff) {
		.dev = &ingress.netdev, .head = frame, .mac = frame,
		.data = frame + ETH_HLEN, .len = frame_bytes - ETH_HLEN, .mac_set = true,
	};
	queue = (struct airoha_queue) { .qdma = &eth.qdma[1], .skb = &packet };
	msg0 = FIELD_PREP(QDMA_ETH_RXMSG_GEM_MASK, 77);
	msg1 = FIELD_PREP(AIROHA_RXD4_FOE_ENTRY, 137) |
		FIELD_PREP(QDMA_ETH_RXMSG_SPORT_MASK, AIROHA_GDM2_IDX) |
		FIELD_PREP(AIROHA_RXD4_PPE_CPU_REASON, PPE_CPU_REASON_HIT_UNBIND_RATE_REACHED);
}

static void dispatch(void)
{
	mutex_unlock(&flow_offload_mutex);
	rx_dispatch(&ingress, &queue, msg0, msg1);
	CHECK(!rcu_depth && !spin_depth && !mutex_depth);
	mutex_lock(&flow_offload_mutex);
	CHECK(flow->hash == 0xffff);
}

static void direct_dispatch(void)
{
	mutex_unlock(&flow_offload_mutex);
	airoha_qdma_pon_unbound_event(&ingress, &queue, &packet, msg0, msg1);
	CHECK(!rcu_depth && !spin_depth && !mutex_depth);
	mutex_lock(&flow_offload_mutex);
	CHECK(flow->hash == 0xffff);
}

static void observe_only(u32 service)
{
	mutex_unlock(&flow_offload_mutex);
	rcu_read_lock();
	airoha_ppe_pon_observe_frame(&ingress, frame, frame_bytes, service);
	rcu_read_unlock();
	mutex_lock(&flow_offload_mutex);
}

static void take_expected(int expected)
{
	struct airoha_pon_unbound_event event, original;
	struct airoha_npu_ipv4_identity identity;
	struct airoha_npu_auth_rule rule;
	unsigned held = holds, released = ref_puts;

	memset(&event, 0xa5, sizeof(event));
	original = event;
	CHECK(airoha_ppe_pon_take_unbound(&ppe, flow->cookie, flow->pon_candidate_serial, &event) == expected);
	CHECK(held == holds && released == ref_puts && mutex_depth == 1 && !spin_depth);
	CHECK(flow->hash == 0xffff);
	if (expected) {
		CHECK(!memcmp(&original, &event, sizeof(event)));
		return;
	}
	events_taken++;
	CHECK(event.serial == flow->pon_candidate_serial && event.generation == generation);
	CHECK(event.hardware_hash == FIELD_GET(AIROHA_RXD4_FOE_ENTRY, msg1));
	CHECK(event.hardware_hash != 0 && event.hardware_hash != flow->hash);
	CHECK(event.service == 77);
	CHECK(!airoha_npu_ingress_parse_ipv4(frame, frame_bytes, 77, &identity));
	CHECK(!airoha_npu_auth_encode_ipv4(&rule, 1, 1, 1, 0, &identity));
	CHECK(!memcmp(event.key, rule.raw + 9, sizeof(event.key)));
	CHECK(!flow->pon_unbound_event.serial);
}

#define GATE(name, change) do { \
	setup(name); observe_only(77); change; direct_dispatch(); \
	CHECK(!flow->pon_unbound_event.serial); finish(); \
} while (0)

static void provenance(void)
{
	struct airoha_npu_ipv4_identity identity;

	for (unsigned encapsulation = 0; encapsulation < 4; encapsulation++) {
		setup("TCP VLAN PPPoE retain original identity");
		frame_bytes = make_frame(frame, encapsulation % 3, encapsulation == 3,
					 true, 8, 5);
		packet.len = frame_bytes - ETH_HLEN;
		CHECK(!airoha_npu_ingress_parse_ipv4(frame, frame_bytes, 77, &identity));
		flow->data.ib1 &= ~AIROHA_FOE_IB1_BIND_UDP;
		dispatch();
		take_expected(0);
		finish();
	}
	setup("trusted descriptor uses actual hardware row");
	dispatch();
	CHECK(flow->pon_unbound_event.serial == 1 && !ppe.ct_pon_qualified);
	take_expected(0);
	take_expected(-EAGAIN);
	finish();

	setup("observer including ER cannot manufacture a row event");
	observe_only(77);
	CHECK(flow->pon_ingress_seen);
	CHECK(!flow->pon_unbound_event.serial);
	take_expected(-EAGAIN);
	finish();

	setup("ordinary LAN path never attaches event");
	observe_only(77);
	ingress.flags = 0;
	ingress_port.id = 1;
	msg1 &= ~QDMA_ETH_RXMSG_SPORT_MASK;
	msg1 |= FIELD_PREP(QDMA_ETH_RXMSG_SPORT_MASK, 0x10);
	dispatch();
	CHECK(!flow->pon_unbound_event.serial && generic_learns);
	finish();

	setup("non UNB RX reason observes identity only");
	msg1 &= ~AIROHA_RXD4_PPE_CPU_REASON;
	dispatch();
	CHECK(flow->pon_ingress_seen && !flow->pon_unbound_event.serial);
	take_expected(-EAGAIN);
	finish();

	GATE("rate reason rechecked", msg1 &= ~AIROHA_RXD4_PPE_CPU_REASON);
	GATE("LAN sport on PON skb", msg1 ^= FIELD_PREP(QDMA_ETH_RXMSG_SPORT_MASK, 3));
	GATE("wrong physical QDMA", queue.qdma = &eth.qdma[0]);
	GATE("wrong attached QDMA", ingress.qdma = &eth.qdma[0]);
	GATE("wrong skb netdev", packet.dev = &egress.netdev);
	GATE("LRO queue", queue.lro = true);
	GATE("GSO packet", packet.gso = true);
	GATE("scattered frame", packet.nonlinear = true);
	GATE("offloaded VLAN", packet.vlan = true);
	GATE("MAC header missing", packet.mac_set = false);
	GATE("MAC data boundary", packet.data++);
	GATE("MAC precedes allocation", packet.head++);
	GATE("invalid hardware row", msg1 |= AIROHA_RXD4_FOE_ENTRY);
	GATE("Bank1 hardware row", msg1 = (msg1 & ~AIROHA_RXD4_FOE_ENTRY) | PPE_SRAM_NUM_ENTRIES);
	GATE("IP descriptor error", msg1 |= QDMA_ETH_RXMSG_IP4F_MASK);
	GATE("L4 descriptor error", msg1 |= QDMA_ETH_RXMSG_L4F_MASK);
	GATE("OAM", msg0 |= QDMA_ETH_RXMSG_OAM_MASK);
	GATE("CRC", msg0 |= QDMA_ETH_RXMSG_CRC_ERR_MASK);
	GATE("runt", msg0 |= QDMA_ETH_RXMSG_RUNT_MASK);
	GATE("long", msg0 |= QDMA_ETH_RXMSG_LONG_MASK);
	GATE("EPON mode", ingress.pon_qdma_tag = AIROHA_PON_QDMA_VALID | AIROHA_PON_QDMA_EPON);
	GATE("EPON table entry", mapping->entries[0].tag |= AIROHA_PON_QDMA_EPON);
	GATE("missing GEM", msg0 = FIELD_PREP(QDMA_ETH_RXMSG_GEM_MASK, 78));
	GATE("invalid mapping", mapping->entries[0].tag &= ~AIROHA_PON_QDMA_VALID);
	GATE("ambiguous GEM", mapping->entries[1] = mapping->entries[0]; mapping->count = 2);
	GATE("no mapping table", ingress.pon_flow_table = NULL);
	GATE("unready update", ingress.pon_update_blocked = true);
	GATE("ingress carrier", ingress.netdev.carrier = false);
	GATE("ingress running", ingress.netdev.running = false);
	GATE("stopping", ppe.ct_stopping = true);
	GATE("host disabled", ppe.ct_host_ppe = false);
	GATE("native pairs disabled", ppe.ct_native_pairs = false);
	GATE("full profile absent", eth.ct_pon_full = false);
	GATE("ordinary profile", eth.ct_ordinary_full_test = true);
	GATE("diagnostic", node.diagnostic = true);
	GATE("fallback", eth.ct_cpu_fallback = true);
	GATE("no controller", ingress.pon_link_ops = NULL);
	GATE("no controller private", ingress.pon_link_priv = NULL);
	GATE("wrong port", ingress_port.id = 1);
	GATE("virtual PON", ingress.nbq = 1);
	GATE("missing candidate", flow->pon_candidate = false);
	GATE("missing serial", flow->pon_candidate_serial = 0);
	GATE("unseen", flow->pon_ingress_seen = false);
	GATE("conflict", flow->pon_ingress_conflict = true);
	GATE("bridge", flow->ct_bridge = true);
	GATE("L2 flow", flow->type = FLOW_TYPE_L2);
	GATE("other ingress", flow->pon_ingress_dev = &alternate);
	GATE("service identity", flow->pon_ingress_service = 78);
	GATE("original tuple", flow->data.ipv4.orig_tuple.src_port++);
	GATE("wrong protocol", flow->data.ib1 ^= AIROHA_FOE_IB1_BIND_UDP);
	GATE("malformed frame", frame[14] = 0x65);
	for (unsigned index = 0; index < 19; index++) {
		GATE("original key word", flow->pon_ingress_key[index] ^= 1);
	}
	setup("bound candidate rejected");
	observe_only(77);
	flow->hash = 137;
	mutex_unlock(&flow_offload_mutex);
	airoha_qdma_pon_unbound_event(&ingress, &queue, &packet, msg0, msg1);
	mutex_lock(&flow_offload_mutex);
	CHECK(flow->hash == 137 && !flow->pon_unbound_event.serial);
	finish();
}

#define STALE(name, change) do { \
	setup(name); dispatch(); CHECK(flow->pon_unbound_event.serial); \
	change; take_expected(-ESTALE); CHECK(!flow->pon_unbound_event.serial); finish(); \
} while (0)

static void consumption(void)
{
	struct airoha_pon_unbound_event event, original, slot;
	u64 old_serial;

	STALE("consume generation", generation++);
	STALE("consume ingress down", ingress.netdev.carrier = false);
	STALE("consume egress down", egress.netdev.carrier = false);
	STALE("consume blocked", ingress.pon_update_blocked = true);
	STALE("consume map removed", mapping->count = 0);
	STALE("consume conflict", flow->pon_ingress_conflict = true);
	STALE("consume unseen", flow->pon_ingress_seen = false);
	STALE("consume profile", eth.ct_pon_full = false);
	STALE("consume stopped", ppe.ct_stopping = true);
	STALE("consume diagnostic", node.diagnostic = true);
	STALE("consume controller", ingress.pon_link_ops = NULL);
	STALE("consume ambiguous map", mapping->entries[1] = mapping->entries[0]; mapping->count = 2);
	STALE("consume event serial", flow->pon_unbound_event.serial++);
	STALE("consume event service", flow->pon_unbound_event.service++);
	STALE("consume event bank", flow->pon_unbound_event.hardware_hash = PPE_SRAM_NUM_ENTRIES);
	for (unsigned index = 0; index < 19; index++) {
		STALE("consume original key", flow->pon_unbound_event.key[index] ^= 1);
	}
	setup("latest descriptor replaces single slot");
	dispatch();
	msg1 = (msg1 & ~AIROHA_RXD4_FOE_ENTRY) | 741;
	dispatch();
	take_expected(0);
	take_expected(-EAGAIN);
	finish();

	setup("cookie recreation rejects old serial and preserves new slot");
	dispatch();
	old_serial = flow->pon_candidate_serial;
	CHECK(!airoha_ppe_ct_remove_pon_flow(&ppe, flow));
	CHECK(!rhashtable_remove_fast(&eth.flow_table, &flow->node, airoha_flow_table_params));
	CHECK(!airoha_ppe_ct_bridge_publish(&eth, flow));
	CHECK(flow->pon_candidate_serial == old_serial + 1 && !flow->pon_unbound_event.serial);
	dispatch();
	CHECK(flow->pon_unbound_event.serial == old_serial + 1);
	slot = flow->pon_unbound_event;
	memset(&event, 0xa5, sizeof(event));
	original = event;
	CHECK(airoha_ppe_pon_take_unbound(&ppe, flow->cookie, old_serial, &event) == -ESTALE);
	CHECK(!memcmp(&event, &original, sizeof(event)));
	CHECK(!memcmp(&slot, &flow->pon_unbound_event, sizeof(slot)));
	take_expected(0);
	finish();

	setup("argument failures preserve slot and output");
	dispatch();
	slot = flow->pon_unbound_event;
	memset(&event, 0xa5, sizeof(event));
	original = event;
	CHECK(airoha_ppe_pon_take_unbound(&ppe, flow->cookie, 0, &event) == -EINVAL);
	CHECK(airoha_ppe_pon_take_unbound(&ppe, flow->cookie + 1, flow->pon_candidate_serial, &event) == -ENOENT);
	CHECK(airoha_ppe_pon_take_unbound(&ppe, flow->cookie, flow->pon_candidate_serial, NULL) == -EINVAL);
	CHECK(!memcmp(&event, &original, sizeof(event)));
	CHECK(!memcmp(&slot, &flow->pon_unbound_event, sizeof(slot)));
	take_expected(0);
	finish();
}

static void revocation(void)
{
	struct flow_cls_offload command;
	struct airoha_pon_unbound_event event = {};
	u64 serial;

	setup("withdraw clears event before cookie removal");
	dispatch();
	CHECK(!airoha_ppe_ct_remove_pon_flow(&ppe, flow));
	CHECK(!flow->pon_unbound_event.serial && !flow->pon_ingress_seen && !flow->list.pprev);
	take_expected(-ESTALE);
	finish();

	setup("destroy cannot leave deferred entry pointer");
	dispatch();
	command.cookie = flow->cookie;
	serial = flow->pon_candidate_serial;
	CHECK(!airoha_ppe_flow_offload_destroy(&eth, &command));
	flow = NULL;
	CHECK(airoha_ppe_pon_take_unbound(&ppe, command.cookie, serial, &event) == -ENOENT);
	finish();

	setup("GEM conflict clears existing event");
	dispatch();
	observe_only(78);
	CHECK(flow->pon_ingress_conflict && !flow->pon_ingress_seen && !flow->pon_unbound_event.serial);
	dispatch();
	CHECK(!flow->pon_unbound_event.serial);
	finish();

	setup("ER original identity conflict clears event");
	dispatch();
	frame[1] ^= 1;
	observe_only(77);
	CHECK(flow->pon_ingress_conflict && !flow->pon_unbound_event.serial);
	finish();

	setup("Bank0 retirement clears slot for software unbound candidate");
	dispatch();
	spin_lock_bh(&ppe_lock);
	airoha_ppe_bank_detach_entry(flow, 1);
	CHECK(flow->pon_unbound_event.serial);
	airoha_ppe_bank_detach_entry(flow, 0);
	spin_unlock_bh(&ppe_lock);
	CHECK(!flow->pon_unbound_event.serial && flow->hash == 0xffff);
	take_expected(-EAGAIN);
	finish();

	setup("retire STATE and timestamp preserve event identity");
	dispatch();
	flow->data.ib1 &= ~AIROHA_FOE_IB1_BIND_STATE;
	flow->data.ib1 ^= AIROHA_FOE_IB1_BIND_TIMESTAMP;
	take_expected(0);
	finish();
}

int main(int argc, char **argv)
{
	if (argc == 2) {
		struct airoha_pon_unbound_event event;

		setup("required event lock");
		dispatch();
		mutex_unlock(&flow_offload_mutex);
		if (!strcmp(argv[1], "take-unlocked"))
			airoha_ppe_pon_take_unbound(&ppe, flow->cookie, flow->pon_candidate_serial, &event);
		else
			airoha_ppe_pon_observe_unbound(&ingress, frame, frame_bytes, 137, 77);
		return 0;
	}
	provenance();
	consumption();
	revocation();
	printf("{\"passed\":true,\"cases\":%u,\"checks\":%u,\"events_taken\":%u,\"holds\":%u,\"puts\":%u,\"generic_learns\":%u}\n",
	       cases, checks, events_taken, holds, ref_puts, generic_learns);
	return 0;
}
