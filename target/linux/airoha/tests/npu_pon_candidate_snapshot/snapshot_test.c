#include "host_stubs.h"

static struct airoha_eth eth;
static struct airoha_ppe ppe;
static struct airoha_gdm_dev ingress, egress, alternate;
static struct port ingress_port = { .id = AIROHA_GDM2_IDX };
static struct device_node node;
static struct device device = { .of_node = &node };
static struct hlist_head bucket;
static struct airoha_pon_flow_table *mapping;
static struct airoha_flow_table_entry *flow;
static struct airoha_pon_candidate_snapshot saved;

static void init_flow(struct airoha_flow_table_entry *entry)
{
	memset(entry, 0, sizeof(*entry));
	entry->cookie = 0x12345678;
	entry->egress_dev = &egress;
	entry->pon_ingress_dev = &ingress;
	entry->pon_candidate = true;
	entry->pon_ingress_seen = true;
	entry->pon_ingress_service = 77;
	for (unsigned index = 0; index < 19; index++)
		entry->pon_ingress_key[index] = 0x10203040 + index;
	entry->data.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND) |
		FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE, PPE_PKT_TYPE_IPV4_HNAPT) |
		AIROHA_FOE_IB1_BIND_UDP | AIROHA_FOE_IB1_BIND_TTL;
	entry->data.ipv4.orig_tuple.src_ip = 0x0a000001;
	entry->data.ipv4.orig_tuple.dest_ip = 0xc0000201;
	entry->data.ipv4.orig_tuple.src_port = 12000;
	entry->data.ipv4.orig_tuple.dest_port = 4500;
	entry->data.ipv4.new_tuple.src_ip = 0xc6336402;
	entry->data.ipv4.new_tuple.dest_ip = 0xc0000201;
	entry->data.ipv4.new_tuple.src_port = 40000;
	entry->data.ipv4.new_tuple.dest_port = 4500;
	entry->data.ipv4.ib2 = 0x123456;
	entry->data.ipv4.data = 0x3456;
	entry->data.ipv4.l2.common.vlan1 = 300;
	entry->data.ipv4.l2.common.dest_mac_hi = 0x00112233;
	entry->data.ipv4.l2.pppoe_id = 11;
}

static void begin(const char *name)
{
	test_case = name;
	cases++;
	CHECK(!mutex_depth && !spin_depth && holds == ref_puts);
	memset(&eth, 0, sizeof(eth));
	memset(&ppe, 0, sizeof(ppe));
	memset(&saved, 0, sizeof(saved));
	memset(&node, 0, sizeof(node));
	bucket.first = NULL;
	generation = 9;
	insert_error = 0;
	before_spin = NULL;
	ingress_port.id = AIROHA_GDM2_IDX;
	eth.ppe = &ppe;
	eth.dev = &device;
	eth.ct_pon_full = true;
	ppe.eth = &eth;
	ppe.ct_host_ppe = true;
	ppe.ct_native_pairs = true;
	ppe.foe_flow = &bucket;
	mapping = calloc(1, sizeof(*mapping) + 3 * sizeof(mapping->entries[0]));
	CHECK(mapping);
	mapping->count = 1;
	mapping->entries[0].tag = AIROHA_PON_QDMA_VALID | (3u << 16) | 77;
	mapping->entries[0].vlan_id = 100;
	mapping->entries[0].pbit_mask = 0xff;
	ingress = (struct airoha_gdm_dev){
		.eth = &eth, .netdev = { .running = true, .carrier = true, .refs = 1 },
		.port = &ingress_port, .flags = BIT(AIROHA_DEV_F_PON), .valid = true,
		.qdma = &eth.qdma[1], .pon_flow_table = mapping,
		.pon_link_ops = &eth, .pon_link_priv = &eth,
	};
	egress = ingress;
	egress.flags = 0;
	alternate = egress;
	flow = calloc(1, sizeof(*flow));
	CHECK(flow);
	init_flow(flow);
	mutex_lock(&flow_offload_mutex);
	CHECK(!airoha_ppe_ct_bridge_publish(&eth, flow));
	CHECK(flow->pon_candidate_serial == 1 && ppe.pon_candidate_serial == 1);
}

static void finish(void)
{
	mutex_unlock(&flow_offload_mutex);
	airoha_ppe_pon_candidate_put(&saved);
	CHECK(ingress.netdev.refs == 1 && egress.netdev.refs == 1 && alternate.netdev.refs == 1);
	CHECK(holds == ref_puts && !spin_depth && !mutex_depth);
	free(flow);
	free(mapping);
}

static void capture(void)
{
	CHECK(!airoha_ppe_pon_candidate_snapshot(&ppe, flow->cookie, &saved));
	CHECK(saved.serial == flow->pon_candidate_serial && saved.generation == generation);
	CHECK(saved.cookie == flow->cookie && saved.service == 77);
	CHECK(!memcmp(saved.key, flow->pon_ingress_key, sizeof(saved.key)));
	CHECK(!memcmp(&saved.data, &flow->data, sizeof(saved.data)));
	CHECK(saved.mapping.tag == mapping->entries[0].tag);
	CHECK(saved.mapping.vlan_id == 100 && saved.mapping.pbit_mask == 0xff);
	CHECK(saved.ingress == &ingress.netdev && saved.egress == &egress.netdev);
	CHECK(ingress.netdev.refs == 2 && egress.netdev.refs == 2);
}

static void rejected(void)
{
	struct airoha_pon_candidate_snapshot output, original;
	unsigned held = holds, released = ref_puts;

	memset(&output, 0xa5, sizeof(output));
	output.serial = 0;
	output.ingress = output.egress = NULL;
	memcpy(&original, &output, sizeof(output));
	CHECK(airoha_ppe_pon_candidate_snapshot(&ppe, flow->cookie, &output) == -ESTALE);
	CHECK(!memcmp(&output, &original, sizeof(output)));
	CHECK(airoha_ppe_pon_candidate_validate(&ppe, &saved) == -ESTALE);
	CHECK(holds == held && ref_puts == released && !spin_depth && mutex_depth == 1);
}

#define REJECT(name, change) do { begin(name); capture(); change; rejected(); finish(); } while (0)
#define CHANGED(name, change) do { \
	begin(name); capture(); change; \
	CHECK(airoha_ppe_pon_candidate_validate(&ppe, &saved) == -ESTALE); \
	finish(); \
} while (0)

static void conflict_at_lock(void)
{
	flow->pon_ingress_conflict = true;
}

static void gates(void)
{
	REJECT("unseen", flow->pon_ingress_seen = false);
	REJECT("conflict", flow->pon_ingress_conflict = true);
	REJECT("not candidate", flow->pon_candidate = false);
	REJECT("zero serial", flow->pon_candidate_serial = 0);
	REJECT("bound row", flow->hash = 3);
	REJECT("bridge", flow->ct_bridge = true);
	REJECT("L2", flow->type = FLOW_TYPE_L2);
	REJECT("IPv6 deferred", flow->data.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE, PPE_PKT_TYPE_IPV6_ROUTE_5T));
	REJECT("service overflow", flow->pon_ingress_service = 0x1004d);
	REJECT("stopping", ppe.ct_stopping = true);
	REJECT("host disabled", ppe.ct_host_ppe = false);
	REJECT("native pairs disabled", ppe.ct_native_pairs = false);
	REJECT("profile disabled", eth.ct_pon_full = false);
	REJECT("ordinary profile", eth.ct_ordinary_full_test = true);
	REJECT("CPU fallback", eth.ct_cpu_fallback = true);
	REJECT("diagnostic", node.diagnostic = true);
	REJECT("missing ingress", flow->pon_ingress_dev = NULL);
	REJECT("missing egress", flow->egress_dev = NULL);
	REJECT("unregistered ingress", ingress.valid = false);
	REJECT("unregistered egress", egress.valid = false);
	REJECT("different controller", egress.eth = NULL);
	REJECT("ingress non PON", ingress.flags = 0);
	REJECT("PON egress", egress.flags = BIT(AIROHA_DEV_F_PON));
	REJECT("wrong port", ingress_port.id = 1);
	REJECT("virtual queue", ingress.nbq = 1);
	REJECT("missing link ops", ingress.pon_link_ops = NULL);
	REJECT("missing link private", ingress.pon_link_priv = NULL);
	REJECT("wrong QDMA", ingress.qdma = &eth.qdma[0]);
	REJECT("ingress update", ingress.pon_update_blocked = true);
	REJECT("egress update", egress.pon_update_blocked = true);
	REJECT("ingress carrier", ingress.netdev.carrier = false);
	REJECT("egress carrier", egress.netdev.carrier = false);
	REJECT("ingress stopped", ingress.netdev.running = false);
	REJECT("egress stopped", egress.netdev.running = false);
	REJECT("namespace", egress.netdev.netns = 1);
	REJECT("no table", ingress.pon_flow_table = NULL);
	REJECT("empty table", mapping->count = 0);
	REJECT("invalid map", mapping->entries[0].tag &= ~AIROHA_PON_QDMA_VALID);
	REJECT("EPON deferred", mapping->entries[0].tag |= AIROHA_PON_QDMA_EPON);
	REJECT("GEM removed", mapping->entries[0].tag++);
	REJECT("ambiguous GEM", mapping->entries[1] = mapping->entries[0]; mapping->count = 2);
	CHANGED("generation", generation++);
	CHANGED("TCONT", mapping->entries[0].tag ^= BIT(16));
	CHANGED("tag pbit", mapping->entries[0].tag ^= BIT(21));
	CHANGED("mapping VLAN", mapping->entries[0].vlan_id++);
	CHANGED("mapping pbit mask", mapping->entries[0].pbit_mask ^= 1);
	CHANGED("device identity", flow->egress_dev = &alternate);
	CHANGED("service identity", flow->pon_ingress_service++; mapping->entries[0].tag++);
	for (unsigned index = 0; index < 19; index++) {
		CHANGED("19 word identity", flow->pon_ingress_key[index] ^= 1);
	}
}

static void actions(void)
{
	const u32 masks[] = { AIROHA_FOE_IB1_BIND_UDP, AIROHA_FOE_IB1_BIND_STATIC,
		AIROHA_FOE_IB1_BIND_TTL, AIROHA_FOE_IB1_BIND_TUNNEL_DECAP,
		AIROHA_FOE_IB1_BIND_PPPOE, AIROHA_FOE_IB1_BIND_VPM, AIROHA_FOE_IB1_BIND_VLAN_LAYER };

	for (unsigned index = 0; index < sizeof(masks) / sizeof(masks[0]); index++) {
		CHANGED("ib1 action", flow->data.ib1 ^= masks[index]);
	}
	CHANGED("original source IP", flow->data.ipv4.orig_tuple.src_ip++);
	CHANGED("original destination IP", flow->data.ipv4.orig_tuple.dest_ip++);
	CHANGED("original source port", flow->data.ipv4.orig_tuple.src_port++);
	CHANGED("original destination port", flow->data.ipv4.orig_tuple.dest_port++);
	CHANGED("NAT source IP", flow->data.ipv4.new_tuple.src_ip++);
	CHANGED("NAT destination IP", flow->data.ipv4.new_tuple.dest_ip++);
	CHANGED("NAT source port", flow->data.ipv4.new_tuple.src_port++);
	CHANGED("NAT destination port", flow->data.ipv4.new_tuple.dest_port++);
	CHANGED("FOE ib2", flow->data.ipv4.ib2 ^= 1);
	CHANGED("FOE data", flow->data.ipv4.data ^= 1);
	for (unsigned index = 0; index < sizeof(flow->data.ipv4.l2); index++) {
		CHANGED("MAC VLAN PPPoE meter", ((u8 *)&flow->data.ipv4.l2)[index] ^= 1);
	}
	begin("retire state timestamp preserves NAT");
	capture();
	flow->data.ib1 &= ~AIROHA_FOE_IB1_BIND_STATE;
	flow->data.ib1 ^= AIROHA_FOE_IB1_BIND_TIMESTAMP;
	CHECK(!airoha_ppe_pon_candidate_validate(&ppe, &saved));
	flow->data.ipv4.new_tuple.src_port++;
	CHECK(airoha_ppe_pon_candidate_validate(&ppe, &saved) == -ESTALE);
	finish();
}

static void publication(void)
{
	struct airoha_flow_table_entry second;
	struct flow_cls_offload command;
	struct airoha_pon_candidate_snapshot missing = {}, before;
	unsigned old_lookups;

	begin("delete frees entry while snapshot owns devices");
	capture();
	command.cookie = flow->cookie;
	CHECK(!airoha_ppe_flow_offload_destroy(&eth, &command));
	flow = NULL;
	CHECK(!bucket.first);
	CHECK(airoha_ppe_pon_candidate_validate(&ppe, &saved) == -ENOENT);
	CHECK(airoha_ppe_pon_candidate_snapshot(&ppe, command.cookie, &missing) == -ENOENT);
	CHECK(!missing.serial && !missing.ingress && ingress.netdev.refs == 2);
	finish();

	begin("same cookie same address rebuilt ABA");
	capture();
	CHECK(!airoha_ppe_ct_remove_pon_flow(&ppe, flow));
	CHECK(!rhashtable_remove_fast(&eth.flow_table, &flow->node, airoha_flow_table_params));
	init_flow(flow);
	CHECK(!airoha_ppe_ct_bridge_publish(&eth, flow));
	CHECK(flow->pon_candidate_serial == 2 && saved.serial == 1);
	old_lookups = lookups;
	CHECK(airoha_ppe_pon_candidate_validate(&ppe, &saved) == -ESTALE);
	CHECK(lookups == old_lookups + 1);
	airoha_ppe_pon_candidate_put(&saved);
	capture();
	CHECK(!airoha_ppe_pon_candidate_validate(&ppe, &saved));
	finish();

	begin("overflow rejects cookie and never wraps");
	ppe.pon_candidate_serial = U64_MAX - 1;
	init_flow(&second);
	second.cookie++;
	second.data.ipv4.orig_tuple.src_ip++;
	CHECK(!airoha_ppe_ct_bridge_publish(&eth, &second));
	CHECK(second.pon_candidate_serial == U64_MAX && ppe.pon_candidate_serial == U64_MAX);
	CHECK(!airoha_ppe_ct_remove_pon_flow(&ppe, &second));
	CHECK(!rhashtable_remove_fast(&eth.flow_table, &second.node, airoha_flow_table_params));
	init_flow(&second);
	second.cookie++;
	second.data.ipv4.orig_tuple.src_ip++;
	for (unsigned attempt = 0; attempt < 2; attempt++) {
		CHECK(airoha_ppe_ct_bridge_publish(&eth, &second) == -EOVERFLOW);
		CHECK(ppe.pon_candidate_serial == U64_MAX && !second.pon_candidate_serial);
		CHECK(!rhashtable_lookup_fast(&eth.flow_table, &second.cookie, airoha_flow_table_params));
		CHECK(!second.list.pprev && bucket.first == &flow->list);
	}
	second.pon_candidate = false;
	second.pon_ingress_dev = NULL;
	CHECK(!airoha_ppe_ct_bridge_publish(&eth, &second));
	CHECK(ppe.pon_candidate_serial == U64_MAX && !second.pon_candidate_serial);
	CHECK(!airoha_ppe_ct_remove_pon_flow(&ppe, &second));
	CHECK(!rhashtable_remove_fast(&eth.flow_table, &second.node, airoha_flow_table_params));
	finish();

	begin("duplicate tuple rolls back cookie without serial");
	init_flow(&second);
	second.cookie++;
	CHECK(airoha_ppe_ct_bridge_publish(&eth, &second) == -EEXIST);
	CHECK(!rhashtable_lookup_fast(&eth.flow_table, &second.cookie, airoha_flow_table_params));
	CHECK(ppe.pon_candidate_serial == 1 && !second.pon_candidate_serial && !second.list.pprev);
	finish();

	begin("cookie allocation failure consumes no serial");
	init_flow(&second);
	second.cookie++;
	insert_error = -ENOMEM;
	CHECK(airoha_ppe_ct_bridge_publish(&eth, &second) == -ENOMEM);
	CHECK(!second.pon_candidate_serial && ppe.pon_candidate_serial == 1 && !second.list.pprev);
	finish();

	begin("failure between lookup and spin lock");
	before = missing;
	before_spin = conflict_at_lock;
	CHECK(airoha_ppe_pon_candidate_snapshot(&ppe, flow->cookie, &missing) == -ESTALE);
	CHECK(!memcmp(&before, &missing, sizeof(before)));
	flow->pon_ingress_conflict = false;
	capture();
	before_spin = conflict_at_lock;
	CHECK(airoha_ppe_pon_candidate_validate(&ppe, &saved) == -ESTALE);
	finish();
}

static void ownership(void)
{
	struct airoha_pon_candidate_snapshot original, zero = {};
	struct airoha_pon_flow_table *replacement;
	unsigned old_holds, old_puts;

	begin("qualified false is eligible and put is idempotent");
	CHECK(!ppe.ct_pon_qualified);
	capture();
	memcpy(&original, &saved, sizeof(saved));
	old_holds = holds;
	old_puts = ref_puts;
	CHECK(airoha_ppe_pon_candidate_snapshot(&ppe, flow->cookie, &saved) == -EINVAL);
	CHECK(!memcmp(&original, &saved, sizeof(saved)) && old_holds == holds);
	CHECK(!airoha_ppe_pon_candidate_validate(&ppe, &saved));
	CHECK(old_holds == holds && old_puts == ref_puts);
	airoha_ppe_pon_candidate_put(&saved);
	CHECK(!memcmp(&saved, &zero, sizeof(saved)));
	CHECK(airoha_ppe_pon_candidate_validate(&ppe, &saved) == -EINVAL);
	airoha_ppe_pon_candidate_put(&saved);
	airoha_ppe_pon_candidate_put(NULL);
	CHECK(ref_puts == old_puts + 2);
	CHECK(airoha_ppe_pon_candidate_snapshot(&ppe, flow->cookie, NULL) == -EINVAL);
	CHECK(airoha_ppe_pon_candidate_validate(&ppe, NULL) == -EINVAL);
	finish();

	begin("current table has target after unrelated and EPON entries");
	mapping->entries[2] = mapping->entries[0];
	mapping->entries[0].tag++;
	mapping->entries[1] = mapping->entries[2];
	mapping->entries[1].tag |= AIROHA_PON_QDMA_EPON;
	mapping->count = 3;
	CHECK(!airoha_ppe_pon_candidate_snapshot(&ppe, flow->cookie, &saved));
	CHECK(saved.mapping.tag == mapping->entries[2].tag);
	CHECK(!airoha_ppe_pon_candidate_validate(&ppe, &saved));
	finish();

	begin("table replaced and freed snapshot contains values");
	capture();
	replacement = calloc(1, sizeof(*mapping) + sizeof(mapping->entries[0]));
	CHECK(replacement);
	replacement->count = 1;
	replacement->entries[0] = mapping->entries[0];
	free(mapping);
	mapping = replacement;
	ingress.pon_flow_table = replacement;
	CHECK(!airoha_ppe_pon_candidate_validate(&ppe, &saved));
	finish();
}

int main(int argc, char **argv)
{
	if (argc == 2) {
		begin("missing mutex rejected");
		capture();
		mutex_unlock(&flow_offload_mutex);
		if (!strcmp(argv[1], "snapshot-unlocked"))
			airoha_ppe_pon_candidate_snapshot(&ppe, flow->cookie, &saved);
		else
			airoha_ppe_pon_candidate_validate(&ppe, &saved);
		return 0;
	}
	gates();
	actions();
	publication();
	ownership();
	printf("{\"passed\":true,\"cases\":%u,\"checks\":%u,\"holds\":%u,\"puts\":%u,\"lookups\":%u,\"spin_locks\":%u}\n",
	       cases, checks, holds, ref_puts, lookups, spin_calls);
	return 0;
}
