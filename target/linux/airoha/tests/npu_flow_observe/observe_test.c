#include "host_stubs.h"

static struct airoha_eth eth;
static struct airoha_ppe ppe;
static struct airoha_gdm_dev dev, other_dev;
static struct port port;
static struct airoha_pon_flow_table mapping, replacement;
static struct hlist_head buckets[16];
static struct airoha_flow_table_entry entry, nat_entry;
static struct sk_buff skb;
static unsigned char storage[1568];
static unsigned char *frame;
static unsigned bytes;
static u32 message;

static void reset(void)
{
	CHECK(!lock_depth && !rcu_depth);
	memset(&eth, 0, sizeof(eth));
	memset(&ppe, 0, sizeof(ppe));
	memset(&dev, 0, sizeof(dev));
	memset(&other_dev, 0, sizeof(other_dev));
	memset(&port, 0, sizeof(port));
	memset(&mapping, 0, sizeof(mapping));
	memset(&replacement, 0, sizeof(replacement));
	memset(buckets, 0, sizeof(buckets));
	memset(&entry, 0, sizeof(entry));
	memset(&nat_entry, 0, sizeof(nat_entry));
	memset(&skb, 0, sizeof(skb));
	memset(storage, 0, sizeof(storage));
	lock_calls = rcu_calls = row_reads = row_writes = 0;
	retiring = NULL;
	row_missing = false;
	row_matches = true;
	commit_error = 0;
	eth.ppe = &ppe;
	ppe.ct_host_ppe = true;
	ppe.foe_flow = buckets;
	dev.eth = &eth;
	dev.port = &port;
	port.id = AIROHA_GDM2_IDX;
	dev.flags = BIT(AIROHA_DEV_F_PON);
	dev.netdev.running = dev.netdev.carrier = true;
	dev.pon_qdma_tag = AIROHA_PON_QDMA_VALID | 0x1234;
	dev.pon_flow_table = &mapping;
	mapping.count = 1;
	mapping.entries[0].tag = dev.pon_qdma_tag;
	other_dev = dev;
	frame = storage + 16;
	bytes = make_frame(frame, 2, true, false, 0, 5);
	message = FIELD_PREP(QDMA_ETH_RXMSG_GEM_MASK, 0x1234);
	skb = (struct sk_buff) {
		.dev = &dev.netdev, .head = storage, .data = frame + ETH_HLEN,
		.mac = frame, .mac_set = true, .len = bytes - ETH_HLEN,
	};
	entry.cookie = 0x12345678;
	entry.type = FLOW_TYPE_L4;
	entry.hash = 0x123;
	entry.pon_ingress_dev = &dev;
	entry.data.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE, PPE_PKT_TYPE_IPV4_HNAPT) |
		AIROHA_FOE_IB1_BIND_UDP;
	entry.data.ipv4.orig_tuple.src_ip = 0xc0000201;
	entry.data.ipv4.orig_tuple.dest_ip = 0xc6336402;
	entry.data.ipv4.orig_tuple.src_port = 0x1234;
	entry.data.ipv4.orig_tuple.dest_port = 0xabcd;
	entry.data.ipv4.new_tuple.src_ip = 0xcb00710a;
	entry.data.ipv4.new_tuple.dest_ip = 0xc0a80178;
	entry.data.ipv4.new_tuple.src_port = 40000;
	entry.data.ipv4.new_tuple.dest_port = 8080;
	memset(&entry.data.ipv4.l2, 0x5a, sizeof(entry.data.ipv4.l2));
	nat_entry = entry;
	nat_entry.cookie = 0x87654321;
	nat_entry.data.ipv4.orig_tuple = entry.data.ipv4.new_tuple;
	nat_entry.data.ipv4.new_tuple = entry.data.ipv4.orig_tuple;
	u32 bucket = airoha_ppe_foe_get_entry_hash(&ppe, &entry.data);
	hlist_add_head(&entry.list, &buckets[bucket]);
	hlist_add_head(&nat_entry.list, &buckets[bucket]);
	hardware_row = entry.data;
	hardware_row.ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND);
}

static void observed(u32 service)
{
	struct airoha_npu_ipv4_identity identity;
	struct airoha_npu_auth_rule rule;

	CHECK(entry.pon_ingress_seen && !entry.pon_ingress_conflict);
	CHECK(entry.pon_ingress_service == service);
	CHECK(!airoha_npu_ingress_parse_ipv4(frame, bytes, service, &identity));
	CHECK(!airoha_npu_auth_encode_ipv4(&rule, 1, 1, 1, 0, &identity));
	CHECK(!memcmp(entry.pon_ingress_key, rule.raw + 9, sizeof(entry.pon_ingress_key)));
	CHECK(!nat_entry.pon_ingress_seen && !nat_entry.pon_ingress_conflict);
	CHECK(!lock_depth && !rcu_depth && !row_reads && !row_writes);
}

static void direct(u32 service)
{
	struct airoha_foe_entry before = entry.data;
	unsigned long cookie = entry.cookie;
	u32 hash = entry.hash;

	airoha_ppe_pon_observe_frame(&dev, frame, bytes, service);
	CHECK(entry.cookie == cookie && entry.hash == hash);
	CHECK(!memcmp(&entry.data, &before, sizeof(before)));
	CHECK(!lock_depth && !rcu_depth && !row_reads && !row_writes);
}

static void receive(void)
{
	struct airoha_foe_entry before = entry.data;
	airoha_qdma_observe_pon_skb(&dev, &eth.qdma[1], &skb, message);
	CHECK(!memcmp(&entry.data, &before, sizeof(before)));
	CHECK(!lock_depth && !rcu_depth && !row_reads && !row_writes);
}

static void test_original_tuple(void)
{
	scenario = "original-cookie-tuple-not-nat-actions";
	reset();
	direct(0x1234);
	observed(0x1234);
	struct airoha_flow_table_entry before = entry;
	for (unsigned repeat = 0; repeat < 3; ++repeat) {
		direct(0x1234);
		CHECK(!memcmp(&before, &entry, sizeof(entry)));
	}
	++cases;
	scenario = "nat-output-tuple-does-not-match-original-cookie";
	for (unsigned variant = 0; variant < 5; ++variant) {
		reset();
		switch (variant) {
		case 0: put32(frame + 42, entry.data.ipv4.new_tuple.src_ip); break;
		case 1: put32(frame + 46, entry.data.ipv4.new_tuple.dest_ip); break;
		case 2: put16(frame + 50, entry.data.ipv4.new_tuple.src_port); break;
		case 3: put16(frame + 52, entry.data.ipv4.new_tuple.dest_port); break;
		case 4: bytes = make_frame(frame, 2, true, true, 0, 5); break;
		}
		direct(0x1234);
		CHECK(!entry.pon_ingress_seen && !entry.pon_ingress_conflict);
		++cases;
	}
	scenario = "tcp-original-cookie";
	reset();
	entry.data.ib1 &= ~AIROHA_FOE_IB1_BIND_UDP;
	bytes = make_frame(frame, 2, true, true, 0, 5);
	direct(0x1234);
	observed(0x1234);
	++cases;
}

static void test_direct_gates(void)
{
	scenario = "observe-device-cookie-and-lifecycle-gates";
	for (unsigned variant = 0; variant < 18; ++variant) {
		reset();
		switch (variant) {
		case 0: eth.ppe = NULL; break;
		case 1: ppe.ct_host_ppe = false; break;
		case 2: ppe.foe_flow = NULL; break;
		case 3: dev.flags = 0; break;
		case 4: port.id = 1; break;
		case 5: dev.nbq = 1; break;
		case 6: ppe.ct_stopping = true; break;
		case 7: dev.pon_update_blocked = true; break;
		case 8: dev.netdev.running = false; break;
		case 9: dev.netdev.carrier = false; break;
		case 10: entry.pon_ingress_dev = &other_dev; break;
		case 11: entry.type = FLOW_TYPE_L2; break;
		case 12: entry.type = FLOW_TYPE_L2_SUBFLOW; break;
		case 13: entry.ct_bridge = true; break;
		case 14: entry.pon_ingress_conflict = true; break;
		case 15: frame[0] |= 1; break;
		case 16: bytes--; break;
		case 17: entry.data.ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE, PPE_PKT_TYPE_IPV4_ROUTE); break;
		}
		struct airoha_flow_table_entry before = entry;
		direct(0x1234);
		CHECK(!memcmp(&entry, &before, sizeof(entry)));
		++cases;
	}
	reset();
	direct(0x10000);
	CHECK(!entry.pon_ingress_seen);
	++cases;
}

static void test_conflicts(void)
{
	scenario = "gem-mac-tag-pppoe-conflict-remains-sticky";
	for (unsigned variant = 0; variant < 8; ++variant) {
		reset();
		direct(0x1234);
		observed(0x1234);
		u32 old_key[19];
		memcpy(old_key, entry.pon_ingress_key, sizeof(old_key));
		u32 service = 0x1234;
		switch (variant) {
		case 0: service++; break;
		case 1: frame[5] ^= 1; break;
		case 2: frame[11] ^= 1; break;
		case 3: frame[15] ^= 1; break;
		case 4: frame[19] ^= 1; break;
		case 5: frame[25] ^= 1; break;
		case 6: bytes = make_frame(frame, 1, true, false, 0, 5); break;
		case 7: bytes = make_frame(frame, 2, false, false, 0, 5); break;
		}
		direct(service);
		CHECK(entry.pon_ingress_conflict && !entry.pon_ingress_seen);
		CHECK(entry.pon_ingress_service == 0x1234);
		CHECK(!memcmp(old_key, entry.pon_ingress_key, sizeof(old_key)));
		struct airoha_flow_table_entry before = entry;
		direct(service);
		CHECK(!memcmp(&before, &entry, sizeof(entry)));
		bytes = make_frame(frame, 2, true, false, 0, 5);
		direct(0x1234);
		CHECK(!memcmp(&before, &entry, sizeof(entry)));
		++cases;
	}
}

static void test_qdma(void)
{
	scenario = "wan-qdma-complete-frame-current-gpon-mapping";
	reset();
	receive();
	observed(0x1234);
	CHECK(rcu_calls == 1 && lock_calls == 1);
	struct airoha_flow_table_entry before = entry;
	receive();
	CHECK(!memcmp(&entry, &before, sizeof(entry)));
	++cases;
	scenario = "qdma-rejects-incomplete-offloaded-or-wrong-provenance";
	for (unsigned variant = 0; variant < 22; ++variant) {
		reset();
		struct airoha_qdma *rx = &eth.qdma[1];
		switch (variant) {
		case 0: dev.flags = 0; break;
		case 1: rx = &eth.qdma[0]; break;
		case 2: skb.dev = &other_dev.netdev; break;
		case 3: skb.nonlinear = true; break;
		case 4: skb.vlan_present = true; break;
		case 5: skb.mac_set = false; break;
		case 6: skb.head = frame + 1; break;
		case 7: skb.data++; break;
		case 8: dev.pon_update_blocked = true; break;
		case 9: message |= QDMA_ETH_RXMSG_OAM_MASK; break;
		case 10: message |= QDMA_ETH_RXMSG_CRC_ERR_MASK; break;
		case 11: message |= QDMA_ETH_RXMSG_RUNT_MASK; break;
		case 12: message |= QDMA_ETH_RXMSG_LONG_MASK; break;
		case 13: dev.pon_flow_table = NULL; break;
		case 14: mapping.count = 0; break;
		case 15: mapping.entries[0].tag &= ~AIROHA_PON_QDMA_VALID; break;
		case 16: message = FIELD_PREP(QDMA_ETH_RXMSG_GEM_MASK, 0x4321); break;
		case 17: skb.len--; break;
		case 18: skb.len = 1519 - ETH_HLEN; break;
		case 19: dev.netdev.running = false; break;
		case 20: dev.netdev.carrier = false; break;
		case 21: ppe.ct_stopping = true; break;
		}
		before = entry;
		airoha_qdma_observe_pon_skb(&dev, rx, &skb, message);
		CHECK(!memcmp(&entry, &before, sizeof(entry)));
		CHECK(!lock_depth && !rcu_depth && !row_reads && !row_writes);
		++cases;
	}
	scenario = "current-table-replaces-stale-default-gem";
	reset();
	replacement.count = 2;
	replacement.entries[0].tag = 0x1234;
	replacement.entries[1].tag = AIROHA_PON_QDMA_VALID | 0x4321;
	dev.pon_flow_table = &replacement;
	receive();
	CHECK(!entry.pon_ingress_seen);
	message = FIELD_PREP(QDMA_ETH_RXMSG_GEM_MASK, 0x4321);
	receive();
	observed(0x4321);
	++cases;
	scenario = "second-valid-gem-quarantines-same-cookie";
	reset();
	receive();
	mapping.entries[mapping.count++].tag = AIROHA_PON_QDMA_VALID | 0x4321;
	message = FIELD_PREP(QDMA_ETH_RXMSG_GEM_MASK, 0x4321);
	receive();
	CHECK(entry.pon_ingress_conflict && !entry.pon_ingress_seen);
	++cases;
	scenario = "epon-current-channel-and-llid";
	for (unsigned variant = 0; variant < 4; ++variant) {
		reset();
		dev.pon_flow_table = NULL;
		dev.pon_qdma_tag = AIROHA_PON_QDMA_VALID | AIROHA_PON_QDMA_EPON |
			FIELD_PREP(AIROHA_PON_QDMA_TCONT_MASK, 7) | 0xbeef;
		message |= FIELD_PREP(QDMA_ETH_RXMSG_CHANNEL_MASK, 7);
		if (variant == 1)
			message ^= FIELD_PREP(QDMA_ETH_RXMSG_CHANNEL_MASK, 1);
		if (variant == 2)
			dev.pon_qdma_tag &= ~AIROHA_PON_QDMA_VALID;
		if (variant == 3)
			dev.pon_qdma_tag ^= FIELD_PREP(AIROHA_PON_QDMA_TCONT_MASK, 1);
		receive();
		if (!variant)
			observed(0xbeef);
		else
			CHECK(!entry.pon_ingress_seen);
		++cases;
	}
}

static void test_withdraw(void)
{
	scenario = "withdraw-clears-seen-before-unlink-read-and-commit";
	for (unsigned variant = 0; variant < 7; ++variant) {
		reset();
		direct(0x1234);
		observed(0x1234);
		retiring = &entry;
		u32 old_hash = entry.hash;
		unsigned long cookie = entry.cookie;
		struct airoha_foe_entry before = entry.data;
		switch (variant) {
		case 0: entry.hash = 0xffff; break;
		case 1: row_missing = true; break;
		case 2: commit_error = -ETIMEDOUT; break;
		case 3: row_matches = false; break;
		case 4: hardware_row.ib1 &= ~AIROHA_FOE_IB1_BIND_STATE; break;
		case 5: hardware_row.ib1 = (hardware_row.ib1 & ~AIROHA_FOE_IB1_BIND_STATE) |
			FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_FIN); break;
		case 6: break;
		}
		int result = airoha_ppe_ct_remove_pon_flow(&ppe, &entry);
		CHECK(result == (variant == 1 || variant == 2 ? -ETIMEDOUT : 0));
		CHECK(!entry.pon_ingress_seen && !entry.list.pprev);
		CHECK(entry.hash == (result ? old_hash : 0xffff));
		CHECK(entry.cookie == cookie && !memcmp(&entry.data, &before, sizeof(before)));
		CHECK(!lock_depth && !rcu_depth);
		CHECK(row_reads == (variant != 0));
		CHECK(row_writes == (variant == 2 || variant == 5 || variant == 6));
		airoha_ppe_pon_observe_frame(&dev, frame, bytes, 0x1234);
		CHECK(!entry.pon_ingress_seen);
		if (result) {
			row_missing = false;
			commit_error = 0;
			CHECK(!airoha_ppe_ct_remove_pon_flow(&ppe, &entry));
			CHECK(!entry.pon_ingress_seen && entry.hash == 0xffff);
		}
		++cases;
	}
}

int main(void)
{
	test_original_tuple();
	test_direct_gates();
	test_conflicts();
	test_qdma();
	test_withdraw();
	printf("{\"passed\":true,\"cases\":%lu,\"checks\":%lu}\n", cases, checks);
	return 0;
}
