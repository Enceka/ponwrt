static struct airoha_foe_entry protected_shadow[PPE_SRAM_NUM_ENTRIES];
static struct airoha_foe_entry protected_hardware[PPE_SRAM_NUM_ENTRIES];

static void protect_reused_rows(void)
{
	memcpy(protected_shadow, &shadow[PPE_SRAM_NUM_ENTRIES], sizeof(protected_shadow));
	memcpy(protected_hardware, &hardware[PPE_SRAM_NUM_ENTRIES], sizeof(protected_hardware));
	fixture_setup = false;
	operation = REUSE;
}

static void check_reused_rows(void)
{
	CHECK(!memcmp(protected_shadow, &shadow[PPE_SRAM_NUM_ENTRIES], sizeof(protected_shadow)));
	CHECK(!memcmp(protected_hardware, &hardware[PPE_SRAM_NUM_ENTRIES], sizeof(protected_hardware)));
	CHECK(!ppe_lock && !flow_offload_mutex && spin_acquires == spin_releases);
}

static void set_wlan_destination(struct airoha_flow_table_entry *entry, unsigned type)
{
	u32 ib2 = FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_GDM3) |
		  FIELD_PREP(AIROHA_FOE_IB2_NBQ, 2);
	u32 data = FIELD_PREP(AIROHA_FOE_CHANNEL, 8);
	if (type == PPE_PKT_TYPE_IPV4_HNAPT) {
		entry->data.ipv4.ib2 = ib2;
		entry->data.ipv4.data = data;
		entry->data.ipv4.l2.common.etype = 17 << 6;
	} else {
		entry->data.ipv6.ib2 = ib2;
		entry->data.ipv6.data = data;
		entry->data.ipv6.l2.etype = 17 << 6;
	}
}

static void test_cookie_reuse(void)
{
	const u32 hashes[] = { 8192, 12288, 16383 };
	const unsigned types[] = { PPE_PKT_TYPE_IPV4_HNAPT, PPE_PKT_TYPE_IPV6_ROUTE_5T };
	const unsigned long cookies[] = { 0, 1, 0x100000000UL, ~0UL };
	struct airoha_gdm_dev pon = { .flags = 1UL << AIROHA_DEV_F_PON }, lan = {};
	for (unsigned path = 0; path < 5; path++) {
		for (unsigned position = 0; position < ARRAY_SIZE(hashes); position++) {
			for (unsigned type_index = 0; type_index < ARRAY_SIZE(types); type_index++) {
				for (unsigned cookie_index = 0; cookie_index < ARRAY_SIZE(cookies); cookie_index++) {
					reset("retired-cookie-stats-destroy-identical-npu-row");
					unsigned type = types[type_index];
					u32 hash = hashes[position];
					struct airoha_flow_table_entry *entry = new_flow(hash, FLOW_TYPE_L4, cookies[cookie_index]);
					entry->data.ib1 = (entry->data.ib1 & ~AIROHA_FOE_IB1_BIND_PACKET_TYPE) |
							 FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE, type);
					ppe.ct_host_ppe = true;
					if (path == 0)
						entry->egress_dev = &lan;
					else if (path == 1)
						entry->egress_dev = &pon;
					else if (path == 2)
						entry->pon_ingress_dev = &pon;
					else {
						set_wlan_destination(entry, type);
						entry->ct_bridge = path == 4;
						if (entry->ct_bridge) {
							entry->data.ib1 &= ~AIROHA_FOE_IB1_BIND_TTL;
							list_add_tail(&entry->ct_bridge_node, &bridges);
						}
					}
					struct airoha_foe_entry original = entry->data;
					CHECK(airoha_ppe_foe_compare_entry(entry, &original));
					CHECK(airoha_ppe_ct_bridge_row_matches(entry, &original));
					if (path == 1 || path == 2)
						CHECK(airoha_ppe_ct_pon_row_matches(entry, &original));
					if (path >= 3)
						CHECK(airoha_ppe_ct_wlan_entry(&original, 0, 17));
					add_walk(entry);
					CHECK(retire() == 0 && entry->hash == 0xffff);
					hardware[hash] = shadow[hash] = original;
					protect_reused_rows();
					struct flow_cls_offload request = { .cookie = entry->cookie };
					for (unsigned repeat = 0; repeat < 2; repeat++) {
						mutex_lock(&flow_offload_mutex);
						CHECK(airoha_ppe_flow_offload_stats(&eth, &request) == 0);
						mutex_unlock(&flow_offload_mutex);
						CHECK(!request.stats.pkts && !request.stats.bytes);
						CHECK(!reuse_reads && !reuse_writes && !reuse_stats);
						check_reused_rows();
					}
					mutex_lock(&flow_offload_mutex);
					CHECK(airoha_ppe_flow_offload_destroy(&eth, &request) == 0);
					mutex_unlock(&flow_offload_mutex);
					CHECK(frees == 1 && removed_cookies == 1 && !removed_l2);
					CHECK(!reuse_reads && !reuse_writes && !reuse_stats && list_empty(&bridges));
					check_reused_rows();
					mutex_lock(&flow_offload_mutex);
					CHECK(airoha_ppe_flow_offload_stats(&eth, &request) == -ENOENT);
					CHECK(airoha_ppe_flow_offload_destroy(&eth, &request) == -ENOENT);
					mutex_unlock(&flow_offload_mutex);
					check_reused_rows();
				}
			}
		}
	}
}

static void test_l2_reuse(void)
{
	const u32 hashes[] = { 0, 8192, 8191, 12288, 16383 };
	for (unsigned rotation = 0; rotation < ARRAY_SIZE(hashes); rotation++) {
		reset("l2-parent-stats-destroy-after-npu-row-reuse");
		struct airoha_gdm_dev lan = {};
		struct airoha_flow_table_entry *parent = new_flow(0xffff, FLOW_TYPE_L2, 0x100000000UL);
		parent->egress_dev = &lan;
		ppe.ct_host_ppe = true;
		struct airoha_foe_entry originals[ARRAY_SIZE(hashes)];
		for (unsigned index = 0; index < ARRAY_SIZE(hashes); index++) {
			u32 hash = hashes[(index + rotation) % ARRAY_SIZE(hashes)];
			struct airoha_flow_table_entry *child = new_flow(hash, FLOW_TYPE_L2_SUBFLOW, index);
			hlist_add_head(&child->l2_subflow_node, &parent->l2_flows);
			originals[index] = child->data;
			if (hash < 8192)
				hardware[hash] = shadow[hash] = child->data;
		}
		memcpy(bank0_shadow, shadow, sizeof(bank0_shadow));
		memcpy(bank0_hardware, hardware, sizeof(bank0_hardware));
		add_walk(parent);
		CHECK(retire() == 0 && frees == 3 && allocated[0].entry == parent);
		check_hlist(&parent->l2_flows, 2);
		for (unsigned index = 0; index < ARRAY_SIZE(hashes); index++) {
			u32 hash = hashes[(index + rotation) % ARRAY_SIZE(hashes)];
			if (hash >= 8192)
				hardware[hash] = shadow[hash] = originals[index];
		}
		protect_reused_rows();
		struct flow_cls_offload request = { .cookie = parent->cookie };
		mutex_lock(&flow_offload_mutex);
		CHECK(airoha_ppe_flow_offload_stats(&eth, &request) == 0);
		mutex_unlock(&flow_offload_mutex);
		CHECK(reuse_reads == 2 && !reuse_writes && !reuse_stats);
		check_reused_rows();
		mutex_lock(&flow_offload_mutex);
		CHECK(airoha_ppe_flow_offload_destroy(&eth, &request) == 0);
		mutex_unlock(&flow_offload_mutex);
		CHECK(reuse_reads == 2 && reuse_writes == 2 && !reuse_stats);
		CHECK(frees == 6 && removed_cookies == 1 && removed_l2 == 1);
		CHECK(!candidates.first);
		for (unsigned index = 0; index < allocation_count; index++)
			CHECK(allocated[index].freed);
		CHECK(!(hardware[0].ib1 & AIROHA_FOE_IB1_BIND_STATE));
		CHECK(!(hardware[8191].ib1 & AIROHA_FOE_IB1_BIND_STATE));
		check_reused_rows();
	}
}
