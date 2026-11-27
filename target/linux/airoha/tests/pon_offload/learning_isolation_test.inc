static void isolation_counters_reset(void)
{
	commits = row_reads = subflow_removals = l2_lookups = 0;
	subflow_commits = native_binds = 0;
}

static unsigned test_learning_isolation(struct airoha_eth *eth,
				       struct airoha_gdm_dev *pon,
				       struct airoha_gdm_dev *wired,
				       struct net_device *wifi)
{
	struct airoha_ppe ppe = {
		.eth = eth, .ct_host_ppe = true, .ct_native_pairs = true,
		.ct_pon_qualified = true,
	};
	const bool bank_allowed[][4] = {
		{ false, true, true, false },
		{ false, true, false, false },
		{ false, false, true, false },
		{ false, false, true, false },
		{ false, true, false, false },
		{ false, false, false, false },
	};
	const bool source_allowed[][3] = {
		{ true, true, false },
		{ false, true, false },
		{ false, false, true },
		{ true, false, false },
		{ false, true, false },
		{ false, false, false },
	};
	const u32 rows[] = { 0, 8191, 8192, 16383, 16384, UINT32_MAX };
	struct net_device *inputs[] = { wired->netdev, wifi, pon->netdev };
	unsigned cases = 0;

	eth->ppe = &ppe;
	for (unsigned family = 0; family < 2; ++family)
		for (unsigned udp = 0; udp < 2; ++udp)
			for (unsigned kind = 0; kind < ARRAY_SIZE(bank_allowed); ++kind) {
				struct airoha_flow_table_entry entry = {
					.type = FLOW_TYPE_L4, .egress_dev = wired,
					.ct_ingress_dsa_port = -1,
				};

				entry.data.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE,
					family ? PPE_PKT_TYPE_IPV6_ROUTE_5T : PPE_PKT_TYPE_IPV4_HNAPT) |
					FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND) |
					FIELD_PREP(AIROHA_FOE_IB1_BIND_UDP, udp);
				entry.ct_bridge = kind == 1;
				if (kind == 2)
					entry.pon_ingress_dev = pon;
				if (kind >= 3)
					entry.egress_dev = pon;
				if (kind == 3) {
					entry.ct_ingress_gdm = wired;
					entry.ct_ingress_ifindex = wired->netdev->ifindex;
				}
				if (kind == 4)
					entry.ct_ingress_ifindex = wifi->ifindex;
				for (unsigned combination = 0; combination < 4; ++combination) {
					assert(airoha_ppe_ct_flow_bank_matches(&ppe, &entry,
						combination < 2 ? 0 : 8192, combination & 1) ==
						bank_allowed[kind][combination]);
					cases++;
				}
				for (unsigned row_index = 0; row_index < ARRAY_SIZE(rows); ++row_index)
					for (unsigned source = 0; source < ARRAY_SIZE(inputs); ++source)
						for (unsigned owned = 0; owned < 2; ++owned) {
							struct sk_buff skb = { .dev = inputs[source] };
							bool rx_wlan = source == 1;
							bool readable = row_index < 4 && !(owned && row_index >= 2);
							bool expected = readable && source_allowed[kind][source] &&
								bank_allowed[kind][(row_index >= 2 ? 2 : 0) + rx_wlan];

							ppe.ct_npu_owner = owned ? &ppe : NULL;
							ppe.foe_flow[0] = &entry;
							entry.hash = 0xffff;
							selected_row = rows[row_index];
							learned = entry.data;
							learned.ib1 = (learned.ib1 & ~AIROHA_FOE_IB1_BIND_STATE) |
								FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_UNBIND);
							skb.hdr.h_proto = htons(family ? ETH_P_IPV6 : ETH_P_IP);
							isolation_counters_reset();
							airoha_ppe_foe_insert_entry(&ppe, &skb, selected_row, rx_wlan, NULL);
							assert(!ppe_lock && commits == expected && row_reads == readable);
							assert(entry.hash == (expected ? selected_row : 0xffff));
							assert(!l2_lookups && !subflow_commits && !native_binds);
							cases++;
						}
			}
	for (unsigned native = 0; native < 2; ++native)
		for (unsigned host = 0; host < 2; ++host)
			for (unsigned bridge = 0; bridge < 2; ++bridge) {
				struct airoha_flow_table_entry entry = { .type = FLOW_TYPE_L4 };
				struct sk_buff skb = { .dev = wifi };

				ppe.ct_npu_owner = NULL;
				ppe.ct_host_ppe = host;
				ppe.ct_native_pairs = native;
				ppe.foe_flow[0] = NULL;
				selected_row = 5;
				l2_candidate = &entry;
				learned.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE,
					bridge ? PPE_PKT_TYPE_BRIDGE : PPE_PKT_TYPE_IPV4_HNAPT);
				isolation_counters_reset();
				airoha_ppe_foe_insert_entry(&ppe, &skb, selected_row, true, NULL);
				assert(native_binds == (native && bridge));
				assert(subflow_commits == (!host && !(native && bridge)));
				assert(l2_lookups == subflow_commits && !commits);
				cases++;
			}
	l2_candidate = NULL;
	ppe.ct_host_ppe = true;
	ppe.ct_native_pairs = true;
	for (unsigned owned = 0; owned < 2; ++owned) {
		struct sk_buff skb = { .dev = wired->netdev };

		ppe.ct_npu_owner = owned ? &ppe : NULL;
		selected_row = 8192;
		learned.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE, PPE_PKT_TYPE_BRIDGE);
		isolation_counters_reset();
		airoha_ppe_foe_insert_entry(&ppe, &skb, selected_row, false, NULL);
		assert(row_reads == !owned && native_binds == !owned && !commits);
		cases++;
	}
	ppe.ct_npu_owner = NULL;
	for (unsigned recorded = 0; recorded < ARRAY_SIZE(rows); ++recorded) {
		struct airoha_flow_table_entry entry = {
			.type = FLOW_TYPE_L2_SUBFLOW, .hash = rows[recorded],
		};
		struct sk_buff skb = { .dev = wifi };

		ppe.foe_flow[0] = &entry;
		selected_row = 0;
		learned.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE, PPE_PKT_TYPE_IPV4_HNAPT);
		isolation_counters_reset();
		airoha_ppe_foe_insert_entry(&ppe, &skb, selected_row, true, NULL);
		assert(subflow_removals == !recorded && !commits);
		assert(entry.hash == (recorded ? rows[recorded] : 0xffff));
		cases++;
	}
	for (unsigned rx_wlan = 0; rx_wlan < 2; ++rx_wlan) {
		struct airoha_flow_table_entry entry = { .egress_dev = pon };

		ppe.ct_native_pairs = false;
		assert(airoha_ppe_ct_flow_bank_matches(&ppe, &entry, 5, rx_wlan));
		cases++;
	}
	eth->ppe = NULL;
	return cases;
}
