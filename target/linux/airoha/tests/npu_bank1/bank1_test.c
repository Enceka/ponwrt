#include "host_stubs.h"

static void cleanup(void)
{
	for (unsigned index = 0; index < allocation_count; index++)
		free(allocated[index].entry);
	allocation_count = 0;
}

static void reset(const char *name)
{
	scenario = name;
	CHECK(!flow_offload_mutex && !ppe_lock && !walk_entered && !walk_active);
	cleanup();
	memset(allocated, 0, sizeof(allocated));
	memset(walk_items, 0, sizeof(walk_items));
	memset(row_writes, 0, sizeof(row_writes));
	memset(row_reads, 0, sizeof(row_reads));
	for (u32 hash = 0; hash < ARRAY_SIZE(shadow); hash++) {
		memset(&shadow[hash], 0x39, sizeof(shadow[hash]));
		memset(&hardware[hash], 0xa6, sizeof(hardware[hash]));
		shadow[hash].ib1 ^= hash;
		hardware[hash].ib1 ^= hash;
	}
	memcpy(other_shadow, &shadow[other_hash(0)], sizeof(other_shadow));
	memcpy(other_hardware, &hardware[other_hash(0)], sizeof(other_hardware));
	ppe = (struct airoha_ppe){ .eth = &eth, .foe = shadow, .ct_owns_sram = true };
	eth.ppe = &ppe;
	candidates = (struct hlist_head){};
	list_init(&bridges);
	operation = IDLE;
	fixture_setup = true;
	spin_acquires = spin_releases = reschedules = 0;
	walk_starts = walk_stops = walk_exits = walk_calls = 0;
	walk_count = frees = writes = reads = write_acks = read_acks = 0;
	reuse_reads = reuse_writes = reuse_stats = removed_cookies = removed_l2 = 0;
	fault = NO_FAULT;
	fault_row = corrupt_byte = control_value = 0;
	active_cursor = NULL;
	ack_unrelated_bits = false;
	scenarios++;
}

static void other_bank_unchanged(void)
{
	CHECK(!memcmp(other_shadow, &shadow[other_hash(0)], sizeof(other_shadow)));
	CHECK(!memcmp(other_hardware, &hardware[other_hash(0)], sizeof(other_hardware)));
}

static void balanced(void)
{
	CHECK(!flow_offload_mutex && !ppe_lock && !walk_entered && !walk_active);
	CHECK(spin_acquires == spin_releases);
	CHECK(walk_starts == walk_stops && walk_stops == walk_exits);
	for (unsigned index = 0; index < allocation_count; index++)
		if (allocated[index].entry)
			CHECK(list_empty(&allocated[index].entry->gc_node));
	other_bank_unchanged();
}

static int retire(void)
{
	fixture_setup = false;
	operation = RETIRE;
	mutex_lock(&flow_offload_mutex);
	int error = selected_bank ? airoha_ppe_bank1_retire_flows(&ppe) : airoha_ppe_bank0_retire_flows(&ppe);
	CHECK(flow_offload_mutex && !ppe_lock);
	mutex_unlock(&flow_offload_mutex);
	operation = IDLE;
	balanced();
	CHECK(!writes && !reads && !write_acks && !read_acks);
	return error;
}

static int clear_rows(u32 *cursor)
{
	fixture_setup = false;
	operation = CLEAR;
	active_cursor = cursor;
	mutex_lock(&flow_offload_mutex);
	int error = selected_bank ? airoha_ppe_bank1_clear_rows(&ppe, cursor) : airoha_ppe_bank0_clear_rows(&ppe, cursor);
	CHECK(flow_offload_mutex && !ppe_lock);
	mutex_unlock(&flow_offload_mutex);
	active_cursor = NULL;
	operation = IDLE;
	balanced();
	return error;
}

static struct airoha_flow_table_entry *new_flow(u32 hash, unsigned type, unsigned long cookie)
{
	CHECK(fixture_setup && allocation_count < ARRAY_SIZE(allocated));
	struct airoha_flow_table_entry *entry = calloc(1, sizeof(*entry));
	CHECK(entry != NULL);
	allocated[allocation_count++].entry = entry;
	entry->type = type;
	entry->hash = hash;
	entry->cookie = cookie;
	entry->stats.bytes = UINT64_C(0x1234567812345678);
	entry->stats.packets = UINT64_C(0xabcdef0187654321);
	entry->ct_bridge_generation = UINT64_C(0x1234567800000001);
	memset(&entry->data, 0x6b, sizeof(entry->data));
	entry->data.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND) |
			  FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE, PPE_PKT_TYPE_IPV6_ROUTE_5T) |
			  AIROHA_FOE_IB1_BIND_UDP | AIROHA_FOE_IB1_BIND_TTL | 0x453;
	list_init(&entry->gc_node);
	list_init(&entry->ct_bridge_node);
	if (type != FLOW_TYPE_L2)
		hlist_add_head(&entry->list, &candidates);
	return entry;
}

static void add_walk(void *entry)
{
	CHECK(walk_count < ARRAY_SIZE(walk_items));
	walk_items[walk_count++] = entry;
}

static void check_entry(struct airoha_flow_table_entry *entry,
			struct airoha_flow_table_entry before, bool retired)
{
	if (retired) {
		before.list = (struct hlist_node){};
		before.hash = 0xffff;
		before.data.ib1 &= ~AIROHA_FOE_IB1_BIND_STATE;
		if (before.ct_bridge)
			before.ct_bridge_dead = true;
	} else {
		CHECK(!!before.list.pprev == !!entry->list.pprev);
		before.list = entry->list;
	}
	CHECK(!memcmp(entry, &before, sizeof(before)));
}

static void test_hash_and_old_cookies(void)
{
	const u32 hashes[] = { 0, 1, 8191, 8192, 8193, 12288, 16383, 16384, 32767, 65535, UINT32_MAX };
	const unsigned long cookies[] = { 0, 1, 0xffff, 0x100000000UL, 0x12345678abcdef01UL, ~0UL };
	for (unsigned index = 0; index < ARRAY_SIZE(hashes); index++) {
		CHECK(airoha_ppe_bank_hash(hashes[index], selected_bank) == in_selected_bank(hashes[index]));
		CHECK(airoha_ppe_bank1_hash(hashes[index]) == (hashes[index] >= 8192 && hashes[index] < 16384));
		CHECK(airoha_ppe_bank0_hash(hashes[index]) == (hashes[index] < 8192));
	}
	for (unsigned cookie = 0; cookie < ARRAY_SIZE(cookies); cookie++) {
		for (unsigned index = 0; index < ARRAY_SIZE(hashes); index++) {
			for (unsigned state = 0; state <= AIROHA_FOE_STATE_FIN; state++) {
				reset("old-cookie-boundary-state");
				struct airoha_flow_table_entry *entry = new_flow(hashes[index], FLOW_TYPE_L4, cookies[cookie]);
				entry->data.ib1 = (entry->data.ib1 & ~AIROHA_FOE_IB1_BIND_STATE) |
						 FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, state);
				entry->ct_bridge = cookie & 1;
				if (entry->ct_bridge)
					list_add_tail(&entry->ct_bridge_node, &bridges);
				if (cookie == 2) {
					candidates.first = NULL;
					entry->list = (struct hlist_node){};
				}
				struct airoha_flow_table_entry before = *entry;
				add_walk(entry);
				CHECK(retire() == 0);
				check_entry(entry, before, in_selected_bank(hashes[index]));
				CHECK(!frees && spin_acquires == 1 && reschedules == 1);
				before = *entry;
				CHECK(retire() == 0);
				check_entry(entry, before, false);
			}
		}
	}
}

static void test_invalid_banks(void)
{
	const u32 banks[] = { 2, 3, 0x80000, 0x80000000, UINT32_MAX };
	const u32 hashes[] = { 0, 8191, 8192, 16383, 16384, 65535, UINT32_MAX };
	for (unsigned index = 0; index < ARRAY_SIZE(banks); ++index) {
		reset("invalid-bank-no-walk-detach-or-clear");
		struct airoha_flow_table_entry *entry = new_flow(selected_hash(0), FLOW_TYPE_L4, 1);
		struct airoha_flow_table_entry *parent = new_flow(selected_hash(0), FLOW_TYPE_L2, 2);
		struct airoha_flow_table_entry *child = new_flow(selected_hash(8191), FLOW_TYPE_L2_SUBFLOW, 3);
		hlist_add_head(&child->l2_subflow_node, &parent->l2_flows);
		struct airoha_flow_table_entry before = *entry, saved_parent = *parent, saved_child = *child;
		add_walk(entry);
		add_walk(parent);
		for (unsigned position = 0; position < ARRAY_SIZE(hashes); ++position)
			CHECK(!airoha_ppe_bank_hash(hashes[position], banks[index]));
		fixture_setup = false;
		operation = RETIRE;
		mutex_lock(&flow_offload_mutex);
		CHECK(airoha_ppe_bank_retire_flows(&ppe, banks[index]) == -EINVAL);
		CHECK(!walk_calls && !walk_starts && !spin_acquires && !reschedules && !frees);
		spin_lock_bh(&ppe_lock);
		airoha_ppe_bank_detach_entry(entry, banks[index]);
		airoha_ppe_bank_detach_entry(parent, banks[index]);
		spin_unlock_bh(&ppe_lock);
		CHECK(!memcmp(entry, &before, sizeof(before)));
		CHECK(!memcmp(parent, &saved_parent, sizeof(saved_parent)));
		CHECK(!memcmp(child, &saved_child, sizeof(saved_child)));
		operation = CLEAR;
		u32 cursor = PPE_SRAM_NUM_ENTRIES;
		active_cursor = &cursor;
		CHECK(airoha_ppe_bank_clear_rows(&ppe, banks[index], &cursor) == -EINVAL);
		CHECK(cursor == PPE_SRAM_NUM_ENTRIES && !writes && !reads);
		cursor = 0;
		CHECK(airoha_ppe_bank_clear_rows(&ppe, banks[index], &cursor) == -EINVAL);
		CHECK(!cursor && !writes && !reads && !reschedules && !frees);
		CHECK(spin_acquires == 1 && !walk_calls);
		active_cursor = NULL;
		mutex_unlock(&flow_offload_mutex);
		operation = IDLE;
		balanced();
		CHECK(retire() == 0 && entry->hash == 0xffff && frees == 1);
	}
}

static void test_resize_and_errors(void)
{
	reset("empty-walk");
	CHECK(retire() == 0 && !spin_acquires && !reschedules);
	const int errors[] = { 0, -EIO, -ENOMEM, -EINVAL };
	for (unsigned error_index = 0; error_index < ARRAY_SIZE(errors); error_index++) {
		for (unsigned position = 0; position < 4; position++) {
			reset("resize-duplicates-hard-error-cleanup-retry");
			struct airoha_flow_table_entry *entries[3];
			struct airoha_flow_table_entry before[3];
			for (unsigned index = 0; index < 3; index++)
				entries[index] = new_flow(index == 2 ? other_hash(8191) : selected_hash(index), FLOW_TYPE_L4, index + 10);
			for (unsigned index = 0; index < 3; index++)
				before[index] = *entries[index];
			for (unsigned index = 0; index <= 3; index++) {
				if (index == position && errors[error_index])
					add_walk(ERR_PTR(errors[error_index]));
				add_walk(ERR_PTR(-EAGAIN));
				if (index < 3) {
					add_walk(entries[index]);
					add_walk(entries[index]);
					add_walk(ERR_PTR(-EAGAIN));
					add_walk(entries[0]);
				}
			}
			CHECK(retire() == errors[error_index]);
			CHECK(spin_acquires == (errors[error_index] ? 0 : 3));
			CHECK(reschedules == spin_acquires && !frees);
			for (unsigned index = 0; index < 3; index++)
				check_entry(entries[index], before[index], !errors[error_index] && index < 2);
			if (errors[error_index]) {
				walk_count = 0;
				for (unsigned index = 0; index < 3; index++)
					add_walk(entries[index]);
				CHECK(retire() == 0 && spin_acquires == 3);
				for (unsigned index = 0; index < 3; index++)
					check_entry(entries[index], before[index], index < 2);
			}
		}
	}
}

static void check_hlist(struct hlist_head *head, unsigned expected)
{
	struct hlist_node **previous = &head->first;
	unsigned count = 0;
	for (struct hlist_node *node = head->first; node; node = node->next) {
		CHECK(++count <= allocation_count && node->pprev == previous);
		previous = &node->next;
	}
	CHECK(count == expected);
}

static void test_l2(void)
{
	const u32 hashes[] = { other_hash(8191), selected_hash(0), selected_hash(4096), selected_hash(8191), other_hash(0), 65535, 16384 };
	for (unsigned order = 0; order < ARRAY_SIZE(hashes); order++) {
		reset("l2-mixed-banks-parent-preserved-resize");
		struct airoha_flow_table_entry *parent = new_flow(selected_hash(0), FLOW_TYPE_L2, 0xabc);
		struct airoha_flow_table_entry *empty = new_flow(65535, FLOW_TYPE_L2, 0xdef);
		struct airoha_flow_table_entry *children[ARRAY_SIZE(hashes)];
		struct airoha_flow_table_entry before[ARRAY_SIZE(hashes)];
		for (unsigned index = 0; index < ARRAY_SIZE(hashes); index++) {
			u32 hash = hashes[(index + order) % ARRAY_SIZE(hashes)];
			children[index] = new_flow(hash, FLOW_TYPE_L2_SUBFLOW, index + 0x100);
			hlist_add_head(&children[index]->l2_subflow_node, &parent->l2_flows);
		}
		for (unsigned index = 0; index < ARRAY_SIZE(hashes); index++)
			before[index] = *children[index];
		struct airoha_flow_table_entry saved_parent = *parent, saved_empty = *empty;
		add_walk(parent);
		add_walk(ERR_PTR(-EAGAIN));
		add_walk(parent);
		add_walk(empty);
		CHECK(retire() == 0 && frees == 3 && spin_acquires == 2 && reschedules == 2);
		saved_parent.l2_flows = parent->l2_flows;
		CHECK(!memcmp(parent, &saved_parent, sizeof(saved_parent)));
		CHECK(!memcmp(empty, &saved_empty, sizeof(saved_empty)));
		for (unsigned index = 0; index < ARRAY_SIZE(hashes); index++) {
			bool retired = in_selected_bank(before[index].hash);
			CHECK(allocated[index + 2].freed == retired);
			if (!retired) {
				CHECK(children[index]->l2_subflow_node.pprev);
				before[index].l2_subflow_node = children[index]->l2_subflow_node;
				check_entry(children[index], before[index], false);
			}
		}
		check_hlist(&parent->l2_flows, 4);
		check_hlist(&candidates, 4);
		CHECK(retire() == 0 && frees == 3 && spin_acquires == 4);
		check_hlist(&parent->l2_flows, 4);
	}
}

static void check_cleared(u32 start, u32 end)
{
	for (u32 row = start; row < end; row++) {
		CHECK(!memcmp(&hardware[selected_hash(row)], &zero_entry, sizeof(zero_entry)));
		CHECK(!memcmp(&shadow[selected_hash(row)], &zero_entry, sizeof(zero_entry)));
	}
}

static void test_clear_guards(void)
{
	const u32 cursors[] = { 0, 8191, 8192, 8193, UINT32_MAX };
	for (unsigned index = 0; index < ARRAY_SIZE(cursors); index++) {
		reset("ownership-and-cursor-guards");
		u32 cursor = cursors[index];
		ppe.ct_owns_sram = false;
		CHECK(clear_rows(&cursor) == -EINVAL && cursor == cursors[index]);
		CHECK(!writes && !reads && !spin_acquires && !reschedules);
		if (cursor > 8192) {
			ppe.ct_owns_sram = true;
			CHECK(clear_rows(&cursor) == -EINVAL && cursor == cursors[index]);
			CHECK(!writes && !reads && !spin_acquires && !reschedules);
		}
	}
	reset("complete-cursor-idempotent");
	u32 cursor = 8192;
	CHECK(clear_rows(&cursor) == 0 && cursor == 8192);
	CHECK(!writes && !reads && !spin_acquires && !reschedules);
	const u32 starts[] = { 0, 1, 4096, 8191 };
	for (unsigned index = 0; index < ARRAY_SIZE(starts); index++) {
		reset("full-and-partial-clear-exact-acks");
		cursor = starts[index];
		ack_unrelated_bits = index & 1;
		CHECK(clear_rows(&cursor) == 0 && cursor == 8192);
		CHECK(writes == 8192 - starts[index] && reads == writes);
		CHECK(write_acks == writes && read_acks == reads);
		CHECK(spin_acquires == writes && reschedules == writes);
		for (u32 row = 0; row < 8192; row++) {
			CHECK(row_writes[row] == (row >= starts[index]));
			CHECK(row_reads[row] == (row >= starts[index]));
		}
		check_cleared(starts[index], 8192);
		unsigned previous = writes;
		CHECK(clear_rows(&cursor) == 0 && writes == previous);
	}
}

static int fault_error(enum fault_kind kind)
{
	return kind == WRITE_TIMEOUT || kind == LOST_WRITE_ACK_APPLIED || kind == READ_TIMEOUT ? -ETIMEDOUT : -EIO;
}

static bool fault_has_read(enum fault_kind kind)
{
	return kind >= READ_TIMEOUT;
}

static void test_clear_faults(void)
{
	const u32 positions[] = { 0, 4096, 8191 };
	for (enum fault_kind kind = WRITE_ERROR; kind < FAULT_COUNT; kind++) {
		unsigned byte_count = kind == READBACK_CORRUPT ? PPE_ENTRY_SIZE : 1;
		for (unsigned position = 0; position < ARRAY_SIZE(positions); position++) {
			for (unsigned byte = 0; byte < byte_count; byte++) {
				char name[100];
				snprintf(name, sizeof(name), "clear-fault-%u-row-%u-byte-%u-retry", kind, positions[position], byte);
				reset(name);
				fault = kind;
				fault_row = positions[position];
				corrupt_byte = byte;
				u32 cursor = 0;
				struct airoha_foe_entry original = hardware[selected_hash(fault_row)];
				CHECK(clear_rows(&cursor) == fault_error(kind) && cursor == fault_row);
				CHECK(writes == fault_row + 1 && reads == fault_row + fault_has_read(kind));
				CHECK(reschedules == fault_row && spin_acquires == writes);
				check_cleared(0, fault_row);
				if (kind == WRITE_ERROR || kind == WRITE_TIMEOUT || kind == WRITE_DROPPED_ACKED)
					CHECK(!memcmp(&original, &hardware[selected_hash(fault_row)], sizeof(original)));
				else
					CHECK(!memcmp(&zero_entry, &hardware[selected_hash(fault_row)], sizeof(zero_entry)));
				for (u32 row = fault_row + 1; row < 8192; row++) {
					CHECK(!row_writes[row] && !row_reads[row]);
					CHECK(hardware[selected_hash(row)].data[79] == 0xa6 && shadow[selected_hash(row)].data[79] == 0x39);
				}
				unsigned completed_writes = writes;
				CHECK(clear_rows(&cursor) == fault_error(kind) && cursor == fault_row);
				CHECK(writes == completed_writes + 1 && reschedules == fault_row);
				fault = NO_FAULT;
				CHECK(clear_rows(&cursor) == 0 && cursor == 8192);
				CHECK(writes == 8194 && reschedules == 8192);
				for (u32 row = 0; row < 8192; row++) {
					CHECK(row_writes[row] == (row == fault_row ? 3 : 1));
					CHECK(row_reads[row] == (row == fault_row ? 1 + 2 * fault_has_read(kind) : 1));
				}
				check_cleared(0, 8192);
			}
		}
	}
}

static void test_multi_call_resume(void)
{
	reset("multi-call-cursor-resume-and-ownership-loss");
	u32 cursor = 0;
	const u32 failures[] = { 0, 19, 4096, 8191 };
	for (unsigned index = 0; index < ARRAY_SIZE(failures); index++) {
		fault_row = failures[index];
		fault = index & 1 ? LOST_WRITE_ACK_APPLIED : READ_TIMEOUT;
		CHECK(clear_rows(&cursor) == -ETIMEDOUT && cursor == fault_row);
		unsigned previous = writes;
		ppe.ct_owns_sram = false;
		CHECK(clear_rows(&cursor) == -EINVAL && writes == previous && cursor == fault_row);
		ppe.ct_owns_sram = true;
	}
	fault = NO_FAULT;
	CHECK(clear_rows(&cursor) == 0 && cursor == 8192 && writes == 8196);
	check_cleared(0, 8192);
	for (u32 row = 0; row < 8192; row++) {
		bool failed = row == 0 || row == 19 || row == 4096 || row == 8191;
		CHECK(row_writes[row] == (failed ? 2 : 1));
	}
}

#include "reuse_test.inc"

int main(void)
{
	scenario = "hash-boundaries";
	CHECK(sizeof(struct airoha_foe_entry) == 80 && PPE_SRAM_NUM_ENTRIES == 8192);
	for (selected_bank = 0; selected_bank < 2; ++selected_bank) {
		test_invalid_banks();
		test_hash_and_old_cookies();
		test_resize_and_errors();
		test_l2();
		test_cookie_reuse();
		test_l2_reuse();
		test_clear_guards();
		test_clear_faults();
		test_multi_call_resume();
	}
	cleanup();
	printf("{\"scenarios\":%u,\"checks\":%lu,\"banks\":2,\"row_bytes\":80,\"bank_rows\":8192}\n", scenarios, checks);
	return 0;
}
