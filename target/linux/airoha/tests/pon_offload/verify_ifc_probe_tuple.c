static unsigned int tuple_cases, tuple_transport_faults, tuple_blocked_retries;
static unsigned int tuple_orphan_faults, tuple_release_faults, tuple_readback_faults;
static unsigned int tuple_tamper_cases, tuple_guard_cases, tuple_late_consumer_faults;
static unsigned int tuple_capacity_cases, tuple_saved_cleared_faults;
static unsigned int tuple_recovery_faults, tuple_input_cases, tuple_ownership_cases;
static unsigned int tuple_failed_drain_cases, tuple_worker_cases;

static void tuple_original_lut(void)
{
	for (unsigned int slot = 0; slot < 32; slot++)
		assert(!memcmp(mock.table[1][slot][0], mock.original_lut[slot], sizeof(mock.original_lut[slot])));
}

static void tuple_prepare(struct fixture *fixture, unsigned int first, unsigned int second,
			  unsigned int capacity)
{
	u32 guards[2][2];
	unsigned int free_slots = 0;
	unsigned int indices[] = { first, second };

	initialize(fixture);
	assert(first < 32 && second < 32 && first != second && capacity <= 30);
	for (unsigned int family = 0; family < 2; family++)
		memcpy(guards[family], mock.table[1][31 - family][0], sizeof(guards[family]));
	for (unsigned int slot = 0; slot < 32; slot++) {
		mock.table[1][slot][0][0] = 0xa5000000 | slot;
		mock.table[1][slot][0][1] = 0x1200 | slot;
		if (slot != first && slot != second && free_slots++ >= capacity)
			mock.table[1][slot][0][1] |= BIT(15);
	}
	for (unsigned int family = 0; family < 2; family++) {
		unsigned int slot = indices[family];

		fixture->ppe.ct_ifc.rule[family].lut_index = slot;
		memcpy(mock.table[1][slot][0], guards[family], sizeof(guards[family]));
		mock.table[0][CT_IFC_RULE(family)][4][0] = BIT(slot);
		mock.table[0][CT_IFC_RULE(family)][4][1] = BIT(slot);
	}
	for (unsigned int slot = 0; slot < 32; slot++)
		memcpy(mock.original_lut[slot], mock.table[1][slot][0], sizeof(mock.original_lut[slot]));
	fixture->ppe.ct_pair_policy_allowed = fixture->ppe.ct_fe.active = true;
	assert(store(fixture, "cover 1") == 7);
	reset_counts();
	mock.tuple_watch = true;
}

static void tuple_check_live(const struct fixture *fixture)
{
	const struct airoha_ct_ifc_pool *pool = &fixture->ppe.ct_pon_ifc_pool;
	u32 masks = 0;
	u32 short_mask = BIT(fixture->ppe.ct_ifc.rule[0].lut_index) |
			 BIT(fixture->ppe.ct_ifc.rule[1].lut_index);
	static const u32 expected[2][11][2] = {
		{ { 0xc0000202, 0xe003 }, { 0xc0000201, 0xe004 },
		  { 0xff0011, 0xc018 }, { 0xffffc001, 0xc01c }, { 0xffffc000, 0xc01d } },
		{ { 2, 0xe005 }, { 0, 0xe006 }, { 0, 0xe007 }, { 0x20010db8, 0xe008 },
		  { 1, 0xe009 }, { 0, 0xe00a }, { 0, 0xe00b }, { 0x20010db8, 0xe00c },
		  { 0xff0011, 0xc019 }, { 0xffffc001, 0xc01c }, { 0xffffc000, 0xc01d } },
	};

	assert(fixture->ppe.ct_pon_ifc_tuple && !fixture->ppe.ct_pon_qualified);
	assert(fixture->ppe.ct_pair_policy_allowed && fixture->ppe.ct_fe.active);
	assert(fixture->ppe.ct_pon_ifc_cover == BIT(1));
	assert(fixture->ppe.ct_pon_ifc_services[0] == 0x2134);
	assert(fixture->ppe.ct_pon_ifc.active == 15);
	assert(!pool->pending && !pool->releasing && !airoha_ct_ifc_pool_orphans(pool));
	for (unsigned int family = 0; family < 2; family++) {
		const struct airoha_ct_ifc_pool_lease *lease = &fixture->ppe.ct_pon_ifc_lease[family];
		unsigned int row = 56 + family;
		u32 mask = 0;

		assert(airoha_ct_ifc_pool_has(pool, lease));
		assert(lease->count == (family ? 11 : 5));
		for (unsigned int index = 0; index < lease->count; index++) {
			unsigned int slot = lease->slot[index];

			assert(slot < 32);
			assert(!memcmp(mock.table[1][slot][0], expected[family][index], sizeof(expected[0][0])));
			assert(!memcmp(pool->words[slot], expected[family][index], sizeof(expected[0][0])));
			assert(!memcmp(pool->saved[slot], mock.original_lut[slot], sizeof(pool->saved[slot])));
			mask |= BIT(slot);
		}
		assert(mask == lease->mask && !(mask & short_mask));
		masks |= mask;
		assert(mock.table[0][row][0][0] == BIT(2) && mock.table[0][row][0][1] == U32_MAX);
		assert(mock.table[0][row][4][0] == mask);
		assert(mock.table[0][row][4][1] == (mask | BIT(fixture->ppe.ct_ifc.rule[family].lut_index)));
		assert(mock.table[0][row][5][0] == (family ? ETH_P_IPV6 : ETH_P_IP));
		assert(mock.table[0][row][5][1] == 0xffff);
		assert(mock.table[0][row][7][0] == 0x21340000 && mock.table[0][row][7][1] == 0xffff0430);
		assert(!mock.table[0][row][8][0] && mock.table[0][row][8][1] == 0xc0);
		assert(mock.table[2][row][1][2] == 2 << 10);
		assert(mock.table[2][row][2][0] == 0xd0000000);
	}
	assert(pool->reserved == masks && pool->dirty == masks && __builtin_popcount(masks) == 14);
	for (unsigned int slot = 0; slot < 32; slot++) {
		unsigned int refs = !!(fixture->ppe.ct_pon_ifc_lease[0].mask & BIT(slot)) +
				    !!(fixture->ppe.ct_pon_ifc_lease[1].mask & BIT(slot));
		assert(pool->refs[slot] == refs);
		if (!refs)
			assert(!memcmp(mock.table[1][slot][0], mock.original_lut[slot], sizeof(mock.original_lut[slot])));
	}
}

static void tuple_install(struct fixture *fixture)
{
	tuple_prepare(fixture, 3, 11, 30);
	assert(store(fixture, "tuple 0 0x2134") == 14);
	tuple_check_live(fixture);
	reset_counts();
}

static void tuple_finish(struct fixture *fixture)
{
	mock.fail_at = 0;
	mock.release = true;
	assert(store(fixture, "off") == 3);
	check_restored(fixture);
	tuple_original_lut();
	assert(!fixture->eth.ct_ifc_command_pending && !mock.busy);
}

static void tuple_lifecycle(void)
{
	static const unsigned int indices[][2] = { { 31, 30 }, { 0, 1 }, { 3, 11 }, { 17, 5 } };
	const char *overwrites[] = { "set 0 0xa134", "cover 0", "source 2", "only 2", "absent 2",
				     "tuple 0 0xa134" };
	struct fixture fixture;

	for (unsigned int index = 0; index < ARRAY_SIZE(indices); index++) {
		tuple_prepare(&fixture, indices[index][0], indices[index][1], 30);
		assert(store(&fixture, "tuple 0 0x2134") == 14);
		tuple_check_live(&fixture);
		fixture.ppe.ct_fe.active = fixture.ppe.ct_pair_policy_allowed = false;
		reset_counts();
		for (unsigned int command = 0; command < ARRAY_SIZE(overwrites); command++) {
			assert(store(&fixture, overwrites[command]) == -EBUSY);
			assert(!mock.commands && !mock.table_writes);
			tuple_guard_cases++;
		}
		fixture.ppe.ct_fe.active = fixture.ppe.ct_pair_policy_allowed = true;
		assert(store(&fixture, "route") == 5);
		assert(fixture.ppe.ct_pon_ifc_route_owned);
		mock.enforce_cpu_before_table = true;
		assert(store(&fixture, "clear 1") == 7);
		assert(!fixture.ppe.ct_pon_ifc_route_owned && !fixture.ppe.ct_pon_ifc_cover);
		assert(fixture.ppe.ct_pon_ifc_tuple && fixture.ppe.ct_pon_ifc.active == 3);
		assert(__builtin_popcount(fixture.ppe.ct_pon_ifc_pool.reserved) == 14);
		assert(store(&fixture, "route") == -ESHUTDOWN);
		assert(store(&fixture, "set 1 0xa134") == 12);
		assert(fixture.ppe.ct_pon_ifc_tuple && !fixture.ppe.ct_pon_ifc_cover);
		assert(store(&fixture, "route") == -ESHUTDOWN);
		assert(store(&fixture, "cover 1") == 7);
		tuple_check_live(&fixture);
		assert(store(&fixture, "route") == 5);
		assert(store(&fixture, "clear 0") == 7);
		assert(!fixture.ppe.ct_pon_ifc_tuple && !fixture.ppe.ct_pon_ifc_pool.reserved);
		assert(fixture.ppe.ct_pon_ifc.active == 12 && fixture.ppe.ct_pon_ifc_cover == 2);
		tuple_original_lut();
		assert(store(&fixture, "tuple 0 0x2134") == 14);
		tuple_check_live(&fixture);
		tuple_finish(&fixture);
		tuple_cases++;
	}
}

static void tuple_capacity(void)
{
	struct fixture fixture;

	for (unsigned int capacity = 0; capacity <= 14; capacity++) {
		tuple_prepare(&fixture, 3, 11, capacity);
		assert(store(&fixture, "tuple 0 0x2134") == (capacity < 14 ? -ENOSPC : 14));
		if (capacity < 14) {
			assert(!mock.table_writes && !fixture.ppe.ct_pon_ifc_pool.reserved);
			assert(!fixture.ppe.ct_pon_ifc_pool.leases && !fixture.ppe.ct_pon_ifc_tuple);
			assert(!fixture.ppe.ct_pon_ifc_errors && !fixture.eth.ct_cpu_fallback);
			tuple_original_lut();
		} else {
			tuple_check_live(&fixture);
		}
		tuple_finish(&fixture);
		tuple_capacity_cases++;
		tuple_cases++;
	}
	tuple_prepare(&fixture, 3, 11, 30);
	for (unsigned int slot = 0; slot < 16; slot++) {
		if (slot == 3 || slot == 11)
			continue;
		mock.table[1][slot][0][1] |= BIT(15);
		memcpy(mock.original_lut[slot], mock.table[1][slot][0], sizeof(mock.original_lut[slot]));
	}
	mock.table[1][16][0][1] |= BIT(15);
	mock.table[1][17][0][1] |= BIT(15);
	memcpy(mock.original_lut[16], mock.table[1][16][0], sizeof(mock.original_lut[16]));
	memcpy(mock.original_lut[17], mock.table[1][17][0], sizeof(mock.original_lut[17]));
	assert(store(&fixture, "tuple 0 0x2134") == 14);
	tuple_check_live(&fixture);
	assert(fixture.ppe.ct_pon_ifc_pool.reserved == GENMASK(31, 18));
	assert(store(&fixture, "route") == 5);
	tuple_finish(&fixture);
	tuple_capacity_cases++;
	tuple_cases++;
}

static void tuple_inputs(void)
{
	const char *invalid[] = {
		"tuple", "tuple 0", "tuple 1 0x2134", "tuple 2 0x2134", "tuple 0 0",
		"tuple 0 65536", "tuple -1 0x2134", "tuple 0 -1", "tuple 0 0x2134 extra",
		"tuple 0 nope", "tuple 0 4294967296", "tuple 4294967296 0x2134",
	};
	struct fixture fixture;

	for (unsigned int index = 0; index < ARRAY_SIZE(invalid); index++) {
		tuple_prepare(&fixture, 3, 11, 30);
		assert(store(&fixture, invalid[index]) == -EINVAL);
		assert(!mock.table_writes && !fixture.ppe.ct_pon_ifc_pool.reserved);
		tuple_finish(&fixture);
		tuple_input_cases++;
		tuple_cases++;
	}
	for (unsigned int state = 0; state < 11; state++) {
		tuple_prepare(&fixture, 3, 11, 30);
		switch (state) {
		case 0: fixture.ppe.ct_pon_ifc_registered = false; break;
		case 1: fixture.ppe.ct_pon_ifc_work_stopping = true; break;
		case 2: fixture.ppe.ct_host_ppe = false; break;
		case 3: fixture.ppe.ct_stopping = true; break;
		case 4: fixture.ppe.ct_pon_qualified = true; break;
		case 5: fixture.eth.ct_cpu_fallback = true; break;
		case 6: fixture.eth.ct_ifc_cpu_port_failed = true; break;
		case 7: fixture.eth.ct_ifc_pon_ready = false; break;
		case 8: fixture.ppe.ct_pon_ifc.pending = true; break;
		case 9: fixture.eth.ct_ifc_command_pending = true; break;
		case 10: fixture.ppe.ct_pon_ifc.saved_valid = false; break;
		}
		assert(airoha_ct_pon_ifc_cpu_tuple(&fixture.ppe, 0, 0x2134) == -ESHUTDOWN);
		assert(!mock.commands && !mock.table_writes && !fixture.ppe.ct_pon_ifc_pool.reserved);
		fixture.ppe.ct_pon_ifc_registered = true;
		fixture.ppe.ct_pon_ifc_work_stopping = false;
		fixture.ppe.ct_pon_qualified = false;
		fixture.ppe.ct_pon_ifc.saved_valid = true;
		tuple_finish(&fixture);
		tuple_input_cases++;
		tuple_cases++;
	}
	for (unsigned int state = 0; state < 4; state++) {
		tuple_prepare(&fixture, 3, 11, 30);
		if (!state)
			fixture.ppe.ct_pon_ifc_cover = 0;
		else if (state == 1)
			fixture.ppe.ct_pon_ifc.active |= 1;
		else if (state == 2)
			fixture.ppe.ct_pon_ifc.dirty |= 1;
		else
			assert(store(&fixture, "set 0 0xa134") == 12);
		reset_counts();
		assert(store(&fixture, "tuple 0 0x2134") == -EBUSY);
		assert(!mock.commands && !mock.table_writes);
		fixture.ppe.ct_pon_ifc.active &= ~3;
		tuple_finish(&fixture);
		tuple_input_cases++;
		tuple_cases++;
	}
}

static void tuple_ownership(void)
{
	const char *overwrites[] = { "set 0 0xa134", "cover 0", "source 2", "only 2", "absent 2" };
	struct fixture fixture;

	for (unsigned int state = 0; state < 9; state++) {
		tuple_prepare(&fixture, 3, 11, 30);
		fixture.ppe.ct_fe.active = fixture.ppe.ct_pair_policy_allowed = false;
		switch (state) {
		case 0: fixture.ppe.ct_pon_ifc_tuple = true; break;
		case 1: fixture.ppe.ct_pon_ifc_pool.pending = true; break;
		case 2: fixture.ppe.ct_pon_ifc_pool.reserved = BIT(31); break;
		case 3: fixture.ppe.ct_pon_ifc_pool.dirty = BIT(31); break;
		case 4: fixture.ppe.ct_pon_ifc_pool.leases = &fixture.ppe.ct_pon_ifc_lease[0]; break;
		case 5: fixture.ppe.ct_pon_ifc_pool.releasing = &fixture.ppe.ct_pon_ifc_lease[0]; break;
		case 6: fixture.ppe.ct_pon_ifc_lease[0].count = 5; break;
		case 7: fixture.ppe.ct_pon_ifc_lease[1].count = 11; break;
		case 8:
			assert(store(&fixture, "tuple 0 0x2134") == 14);
			fixture.ppe.ct_pon_ifc_tuple = false;
			reset_counts();
			break;
		}
		for (unsigned int command = 0; command < ARRAY_SIZE(overwrites); command++) {
			assert(store(&fixture, overwrites[command]) == -EBUSY);
			assert(!mock.commands && !mock.table_writes);
			tuple_ownership_cases++;
		}
		if (state < 8) {
			fixture.ppe.ct_pon_ifc_tuple = false;
			memset(&fixture.ppe.ct_pon_ifc_pool, 0, sizeof(fixture.ppe.ct_pon_ifc_pool));
			memset(fixture.ppe.ct_pon_ifc_lease, 0, sizeof(fixture.ppe.ct_pon_ifc_lease));
		}
		tuple_finish(&fixture);
		tuple_cases++;
	}
}

static const char *tuple_operations[] = { "tuple 0 0x2134", "route", "clear 0", "clear 1", "off" };

static void tuple_operation_prepare(struct fixture *fixture, unsigned int operation)
{
	if (!operation)
		tuple_prepare(fixture, 3, 11, 30);
	else
		tuple_install(fixture);
	if (operation >= 2) {
		assert(store(fixture, "route") == 5);
		reset_counts();
		mock.enforce_cpu_before_table = true;
	}
}

static void tuple_fault_case(unsigned int operation, unsigned int position, enum fault mode)
{
	struct fixture fixture;
	struct airoha_ct_ifc_pool saved_pool;
	struct airoha_ct_ifc_pool_lease saved_lease[2];
	unsigned int data_writes, control_writes;

	tuple_operation_prepare(&fixture, operation);
	mock.fail_at = position;
	mock.fault = mode;
	assert(store(&fixture, tuple_operations[operation]) < 0);
	assert(mock.commands == position);
	if (mode != READBACK)
		assert(mock.busy && fixture.eth.ct_ifc_command_pending);
	assert(!fixture.ppe.ct_pon_ifc_route_owned && !fixture.ppe.ct_pon_qualified);
	assert(fixture.ppe.ct_pon_ifc_errors && fixture.ppe.ct_pon_ifc_work.scheduled);
	if (airoha_ct_ifc_pool_orphans(&fixture.ppe.ct_pon_ifc_pool) &&
	    fixture.ppe.ct_pon_ifc_lease[0].count && !fixture.ppe.ct_pon_ifc_lease[1].count)
		tuple_orphan_faults++;
	if (fixture.ppe.ct_pon_ifc_pool.releasing) {
		tuple_release_faults++;
		if (!fixture.ppe.ct_pon_ifc.saved_valid)
			tuple_saved_cleared_faults++;
	}
	if (mode == DEFERRED && (mock.command & BIT(1)) &&
	    ((mock.command >> 4) & 3) == 2 && ((mock.command >> 8) & 15) == 2 &&
	    ((mock.command >> 16) & 63) < 58)
		tuple_late_consumer_faults++;
	if (mode != READBACK) {
		assert(store(&fixture, "off") == -ETIMEDOUT);
		saved_pool = fixture.ppe.ct_pon_ifc_pool;
		memcpy(saved_lease, fixture.ppe.ct_pon_ifc_lease, sizeof(saved_lease));
		data_writes = mock.data_writes;
		control_writes = mock.control_writes;
		for (unsigned int attempt = 0; attempt < 2; attempt++) {
			assert(store(&fixture, "off") == -ETIMEDOUT);
			assert(!memcmp(&saved_pool, &fixture.ppe.ct_pon_ifc_pool, sizeof(saved_pool)));
			assert(!memcmp(saved_lease, fixture.ppe.ct_pon_ifc_lease, sizeof(saved_lease)));
			assert(mock.data_writes == data_writes && mock.control_writes == control_writes);
			tuple_blocked_retries++;
		}
		tuple_transport_faults++;
	} else {
		tuple_readback_faults++;
	}
	tuple_finish(&fixture);
	tuple_cases++;
}

static void tuple_io_faults(void)
{
	struct fixture fixture;
	u32 commands[512];
	unsigned int count;

	for (unsigned int operation = 0; operation < ARRAY_SIZE(tuple_operations); operation++) {
		tuple_operation_prepare(&fixture, operation);
		assert(store(&fixture, tuple_operations[operation]) == (ssize_t)strlen(tuple_operations[operation]));
		count = mock.trace_count;
		assert(count && count < ARRAY_SIZE(commands));
		for (unsigned int index = 0; index < count; index++)
			commands[index] = mock.trace[index].command;
		tuple_finish(&fixture);
		for (unsigned int position = 1; position <= count; position++) {
			for (unsigned int mode = BEFORE; mode <= DEFERRED; mode++)
				tuple_fault_case(operation, position, mode);
			if (position > 1 && !(commands[position - 1] & BIT(1)) &&
			    commands[position - 2] == (commands[position - 1] | BIT(1)))
				tuple_fault_case(operation, position, READBACK);
		}
	}
	assert(tuple_orphan_faults && tuple_release_faults && tuple_saved_cleared_faults);
	assert(tuple_late_consumer_faults && tuple_readback_faults);
}

static void tuple_tampering(void)
{
	struct fixture fixture;

	for (unsigned int family = 0; family < 2; family++) {
		for (unsigned int stage = 0; stage < 2; stage++) {
			for (unsigned int word = 0; word < 2; word++) {
				unsigned int slot;
				u32 original;

				if (stage)
					tuple_install(&fixture);
				else
					tuple_prepare(&fixture, 3, 11, 30);
				slot = fixture.ppe.ct_ifc.rule[family].lut_index;
				original = mock.table[1][slot][0][word];
				mock.table[1][slot][0][word] ^= 1;
				assert(store(&fixture, stage ? "route" : "tuple 0 0x2134") == -EUCLEAN);
				assert(!fixture.ppe.ct_pon_ifc_route_owned && !mock.table_writes);
				mock.table[1][slot][0][word] = original;
				tuple_finish(&fixture);
				tuple_tamper_cases++;
				tuple_cases++;
			}
		}
		for (unsigned int word = 0; word < 2; word++) {
			tuple_prepare(&fixture, 3, 11, 30);
			mock.table[0][58 + family][8][word] ^= 0x40;
			assert(store(&fixture, "tuple 0 0x2134") == -EUCLEAN);
			assert(!mock.table_writes && !fixture.ppe.ct_pon_ifc_pool.reserved);
			tuple_finish(&fixture);
			tuple_tamper_cases++;
			tuple_cases++;
		}
		for (unsigned int index = 0; index < (family ? 11U : 5U); index++) {
			for (unsigned int word = 0; word < 2; word++) {
				unsigned int slot;

				tuple_install(&fixture);
				slot = fixture.ppe.ct_pon_ifc_lease[family].slot[index];
				mock.table[1][slot][0][word] ^= 1;
				assert(store(&fixture, "route") == -EUCLEAN);
				assert(!fixture.ppe.ct_pon_ifc_route_owned && !mock.table_writes);
				tuple_finish(&fixture);
				tuple_tamper_cases++;
				tuple_cases++;
			}
		}
		for (unsigned int page = 0; page < 9; page++) {
			for (unsigned int word = 0; word < 2; word++) {
				u32 mask;

				tuple_install(&fixture);
				mask = mock.table[0][56 + family][page][1];
				if (!word && !mask) {
					tuple_finish(&fixture);
					continue;
				}
				mock.table[0][56 + family][page][word] ^= word ? 1 : mask & (0U - mask);
				assert(store(&fixture, "route") == -EUCLEAN);
				assert(!fixture.ppe.ct_pon_ifc_route_owned && !mock.table_writes);
				tuple_finish(&fixture);
				tuple_tamper_cases++;
				tuple_cases++;
			}
		}
		for (unsigned int page = 0; page < 3; page++) {
			for (unsigned int word = 0; word < page_words(2, page); word++) {
				tuple_install(&fixture);
				mock.table[2][56 + family][page][word] ^= 1;
				assert(store(&fixture, "route") == -EUCLEAN);
				assert(!fixture.ppe.ct_pon_ifc_route_owned && !mock.table_writes);
				tuple_finish(&fixture);
				tuple_tamper_cases++;
				tuple_cases++;
			}
		}
	}
}

static void tuple_recovery_prepare(struct fixture *fixture, unsigned int operation,
				   unsigned int position)
{
	bool acknowledged;

	tuple_operation_prepare(fixture, operation);
	mock.fail_at = position;
	mock.fault = DEFERRED;
	assert(store(fixture, tuple_operations[operation]) == -ETIMEDOUT);
	assert(mock.busy && mock.late);
	mock.release = true;
	spin_lock_bh(&ppe_lock);
	assert(!airoha_ct_ifc_command_drain(&fixture->eth));
	spin_unlock_bh(&ppe_lock);
	assert(!mock.busy && !fixture->eth.ct_ifc_command_pending);
	acknowledged = mock.cpu_acknowledged;
	reset_counts();
	mock.cpu_acknowledged = acknowledged;
}

static void tuple_recovery(void)
{
	struct fixture fixture;
	unsigned int failures[2] = {}, counts[2], operations[] = { 0, 4 };
	u32 commands[512];

	for (unsigned int scenario = 0; scenario < ARRAY_SIZE(operations); scenario++) {
		tuple_operation_prepare(&fixture, operations[scenario]);
		assert(store(&fixture, tuple_operations[operations[scenario]]) > 0);
		for (unsigned int index = 0; index < mock.trace_count; index++) {
			u32 command = mock.trace[index].command;
			unsigned int field = mock.trace[index].words[1] & 0x3f;

			if (!(command & BIT(1)) || ((command >> 4) & 3) != 1)
				continue;
			if ((!scenario && field == 5) || scenario)
				failures[scenario] = index + 1;
			if (!scenario && failures[scenario])
				break;
		}
		assert(failures[scenario]);
		tuple_finish(&fixture);
		tuple_recovery_prepare(&fixture, operations[scenario], failures[scenario]);
		if (!scenario) {
			assert(airoha_ct_ifc_pool_orphans(&fixture.ppe.ct_pon_ifc_pool));
			assert(fixture.ppe.ct_pon_ifc_lease[0].count == 5 && !fixture.ppe.ct_pon_ifc_lease[1].count);
		} else {
			assert(!fixture.ppe.ct_pon_ifc.saved_valid && fixture.ppe.ct_pon_ifc_pool.releasing);
		}
		assert(store(&fixture, "off") == 3);
		check_restored(&fixture);
		tuple_original_lut();
		counts[scenario] = mock.trace_count;
		assert(counts[scenario] && counts[scenario] < ARRAY_SIZE(commands));
		for (unsigned int index = 0; index < counts[scenario]; index++)
			commands[index] = mock.trace[index].command;
		for (unsigned int position = 1; position <= counts[scenario]; position++) {
			for (unsigned int mode = BEFORE; mode <= READBACK; mode++) {
				if (mode == READBACK && (position == 1 || (commands[position - 1] & BIT(1)) ||
				    commands[position - 2] != (commands[position - 1] | BIT(1))))
					continue;
				tuple_recovery_prepare(&fixture, operations[scenario], failures[scenario]);
				mock.fail_at = position;
				mock.fault = mode;
				assert(store(&fixture, "off") < 0);
				assert(mock.commands == position);
				if (mode != READBACK) {
					unsigned int data = mock.data_writes, control = mock.control_writes;
					struct airoha_ct_ifc_pool saved = fixture.ppe.ct_pon_ifc_pool;

					assert(store(&fixture, "off") == -ETIMEDOUT);
					assert(mock.data_writes == data && mock.control_writes == control);
					assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc_pool, sizeof(saved)));
				}
				tuple_finish(&fixture);
				tuple_recovery_faults++;
				tuple_cases++;
			}
		}
	}
}

static void tuple_failed_drain(void)
{
	struct fixture fixture;
	unsigned int operations[] = { 0, 0, 2, 4 };
	unsigned int failures[4] = {};

	for (unsigned int scenario = 0; scenario < ARRAY_SIZE(operations); scenario++) {
		struct airoha_ct_ifc_pool saved;
		struct airoha_ct_ifc_pool_lease leases[2];
		u32 applied[3], command;
		unsigned int data, control, writes, bank, row, page;

		tuple_operation_prepare(&fixture, operations[scenario]);
		assert(store(&fixture, tuple_operations[operations[scenario]]) > 0);
		for (unsigned int index = 0; index < mock.trace_count; index++) {
			command = mock.trace[index].command;
			bank = (command >> 4) & 3;
			row = (command >> 16) & 63;
			page = (command >> 8) & 15;
			if (!(command & BIT(1)))
				continue;
			if ((!scenario && bank == 1 && (mock.trace[index].words[1] & 0x3f) == 5) ||
			    (scenario == 1 && bank == 2 && row == 56 && page == 2 &&
			     (mock.trace[index].words[0] & BIT(31))) ||
			    (scenario == 2 && bank == 2 && row == 56 && page == 2 &&
			     !mock.trace[index].words[0]) || (scenario == 3 && bank == 1))
				failures[scenario] = index + 1;
			if (scenario < 3 && failures[scenario])
				break;
		}
		assert(failures[scenario]);
		tuple_finish(&fixture);
		tuple_operation_prepare(&fixture, operations[scenario]);
		mock.fault = DEFERRED;
		mock.fail_at = failures[scenario];
		assert(store(&fixture, tuple_operations[operations[scenario]]) == -ETIMEDOUT);
		assert(mock.busy && mock.late && fixture.eth.ct_ifc_command_pending);
		command = mock.command;
		bank = (command >> 4) & 3;
		row = (command >> 16) & 63;
		page = (command >> 8) & 15;
		for (unsigned int word = 0; word < page_words(bank, page); word++)
			applied[word] = mock.registers[CT_IFC_DATA(word) / 4];
		saved = fixture.ppe.ct_pon_ifc_pool;
		memcpy(leases, fixture.ppe.ct_pon_ifc_lease, sizeof(leases));
		data = mock.data_writes;
		control = mock.control_writes;
		writes = mock.table_writes;
		mock.complete_without_done = true;
		for (unsigned int attempt = 0; attempt < 3; attempt++) {
			assert(store(&fixture, "off") == -ETIMEDOUT);
			assert(mock.busy && !mock.late && fixture.eth.ct_ifc_command_pending);
			assert(!memcmp(&saved, &fixture.ppe.ct_pon_ifc_pool, sizeof(saved)));
			assert(!memcmp(leases, fixture.ppe.ct_pon_ifc_lease, sizeof(leases)));
			assert(mock.data_writes == data && mock.control_writes == control);
			assert(mock.table_writes == writes + 1);
			assert(!memcmp(mock.table[bank][row][page], applied, page_words(bank, page) * sizeof(u32)));
			tuple_failed_drain_cases++;
		}
		tuple_finish(&fixture);
		tuple_cases++;
	}
}

static void tuple_worker_run(struct fixture *fixture)
{
	assert(rtnl && flow_offload_mutex.held && !worker_context && !lock_depth);
	flow_offload_mutex.held = rtnl = false;
	worker_context = true;
	airoha_ct_pon_ifc_repair_work(&fixture->ppe.ct_pon_ifc_work.work);
	assert(!rtnl && !flow_offload_mutex.held && !lock_depth && !rcu_depth);
	worker_context = false;
	flow_offload_mutex.held = rtnl = true;
}

static void tuple_worker(void)
{
	struct fixture fixture;

	for (unsigned int scenario = 0; scenario < 4; scenario++) {
		unsigned int scheduled;

		tuple_install(&fixture);
		assert(store(&fixture, "route") == 5);
		reset_counts();
		mock.enforce_cpu_before_table = true;
		scheduled = fixture.ppe.ct_pon_ifc_work.scheduled;
		if (scenario == 1) {
			fixture.ppe.ct_pon_ifc_work_stopping = true;
			tuple_worker_run(&fixture);
			assert(!mock.commands && !mock.route_writes && !mock.table_writes);
			assert(fixture.ppe.ct_pon_ifc_work.scheduled == scheduled);
			tuple_check_live(&fixture);
			fixture.ppe.ct_pon_ifc_work_stopping = false;
		} else if (scenario >= 2) {
			mock.fail_at = 1;
			mock.fault = DEFERRED;
			tuple_worker_run(&fixture);
			assert(mock.busy && fixture.eth.ct_ifc_command_pending);
			assert(fixture.ppe.ct_pon_ifc_work.scheduled == scheduled + 2);
			assert(fixture.ppe.ct_pon_ifc_lease[0].count == 5 &&
			       fixture.ppe.ct_pon_ifc_lease[1].count == 11);
			assert(__builtin_popcount(fixture.ppe.ct_pon_ifc_pool.reserved) == 14);
			if (scenario == 3) {
				unsigned int data = mock.data_writes, control = mock.control_writes;

				scheduled = fixture.ppe.ct_pon_ifc_work.scheduled;
				fixture.ppe.ct_pon_ifc_work_stopping = true;
				tuple_worker_run(&fixture);
				assert(mock.data_writes == data && mock.control_writes == control);
				assert(fixture.ppe.ct_pon_ifc_work.scheduled == scheduled);
				fixture.ppe.ct_pon_ifc_work_stopping = false;
			}
			mock.release = true;
			mock.fail_at = 0;
		}
		tuple_worker_run(&fixture);
		check_restored(&fixture);
		tuple_original_lut();
		assert(!fixture.eth.ct_ifc_command_pending && !mock.busy);
		scheduled = fixture.ppe.ct_pon_ifc_work.scheduled;
		reset_counts();
		tuple_worker_run(&fixture);
		assert(!mock.commands && !mock.route_writes && !mock.table_writes);
		assert(fixture.ppe.ct_pon_ifc_work.scheduled == scheduled);
		tuple_worker_cases++;
		tuple_cases++;
	}
}

static void tuple_tests(void)
{
	tuple_lifecycle();
	tuple_capacity();
	tuple_inputs();
	tuple_ownership();
	tuple_io_faults();
	tuple_tampering();
	tuple_recovery();
	tuple_failed_drain();
	tuple_worker();
	printf("{\"passed\":true,\"tuple_cases\":%u,\"tuple_transport_faults\":%u,"
	       "\"tuple_blocked_retries\":%u,\"tuple_orphan_faults\":%u,\"tuple_release_faults\":%u,"
	       "\"tuple_readback_faults\":%u,\"tuple_tamper_cases\":%u,\"tuple_guard_cases\":%u,"
	       "\"tuple_late_consumer_faults\":%u,\"tuple_capacity_cases\":%u,\"tuple_saved_cleared_faults\":%u,"
	       "\"tuple_recovery_faults\":%u,\"tuple_input_cases\":%u,\"tuple_ownership_cases\":%u,"
	       "\"tuple_failed_drain_cases\":%u,\"tuple_worker_cases\":%u}\n",
	       tuple_cases, tuple_transport_faults, tuple_blocked_retries, tuple_orphan_faults,
	       tuple_release_faults, tuple_readback_faults, tuple_tamper_cases, tuple_guard_cases,
	       tuple_late_consumer_faults, tuple_capacity_cases, tuple_saved_cleared_faults,
	       tuple_recovery_faults, tuple_input_cases, tuple_ownership_cases,
	       tuple_failed_drain_cases, tuple_worker_cases);
}
