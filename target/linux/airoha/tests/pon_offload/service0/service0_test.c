#include "probe_fixture.inc"

static unsigned int service_cases, match_cases, timeout_cases, retry_cases;
static unsigned int lease_retention_cases, readback_cases, guard_cases, worker_cases;

static void command_ok(struct fixture *fixture, const char *command)
{
	assert(store(fixture, command) == (ssize_t)strlen(command));
	assert(!fixture->ppe.ct_pon_qualified);
}

static void service_command(struct fixture *fixture, const char *verb,
			    unsigned int slot, unsigned int service)
{
	char command[64];

	snprintf(command, sizeof(command), "%s %u %u", verb, slot, service);
	command_ok(fixture, command);
}

static int tuple_health(struct fixture *fixture)
{
	int result;

	spin_lock_bh(&ppe_lock);
	result = airoha_ct_pon_ifc_tuple_check(&fixture->ppe);
	spin_unlock_bh(&ppe_lock);
	return result;
}

static bool row_match(unsigned int row, unsigned int service, unsigned int family, u32 lut)
{
	u32 input[9] = { [0] = BIT(2), [4] = lut, [5] = family ? ETH_P_IPV6 : ETH_P_IP,
			 [7] = service << 16 };

	assert(mock.table[2][row][2][0] == (BIT(31) | BIT(30) | BIT(28)));
	for (unsigned int page = 0; page < ARRAY_SIZE(input); page++)
		if ((input[page] ^ mock.table[0][row][page][0]) & mock.table[0][row][page][1])
			return false;
	return true;
}

static void check_service(struct fixture *fixture, unsigned int slot, unsigned int service,
			  bool tuple, bool sweep)
{
	assert((fixture->ppe.ct_pon_ifc.active & (3 << (slot * 2))) == (3 << (slot * 2)));
	assert(!(fixture->ppe.ct_pon_ifc_cover & BIT(slot)));
	assert(fixture->ppe.ct_pon_ifc_services[slot] == service);
	for (unsigned int family = 0; family < 2; family++) {
		unsigned int row = 56 + slot * 2 + family;
		u32 lut = tuple ? fixture->ppe.ct_pon_ifc_lease[family].mask : 0;

		assert(mock.table[0][row][7][0] == service << 16);
		assert(mock.table[0][row][7][1] == 0xffff0430);
		assert(mock.table[2][row][1][2] == (slot ? 4U : 2U) << 10);
		assert(row_match(row, service, family, lut));
		assert(!row_match(row, service ^ 0x8000, family, lut));
		assert(!row_match(row, service, family ^ 1, lut));
		if (tuple)
			for (unsigned int bit = 0; bit < 32; bit++)
				if (lut & BIT(bit)) {
					assert(!row_match(row, service, family, lut ^ BIT(bit)));
					match_cases++;
				}
		if (sweep)
			for (unsigned int candidate = 0; candidate <= U16_MAX; candidate++) {
				assert(row_match(row, candidate, family, lut) == (candidate == service));
				match_cases++;
			}
	}
	check_shadow(fixture);
	service_cases++;
}

static void wide_lifecycle(void)
{
	const unsigned int services[] = { 0, 0x2134, 0xa134, 0xffff };
	struct fixture fixture;

	for (unsigned int slot = 0; slot < 2; slot++)
		for (unsigned int index = 0; index < ARRAY_SIZE(services); index++) {
			unsigned int service = services[index], peer = slot ^ 1;
			char duplicate[32];

			initialize(&fixture);
			assert(!airoha_ct_pon_ifc_busy(&fixture.ppe));
			service_command(&fixture, "set", slot, service);
			check_service(&fixture, slot, service, false, true);
			service_command(&fixture, "set", slot, service);
			check_service(&fixture, slot, service, false, false);
			reset_counts();
			snprintf(duplicate, sizeof(duplicate), "set %u %u", peer, service);
			assert(store(&fixture, duplicate) == -EEXIST);
			assert(!mock.commands && !mock.table_writes);
			service_command(&fixture, "set", peer, service ^ 0x8000);
			check_service(&fixture, peer, service ^ 0x8000, false, false);
			assert(!airoha_ct_pon_ifc_cpu_clear(&fixture.ppe, peer));
			service_command(&fixture, "set", slot, service ^ 1);
			service_command(&fixture, "set", slot, service);
			assert(!airoha_ct_pon_ifc_cpu_clear(&fixture.ppe, slot));
			check_restored(&fixture);
			assert(!airoha_ct_pon_ifc_busy(&fixture.ppe));
			service_command(&fixture, "set", peer, service);
			command_ok(&fixture, "off");
			check_restored(&fixture);
		}
	for (unsigned int slot = 0; slot < 2; slot++)
		for (unsigned int cover_first = 0; cover_first < 2; cover_first++) {
			initialize(&fixture);
			if (cover_first)
				assert(!airoha_ct_pon_ifc_cpu_publish(&fixture.ppe, slot ^ 1, 0, true));
			service_command(&fixture, "set", slot, 0);
			if (!cover_first)
				assert(!airoha_ct_pon_ifc_cpu_publish(&fixture.ppe, slot ^ 1, 0, true));
			check_service(&fixture, slot, 0, false, false);
			for (unsigned int candidate = 0; candidate <= U16_MAX; candidate++) {
				assert(row_match(56 + (slot ^ 1) * 2, candidate, 0, 0));
				match_cases++;
			}
			assert(!mock.table[0][56 + (slot ^ 1) * 2][7][1]);
			command_ok(&fixture, "route");
			assert(!airoha_ct_pon_ifc_cpu_clear(&fixture.ppe, slot ^ 1));
			check_service(&fixture, slot, 0, false, false);
			command_ok(&fixture, "off");
			check_restored(&fixture);
		}
}

static void tuple_lifecycle_zero(void)
{
	const unsigned int services[] = { 0, 0x2134, 0xa134, 0xffff };
	struct fixture fixture;

	for (unsigned int index = 0; index < ARRAY_SIZE(services); index++) {
		unsigned int service = services[index];
		struct airoha_ct_ifc_pool_lease leases[2];

		tuple_prepare(&fixture, 3, 11, 30);
		service_command(&fixture, "tuple", 0, service);
		check_service(&fixture, 0, service, true, true);
		assert(!tuple_health(&fixture));
		assert(fixture.ppe.ct_pon_ifc_tuple);
		assert(airoha_ct_ifc_pool_has(&fixture.ppe.ct_pon_ifc_pool, &fixture.ppe.ct_pon_ifc_lease[0]));
		assert(airoha_ct_ifc_pool_has(&fixture.ppe.ct_pon_ifc_pool, &fixture.ppe.ct_pon_ifc_lease[1]));
		assert(__builtin_popcount(fixture.ppe.ct_pon_ifc_pool.reserved) == 14);
		memcpy(leases, fixture.ppe.ct_pon_ifc_lease, sizeof(leases));
		reset_counts();
		assert(airoha_ct_pon_ifc_cpu_tuple(&fixture.ppe, 0, service) == -EBUSY);
		assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, 0, service) == -EBUSY);
		assert(!mock.commands && !mock.table_writes);
		command_ok(&fixture, "route");
		command_ok(&fixture, "clear 1");
		assert(fixture.ppe.ct_pon_ifc.active == 3 && !fixture.ppe.ct_pon_ifc_cover);
		assert(!memcmp(leases, fixture.ppe.ct_pon_ifc_lease, sizeof(leases)));
		assert(!tuple_health(&fixture));
		assert(store(&fixture, "route") == -ESHUTDOWN);
		command_ok(&fixture, "cover 1");
		command_ok(&fixture, "route");
		command_ok(&fixture, "clear 0");
		assert(!fixture.ppe.ct_pon_ifc_tuple && !airoha_ct_pon_ifc_tuple_busy(&fixture.ppe));
		assert(tuple_health(&fixture) == -ESHUTDOWN);
		tuple_original_lut();
		service_command(&fixture, "tuple", 0, service);
		assert(!tuple_health(&fixture));
		tuple_finish(&fixture);
	}
	tuple_prepare(&fixture, 3, 11, 30);
	command_ok(&fixture, "tuple 0 0");
	fixture.ppe.ct_pon_ifc.active &= ~BIT(0);
	assert(tuple_health(&fixture) == -ESHUTDOWN);
	fixture.ppe.ct_pon_ifc.active |= BIT(0);
	fixture.ppe.ct_pon_ifc_lease[0].count--;
	assert(tuple_health(&fixture) == -EUCLEAN);
	fixture.ppe.ct_pon_ifc_lease[0].count++;
	mock.table[0][56][7][1] &= 0xffff;
	assert(tuple_health(&fixture) == -EUCLEAN);
	mock.table[0][56][7][1] = 0xffff0430;
	assert(!tuple_health(&fixture));
	tuple_finish(&fixture);
}

static const char *operations[] = {
	"set 0 0", "set 0 0", "clear 0", "off", "tuple 0 0", "route", "clear 0", "clear 1", "off",
};

static void operation_prepare(struct fixture *fixture, unsigned int operation)
{
	if (operation < 4) {
		initialize(fixture);
		command_ok(fixture, "cover 1");
		if (operation)
			command_ok(fixture, operation == 1 ? "set 0 8500" : "set 0 0");
	} else {
		tuple_prepare(fixture, 3, 11, 30);
		if (operation > 4)
			command_ok(fixture, "tuple 0 0");
	}
	if ((operation >= 1 && operation <= 3) || operation >= 6)
		command_ok(fixture, "route");
	reset_counts();
}

static void timeouts(void)
{
	struct fixture fixture;
	u32 commands[1024];

	for (unsigned int operation = 0; operation < ARRAY_SIZE(operations); operation++) {
		unsigned int count;

		operation_prepare(&fixture, operation);
		command_ok(&fixture, operations[operation]);
		count = mock.trace_count;
		assert(count && count < ARRAY_SIZE(commands));
		for (unsigned int index = 0; index < count; index++)
			commands[index] = mock.trace[index].command;
		tuple_finish(&fixture);
		for (unsigned int position = 1; position <= count; position++)
			for (enum fault mode = BEFORE; mode <= READBACK; mode++) {
				struct airoha_ct_ifc_pool saved_pool;
				struct airoha_ct_ifc_pool_lease saved_leases[2];
				struct airoha_ct_pon_ifc_owner saved_owner;
				unsigned int writes, controls;

				if (mode == READBACK && (position == 1 || (commands[position - 1] & BIT(1)) ||
				    commands[position - 2] != (commands[position - 1] | BIT(1))))
					continue;
				operation_prepare(&fixture, operation);
				mock.fail_at = position;
				mock.fault = mode;
				assert(store(&fixture, operations[operation]) < 0);
				assert(mock.commands == position && !fixture.ppe.ct_pon_qualified);
				assert(!fixture.ppe.ct_pon_ifc_route_owned);
				check_shadow(&fixture);
				if (mode == READBACK) {
					readback_cases++;
				} else {
					assert(mock.busy && fixture.eth.ct_ifc_command_pending);
					assert(store(&fixture, "off") == -ETIMEDOUT);
					saved_pool = fixture.ppe.ct_pon_ifc_pool;
					memcpy(saved_leases, fixture.ppe.ct_pon_ifc_lease, sizeof(saved_leases));
					saved_owner = fixture.ppe.ct_pon_ifc;
					writes = mock.data_writes;
					controls = mock.control_writes;
					for (unsigned int attempt = 0; attempt < 2; attempt++) {
						assert(store(&fixture, "off") == -ETIMEDOUT);
						assert(store(&fixture, operation < 4 ? "set 0 0" : "tuple 0 0") < 0);
						assert(!memcmp(&saved_pool, &fixture.ppe.ct_pon_ifc_pool, sizeof(saved_pool)));
						assert(!memcmp(saved_leases, fixture.ppe.ct_pon_ifc_lease, sizeof(saved_leases)));
						assert(!memcmp(&saved_owner, &fixture.ppe.ct_pon_ifc, sizeof(saved_owner)));
						assert(writes == mock.data_writes && controls == mock.control_writes);
						retry_cases++;
					}
					if (saved_pool.leases || saved_pool.releasing || saved_pool.reserved)
						lease_retention_cases++;
					timeout_cases++;
				}
				tuple_finish(&fixture);
			}
	}
}

static void guards(void)
{
	const char *commands[] = { "set 0 0", "set 1 0", "tuple 0 0", "clear 0", "clear 1",
				   "cover 0", "cover 1", "route", "off", "source 2", "only 2", "absent 2" };
	const char *invalid[] = { "set 0 65536", "tuple 0 65536", "set 0 -1", "tuple 0 -1",
				  "set 2 0", "tuple 1 0", "set 0", "tuple 0" };
	struct fixture fixture;

	for (unsigned int configured = 0; configured < 2; configured++) {
		initialize(&fixture);
		if (configured) {
			command_ok(&fixture, "cover 1");
			command_ok(&fixture, "tuple 0 0");
		}
		fixture.ppe.ct_npu_owner = &fixture;
		fixture.eth.ct_bank1_routes.owner = &fixture;
		reset_counts();
		for (unsigned int index = 0; index < ARRAY_SIZE(commands); index++) {
			assert(store(&fixture, commands[index]) == -EBUSY);
			assert(!mock.commands && !mock.data_writes && !mock.route_writes && !mock.port_writes);
			guard_cases++;
		}
		assert(airoha_ct_pon_ifc_cpu_stop(&fixture.ppe) == (configured ? -EBUSY : 0));
		fixture.ppe.ct_npu_owner = NULL;
		fixture.eth.ct_bank1_routes.owner = NULL;
		tuple_finish(&fixture);
	}
	for (unsigned int index = 0; index < ARRAY_SIZE(invalid); index++) {
		tuple_prepare(&fixture, 3, 11, 30);
		assert(store(&fixture, invalid[index]) == -EINVAL);
		assert(!mock.commands && !mock.table_writes);
		tuple_finish(&fixture);
		guard_cases++;
	}
	tuple_prepare(&fixture, 3, 11, 30);
	fixture.ppe.ct_pon_qualified = true;
	assert(store(&fixture, "set 0 0") == -ESHUTDOWN);
	assert(store(&fixture, "tuple 0 0") == -ESHUTDOWN);
	assert(store(&fixture, "route") == -ESHUTDOWN);
	assert(!mock.commands && !mock.table_writes);
	fixture.ppe.ct_pon_qualified = false;
	tuple_finish(&fixture);
	guard_cases += 3;
}

static void worker_recovery(void)
{
	struct fixture fixture;

	tuple_prepare(&fixture, 3, 11, 30);
	command_ok(&fixture, "tuple 0 0");
	reset_counts();
	mock.fail_at = 1;
	mock.fault = DEFERRED;
	assert(store(&fixture, "clear 0") == -ETIMEDOUT);
	for (unsigned int release = 0; release < 2; release++) {
		flow_offload_mutex.held = rtnl = false;
		worker_context = true;
		mock.release = release;
		airoha_ct_pon_ifc_repair_work(&fixture.ppe.ct_pon_ifc_work.work);
		worker_context = false;
		flow_offload_mutex.held = rtnl = true;
		if (!release) {
			assert(fixture.ppe.ct_pon_ifc.pending);
			assert(airoha_ct_ifc_pool_has(&fixture.ppe.ct_pon_ifc_pool, &fixture.ppe.ct_pon_ifc_lease[0]));
			assert(airoha_ct_ifc_pool_has(&fixture.ppe.ct_pon_ifc_pool, &fixture.ppe.ct_pon_ifc_lease[1]));
		} else {
			check_restored(&fixture);
			tuple_original_lut();
		}
		worker_cases++;
	}
}

static void clear_retry(void)
{
	struct fixture fixture;

	for (unsigned int tuple = 0; tuple < 2; tuple++)
		for (enum fault mode = BEFORE; mode <= DEFERRED; mode++) {
			struct airoha_ct_ifc_pool_lease leases[2];
			unsigned int writes;

			operation_prepare(&fixture, tuple ? 6 : 2);
			memcpy(leases, fixture.ppe.ct_pon_ifc_lease, sizeof(leases));
			mock.fail_at = 1;
			mock.fault = mode;
			assert(store(&fixture, "clear 0") == -ETIMEDOUT);
			writes = mock.data_writes;
			assert(store(&fixture, "clear 0") == -ETIMEDOUT);
			assert(mock.data_writes == writes && fixture.ppe.ct_pon_ifc.saved_valid);
			assert(fixture.ppe.ct_pon_ifc_cover == BIT(1));
			assert(fixture.ppe.ct_pon_ifc_services[0] == 0);
			assert(!memcmp(leases, fixture.ppe.ct_pon_ifc_lease, sizeof(leases)));
			mock.release = true;
			mock.fail_at = 0;
			command_ok(&fixture, "clear 0");
			assert(fixture.ppe.ct_pon_ifc.active == 12);
			assert(!airoha_ct_pon_ifc_tuple_busy(&fixture.ppe));
			tuple_finish(&fixture);
			retry_cases++;
		}
	for (enum fault mode = BEFORE; mode <= DEFERRED; mode++) {
		operation_prepare(&fixture, 2);
		mock.fail_at = 28;
		mock.fault = mode;
		assert(store(&fixture, "set 0 8500") == -ETIMEDOUT);
		assert(fixture.ppe.ct_pon_ifc_services[0] == 0);
		assert(fixture.ppe.ct_pon_ifc.saved_valid && fixture.ppe.ct_pon_ifc.dirty);
		assert(store(&fixture, "set 0 0") < 0);
		tuple_finish(&fixture);
		retry_cases++;
	}
}

int main(void)
{
	wide_lifecycle();
	tuple_lifecycle_zero();
	guards();
	worker_recovery();
	clear_retry();
	timeouts();
	assert(timeout_cases && retry_cases && lease_retention_cases && readback_cases);
	printf("{\"passed\":true,\"service_cases\":%u,\"match_cases\":%u,\"timeout_cases\":%u,"
	       "\"blocked_retries\":%u,\"lease_retention_cases\":%u,\"readback_cases\":%u,"
	       "\"guard_cases\":%u,\"worker_cases\":%u}\n", service_cases, match_cases, timeout_cases,
	       retry_cases, lease_retention_cases, readback_cases, guard_cases, worker_cases);
	return 0;
}
