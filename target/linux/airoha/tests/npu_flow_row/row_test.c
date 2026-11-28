#include <stdbool.h>

static bool *tracked_attempt;
#define main diag_regression_main
#include "diag_reuse.c"
#undef main

static int install_row(u32 hash, const struct airoha_foe_entry *entry, bool *attempted)
{
	int error;

	tracked_attempt = attempted;
	spin_lock_bh(&ppe_lock);
	error = airoha_npu_bank0_install_checked(&ppe, hash, entry, attempted);
	spin_unlock_bh(&ppe_lock);
	tracked_attempt = NULL;
	return error;
}

static int check_row(u32 hash, const struct airoha_foe_entry *entry)
{
	int error;

	spin_lock_bh(&ppe_lock);
	error = airoha_npu_bank0_check_unbound(&ppe, hash, entry);
	spin_unlock_bh(&ppe_lock);
	return error;
}

static void row_fixture(bool udp)
{
	prepare_bound_install();
	session.diag_entry.ib1 &= ~AIROHA_FOE_IB1_BIND_UDP;
	session.diag_entry.ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_UDP, udp);
	session.diag_entry.ipv4.orig_tuple.dest_ip = 0xc6336402;
	session.diag_entry.ipv4.orig_tuple.src_port = 12345;
	session.diag_entry.ipv4.orig_tuple.dest_port = 443;
	session.diag_entry.ipv4.new_tuple.src_ip = 0x0a000001;
	session.diag_entry.ipv4.new_tuple.src_port = 23456;
	session.bank0_next_row = 0;
}

static void test_row_arguments(void)
{
	const u32 invalid_hashes[] = {8192, 16383, 16384, UINT32_MAX};
	bool attempted;

	for (unsigned int index = 0; index < ARRAY_SIZE(invalid_hashes); ++index) {
		row_fixture(false);
		attempted = true;
		CHECK(check_row(invalid_hashes[index], &session.diag_entry) == -EINVAL);
		CHECK(install_row(invalid_hashes[index], &session.diag_entry, &attempted) == -EINVAL);
		CHECK(!attempted && !sram_reads && !sram_commits);
		cases++;
	}
	for (unsigned int kind = 0; kind < 3; ++kind) {
		row_fixture(false);
		attempted = true;
		spin_lock_bh(&ppe_lock);
		CHECK(airoha_npu_bank0_install_checked(kind == 0 ? NULL : &ppe, expected_hash,
			kind == 1 ? NULL : &session.diag_entry, kind == 2 ? NULL : &attempted) == -EINVAL);
		if (kind < 2)
			CHECK(airoha_npu_bank0_check_unbound(kind == 0 ? NULL : &ppe,
				expected_hash, kind == 1 ? NULL : &session.diag_entry) == -EINVAL);
		spin_unlock_bh(&ppe_lock);
		CHECK(!sram_reads && !sram_commits);
		CHECK(kind == 2 || !attempted);
		cases++;
	}
	for (unsigned int field = 0; field < 2; ++field) {
		u32 mask = field ? AIROHA_FOE_IB1_BIND_PACKET_TYPE : AIROHA_FOE_IB1_BIND_STATE;
		u32 valid = field ? PPE_PKT_TYPE_IPV4_HNAPT : AIROHA_FOE_STATE_BIND;

		for (u32 value = 0; value <= FIELD_GET(mask, mask); ++value) {
			if (value == valid)
				continue;
			row_fixture(false);
			session.diag_entry.ib1 = (session.diag_entry.ib1 & ~mask) | FIELD_PREP(mask, value);
			attempted = true;
			CHECK(check_row(expected_hash, &session.diag_entry) == -EINVAL);
			CHECK(install_row(expected_hash, &session.diag_entry, &attempted) == -EINVAL);
			CHECK(!attempted && !sram_reads && !sram_commits);
			cases++;
		}
	}
}

static void test_unbound_rows(void)
{
	for (unsigned int udp = 0; udp < 2; ++udp) {
		for (unsigned int fault = 0; fault < 6; ++fault) {
			row_fixture(udp);
			hardware_entry = session.diag_entry;
			hardware_entry.ib1 = (hardware_entry.ib1 & ~AIROHA_FOE_IB1_BIND_STATE) |
				FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_UNBIND);
			int expected = 0;
			switch (fault) {
			case 0: hardware_entry.ipv4.new_tuple.dest_ip ^= 1; break;
			case 1: fail_sram_read = 1; expected = -ETIMEDOUT; break;
			case 2: bad_sram_ack = 1; expected = -EIO; break;
			case 3: hardware_entry.ib1 ^= AIROHA_FOE_IB1_BIND_UDP; expected = -ESTALE; break;
			case 4: hardware_entry.ib1 ^= FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE, 1); expected = -ESTALE; break;
			case 5: hardware_entry.ib1 = session.diag_entry.ib1; expected = -ESTALE; break;
			}
			struct airoha_foe_entry before = hardware_entry, template = session.diag_entry;
			CHECK(check_row(expected_hash, &session.diag_entry) == expected);
			CHECK(!memcmp(&before, &hardware_entry, sizeof(before)) && !sram_commits);
			CHECK(!memcmp(&template, &session.diag_entry, sizeof(template)));
			cases++;
		}
		for (unsigned int bit = 0; bit < sizeof(hardware_entry.ipv4.orig_tuple) * 8; ++bit) {
			row_fixture(udp);
			hardware_entry = session.diag_entry;
			hardware_entry.ib1 = (hardware_entry.ib1 & ~AIROHA_FOE_IB1_BIND_STATE) |
				FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_UNBIND);
			((u8 *)&hardware_entry.ipv4.orig_tuple)[bit / 8] ^= BIT(bit % 8);
			CHECK(check_row(expected_hash, &session.diag_entry) == -ESTALE);
			CHECK(!sram_commits);
			cases++;
		}
	}
}

static void test_checked_install(void)
{
	for (unsigned int udp = 0; udp < 2; ++udp) {
		for (unsigned int bit = 0; bit < sizeof(hardware_entry) * 8; ++bit) {
			bool attempted = true;
			row_fixture(udp);
			hardware_entry.data[bit / 8] = BIT(bit % 8);
			struct airoha_foe_entry before = hardware_entry;
			CHECK(install_row(expected_hash, &session.diag_entry, &attempted) == -EIO);
			CHECK(!attempted && !sram_commits && !memcmp(&hardware_entry, &before, sizeof(before)));
			cases++;
			row_fixture(udp);
			corrupt_sram_read = 2; corrupt_sram_byte = bit / 8; corrupt_sram_mask = BIT(bit % 8);
			CHECK(install_row(expected_hash, &session.diag_entry, &attempted) == -EIO);
			CHECK(attempted && sram_commits == 1 && !memcmp(&hardware_entry, &session.diag_entry, sizeof(hardware_entry)));
			cases++;
		}
		for (unsigned int fault = 0; fault < 8; ++fault) {
			bool attempted = true;
			row_fixture(udp);
			int expected = -EIO;
			switch (fault) {
			case 0: fail_sram_read = 1; expected = -ETIMEDOUT; break;
			case 1: bad_sram_ack = 1; break;
			case 2: fail_commit = -ETIMEDOUT; expected = -ETIMEDOUT; break;
			case 3: fail_commit = -ETIMEDOUT; commit_takes_effect = true; expected = -ETIMEDOUT; break;
			case 4: bad_sram_ack = 2; break;
			case 5: fail_sram_read = 2; expected = -ETIMEDOUT; break;
			case 6: bad_sram_ack = 3; break;
			case 7: corrupt_sram_read = 2; corrupt_sram_byte = 79; break;
			}
			CHECK(install_row(expected_hash, &session.diag_entry, &attempted) == expected);
			CHECK(attempted == (fault >= 2) && sram_commits == (fault >= 2));
			CHECK(!memcmp(&hardware_entry, fault >= 3 ? &session.diag_entry : &(struct airoha_foe_entry){}, sizeof(hardware_entry)));
			cases++;
		}
		for (unsigned int boundary = 0; boundary < 2; ++boundary) {
			bool attempted = false;
			row_fixture(udp);
			expected_hash = boundary ? 8191 : 0;
			shadow_entry = session.diag_entry;
			CHECK(!install_row(expected_hash, &shadow_entry, &attempted));
			CHECK(attempted && sram_reads == 2 && sram_commits == 1);
			CHECK(!memcmp(&hardware_entry, &session.diag_entry, sizeof(hardware_entry)));
			cases++;
		}
	}
}

static void test_dirty_cleanup_retry(void)
{
	const u32 pending_cursors[] = {0, 1, 17, PPE_SRAM_NUM_ENTRIES - 1,
		PPE_SRAM_NUM_ENTRIES + 1, UINT32_MAX};

	for (unsigned int index = 0; index < ARRAY_SIZE(pending_cursors); ++index) {
		prepare_bound_install();
		session.bank0_next_row = pending_cursors[index];
		hardware_entry.data[79] = 1;
		CHECK(airoha_npu_diag_install(&session) == -EINVAL);
		CHECK(session.bank0_next_row == pending_cursors[index]);
		CHECK(!sram_reads && !sram_commits && hardware_entry.data[79] == 1);
		CHECK(ppe.ct_npu_owner == &session && lower.references && lan.references);
		cases++;
	}
	prepare_bound_install();
	fail_commit = -ETIMEDOUT;
	commit_takes_effect = true;
	CHECK(airoha_npu_diag_install(&session) == -ETIMEDOUT);
	CHECK(session.bank0_next_row == 0 && sram_commits == 1);
	CHECK(!memcmp(&hardware_entry, &session.diag_entry, sizeof(hardware_entry)));
	fail_commit = 0;
	clear_error[0] = -EIO;
	close_clears_rows = true;
	CHECK(airoha_npu_diag_close(&ppe, true) == -EIO);
	CHECK(ppe.ct_npu_owner == &session && !freed && lower.references && lan.references);
	CHECK(session.bank0_next_row == 17 && !netdev_puts);
	clear_error[0] = 0;
	close_clears_rows = true;
	CHECK(!airoha_npu_diag_close(&ppe, true));
	CHECK(close_bank0_row == 17);
	CHECK(!ppe.ct_npu_owner && freed == 1 && !lower.references && !lan.references);
	CHECK(!memcmp(&hardware_entry, &(struct airoha_foe_entry){}, sizeof(hardware_entry)));
	balanced();
}

int main(int argc, char **argv)
{
	int result = diag_regression_main(argc, argv);
	if (result)
		return result;
	checks = cases = 0;
	test_row_arguments();
	test_unbound_rows();
	test_checked_install();
	test_dirty_cleanup_retry();
	printf("{\"passed\":true,\"row_cases\":%u,\"row_checks\":%u}\n", cases, checks);
	return 0;
}
