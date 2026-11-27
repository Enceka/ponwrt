#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EUCLEAN
#define EUCLEAN 117
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define BIT(index) (UINT32_C(1) << (index))
#define U32_MAX UINT32_MAX
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#include "airoha_npu_ingress.h"

static unsigned int checks, scenarios, injected_faults;
static unsigned int ignored_key_bits, rejected_key_bits, rejected_mask_bits, rejected_action_bits;
static unsigned int cpu_cover_packets;
#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
		abort(); \
	} \
} while (0)

enum fault_mode { NO_FAULT, BEFORE_EFFECT, AFTER_EFFECT, DELAYED_EFFECT };
struct host {
	struct airoha_ct_pon_ifc_owner owner;
	struct airoha_ct_pon_ifc_io io;
	struct airoha_ct_pon_ifc_words hardware[4], original[4];
	unsigned int commands, puts, reads, drains, fail_at, drain_failures;
	u16 dependencies[4];
	u8 closed, target, completed;
	bool restoring, busy, delayed, finish_on_failed_drain;
	bool normalize_tcam;
	u32 unused_key_pattern;
	enum fault_mode fault;
	u32 *late_page, late_words[3];
	unsigned int late_count;
};

static const unsigned int short_lut[2] = { 31, 30 };

static u32 *page_address(struct host *host, unsigned int bank, unsigned int row,
			unsigned int page, unsigned int count)
{
	CHECK(row >= 56 && row < 60);
	CHECK(bank == 0 || bank == 2);
	CHECK(bank == 0 ? page < 9 && count == 2 :
	      page < 3 && count == airoha_ct_pon_ifc_action_words[page]);
	return bank == 0 ? host->hardware[row - 56].tcam[page] :
			  host->hardware[row - 56].action[page];
}

static int transfer(struct host *host, unsigned int bank, unsigned int row,
		    unsigned int page, u32 *words, unsigned int count, bool write)
{
	u32 *location = page_address(host, bank, row, page, count);
	bool fail;

	CHECK(!host->busy);
	if (write) {
		u8 pair = host->restoring ? host->target : row < 58 ? 3 : 12;

		CHECK(host->owner.saved_valid && (host->owner.dirty & BIT(row - 56)));
		CHECK(host->target & BIT(row - 56));
		CHECK(!(host->owner.active & pair));
		if (!host->restoring && row < 58)
			CHECK((host->completed & 12) == 12);
		if (bank != 2 || page != 2) {
			CHECK((host->closed & pair) == pair);
			for (unsigned int index = 0; index < 4; ++index)
				if (pair & BIT(index))
					CHECK(!(host->hardware[index].action[2][0] & BIT(31)));
		} else if (words[0]) {
			CHECK((host->closed & pair) == pair);
			for (unsigned int index = 0; index < 4; ++index)
				if (pair & BIT(index))
					CHECK(host->dependencies[index] == 0x7ff);
			CHECK(host->restoring == !(words[0] & BIT(31)));
		}
		++host->puts;
	} else {
		++host->reads;
	}
	++host->commands;
	fail = host->fail_at == host->commands;
	if (fail && host->fault == DELAYED_EFFECT) {
		host->delayed = write;
		host->late_page = location;
		host->late_count = count;
		if (write)
			memcpy(host->late_words, words, count * sizeof(u32));
	} else if (!(fail && host->fault == BEFORE_EFFECT)) {
		if (write)
			memcpy(location, words, count * sizeof(u32));
		else
			memcpy(words, location, count * sizeof(u32));
	}
	if (fail) {
		host->busy = true;
		return host->fault == DELAYED_EFFECT ? -ETIMEDOUT : -EIO;
	}
	if (write) {
		if (bank == 0)
			host->dependencies[row - 56] |= BIT(page);
		else if (page < 2)
			host->dependencies[row - 56] |= BIT(9 + page);
		else if (!words[0])
			host->closed |= BIT(row - 56);
		else if (words[0] & BIT(31))
			host->completed |= BIT(row - 56);
	}
	return 0;
}

static int read_words(void *context, unsigned int bank, unsigned int row,
		      unsigned int page, u32 *words, unsigned int count)
{
	struct host *host = context;
	int error = transfer(host, bank, row, page, words, count, false);

	if (!error && !bank && host->normalize_tcam)
		words[0] = (words[0] & words[1]) | (host->unused_key_pattern & ~words[1]);
	return error;
}

static int put_words(void *context, unsigned int bank, unsigned int row,
		     unsigned int page, const u32 *words, unsigned int count)
{
	u32 copy[3];

	CHECK(count <= 3);
	memcpy(copy, words, count * sizeof(u32));
	return transfer(context, bank, row, page, copy, count, true);
}

static int drain(void *context)
{
	struct host *host = context;

	CHECK(host->owner.pending);
	++host->drains;
	if ((!host->drain_failures || host->finish_on_failed_drain) && host->delayed) {
		memcpy(host->late_page, host->late_words, host->late_count * sizeof(u32));
		host->delayed = false;
	}
	if (host->drain_failures) {
		--host->drain_failures;
		return -EAGAIN;
	}
	host->busy = false;
	return 0;
}

static void operation(struct host *host, bool restoring)
{
	host->commands = host->puts = host->reads = host->drains = 0;
	host->fail_at = host->drain_failures = 0;
	host->fault = NO_FAULT;
	host->closed = host->completed = 0;
	memset(host->dependencies, 0, sizeof(host->dependencies));
	host->restoring = restoring;
	host->target = restoring ? host->owner.dirty : 15;
	host->finish_on_failed_drain = false;
}

static void initialize(struct host *host)
{
	memset(host, 0, sizeof(*host));
	host->io = (struct airoha_ct_pon_ifc_io) {
		.ctx = host, .read = read_words, .put = put_words, .drain = drain,
	};
	for (unsigned int row = 0; row < 4; ++row) {
		for (unsigned int page = 0; page < 9; ++page)
			for (unsigned int word = 0; word < 2; ++word)
				host->hardware[row].tcam[page][word] = 0x12340000 | row << 12 | page << 4 | word;
		for (unsigned int page = 0; page < 3; ++page)
			for (unsigned int word = 0; word < airoha_ct_pon_ifc_action_words[page]; ++word)
				host->hardware[row].action[page][word] = 0x23450000 | row << 12 | page << 4 | word;
	}
	memcpy(host->original, host->hardware, sizeof(host->original));
}

static void unchanged_snapshot(const struct host *host)
{
	if (host->owner.saved_valid)
		CHECK(!memcmp(host->owner.saved, host->original, sizeof(host->original)));
}

static void prepare_ok(struct host *host, bool initial)
{
	operation(host, false);
	CHECK(!airoha_npu_ingress_prepare(&host->owner, &host->io, short_lut));
	CHECK(host->puts == 52 && host->reads == (initial ? 96 : 48));
	CHECK(host->owner.active == 15 && host->owner.dirty == 15 && !host->owner.pending);
	CHECK(host->completed == 15);
	unchanged_snapshot(host);
}

static void restore_ok(struct host *host)
{
	operation(host, true);
	CHECK(!airoha_npu_ingress_restore(&host->owner, &host->io));
	CHECK(!host->owner.saved_valid && !host->owner.dirty && !host->owner.active && !host->owner.pending);
	CHECK(!memcmp(host->hardware, host->original, sizeof(host->original)));
	CHECK(!airoha_npu_ingress_restore(&host->owner, &host->io));
}

static void invalid_inputs(void)
{
	struct host host;
	struct airoha_ct_pon_ifc_words rows[2], saved[2];
	unsigned int invalid[2] = { 31, 31 };

	initialize(&host);
	memset(rows, 0x5a, sizeof(rows));
	memcpy(saved, rows, sizeof(saved));
	CHECK(airoha_npu_ingress_rows(rows, invalid) == -EINVAL);
	CHECK(!memcmp(rows, saved, sizeof(rows)));
	CHECK(airoha_npu_ingress_encode(rows, 0x806, 31) == -EINVAL);
	CHECK(airoha_npu_ingress_encode(rows, ETH_P_IP, 32) == -EINVAL);
	CHECK(airoha_npu_ingress_encode(NULL, ETH_P_IP, 31) == -EINVAL);
	CHECK(!memcmp(rows, saved, sizeof(rows)));
	CHECK(airoha_npu_ingress_prepare(NULL, &host.io, short_lut) == -EINVAL);
	CHECK(airoha_npu_ingress_prepare(&host.owner, NULL, short_lut) == -EINVAL);
	CHECK(airoha_npu_ingress_prepare(&host.owner, &host.io, NULL) == -EINVAL);
	CHECK(airoha_npu_ingress_check(&host.owner, &host.io, short_lut) == -ESTALE);
	CHECK(airoha_npu_ingress_prepare(&host.owner, &host.io, invalid) == -EINVAL);
	invalid[1] = 32;
	CHECK(airoha_npu_ingress_prepare(&host.owner, &host.io, invalid) == -EINVAL);
	CHECK(!host.commands);
	for (unsigned int field = 0; field < 3; ++field) {
		struct airoha_ct_pon_ifc_io invalid_io = host.io;

		if (field == 0) invalid_io.read = NULL;
		if (field == 1) invalid_io.put = NULL;
		if (field == 2) invalid_io.drain = NULL;
		CHECK(airoha_npu_ingress_prepare(&host.owner, &invalid_io, short_lut) == -EINVAL);
		CHECK(airoha_npu_ingress_check(&host.owner, &invalid_io, short_lut) == -EINVAL);
		CHECK(airoha_npu_ingress_restore(&host.owner, &invalid_io) == -EINVAL);
	}
	for (unsigned int field = 0; field < 2; ++field) {
		if (field == 0) host.owner.dirty = 16;
		else { host.owner.dirty = 0; host.owner.active = 16; }
		CHECK(airoha_npu_ingress_prepare(&host.owner, &host.io, short_lut) == -EBUSY);
		CHECK(airoha_npu_ingress_restore(&host.owner, &host.io) == -EBUSY);
	}
	CHECK(!host.commands);
	for (unsigned int row = 0; row < 4; ++row) {
		initialize(&host);
		host.hardware[row].action[2][0] |= BIT(31);
		CHECK(airoha_npu_ingress_prepare(&host.owner, &host.io, short_lut) == -EBUSY);
		CHECK(!host.puts && !host.owner.saved_valid);
	}
	++scenarios;
}

static void audit_words(void)
{
	struct host host;

	initialize(&host);
	prepare_ok(&host, true);
	for (unsigned int row = 0; row < 4; ++row)
		for (unsigned int bank = 0; bank <= 2; bank += 2)
			for (unsigned int page = 0; page < (bank ? 3 : 9); ++page)
				for (unsigned int word = 0; word < (bank ? airoha_ct_pon_ifc_action_words[page] : 2); ++word)
					for (unsigned int bit = 0; bit < 32; ++bit) {
						u32 *location = bank ? &host.hardware[row].action[page][word] :
								       &host.hardware[row].tcam[page][word];
						bool significant = bank || word ||
							(host.hardware[row].tcam[page][1] & BIT(bit));

						*location ^= BIT(bit);
						CHECK(airoha_npu_ingress_check(&host.owner, &host.io, short_lut) ==
						      (significant ? -EUCLEAN : 0));
						CHECK(host.owner.active == 15 && host.owner.dirty == 15 && !host.owner.pending);
						if (bank) ++rejected_action_bits;
						else if (word) ++rejected_mask_bits;
						else if (significant) ++rejected_key_bits;
						else ++ignored_key_bits;
						*location ^= BIT(bit);
						++scenarios;
					}
	CHECK(host.puts == 52);
	operation(&host, false);
	CHECK(!airoha_npu_ingress_check(&host.owner, &host.io, short_lut));
	CHECK(host.reads == 48 && !host.puts);
	prepare_ok(&host, false);
	restore_ok(&host);
}

static void fault_sweep(void)
{
	for (unsigned int stage = 0; stage < 4; ++stage) {
		unsigned int positions = stage == 0 ? 148 : stage == 1 ? 100 : stage == 2 ? 48 : 52;

		for (unsigned int position = 1; position <= positions; ++position)
			for (unsigned int mode = BEFORE_EFFECT; mode <= DELAYED_EFFECT; ++mode)
				for (unsigned int recovery = 0; recovery < 2; ++recovery) {
					struct host host;
					struct airoha_ct_pon_ifc_owner saved;
					int result;

					initialize(&host);
					if (stage) prepare_ok(&host, true);
					operation(&host, stage == 3);
					host.fail_at = position;
					host.fault = mode;
					if (stage == 3)
						result = airoha_npu_ingress_restore(&host.owner, &host.io);
					else if (stage == 2)
						result = airoha_npu_ingress_check(&host.owner, &host.io, short_lut);
					else
						result = airoha_npu_ingress_prepare(&host.owner, &host.io, short_lut);
					CHECK(result == (mode == DELAYED_EFFECT ? -ETIMEDOUT : -EIO));
					CHECK(host.commands == position && host.owner.pending);
					unchanged_snapshot(&host);
					saved = host.owner;
					for (unsigned int failed = 0; failed < 2; ++failed) {
						operation(&host, recovery || stage == 3);
						host.drain_failures = 1;
						host.finish_on_failed_drain = failed;
						result = recovery || stage == 3 ?
							airoha_npu_ingress_restore(&host.owner, &host.io) :
							airoha_npu_ingress_prepare(&host.owner, &host.io, short_lut);
						CHECK(result == -EAGAIN && !host.commands && host.drains == 1);
						CHECK(!memcmp(&saved, &host.owner, sizeof(saved)));
					}
					if (!recovery && stage != 3)
						prepare_ok(&host, !host.owner.saved_valid);
					restore_ok(&host);
					++scenarios;
					++injected_faults;
				}
	}
}

static void audit_restore(void)
{
	for (unsigned int row = 0; row < 4; ++row)
		for (unsigned int bank = 0; bank <= 2; bank += 2)
			for (unsigned int page = 0; page < (bank ? 3 : 9); ++page)
				for (unsigned int word = 0; word < (bank ? airoha_ct_pon_ifc_action_words[page] : 2); ++word) {
					struct host host;
					u32 *location;

					initialize(&host);
					prepare_ok(&host, true);
					location = bank ? &host.hardware[row].action[page][word] :
							  &host.hardware[row].tcam[page][word];
					*location ^= BIT(31);
					CHECK(airoha_npu_ingress_check(&host.owner, &host.io, short_lut) ==
					      (bank || word || (host.hardware[row].tcam[page][1] & BIT(31)) ? -EUCLEAN : 0));
					CHECK(host.owner.active == 15 && host.owner.dirty == 15 && !host.owner.pending);
					unchanged_snapshot(&host);
					restore_ok(&host);
					++scenarios;
				}
}

static void normalized_readback(void)
{
	const u32 patterns[] = { U32_MAX, 0, 0xa5a5a5a5 };

	for (unsigned int pattern = 0; pattern < 3; ++pattern) {
		struct host host;
		u32 actual[2];

		initialize(&host);
		host.normalize_tcam = true;
		host.unused_key_pattern = patterns[pattern];
		for (unsigned int row = 0; row < 4; ++row)
			for (unsigned int page = 0; page < 9; ++page) {
				u32 *words = host.hardware[row].tcam[page];

				words[0] = (words[0] & words[1]) | (patterns[pattern] & ~words[1]);
			}
		memcpy(host.original, host.hardware, sizeof(host.original));
		prepare_ok(&host, true);
		CHECK(!host.hardware[0].tcam[1][0] && !host.hardware[0].tcam[1][1]);
		CHECK(!read_words(&host, 0, 56, 1, actual, 2));
		CHECK(actual[0] == patterns[pattern] && !actual[1]);
		CHECK(!airoha_npu_ingress_check(&host.owner, &host.io, short_lut));
		prepare_ok(&host, false);
		restore_ok(&host);
		++scenarios;
	}
}

static int classify(const struct host *host, const u32 key[9])
{
	for (unsigned int row = 0; row < 4; ++row) {
		bool match = !!(host->hardware[row].action[2][0] & BIT(31));

		for (unsigned int page = 0; page < 9; ++page)
			if ((key[page] ^ host->hardware[row].tcam[page][0]) &
			    host->hardware[row].tcam[page][1])
				match = false;
		if (match)
			return row;
	}
	return -1;
}

static void cpu_protection(void)
{
	const struct { u32 protocol, encapsulation, hits, type; int row; } packets[] = {
		{ ETH_P_IP, 0, 0, 0, 0 }, { ETH_P_IPV6, 0, 0, 0, 1 },
		{ ETH_P_IP, 0, BIT(31), 0, 2 }, { ETH_P_IPV6, 0, BIT(30), 0, 2 },
		{ 0x0806, 0, 0, 0, 2 }, { 0x8864, 0, 0, 0, 2 },
		{ ETH_P_IP, 0x10, 0, 0, 2 }, { ETH_P_IPV6, 0x400, 0, 0, 2 },
		{ ETH_P_IP, 0, 0, 1, 3 }, { 0, 0x430, U32_MAX, 1, 3 },
	};
	struct host host;

	initialize(&host);
	prepare_ok(&host, true);
	for (unsigned int row = 2; row < 4; ++row) {
		CHECK(host.hardware[row].tcam[0][0] == BIT(2) &&
		      host.hardware[row].tcam[0][1] == U32_MAX);
		CHECK(host.hardware[row].tcam[8][0] == (row - 2) << 6 &&
		      host.hardware[row].tcam[8][1] == 0xc0);
		CHECK(!host.hardware[row].action[0][0] && !host.hardware[row].action[0][1]);
		CHECK(!host.hardware[row].action[1][0] && !host.hardware[row].action[1][1]);
		CHECK(host.hardware[row].action[1][2] == 4 << 10);
		CHECK(host.hardware[row].action[2][0] == (BIT(31) | BIT(30) | BIT(28)));
	}
	for (unsigned int source = 0; source < 32; ++source)
		for (unsigned int packet = 0; packet < sizeof(packets) / sizeof(packets[0]); ++packet) {
			u32 key[9] = { BIT(source), 0xffff, 0, 0, packets[packet].hits,
				packets[packet].protocol, 0, packets[packet].encapsulation, packets[packet].type << 6 };

			CHECK(classify(&host, key) == (source == 2 ? packets[packet].row : -1));
			++cpu_cover_packets;
		}
	for (unsigned int row = 0; row < 4; ++row) {
		unsigned int commands = host.commands;

		host.owner.active ^= BIT(row);
		CHECK(airoha_npu_ingress_check(&host.owner, &host.io, short_lut) == -ESTALE);
		host.owner.active ^= BIT(row);
		host.owner.dirty ^= BIT(row);
		CHECK(airoha_npu_ingress_check(&host.owner, &host.io, short_lut) == -ESTALE);
		host.owner.dirty ^= BIT(row);
		CHECK(host.commands == commands);
	}
	restore_ok(&host);
	++scenarios;
}

static void emit_words(void)
{
	for (unsigned int family = 0; family < 2; ++family)
		for (unsigned int lut = 0; lut < 32; ++lut) {
			struct airoha_ct_pon_ifc_words row;

			CHECK(!airoha_npu_ingress_encode(&row, family ? ETH_P_IPV6 : ETH_P_IP, lut));
			for (unsigned int page = 0; page < 9; ++page)
				for (unsigned int word = 0; word < 2; ++word)
					printf("%08x ", row.tcam[page][word]);
			for (unsigned int page = 0; page < 3; ++page)
				for (unsigned int word = 0; word < 3; ++word)
					printf("%08x%c", row.action[page][word], page == 2 && word == 2 ? '\n' : ' ');
		}
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "words")) {
		emit_words();
		return 0;
	}
	invalid_inputs();
	normalized_readback();
	cpu_protection();
	audit_words();
	audit_restore();
	fault_sweep();
	printf("{\"passed\":true,\"scenarios\":%u,\"checks\":%u,\"transport_faults\":%u,"
	       "\"ignored_key_bits\":%u,\"rejected_key_bits\":%u,\"rejected_mask_bits\":%u,"
	       "\"rejected_action_bits\":%u,\"normalization_patterns\":3,\"cpu_cover_packets\":%u}\n",
	       scenarios, checks, injected_faults, ignored_key_bits, rejected_key_bits,
	       rejected_mask_bits, rejected_action_bits, cpu_cover_packets);
	return 0;
}
