#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef EUCLEAN
#define EUCLEAN 117
#endif
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define BIT(index) (UINT32_C(1) << (index))
#define U32_MAX UINT32_MAX
#include "airoha_ct_ifc_tuple_pool.h"

enum fault { BEFORE, AFTER, DEFERRED };

struct device {
	struct airoha_ct_ifc_pool pool;
	struct airoha_ct_ifc_pool_io io;
	u32 hardware[32][2], original[32][2];
	u32 late_words[2];
	unsigned int commands, reads, puts, drains, fail_at, corrupt_at;
	unsigned int late_slot, drain_failures;
	enum fault fault;
	bool busy, late, partial_write, late_on_failed_drain;
	unsigned int partial_word;
};

static unsigned int cases, fault_cases, retry_cases, drain_checks, checked_io;
static unsigned int review_cases;

static void shadows(const struct device *device)
{
	const struct airoha_ct_ifc_pool *pool = &device->pool;

	assert(!(pool->dirty & ~pool->reserved));
	for (unsigned int slot = 0; slot < 32; slot++) {
		if (pool->reserved & BIT(slot)) {
			assert(!memcmp(pool->saved[slot], device->original[slot], sizeof(pool->saved[slot])));
			assert(!(pool->saved[slot][1] & BIT(15)));
		} else {
			assert(!pool->refs[slot]);
			assert(!pool->saved[slot][0] && !pool->saved[slot][1]);
			assert(!pool->words[slot][0] && !pool->words[slot][1]);
		}
		if (pool->refs[slot])
			assert(pool->dirty & BIT(slot));
	}
}

static int read_row(void *ctx, unsigned int slot, u32 words[2])
{
	struct device *device = ctx;
	bool fail;

	assert(slot < 32 && !device->busy);
	shadows(device);
	checked_io++;
	device->reads++;
	fail = ++device->commands == device->fail_at;
	if (!fail || device->fault != BEFORE)
		memcpy(words, device->hardware[slot], sizeof(device->hardware[slot]));
	if (fail) {
		device->busy = true;
		return -ETIMEDOUT;
	}
	if (device->commands == device->corrupt_at)
		words[0] ^= BIT(0);
	return 0;
}

static int put_row(void *ctx, unsigned int slot, const u32 words[2])
{
	struct device *device = ctx;
	const struct airoha_ct_ifc_pool *pool = &device->pool;
	bool fail;

	assert(slot < 32 && !device->busy);
	shadows(device);
	assert(pool->reserved & BIT(slot));
	assert(pool->dirty & BIT(slot));
	assert(!(device->original[slot][1] & BIT(15)));
	if (pool->refs[slot]) {
		assert(pool->releasing && (pool->releasing->mask & BIT(slot)));
		assert(pool->refs[slot] == 1);
		assert(!memcmp(words, device->original[slot], sizeof(device->original[slot])));
	}
	checked_io++;
	device->puts++;
	fail = ++device->commands == device->fail_at;
	if (fail && device->partial_write) {
		assert(device->fault != DEFERRED && device->partial_word < 2);
		memcpy(&device->hardware[slot][device->partial_word],
		       &words[device->partial_word], sizeof(words[0]));
	} else if (fail && device->fault == DEFERRED) {
		device->late = true;
		device->late_slot = slot;
		memcpy(device->late_words, words, sizeof(device->late_words));
	} else if (!fail || device->fault == AFTER) {
		memcpy(device->hardware[slot], words, sizeof(device->hardware[slot]));
	}
	if (fail) {
		device->busy = true;
		return -ETIMEDOUT;
	}
	return 0;
}

static int drain(void *ctx)
{
	struct device *device = ctx;

	device->drains++;
	assert(device->pool.pending);
	if (device->drain_failures) {
		device->drain_failures--;
		if (device->late_on_failed_drain && device->late) {
			memcpy(device->hardware[device->late_slot], device->late_words,
			       sizeof(device->late_words));
			device->late = false;
		}
		return -ETIMEDOUT;
	}
	if (device->late) {
		memcpy(device->hardware[device->late_slot], device->late_words, sizeof(device->late_words));
		device->late = false;
	}
	device->busy = false;
	return 0;
}

static void init(struct device *device, bool short_guards)
{
	*device = (struct device) {};
	device->io = (struct airoha_ct_ifc_pool_io) {
		.ctx = device, .read = read_row, .put = put_row, .drain = drain,
	};
	for (unsigned int slot = 0; slot < 32; slot++) {
		device->hardware[slot][0] = 0x13570000 + slot;
		device->hardware[slot][1] = 0x2100 + slot;
	}
	if (short_guards) {
		device->hardware[30][1] = 0xc010;
		device->hardware[31][1] = 0xc011;
	}
	memcpy(device->original, device->hardware, sizeof(device->original));
}

static struct airoha_ct_ifc_tuple_words tuple(unsigned int family, unsigned int seed,
					    bool common)
{
	struct airoha_ct_ifc_tuple input = {
		.family = family, .protocol = common || seed % 2 ? 6 : 17,
		.sport = common ? 1234 : 1000 + seed,
		.dport = common ? 443 : 2000 + seed,
	};
	struct airoha_ct_ifc_tuple_words words = {};

	for (unsigned int part = 0; part < (family == 4 ? 1U : 4U); part++) {
		input.src[part] = 0xa0000000 + seed * 16 + part;
		input.dst[part] = 0xb0000000 + seed * 16 + part;
	}
	assert(!airoha_ct_ifc_tuple_encode(&words, &input));
	return words;
}

static void live(const struct device *device, const struct airoha_ct_ifc_pool_lease *lease,
		 const struct airoha_ct_ifc_tuple_words *words)
{
	u32 mask = 0;

	assert(airoha_ct_ifc_pool_has(&device->pool, lease));
	assert(lease->count == words->count);
	assert(!device->pool.pending && !device->busy);
	for (unsigned int index = 0; index < words->count; index++) {
		unsigned int slot = lease->slot[index];

		assert(slot < 32 && device->pool.refs[slot]);
		assert(!memcmp(device->hardware[slot], words->lut[index], sizeof(words->lut[index])));
		mask |= BIT(slot);
	}
	assert(mask == lease->mask);
	shadows(device);
}

static void empty(const struct device *device)
{
	struct airoha_ct_ifc_pool zero = {};

	assert(!memcmp(&device->pool, &zero, sizeof(zero)));
	assert(!memcmp(device->hardware, device->original, sizeof(device->hardware)));
	assert(!device->busy && !device->late);
}

static void blocked_drain(struct device *device)
{
	struct airoha_ct_ifc_pool saved = device->pool;
	unsigned int before = device->commands;

	assert(device->pool.pending);
	device->drain_failures = 2;
	for (unsigned int retry = 0; retry < 2; retry++) {
		assert(airoha_ct_ifc_pool_recover(&device->pool, &device->io) == -ETIMEDOUT);
		assert(device->commands == before);
		assert(!memcmp(&device->pool, &saved, sizeof(saved)));
		drain_checks++;
	}
}

static void sharing(void)
{
	struct device device;
	struct airoha_ct_ifc_pool_lease first = {}, second = {}, copied, invalid = {};
	struct airoha_ct_ifc_tuple_words words = tuple(4, 1, true);
	unsigned int puts, commands;

	init(&device, true);
	assert(!airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &first));
	live(&device, &first, &words);
	assert(device.reads == 10 && device.puts == 5);
	assert(device.pool.reserved == 31);
	puts = device.puts;
	assert(!airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &second));
	live(&device, &second, &words);
	assert(first.mask == second.mask && device.puts == puts);
	for (unsigned int slot = 0; slot < 5; slot++)
		assert(device.pool.refs[slot] == 2);
	commands = device.commands;
	assert(airoha_ct_ifc_pool_release(&device.pool, &device.io, &first, false) == -EBUSY);
	copied = first;
	assert(airoha_ct_ifc_pool_release(&device.pool, &device.io, &copied, true) == -EINVAL);
	assert(airoha_ct_ifc_pool_release(&device.pool, &device.io, &invalid, true) == -EINVAL);
	assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &first) == -EBUSY);
	assert(device.commands == commands);
	assert(!airoha_ct_ifc_pool_release(&device.pool, &device.io, &first, true));
	assert(!first.count && !first.mask && device.puts == puts);
	live(&device, &second, &words);
	assert(airoha_ct_ifc_pool_release(&device.pool, &device.io, &first, true) == -EINVAL);
	assert(!airoha_ct_ifc_pool_recover(&device.pool, &device.io));
	live(&device, &second, &words);
	assert(!airoha_ct_ifc_pool_release(&device.pool, &device.io, &second, true));
	assert(device.puts == puts + 5);
	empty(&device);
	cases++;
}

static void capacity(void)
{
	for (unsigned int common = 0; common < 2; common++) {
		struct device device;
		struct airoha_ct_ifc_pool_lease leases[4] = {};
		struct airoha_ct_ifc_tuple_words words[4];

		init(&device, true);
		for (unsigned int index = 0; index < 4; index++) {
			unsigned int puts = device.puts;
			struct airoha_ct_ifc_pool saved = device.pool;
			int err;

			words[index] = tuple(index < 2 ? 4 : 6, index + 1, common);
			err = airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words[index], &leases[index]);
			if (!common && index == 3) {
				assert(err == -ENOSPC && device.puts == puts);
				assert(!memcmp(&device.pool, &saved, sizeof(saved)));
				assert(!leases[index].count && !leases[index].mask);
			} else {
				assert(!err);
				live(&device, &leases[index], &words[index]);
			}
		}
		assert(__builtin_popcount(device.pool.reserved) == (common ? 24 : 21));
		assert(device.puts == (common ? 24U : 21U));
		for (unsigned int index = 4; index-- > 0;)
			if (leases[index].count)
				assert(!airoha_ct_ifc_pool_release(&device.pool, &device.io, &leases[index], true));
		empty(&device);
		cases++;
	}
	struct device device;
	struct airoha_ct_ifc_pool_lease leases[4] = {};

	init(&device, false);
	for (unsigned int index = 0; index < 4; index++) {
		struct airoha_ct_ifc_tuple_words words = tuple(index < 2 ? 4 : 6, index + 1, false);

		assert(!airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &leases[index]));
		live(&device, &leases[index], &words);
	}
	assert(device.pool.reserved == U32_MAX && device.pool.refs[31] == 1);
	for (unsigned int index = 0; index < 4; index++)
		assert(!airoha_ct_ifc_pool_release(&device.pool, &device.io, &leases[index], true));
	empty(&device);
	cases++;
}

static void boundaries(void)
{
	struct device device, foreign;
	struct airoha_ct_ifc_pool_lease lease = {}, extra = {};
	struct airoha_ct_ifc_tuple_words words = tuple(4, 1, true), duplicate = {};
	unsigned int before;

	init(&device, true);
	init(&foreign, true);
	duplicate.count = 3;
	duplicate.lut[0][0] = duplicate.lut[1][0] = duplicate.lut[2][0] = 0x1234;
	duplicate.lut[0][1] = duplicate.lut[1][1] = 0xe003;
	duplicate.lut[2][1] = 0xe004;
	assert(!airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &duplicate, &lease));
	assert(lease.slot[0] == lease.slot[1] && lease.slot[0] != lease.slot[2]);
	assert(device.pool.refs[0] == 1 && device.pool.refs[1] == 1 && device.puts == 2);
	live(&device, &lease, &duplicate);
	assert(airoha_ct_ifc_pool_release(&foreign.pool, &foreign.io, &lease, true) == -EINVAL);
	device.pool.refs[0] = U32_MAX;
	before = device.commands;
	assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &duplicate, &extra) == -EOVERFLOW);
	assert(before == device.commands && !extra.count);
	device.pool.refs[0] = 1;
	device.hardware[0][1] ^= BIT(0);
	before = device.puts;
	assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &duplicate, &extra) == -EUCLEAN);
	assert(before == device.puts && !extra.count && device.pool.refs[0] == 1);
	assert(!airoha_ct_ifc_pool_release(&device.pool, &device.io, &lease, true));
	empty(&device);
	for (unsigned int slot = 0; slot < 32; slot++) {
		memcpy(device.hardware[slot], words.lut[0], sizeof(words.lut[0]));
		memcpy(device.original[slot], words.lut[0], sizeof(words.lut[0]));
	}
	before = device.puts;
	assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &lease) == -ENOSPC);
	assert(device.puts == before);
	empty(&device);
	device.hardware[7][1] = device.original[7][1] = 0x1234;
	words.count = 1;
	assert(!airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &lease));
	assert(lease.mask == BIT(7));
	assert(!airoha_ct_ifc_pool_release(&device.pool, &device.io, &lease, true));
	empty(&device);
	cases++;
}

static void invalid_inputs(void)
{
	struct device device;
	struct airoha_ct_ifc_pool_lease lease = {};
	struct airoha_ct_ifc_tuple_words words = tuple(4, 1, true), bad;
	const u32 controls[] = { 0, 0x6003, 0xc003, 0xe002, 0xe00d, 0xc010, 0xe018, 0xc01a, 0xc058 };

	init(&device, true);
	assert(airoha_ct_ifc_pool_acquire(NULL, &device.io, &words, &lease) == -EINVAL);
	assert(airoha_ct_ifc_pool_acquire(&device.pool, NULL, &words, &lease) == -EINVAL);
	assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, NULL, &lease) == -EINVAL);
	assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, NULL) == -EINVAL);
	assert(airoha_ct_ifc_pool_recover(NULL, &device.io) == -EINVAL);
	for (unsigned int index = 0; index < sizeof(controls) / sizeof(controls[0]); index++) {
		bad = words;
		bad.lut[0][1] = controls[index];
		assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &bad, &lease) == -EINVAL);
	}
	for (unsigned int index = 0; index < 4; index++) {
		bad = words;
		if (index < 2)
			bad.count = index ? 12 : 0;
		else
			bad.lut[index][0] ^= BIT(24);
		assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &bad, &lease) == -EINVAL);
	}
	assert(!device.commands);
	empty(&device);
	cases++;
}

static unsigned int setup(struct device *device, bool shared, bool releasing,
			  struct airoha_ct_ifc_pool_lease *anchor,
			  struct airoha_ct_ifc_pool_lease *target,
			  struct airoha_ct_ifc_tuple_words *words)
{
	init(device, true);
	*anchor = (struct airoha_ct_ifc_pool_lease) {};
	*target = (struct airoha_ct_ifc_pool_lease) {};
	if (shared) {
		struct airoha_ct_ifc_tuple_words base = tuple(4, 1, true);

		assert(!airoha_ct_ifc_pool_acquire(&device->pool, &device->io, &base, anchor));
	}
	*words = tuple(shared ? 6 : 4, 2, true);
	if (releasing)
		assert(!airoha_ct_ifc_pool_acquire(&device->pool, &device->io, words, target));
	return device->commands;
}

static void fault_matrix(bool shared, bool releasing)
{
	struct device baseline;
	struct airoha_ct_ifc_pool_lease anchor = {}, target = {};
	struct airoha_ct_ifc_tuple_words words;
	unsigned int start = setup(&baseline, shared, releasing, &anchor, &target, &words);
	unsigned int positions;

	if (releasing)
		assert(!airoha_ct_ifc_pool_release(&baseline.pool, &baseline.io, &target, true));
	else
		assert(!airoha_ct_ifc_pool_acquire(&baseline.pool, &baseline.io, &words, &target));
	positions = baseline.commands - start;
	assert(positions == (releasing ? (shared ? 18U : 10U) : (shared ? 29U : 15U)));
	for (unsigned int mode = BEFORE; mode <= DEFERRED; mode++) {
		for (unsigned int position = 1; position <= positions; position++) {
			struct device device;
			struct airoha_ct_ifc_pool_lease keeper = {}, lease = {}, extra = {};
			struct airoha_ct_ifc_pool saved;
			unsigned int before;
			int err;

			start = setup(&device, shared, releasing, &keeper, &lease, &words);
			saved = device.pool;
			device.fail_at = start + position;
			device.fault = mode;
			err = releasing ? airoha_ct_ifc_pool_release(&device.pool, &device.io, &lease, true) :
				airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &lease);
			assert(err == -ETIMEDOUT && device.pool.pending);
			assert(!memcmp(device.pool.refs, saved.refs, sizeof(saved.refs)));
			if (releasing) {
				assert(device.pool.releasing == &lease && lease.count == words.count);
				before = device.commands;
				assert(airoha_ct_ifc_pool_release(&device.pool, &device.io, &lease, false) == -EBUSY);
				assert(device.commands == before);
			} else {
				assert(!lease.count && !lease.mask && !lease.next);
			}
			if (device.pool.releasing || airoha_ct_ifc_pool_orphans(&device.pool)) {
				before = device.commands;
				assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &extra) == -EBUSY);
				assert(before == device.commands);
			}
			blocked_drain(&device);
			assert(!airoha_ct_ifc_pool_recover(&device.pool, &device.io));
			assert(!lease.count && !lease.mask);
			if (shared) {
				struct airoha_ct_ifc_tuple_words base = tuple(4, 1, true);

				live(&device, &keeper, &base);
				assert(device.pool.reserved == keeper.mask);
			} else {
				empty(&device);
			}
			assert(!airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &lease));
			live(&device, &lease, &words);
			assert(!airoha_ct_ifc_pool_release(&device.pool, &device.io, &lease, true));
			if (shared)
				assert(!airoha_ct_ifc_pool_release(&device.pool, &device.io, &keeper, true));
			empty(&device);
			cases++;
			fault_cases++;
		}
	}
}

static void recovery_faults(void)
{
	for (unsigned int releasing = 0; releasing < 2; releasing++) {
		for (unsigned int mode = BEFORE; mode <= DEFERRED; mode++) {
			for (unsigned int position = 1; position <= 10; position++) {
				struct device device;
				struct airoha_ct_ifc_pool_lease anchor = {}, lease = {};
				struct airoha_ct_ifc_tuple_words words;
				unsigned int start = setup(&device, false, releasing, &anchor, &lease, &words);
				struct airoha_ct_ifc_pool saved;

				device.fail_at = start + (releasing ? 1 : 15);
				device.fault = DEFERRED;
				if (releasing)
					assert(airoha_ct_ifc_pool_release(&device.pool, &device.io, &lease, true) == -ETIMEDOUT);
				else
					assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &lease) == -ETIMEDOUT);
				device.fail_at = device.commands + position;
				device.fault = mode;
				saved = device.pool;
				assert(airoha_ct_ifc_pool_recover(&device.pool, &device.io) == -ETIMEDOUT);
				assert(!memcmp(&saved, &device.pool, sizeof(saved)));
				blocked_drain(&device);
				assert(!airoha_ct_ifc_pool_recover(&device.pool, &device.io));
				assert(!lease.count && !lease.mask);
				empty(&device);
				cases++;
				fault_cases++;
				retry_cases++;
			}
		}
	}
}

static void readback_mismatches(void)
{
	for (unsigned int releasing = 0; releasing < 2; releasing++) {
		for (unsigned int position = 0; position < 5; position++) {
			struct device device;
			struct airoha_ct_ifc_pool_lease anchor = {}, lease = {};
			struct airoha_ct_ifc_tuple_words words;
			unsigned int start = setup(&device, false, releasing, &anchor, &lease, &words);
			int err;

			device.corrupt_at = start + (releasing ? 2 : 7) + 2 * position;
			err = releasing ? airoha_ct_ifc_pool_release(&device.pool, &device.io, &lease, true) :
				airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &lease);
			assert(err == -EIO && device.pool.pending);
			assert(!!lease.count == !!releasing);
			blocked_drain(&device);
			assert(!airoha_ct_ifc_pool_recover(&device.pool, &device.io));
			empty(&device);
			cases++;
			fault_cases++;
		}
	}
}

static void partial_puts(void)
{
	for (unsigned int releasing = 0; releasing < 2; releasing++) {
		for (unsigned int word = 0; word < 2; word++) {
			struct device baseline, device;
			struct airoha_ct_ifc_pool_lease lease = {};
			struct airoha_ct_ifc_tuple_words words = tuple(4, 1, true);
			struct airoha_ct_ifc_pool_lease saved_lease;
			struct airoha_ct_ifc_pool saved = {};
			unsigned int start, first_put, before;
			int err;

			init(&baseline, true);
			start = baseline.commands;
			assert(!airoha_ct_ifc_pool_acquire(&baseline.pool, &baseline.io, &words, &lease));
			first_put = baseline.reads - baseline.puts + 1;
			assert(first_put == 6);
			assert(baseline.commands - start == 15);
			if (releasing) {
				start = baseline.commands;
				assert(!airoha_ct_ifc_pool_release(&baseline.pool, &baseline.io, &lease, true));
				assert(baseline.commands - start == 10);
				first_put = 1;
			}

			init(&device, true);
			lease = (struct airoha_ct_ifc_pool_lease) {};
			start = device.commands;
			if (releasing) {
				assert(!airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &lease));
				start = device.commands;
				saved = device.pool;
			}
			device.fail_at = start + first_put;
			device.fault = BEFORE;
			device.partial_write = true;
			device.partial_word = word;
			saved_lease = lease;
			err = releasing ? airoha_ct_ifc_pool_release(&device.pool, &device.io, &lease, true) :
				airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &lease);
			assert(err == -ETIMEDOUT && device.pool.pending && device.busy);
			if (releasing) {
				assert(device.pool.releasing == &lease && lease.count == words.count);
				assert(!memcmp(lease.slot, saved_lease.slot, sizeof(lease.slot)));
				assert(!memcmp(device.pool.refs, saved.refs, sizeof(saved.refs)));
			} else {
				assert(!lease.count && !lease.mask && !lease.next);
				assert(!device.pool.refs[0] && device.pool.reserved);
				assert(airoha_ct_ifc_pool_orphans(&device.pool));
			}
			assert((device.pool.reserved & BIT(0)) && (device.pool.dirty & BIT(0)));
			assert(!memcmp(device.pool.saved[0], device.original[0], sizeof(device.original[0])));
			assert(device.hardware[0][word] ==
			       (releasing ? device.original[0][word] : words.lut[0][word]));
			assert(device.hardware[0][!word] ==
			       (releasing ? words.lut[0][!word] : device.original[0][!word]));
			before = device.commands;
			blocked_drain(&device);
			assert(device.commands == before && device.pool.pending);
			assert(!airoha_ct_ifc_pool_recover(&device.pool, &device.io));
			assert(!lease.count && !lease.mask);
			empty(&device);
			cases++;
			fault_cases++;
			review_cases++;
		}
	}
}

static void deferred_drain_failures(void)
{
	for (unsigned int releasing = 0; releasing < 2; releasing++) {
		struct device device;
		struct airoha_ct_ifc_pool_lease lease = {};
		struct airoha_ct_ifc_pool_lease extra = {};
		struct airoha_ct_ifc_tuple_words words = tuple(4, 1, true);
		struct airoha_ct_ifc_tuple_words other = tuple(4, 2, true);
		struct airoha_ct_ifc_pool saved;
		const u32 *late, *before_drain;
		unsigned int start, first_put, before;
		int err;

		init(&device, true);
		start = device.commands;
		if (releasing) {
			assert(!airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &lease));
			start = device.commands;
		}
		first_put = releasing ? 1 : 6;
		device.fail_at = start + first_put;
		device.fault = DEFERRED;
		device.late_on_failed_drain = true;
		err = releasing ? airoha_ct_ifc_pool_release(&device.pool, &device.io, &lease, true) :
			airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &words, &lease);
		assert(err == -ETIMEDOUT && device.pool.pending && device.late);
		before_drain = releasing ? words.lut[0] : device.original[0];
		late = releasing ? device.original[0] : words.lut[0];
		assert(!memcmp(device.hardware[0], before_drain, sizeof(device.hardware[0])));
		if (releasing) {
			assert(device.pool.releasing == &lease && lease.count == words.count);
			assert(device.pool.refs[0] == 1);
		} else {
			assert(!lease.count && !lease.mask);
			assert(device.pool.reserved && airoha_ct_ifc_pool_orphans(&device.pool));
		}
		saved = device.pool;
		before = device.commands;
		device.drain_failures = 1;
		assert(airoha_ct_ifc_pool_recover(&device.pool, &device.io) == -ETIMEDOUT);
		assert(device.pool.pending && !device.late);
		assert(device.commands == before);
		assert(!memcmp(&device.pool, &saved, sizeof(saved)));
		assert(!memcmp(device.hardware[0], late, sizeof(device.hardware[0])));
		if (releasing) {
			assert(device.pool.releasing == &lease && lease.count == words.count);
			assert(device.pool.refs[0] == 1);
		} else {
			assert(!lease.count && !lease.mask);
			assert(device.pool.reserved && airoha_ct_ifc_pool_orphans(&device.pool));
		}
		device.drain_failures = 0;
		assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &other, &extra) == -EBUSY);
		assert(device.commands == before && !extra.count && !extra.mask);
		assert(device.pool.pending && !memcmp(&device.pool, &saved, sizeof(saved)));
		assert(!airoha_ct_ifc_pool_recover(&device.pool, &device.io));
		assert(!lease.count && !lease.mask);
		empty(&device);
		cases++;
		fault_cases++;
		retry_cases++;
		review_cases++;
	}
}

static void shared_restore_retry(void)
{
	struct device baseline, device;
	struct airoha_ct_ifc_pool_lease first = {}, second = {};
	struct airoha_ct_ifc_tuple_words first_words = tuple(4, 1, true);
	struct airoha_ct_ifc_tuple_words second_words = tuple(6, 2, true);
	struct airoha_ct_ifc_pool saved;
	unsigned int start, before;

	init(&baseline, true);
	assert(!airoha_ct_ifc_pool_acquire(&baseline.pool, &baseline.io, &first_words, &first));
	assert(!airoha_ct_ifc_pool_acquire(&baseline.pool, &baseline.io, &second_words, &second));
	assert(first.mask & second.mask && __builtin_popcount(first.mask & second.mask) == 2);
	start = baseline.commands;
	assert(!airoha_ct_ifc_pool_release(&baseline.pool, &baseline.io, &first, true));
	assert(baseline.commands - start == 6);

	init(&device, true);
	first = (struct airoha_ct_ifc_pool_lease) {};
	second = (struct airoha_ct_ifc_pool_lease) {};
	assert(!airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &first_words, &first));
	assert(!airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &second_words, &second));
	saved = device.pool;
	start = device.commands;
	device.fail_at = start + 3;
	device.fault = BEFORE;
	assert(airoha_ct_ifc_pool_release(&device.pool, &device.io, &first, true) == -ETIMEDOUT);
	assert(device.pool.pending && device.pool.releasing == &first);
	assert(first.count == first_words.count && second.count == second_words.count);
	assert(!memcmp(device.pool.refs, saved.refs, sizeof(saved.refs)));
	assert(!memcmp(device.pool.words, saved.words, sizeof(saved.words)));
	assert(!memcmp(device.pool.saved, saved.saved, sizeof(saved.saved)));
	before = device.commands;
	assert(airoha_ct_ifc_pool_release(&device.pool, &device.io, &second, true) == -EBUSY);
	assert(device.commands == before && !memcmp(device.pool.refs, saved.refs, sizeof(saved.refs)));
	assert(device.pool.releasing == &first && first.count == first_words.count &&
	       second.count == second_words.count);
	assert(!airoha_ct_ifc_pool_release(&device.pool, &device.io, &first, true));
	assert(!first.count && !first.mask && !device.pool.releasing);
	for (unsigned int slot = 0; slot < 32; slot++)
		if (saved.refs[slot])
			assert(device.pool.refs[slot] == (second.mask & BIT(slot) ? 1 : 0));
	live(&device, &second, &second_words);
	for (unsigned int slot = 0; slot < 32; slot++)
		if (second.mask & BIT(slot))
			assert(device.pool.refs[slot] == 1);
	assert(device.pool.reserved == second.mask);
	start = device.commands;
	assert(!airoha_ct_ifc_pool_release(&device.pool, &device.io, &second, true));
	assert(device.commands - start == 22);
	empty(&device);
	cases++;
	fault_cases++;
	retry_cases++;
	review_cases++;
}

static void orphan_blocks_release(void)
{
	struct device baseline, device;
	struct airoha_ct_ifc_pool_lease first = {}, attempt = {}, extra = {};
	struct airoha_ct_ifc_tuple_words first_words = tuple(4, 1, true);
	struct airoha_ct_ifc_tuple_words attempt_words = tuple(6, 3, true);
	struct airoha_ct_ifc_tuple_words extra_words = tuple(4, 4, true);
	struct airoha_ct_ifc_pool saved;
	unsigned int start, first_put, before;
	unsigned int before_reads, before_puts, after_reads, after_puts;

	init(&baseline, true);
	assert(!airoha_ct_ifc_pool_acquire(&baseline.pool, &baseline.io, &first_words, &first));
	start = baseline.commands;
	before_reads = baseline.reads;
	before_puts = baseline.puts;
	assert(!airoha_ct_ifc_pool_acquire(&baseline.pool, &baseline.io, &attempt_words, &attempt));
	after_reads = baseline.reads;
	after_puts = baseline.puts;
	first_put = (after_reads - before_reads) - (after_puts - before_puts) + 1;
	assert(first_put == 12);
	assert(baseline.commands - start == 29);
	assert(!airoha_ct_ifc_pool_release(&baseline.pool, &baseline.io, &first, true));
	assert(!airoha_ct_ifc_pool_release(&baseline.pool, &baseline.io, &attempt, true));
	empty(&baseline);

	init(&device, true);
	first = (struct airoha_ct_ifc_pool_lease) {};
	attempt = (struct airoha_ct_ifc_pool_lease) {};
	extra = (struct airoha_ct_ifc_pool_lease) {};
	assert(!airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &first_words, &first));
	saved = device.pool;
	start = device.commands;
	device.fail_at = start + first_put;
	device.fault = BEFORE;
	assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &attempt_words, &attempt) ==
	       -ETIMEDOUT);
	assert(device.pool.pending && !attempt.count && !attempt.mask);
	assert(airoha_ct_ifc_pool_orphans(&device.pool));
	assert(airoha_ct_ifc_pool_orphans(&device.pool) == (device.pool.reserved & ~first.mask));
	assert(!memcmp(device.pool.refs, saved.refs, sizeof(saved.refs)));
	before = device.commands;
	assert(airoha_ct_ifc_pool_release(&device.pool, &device.io, &first, true) == -EBUSY);
	assert(device.commands == before && !device.pool.releasing);
	assert(first.count == first_words.count && !memcmp(device.pool.refs, saved.refs, sizeof(saved.refs)));
	assert(airoha_ct_ifc_pool_acquire(&device.pool, &device.io, &extra_words, &extra) == -EBUSY);
	assert(device.commands == before && !extra.count && !extra.mask);
	blocked_drain(&device);
	assert(!airoha_ct_ifc_pool_recover(&device.pool, &device.io));
	assert(device.pool.reserved == first.mask);
	live(&device, &first, &first_words);
	assert(!airoha_ct_ifc_pool_release(&device.pool, &device.io, &first, true));
	empty(&device);
	cases++;
	fault_cases++;
	retry_cases++;
	review_cases++;
}

int main(void)
{
	sharing();
	capacity();
	boundaries();
	invalid_inputs();
	for (unsigned int shared = 0; shared < 2; shared++)
		for (unsigned int releasing = 0; releasing < 2; releasing++)
			fault_matrix(shared, releasing);
	recovery_faults();
	readback_mismatches();
	partial_puts();
	deferred_drain_failures();
	shared_restore_retry();
	orphan_blocks_release();
	printf("{\"passed\":true,\"cases\":%u,\"fault_cases\":%u,"
	       "\"recovery_fault_cases\":%u,\"review_cases\":%u,"
	       "\"failed_drain_checks\":%u,\"checked_io\":%u}\n",
	       cases, fault_cases, retry_cases, review_cases, drain_checks, checked_io);
	return 0;
}
