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
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#include "airoha_ct_pon_ifc_owner.h"

enum operation { SNAPSHOT, PUBLISH, RESTORE, WITHDRAW };
enum fault_mode { NO_FAULT, BEFORE_EFFECT, AFTER_EFFECT, AFTER_TIMEOUT, DELAYED_EFFECT };

struct command {
	bool write;
	unsigned int bank, row, page, count;
	u32 words[3];
};

struct device {
	struct airoha_ct_pon_ifc_owner owner;
	struct airoha_ct_pon_ifc_io io;
	struct airoha_ct_pon_ifc_words hardware[4], original[4];
	struct command late;
	enum operation operation;
	enum fault_mode fault;
	unsigned int fail_at, commands, reads, puts, drains;
	unsigned int drain_failures;
	bool busy, late_valid, finish_on_failed_drain;
	bool dependencies_started;
	u8 target, closed_ack;
	u16 dependencies[4];
};

static unsigned int cases, fault_cases, drain_checks, commands_checked, retry_fault_cases;

static int fault_error(unsigned int mode)
{
	return mode >= AFTER_TIMEOUT ? -ETIMEDOUT : -EIO;
}

static void check_state(const struct device *device)
{
	const struct airoha_ct_pon_ifc_owner *owner = &device->owner;

	assert((owner->active & 3) == 0 || (owner->active & 3) == 3);
	assert((owner->active & 12) == 0 || (owner->active & 12) == 12);
	assert(!(owner->active & ~owner->dirty));
	if (owner->saved_valid)
		assert(!memcmp(owner->saved, device->original, sizeof(owner->saved)));
}

static void address_check(unsigned int bank, unsigned int row,
			  unsigned int page, unsigned int count)
{
	assert(row >= AIROHA_CT_PON_IFC_ROW_BASE && row < AIROHA_CT_PON_IFC_ROW_BASE + 4);
	assert(bank == 0 || bank == 2);
	if (bank == 0)
		assert(page < 9 && count == 2);
	else
		assert(page < 3 && count == (page == 0 ? 2 : page == 1 ? 3 : 1));
}

static u32 *hardware_page(struct device *device, const struct command *command)
{
	struct airoha_ct_pon_ifc_words *row =
		&device->hardware[command->row - AIROHA_CT_PON_IFC_ROW_BASE];

	return command->bank == 0 ? row->tcam[command->page] : row->action[command->page];
}

static bool dependencies_ready(const struct device *device)
{
	for (unsigned int row = 0; row < 4; row++)
		if ((device->target & BIT(row)) && device->dependencies[row] != 0x7ff)
			return false;
	return true;
}

static void put_check(struct device *device, const struct command *command)
{
	unsigned int row = command->row - AIROHA_CT_PON_IFC_ROW_BASE;
	bool action2 = command->bank == 2 && command->page == 2;

	assert(device->operation != SNAPSHOT);
	assert(device->target & BIT(row));
	assert(device->owner.saved_valid && (device->owner.dirty & BIT(row)));
	assert(!(device->owner.active & device->target));
	if (!action2) {
		assert(device->closed_ack == device->target);
		for (unsigned int index = 0; index < 4; index++)
			if (device->target & BIT(index))
				assert(!(device->hardware[index].action[2][0] & BIT(31)));
		device->dependencies_started = true;
	} else if ((command->words[0] & BIT(31)) || device->dependencies_started) {
		assert(device->closed_ack == device->target && dependencies_ready(device));
		if (device->operation != PUBLISH)
			assert(!(command->words[0] & BIT(31)));
	} else {
		assert(command->words[0] == 0);
	}
}

static void acknowledge(struct device *device, const struct command *command)
{
	unsigned int row = command->row - AIROHA_CT_PON_IFC_ROW_BASE;

	if (!command->write)
		return;
	if (command->bank == 0)
		device->dependencies[row] |= BIT(command->page);
	else if (command->page < 2)
		device->dependencies[row] |= BIT(9 + command->page);
	else if (!device->dependencies_started && !(command->words[0] & BIT(31)))
		device->closed_ack |= BIT(row);
}

static int execute(struct device *device, struct command *command, u32 *output)
{
	bool fail;

	assert(!device->busy);
	address_check(command->bank, command->row, command->page, command->count);
	check_state(device);
	if (command->write)
		put_check(device, command);
	else
		assert(device->operation == SNAPSHOT && !device->owner.saved_valid);
	device->commands++;
	commands_checked++;
	fail = device->fail_at == device->commands;
	if (command->write)
		device->puts++;
	else
		device->reads++;
	if (fail && device->fault == DELAYED_EFFECT) {
		device->late = *command;
		device->late_valid = device->busy = true;
		return -ETIMEDOUT;
	}
	if (!(fail && device->fault == BEFORE_EFFECT)) {
		if (command->write)
			memcpy(hardware_page(device, command), command->words,
			       command->count * sizeof(u32));
		else
			memcpy(output, hardware_page(device, command), command->count * sizeof(u32));
	}
	if (fail) {
		device->busy = true;
		return fault_error(device->fault);
	}
	acknowledge(device, command);
	return 0;
}

static int read_words(void *context, unsigned int bank, unsigned int row,
		      unsigned int page, u32 *words, unsigned int count)
{
	struct device *device = context;
	struct command command = { .bank = bank, .row = row, .page = page, .count = count };

	return execute(device, &command, words);
}

static int put_words(void *context, unsigned int bank, unsigned int row,
		     unsigned int page, const u32 *words, unsigned int count)
{
	struct device *device = context;
	struct command command = {
		.write = true, .bank = bank, .row = row, .page = page, .count = count,
	};

	assert(count <= 3);
	memcpy(command.words, words, count * sizeof(u32));
	return execute(device, &command, NULL);
}

static void finish_late(struct device *device)
{
	if (device->late_valid && device->late.write)
		memcpy(hardware_page(device, &device->late), device->late.words,
		       device->late.count * sizeof(u32));
	device->late_valid = false;
}

static int drain(void *context)
{
	struct device *device = context;

	assert(device->owner.pending);
	device->drains++;
	if (device->drain_failures) {
		device->drain_failures--;
		if (device->finish_on_failed_drain)
			finish_late(device);
		return -EAGAIN;
	}
	finish_late(device);
	device->busy = false;
	return 0;
}

static void begin(struct device *device, enum operation operation, u8 target)
{
	device->operation = operation;
	device->target = target;
	device->commands = device->reads = device->puts = device->drains = 0;
	device->fail_at = device->drain_failures = 0;
	device->fault = NO_FAULT;
	device->dependencies_started = device->finish_on_failed_drain = false;
	device->closed_ack = 0;
	memset(device->dependencies, 0, sizeof(device->dependencies));
}

static void initialize(struct device *device)
{
	memset(device, 0, sizeof(*device));
	device->io = (struct airoha_ct_pon_ifc_io) {
		.ctx = device, .read = read_words, .put = put_words, .drain = drain,
	};
	for (unsigned int row = 0; row < 4; row++) {
		for (unsigned int page = 0; page < 9; page++)
			for (unsigned int word = 0; word < 2; word++)
				device->hardware[row].tcam[page][word] =
					0x12345678 ^ (row << 20) ^ (page << 12) ^ (word << 8);
		for (unsigned int page = 0; page < 3; page++)
			for (unsigned int word = 0; word < airoha_ct_pon_ifc_action_words[page]; word++)
				device->hardware[row].action[page][word] =
					0x65432101 ^ (row << 20) ^ (page << 12) ^ (word << 8);
	}
	memcpy(device->original, device->hardware, sizeof(device->original));
	begin(device, SNAPSHOT, 15);
}

static void encode(struct airoha_ct_pon_ifc_words rows[2], unsigned int slot, bool update)
{
	u16 service = (slot ? 0xa134 : 0x2134) + (update ? 9 : 0);

	assert(!airoha_ct_pon_ifc_cpu_encode(&rows[0], service, ETH_P_IP, slot ? 4 : 2, 31));
	assert(!airoha_ct_pon_ifc_cpu_encode(&rows[1], service, ETH_P_IPV6, slot ? 4 : 2, 30));
}

static void snapshot(struct device *device)
{
	begin(device, SNAPSHOT, 15);
	assert(!airoha_ct_pon_ifc_snapshot(&device->owner, &device->io));
	assert(device->reads == 48 && !device->puts && !device->owner.dirty &&
	       !device->owner.active && device->owner.saved_valid && !device->owner.pending);
	check_state(device);
}

static void publish(struct device *device, unsigned int slot, bool update)
{
	struct airoha_ct_pon_ifc_words rows[2], other[2];
	unsigned int first = slot * 2, peer = (1 - slot) * 2;
	u8 previous_active = device->owner.active;

	encode(rows, slot, update);
	memcpy(other, device->hardware + peer, sizeof(other));
	begin(device, PUBLISH, 3 << first);
	assert(!airoha_ct_pon_ifc_publish(&device->owner, &device->io, slot, rows));
	assert(device->puts == 26 && !device->reads && !device->owner.pending);
	assert(device->owner.active == (previous_active | (3 << first)));
	assert(!memcmp(device->hardware + first, rows, sizeof(rows)));
	assert(!memcmp(device->hardware + peer, other, sizeof(other)));
	check_state(device);
}

static void prepare(struct device *device, bool both)
{
	initialize(device);
	snapshot(device);
	publish(device, 0, false);
	if (both)
		publish(device, 1, false);
}

static void restored(const struct device *device)
{
	assert(!device->owner.saved_valid && !device->owner.pending &&
	       !device->owner.dirty && !device->owner.active && !device->busy);
	assert(!memcmp(device->hardware, device->original, sizeof(device->hardware)));
}

static void restore(struct device *device)
{
	unsigned int count = __builtin_popcount(device->owner.dirty);

	begin(device, RESTORE, device->owner.dirty);
	assert(!airoha_ct_pon_ifc_restore(&device->owner, &device->io));
	assert(device->puts == count * 13 && !device->reads);
	restored(device);
}

static int retry(struct device *device, enum operation operation, unsigned int slot)
{
	struct airoha_ct_pon_ifc_words rows[2];

	encode(rows, slot, true);
	switch (operation) {
	case SNAPSHOT:
		return airoha_ct_pon_ifc_snapshot(&device->owner, &device->io);
	case PUBLISH:
		return airoha_ct_pon_ifc_publish(&device->owner, &device->io, slot, rows);
	case WITHDRAW:
		return airoha_ct_pon_ifc_withdraw(&device->owner, &device->io, slot);
	case RESTORE:
		return airoha_ct_pon_ifc_restore(&device->owner, &device->io);
	}
	assert(false);
	return -EINVAL;
}

static void failed_drain(struct device *device, enum operation operation, unsigned int slot,
			 u8 target)
{
	struct airoha_ct_pon_ifc_owner previous = device->owner;

	for (unsigned int completed = 0; completed < 2; completed++) {
		begin(device, operation, target);
		device->drain_failures = 1;
		device->finish_on_failed_drain = completed;
		assert(retry(device, operation, slot) == -EAGAIN);
		assert(device->drains == 1 && !device->commands);
		assert(!memcmp(&previous, &device->owner, sizeof(previous)));
		drain_checks++;
	}
}

static void lifecycle(void)
{
	struct device device;
	struct airoha_ct_pon_ifc_words other[2];

	prepare(&device, true);
	publish(&device, 0, true);
	memcpy(other, device.hardware + 2, sizeof(other));
	begin(&device, WITHDRAW, 3);
	assert(!airoha_ct_pon_ifc_withdraw(&device.owner, &device.io, 0));
	assert(device.puts == 26 && device.owner.dirty == 12 &&
	       device.owner.active == 12 && device.owner.saved_valid);
	assert(!memcmp(device.hardware, device.original, 2 * sizeof(other[0])));
	assert(!memcmp(device.hardware + 2, other, sizeof(other)));
	check_state(&device);
	begin(&device, WITHDRAW, 3);
	assert(!airoha_ct_pon_ifc_withdraw(&device.owner, &device.io, 0));
	assert(device.owner.saved_valid && device.owner.active == 12 && device.owner.dirty == 12);
	publish(&device, 0, true);
	begin(&device, WITHDRAW, 12);
	assert(!airoha_ct_pon_ifc_withdraw(&device.owner, &device.io, 1));
	assert(device.owner.saved_valid && device.owner.active == 3 && device.owner.dirty == 3);
	restore(&device);
	restore(&device);
	snapshot(&device);
	begin(&device, RESTORE, 0);
	assert(!airoha_ct_pon_ifc_restore(&device.owner, &device.io) && !device.commands);
	restored(&device);
	cases++;
	for (unsigned int slot = 0; slot < 2; slot++) {
		initialize(&device);
		snapshot(&device);
		publish(&device, slot, false);
		restore(&device);
		cases++;
	}
	prepare(&device, true);
	for (unsigned int slot = 0; slot < 2; slot++) {
		begin(&device, WITHDRAW, 3 << (slot * 2));
		assert(!airoha_ct_pon_ifc_withdraw(&device.owner, &device.io, slot));
	}
	assert(device.owner.saved_valid && !device.owner.dirty && !device.owner.active);
	assert(airoha_ct_pon_ifc_snapshot(&device.owner, &device.io) == -EBUSY);
	restore(&device);
	cases++;
}

static void invalid_inputs(void)
{
	struct device device;
	struct airoha_ct_pon_ifc_words rows[2];
	struct airoha_ct_pon_ifc_io invalid;

	initialize(&device);
	encode(rows, 0, false);
	assert(airoha_ct_pon_ifc_snapshot(NULL, &device.io) == -EINVAL);
	assert(airoha_ct_pon_ifc_snapshot(&device.owner, NULL) == -EINVAL);
	assert(airoha_ct_pon_ifc_publish(NULL, &device.io, 0, rows) == -EINVAL);
	assert(airoha_ct_pon_ifc_restore(NULL, &device.io) == -EINVAL);
	assert(airoha_ct_pon_ifc_withdraw(NULL, &device.io, 0) == -EINVAL);
	for (unsigned int field = 0; field < 3; field++) {
		invalid = device.io;
		if (field == 0)
			invalid.read = NULL;
		else if (field == 1)
			invalid.put = NULL;
		else
			invalid.drain = NULL;
		assert(airoha_ct_pon_ifc_snapshot(&device.owner, &invalid) == -EINVAL);
		assert(airoha_ct_pon_ifc_publish(&device.owner, &invalid, 0, rows) == -EINVAL);
		assert(airoha_ct_pon_ifc_withdraw(&device.owner, &invalid, 0) == -EINVAL);
		assert(airoha_ct_pon_ifc_restore(&device.owner, &invalid) == -EINVAL);
	}
	assert(airoha_ct_pon_ifc_publish(&device.owner, &device.io, 0, rows) == -EINVAL);
	assert(airoha_ct_pon_ifc_withdraw(&device.owner, &device.io, 0) == -EINVAL);
	assert(!device.commands && !device.drains);
	snapshot(&device);
	begin(&device, PUBLISH, 3);
	assert(airoha_ct_pon_ifc_snapshot(&device.owner, &device.io) == -EBUSY);
	assert(airoha_ct_pon_ifc_publish(&device.owner, &device.io, 2, rows) == -EINVAL);
	assert(airoha_ct_pon_ifc_publish(&device.owner, &device.io, 0, NULL) == -EINVAL);
	assert(airoha_ct_pon_ifc_withdraw(&device.owner, &device.io, 2) == -EINVAL);
	for (unsigned int row = 0; row < 2; row++) {
		encode(rows, 0, false);
		rows[row].action[2][0] &= ~BIT(31);
		assert(airoha_ct_pon_ifc_publish(&device.owner, &device.io, 0, rows) == -EINVAL);
	}
	assert(!device.commands && !device.drains);
	check_state(&device);
	initialize(&device);
	device.owner.dirty = 1;
	assert(airoha_ct_pon_ifc_restore(&device.owner, &device.io) == -EUCLEAN);
	assert(airoha_ct_pon_ifc_snapshot(&device.owner, &device.io) == -EBUSY);
	device.owner.dirty = 0;
	device.owner.active = 3;
	assert(airoha_ct_pon_ifc_restore(&device.owner, &device.io) == -EUCLEAN);
	assert(airoha_ct_pon_ifc_snapshot(&device.owner, &device.io) == -EBUSY);
	assert(!device.commands && !device.drains);
	cases++;
}

static void snapshot_faults(void)
{
	struct device device;

	for (unsigned int row = 0; row < 4; row++) {
		initialize(&device);
		device.hardware[row].action[2][0] |= BIT(31);
		assert(airoha_ct_pon_ifc_snapshot(&device.owner, &device.io) == -EBUSY);
		assert(device.reads == 48 && !device.puts && !device.owner.saved_valid &&
		       !device.owner.pending && !device.owner.dirty);
		device.hardware[row].action[2][0] &= ~BIT(31);
		snapshot(&device);
		cases++;
	}
	for (unsigned int mode = BEFORE_EFFECT; mode <= DELAYED_EFFECT; mode++)
		for (unsigned int position = 1; position <= 48; position++) {
			initialize(&device);
			device.fault = mode;
			device.fail_at = position;
			assert(airoha_ct_pon_ifc_snapshot(&device.owner, &device.io) == fault_error(mode));
			assert(device.reads == position && !device.puts && device.owner.pending &&
			       !device.owner.saved_valid && !device.owner.dirty && !device.owner.active);
			failed_drain(&device, SNAPSHOT, 0, 15);
			begin(&device, SNAPSHOT, 15);
			assert(!retry(&device, SNAPSHOT, 0));
			assert(device.drains == 1 && device.reads == 48 && device.owner.saved_valid &&
			       !device.owner.pending);
			check_state(&device);
			cases++;
			fault_cases++;
		}
	initialize(&device);
	device.fault = DELAYED_EFFECT;
	device.fail_at = 3;
	assert(airoha_ct_pon_ifc_snapshot(&device.owner, &device.io) == -ETIMEDOUT);
	failed_drain(&device, RESTORE, 0, 0);
	begin(&device, RESTORE, 0);
	assert(!airoha_ct_pon_ifc_restore(&device.owner, &device.io));
	assert(device.drains == 1 && !device.commands);
	restored(&device);
	snapshot(&device);
	cases++;
}

static void publish_faults(void)
{
	struct device device;
	struct airoha_ct_pon_ifc_words rows[2], other[2];

	for (unsigned int initial = 0; initial < 2; initial++)
		for (unsigned int slot = 0; slot < 2; slot++)
			for (unsigned int mode = BEFORE_EFFECT; mode <= DELAYED_EFFECT; mode++)
				for (unsigned int position = 1; position <= 26; position++) {
					unsigned int first = slot * 2, peer = (1 - slot) * 2;
					u8 mask = 3 << first, peer_mask = 3 << peer;

					initialize(&device);
					snapshot(&device);
					publish(&device, 1 - slot, false);
					if (!initial)
						publish(&device, slot, false);
					encode(rows, slot, true);
					memcpy(other, device.hardware + peer, sizeof(other));
					begin(&device, PUBLISH, mask);
					device.fault = mode;
					device.fail_at = position;
					assert(airoha_ct_pon_ifc_publish(&device.owner, &device.io, slot, rows) ==
					       fault_error(mode));
					assert(device.puts == position && !device.reads && device.owner.pending &&
					       device.owner.saved_valid && device.owner.dirty == 15 &&
					       device.owner.active == peer_mask);
					assert(!memcmp(device.hardware + peer, other, sizeof(other)));
					check_state(&device);
					failed_drain(&device, PUBLISH, slot, mask);
					begin(&device, PUBLISH, mask);
					assert(!retry(&device, PUBLISH, slot));
					assert(device.drains == 1 && device.puts == 26 &&
					       device.owner.active == 15 && device.owner.dirty == 15 &&
					       !device.owner.pending);
					assert(!memcmp(device.hardware + first, rows, sizeof(rows)));
					assert(!memcmp(device.hardware + peer, other, sizeof(other)));
					restore(&device);
					cases++;
					fault_cases++;
				}
}

static void restore_faults(void)
{
	struct device device;

	for (unsigned int mode = BEFORE_EFFECT; mode <= DELAYED_EFFECT; mode++)
		for (unsigned int position = 1; position <= 52; position++) {
			unsigned int completed = position > 49 ? position - 49 : 0;
			u8 expected_dirty = 15 & ~((1 << completed) - 1);

			prepare(&device, true);
			begin(&device, RESTORE, 15);
			device.fault = mode;
			device.fail_at = position;
			assert(airoha_ct_pon_ifc_restore(&device.owner, &device.io) == fault_error(mode));
			assert(device.puts == position && !device.reads && device.owner.pending &&
			       device.owner.saved_valid && !device.owner.active &&
			       device.owner.dirty == expected_dirty);
			check_state(&device);
			failed_drain(&device, RESTORE, 0, expected_dirty);
			restore(&device);
			assert(device.drains == 1);
			cases++;
			fault_cases++;
		}
}

static void withdraw_faults(void)
{
	struct device device;
	struct airoha_ct_pon_ifc_words other[2];

	for (unsigned int slot = 0; slot < 2; slot++)
		for (unsigned int mode = BEFORE_EFFECT; mode <= DELAYED_EFFECT; mode++)
			for (unsigned int position = 1; position <= 26; position++) {
				unsigned int first = slot * 2, peer = (1 - slot) * 2;
				u8 mask = 3 << first, peer_mask = 3 << peer;
				u8 expected_dirty = position == 26 ? 15 & ~BIT(first) : 15;

				prepare(&device, true);
				memcpy(other, device.hardware + peer, sizeof(other));
				begin(&device, WITHDRAW, mask);
				device.fault = mode;
				device.fail_at = position;
				assert(airoha_ct_pon_ifc_withdraw(&device.owner, &device.io, slot) ==
				       fault_error(mode));
				assert(device.puts == position && !device.reads && device.owner.pending &&
				       device.owner.saved_valid && device.owner.active == peer_mask &&
				       device.owner.dirty == expected_dirty);
				assert(!memcmp(device.hardware + peer, other, sizeof(other)));
				check_state(&device);
				failed_drain(&device, WITHDRAW, slot, mask);
				begin(&device, WITHDRAW, mask);
				assert(!retry(&device, WITHDRAW, slot));
				assert(device.drains == 1 && device.puts == 26 && !device.owner.pending &&
				       device.owner.saved_valid && device.owner.dirty == peer_mask &&
				       device.owner.active == peer_mask);
				assert(!memcmp(device.hardware + first, device.original + first,
					       2 * sizeof(other[0])));
				assert(!memcmp(device.hardware + peer, other, sizeof(other)));
				publish(&device, 1 - slot, true);
				restore(&device);
				cases++;
				fault_cases++;
			}
}

static void direct_restore_faults(void)
{
	struct device device;
	enum operation operations[] = { PUBLISH, WITHDRAW };
	struct airoha_ct_pon_ifc_words other[2];

	for (unsigned int operation = 0; operation < 2; operation++)
		for (unsigned int slot = 0; slot < 2; slot++)
			for (unsigned int mode = BEFORE_EFFECT; mode <= DELAYED_EFFECT; mode++)
				for (unsigned int position = 1; position <= 26; position++) {
					unsigned int peer = (1 - slot) * 2;

					prepare(&device, true);
					memcpy(other, device.hardware + peer, sizeof(other));
					begin(&device, operations[operation], 3 << (slot * 2));
					device.fault = mode;
					device.fail_at = position;
					assert(retry(&device, operations[operation], slot) == fault_error(mode));
					assert(device.commands == position && device.owner.pending &&
					       device.owner.saved_valid);
					assert(!memcmp(device.hardware + peer, other, sizeof(other)));
					restore(&device);
					assert(device.drains == 1);
					cases++;
					fault_cases++;
				}
}

static void retry_faults(void)
{
	struct device device;
	enum operation operations[] = { SNAPSHOT, PUBLISH, WITHDRAW, RESTORE };

	for (unsigned int operation = 0; operation < 4; operation++) {
		enum operation current = operations[operation];
		unsigned int slots = current == PUBLISH || current == WITHDRAW ? 2 : 1;
		unsigned int first_count = current == SNAPSHOT ? 48 : current == RESTORE ? 52 : 26;
		unsigned int retry_count = current == RESTORE ? 13 : first_count;

		for (unsigned int slot = 0; slot < slots; slot++)
			for (unsigned int mode = BEFORE_EFFECT; mode <= DELAYED_EFFECT; mode++)
				for (unsigned int position = 1; position <= retry_count; position++) {
					u8 target = current == SNAPSHOT || current == RESTORE ? 15 : 3 << (slot * 2);

					if (current == SNAPSHOT)
						initialize(&device);
					else
						prepare(&device, true);
					begin(&device, current, target);
					device.fault = AFTER_TIMEOUT;
					device.fail_at = first_count;
					assert(retry(&device, current, slot) == -ETIMEDOUT);
					assert(device.commands == first_count && device.owner.pending);
					if (current == RESTORE)
						target = device.owner.dirty;
					failed_drain(&device, current, slot, target);
					begin(&device, current, target);
					device.fault = mode;
					device.fail_at = position;
					assert(retry(&device, current, slot) == fault_error(mode));
					assert(device.commands == position && device.drains == 1 &&
					       device.owner.pending && device.owner.saved_valid == (current != SNAPSHOT));
					check_state(&device);
					failed_drain(&device, current, slot, target);
					begin(&device, current, target);
					assert(!retry(&device, current, slot));
					assert(device.commands == retry_count && device.drains == 1 &&
					       !device.owner.pending);
					check_state(&device);
					restore(&device);
					cases++;
					fault_cases++;
					retry_fault_cases++;
				}
	}
}

int main(void)
{
	invalid_inputs();
	lifecycle();
	snapshot_faults();
	publish_faults();
	restore_faults();
	withdraw_faults();
	direct_restore_faults();
	retry_faults();
	printf("{\"passed\":true,\"cases\":%u,\"fault_cases\":%u,\"failed_drain_checks\":%u,"
	       "\"commands_checked\":%u,\"snapshot_positions\":48,\"publish_positions_per_slot\":26,"
	       "\"restore_positions\":52,\"withdraw_positions_per_slot\":26,"
	       "\"direct_restore_positions_per_slot\":26,\"fault_modes\":4,\"retry_fault_cases\":%u}\n",
	       cases, fault_cases, drain_checks, commands_checked, retry_fault_cases);
	return 0;
}
