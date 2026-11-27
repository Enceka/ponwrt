#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "airoha_npu_transaction_core.h"
#include "npu_eth_return_abi.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "%s:%d: case %u (%s): %s\n", __FILE__, __LINE__, \
			tests_run, current_test, #condition); \
		abort(); \
	} \
} while (0)

enum action {
	ROUTES_CLOSE, CLOSE, AUTH_QUERY, AUTH_DISARM, FE_QUIESCE, QUIET,
	PPE_DRAIN, READY, PPE_RESTORE, FE_ARM, OPEN, ROUTES_OPEN, ACTION_COUNT,
};

enum fault_mode { NO_FAULT, BEFORE_EFFECT, AFTER_EFFECT, BAD_REPLY };

struct record {
	enum action action;
	enum airoha_npu_txn_phase phase;
	struct airoha_npu_txn_identity id;
	gate_u32 request[AUTH_MBOX_WORDS];
	unsigned int words;
	bool effect;
	int result;
};

struct fixture {
	struct airoha_npu_txn txn;
	struct airoha_npu_txn_ops ops;
	struct record trace[256];
	size_t length;
	unsigned int calls[ACTION_COUNT], effects[ACTION_COUNT];
	enum action target;
	enum fault_mode mode;
	unsigned int failures_left, corrupt_word, failure_after_calls;
	gate_u32 corrupt_value;
	int injected_error;
	gate_u32 gate_epoch, gate_generation, gate_mask, gate_caps;
	bool gate_quiet, routes_enabled, fe_enabled, fe_quiesced, ppe_present;
	gate_u32 auth_epoch, auth_generation, auth_count, auth_inflight;
	bool auth_enabled, ready_allowed, rings_napi[2];
	struct er_message rings[2];
	gate_u32 ring_consumed[2];
};

static const enum airoha_npu_txn_phase phases[ACTION_COUNT] = {
	NPU_TXN_ROUTES_CLOSE, NPU_TXN_GATE_CLOSE, NPU_TXN_AUTH_QUERY,
	NPU_TXN_AUTH_DISARM, NPU_TXN_FE_QUIESCE, NPU_TXN_GATE_QUIET,
	NPU_TXN_PPE_DRAIN, NPU_TXN_READY, NPU_TXN_PPE_RESTORE,
	NPU_TXN_FE_ARM, NPU_TXN_GATE_OPEN, NPU_TXN_ROUTES_OPEN,
};

static const char *names[ACTION_COUNT] = {
	"routes_close", "gate CLOSE", "AUTH QUERY", "AUTH DISARM", "fe_quiesce",
	"gate QUIET", "ppe_drain", "ready", "ppe_restore", "fe_arm", "gate OPEN",
	"routes_open",
};

static unsigned int tests_run;
static const char *current_test = "initialization";

static void begin_case(const char *name)
{
	current_test = name;
	++tests_run;
}

static bool same_id(const struct airoha_npu_txn_identity *left,
		    const struct airoha_npu_txn_identity *right)
{
	return left->epoch == right->epoch && left->generation == right->generation &&
		left->open_mask == right->open_mask;
}

static bool same_txn(const struct airoha_npu_txn *left, const struct airoha_npu_txn *right)
{
	return same_id(&left->id, &right->id) && left->phase == right->phase &&
		left->auth_epoch == right->auth_epoch && left->auth_generation == right->auth_generation &&
		left->last_error == right->last_error && left->renew_epoch == right->renew_epoch;
}

static struct record *record_call(struct fixture *fixture, enum action action,
				   const gate_u32 *request, unsigned int words)
{
	struct record *record;

	CHECK(fixture->length < ARRAY_SIZE(fixture->trace));
	CHECK(fixture->txn.phase == phases[action]);
	record = &fixture->trace[fixture->length++];
	*record = (struct record) {
		.action = action, .phase = fixture->txn.phase, .id = fixture->txn.id,
		.words = words,
	};
	if (words)
		memcpy(record->request, request, words * sizeof(*request));
	++fixture->calls[action];
	return record;
}

static int fail_before(struct fixture *fixture, struct record *record)
{
	if (fixture->target == record->action && fixture->failures_left &&
	    fixture->calls[record->action] > fixture->failure_after_calls &&
	    fixture->mode == BEFORE_EFFECT) {
		--fixture->failures_left;
		record->result = fixture->injected_error;
		return record->result;
	}
	return 0;
}

static int finish_call(struct fixture *fixture, struct record *record, gate_u32 *reply)
{
	record->effect = true;
	++fixture->effects[record->action];
	if (fixture->target != record->action || !fixture->failures_left ||
	    fixture->calls[record->action] <= fixture->failure_after_calls)
		return 0;
	if (fixture->mode == AFTER_EFFECT) {
		--fixture->failures_left;
		record->result = fixture->injected_error;
		if (record->action == ROUTES_OPEN)
			fixture->routes_enabled = false;
		return record->result;
	}
	if (fixture->mode == BAD_REPLY) {
		CHECK(reply && fixture->corrupt_word < record->words);
		--fixture->failures_left;
		reply[fixture->corrupt_word] = fixture->corrupt_value;
	}
	return 0;
}

static gate_u32 queued(const struct fixture *fixture)
{
	return fixture->rings[0].w[11] - fixture->ring_consumed[0] +
		fixture->rings[1].w[11] - fixture->ring_consumed[1];
}

static void gate_snapshot(struct fixture *fixture, struct npu_gate_message *message)
{
	gate_u32 *words = message->w;

	words[GM_STATUS] = 0;
	words[GM_CAPS] = fixture->gate_caps;
	words[GM_STATE_EPOCH] = fixture->gate_epoch;
	words[GM_STATE_GENERATION] = fixture->gate_generation;
	words[GM_CLOSED] = !fixture->gate_mask;
	words[GM_MASK] = fixture->gate_mask;
	words[GM_QUIET_ACK] = fixture->gate_quiet;
	words[GM_FE_ENABLED] = fixture->fe_enabled;
	words[GM_FE_QUIESCED] = fixture->fe_quiesced;
	words[GM_ER_FLAGS] = GATE_ER_BOUND | (fixture->fe_enabled ? GATE_ER_ACTIVE : 0);
	words[GM_ER_QUEUED] = queued(fixture);
	words[GM_DMA_IDLE] = 1;
	words[GM_AUTH_INFLIGHT] = fixture->auth_inflight;
	words[GM_AUTH_ENABLED] = fixture->auth_enabled;
	words[GM_AUTH_EPOCH] = fixture->auth_epoch;
	words[GM_AUTH_GENERATION] = fixture->auth_generation;
}

static int gate(void *opaque, struct npu_gate_message *message)
{
	struct fixture *fixture = opaque;
	gate_u32 operation = message->w[GM_ABI_OP] >> 16;
	enum action action = operation == GATE_CLOSE ? CLOSE :
		operation == GATE_QUIET ? QUIET : OPEN;
	struct record *record;
	gate_u32 index;
	int error;

	CHECK(operation == GATE_CLOSE || operation == GATE_QUIET || operation == GATE_OPEN);
	CHECK(message->w[GM_MAGIC] == GATE_MAGIC);
	CHECK(message->w[GM_ABI_OP] == (GATE_ABI | operation << 16));
	CHECK(message->w[GM_BYTES] == sizeof(*message));
	CHECK(message->w[GM_EPOCH] == fixture->txn.id.epoch);
	CHECK(message->w[GM_GENERATION] == fixture->txn.id.generation);
	CHECK(message->w[GM_OPEN_MASK] == (operation == GATE_OPEN ? fixture->txn.id.open_mask : 0));
	CHECK(message->w[GM_RESERVED0] == 0 && message->w[GM_RESERVED1] == 0);
	CHECK(message->w[GM_STATUS] == (gate_u32)-115);
	for (index = GM_STATUS + 1; index < GATE_WORDS; ++index)
		CHECK(message->w[index] == 0);
	record = record_call(fixture, action, message->w, GATE_WORDS);
	error = fail_before(fixture, record);
	if (error)
		return error;
	CHECK(!fixture->routes_enabled);
	if (operation == GATE_CLOSE) {
		fixture->gate_epoch = message->w[GM_EPOCH];
		fixture->gate_generation = message->w[GM_GENERATION];
		fixture->gate_mask = 0;
		fixture->gate_quiet = false;
	} else {
		CHECK(fixture->gate_epoch == message->w[GM_EPOCH]);
		CHECK(fixture->gate_generation == message->w[GM_GENERATION]);
		if (operation == GATE_QUIET) {
			CHECK(!fixture->gate_mask && fixture->fe_quiesced && !fixture->fe_enabled);
			CHECK(!fixture->auth_enabled && fixture->rings_napi[0] && fixture->rings_napi[1]);
			if (queued(fixture) || fixture->auth_inflight) {
				gate_snapshot(fixture, message);
				message->w[GM_STATUS] = (gate_u32)-EAGAIN;
				record->result = -EAGAIN;
				return -EAGAIN;
			}
			fixture->gate_quiet = true;
		} else {
			CHECK(fixture->fe_enabled && !fixture->fe_quiesced && fixture->ppe_present);
			if (!fixture->auth_enabled || fixture->auth_epoch != fixture->txn.id.epoch ||
			    fixture->auth_generation != fixture->txn.id.generation) {
				gate_snapshot(fixture, message);
				message->w[GM_STATUS] = (gate_u32)-ESTALE;
				record->result = -ESTALE;
				return -ESTALE;
			}
			fixture->gate_mask = message->w[GM_OPEN_MASK];
			fixture->gate_quiet = false;
		}
	}
	gate_snapshot(fixture, message);
	return finish_call(fixture, record, message->w);
}

static int auth(void *opaque, struct npu_auth_message *message)
{
	struct fixture *fixture = opaque;
	gate_u32 operation = message->w[AM_ABI_OP] >> 16;
	enum action action = operation == AUTH_MBOX_QUERY ? AUTH_QUERY : AUTH_DISARM;
	struct record *record;
	gate_u32 index;
	int error;

	CHECK(operation == AUTH_MBOX_QUERY || operation == AUTH_MBOX_DISARM);
	CHECK(message->w[AM_MAGIC] == AUTH_MBOX_MAGIC);
	CHECK(message->w[AM_ABI_OP] == (AUTH_MBOX_ABI | operation << 16));
	CHECK(message->w[AM_BYTES] == sizeof(*message));
	CHECK(message->w[AM_EPOCH] == (operation == AUTH_MBOX_QUERY ? 0 : fixture->txn.auth_epoch));
	CHECK(message->w[AM_GENERATION] == (operation == AUTH_MBOX_QUERY ? 0 : fixture->txn.auth_generation));
	for (index = AM_RULE_COUNT; index < AM_STATUS; ++index)
		CHECK(message->w[index] == 0);
	CHECK(message->w[AM_STATUS] == (auth_u32)-115);
	for (index = AM_STATUS + 1; index < AUTH_MBOX_WORDS; ++index)
		CHECK(message->w[index] == 0);
	record = record_call(fixture, action, message->w, AUTH_MBOX_WORDS);
	error = fail_before(fixture, record);
	if (error)
		return error;
	CHECK(!fixture->routes_enabled && !fixture->gate_mask);
	if (operation == AUTH_MBOX_DISARM) {
		if (message->w[AM_EPOCH] != fixture->auth_epoch ||
		    message->w[AM_GENERATION] != fixture->auth_generation) {
			record->result = -ESTALE;
			return -ESTALE;
		}
		fixture->auth_enabled = false;
	}
	message->w[AM_STATUS] = 0;
	message->w[AM_CAPS] = AUTH_MBOX_CAPS;
	message->w[AM_STATE_EPOCH] = fixture->auth_epoch;
	message->w[AM_STATE_GENERATION] = fixture->auth_generation;
	message->w[AM_COUNT] = fixture->auth_count;
	message->w[AM_INFLIGHT] = fixture->auth_inflight;
	message->w[AM_ENABLED] = fixture->auth_enabled;
	return finish_call(fixture, record, message->w);
}

static bool owner_ready(struct fixture *fixture, const struct airoha_npu_txn_identity *id)
{
	size_t source;

	if (!fixture->ready_allowed || !fixture->auth_enabled ||
	    fixture->auth_epoch != id->epoch || fixture->auth_generation != id->generation)
		return false;
	for (source = 0; source < ARRAY_SIZE(fixture->rings); ++source) {
		gate_u32 source_mask = source ? GATE_PON2 : GATE_FE24;
		struct er_message *ring = &fixture->rings[source];

		if ((id->open_mask & source_mask) &&
		    (ring->w[8] || ring->w[4] != id->epoch || ring->w[7] != id->generation ||
		     ring->w[6] != (source ? ER_PON : ER_LAN1)))
			return false;
	}
	return true;
}

static int owner_action(void *opaque, const struct airoha_npu_txn_identity *id,
			enum action action)
{
	struct fixture *fixture = opaque;
	struct record *record;
	int error;

	CHECK(same_id(id, &fixture->txn.id));
	record = record_call(fixture, action, NULL, 0);
	error = fail_before(fixture, record);
	if (error)
		return error;
	if (action != ROUTES_CLOSE)
		CHECK(!fixture->routes_enabled);
	switch (action) {
	case ROUTES_CLOSE:
		fixture->routes_enabled = false;
		break;
	case FE_QUIESCE:
		CHECK(!fixture->gate_mask && !fixture->auth_enabled);
		CHECK(fixture->rings_napi[0] && fixture->rings_napi[1]);
		fixture->fe_enabled = false;
		fixture->fe_quiesced = true;
		break;
	case PPE_DRAIN:
		CHECK(fixture->gate_quiet && !queued(fixture) && !fixture->auth_inflight);
		fixture->ppe_present = false;
		break;
	case READY:
		if (!owner_ready(fixture, id)) {
			record->result = -EAGAIN;
			return -EAGAIN;
		}
		break;
	case PPE_RESTORE:
		fixture->ppe_present = true;
		break;
	case FE_ARM:
		if (!owner_ready(fixture, id)) {
			record->result = -ESTALE;
			return -ESTALE;
		}
		CHECK(fixture->ppe_present && fixture->auth_enabled);
		fixture->fe_enabled = true;
		fixture->fe_quiesced = false;
		break;
	case ROUTES_OPEN:
		if (!owner_ready(fixture, id)) {
			fixture->routes_enabled = false;
			record->result = -ESTALE;
			return -ESTALE;
		}
		CHECK(fixture->gate_mask == id->open_mask && fixture->fe_enabled);
		fixture->routes_enabled = true;
		break;
	default:
		CHECK(false);
	}
	return finish_call(fixture, record, NULL);
}

#define OWNER_CALLBACK(name, action) \
static int name(void *opaque, const struct airoha_npu_txn_identity *id) \
{ return owner_action(opaque, id, action); }

OWNER_CALLBACK(routes_close, ROUTES_CLOSE)
OWNER_CALLBACK(fe_quiesce, FE_QUIESCE)
OWNER_CALLBACK(ppe_drain, PPE_DRAIN)
OWNER_CALLBACK(ready, READY)
OWNER_CALLBACK(ppe_restore, PPE_RESTORE)
OWNER_CALLBACK(fe_arm, FE_ARM)
OWNER_CALLBACK(routes_open, ROUTES_OPEN)

static const struct airoha_npu_txn_ops operations = {
	.gate = gate, .auth = auth, .routes_close = routes_close,
	.fe_quiesce = fe_quiesce, .ppe_drain = ppe_drain, .ready = ready,
	.ppe_restore = ppe_restore, .fe_arm = fe_arm, .routes_open = routes_open,
};

static void initialize(struct fixture *fixture, gate_u32 epoch, gate_u32 mask)
{
	memset(fixture, 0, sizeof(*fixture));
	fixture->ops = operations;
	fixture->gate_caps = GATE_CAPS | GATE_CAP_PON2;
	fixture->gate_epoch = 9;
	fixture->gate_generation = 13;
	fixture->gate_mask = GATE_FE24 | GATE_PON2;
	fixture->routes_enabled = true;
	fixture->fe_enabled = true;
	fixture->ppe_present = true;
	fixture->auth_epoch = 7;
	fixture->auth_generation = 11;
	fixture->auth_count = 2;
	fixture->auth_enabled = true;
	fixture->ready_allowed = true;
	fixture->rings_napi[0] = fixture->rings_napi[1] = true;
	CHECK(airoha_npu_txn_begin(&fixture->txn, epoch, 23, mask) == 0);
	CHECK(fixture->txn.phase == NPU_TXN_ROUTES_CLOSE);
}

static void inject(struct fixture *fixture, enum action action, enum fault_mode mode,
		    int error, unsigned int attempts)
{
	fixture->target = action;
	fixture->mode = mode;
	fixture->injected_error = error;
	fixture->failures_left = attempts;
	fixture->failure_after_calls = fixture->calls[action];
}

static void corrupt(struct fixture *fixture, enum action action, unsigned int word,
		     gate_u32 value)
{
	inject(fixture, action, BAD_REPLY, 0, 1);
	fixture->corrupt_word = word;
	fixture->corrupt_value = value;
}

static void close_ok(struct fixture *fixture)
{
	CHECK(airoha_npu_txn_close(&fixture->txn, &fixture->ops, fixture) == 0);
	CHECK(fixture->txn.phase == NPU_TXN_CLOSED && fixture->txn.last_error == 0);
	CHECK(!fixture->routes_enabled && !fixture->gate_mask && fixture->gate_quiet);
	CHECK(!fixture->auth_enabled && !fixture->fe_enabled && fixture->fe_quiesced);
	CHECK(!fixture->ppe_present && fixture->rings_napi[0] && fixture->rings_napi[1]);
}

static void prepare_owner(struct fixture *fixture)
{
	size_t source;

	CHECK(fixture->txn.phase == NPU_TXN_CLOSED || fixture->txn.phase == NPU_TXN_READY);
	fixture->auth_epoch = fixture->txn.id.epoch;
	fixture->auth_generation = fixture->txn.id.generation;
	fixture->auth_enabled = true;
	fixture->auth_count = 2;
	for (source = 0; source < ARRAY_SIZE(fixture->rings); ++source) {
		fixture->rings[source] = (struct er_message) {
			.w = { ER_MAGIC, ER_ABI | ER_BIND << 16,
			       0x01000000u + (gate_u32)source * 0x00100000u, er_bytes(ER_MIN_COUNT),
			       fixture->txn.id.epoch, ER_MIN_COUNT, source ? ER_PON : ER_LAN1,
			       fixture->txn.id.generation, 0, ER_CAPS | ER_CAP_SOURCES, ER_IDLE },
		};
		fixture->ring_consumed[source] = 0;
	}
}

static void open_ok(struct fixture *fixture)
{
	CHECK(airoha_npu_txn_open(&fixture->txn, &fixture->ops, fixture) == 0);
	CHECK(fixture->txn.phase == NPU_TXN_OPEN && fixture->txn.last_error == 0);
	CHECK(fixture->routes_enabled && fixture->gate_mask == fixture->txn.id.open_mask);
	CHECK(fixture->fe_enabled && fixture->auth_enabled && fixture->ppe_present);
}

static void check_retry_identity(struct fixture *fixture, const struct airoha_npu_txn *saved)
{
	size_t calls = fixture->length;

	CHECK(airoha_npu_txn_begin(&fixture->txn, saved->id.epoch,
		saved->id.generation, saved->id.open_mask) == 0);
	CHECK(same_txn(&fixture->txn, saved));
	CHECK(airoha_npu_txn_begin(&fixture->txn, saved->id.epoch + 1,
		saved->id.generation, saved->id.open_mask) == -ESTALE);
	CHECK(airoha_npu_txn_begin(&fixture->txn, saved->id.epoch,
		saved->id.generation + 1, saved->id.open_mask) == -ESTALE);
	CHECK(airoha_npu_txn_begin(&fixture->txn, saved->id.epoch,
		saved->id.generation, saved->id.open_mask == 1 ? 4 : 1) == -ESTALE);
	CHECK(same_txn(&fixture->txn, saved) && fixture->length == calls);
}

static void check_same_request(const struct record *left, const struct record *right)
{
	CHECK(left->action == right->action && left->phase == right->phase);
	CHECK(same_id(&left->id, &right->id) && left->words == right->words);
	CHECK(!memcmp(left->request, right->request, left->words * sizeof(*left->request)));
}

static void test_success(void)
{
	gate_u32 masks[] = { GATE_FE24, GATE_PON2, GATE_FE24 | GATE_PON2, GATE_FE24 };
	size_t index, action;

	for (index = 0; index < ARRAY_SIZE(masks); ++index) {
		struct fixture fixture;
		size_t length;

		begin_case("ordered CLOSE/AUTH/QUIET and ready/PPE/FE/OPEN for supported masks");
		initialize(&fixture, 41, masks[index]);
		if (index == 3)
			fixture.gate_caps = GATE_CAPS;
		close_ok(&fixture);
		CHECK(fixture.length == 7 && fixture.txn.auth_epoch == 7 && fixture.txn.auth_generation == 11);
		for (action = ROUTES_CLOSE; action <= PPE_DRAIN; ++action)
			CHECK(fixture.trace[action].action == (enum action)action);
		CHECK(fixture.trace[AUTH_DISARM].request[AM_EPOCH] == 7);
		CHECK(fixture.trace[AUTH_DISARM].request[AM_GENERATION] == 11);
		length = fixture.length;
		close_ok(&fixture);
		CHECK(fixture.length == length);
		prepare_owner(&fixture);
		open_ok(&fixture);
		CHECK(fixture.length == ACTION_COUNT);
		for (action = 0; action < ACTION_COUNT; ++action) {
			CHECK(fixture.trace[action].action == (enum action)action);
			CHECK(fixture.trace[action].result == 0 && fixture.trace[action].effect);
			CHECK(fixture.calls[action] == 1);
		}
		open_ok(&fixture);
		CHECK(fixture.length == ACTION_COUNT);
	}
}

static void test_failure_matrix(void)
{
	int errors[] = { -ETIMEDOUT, -EIO, -EAGAIN, 1 };
	enum action target;
	enum fault_mode mode;
	size_t error_index;

	for (target = 0; target < ACTION_COUNT; ++target) {
		for (mode = BEFORE_EFFECT; mode <= AFTER_EFFECT; ++mode) {
			for (error_index = 0; error_index < ARRAY_SIZE(errors); ++error_index) {
				struct fixture fixture;
				struct airoha_npu_txn saved;
				int expected = errors[error_index] > 0 ? -EPROTO : errors[error_index];
				bool opening = target >= READY;
				size_t first, second, retry, index;
				int result;

				begin_case(names[target]);
				initialize(&fixture, 41, GATE_FE24 | GATE_PON2);
				if (opening) {
					close_ok(&fixture);
					prepare_owner(&fixture);
				}
				inject(&fixture, target, mode, errors[error_index], 2);
				result = opening ? airoha_npu_txn_open(&fixture.txn, &fixture.ops, &fixture) :
					airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture);
				CHECK(result == expected && fixture.txn.last_error == expected);
				CHECK(fixture.txn.phase == phases[target]);
				CHECK(fixture.txn.id.epoch == 41 && fixture.txn.id.generation == 23);
				CHECK(fixture.txn.id.open_mask == (GATE_FE24 | GATE_PON2));
				first = fixture.length - 1;
				CHECK(fixture.trace[first].action == target);
				CHECK(fixture.effects[target] == (mode == AFTER_EFFECT ? 1u : 0u));
				for (index = (size_t)target + 1; index < ACTION_COUNT; ++index)
					CHECK(fixture.calls[index] == 0);
				if (target > AUTH_QUERY) {
					CHECK(fixture.txn.auth_epoch == 7 && fixture.txn.auth_generation == 11);
				} else {
					CHECK(fixture.txn.auth_epoch == 0 && fixture.txn.auth_generation == 0);
				}
				if (target == ROUTES_OPEN)
					CHECK(!fixture.routes_enabled);
				saved = fixture.txn;
				check_retry_identity(&fixture, &saved);
				second = fixture.length;
				result = opening ? airoha_npu_txn_open(&fixture.txn, &fixture.ops, &fixture) :
					airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture);
				CHECK(result == expected && same_txn(&fixture.txn, &saved));
				CHECK(fixture.length == second + 1);
				check_same_request(&fixture.trace[first], &fixture.trace[second]);
				retry = fixture.length;
				if (opening)
					open_ok(&fixture);
				else
					close_ok(&fixture);
				check_same_request(&fixture.trace[first], &fixture.trace[retry]);
				CHECK(fixture.calls[target] == 3);
				CHECK(fixture.effects[target] == (mode == AFTER_EFFECT ? 3u : 1u));
				for (index = 0; index <= (opening ? ROUTES_OPEN : PPE_DRAIN); ++index)
					CHECK(fixture.calls[index] == (index == (size_t)target ? 3u : 1u));
			}
		}
	}
}

static void test_cached_authorization(void)
{
	struct fixture fixture;
	struct airoha_npu_txn saved;
	size_t retry;

	begin_case("DISARM retry preserves cached old authorization despite external state change");
	initialize(&fixture, 41, 5);
	inject(&fixture, AUTH_DISARM, AFTER_EFFECT, -ETIMEDOUT, 1);
	CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -ETIMEDOUT);
	CHECK(!fixture.auth_enabled && fixture.txn.auth_epoch == 7 && fixture.txn.auth_generation == 11);
	saved = fixture.txn;
	fixture.auth_epoch = 99;
	fixture.auth_generation = 101;
	fixture.auth_enabled = true;
	retry = fixture.length;
	CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -ESTALE);
	CHECK(fixture.length == retry + 1 && fixture.calls[AUTH_QUERY] == 1);
	CHECK(fixture.trace[retry].request[AM_EPOCH] == 7);
	CHECK(fixture.trace[retry].request[AM_GENERATION] == 11);
	CHECK(fixture.txn.phase == saved.phase && same_id(&fixture.txn.id, &saved.id));
	CHECK(fixture.txn.auth_epoch == 7 && fixture.txn.auth_generation == 11);
	CHECK(fixture.calls[FE_QUIESCE] == 0 && fixture.auth_enabled);
	fixture.auth_epoch = 7;
	fixture.auth_generation = 11;
	close_ok(&fixture);
	CHECK(fixture.calls[AUTH_QUERY] == 1 && fixture.calls[AUTH_DISARM] == 3);
}

static void test_no_auth_and_quiet_waits(void)
{
	struct fixture fixture;
	struct airoha_npu_txn saved;
	size_t before;

	begin_case("initial empty authorization skips DISARM");
	initialize(&fixture, 41, 5);
	fixture.auth_epoch = fixture.auth_generation = fixture.auth_count = 0;
	fixture.auth_enabled = false;
	close_ok(&fixture);
	CHECK(fixture.calls[AUTH_QUERY] == 1 && fixture.calls[AUTH_DISARM] == 0);
	CHECK(fixture.txn.auth_epoch == 0 && fixture.txn.auth_generation == 0);

	begin_case("QUIET waits for both live NAPI consumers and authorization inflight");
	initialize(&fixture, 41, 5);
	fixture.rings[0].w[11] = 3;
	fixture.rings[1].w[11] = 5;
	fixture.auth_inflight = 1;
	CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -EAGAIN);
	CHECK(fixture.txn.phase == NPU_TXN_GATE_QUIET && fixture.calls[PPE_DRAIN] == 0);
	saved = fixture.txn;
	check_retry_identity(&fixture, &saved);
	fixture.ring_consumed[0] = 3;
	before = fixture.length;
	CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -EAGAIN);
	CHECK(fixture.length == before + 1 && fixture.trace[before].action == QUIET);
	CHECK(same_txn(&fixture.txn, &saved));
	fixture.ring_consumed[1] = 5;
	CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -EAGAIN);
	CHECK(fixture.calls[PPE_DRAIN] == 0 && fixture.rings_napi[0] && fixture.rings_napi[1]);
	fixture.auth_inflight = 0;
	close_ok(&fixture);
	CHECK(fixture.calls[QUIET] == 4 && fixture.calls[PPE_DRAIN] == 1);
	CHECK(fixture.calls[AUTH_QUERY] == 1 && fixture.calls[AUTH_DISARM] == 1);
}

static void test_abort_reopen(void)
{
	enum action failed;
	enum fault_mode mode;

	for (failed = READY; failed <= ROUTES_OPEN; ++failed) {
		for (mode = BEFORE_EFFECT; mode <= AFTER_EFFECT; ++mode) {
			struct fixture fixture;
			size_t start, index;
			const enum action expected[] = {
				ROUTES_CLOSE, CLOSE, CLOSE, AUTH_QUERY, AUTH_DISARM, FE_QUIESCE, QUIET, PPE_DRAIN,
			};

			begin_case("abort reopen closes original identity before advancing epoch");
			initialize(&fixture, 41, 5);
			close_ok(&fixture);
			prepare_owner(&fixture);
			inject(&fixture, failed, mode, -ETIMEDOUT, 1);
			CHECK(airoha_npu_txn_open(&fixture.txn, &fixture.ops, &fixture) == -ETIMEDOUT);
			CHECK(fixture.txn.phase == phases[failed] && fixture.txn.id.epoch == 41);
			start = fixture.length;
			close_ok(&fixture);
			CHECK(fixture.length == start + ARRAY_SIZE(expected));
			for (index = 0; index < ARRAY_SIZE(expected); ++index) {
				CHECK(fixture.trace[start + index].action == expected[index]);
				CHECK(fixture.trace[start + index].id.epoch == (index < 2 ? 41u : 42u));
				CHECK(fixture.trace[start + index].id.generation == 23);
				CHECK(fixture.trace[start + index].id.open_mask == 5);
			}
			CHECK(fixture.trace[start + 1].request[GM_EPOCH] == 41);
			CHECK(fixture.trace[start + 2].request[GM_EPOCH] == 42);
			CHECK(fixture.trace[start + 4].request[AM_EPOCH] == 41);
			CHECK(fixture.trace[start + 4].request[AM_GENERATION] == 23);
			CHECK(fixture.txn.id.epoch == 42 && !fixture.txn.renew_epoch);
			prepare_owner(&fixture);
			open_ok(&fixture);
		}
	}
}

static void test_rollback_ack_loss(void)
{
	enum fault_mode mode;
	unsigned int boundary;

	for (boundary = 0; boundary < 3; ++boundary) {
		for (mode = BEFORE_EFFECT; mode <= AFTER_EFFECT; ++mode) {
			struct fixture fixture;
			struct airoha_npu_txn saved;
			size_t retry, first;

			begin_case("rollback ACK loss keeps old CLOSE or renewed CLOSE identity stable");
			initialize(&fixture, 41, 5);
			close_ok(&fixture);
			prepare_owner(&fixture);
			open_ok(&fixture);
			inject(&fixture, boundary == 0 ? ROUTES_CLOSE : CLOSE, mode, -ETIMEDOUT, 2);
			if (boundary == 2)
				++fixture.failure_after_calls;
			CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -ETIMEDOUT);
			CHECK(fixture.txn.id.epoch == (boundary == 2 ? 42u : 41u));
			CHECK(fixture.txn.renew_epoch == (boundary != 2));
			first = fixture.length - 1;
			saved = fixture.txn;
			check_retry_identity(&fixture, &saved);
			CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -ETIMEDOUT);
			CHECK(same_txn(&fixture.txn, &saved));
			check_same_request(&fixture.trace[first], &fixture.trace[first + 1]);
			retry = fixture.length;
			close_ok(&fixture);
			check_same_request(&fixture.trace[first], &fixture.trace[retry]);
			CHECK(fixture.txn.id.epoch == 42 && !fixture.txn.renew_epoch);
		}
	}
}

static void test_epoch_overflow(void)
{
	gate_u32 initial[] = { UINT32_MAX, UINT32_MAX - 1 };
	size_t index;

	for (index = 0; index < ARRAY_SIZE(initial); ++index) {
		struct fixture fixture;
		struct airoha_npu_txn saved;
		size_t start, stopped;

		begin_case("epoch U32MAX closes old identity then stays at EPOCH_ADVANCE without wrap");
		initialize(&fixture, initial[index], 5);
		close_ok(&fixture);
		prepare_owner(&fixture);
		open_ok(&fixture);
		if (index) {
			close_ok(&fixture);
			CHECK(fixture.txn.id.epoch == UINT32_MAX);
			prepare_owner(&fixture);
			open_ok(&fixture);
		}
		start = fixture.length;
		inject(&fixture, CLOSE, AFTER_EFFECT, -ETIMEDOUT, 1);
		CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -ETIMEDOUT);
		CHECK(fixture.txn.phase == NPU_TXN_GATE_CLOSE && fixture.txn.id.epoch == UINT32_MAX);
		CHECK(fixture.length == start + 2 && !fixture.routes_enabled && !fixture.gate_mask);
		CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -EOVERFLOW);
		CHECK(fixture.txn.phase == NPU_TXN_EPOCH_ADVANCE && fixture.txn.renew_epoch);
		CHECK(fixture.txn.id.epoch == UINT32_MAX && fixture.txn.last_error == -EOVERFLOW);
		CHECK(fixture.length == start + 3);
		check_same_request(&fixture.trace[start + 1], &fixture.trace[start + 2]);
		stopped = fixture.length;
		saved = fixture.txn;
		CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -EOVERFLOW);
		CHECK(airoha_npu_txn_open(&fixture.txn, &fixture.ops, &fixture) == -EBUSY);
		CHECK(airoha_npu_txn_begin(&fixture.txn, UINT32_MAX, 23, 5) == 0);
		CHECK(airoha_npu_txn_begin(&fixture.txn, 1, 23, 5) == -ESTALE);
		CHECK(airoha_npu_txn_begin(&fixture.txn, 0, 23, 5) == -EINVAL);
		CHECK(same_txn(&fixture.txn, &saved) && fixture.length == stopped);
	}
}

static void test_closed_owner_rebuild(void)
{
	unsigned int partial;

	for (partial = 0; partial < 2; ++partial) {
		struct fixture fixture;
		struct airoha_npu_txn saved;
		size_t start;

		begin_case("CLOSED owner AUTH BEGIN/ADD failure needs explicit newer begin and close");
		initialize(&fixture, 41, 5);
		close_ok(&fixture);
		fixture.auth_epoch = 41;
		fixture.auth_generation = 23;
		fixture.auth_count = partial ? 1 : 0;
		fixture.auth_enabled = false;
		saved = fixture.txn;
		start = fixture.length;
		CHECK(airoha_npu_txn_begin(&fixture.txn, 41, 23, 5) == 0);
		CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == 0);
		CHECK(same_txn(&fixture.txn, &saved) && fixture.length == start);
		CHECK(fixture.auth_count == partial && fixture.auth_epoch == 41);
		CHECK(airoha_npu_txn_begin(&fixture.txn, 42, 24, 5) == 0);
		CHECK(fixture.txn.phase == NPU_TXN_ROUTES_CLOSE);
		CHECK(fixture.txn.auth_epoch == 0 && fixture.txn.auth_generation == 0);
		close_ok(&fixture);
		CHECK(fixture.length == start + 7);
		CHECK(fixture.trace[start + CLOSE].request[GM_EPOCH] == 42);
		CHECK(fixture.trace[start + AUTH_DISARM].request[AM_EPOCH] == 41);
		CHECK(fixture.trace[start + AUTH_DISARM].request[AM_GENERATION] == 23);
		prepare_owner(&fixture);
		open_ok(&fixture);
		CHECK(fixture.txn.id.epoch == 42 && fixture.txn.id.generation == 24);
	}
}

static void test_owner_live_revalidation(void)
{
	enum action target;
	unsigned int revoked;

	for (target = FE_ARM; target <= ROUTES_OPEN; ++target) {
		for (revoked = 0; revoked < 3; ++revoked) {
			struct fixture fixture;
			size_t retry;
			int error;

			begin_case("retry skips ready; FE/routes callbacks recheck live authorization and both ERs");
			initialize(&fixture, 41, 5);
			close_ok(&fixture);
			prepare_owner(&fixture);
			inject(&fixture, target, BEFORE_EFFECT, -ETIMEDOUT, 1);
			CHECK(airoha_npu_txn_open(&fixture.txn, &fixture.ops, &fixture) == -ETIMEDOUT);
			CHECK(fixture.calls[READY] == 1);
			if (revoked == 0)
				fixture.auth_enabled = false;
			else if (revoked == 1)
				++fixture.rings[0].w[7];
			else
				++fixture.rings[1].w[7];
			retry = fixture.length;
			error = airoha_npu_txn_open(&fixture.txn, &fixture.ops, &fixture);
			CHECK(error == -ESTALE && fixture.txn.last_error == -ESTALE);
			CHECK(fixture.calls[READY] == 1 && !fixture.routes_enabled);
			if (target == OPEN && revoked) {
				CHECK(fixture.txn.phase == NPU_TXN_ROUTES_OPEN && fixture.length == retry + 2);
				CHECK(fixture.trace[retry].action == OPEN && fixture.trace[retry].result == 0);
			} else {
				CHECK(fixture.txn.phase == phases[target] && fixture.length == retry + 1);
			}
			fixture.auth_enabled = true;
			fixture.rings[0].w[7] = fixture.rings[1].w[7] = fixture.txn.id.generation;
			open_ok(&fixture);
			CHECK(fixture.calls[READY] == 1);
		}
	}
	{
		struct fixture fixture;

		begin_case("ready prevents reopening until owner installs new auth and matching both ERs");
		initialize(&fixture, 41, 5);
		close_ok(&fixture);
		CHECK(airoha_npu_txn_open(&fixture.txn, &fixture.ops, &fixture) == -EAGAIN);
		CHECK(fixture.txn.phase == NPU_TXN_READY && fixture.calls[PPE_RESTORE] == 0);
		prepare_owner(&fixture);
		fixture.rings[1].w[8] = (gate_u32)-ETIMEDOUT;
		CHECK(airoha_npu_txn_open(&fixture.txn, &fixture.ops, &fixture) == -EAGAIN);
		CHECK(fixture.calls[PPE_RESTORE] == 0);
		fixture.rings[1].w[8] = 0;
		open_ok(&fixture);
		CHECK(fixture.calls[READY] == 3);
	}
}

static void reject_reply(enum action action, unsigned int word, gate_u32 value)
{
	struct fixture fixture;
	struct airoha_npu_txn saved;
	size_t first, retry;
	bool opening = action == OPEN;
	int result;

	begin_case("corrupt immutable echo or successful mailbox snapshot");
	initialize(&fixture, 41, 5);
	if (opening) {
		close_ok(&fixture);
		prepare_owner(&fixture);
	}
	corrupt(&fixture, action, word, value);
	result = opening ? airoha_npu_txn_open(&fixture.txn, &fixture.ops, &fixture) :
		airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture);
	if (result != -EPROTO)
		fprintf(stderr, "accepted corruption: action=%s word=%u value=%08x result=%d\n",
			names[action], word, value, result);
	CHECK(result == -EPROTO && fixture.txn.last_error == -EPROTO);
	CHECK(fixture.txn.phase == phases[action]);
	first = fixture.length - 1;
	CHECK(fixture.trace[first].action == action && fixture.trace[first].result == 0);
	CHECK(!fixture.routes_enabled);
	if (action == AUTH_QUERY)
		CHECK(!fixture.txn.auth_epoch && !fixture.txn.auth_generation);
	else if (action == AUTH_DISARM)
		CHECK(fixture.txn.auth_epoch == 7 && fixture.txn.auth_generation == 11);
	saved = fixture.txn;
	check_retry_identity(&fixture, &saved);
	retry = fixture.length;
	if (opening)
		open_ok(&fixture);
	else
		close_ok(&fixture);
	check_same_request(&fixture.trace[first], &fixture.trace[retry]);
}

static void test_gate_corruption(void)
{
	const enum action actions[] = { CLOSE, QUIET, OPEN };
	static const struct { unsigned int word; gate_u32 value; } common[] = {
		{ GM_STATUS, 1 }, { GM_STATUS, (gate_u32)-115 }, { GM_STATUS, (gate_u32)-EIO },
		{ GM_CAPS, 0 }, { GM_CAPS, GATE_CAPS | 0x100 }, { GM_RESERVED2, 1 },
		{ GM_STATE_EPOCH, 0 }, { GM_STATE_EPOCH, 42 }, { GM_STATE_GENERATION, 24 },
	};
	static const struct { unsigned int word; gate_u32 value; } quiet_fields[] = {
		{ GM_QUIET_ACK, 0 }, { GM_QUIET_ACK, 2 }, { GM_FAULT, 1 },
		{ GM_TDMA0, 1 }, { GM_TDMA1, 1 }, { GM_COMPLETION, 1 }, { GM_DONE, 1 },
		{ GM_FE_ENABLED, 1 }, { GM_FE_QUIESCED, 0 }, { GM_FE_QUIESCED, 2 },
		{ GM_FE_INFLIGHT, 1 }, { GM_ER_STATE, ER_QUEUED }, { GM_ER_QUEUED, 1 },
		{ GM_DMA_IDLE, 0 }, { GM_DMA_IDLE, 2 }, { GM_AUTH_INFLIGHT, 1 },
		{ GM_AUTH_ENABLED, 1 },
	};
	static const struct { unsigned int word; gate_u32 value; } open_fields[] = {
		{ GM_CLOSED, 1 }, { GM_MASK, 0 }, { GM_MASK, GATE_FE24 },
		{ GM_CAPS, GATE_CAPS }, { GM_QUIET_ACK, 1 }, { GM_FAULT, 1 },
		{ GM_FE_ENABLED, 0 }, { GM_FE_ENABLED, 2 }, { GM_FE_QUIESCED, 1 },
		{ GM_ER_FLAGS, 0 }, { GM_ER_FLAGS, GATE_ER_ACTIVE },
		{ GM_ER_FLAGS, GATE_ER_BOUND }, { GM_ER_FLAGS, 4 },
		{ GM_AUTH_ENABLED, 0 }, { GM_AUTH_ENABLED, 2 },
		{ GM_AUTH_EPOCH, 42 }, { GM_AUTH_GENERATION, 24 },
	};
	size_t action, field;
	unsigned int word;

	for (action = 0; action < ARRAY_SIZE(actions); ++action) {
		for (word = 0; word < GM_STATUS; ++word)
			reject_reply(actions[action], word, 0xdeadbeefu);
		for (field = 0; field < ARRAY_SIZE(common); ++field)
			reject_reply(actions[action], common[field].word, common[field].value);
		if (actions[action] != OPEN) {
			reject_reply(actions[action], GM_CLOSED, 0);
			reject_reply(actions[action], GM_CLOSED, 2);
			reject_reply(actions[action], GM_MASK, GATE_FE24);
		}
	}
	for (field = 0; field < ARRAY_SIZE(quiet_fields); ++field)
		reject_reply(QUIET, quiet_fields[field].word, quiet_fields[field].value);
	for (field = 0; field < ARRAY_SIZE(open_fields); ++field)
		reject_reply(OPEN, open_fields[field].word, open_fields[field].value);
}

static void test_auth_corruption(void)
{
	const enum action actions[] = { AUTH_QUERY, AUTH_DISARM };
	static const struct { unsigned int word; gate_u32 value; } common[] = {
		{ AM_STATUS, 1 }, { AM_STATUS, (auth_u32)-115 }, { AM_STATUS, (auth_u32)-EIO },
		{ AM_CAPS, 0 }, { AM_CAPS, AUTH_MBOX_CAPS | 8 }, { AM_RESERVED2, 1 },
		{ AM_COUNT, 33 }, { AM_INFLIGHT, 65 }, { AM_ENABLED, 2 },
		{ AM_STATE_EPOCH, 0 }, { AM_STATE_GENERATION, 0 },
	};
	size_t action, field;
	unsigned int word;

	for (action = 0; action < ARRAY_SIZE(actions); ++action) {
		for (word = 0; word < AM_STATUS; ++word)
			reject_reply(actions[action], word, 0xdeadbeefu);
		for (field = 0; field < ARRAY_SIZE(common); ++field)
			reject_reply(actions[action], common[field].word, common[field].value);
	}
	reject_reply(AUTH_DISARM, AM_STATE_EPOCH, 41);
	reject_reply(AUTH_DISARM, AM_STATE_GENERATION, 23);
	reject_reply(AUTH_DISARM, AM_ENABLED, 1);
	for (field = 0; field < 3; ++field) {
		struct fixture fixture;
		unsigned int fields[] = { AM_COUNT, AM_INFLIGHT, AM_ENABLED };

		begin_case("zero AUTH identity requires zero count/inflight/enabled");
		initialize(&fixture, 41, 5);
		fixture.auth_epoch = fixture.auth_generation = fixture.auth_count = 0;
		fixture.auth_enabled = false;
		corrupt(&fixture, AUTH_QUERY, fields[field], 1);
		CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -EPROTO);
		CHECK(fixture.txn.phase == NPU_TXN_AUTH_QUERY);
		CHECK(fixture.txn.auth_epoch == 0 && fixture.txn.auth_generation == 0);
		close_ok(&fixture);
		CHECK(fixture.calls[AUTH_DISARM] == 0);
	}
}

static void test_parameters(void)
{
	gate_u32 invalid_masks[] = { 0, 2, 3, 6, 7, 8, UINT32_MAX };
	size_t index;
	unsigned int missing;

	for (index = 0; index < ARRAY_SIZE(invalid_masks) + 2; ++index) {
		struct airoha_npu_txn txn = { 0 }, saved = txn;
		gate_u32 epoch = 41, generation = 23, mask = 5;

		begin_case("begin rejects invalid mask and zero epoch/generation without changing state");
		if (index < ARRAY_SIZE(invalid_masks))
			mask = invalid_masks[index];
		else if (index == ARRAY_SIZE(invalid_masks))
			epoch = 0;
		else
			generation = 0;
		CHECK(airoha_npu_txn_begin(&txn, epoch, generation, mask) == -EINVAL);
		CHECK(same_txn(&txn, &saved));
	}
	for (missing = 0; missing < 10; ++missing) {
		struct fixture fixture;
		struct airoha_npu_txn saved;
		const struct airoha_npu_txn_ops *ops;

		begin_case("missing ops rejects close/open before callbacks");
		initialize(&fixture, 41, 5);
		ops = &fixture.ops;
		switch (missing) {
		case 0: ops = NULL; break;
		case 1: fixture.ops.gate = NULL; break;
		case 2: fixture.ops.auth = NULL; break;
		case 3: fixture.ops.routes_close = NULL; break;
		case 4: fixture.ops.fe_quiesce = NULL; break;
		case 5: fixture.ops.ppe_drain = NULL; break;
		case 6: fixture.ops.ready = NULL; break;
		case 7: fixture.ops.ppe_restore = NULL; break;
		case 8: fixture.ops.fe_arm = NULL; break;
		case 9: fixture.ops.routes_open = NULL; break;
		}
		saved = fixture.txn;
		CHECK(airoha_npu_txn_close(&fixture.txn, ops, &fixture) == -EINVAL);
		CHECK(airoha_npu_txn_open(&fixture.txn, ops, &fixture) == -EINVAL);
		CHECK(same_txn(&fixture.txn, &saved) && fixture.length == 0);
	}
	for (index = 0; index < 3; ++index) {
		struct fixture fixture;
		struct airoha_npu_txn saved;
		int bad_phase[] = { -1, NPU_TXN_OPEN + 1, INT_MAX };

		begin_case("invalid phase rejects begin/close/open without callbacks");
		initialize(&fixture, 41, 5);
		fixture.txn.phase = (enum airoha_npu_txn_phase)bad_phase[index];
		saved = fixture.txn;
		CHECK(airoha_npu_txn_begin(&fixture.txn, 42, 23, 5) == -EINVAL);
		CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -EINVAL);
		CHECK(airoha_npu_txn_open(&fixture.txn, &fixture.ops, &fixture) == -EINVAL);
		CHECK(same_txn(&fixture.txn, &saved) && fixture.length == 0);
	}
	for (index = NPU_TXN_IDLE; index < NPU_TXN_CLOSED; ++index) {
		struct fixture fixture;
		struct airoha_npu_txn saved;

		begin_case("open before CLOSED is busy and preserves phase");
		initialize(&fixture, 41, 5);
		fixture.txn.phase = (enum airoha_npu_txn_phase)index;
		saved = fixture.txn;
		CHECK(airoha_npu_txn_open(&fixture.txn, &fixture.ops, &fixture) == -EBUSY);
		CHECK(same_txn(&fixture.txn, &saved) && fixture.length == 0);
	}
	{
		struct fixture fixture;
		struct airoha_npu_txn saved;

		begin_case("null transaction and invalid operation identity");
		initialize(&fixture, 41, 5);
		CHECK(airoha_npu_txn_begin(NULL, 41, 23, 5) == -EINVAL);
		CHECK(airoha_npu_txn_close(NULL, &fixture.ops, &fixture) == -EINVAL);
		CHECK(airoha_npu_txn_open(NULL, &fixture.ops, &fixture) == -EINVAL);
		fixture.txn.id.epoch = 0;
		saved = fixture.txn;
		CHECK(airoha_npu_txn_close(&fixture.txn, &fixture.ops, &fixture) == -EINVAL);
		CHECK(airoha_npu_txn_open(&fixture.txn, &fixture.ops, &fixture) == -EINVAL);
		CHECK(same_txn(&fixture.txn, &saved) && fixture.length == 0);
	}
}

static void test_begin_boundaries(void)
{
	unsigned int opened;

	for (opened = 0; opened < 2; ++opened) {
		struct fixture fixture;
		struct airoha_npu_txn saved;
		size_t start;

		begin_case("CLOSED/OPEN begin is idempotent and only a newer epoch starts a transaction");
		initialize(&fixture, 41, 5);
		close_ok(&fixture);
		if (opened) {
			prepare_owner(&fixture);
			open_ok(&fixture);
		}
		saved = fixture.txn;
		start = fixture.length;
		CHECK(airoha_npu_txn_begin(&fixture.txn, 41, 23, 5) == 0);
		CHECK(same_txn(&fixture.txn, &saved));
		CHECK(airoha_npu_txn_begin(&fixture.txn, 40, 23, 5) == -ESTALE);
		CHECK(airoha_npu_txn_begin(&fixture.txn, 41, 24, 5) == -ESTALE);
		CHECK(airoha_npu_txn_begin(&fixture.txn, 41, 23, 1) == -ESTALE);
		CHECK(same_txn(&fixture.txn, &saved) && fixture.length == start);
		CHECK(airoha_npu_txn_begin(&fixture.txn, 42, 24, 1) == 0);
		CHECK(fixture.txn.phase == NPU_TXN_ROUTES_CLOSE && !fixture.txn.renew_epoch);
		CHECK(fixture.txn.auth_epoch == 0 && fixture.txn.auth_generation == 0);
		close_ok(&fixture);
		CHECK(fixture.trace[start].action == ROUTES_CLOSE);
		CHECK(fixture.trace[start + 1].action == CLOSE);
		CHECK(fixture.trace[start + 1].request[GM_EPOCH] == 42);
		CHECK(fixture.txn.id.epoch == 42 && fixture.txn.id.generation == 24);
	}
}

int main(void)
{
	test_success();
	test_failure_matrix();
	test_cached_authorization();
	test_no_auth_and_quiet_waits();
	test_abort_reopen();
	test_rollback_ack_loss();
	test_epoch_overflow();
	test_closed_owner_rebuild();
	test_owner_live_revalidation();
	test_gate_corruption();
	test_auth_corruption();
	test_parameters();
	test_begin_boundaries();
	printf("PASS %u cases: real 990 core and 988 ABIs; phase retry, lost ACK, "
	       "rollback epochs, old auth, dual-ring QUIET, owner contracts and damaged replies\n", tests_run);
	return 0;
}
