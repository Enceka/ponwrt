#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef uint32_t __le32;

#ifdef TEST_SWAPPED_ENDIAN
#define cpu_to_le32(value) __builtin_bswap32((u32)(value))
#define le32_to_cpu(value) __builtin_bswap32((u32)(value))
#else
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define cpu_to_le32(value) ((u32)(value))
#define le32_to_cpu(value) ((u32)(value))
#else
#define cpu_to_le32(value) __builtin_bswap32((u32)(value))
#define le32_to_cpu(value) __builtin_bswap32((u32)(value))
#endif
#endif

#define NPU_OP_SET 1
#define NPU_FUNC_WIFI 0
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#include "airoha_npu_transaction.h"

struct device { void *of_node; };
struct airoha_npu { struct device *dev; };
static struct device device;
static struct airoha_npu npu = { .dev = &device };
static bool ready = true, property = true;
static unsigned int calls, checks;
static int send_error;

union message {
	struct npu_auth_message auth;
	struct er_message er;
	struct npu_gate_message gate;
};

struct transaction {
	u32 function, words, status;
	union message message;
	u32 reply[AUTH_MBOX_WORDS];
};

static struct transaction *pending;

static u32 *request_words(struct transaction *test)
{
	switch (test->function) {
	case AUTH_MBOX_FUNC:
		return test->message.auth.w;
	case ER_FUNC:
		return test->message.er.w;
	default:
		assert(test->function == GATE_FUNC);
		return test->message.gate.w;
	}
}

static bool airoha_npu_wlan_short_guard_ready(struct airoha_npu *instance)
{
	assert(instance == &npu);
	return ready;
}

static bool of_property_read_bool(void *node, const char *name)
{
	assert(node == device.of_node);
	assert(!strcmp(name, "airoha,connac2-rebuilt-ram-lab"));
	return property;
}

static int __airoha_npu_send_msg(struct airoha_npu *instance, int function,
				 const void *data, int bytes, void *response,
				 u16 reply_bytes)
{
	const __le32 *packet = data;
	__le32 *reply = response;
	u32 *request = request_words(pending);

	assert(instance == &npu && function == NPU_FUNC_WIFI);
	assert(bytes == (int)((pending->words + 2) * sizeof(u32)));
	assert(reply_bytes == pending->words * sizeof(u32));
	assert(packet[0] == cpu_to_le32(0x10));
	assert(packet[1] == cpu_to_le32(pending->function));
	for (u32 index = 0; index < pending->words; index++)
		assert(packet[index + 2] == cpu_to_le32(request[index]));
	calls++;
	if (send_error)
		return send_error;
	for (u32 index = 0; index < pending->words; index++)
		reply[index] = cpu_to_le32(pending->reply[index]);
	return 0;
}

#include "airoha_npu_transaction.inc"

static int command(struct airoha_npu *instance, struct transaction *test,
		   bool null_message)
{
	switch (test->function) {
	case AUTH_MBOX_FUNC:
		return airoha_npu_auth_command(instance,
					null_message ? NULL : &test->message.auth);
	case ER_FUNC:
		return airoha_npu_er_command(instance,
				      null_message ? NULL : &test->message.er);
	default:
		return airoha_npu_gate_command(instance,
					null_message ? NULL : &test->message.gate);
	}
}

static void verify(struct transaction test, int expected)
{
	union message original = test.message;
	unsigned int before = calls;

	pending = &test;
	int result = command(&npu, &test, false);

	if (result != expected) {
		fprintf(stderr, "check %u: function %u op %u expected %d got %d\n",
			checks, test.function, request_words(&test)[1] >> 16,
			expected, result);
		assert(result == expected);
	}
	assert(calls == before + 1);
	if (expected == -EPROTO || send_error)
		assert(!memcmp(&original, &test.message, sizeof(original)));
	else
		assert(!memcmp(request_words(&test), test.reply,
			       test.words * sizeof(u32)));
	checks++;
}

static void change(struct transaction test, u32 word, u32 value, int expected)
{
	test.reply[word] = value;
	verify(test, expected);
}

static struct transaction auth_request(u32 op)
{
	struct transaction test = { .function = AUTH_MBOX_FUNC,
		.words = AUTH_MBOX_WORDS, .status = AM_STATUS };
	u32 *request = test.message.auth.w;

	request[AM_MAGIC] = AUTH_MBOX_MAGIC;
	request[AM_ABI_OP] = AUTH_MBOX_ABI | op << 16;
	request[AM_BYTES] = AUTH_MBOX_BYTES;
	request[AM_STATUS] = (u32)-EINPROGRESS;
	if (op != AUTH_MBOX_QUERY) {
		request[AM_EPOCH] = 3;
		request[AM_GENERATION] = 7;
	}
	if (op == AUTH_MBOX_ADD) {
		request[AM_RULE_COUNT] = 1;
		for (u32 index = 0; index < 32; index++)
			request[AM_RULE + index] = 0x12345600 + index;
		request[AM_RULE + 1] = request[AM_EPOCH];
		request[AM_RULE + 8] = request[AM_GENERATION];
	}
	memcpy(test.reply, request, sizeof(test.message.auth));
	test.reply[AM_STATUS] = 0;
	test.reply[AM_CAPS] = AUTH_MBOX_CAPS;
	test.reply[AM_STATE_EPOCH] = request[AM_EPOCH];
	test.reply[AM_STATE_GENERATION] = request[AM_GENERATION];
	test.reply[AM_COUNT] = op >= AUTH_MBOX_ADD;
	test.reply[AM_ENABLED] = op == AUTH_MBOX_ARM;
	return test;
}

static struct transaction er_request(u32 op, u32 caps, u32 sport)
{
	struct transaction test = { .function = ER_FUNC, .words = 16, .status = 8 };
	u32 *request = test.message.er.w;

	request[0] = ER_MAGIC;
	request[1] = ER_ABI | op << 16;
	request[6] = sport;
	request[8] = (u32)-EINPROGRESS;
	if (op != ER_QUERY) {
		request[2] = 0x18004000;
		request[3] = er_bytes(ER_MIN_COUNT);
		request[4] = 3;
		request[5] = ER_MIN_COUNT;
		request[7] = 7;
	}
	memcpy(test.reply, request, sizeof(test.message.er));
	test.reply[8] = 0;
	test.reply[9] = caps;
	test.reply[11] = op == ER_BIND ? 0 :
		(sport == ER_LAN1 ? 0x10203040 : sport == ER_PON ? 0x98765432 : 0);
	return test;
}

static struct transaction gate_request(u32 op, u32 caps, u32 mask)
{
	struct transaction test = { .function = GATE_FUNC,
		.words = GATE_WORDS, .status = GM_STATUS };
	u32 *request = test.message.gate.w;

	request[GM_MAGIC] = GATE_MAGIC;
	request[GM_ABI_OP] = GATE_ABI | op << 16;
	request[GM_BYTES] = GATE_BYTES;
	request[GM_STATUS] = (u32)-EINPROGRESS;
	if (op != GATE_QUERY) {
		request[GM_EPOCH] = 3;
		request[GM_GENERATION] = 7;
	}
	request[GM_OPEN_MASK] = op == GATE_OPEN ? mask : 0;
	memcpy(test.reply, request, sizeof(test.message.gate));
	test.reply[GM_STATUS] = 0;
	test.reply[GM_CAPS] = caps;
	test.reply[GM_CLOSED] = 1;
	test.reply[GM_DMA_IDLE] = 1;
	test.reply[GM_STATE_EPOCH] = request[GM_EPOCH];
	test.reply[GM_STATE_GENERATION] = request[GM_GENERATION];
	if (op == GATE_QUIET) {
		test.reply[GM_QUIET_ACK] = 1;
		test.reply[GM_FE_QUIESCED] = 1;
	}
	if (op == GATE_OPEN) {
		test.reply[GM_CLOSED] = 0;
		test.reply[GM_MASK] = mask;
		test.reply[GM_FE_ENABLED] = 1;
		test.reply[GM_ER_FLAGS] = GATE_ER_BOUND | GATE_ER_ACTIVE;
		test.reply[GM_AUTH_ENABLED] = 1;
		test.reply[GM_AUTH_EPOCH] = request[GM_EPOCH];
		test.reply[GM_AUTH_GENERATION] = request[GM_GENERATION];
	}
	return test;
}

static void common_cases(struct transaction test)
{
	const int errors[] = { -EAGAIN, -ESTALE, -EINVAL, -EIO, -EEXIST, -EBUSY };

	verify(test, 0);
	for (u32 index = 0; index < test.status; index++)
		change(test, index, test.reply[index] ^ 1, -EPROTO);
	change(test, test.status, 1, -EPROTO);
	for (u32 index = 0; index < ARRAY_SIZE(errors); index++) {
		struct transaction negative = test;

		negative.reply[test.status] = (u32)errors[index];
		verify(negative, errors[index]);
		change(negative, 0, 0, -EPROTO);
		change(negative, test.status + 1, 0, -EPROTO);
	}
	memcpy(test.reply, request_words(&test), test.words * sizeof(u32));
	verify(test, -EPROTO);
}

static void auth_cases(void)
{
	for (u32 op = AUTH_MBOX_QUERY; op <= AUTH_MBOX_DISARM; op++) {
		struct transaction test = auth_request(op);
		const u32 invalid[][2] = {
			{ AM_CAPS, 6 }, { AM_CAPS, 15 }, { AM_CAPS, 0x80000007 },
			{ AM_RESERVED2, 1 }, { AM_COUNT, 33 }, { AM_INFLIGHT, 65 },
			{ AM_ENABLED, 2 }, { AM_STATE_EPOCH, 0x10203040 },
			{ AM_STATE_GENERATION, 0x10203040 },
		};

		common_cases(test);
		for (u32 index = 0; index < ARRAY_SIZE(invalid); index++)
			change(test, invalid[index][0], invalid[index][1], -EPROTO);
		memset(test.reply + AM_STATE_EPOCH, 0,
		       (AUTH_MBOX_WORDS - AM_STATE_EPOCH) * sizeof(u32));
		test.reply[AM_STATUS] = (u32)-EAGAIN;
		verify(test, -EAGAIN);
		change(test, AM_COUNT, 1, -EPROTO);
		change(test, AM_INFLIGHT, 1, -EPROTO);
		change(test, AM_ENABLED, 1, -EPROTO);
	}
	change(auth_request(AUTH_MBOX_BEGIN), AM_COUNT, 1, -EPROTO);
	change(auth_request(AUTH_MBOX_BEGIN), AM_INFLIGHT, 1, -EPROTO);
	change(auth_request(AUTH_MBOX_BEGIN), AM_ENABLED, 1, -EPROTO);
	change(auth_request(AUTH_MBOX_ADD), AM_COUNT, 0, -EPROTO);
	change(auth_request(AUTH_MBOX_ADD), AM_COUNT, 32, 0);
	change(auth_request(AUTH_MBOX_ADD), AM_ENABLED, 1, -EPROTO);
	change(auth_request(AUTH_MBOX_ADD), AM_INFLIGHT, 1, -EPROTO);
	change(auth_request(AUTH_MBOX_ARM), AM_ENABLED, 0, -EPROTO);
	change(auth_request(AUTH_MBOX_ARM), AM_INFLIGHT, 1, -EPROTO);
	change(auth_request(AUTH_MBOX_DISARM), AM_ENABLED, 1, -EPROTO);
	change(auth_request(AUTH_MBOX_DISARM), AM_INFLIGHT, 64, 0);
	struct transaction test = auth_request(AUTH_MBOX_QUERY);

	test.reply[AM_STATE_EPOCH] = 99;
	test.reply[AM_STATE_GENERATION] = 100;
	test.reply[AM_COUNT] = 32;
	test.reply[AM_INFLIGHT] = 64;
	test.reply[AM_ENABLED] = 1;
	verify(test, 0);
	test.message.auth.w[AM_ABI_OP] = AUTH_MBOX_ABI | 5u << 16;
	test.reply[AM_ABI_OP] = test.message.auth.w[AM_ABI_OP];
	verify(test, -EPROTO);
}

static void er_cases(void)
{
	const u32 capabilities[] = { ER_CAPS, ER_CAPS | ER_CAP_SOURCES };
	const u32 invalid_caps[] = { 0, 1, 3, 6, 8, 14, 23, 31, 0x80000007 };
	const u32 sports[] = { ER_LAN1, ER_PON };

	for (u32 cap_index = 0; cap_index < ARRAY_SIZE(capabilities); cap_index++) {
		for (u32 source = 0; source < ARRAY_SIZE(sports); source++) {
			for (u32 op = ER_QUERY; op <= ER_UNBIND; op++) {
				struct transaction test = er_request(op, capabilities[cap_index],
							     sports[source]);

				if (!cap_index && source) {
					verify(test, -EPROTO);
					change(test, 8, (u32)-ESTALE, -ESTALE);
					continue;
				}
				common_cases(test);
				for (u32 index = 0; index < ARRAY_SIZE(invalid_caps); index++)
					change(test, 9, invalid_caps[index], -EPROTO);
				for (u32 index = 13; index < 16; index++)
					change(test, index, 1, -EPROTO);
				change(test, 10, ER_FAULT + 1, -EPROTO);
			}
		}
		struct transaction test = er_request(ER_QUERY, capabilities[cap_index], ER_LAN1);

		for (u32 state = ER_IDLE; state <= ER_FAULT; state++)
			change(test, 10, state, 0);
		change(test, 11, UINT32_MAX, 0);
		change(test, 12, 3, 0);
		struct transaction discovery = er_request(ER_QUERY, capabilities[cap_index], 0);

		for (u32 index = 2; index < 8; index++)
			assert(!discovery.message.er.w[index]);
		assert(!discovery.reply[11]);
		common_cases(discovery);
		for (u32 state = ER_IDLE; state <= ER_FAULT; state++)
			change(discovery, 10, state, 0);
		change(discovery, 12, 3, 0);
		for (u32 index = 2; index < 8; index++) {
			struct transaction malformed = discovery;

			malformed.message.er.w[index] = malformed.reply[index] = 1;
			verify(malformed, -EPROTO);
		}
		for (u32 op = ER_BIND; op <= ER_UNBIND; op++)
			verify(er_request(op, capabilities[cap_index], 0), -EPROTO);
		test.message.er.w[6] = test.reply[6] = 25;
		verify(test, -EPROTO);
		test.message.er.w[6] = test.reply[6] = ER_LAN1;
		test.message.er.w[1] = test.reply[1] = ER_ABI | 4u << 16;
		verify(test, -EPROTO);
	}
}

static void gate_cases(void)
{
	const u32 capabilities[] = { GATE_CAPS, GATE_CAPS | GATE_CAP_PON2 };
	const u32 masks[] = { GATE_FE24, GATE_PON2, GATE_FE24 | GATE_PON2 };
	const u32 invalid_caps[] = { 0, 1, 3, 6, 8, 14, 23, 31, 0x80000007 };
	const u32 invalid[][2] = {
		{ GM_RESERVED2, 1 }, { GM_MASK, 2 }, { GM_MASK, 8 },
		{ GM_CLOSED, 2 }, { GM_QUIET_ACK, 2 },
		{ GM_TDMA0, 3001 }, { GM_TDMA1, 3001 },
		{ GM_COMPLETION, 2 }, { GM_DONE, 65536 }, { GM_FE_ENABLED, 2 },
		{ GM_FE_QUIESCED, 2 }, { GM_FE_INFLIGHT, 2 }, { GM_ER_STATE, 6 },
		{ GM_ER_FLAGS, 2 }, { GM_ER_FLAGS, 4 }, { GM_DMA_IDLE, 2 },
		{ GM_AUTH_INFLIGHT, 65 }, { GM_AUTH_ENABLED, 2 },
		{ GM_STATE_EPOCH, 99 }, { GM_STATE_GENERATION, 99 },
	};
	const u32 quiet_nonzero[] = { GM_FAULT, GM_TDMA0, GM_TDMA1,
		GM_COMPLETION, GM_DONE, GM_FE_ENABLED, GM_FE_INFLIGHT,
		GM_ER_STATE, GM_ER_QUEUED, GM_AUTH_INFLIGHT };
	const u32 quiet_required[] = { GM_QUIET_ACK, GM_FE_QUIESCED, GM_DMA_IDLE };
	const u32 open_invalid[][2] = { { GM_CLOSED, 1 }, { GM_MASK, 0 },
		{ GM_QUIET_ACK, 1 }, { GM_FAULT, 1 }, { GM_FE_ENABLED, 0 },
		{ GM_FE_QUIESCED, 1 }, { GM_ER_FLAGS, 0 }, { GM_AUTH_ENABLED, 0 },
		{ GM_AUTH_EPOCH, 4 }, { GM_AUTH_GENERATION, 8 } };

	for (u32 cap_index = 0; cap_index < ARRAY_SIZE(capabilities); cap_index++) {
		u32 caps = capabilities[cap_index];
		u32 limit = cap_index ? 1024 : 512;

		for (u32 op = GATE_QUERY; op <= GATE_OPEN; op++) {
			struct transaction test = gate_request(op, caps, GATE_FE24);

			common_cases(test);
			for (u32 index = 0; index < ARRAY_SIZE(invalid); index++)
				change(test, invalid[index][0], invalid[index][1], -EPROTO);
			for (u32 index = 0; index < ARRAY_SIZE(invalid_caps); index++)
				change(test, GM_CAPS, invalid_caps[index], -EPROTO);
			change(test, GM_ER_QUEUED, limit + 1, -EPROTO);
			test.reply[GM_TDMA0] = 1501;
			test.reply[GM_TDMA1] = 1500;
			verify(test, -EPROTO);
			test = gate_request(op, caps, GATE_FE24);
			memset(test.reply + GM_STATE_EPOCH, 0,
			       (GATE_WORDS - GM_STATE_EPOCH) * sizeof(u32));
			test.reply[GM_CLOSED] = 1;
			test.reply[GM_STATUS] = (u32)-EAGAIN;
			verify(test, -EAGAIN);
			change(test, GM_ER_QUEUED, limit + 1, -EPROTO);
			change(test, GM_AUTH_EPOCH, 1, -EPROTO);
		}
		struct transaction test = gate_request(GATE_QUERY, caps, 0);

		change(test, GM_ER_QUEUED, limit, 0);
		change(test, GM_ER_QUEUED, 513, cap_index ? 0 : -EPROTO);
		test.reply[GM_STATE_EPOCH] = 99;
		test.reply[GM_STATE_GENERATION] = 100;
		test.reply[GM_AUTH_EPOCH] = 101;
		test.reply[GM_AUTH_GENERATION] = 102;
		test.reply[GM_TDMA0] = 1500;
		test.reply[GM_TDMA1] = 1500;
		test.reply[GM_DONE] = 65535;
		verify(test, 0);
		for (u32 index = 0; index < ARRAY_SIZE(masks); index++) {
			struct transaction opened = gate_request(GATE_OPEN, caps, masks[index]);
			int expected = !cap_index && index ? -EPROTO : 0;

			verify(opened, expected);
			change(opened, GM_ER_FLAGS, GATE_ER_BOUND,
			       cap_index && index < 2 ? 0 : -EPROTO);
			if (expected)
				continue;
			for (u32 field = 0; field < ARRAY_SIZE(open_invalid); field++)
				change(opened, open_invalid[field][0], open_invalid[field][1], -EPROTO);
			for (u32 other = 0; other < ARRAY_SIZE(masks); other++)
				if (other != index)
					change(opened, GM_MASK, masks[other], -EPROTO);
			change(opened, GM_AUTH_INFLIGHT, 64, 0);
			change(opened, GM_ER_QUEUED, limit, 0);
			change(opened, GM_ER_STATE, ER_RELEASING, 0);
		}
		struct transaction quiet = gate_request(GATE_QUIET, caps, 0);

		for (u32 index = 0; index < ARRAY_SIZE(quiet_nonzero); index++)
			change(quiet, quiet_nonzero[index], 1, -EPROTO);
		for (u32 index = 0; index < ARRAY_SIZE(quiet_required); index++)
			change(quiet, quiet_required[index], 0, -EPROTO);
		change(quiet, GM_ER_FLAGS, GATE_ER_BOUND, 0);
		change(quiet, GM_ER_FLAGS, GATE_ER_BOUND | GATE_ER_ACTIVE, 0);
		test = gate_request(GATE_CLOSE, caps, 0);
		test.reply[GM_CLOSED] = 0;
		test.reply[GM_MASK] = GATE_FE24;
		verify(test, -EPROTO);
		test.reply[GM_STATUS] = (u32)-ESTALE;
		verify(test, -ESTALE);
		test = gate_request(GATE_OPEN, caps, GATE_PON2);
		memset(test.reply + GM_STATE_EPOCH, 0,
		       (GATE_WORDS - GM_STATE_EPOCH) * sizeof(u32));
		test.reply[GM_CLOSED] = 1;
		test.reply[GM_STATUS] = (u32)-EINVAL;
		verify(test, -EINVAL);
		test = gate_request(GATE_QUERY, caps, 0);
		test.message.gate.w[GM_ABI_OP] = test.reply[GM_ABI_OP] = GATE_ABI | 4u << 16;
		verify(test, -EPROTO);
		const u32 bad_masks[] = { 0, 2, 3, 6, 7, 8, UINT32_MAX };

		for (u32 index = 0; index < ARRAY_SIZE(bad_masks); index++)
			verify(gate_request(GATE_OPEN, caps, bad_masks[index]), -EPROTO);
	}
}

static void availability_cases(void)
{
	struct transaction cases[] = { auth_request(AUTH_MBOX_QUERY),
		er_request(ER_QUERY, ER_CAPS, ER_LAN1), gate_request(GATE_QUERY, GATE_CAPS, 0) };

	for (u32 index = 0; index < ARRAY_SIZE(cases); index++) {
		struct transaction *test = &cases[index];
		union message original = test->message;

		send_error = -ETIMEDOUT;
		verify(*test, -ETIMEDOUT);
		send_error = -EIO;
		verify(*test, -EIO);
		send_error = 0;
		unsigned int before = calls;

		pending = test;
		ready = false;
		assert(command(&npu, test, false) == -EOPNOTSUPP);
		ready = true;
		property = false;
		assert(command(&npu, test, false) == -EOPNOTSUPP);
		property = true;
		assert(command(NULL, test, false) == -EOPNOTSUPP);
		assert(command(&npu, test, true) == -EOPNOTSUPP);
		assert(calls == before);
		assert(!memcmp(&test->message, &original, sizeof(original)));
		checks += 4;
	}
}

int main(void)
{
	_Static_assert(sizeof(struct er_message) == 64, "ER reply size");
	_Static_assert(sizeof(struct npu_auth_message) + 8 == 200, "AUTH envelope size");
	_Static_assert(sizeof(struct npu_gate_message) + 8 == 136, "GATE envelope size");
	auth_cases();
	er_cases();
	gate_cases();
	availability_cases();
	printf("PASS %u transport checks; %u mailbox calls\n", checks, calls);
	return 0;
}
