#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "airoha_npu_auth_publish.h"
#include "npu_ingress_auth.h"

#define TEST_EPOCH 0x10203040u
#define TEST_GENERATION 0x8090a0b0u
#define TEST_COUNT 32u
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed [%s] line %d: %s\n", \
			test_name, __LINE__, #condition); \
		exit(1); \
	} \
} while (0)

static const char *test_name = "startup";
static unsigned int publications;

enum fault_kind {
	FAULT_NONE, FAULT_BEFORE, FAULT_AFTER, FAULT_XOR, FAULT_SET
};

struct mock {
	struct npu_auth_state state;
	struct airoha_npu_auth_rule expected[TEST_COUNT];
	struct npu_auth_message last_add;
	auth_u32 epoch, generation, state_generation, count, calls;
	auth_u32 fault_at, fault_word, fault_value;
	enum fault_kind fault;
	int error;
};

static struct airoha_npu_auth_rule make_rule(auth_u32 index)
{
	struct airoha_npu_auth_rule rule = {
		.raw = {
			[0] = 1, [1] = TEST_EPOCH, [2] = 0x81020304u,
			[3] = 1, [4] = 127, [5] = 4, [6] = 2,
			[7] = 0xabcd, [8] = TEST_GENERATION,
			[9] = 4, [10] = 17, [11] = 0xc0000201u,
			[15] = 0xc6336402u, [19] = 0x1234abcdu,
			[25] = 0x02112233u, [26] = 0x44550266u,
			[27] = 0x778899aau,
		},
	};

	rule.raw[2] += index;
	rule.raw[4] += index;
	rule.raw[19] += index;
	return rule;
}

static void fill_rules(struct airoha_npu_auth_rule *rules, auth_u32 count)
{
	auth_u32 index;

	for (index = 0; index < count; ++index)
		rules[index] = make_rule(index);
}

static void prepare(struct mock *mock, const struct airoha_npu_auth_rule *rules,
		    auth_u32 count)
{
	memset(mock, 0, sizeof(*mock));
	CHECK(count && count <= TEST_COUNT);
	memcpy(mock->expected, rules, count * sizeof(*rules));
	mock->epoch = rules[0].raw[1];
	mock->generation = rules[0].raw[8];
	mock->count = count;
	npu_auth_init(&mock->state);
	mock->state.epoch = mock->epoch - 1u;
	mock->state_generation = mock->generation;
}

static int command(void *ctx, struct npu_auth_message *message)
{
	struct mock *mock = ctx;
	struct npu_auth_message expected = { .w = { 0 } };
	struct npu_auth_rule firmware_rule;
	auth_u32 op;
	int result;

	++mock->calls;
	CHECK(mock->calls <= mock->count + 2u);
	op = mock->calls == 1u ? AUTH_MBOX_BEGIN :
	     mock->calls == mock->count + 2u ? AUTH_MBOX_ARM : AUTH_MBOX_ADD;
	expected.w[AM_MAGIC] = 0x41555431u;
	expected.w[AM_ABI_OP] = 1u | (op << 16);
	expected.w[AM_BYTES] = 192u;
	expected.w[AM_EPOCH] = mock->epoch;
	expected.w[AM_GENERATION] = mock->generation;
	expected.w[AM_STATUS] = 0xffffff8du;
	if (op == AUTH_MBOX_ADD) {
		expected.w[AM_RULE_COUNT] = 1;
		memcpy(expected.w + AM_RULE, mock->expected[mock->calls - 2u].raw,
		       128);
		mock->last_add = *message;
	}
	CHECK(!memcmp(message, &expected, sizeof(expected)));
	if (mock->calls == mock->fault_at && mock->fault == FAULT_BEFORE)
		return mock->error;
	switch (op) {
	case AUTH_MBOX_BEGIN:
		result = npu_auth_begin(&mock->state, message->w[AM_EPOCH]);
		mock->state_generation = message->w[AM_GENERATION];
		break;
	case AUTH_MBOX_ADD:
		memcpy(firmware_rule.raw, message->w + AM_RULE, sizeof(firmware_rule));
		CHECK(firmware_rule.raw[5] == 4 && firmware_rule.raw[6] == 2);
		CHECK(firmware_rule.raw[7] < 65536u);
		CHECK(firmware_rule.raw[8] == mock->state_generation);
		result = npu_auth_add(&mock->state, &firmware_rule);
		break;
	case AUTH_MBOX_ARM:
		result = npu_auth_arm(&mock->state, message->w[AM_EPOCH]);
		break;
	default:
		CHECK(0);
		return -EINVAL;
	}
	CHECK(result == 0);
	message->w[AM_STATUS] = 0;
	message->w[AM_CAPS] = 7;
	message->w[AM_STATE_EPOCH] = mock->state.epoch;
	message->w[AM_STATE_GENERATION] = mock->state_generation;
	message->w[AM_COUNT] = mock->state.count;
	message->w[AM_INFLIGHT] = mock->state.inflight;
	message->w[AM_ENABLED] = mock->state.enabled;
	message->w[AM_RESERVED2] = 0;
	if (mock->calls == mock->fault_at) {
		if (mock->fault == FAULT_AFTER)
			return mock->error;
		if (mock->fault == FAULT_XOR)
			message->w[mock->fault_word] ^= mock->fault_value;
		if (mock->fault == FAULT_SET)
			message->w[mock->fault_word] = mock->fault_value;
	}
	return 0;
}

static int publish(struct mock *mock, const struct airoha_npu_auth_rule *rules)
{
	++publications;
	return airoha_npu_auth_publish(mock->epoch, mock->generation, rules,
				       mock->count, command, mock);
}

static void put_be16(uint8_t *bytes, auth_u32 value)
{
	bytes[0] = (uint8_t)(value >> 8);
	bytes[1] = (uint8_t)value;
}

static void put_be32(uint8_t *bytes, auth_u32 value)
{
	put_be16(bytes, value >> 16);
	put_be16(bytes + 2, value);
}

static void check_frame(const struct airoha_npu_auth_rule *rule)
{
	uint8_t frame[128] = { 0 };
	auth_u32 key[19], offset = 12, word;
	const auth_u32 *raw = rule->raw;
	auth_u32 transport_bytes = raw[10] == 6u ? 20u : 8u;
	auth_u32 ip_bytes = raw[9] == 4u ? 20u : 40u;
	auth_u32 ethertype = raw[9] == 4u ? 0x0800u : 0x86ddu;

	for (word = 0; word < 3; ++word)
		put_be32(frame + 4u * word, raw[25 + word]);
	for (word = 0; word < raw[20]; ++word) {
		put_be32(frame + offset, raw[21 + word]);
		offset += 4;
	}
	put_be16(frame + offset, raw[23] ? 0x8864u : ethertype);
	offset += 2;
	if (raw[23]) {
		frame[offset] = 0x11;
		put_be16(frame + offset + 2, raw[23]);
		put_be16(frame + offset + 4, ip_bytes + transport_bytes + 2);
		put_be16(frame + offset + 6, raw[24]);
		offset += 8;
	}
	if (raw[9] == 4u) {
		frame[offset] = 0x45;
		put_be16(frame + offset + 2, ip_bytes + transport_bytes);
		frame[offset + 8] = 64;
		frame[offset + 9] = (uint8_t)raw[10];
		put_be32(frame + offset + 12, raw[11]);
		put_be32(frame + offset + 16, raw[15]);
	} else {
		frame[offset] = 0x60;
		put_be16(frame + offset + 4, transport_bytes);
		frame[offset + 6] = (uint8_t)raw[10];
		frame[offset + 7] = 64;
		for (word = 0; word < 8; ++word)
			put_be32(frame + offset + 8 + 4u * word, raw[11 + word]);
	}
	offset += ip_bytes;
	put_be32(frame + offset, raw[19]);
	if (raw[10] == 6u) {
		frame[offset + 12] = 0x50;
		frame[offset + 13] = 0x10;
	} else {
		put_be16(frame + offset + 4, transport_bytes);
		put_be16(frame + offset + 6, 0x1234);
	}
	offset += transport_bytes;
	CHECK(npu_auth_parse(frame, offset, key) == NPU_AUTH_PPE1);
	CHECK(!memcmp(key, raw + 9, sizeof(key)));
}

static void expect_success(struct airoha_npu_auth_rule *rules, auth_u32 count)
{
	struct mock mock;
	struct airoha_npu_auth_rule saved[TEST_COUNT];
	auth_u32 index;

	memcpy(saved, rules, count * sizeof(*rules));
	for (index = 0; index < count; ++index)
		check_frame(&rules[index]);
	prepare(&mock, rules, count);
	CHECK(publish(&mock, rules) == 0);
	CHECK(mock.calls == count + 2u);
	CHECK(mock.state.count == count && mock.state.enabled == 1);
	CHECK(!mock.state.inflight);
	CHECK(mock.state.epoch == mock.epoch);
	CHECK(mock.state_generation == mock.generation);
	CHECK(!memcmp(saved, rules, count * sizeof(*rules)));
	CHECK(!memcmp(mock.state.rules, rules, count * sizeof(*rules)));
}

static void test_valid(void)
{
	static const auth_u32 endpoints[] = { 0, 0xfff, 0x1000, 0x8000, 0xabcd, 0xffff };
	struct airoha_npu_auth_rule rules[TEST_COUNT];
	auth_u32 family, protocol, tags, ppp, endpoint, word;

	test_name = "canonical-valid";
	for (family = 4; family <= 6; family += 2)
		for (protocol = 6; protocol <= 17; protocol += 11)
			for (tags = 0; tags <= 2; ++tags)
				for (ppp = 0; ppp <= 1; ++ppp)
					for (endpoint = 0; endpoint < ARRAY_SIZE(endpoints); ++endpoint) {
						rules[0] = make_rule(0);
						rules[0].raw[7] = endpoints[endpoint];
						rules[0].raw[9] = family;
						rules[0].raw[10] = protocol;
						if (family == 6)
							for (word = 11; word < 19; ++word)
								rules[0].raw[word] = 0x20010db8u + word;
						rules[0].raw[20] = tags;
						rules[0].raw[21] = tags ? 0x8100ffffu : 0;
						rules[0].raw[22] = tags == 2 ? 0x88a8ffffu : 0;
						rules[0].raw[23] = ppp ? 0xffffu : 0;
						rules[0].raw[24] = ppp ? (family == 4 ? 0x21u : 0x57u) : 0;
						expect_success(rules, 1);
					}
	rules[0] = make_rule(0);
	rules[0].raw[1] = UINT32_MAX;
	rules[0].raw[2] = UINT32_MAX;
	rules[0].raw[4] = 8191;
	rules[0].raw[8] = UINT32_MAX;
	rules[0].raw[19] = UINT32_MAX;
	expect_success(rules, 1);
	rules[0] = make_rule(0);
	rules[0].raw[1] = 1;
	rules[0].raw[2] = 1;
	rules[0].raw[4] = 0;
	rules[0].raw[8] = 1;
	rules[0].raw[11] = 0;
	rules[0].raw[15] = 0;
	rules[0].raw[19] = 0;
	rules[0].raw[25] = 0;
	rules[0].raw[26] = 0x00010000;
	rules[0].raw[27] = 1;
	expect_success(rules, 1);
	fill_rules(rules, TEST_COUNT);
	expect_success(rules, TEST_COUNT);
	for (word = 9; word < 20; ++word) {
		rules[0] = make_rule(0);
		rules[1] = make_rule(1);
		rules[0].raw[9] = rules[1].raw[9] = 6;
		rules[1].raw[19] = rules[0].raw[19];
		rules[1].raw[word] = word == 9 ? 4 :
				     word == 10 ? 6 : rules[0].raw[word] + 1;
		expect_success(rules, 2);
	}
}

static int count_command(void *ctx, struct npu_auth_message *message)
{
	unsigned int *calls = ctx;

	(void)message;
	++*calls;
	return -EIO;
}

static void expect_rejected(auth_u32 epoch, auth_u32 generation,
			    const struct airoha_npu_auth_rule *rules,
			    auth_u32 count, int expected)
{
	unsigned int calls = 0;

	++publications;
	CHECK(airoha_npu_auth_publish(epoch, generation, rules, count,
				     count_command, &calls) == expected);
	CHECK(calls == 0);
}

static void test_invalid(void)
{
	static const struct {
		auth_u32 word, value;
	} invalid[] = {
		{ 0, 0 }, { 0, 2 }, { 1, 0 }, { 1, TEST_EPOCH + 1 },
		{ 2, 0 }, { 3, 0 }, { 3, 2 }, { 4, 8192 }, { 4, UINT32_MAX },
		{ 5, 1 }, { 5, 2 }, { 5, 3 }, { 5, 5 }, { 6, 0 }, { 6, 3 },
		{ 6, 24 }, { 7, 65536 }, { 7, UINT32_MAX },
		{ 8, 0 }, { 8, TEST_GENERATION + 1 },
		{ 9, 0 }, { 9, 5 }, { 9, UINT32_MAX },
		{ 10, 0 }, { 10, 1 }, { 10, 58 },
		{ 12, 1 }, { 13, 1 }, { 14, 1 },
		{ 16, 1 }, { 17, 1 }, { 18, 1 },
		{ 20, 3 }, { 20, UINT32_MAX }, { 21, 0x81000001 }, { 22, 1 },
		{ 23, 65536 }, { 23, UINT32_MAX }, { 24, 0x21 }, { 24, 0x57 },
		{ 25, 0x03112233 }, { 26, 0x44550366 },
		{ 28, 1 }, { 29, 1 }, { 30, 1 }, { 31, 1 },
	};
	struct airoha_npu_auth_rule rules[TEST_COUNT];
	auth_u32 index;
	unsigned int calls = 0;

	test_name = "zero-command-rejection";
	fill_rules(rules, TEST_COUNT);
	expect_rejected(0, TEST_GENERATION, rules, TEST_COUNT, -EINVAL);
	expect_rejected(TEST_EPOCH, 0, rules, TEST_COUNT, -EINVAL);
	expect_rejected(TEST_EPOCH, TEST_GENERATION, NULL, 1, -EINVAL);
	expect_rejected(TEST_EPOCH, TEST_GENERATION, rules, 0, -EINVAL);
	expect_rejected(TEST_EPOCH, TEST_GENERATION, rules, 33, -EINVAL);
	expect_rejected(TEST_EPOCH, TEST_GENERATION, rules, UINT32_MAX, -EINVAL);
	CHECK(airoha_npu_auth_publish(TEST_EPOCH, TEST_GENERATION, rules, 1,
				     NULL, &calls) == -EINVAL);
	CHECK(!calls);
	for (index = 0; index < ARRAY_SIZE(invalid); ++index) {
		fill_rules(rules, TEST_COUNT);
		rules[TEST_COUNT - 1].raw[invalid[index].word] = invalid[index].value;
		expect_rejected(TEST_EPOCH, TEST_GENERATION, rules, TEST_COUNT, -EINVAL);
	}
	fill_rules(rules, TEST_COUNT);
	rules[31].raw[25] = 0;
	rules[31].raw[26] &= 0xffff;
	expect_rejected(TEST_EPOCH, TEST_GENERATION, rules, TEST_COUNT, -EINVAL);
	fill_rules(rules, TEST_COUNT);
	rules[31].raw[26] &= 0xffff0000u;
	rules[31].raw[27] = 0;
	expect_rejected(TEST_EPOCH, TEST_GENERATION, rules, TEST_COUNT, -EINVAL);
	for (index = 0; index < 5; ++index) {
		fill_rules(rules, TEST_COUNT);
		rules[31].raw[20] = 2;
		rules[31].raw[21] = 0x88a8a123;
		rules[31].raw[22] = 0x81007123;
		if (index == 0)
			rules[31].raw[21] = 0x08000001;
		if (index == 1)
			rules[31].raw[22] = 0x91000001;
		if (index == 2)
			rules[31].raw[21] = 0;
		if (index == 3)
			rules[31].raw[22] = 0;
		if (index == 4)
			rules[31].raw[20] = 1;
		expect_rejected(TEST_EPOCH, TEST_GENERATION, rules, TEST_COUNT, -EINVAL);
	}
	for (index = 0; index < 4; ++index) {
		fill_rules(rules, TEST_COUNT);
		rules[31].raw[23] = 0xbeef;
		rules[31].raw[24] = index == 0 ? 0 : index == 1 ? 0x57 : 0x21;
		if (index >= 2)
			rules[31].raw[9] = 6;
		if (index == 3)
			rules[31].raw[24] = 0x10057;
		expect_rejected(TEST_EPOCH, TEST_GENERATION, rules, TEST_COUNT, -EINVAL);
	}
}

static void check_firmware_conflict(const struct airoha_npu_auth_rule *first,
				    const struct airoha_npu_auth_rule *last)
{
	struct npu_auth_state state;
	struct npu_auth_rule rule;

	npu_auth_init(&state);
	CHECK(npu_auth_begin(&state, TEST_EPOCH) == 0);
	memcpy(&rule, first, sizeof(rule));
	CHECK(npu_auth_add(&state, &rule) == 0);
	memcpy(&rule, last, sizeof(rule));
	CHECK(npu_auth_add(&state, &rule) == NPU_AUTH_EXISTS);
}

static void test_duplicates(void)
{
	struct airoha_npu_auth_rule rules[TEST_COUNT];
	auth_u32 variant;

	test_name = "firmware-duplicate-key-token-row";
	for (variant = 0; variant < 7; ++variant) {
		fill_rules(rules, TEST_COUNT);
		if (variant == 0)
			rules[31].raw[2] = rules[0].raw[2];
		else if (variant == 1)
			rules[31].raw[4] = rules[0].raw[4];
		else {
			rules[31].raw[19] = rules[0].raw[19];
			if (variant == 3)
				rules[31].raw[7] = 0x1234;
			if (variant == 4) {
				rules[31].raw[20] = 2;
				rules[31].raw[21] = 0x88a8f123;
				rules[31].raw[22] = 0x8100b456;
			}
			if (variant == 5) {
				rules[31].raw[23] = 0x1234;
				rules[31].raw[24] = 0x21;
			}
			if (variant == 6) {
				rules[31].raw[25] ^= 0x02000000u;
				rules[31].raw[26] ^= 0x200u;
			}
		}
		check_frame(&rules[31]);
		check_firmware_conflict(&rules[0], &rules[31]);
		expect_rejected(TEST_EPOCH, TEST_GENERATION, rules, TEST_COUNT, -EEXIST);
	}
}

static void test_failures(void)
{
	static const int errors[] = { -EIO, -ETIMEDOUT, -EAGAIN, -ESTALE, -EEXIST, 1, 7 };
	struct airoha_npu_auth_rule rules[TEST_COUNT];
	struct mock mock;
	auth_u32 step, fault, error, before_count, after_count;

	test_name = "every-step-failure-and-lost-ack";
	fill_rules(rules, TEST_COUNT);
	for (step = 1; step <= TEST_COUNT + 2; ++step) {
		before_count = step < 2 ? 0 : step - 2;
		after_count = step <= TEST_COUNT + 1 ? step - 1 : TEST_COUNT;
		for (fault = FAULT_BEFORE; fault <= FAULT_AFTER; ++fault)
			for (error = 0; error < ARRAY_SIZE(errors); ++error) {
				prepare(&mock, rules, TEST_COUNT);
				mock.fault_at = step;
				mock.fault = (enum fault_kind)fault;
				mock.error = errors[error];
				CHECK(publish(&mock, rules) ==
				      (mock.error < 0 ? mock.error : -EPROTO));
				CHECK(mock.calls == step);
				CHECK(mock.state.count ==
				      (fault == FAULT_BEFORE ? before_count : after_count));
				CHECK(mock.state.enabled ==
				      (fault == FAULT_AFTER && step == TEST_COUNT + 2));
				CHECK(mock.state.epoch ==
				      (fault == FAULT_BEFORE && step == 1 ?
				       TEST_EPOCH - 1 : TEST_EPOCH));
			}
	}
}

static void test_replies(void)
{
	static const struct {
		auth_u32 word, value;
	} bad[] = {
		{ AM_STATUS, UINT32_MAX }, { AM_STATUS, 0xffffff8d },
		{ AM_CAPS, 15 }, { AM_COUNT, 33 }, { AM_INFLIGHT, 64 },
		{ AM_ENABLED, 2 }, { AM_STATE_EPOCH, 0 },
		{ AM_STATE_GENERATION, 0 }, { AM_RESERVED2, 0x80000000 },
	};
	struct airoha_npu_auth_rule rules[TEST_COUNT];
	struct mock mock;
	auth_u32 step, word, index;

	test_name = "all-48-reply-words-at-every-step";
	fill_rules(rules, TEST_COUNT);
	for (step = 1; step <= TEST_COUNT + 2; ++step) {
		for (word = 0; word < AUTH_MBOX_WORDS; ++word) {
			prepare(&mock, rules, TEST_COUNT);
			mock.fault_at = step;
			mock.fault = FAULT_XOR;
			mock.fault_word = word;
			mock.fault_value = 1;
			CHECK(publish(&mock, rules) == -EPROTO);
			CHECK(mock.calls == step);
		}
		for (index = 0; index < ARRAY_SIZE(bad); ++index) {
			prepare(&mock, rules, TEST_COUNT);
			mock.fault_at = step;
			mock.fault = FAULT_SET;
			mock.fault_word = bad[index].word;
			mock.fault_value = bad[index].value;
			CHECK(publish(&mock, rules) == -EPROTO);
			CHECK(mock.calls == step);
		}
	}
}

static void test_transport_values(void)
{
	struct airoha_npu_auth_rule rule = make_rule(0);
	struct mock mock;
	uint8_t wire[AUTH_MBOX_BYTES];
	auth_u32 word, byte;

	test_name = "host-numeric-transport-and-little-endian-vectors";
	rule.raw[20] = 2;
	rule.raw[21] = 0x88a8f123;
	rule.raw[22] = 0x8100b456;
	rule.raw[23] = 0xbeef;
	rule.raw[24] = 0x21;
	check_frame(&rule);
	prepare(&mock, &rule, 1);
	CHECK(publish(&mock, &rule) == 0);
	CHECK(mock.last_add.w[AM_ABI_OP] == 0x00020001);
	CHECK(mock.last_add.w[AM_RULE + 1] == 0x10203040);
	CHECK(mock.last_add.w[AM_RULE + 7] == 0xabcd);
	CHECK(mock.last_add.w[AM_RULE + 8] == 0x8090a0b0);
	CHECK(mock.last_add.w[AM_RULE + 11] == 0xc0000201);
	CHECK(mock.last_add.w[AM_RULE + 19] == 0x1234abcd);
	CHECK(mock.last_add.w[AM_RULE + 21] == 0x88a8f123);
	CHECK(mock.last_add.w[AM_RULE + 26] == 0x44550266);
	CHECK(mock.last_add.w[AM_STATUS] == 0xffffff8d);
	for (word = 0; word < AUTH_MBOX_WORDS; ++word)
		for (byte = 0; byte < 4; ++byte)
			wire[word * 4 + byte] = (uint8_t)(mock.last_add.w[word] >> (byte * 8));
	CHECK(!memcmp(wire + AM_MAGIC * 4, "\x31\x54\x55\x41", 4));
	CHECK(!memcmp(wire + AM_ABI_OP * 4, "\x01\x00\x02\x00", 4));
	CHECK(!memcmp(wire + AM_EPOCH * 4, "\x40\x30\x20\x10", 4));
	CHECK(!memcmp(wire + AM_GENERATION * 4, "\xb0\xa0\x90\x80", 4));
	CHECK(!memcmp(wire + (AM_RULE + 7) * 4, "\xcd\xab\x00\x00", 4));
	CHECK(!memcmp(wire + (AM_RULE + 11) * 4, "\x01\x02\x00\xc0", 4));
	CHECK(!memcmp(wire + (AM_RULE + 19) * 4, "\xcd\xab\x34\x12", 4));
	CHECK(!memcmp(wire + (AM_RULE + 21) * 4, "\x23\xf1\xa8\x88", 4));
	CHECK(!memcmp(wire + (AM_RULE + 23) * 4, "\xef\xbe\x00\x00", 4));
	CHECK(!memcmp(wire + (AM_RULE + 26) * 4, "\x66\x02\x55\x44", 4));
	CHECK(!memcmp(wire + AM_STATUS * 4, "\x8d\xff\xff\xff", 4));
}

static int null_context_command(void *ctx, struct npu_auth_message *message)
{
	static struct mock mock;
	struct airoha_npu_auth_rule rule = make_rule(0);

	CHECK(ctx == NULL);
	if ((message->w[AM_ABI_OP] >> 16) == AUTH_MBOX_BEGIN)
		prepare(&mock, &rule, 1);
	return command(&mock, message);
}

int main(void)
{
	struct airoha_npu_auth_rule rule = make_rule(0);

	test_valid();
	test_invalid();
	test_duplicates();
	test_failures();
	test_replies();
	test_transport_values();
	test_name = "optional-context";
	CHECK(airoha_npu_auth_publish(TEST_EPOCH, TEST_GENERATION, &rule, 1,
				     null_context_command, NULL) == 0);
	printf("PASS: %u publications; canonical/firmware, numeric transport, "
	       "34 boundaries, all 48 reply words, lost ACK and zero-command rejection\n",
	       publications + 1);
	return 0;
}
