#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "airoha_npu_flow_key.h"
#include "npu_ingress_auth.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define EPOCH 0x10203040u
#define GENERATION 0x8090a0b0u
#define TOKEN 0x81020304u
static unsigned long checks;
static unsigned cases;
static const char *scenario;
#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed [%s] line %d: %s\n", scenario, __LINE__, #condition); \
		exit(1); \
	} \
} while (0)

static struct airoha_npu_ipv4_identity identity(void)
{
	return (struct airoha_npu_ipv4_identity) {
		.service = 0xabcd, .source_ip = 0xc0000201, .destination_ip = 0xc6336402,
		.source_port = 0x1234, .destination_port = 0xabcd, .protocol = 17,
		.vlan_count = 2, .vlan = { 0x88a8f123, 0x8100b456 }, .pppoe_session = 0xbeef,
		.destination_mac = { 0xfe, 0x11, 0x22, 0x33, 0x44, 0x55 },
		.source_mac = { 0x82, 0x66, 0x77, 0x88, 0x99, 0xaa },
	};
}

static void put16(unsigned char *bytes, auth_u32 value)
{
	bytes[0] = value >> 8;
	bytes[1] = value;
}

static void put32(unsigned char *bytes, auth_u32 value)
{
	put16(bytes, value >> 16);
	put16(bytes + 2, value);
}

static unsigned make_frame(const struct airoha_npu_ipv4_identity *input,
			   unsigned char frame[128])
{
	unsigned offset = 12;
	unsigned transport_bytes = input->protocol == 6 ? 20 : 8;

	memset(frame, 0, 128);
	memcpy(frame, input->destination_mac, 6);
	memcpy(frame + 6, input->source_mac, 6);
	for (unsigned tag = 0; tag < input->vlan_count; ++tag) {
		put32(frame + offset, input->vlan[tag]);
		offset += 4;
	}
	put16(frame + offset, input->pppoe_session ? 0x8864 : 0x0800);
	offset += 2;
	if (input->pppoe_session) {
		frame[offset] = 0x11;
		put16(frame + offset + 2, input->pppoe_session);
		put16(frame + offset + 4, 22 + transport_bytes);
		put16(frame + offset + 6, 0x21);
		offset += 8;
	}
	frame[offset] = 0x45;
	put16(frame + offset + 2, 20 + transport_bytes);
	frame[offset + 8] = 64;
	frame[offset + 9] = input->protocol;
	put32(frame + offset + 12, input->source_ip);
	put32(frame + offset + 16, input->destination_ip);
	offset += 20;
	put16(frame + offset, input->source_port);
	put16(frame + offset + 2, input->destination_port);
	if (input->protocol == 6) {
		frame[offset + 12] = 0x50;
		frame[offset + 13] = 0x10;
	} else {
		put16(frame + offset + 4, transport_bytes);
		put16(frame + offset + 6, 0x1234);
	}
	return offset + transport_bytes;
}

static void check_take(const struct airoha_npu_auth_rule *rule,
		       const struct airoha_npu_ipv4_identity *frame_identity,
		       auth_u32 service, auth_u32 generation, bool expected)
{
	struct npu_auth_state state;
	struct npu_auth_rule firmware_rule;
	struct npu_auth_ticket ticket = { 0 };
	struct npu_auth_domain domain = { NPU_AUTH_PON, 2, service, generation };
	unsigned char frame[128];
	unsigned bytes = make_frame(frame_identity, frame);
	uint32_t descriptor[8] = { bytes, service, 7, 0, 0, 6u << 28, 2, 0 };

	npu_auth_init(&state);
	CHECK(!npu_auth_begin(&state, rule->raw[1]));
	memcpy(&firmware_rule, rule, sizeof(firmware_rule));
	CHECK(!npu_auth_add(&state, &firmware_rule));
	CHECK(!npu_auth_arm(&state, rule->raw[1]));
	CHECK(npu_auth_take(&state, &domain, frame, bytes, &ticket) == (expected ? NPU_AUTH_PPE1 : NPU_AUTH_CPU));
	CHECK(state.inflight == expected);
	if (expected) {
		CHECK(ticket.epoch == rule->raw[1] && ticket.serial && ticket.lease);
		CHECK(!npu_auth_complete(&state, &ticket));
	}
	CHECK(!ticket.epoch && !ticket.serial && !ticket.lease && !state.inflight);
	CHECK(npu_auth_fe_take_ex(&state, descriptor, generation, frame, bytes, &ticket) ==
	      (expected ? NPU_AUTH_PPE1 : NPU_AUTH_CPU));
	CHECK(state.inflight == expected);
	if (expected)
		CHECK(!npu_auth_complete(&state, &ticket));
	CHECK(!ticket.epoch && !ticket.serial && !ticket.lease && !state.inflight);
}

static void success(const struct airoha_npu_ipv4_identity *input,
		    auth_u32 epoch, auth_u32 generation, auth_u32 token, auth_u32 row)
{
	struct airoha_npu_auth_rule rule;
	struct airoha_npu_ipv4_identity saved = *input;
	unsigned char frame[128];
	uint32_t key[NPU_AUTH_KEY_WORDS];
	unsigned bytes = make_frame(input, frame);

	memset(&rule, 0xa5, sizeof(rule));
	CHECK(!airoha_npu_auth_encode_ipv4(&rule, epoch, generation, token, row, input));
	CHECK(!memcmp(input, &saved, sizeof(saved)));
	CHECK(rule.raw[0] == AUTH_MBOX_ABI && rule.raw[1] == epoch && rule.raw[2] == token);
	CHECK(rule.raw[3] == 0 && rule.raw[4] == row && rule.raw[5] == 4 && rule.raw[6] == 2);
	CHECK(rule.raw[7] == input->service && rule.raw[8] == generation);
	for (unsigned word = 28; word < 32; ++word)
		CHECK(!rule.raw[word]);
	CHECK(!airoha_npu_auth_rules_validate(epoch, generation, &rule, 1));
	CHECK(npu_auth_parse(frame, bytes, key) == NPU_AUTH_PPE1);
	CHECK(!memcmp(key, rule.raw + 9, sizeof(key)));
	check_take(&rule, input, input->service, generation, true);
	++cases;
}

static void test_valid(void)
{
	static const auth_u32 services[] = { 0, 1, 0xfff, 0x1000, 0x8000, 0xffff };
	static const auth_u32 ports[] = { 0, 1, 0x8000, 0xffff };
	static const auth_u32 sessions[] = { 0, 1, 0xffff };
	static const auth_u32 tags[] = { 0x81000000, 0x8100ffff, 0x88a80000, 0x88a8ffff };

	scenario = "valid-identity-firmware-parser-and-take";
	for (unsigned protocol = 0; protocol < 2; ++protocol)
		for (unsigned count = 0; count <= 2; ++count)
			for (unsigned tag = 0; tag < ARRAY_SIZE(tags); ++tag)
				for (unsigned ppp = 0; ppp < ARRAY_SIZE(sessions); ++ppp)
					for (unsigned service = 0; service < ARRAY_SIZE(services); ++service)
						for (unsigned port = 0; port < ARRAY_SIZE(ports); ++port) {
							struct airoha_npu_ipv4_identity input = identity();
							input.protocol = protocol ? 17 : 6;
							input.vlan_count = count;
							input.vlan[0] = count ? tags[tag] : 0;
							input.vlan[1] = count == 2 ? tags[(tag + 1) % ARRAY_SIZE(tags)] : 0;
							input.pppoe_session = sessions[ppp];
							input.service = services[service];
							input.source_port = ports[port];
							input.destination_port = ports[ARRAY_SIZE(ports) - port - 1];
							success(&input, EPOCH, GENERATION, TOKEN, 0x458);
						}
	for (unsigned boundary = 0; boundary < 2; ++boundary) {
		struct airoha_npu_ipv4_identity input = identity();
		input.source_ip = boundary ? UINT32_MAX : 0;
		input.destination_ip = boundary ? 0 : UINT32_MAX;
		success(&input, boundary ? UINT32_MAX : 1, boundary ? UINT32_MAX : 1,
			boundary ? UINT32_MAX : 1, boundary ? 8191 : 0);
	}
}

static void test_golden(void)
{
	struct airoha_npu_ipv4_identity input = identity();
	struct airoha_npu_auth_rule rule;
	static const auth_u32 expected[32] = {
		1, EPOCH, TOKEN, 0, 0x458, 4, 2, 0xabcd, GENERATION,
		4, 17, 0xc0000201, 0, 0, 0, 0xc6336402, 0, 0, 0, 0x1234abcd,
		2, 0x88a8f123, 0x8100b456, 0xbeef, 0x21,
		0xfe112233, 0x44558266, 0x778899aa, 0, 0, 0, 0,
	};

	scenario = "independent-32-word-golden-vector";
	CHECK(!airoha_npu_auth_encode_ipv4(&rule, EPOCH, GENERATION, TOKEN, 0x458, &input));
	CHECK(!memcmp(rule.raw, expected, sizeof(expected)));
	++cases;
}

static void rejected(const struct airoha_npu_ipv4_identity *input,
		     auth_u32 epoch, auth_u32 generation, auth_u32 token, auth_u32 row)
{
	struct airoha_npu_auth_rule rule, before;
	struct airoha_npu_ipv4_identity saved;

	memset(&rule, 0xa5, sizeof(rule));
	before = rule;
	if (input)
		saved = *input;
	CHECK(airoha_npu_auth_encode_ipv4(&rule, epoch, generation, token, row, input) == -EINVAL);
	CHECK(!memcmp(&rule, &before, sizeof(rule)));
	if (input)
		CHECK(!memcmp(input, &saved, sizeof(saved)));
	++cases;
}

static void test_invalid(void)
{
	struct airoha_npu_ipv4_identity input = identity();
	static const auth_u32 protocols[] = { 0, 1, 58, 0x106, 0x111, UINT32_MAX };
	static const auth_u32 bad_tags[] = { 0, 0x08000001, 0x91000001, UINT32_MAX };

	scenario = "null-identity-and-rule-identifiers";
	CHECK(airoha_npu_auth_encode_ipv4(NULL, EPOCH, GENERATION, TOKEN, 0, &input) == -EINVAL);
	CHECK(airoha_npu_auth_encode_ipv4(NULL, EPOCH, GENERATION, TOKEN, 0, NULL) == -EINVAL);
	rejected(NULL, EPOCH, GENERATION, TOKEN, 0);
	rejected(&input, 0, GENERATION, TOKEN, 0);
	rejected(&input, EPOCH, 0, TOKEN, 0);
	rejected(&input, EPOCH, GENERATION, 0, 0);
	rejected(&input, EPOCH, GENERATION, TOKEN, 8192);
	rejected(&input, EPOCH, GENERATION, TOKEN, UINT32_MAX);
	scenario = "original-fields-before-narrowing";
	for (unsigned field = 0; field < 4; ++field)
		for (unsigned bit = 16; bit <= 32; ++bit) {
			input = identity();
			auth_u32 value = bit == 32 ? UINT32_MAX : (1u << bit) | 1u;
			switch (field) {
			case 0: input.service = value; break;
			case 1: input.source_port = value; break;
			case 2: input.destination_port = value; break;
			case 3: input.pppoe_session = value; break;
			}
			rejected(&input, EPOCH, GENERATION, TOKEN, 0);
		}
	for (unsigned index = 0; index < ARRAY_SIZE(protocols); ++index) {
		input = identity();
		input.protocol = protocols[index];
		rejected(&input, EPOCH, GENERATION, TOKEN, 0);
	}
	scenario = "invalid-and-unused-vlan-fields";
	for (unsigned slot = 0; slot < 2; ++slot)
		for (unsigned index = 0; index < ARRAY_SIZE(bad_tags); ++index) {
			input = identity();
			input.vlan[slot] = bad_tags[index];
			rejected(&input, EPOCH, GENERATION, TOKEN, 0);
		}
	for (unsigned variant = 0; variant < 6; ++variant) {
		input = identity();
		switch (variant) {
		case 0: input.vlan_count = 3; break;
		case 1: input.vlan_count = UINT32_MAX; break;
		case 2: input.vlan_count = 0x10000; break;
		case 3: input.vlan_count = 0; input.vlan[1] = 0; break;
		case 4: input.vlan_count = 0; input.vlan[0] = 0; break;
		case 5: input.vlan_count = 1; break;
		}
		rejected(&input, EPOCH, GENERATION, TOKEN, 0);
	}
	scenario = "invalid-unicast-mac-addresses";
	for (unsigned side = 0; side < 2; ++side)
		for (unsigned variant = 0; variant < 3; ++variant) {
			input = identity();
			unsigned char *mac = side ? input.source_mac : input.destination_mac;
			if (variant == 0)
				memset(mac, 0, 6);
			else if (variant == 1)
				memset(mac, 0xff, 6);
			else
				mac[0] |= 1;
			rejected(&input, EPOCH, GENERATION, TOKEN, 0);
		}
}

static void test_ingress_identity(void)
{
	struct airoha_npu_ipv4_identity ingress = identity();
	struct airoha_npu_auth_rule rule;

	scenario = "original-ingress-versus-nat-and-other-identities";
	CHECK(!airoha_npu_auth_encode_ipv4(&rule, EPOCH, GENERATION, TOKEN, 0x458, &ingress));
	for (unsigned variant = 0; variant < 13; ++variant) {
		struct airoha_npu_ipv4_identity changed = ingress;
		struct airoha_npu_auth_rule changed_rule;
		switch (variant) {
		case 0: changed.source_ip = 0xcb00710a; break;
		case 1: changed.destination_ip = 0xc0a80178; break;
		case 2: changed.source_port = 40000; break;
		case 3: changed.destination_port = 8080; break;
		case 4: changed.destination_mac[5] ^= 1; break;
		case 5: changed.source_mac[5] ^= 1; break;
		case 6: changed.vlan[0] ^= 0x1000; break;
		case 7: changed.vlan[1] ^= 1; break;
		case 8: changed.pppoe_session++; break;
		case 9: changed.protocol = 6; break;
		case 10: changed.service ^= 0x8000; break;
		case 11: changed.vlan_count = 1; changed.vlan[1] = 0; break;
		case 12: changed.pppoe_session = 0; break;
		}
		check_take(&rule, &changed, changed.service, GENERATION, false);
		CHECK(!airoha_npu_auth_encode_ipv4(&changed_rule, EPOCH, GENERATION, TOKEN, 0x458, &changed));
		check_take(&changed_rule, &ingress, ingress.service, GENERATION, false);
		check_take(&changed_rule, &changed, changed.service, GENERATION, true);
		++cases;
	}
	check_take(&rule, &ingress, ingress.service, GENERATION ^ 1u, false);
	check_take(&rule, &ingress, ingress.service, GENERATION, true);
}

int main(void)
{
	test_golden();
	test_valid();
	test_invalid();
	test_ingress_identity();
	printf("{\"passed\":true,\"cases\":%u,\"checks\":%lu}\n", cases, checks);
	return 0;
}
