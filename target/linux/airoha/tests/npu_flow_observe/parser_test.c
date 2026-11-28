#include "frame_fixture.h"
#include "npu_ingress_auth.h"

static unsigned long accepted, rejected;

static void differential(const unsigned char *input, unsigned bytes, unsigned service)
{
	unsigned char *frame = malloc(bytes ? bytes : 1);
	struct airoha_npu_ipv4_identity identity, before;
	struct airoha_npu_auth_rule rule;
	uint32_t key[NPU_AUTH_KEY_WORDS];
	int firmware_result, result;

	CHECK(frame);
	memcpy(frame, input, bytes);
	memset(&identity, 0xa5, sizeof(identity));
	before = identity;
	firmware_result = npu_auth_parse(frame, bytes, key);
	result = airoha_npu_ingress_parse_ipv4(frame, bytes, service, &identity);
	CHECK((result == 0) == (firmware_result == NPU_AUTH_PPE1 && key[0] == 4));
	if (!result) {
		CHECK(identity.service == service);
		CHECK(!airoha_npu_auth_encode_ipv4(&rule, 1, 1, 1, 0, &identity));
		CHECK(!memcmp(rule.raw + 9, key, sizeof(key)));
		++accepted;
	} else {
		CHECK(result == -EINVAL);
		CHECK(!memcmp(&identity, &before, sizeof(identity)));
		++rejected;
	}
	CHECK(!memcmp(frame, input, bytes));
	free(frame);
	++cases;
}

static void test_frames(void)
{
	unsigned char frame[1536];

	scenario = "firmware-differential-truncations-and-every-field-bit";
	for (unsigned tags = 0; tags <= 2; ++tags)
		for (unsigned ppp = 0; ppp < 2; ++ppp)
			for (unsigned tcp = 0; tcp < 2; ++tcp)
				for (unsigned variant = 0; variant < 3; ++variant) {
					unsigned bytes = make_frame(frame, tags, ppp, tcp, variant * 4, 5 + variant);
					differential(frame, bytes, variant ? 0xffff : 0);
					for (unsigned length = 0; length < bytes; ++length)
						differential(frame, length, 0xabcd);
					for (unsigned offset = 0; offset < bytes; ++offset)
						for (unsigned bit = 0; bit < 8; ++bit) {
							frame[offset] ^= 1u << bit;
							differential(frame, bytes, 0xabcd);
							frame[offset] ^= 1u << bit;
						}
					differential(frame, bytes + 1, 0xabcd);
					differential(frame, 1518, 0xabcd);
					differential(frame, 1519, 0xabcd);
				}
	scenario = "third-vlan-rejected";
	unsigned bytes = make_frame(frame, 3, true, true, 0, 5);
	differential(frame, bytes, 1);
	scenario = "valid-ipv6-is-outside-ipv4-parser";
	make_frame(frame, 0, false, false, 0, 5);
	memset(frame + 14, 0, 48);
	put16(frame + 12, 0x86dd);
	frame[14] = 0x60;
	put16(frame + 18, 8);
	frame[20] = 17;
	put16(frame + 54, 1234);
	put16(frame + 56, 5678);
	put16(frame + 58, 8);
	put16(frame + 60, 1);
	uint32_t key[NPU_AUTH_KEY_WORDS];
	CHECK(npu_auth_parse(frame, 62, key) == NPU_AUTH_PPE1 && key[0] == 6);
	differential(frame, 62, 1);
}

static void test_invalid_arguments(void)
{
	unsigned char frame[1536];
	unsigned bytes = make_frame(frame, 2, true, true, 0, 5);
	struct airoha_npu_ipv4_identity output, before;
	const unsigned invalid_services[] = { 0x10000, 0x10001, UINT32_MAX };

	scenario = "null-and-original-service-overflow-preserve-output";
	memset(&output, 0xa5, sizeof(output));
	before = output;
	CHECK(airoha_npu_ingress_parse_ipv4(NULL, bytes, 1, &output) == -EINVAL);
	CHECK(!memcmp(&output, &before, sizeof(output)));
	CHECK(airoha_npu_ingress_parse_ipv4(frame, bytes, 1, NULL) == -EINVAL);
	CHECK(airoha_npu_ingress_parse_ipv4(NULL, 0, 1, NULL) == -EINVAL);
	for (unsigned index = 0; index < sizeof(invalid_services) / sizeof(invalid_services[0]); ++index) {
		CHECK(airoha_npu_ingress_parse_ipv4(frame, bytes, invalid_services[index], &output) == -EINVAL);
		CHECK(!memcmp(&output, &before, sizeof(output)));
		++cases;
	}
	CHECK(airoha_npu_ingress_parse_ipv4(frame, UINT32_MAX, 1, &output) == -EINVAL);
	CHECK(!memcmp(&output, &before, sizeof(output)));
}

int main(void)
{
	test_frames();
	test_invalid_arguments();
	printf("{\"passed\":true,\"cases\":%lu,\"checks\":%lu,\"accepted\":%lu,\"rejected\":%lu}\n",
	       cases, checks, accepted, rejected);
	return 0;
}
