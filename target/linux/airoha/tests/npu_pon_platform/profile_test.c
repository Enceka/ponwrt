#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define AIROHA_CT_PAIR_SLOTS 32
#define GFP_KERNEL 1
static unsigned checks, cases, allocations, node_puts, node_gets;
static unsigned eth_bits, npu_bits;
static bool requested, allocation_failure, missing_phandle;
#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed line %d: %s eth=%u npu=%u requested=%d fail=%d missing=%d\n", \
			__LINE__, #condition, eth_bits, npu_bits, requested, allocation_failure, missing_phandle); \
		exit(1); \
	} \
} while (0)

struct device_node { unsigned bits; bool npu; };
struct device { struct device_node *of_node; };
struct airoha_eth { struct device *dev; };
struct pair { uint32_t token; };
struct airoha_ppe { struct pair *ct_pairs; bool ct_native_pairs; };
static struct pair pairs[AIROHA_CT_PAIR_SLOTS];
static struct device_node ethernet_node, npu_node;

static bool of_property_read_bool(struct device_node *node, const char *name)
{
	CHECK(node == &ethernet_node || node == &npu_node);
	if (!strcmp(name, "airoha,connac2-rebuilt-ram-lab")) {
		CHECK(node->npu);
		return node->bits & 1;
	}
	if (!strcmp(name, "airoha,connac2-ram-native-pairs")) {
		CHECK(!node->npu);
		return node->bits & 1;
	}
	if (!strcmp(name, "airoha,connac2-ordinary-full-test"))
		return node->bits & 2;
	CHECK(!strcmp(name, "airoha,connac2-pon-full"));
	return node->bits & 4;
}

static struct device_node *of_parse_phandle(struct device_node *node, const char *name, int index)
{
	CHECK(node == &ethernet_node && !strcmp(name, "airoha,npu") && !index);
	++node_gets;
	return missing_phandle ? NULL : &npu_node;
}

static void of_node_put(struct device_node *node)
{
	CHECK(node == (missing_phandle ? NULL : &npu_node));
	CHECK(node_gets == 1 && !node_puts);
	++node_puts;
}

static bool airoha_ppe_ct_requested(struct airoha_eth *eth)
{
	CHECK(eth->dev->of_node == &ethernet_node && node_puts == 1);
	return requested;
}

static void *devm_kcalloc(struct device *device, size_t count, size_t size, int flags)
{
	CHECK(device->of_node == &ethernet_node && node_puts == 1);
	CHECK(count == AIROHA_CT_PAIR_SLOTS && size == sizeof(struct pair) && flags == GFP_KERNEL);
	++allocations;
	return allocation_failure ? NULL : pairs;
}

static int profile(struct airoha_eth *eth, struct airoha_ppe *ppe)
{
#include "profile.inc"
	return 0;
}

static void run_case(void)
{
	struct device device = { &ethernet_node };
	struct airoha_eth eth = { &device };
	struct airoha_ppe ppe = { 0 };
	unsigned effective_npu = missing_phandle ? 0 : npu_bits;
	bool matching_single = requested && eth_bits == effective_npu &&
		(eth_bits == 1 || eth_bits == 2 || eth_bits == 4);
	bool absent = !eth_bits && !effective_npu;
	int expected = absent ? 0 : !matching_single ? -EOPNOTSUPP : allocation_failure ? -ENOMEM : 0;

	ethernet_node = (struct device_node) { eth_bits, false };
	npu_node = (struct device_node) { npu_bits, true };
	allocations = node_puts = node_gets = 0;
	CHECK(profile(&eth, &ppe) == expected);
	CHECK(allocations == matching_single);
	CHECK(node_puts == 1 && node_gets == 1);
	CHECK(ppe.ct_native_pairs == (matching_single && !allocation_failure));
	CHECK(ppe.ct_pairs == (matching_single && !allocation_failure ? pairs : NULL));
	++cases;
}

int main(void)
{
	for (unsigned bits = 0; bits < 64; ++bits)
		for (unsigned mode = 0; mode < 4; ++mode) {
			eth_bits = bits & 7;
			npu_bits = bits >> 3;
			requested = mode & 1;
			allocation_failure = mode & 2;
			run_case();
		}
	missing_phandle = true;
	for (eth_bits = 0; eth_bits < 8; ++eth_bits)
		for (unsigned mode = 0; mode < 4; ++mode) {
			requested = mode & 1;
			allocation_failure = mode & 2;
			run_case();
		}
	printf("{\"passed\":true,\"profile_combinations\":64,\"cases\":%u,\"checks\":%u}\n", cases, checks);
	return 0;
}
