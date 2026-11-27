#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t u32;
typedef uint16_t u16;

#define BIT(index) (UINT32_C(1) << (index))
#define container_of(pointer, type, member) \
	((type *)((char *)(pointer) - offsetof(type, member)))

static unsigned long checks, cases;
static u32 initial_value;
static unsigned long current_id;
static unsigned int current_assert, current_seed, current_pattern;

#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "FAIL line %d: %s; id=%lu assert=%u seed=%u pattern=%u\n", \
			__LINE__, #condition, current_id, current_assert, current_seed, current_pattern); \
		exit(1); \
	} \
} while (0)

struct reset_controller_dev {
	u32 cookie;
};

struct regmap {
	u32 words[3];
	u32 last_addr, last_mask, last_value;
	unsigned int updates, reads, writes;
	int read_error, write_error;
};

#include "reset_types.inc"

static unsigned int bank_index(u32 addr)
{
	unsigned int bank;

	for (bank = 0; bank < 3; ++bank)
		if (en7581_rst_ofs[bank] == addr)
			return bank;
	CHECK(false);
	return 0;
}

static int regmap_read(struct regmap *map, u32 addr, u32 *value)
{
	++map->reads;
	map->last_addr = addr;
	if (map->read_error)
		return map->read_error;
	*value = map->words[bank_index(addr)];
	return 0;
}

static int regmap_update_bits(struct regmap *map, u32 addr, u32 mask, u32 value)
{
	u32 previous, next;
	int error;

	++map->updates;
	map->last_mask = mask;
	map->last_value = value;
	error = regmap_read(map, addr, &previous);
	if (error)
		return error;
	next = (previous & ~mask) | (value & mask);
	if (next == previous)
		return 0;
	++map->writes;
	if (map->write_error)
		return map->write_error;
	map->words[bank_index(addr)] = next;
	return 0;
}

#include "reset_functions.inc"

static u32 pattern(unsigned int index)
{
	static const u32 fixed[] = { 0, UINT32_MAX, 0xaaaaaaaa, 0x55555555 };

	if (index < 4)
		return fixed[index];
	if (index < 36)
		return BIT(index - 4);
	return ~BIT(index - 36);
}

static struct regmap new_map(unsigned int bank, u32 value)
{
	struct regmap map = { .words = { 0x13579bdf, 0x2468ace0, 0xa55a5aa5 } };

	map.words[bank] = value;
	return map;
}

static int operation(struct en_rst_data *reset, bool asserted)
{
	return asserted ? en7523_reset_assert(&reset->rcdev, current_id) :
		en7523_reset_deassert(&reset->rcdev, current_id);
}

static void test_success(unsigned int bank, u32 mask, bool asserted, u32 before)
{
	struct regmap map = new_map(bank, before);
	struct en_rst_data reset = { .bank_ofs = en7581_rst_ofs, .map = &map };
	u32 expected[3], value = asserted != (bank == 2) ? mask : 0;
	unsigned int writes;

	memcpy(expected, map.words, sizeof(expected));
	expected[bank] = (before & ~mask) | value;
	CHECK(operation(&reset, asserted) == 0);
	CHECK(map.updates == 1 && map.reads == 1);
	CHECK(map.last_addr == en7581_rst_ofs[bank]);
	CHECK(map.last_mask == mask && map.last_value == value);
	CHECK(memcmp(expected, map.words, sizeof(expected)) == 0);
	CHECK(map.writes == (unsigned int)(before != expected[bank]));
	writes = map.writes;
	CHECK(operation(&reset, asserted) == 0);
	CHECK(map.updates == 2 && map.reads == 2 && map.writes == writes);
	CHECK(memcmp(expected, map.words, sizeof(expected)) == 0);
	CHECK(en7523_reset_status(&reset.rcdev, current_id) == (int)asserted);
	CHECK(map.updates == 2 && map.reads == 3 && map.writes == writes);
	CHECK(memcmp(expected, map.words, sizeof(expected)) == 0);
	++cases;
}

static void test_errors(unsigned int bank, u32 mask, bool asserted)
{
	static const int errors[] = { -5, -11, -110 };
	u32 value = asserted != (bank == 2) ? mask : 0;
	unsigned int index, stage;

	for (index = 0; index < sizeof(errors) / sizeof(errors[0]); ++index) {
		for (stage = 0; stage < 3; ++stage) {
			struct regmap map = new_map(bank, (0xa5a55a5a & ~mask) | (value ^ mask));
			struct en_rst_data reset = { .bank_ofs = en7581_rst_ofs, .map = &map };
			u32 before[3];

			memcpy(before, map.words, sizeof(before));
			if (stage == 1)
				map.write_error = errors[index];
			else
				map.read_error = errors[index];
			if (stage == 2) {
				CHECK(en7523_reset_status(&reset.rcdev, current_id) == errors[index]);
				CHECK(map.updates == 0 && map.reads == 1 && map.writes == 0);
			} else {
				CHECK(operation(&reset, asserted) == errors[index]);
				CHECK(map.updates == 1 && map.reads == 1 && map.writes == stage);
				CHECK(map.last_mask == mask && map.last_value == value);
			}
			CHECK(map.last_addr == en7581_rst_ofs[bank]);
			CHECK(memcmp(before, map.words, sizeof(before)) == 0);
			map.read_error = map.write_error = 0;
			CHECK(operation(&reset, asserted) == 0);
			CHECK(en7523_reset_status(&reset.rcdev, current_id) == (int)asserted);
			++cases;
		}
	}
}

int main(void)
{
	unsigned int bank, bit, seeds = 1;

#ifdef SEEDED_LOCALS
	seeds = 68;
#endif
	CHECK(sizeof(en7581_rst_ofs) / sizeof(en7581_rst_ofs[0]) == 3);
	CHECK(en7581_rst_ofs[0] == REG_RST_CTRL2);
	CHECK(en7581_rst_ofs[1] == REG_RST_CTRL1);
	CHECK(en7581_rst_ofs[2] == REG_NP_SCU_PCIC);
	for (current_seed = 0; current_seed < seeds; ++current_seed) {
		initial_value = pattern(current_seed);
		for (bank = 0; bank < 3; ++bank) {
			for (bit = 0; bit < 32; ++bit) {
				current_id = bank * 32 + bit;
				for (current_assert = 0; current_assert < 2; ++current_assert) {
					for (current_pattern = 0; current_pattern < 68; ++current_pattern)
						test_success(bank, BIT(bit), current_assert, pattern(current_pattern));
					test_errors(bank, BIT(bit), current_assert);
				}
			}
		}
	}
	printf("PASS: %lu cases; %lu checks; %u local seeds; 3 banks x 32 bits\n",
	       cases, checks, seeds);
	return 0;
}
