#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define BIT(index) (UINT32_C(1) << (index))
#include "airoha_ct_ifc_tuple_words.h"

static void invalid_inputs(void)
{
	struct airoha_ct_ifc_tuple tuple = { .family = 4, .protocol = 6 };
	struct airoha_ct_ifc_tuple_words words, previous;

	memset(&words, 0xa5, sizeof(words));
	previous = words;
	assert(airoha_ct_ifc_tuple_encode(NULL, &tuple) == -EINVAL);
	assert(airoha_ct_ifc_tuple_encode(&words, NULL) == -EINVAL);
	for (unsigned int family = 0; family < 256; family++) {
		if (family == 4 || family == 6)
			continue;
		tuple.family = family;
		assert(airoha_ct_ifc_tuple_encode(&words, &tuple) == -EINVAL);
		assert(!memcmp(&words, &previous, sizeof(words)));
	}
	tuple.family = 4;
	for (unsigned int protocol = 0; protocol < 256; protocol++) {
		if (protocol == 6 || protocol == 17)
			continue;
		tuple.protocol = protocol;
		assert(airoha_ct_ifc_tuple_encode(&words, &tuple) == -EINVAL);
		assert(!memcmp(&words, &previous, sizeof(words)));
	}
	tuple.protocol = 6;
	for (unsigned int index = 1; index < 4; index++) {
		tuple.src[index] = 1;
		assert(airoha_ct_ifc_tuple_encode(&words, &tuple) == -EINVAL);
		tuple.src[index] = 0;
		tuple.dst[index] = 1;
		assert(airoha_ct_ifc_tuple_encode(&words, &tuple) == -EINVAL);
		tuple.dst[index] = 0;
		assert(!memcmp(&words, &previous, sizeof(words)));
	}
}

int main(void)
{
	unsigned int family, protocol, sport, dport;

	invalid_inputs();
	while (scanf("%u %u %u %u", &family, &protocol, &sport, &dport) == 4) {
		struct airoha_ct_ifc_tuple tuple = {
			.family = family, .protocol = protocol, .sport = sport, .dport = dport,
		};
		struct airoha_ct_ifc_tuple_words words;

		for (unsigned int index = 0; index < 4; index++)
			assert(scanf("%x", &tuple.src[index]) == 1);
		for (unsigned int index = 0; index < 4; index++)
			assert(scanf("%x", &tuple.dst[index]) == 1);
		assert(!airoha_ct_ifc_tuple_encode(&words, &tuple));
		assert(words.count == (family == 4 ? 5 : 11));
		printf("%u", words.count);
		for (unsigned int index = 0; index < 11; index++) {
			if (index < words.count)
				assert((words.lut[index][1] & 0xc000) == 0xc000);
			else
				assert(!words.lut[index][0] && !words.lut[index][1]);
			printf(" %08x %08x", words.lut[index][0], words.lut[index][1]);
		}
		putchar('\n');
	}
	return 0;
}
