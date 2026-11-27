#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
typedef uint16_t u16;
#define BIT(index) (UINT32_C(1) << (index))
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#include "airoha_ct_pon_ifc_words.h"

int main(void)
{
	struct airoha_ct_pon_ifc_words row, before;
	unsigned int service, protocol, ring, short_lut;

	memset(&row, 0xa5, sizeof(row));
	before = row;
	assert(airoha_ct_pon_ifc_cpu_encode(NULL, 1, ETH_P_IP, 2, 31) == -EINVAL);
	assert(airoha_ct_pon_ifc_cpu_encode(&row, 1, 0x88b5, 2, 31) == -EINVAL);
	assert(!memcmp(&row, &before, sizeof(row)));
	assert(airoha_ct_pon_ifc_cpu_encode(&row, 1, ETH_P_IP, 1, 31) == -EINVAL);
	assert(!memcmp(&row, &before, sizeof(row)));
	assert(airoha_ct_pon_ifc_cpu_encode(&row, 1, ETH_P_IP, 2, 32) == -EINVAL);
	assert(!memcmp(&row, &before, sizeof(row)));
	while (scanf("%u %u %u %u", &service, &protocol, &ring, &short_lut) == 4) {
		assert(service <= UINT16_MAX && protocol <= UINT16_MAX);
		assert(!airoha_ct_pon_ifc_cpu_encode(&row, service, protocol, ring, short_lut));
		for (unsigned int page = 0; page < 9; page++)
			printf("%08x %08x ", row.tcam[page][0], row.tcam[page][1]);
		for (unsigned int page = 0; page < 3; page++)
			for (unsigned int word = 0; word < 3; word++)
				printf("%08x ", row.action[page][word]);
		puts("");
	}
	return 0;
}
