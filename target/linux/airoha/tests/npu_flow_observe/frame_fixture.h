#ifndef FLOW_OBSERVE_FRAME_FIXTURE_H
#define FLOW_OBSERVE_FRAME_FIXTURE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "airoha_npu_flow_observe.h"

static unsigned long checks, cases;
static const char *scenario;
#define CHECK(condition) do { \
	++checks; \
	if (!(condition)) { \
		fprintf(stderr, "CHECK failed [%s] line %d: %s\n", scenario, __LINE__, #condition); \
		exit(1); \
	} \
} while (0)

static void put16(unsigned char *bytes, uint32_t value)
{
	bytes[0] = value >> 8;
	bytes[1] = value;
}

static void put32(unsigned char *bytes, uint32_t value)
{
	put16(bytes, value >> 16);
	put16(bytes + 2, value);
}

static unsigned make_frame(unsigned char *frame, unsigned tags, bool ppp,
			   bool tcp, unsigned payload, unsigned tcp_words)
{
	static const unsigned char macs[12] = {
		0xfe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x82, 0x66, 0x77, 0x88, 0x99, 0xaa,
	};
	unsigned offset = 12;
	unsigned transport = (tcp ? tcp_words * 4 : 8) + payload;

	memset(frame, 0, 1536);
	memcpy(frame, macs, sizeof(macs));
	for (unsigned tag = 0; tag < tags; ++tag) {
		put32(frame + offset, tag ? 0x8100b456 : 0x88a8f123);
		offset += 4;
	}
	put16(frame + offset, ppp ? 0x8864 : 0x0800);
	offset += 2;
	if (ppp) {
		frame[offset] = 0x11;
		put16(frame + offset + 2, 0xbeef);
		put16(frame + offset + 4, 22 + transport);
		put16(frame + offset + 6, 0x21);
		offset += 8;
	}
	frame[offset] = 0x45;
	put16(frame + offset + 2, 20 + transport);
	frame[offset + 8] = 64;
	frame[offset + 9] = tcp ? 6 : 17;
	put32(frame + offset + 12, 0xc0000201);
	put32(frame + offset + 16, 0xc6336402);
	offset += 20;
	put16(frame + offset, 0x1234);
	put16(frame + offset + 2, 0xabcd);
	if (tcp) {
		frame[offset + 12] = tcp_words << 4;
		frame[offset + 13] = 0x10;
	} else {
		put16(frame + offset + 4, transport);
		put16(frame + offset + 6, 0x1234);
	}
	return offset + transport;
}

#endif
