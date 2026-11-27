/* SPDX-License-Identifier: GPL-2.0-only */
#include "airoha_ct_gre4_port.h"

struct trace {
	u32 reg[25], value[25];
	int n, ack, stop;
};

static void wr(void *ctx, u32 reg, u32 val)
{
	struct trace *t = ctx;

	if (t->n < ARRAY_SIZE(t->reg)) {
		t->reg[t->n] = reg;
		t->value[t->n] = val;
	}
	t->n++;
}

static int wait_cmd(void *ctx)
{
	struct trace *t = ctx;

	return ++t->ack == t->stop ? -ETIMEDOUT : 0;
}

static struct airoha_ct_gre4_pool pool;

int gre4_port_test(unsigned int slot, int stop, bool clear);
int gre4_port_test(unsigned int slot, int stop, bool clear)
{
	static const u8 header[] = {
		2, 1, 2, 3, 4, 5, 2, 6, 7, 8, 9, 10, 8, 0,
		0x45, 0, 0, 60, 0x12, 0x34, 0x40, 0, 64, 47, 0, 0,
		10, 0, 0, 1, 10, 0, 0, 2, 0, 0, 8, 0,
	};
	static const u8 order[] = { 4, 0, 1, 2, 3 };
	struct airoha_ct_gre4_ref ref = {}, dup = {};
	struct airoha_ct_gre4_row row;
	struct airoha_foe_entry foe = {}, before;
	struct trace t = { .stop = stop };
	struct airoha_ct_gre4_port p = { wr, wait_cmd, &t };
	struct airoha_ct_gre4_io io = { airoha_ct_gre4_write, airoha_ct_gre4_drain, &p };
	int i, j, err, banks = stop ? stop : 5;

#define CHECK(c) do { if (!(c)) return __LINE__; } while (0)
	if (slot < 32 || slot > 63 || stop < 0 || stop > 5)
		return -EINVAL;
	memset(&pool, 0, sizeof(pool));
	CHECK(!airoha_ct_gre4_row_encode(&row, FLOW_ACTION_TUNNEL_ENCAP, header, sizeof(header)));
	foe.ib1 = FIELD_PREP(AIROHA_FOE_IB1_BIND_PACKET_TYPE, PPE_PKT_TYPE_IPV4_HNAPT);
	before = foe;
	CHECK(airoha_ct_gre4_prepare(&pool, &ref, &io, &foe, FLOW_ACTION_TUNNEL_ENCAP,
				     header, sizeof(header)) == -EOPNOTSUPP && !t.n);
	pool.owned = BIT(slot - 32);
	if (clear) {
		err = io.write(io.ctx, slot, NULL);
	} else {
		err = airoha_ct_gre4_prepare(&pool, &ref, &io, &foe, FLOW_ACTION_TUNNEL_ENCAP,
					    header, sizeof(header));
		if (stop) {
			CHECK(pool.fault == slot && !ref.pool && !memcmp(&before, &foe, sizeof(foe)));
		} else {
			CHECK(ref.slot == slot && FIELD_GET(AIROHA_FOE_TUNNEL_ID, foe.ipv4.data) == slot);
			CHECK(!airoha_ct_gre4_prepare(&pool, &dup, &io, &before, FLOW_ACTION_TUNNEL_ENCAP,
						      header, sizeof(header)) && dup.slot == slot);
		}
	}
	CHECK(err == (stop ? -ETIMEDOUT : 0) && t.n == banks * 5 && t.ack == banks);
	for (i = 0; i < banks; i++) {
		for (j = 0; j < 4; j++) {
			int n = i * 5 + j;
			u32 value = !i ? (j == 3 ? row.words[0] : 0) : row.words[1 + 4 * (i - 1) + j];

			CHECK(t.reg[n] == 0x208c - 4 * j && t.value[n] == (clear ? 0 : value));
		}
		CHECK(t.reg[5 * i + 4] == 0x207c && t.value[5 * i + 4] == (order[i] << 16 | slot << 8 | 0x11));
	}
	return 0;
}
