#include "airoha_ct_gre4_lifetime.h"

struct fe_model {
	struct airoha_ct_gre4_row hw[64], staged;
	u32 writes, drains, forbidden;
	u8 late;
	bool fail_write, fail_drain;
};

static struct fe_model fe;
static struct airoha_ct_gre4_pool pool;
static struct airoha_ct_gre4_ref refs[33];

static int write_row(void *ctx, u8 slot, const struct airoha_ct_gre4_row *row)
{
	struct fe_model *m = ctx;

	if (m->late || slot < 32 || slot >= 64 || !(pool.owned & BIT(slot - 32))) {
		m->forbidden++;
		return -EBUSY;
	}
	m->writes++;
	m->staged = row ? *row : (struct airoha_ct_gre4_row) {};
	if (m->fail_write) {
		m->late = slot;
		return -ETIMEDOUT;
	}
	m->hw[slot] = m->staged;
	return 0;
}

static int drain(void *ctx)
{
	struct fe_model *m = ctx;

	m->drains++;
	if (m->fail_drain)
		return -ETIMEDOUT;
	if (m->late) {
		m->hw[m->late] = m->staged;
		m->late = 0;
	}
	return 0;
}

static const struct airoha_ct_gre4_io io = { write_row, drain, &fe };

struct flow_model { int err, calls; };
static int retire(void *ctx)
{
	struct flow_model *f = ctx;

	f->calls++;
	return f->err;
}

#define CHECK(expr) do { if (!(expr)) return __LINE__; } while (0)
#define GET(n, r) airoha_ct_gre4_get(&pool, &refs[n], &(r), &io)
#define PUT(n) airoha_ct_gre4_put(&refs[n], &io, retire, &flow)
#define RECOVER() airoha_ct_gre4_recover(&pool, &io)

int gre4_lifetime_test(void);
int gre4_lifetime_test(void)
{
	struct airoha_ct_gre4_row a = { .words = { 1 } }, b, zero = {};
	struct flow_model flow = {};
	int i, w, calls;

	memset(&fe, 0, sizeof(fe));
	memset(&pool, 0, sizeof(pool));
	memset(refs, 0, sizeof(refs));
	CHECK(GET(0, a) == -ENOSPC && !fe.writes);
	pool.owned = BIT(0) | BIT(31);
	CHECK(!GET(0, a) && refs[0].slot == 32 && !memcmp(&a, &fe.hw[32], sizeof(a)));
	CHECK(GET(0, a) == -EALREADY && fe.writes == 1);
	CHECK(!GET(1, a) && refs[1].slot == 32 && fe.writes == 1);
	CHECK(!PUT(0) && fe.writes == 1);
	CHECK(PUT(0) == -ENOENT && flow.calls == 1);
	for (i = 0; i < ARRAY_SIZE(a.words); i++) {
		b = a;
		b.words[i] ^= BIT(10);
		CHECK(!GET(2, b) && refs[2].slot == 63 && !memcmp(&b, &fe.hw[63], sizeof(b)));
		CHECK(GET(0, zero) == -ENOSPC);
		CHECK(!PUT(2) && !memcmp(&zero, &fe.hw[63], sizeof(zero)));
	}
	w = fe.writes;
	flow.err = -ETIMEDOUT;
	CHECK(PUT(1) == -ETIMEDOUT && refs[1].pool && !refs[1].retired && fe.writes == w);
	CHECK(!memcmp(&a, &fe.hw[32], sizeof(a)));
	flow.err = 0;
	fe.fail_write = true;
	CHECK(PUT(1) == -ETIMEDOUT && refs[1].retired && fe.late == 32);
	calls = flow.calls;
	CHECK(PUT(1) == -EAGAIN && flow.calls == calls);
	CHECK(GET(0, a) == -EAGAIN && GET(2, b) == -EAGAIN);
	fe.fail_drain = true;
	CHECK(RECOVER() == -ETIMEDOUT && fe.writes == w + 1);
	fe.fail_drain = false;
	CHECK(RECOVER() == -ETIMEDOUT && fe.late == 32);
	CHECK(GET(0, a) == -EAGAIN);
	fe.fail_write = false;
	CHECK(!RECOVER() && !fe.late && fe.drains == 3 && !memcmp(&zero, &fe.hw[32], sizeof(zero)));
	CHECK(!GET(0, a) && refs[0].slot == 63);
	w = fe.writes;
	CHECK(!PUT(1) && flow.calls == calls && fe.writes == w);
	CHECK(!PUT(0));
	CHECK(!GET(1, a));
	fe.fail_write = true;
	CHECK(GET(0, b) == -ETIMEDOUT && !refs[0].pool && fe.late == 63);
	w = fe.writes;
	CHECK(GET(2, b) == -EAGAIN && PUT(1) == -EAGAIN && refs[1].retired);
	fe.fail_drain = true;
	CHECK(RECOVER() == -ETIMEDOUT && fe.writes == w);
	fe.fail_drain = false;
	CHECK(RECOVER() == -ETIMEDOUT && fe.writes == w + 1);
	fe.fail_write = false;
	CHECK(!RECOVER() && !memcmp(&zero, &fe.hw[63], sizeof(zero)));
	CHECK(!memcmp(&a, &fe.hw[32], sizeof(a)) && !PUT(1));
	/* Start a new ownership epoch only after every old reference has gone. */
	pool.owned = U32_MAX;
	for (i = 0; i < 32; i++) {
		a.words[1] = i;
		CHECK(!GET(i, a) && refs[i].slot == 32 + i);
	}
	a.words[1]++;
	CHECK(GET(32, a) == -ENOSPC);
	a.words[1] = 1;
	CHECK(!PUT(0) && !GET(32, a) && refs[32].slot == 33);
	CHECK(!PUT(32));
	for (i = 1; i < 32; i++)
		CHECK(!PUT(i));
	CHECK(!fe.forbidden && !fe.late);
	return 0;
}
