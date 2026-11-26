#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint32_t u32;
typedef uint16_t u16;
#define BIT(n) (UINT32_C(1) << (n))
#define GENMASK(h,l) ((UINT32_MAX >> (31 - (h))) & (UINT32_MAX << (l)))
#define FIELD_GET(m,v) (((v) & (m)) >> __builtin_ctz(m))
#define AIROHA_DEV_F_PON 0
#define READ_ONCE(x) (x)
#define smp_load_acquire(p) (*(p))
#define test_bit(n,p) ((*(p) & BIT(n)) != 0)
#define netdev_from_priv(dev) (&(dev)->net)
struct airoha_pon_flow_table { unsigned count; struct { u32 tag; } entries[3]; };
struct ppe { int dev; };
struct eth { struct ppe *ppe; };
struct airoha_gdm_dev {
	struct eth *eth;
	int net;
	u32 flags, pon_qdma_tag;
	bool pon_update_blocked;
	struct airoha_pon_flow_table *pon_flow_table;
};
struct sk_buff { int *dev; bool nonlinear; };
#define skb_is_nonlinear(skb) ((skb)->nonlinear)
static unsigned readers, learns, cases;
static struct airoha_gdm_dev dev;
static struct sk_buff skb = { .dev = &dev.net };
#define rcu_read_lock() (++readers)
#define rcu_read_unlock() (--readers)
#define rcu_dereference(x) (assert(readers), (x))
static void airoha_ppe_check_skb(int *ppe, struct sk_buff *s, u32 hash, bool wlan)
{
	assert(ppe == &dev.eth->ppe->dev && s == &skb && hash == 123 && !wlan);
	assert(!dev.flags || readers == 1);
	learns++;
}
#include "production.h"

static void check(u32 msg, bool expected)
{
	unsigned before = learns;
	airoha_qdma_learn_skb(&dev, &skb, 123, msg);
	assert(!readers && learns == before + expected);
	cases++;
}

int main(void)
{
	struct ppe ppe = {0};
	struct eth eth = { &ppe };
	struct airoha_pon_flow_table table = { 3, {{0x8000a501}, {0x100}, {0x8000ffff}} };
	u32 msg = 0xa501u << 14;
	dev.eth = &eth;
	dev.flags = 1;
	check(msg, false);
	dev.pon_flow_table = &table;
	for (unsigned i = 0; i <= UINT16_MAX; i++)
		check(i << 14, i == 0xa501 || i == 0xffff);
	for (unsigned i = 0; i < 32; i++) {
		check(msg | i << 3, true);
		dev.pon_qdma_tag = 0xc0000000u | i << 16;
		for (unsigned j = 0; j < 32; j++) {
			check(j << 3, i == j);
			check(msg | j << 3, i == j);
		}
		dev.pon_qdma_tag &= ~BIT(31);
		check(msg | i << 3, false);
		dev.pon_qdma_tag = 0;
	}
	for (unsigned i = 0; i < 2; i++) {
		dev.pon_qdma_tag = i ? 0xc0000000u : 0;
		check(msg, true);
		check(msg | BIT(8), false);
		for (unsigned bit = 11; bit <= 13; bit++) check(msg | BIT(bit), false);
		dev.pon_update_blocked = true;
		check(msg, false);
		dev.pon_update_blocked = false;
		skb.nonlinear = true;
		check(msg, false);
		skb.nonlinear = false;
	}
	dev.pon_qdma_tag = 0;
	table.count = 0;
	check(msg, false);
	dev.flags = 0;
	skb.nonlinear = true;
	check(msg, true);
	skb.dev = NULL;
	check(msg, false);
	printf("%u QDMA RX learn cases passed\n", cases);
}
