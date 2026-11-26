#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define BIT(n) (1u << (n))
#define AIROHA_PON_VID_ANY 0xffffu
#define VLAN_VID_MASK 0xfffu
#define VLAN_PRIO_MASK 0xe000u
#define VLAN_PRIO_SHIFT 13u
#define rcu_dereference(p) (p)
struct ethhdr { u8 macs[12]; u16 h_proto; };
struct vlan_ethhdr { u8 macs[12]; u16 h_vlan_proto, h_vlan_TCI, h_vlan_encapsulated_proto; };
struct sk_buff { u8 frame[22]; unsigned len, linear; bool tag; u16 tci; };
#define skb_vlan_tag_present(s) ((s)->tag)
#define skb_vlan_tag_get_id(s) ((s)->tci & VLAN_VID_MASK)
#define skb_vlan_tag_get_prio(s) ((s)->tci >> VLAN_PRIO_SHIFT)
#define eth_type_vlan(t) ((t) == htons(0x8100) || (t) == htons(0x88a8))
struct airoha_pon_flow_entry { u16 vlan_id; u8 pbit_mask; u32 tag; };
struct airoha_pon_flow_table { unsigned count; struct airoha_pon_flow_entry entries[2]; };
struct airoha_gdm_dev { struct airoha_pon_flow_table *pon_flow_table; };
static const void *skb_header_pointer(struct sk_buff *s, unsigned off, unsigned len, void *copy)
{
    if (off + len > s->len) return NULL;
    if (off + len <= s->linear) return s->frame + off;
    return memcpy(copy, s->frame + off, len);
}
#include "tx_vlan.inc"

int main(void)
{
    const u32 exact = 0x8001abcd, fallback = 0x8002fefe;
    struct airoha_pon_flow_table table = {2, {{42, BIT(5), exact}, {AIROHA_PON_VID_ANY, 255, fallback}}};
    struct airoha_gdm_dev dev = {&table};
    const u16 tpids[] = {0x0800, 0x8100, 0x88a8};
    struct sk_buff truncated = {.len=14, .linear=14};
    truncated.frame[12] = 0x81;
    assert(!airoha_pon_select_flow(&dev, &truncated));
    for (unsigned proto = 0; proto < 3; proto++) {
        u16 tpid = htons(tpids[proto]);
        for (unsigned n = 0; n <= 22; n++) {
            for (unsigned linear = 0; linear <= n; linear++) {
                struct sk_buff skb = {.len=n, .linear=linear};
                u16 headers[] = {tpid, htons((5 << 13) | 42), htons(0x8100), htons(9), htons(0x0800)};
                memcpy(skb.frame + 12, headers, sizeof(headers));
                u32 tag = airoha_pon_select_flow(&dev, &skb);
                u32 want = n < 14 ? 0 : proto == 0 ? fallback : n < 18 ? 0 : exact;
                assert(tag == want);
                if (n == 22) {
                    /* A hardware-stripped outer tag precedes the in-band header. */
                    skb.tag = true; skb.tci = 9;
                    assert(airoha_pon_select_flow(&dev, &skb) == fallback);
                }
            }
        }
    }
    puts("PASS: complete and truncated PON TX VLAN headers, split and stripped tags");
}
