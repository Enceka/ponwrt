#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "loopback_constants.inc"

#if defined(__APPLE__) && !defined(s6_addr32)
#define s6_addr32 __u6_addr.__u6_addr32
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint16_t __be16;
#define BIT(index) (UINT32_C(1) << (index))
#define U16_MAX UINT16_MAX
#define ETH_HLEN 14
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_ARP 0x0806
#define ETH_P_8021Q 0x8100
#define ETH_P_PPP_SES 0x8864
#define VLAN_HLEN 4
#define NET_IP_ALIGN 2
#define ARPHRD_ETHER 1
#define ARPOP_REQUEST 1
#define IP_MF 0x2000
#define CHECKSUM_NONE 0
#define CSUM_MANGLED_0 0xffff
#define WRITE_ONCE(value, next) ((value) = (next))
#define smp_store_release(address, value) (*(address) = (value))
#define read_poll_timeout(reader, value, condition, delay, timeout, sleep, pointer) \
	({ (value) = reader(pointer); (condition) ? 0 : -ETIMEDOUT; })

struct ethhdr { u8 h_dest[6], h_source[6]; __be16 h_proto; };
struct iphdr {
	u8 ihl : 4, version : 4;
	u8 tos;
	u16 tot_len, id, frag_off;
	u8 ttl, protocol;
	u16 check;
	u32 saddr, daddr;
};
struct ipv6hdr {
	u8 priority : 4, version : 4;
	u8 flow_label[3];
	u16 payload_len;
	u8 nexthdr, hop_limit;
	struct in6_addr saddr, daddr;
};
struct udphdr { u16 source, dest, len, check; };
struct net_device { u8 dev_addr[6]; };
struct airoha_gdm_dev { int pon_tx_pending; };
struct sk_buff {
	u8 *storage, *data;
	unsigned int capacity, len, network, transport;
	u16 protocol;
	int ip_summed;
	struct net_device *dev;
};

static struct net_device netdev;
static struct airoha_gdm_dev device;
static struct net_device *probe_netdev = &netdev;
static struct airoha_gdm_dev *probe_dev = &device;
static bool retained, opened, awaiting, configured, mapping_enable;
static bool allocation_failed;
static unsigned int mapping_service, mapped_service, mapping_phase, failure_phase;
static unsigned int begin_calls, configure_calls, end_calls, submissions, allocation_count;
static unsigned int mapping_cases, transmit_cases, failure_cases;
static u32 sequence, probe_cookie = 0x10203040, sent_kind, sent_length, sent_variant;
static int transmit_error;

static int airoha_eth_pon_update_begin(struct net_device *dev, unsigned int channels)
{
	assert(dev == probe_netdev && channels == BIT(0));
	begin_calls++;
	mapping_phase = 1;
	return failure_phase == 1 ? -ETIMEDOUT : 0;
}

static int airoha_eth_pon_configure(struct net_device *dev, unsigned int channel,
				    unsigned int service, bool enable)
{
	assert(dev == probe_netdev && !channel && service <= U16_MAX && mapping_phase == 1);
	configure_calls++;
	mapping_phase = 2;
	mapping_service = service;
	mapping_enable = enable;
	return failure_phase == 2 ? -ETIMEDOUT : 0;
}

static int airoha_eth_pon_update_end(struct net_device *dev)
{
	assert(dev == probe_netdev && mapping_phase == 2);
	end_calls++;
	mapping_phase = 3;
	if (failure_phase == 3)
		return -ETIMEDOUT;
	configured = mapping_enable;
	mapped_service = mapping_service;
	return 0;
}

static struct sk_buff *netdev_alloc_skb(struct net_device *dev, unsigned int size)
{
	struct sk_buff *skb;

	assert(dev == probe_netdev);
	if (allocation_failed)
		return NULL;
	skb = calloc(1, sizeof(*skb));
	assert(skb);
	skb->storage = calloc(1, size);
	assert(skb->storage);
	skb->data = skb->storage;
	skb->capacity = size;
	allocation_count++;
	return skb;
}

static void skb_reserve(struct sk_buff *skb, unsigned int count)
{
	assert(count <= skb->capacity);
	skb->data += count;
	skb->capacity -= count;
}

static u8 *skb_put_zero(struct sk_buff *skb, unsigned int count)
{
	assert(count <= skb->capacity);
	skb->len = count;
	return skb->data;
}

static void ether_addr_copy(u8 *destination, const u8 *source) { memcpy(destination, source, 6); }
static void eth_random_addr(u8 *address) { memset(address, 0x22, 6); }
static void skb_reset_mac_header(struct sk_buff *skb) { assert(skb->len); }
static void skb_set_network_header(struct sk_buff *skb, unsigned int offset) { skb->network = offset; }
static void skb_set_transport_header(struct sk_buff *skb, unsigned int offset) { skb->transport = offset; }
static struct iphdr *ip_hdr(struct sk_buff *skb) { return (void *)(skb->data + skb->network); }
static struct ipv6hdr *ipv6_hdr(struct sk_buff *skb) { return (void *)(skb->data + skb->network); }
static struct udphdr *udp_hdr(struct sk_buff *skb) { return (void *)(skb->data + skb->transport); }
static void ip_send_check(struct iphdr *header) { header->check = 0; }
static u32 csum_partial(const void *data, unsigned int size, u32 seed) { return seed; }
static u16 csum_ipv6_magic(const struct in6_addr *source, const struct in6_addr *destination,
			   unsigned int length, unsigned int protocol, u32 sum) { return 0; }
static int atomic_read(const int *value) { return *value; }
static void msleep(unsigned int milliseconds) { assert(milliseconds == 20); }
static int net_xmit_errno(int error) { return -EIO; }
static void put_unaligned_be16(u16 value, void *address) { value = htons(value); memcpy(address, &value, 2); }
static void put_unaligned_be32(u32 value, void *address) { value = htonl(value); memcpy(address, &value, 4); }

static int dev_queue_xmit(struct sk_buff *skb)
{
	u8 *marker = skb->data + (sent_kind == PROBE_ARP ? skb->network + 28 : skb->transport + 8);
	u32 expected[] = { PROBE_MAGIC, sequence, probe_cookie, sent_kind, sent_length };

	assert(configured && mapping_enable && skb->dev == probe_netdev && awaiting);
	assert(skb->len == sent_length);
	assert(marker + sizeof(expected) <= skb->data + skb->len);
	for (unsigned int index = 0; index < 5; index++) {
		u32 actual;

		memcpy(&actual, marker + 4 * index, sizeof(actual));
		assert(ntohl(actual) == expected[index]);
	}
	submissions++;
	free(skb->storage);
	free(skb);
	allocation_count--;
	return transmit_error;
}

#include "loopback_production.inc"

int main(void)
{
	const unsigned int services[] = { 0, 0x2134, 0xa134, 0xffff };

	retained = opened = true;
	for (unsigned int service = 0; service <= U16_MAX; service++) {
		assert(!mapping(service, true));
		assert(configured && mapped_service == service && mapping_enable);
		assert(!mapping(0, false));
		assert(!configured && !mapping_enable);
		mapping_cases += 2;
	}
	for (unsigned int index = 0; index < sizeof(services) / sizeof(services[0]); index++)
		for (unsigned int kind = 0; kind < PROBE_KIND_COUNT; kind++)
			for (unsigned int variant = 0; variant < (kind <= PROBE_IPV6 ? 5U : 1U); variant++) {
				unsigned int previous = submissions;

				assert(!transmit(services[index], kind, variant));
				assert(configured && mapped_service == services[index] && mapping_enable);
				assert(!awaiting && !allocation_count && previous + 1 == submissions);
				assert(sent_kind == kind && sent_variant == variant);
				transmit_cases++;
			}
	for (unsigned int phase = 1; phase <= 3; phase++) {
		unsigned int previous = submissions;

		assert(!mapping(0, true));
		failure_phase = phase;
		assert(transmit(0, PROBE_IPV4, 0) == -ETIMEDOUT);
		assert(previous == submissions && mapping_phase == phase && retained && opened);
		assert(configured && mapped_service == 0);
		assert(mapping(0, false) == -ETIMEDOUT);
		assert(configured && retained && opened);
		failure_phase = 0;
		assert(!mapping(0, false) && !configured);
		failure_cases += 2;
	}
	device.pon_tx_pending = 1;
	assert(transmit(0, PROBE_IPV6, 0) == -ETIMEDOUT);
	assert(configured && mapped_service == 0 && retained && opened && !awaiting);
	device.pon_tx_pending = 0;
	assert(!transmit(0, PROBE_IPV6, 0));
	transmit_error = 1;
	assert(transmit(0, PROBE_IPV4, 0) == -EIO);
	assert(configured && !awaiting && !allocation_count);
	transmit_error = 0;
	allocation_failed = true;
	assert(transmit(0, PROBE_IPV4, 0) == -ENOMEM);
	assert(configured && !allocation_count);
	allocation_failed = false;
	for (unsigned int state = 0; state < 6; state++) {
		unsigned int previous = begin_calls;

		retained = state != 0;
		opened = state != 1;
		assert(transmit(state == 2 ? 65536 : 0, state == 3 ? PROBE_KIND_COUNT :
				state == 4 ? PROBE_ARP : PROBE_IPV4, state == 4 ? 1 : state == 5 ? 5 : 0) == -EINVAL);
		assert(begin_calls == previous);
		failure_cases++;
	}
	assert(!mapping(0, false) && !configured);
	failure_cases += 3;
	printf("{\"passed\":true,\"mapping_cases\":%u,\"transmit_cases\":%u,\"failure_cases\":%u}\n",
	       mapping_cases, transmit_cases, failure_cases);
	return 0;
}
