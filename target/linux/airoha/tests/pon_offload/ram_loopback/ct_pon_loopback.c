#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/ipv6.h>
#include <linux/of.h>
#include <linux/random.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/unaligned.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include "airoha_eth.h"
#include "airoha_regs.h"

#define PROBE_MAGIC 0x4354504e
#define PROBE_BYTES 128
#define PROBE_MARKER_BYTES 20
#define PROBE_MAX_BYTES 130
#define PROBE_CURRENT_SERVICE (~0U)
#undef airoha_fe_rr
#undef airoha_fe_wr
#define airoha_fe_rr(eth, reg) readl((eth)->fe_regs + (reg))
#define airoha_fe_wr(eth, reg, value) writel((value), (eth)->fe_regs + (reg))

static DEFINE_MUTEX(probe_lock);
static struct dentry *probe_dir;
static struct net_device *probe_netdev;
static struct airoha_gdm_dev *probe_dev;
static bool retained, controller, opened, handler;
static bool registers_saved;
static bool configured, sent_current;
static u32 mapped_service;
static u32 saved_ifc_desired, saved_vip;
static u32 saved_registers[10];
static u32 sequence;
static atomic_t received = ATOMIC_INIT(0);
static u32 received_sequence, received_msg0, received_msg1;
enum probe_kind {
	PROBE_IPV4, PROBE_IPV6, PROBE_ARP, PROBE_VLAN, PROBE_PPPOE,
	PROBE_FRAGMENT, PROBE_SHORT, PROBE_KIND_COUNT,
};
static const char * const kind_names[] = {
	"ipv4", "ipv6", "arp", "vlan", "pppoe", "fragment", "short",
};
static u32 probe_cookie, sent_kind, sent_length, received_kind, received_length;
static u32 sent_variant;
static bool awaiting;
static int last_error;
static bool special_tag;
module_param(special_tag, bool, 0400);
static const u32 registers[] = {
	REG_GDM_FWD_CFG(2), REG_GDM_INGRESS_CFG(2), REG_GDM_LEN_CFG(2),
	REG_GDM_LPBK_CFG(2), REG_GDM_TXCHN_EN(2), REG_GDM_RXCHN_EN(2),
	0x1740, 0x1744, 0x1748, 0x174c,
};

static int controller_start(void *priv)
{
	struct airoha_eth *eth = probe_dev->eth;
	u32 value;
	int err;

	if (priv != probe_dev)
		return -EINVAL;
	spin_lock_bh(&eth->ct_route_lock);
	value = (airoha_fe_rr(eth, REG_GDM_FWD_CFG(2)) & ~GENMASK(15, 0)) | 0x5555;
	airoha_fe_wr(eth, REG_GDM_FWD_CFG(2), value);
	err = airoha_fe_rr(eth, REG_GDM_FWD_CFG(2)) == value ? 0 : -EIO;
	spin_unlock_bh(&eth->ct_route_lock);
	return err;
}

static void controller_stop(void *priv)
{
	WARN_ON(priv != probe_dev);
}

static const struct airoha_pon_link_ops controller_ops = {
	.start = controller_start,
	.stop = controller_stop,
};

static int marker_offset(struct sk_buff *skb, u32 kind)
{
	struct iphdr ipv4;
	struct ipv6hdr ipv6;
	struct udphdr udp;
	u8 header[28];
	unsigned int offset = 0, end = skb->len, transport_length;
	__be16 protocol = skb->protocol;
	bool tagged = skb_vlan_tag_present(skb), session = false;
	u16 fragment;

	if (protocol == htons(ETH_P_8021Q)) {
		if (skb_copy_bits(skb, 0, header, VLAN_HLEN) ||
		    get_unaligned_be16(header) != 37)
			return -EINVAL;
		protocol = htons(get_unaligned_be16(header + 2));
		offset = VLAN_HLEN;
		tagged = true;
	}
	if (tagged && kind != PROBE_VLAN)
		return -EINVAL;
	if (protocol == htons(ETH_P_PPP_SES)) {
		if (kind != PROBE_PPPOE ||
		    skb_copy_bits(skb, offset, header, 8) ||
		    header[0] != 0x11 || header[1] ||
		    get_unaligned_be16(header + 2) != 1 ||
		    get_unaligned_be16(header + 6) != 0x21 ||
		    get_unaligned_be16(header + 4) < 2 ||
		    get_unaligned_be16(header + 4) > end - offset - 6)
			return -EINVAL;
		end = offset + 6 + get_unaligned_be16(header + 4);
		offset += 8;
		protocol = htons(ETH_P_IP);
		session = true;
	}
	if (kind == PROBE_PPPOE && !session)
		return -EINVAL;
	if (protocol == htons(ETH_P_ARP)) {
		if (kind != PROBE_ARP || skb_copy_bits(skb, offset, header, sizeof(header)) ||
		    get_unaligned_be16(header) != ARPHRD_ETHER ||
		    get_unaligned_be16(header + 2) != ETH_P_IP ||
		    header[4] != ETH_ALEN || header[5] != 4 ||
		    get_unaligned_be16(header + 6) != ARPOP_REQUEST)
			return -EINVAL;
		return offset + sizeof(header);
	}
	if (protocol == htons(ETH_P_IPV6)) {
		if (kind != PROBE_IPV6 || end - offset < sizeof(ipv6) ||
		    skb_copy_bits(skb, offset, &ipv6, sizeof(ipv6)) ||
		    ipv6.version != 6 || ipv6.nexthdr != IPPROTO_UDP ||
		    ntohs(ipv6.payload_len) > end - offset - sizeof(ipv6))
			return -EINVAL;
		offset += sizeof(ipv6);
		transport_length = ntohs(ipv6.payload_len);
	} else if (protocol == htons(ETH_P_IP)) {
		if (kind == PROBE_IPV6 || kind == PROBE_ARP ||
		    end - offset < sizeof(ipv4) ||
		    skb_copy_bits(skb, offset, &ipv4, sizeof(ipv4)) ||
		    ipv4.version != 4 || ipv4.ihl != 5 || ipv4.protocol != IPPROTO_UDP ||
		    ntohs(ipv4.tot_len) < sizeof(ipv4) + sizeof(udp) + PROBE_MARKER_BYTES ||
		    ntohs(ipv4.tot_len) > end - offset)
			return -EINVAL;
		fragment = ntohs(ipv4.frag_off);
		if (fragment != (kind == PROBE_FRAGMENT ? IP_MF : 0) ||
		    (kind == PROBE_SHORT && ntohs(ipv4.tot_len) != 56))
			return -EINVAL;
		offset += sizeof(ipv4);
		transport_length = ntohs(ipv4.tot_len) - sizeof(ipv4);
	} else {
		return -EINVAL;
	}
	if (transport_length < sizeof(udp) + PROBE_MARKER_BYTES ||
	    skb_copy_bits(skb, offset, &udp, sizeof(udp)) ||
	    udp.source != (READ_ONCE(sent_variant) == 3 ? htons(49153) : htons(49152)) ||
	    udp.dest != (READ_ONCE(sent_variant) == 4 ? htons(49154) : htons(49153)) ||
	    ntohs(udp.len) != transport_length + (kind == PROBE_FRAGMENT ? 8 : 0))
		return -EINVAL;
	return offset + sizeof(udp);
}

static rx_handler_result_t receive(struct sk_buff **packet)
{
	struct sk_buff *skb = *packet;
	u8 payload[PROBE_MARKER_BYTES];
	u32 kind;
	int offset;

	if (!smp_load_acquire(&awaiting) || skb->len > PROBE_MAX_BYTES)
		return RX_HANDLER_PASS;
	kind = READ_ONCE(sent_kind);
	if (kind >= PROBE_KIND_COUNT)
		return RX_HANDLER_PASS;
	offset = marker_offset(skb, kind);
	if (offset < 0 || skb_copy_bits(skb, offset, payload, sizeof(payload)) ||
	    get_unaligned_be32(payload) != PROBE_MAGIC ||
	    get_unaligned_be32(payload + 4) != READ_ONCE(sequence) ||
	    get_unaligned_be32(payload + 8) != probe_cookie ||
	    get_unaligned_be32(payload + 12) != kind ||
	    get_unaligned_be32(payload + 16) != READ_ONCE(sent_length))
		return RX_HANDLER_PASS;
	WRITE_ONCE(received_kind, kind);
	WRITE_ONCE(received_length, skb->len);
	WRITE_ONCE(received_sequence, get_unaligned_be32(payload + 4));
	WRITE_ONCE(received_msg0, READ_ONCE(probe_dev->pon_stats.last_rx_msg0));
	WRITE_ONCE(received_msg1, READ_ONCE(probe_dev->pon_stats.last_rx_msg1));
	atomic_inc(&received);
	smp_store_release(&awaiting, false);
	dev_kfree_skb_any(skb);
	return RX_HANDLER_CONSUMED;
}

static int write_verified(struct airoha_eth *eth, u32 reg, u32 value)
{
	airoha_fe_wr(eth, reg, value);
	return airoha_fe_rr(eth, reg) == value ? 0 : -EIO;
}

static int eligible(void)
{
	struct airoha_eth *eth = probe_dev->eth;
	struct device_node *node;
	bool safe;

	if (!of_machine_is_compatible("fiberhome,hg5585f-ct") ||
	    !eth->ppe || !eth->ppe->ct_native_pairs || eth->ppe->ct_pon_qualified ||
	    eth->ct_cpu_fallback || eth->ct_ifc_cpu_port_failed ||
	    !of_property_read_bool(eth->dev->of_node, "airoha,connac2-ram-native-pairs") ||
	    probe_dev->port->id != AIROHA_GDM2_IDX || probe_dev->nbq ||
	    !test_bit(AIROHA_DEV_F_PON, &probe_dev->flags) ||
	    (airoha_fe_rr(eth, REG_GDM_FWD_CFG(2)) & GENMASK(15, 0)) != 0x5555 ||
	    FIELD_GET(SP_CPORT_MASK(2), airoha_fe_rr(eth, REG_SP_DFT_CPORT(0))) != 5)
		return -EPERM;
	node = of_find_node_by_path("/soc/system-controller@1fbf0200/pinctrl/ram-tx-disable-hog");
	safe = node && of_property_read_bool(node, "gpio-hog") &&
		of_property_read_bool(node, "output-high");
	of_node_put(node);
	if (!safe)
		return -EPERM;
	node = of_find_node_by_path("/soc/nand-controller@1fa11000");
	safe = node && !of_device_is_available(node);
	of_node_put(node);
	if (!safe)
		return -EPERM;
	node = of_find_node_by_path("/soc/ethernet@1fb64000");
	safe = node && !of_device_is_available(node);
	of_node_put(node);
	if (!safe)
		return -EPERM;
	for_each_compatible_node(node, NULL, "airoha,en7581-snand") {
		if (of_device_is_available(node)) {
			of_node_put(node);
			return -EPERM;
		}
	}
	return 0;
}

static int mapping(unsigned int service, bool enable)
{
	int err;

	err = airoha_eth_pon_update_begin(probe_netdev, BIT(0));
	if (err)
		return err;
	err = airoha_eth_pon_configure(probe_netdev, 0, service, enable);
	if (err)
		return err;
	err = airoha_eth_pon_update_end(probe_netdev);
	if (!err) {
		configured = enable;
		mapped_service = service;
	}
	return err;
}

static int map_service(unsigned int service)
{
	if (!retained || !opened || service > U16_MAX)
		return -EINVAL;
	if (READ_ONCE(probe_dev->eth->ppe->ct_npu_owner))
		return -EBUSY;
	return mapping(service, true);
}

static bool mapping_current(void)
{
	const struct airoha_pon_flow_table *table;
	bool matches;
	u32 tag;

	if (!configured || smp_load_acquire(&probe_dev->pon_update_blocked) ||
	    READ_ONCE(probe_dev->pon_qdma_tag) ||
	    !netif_running(probe_netdev) || !netif_carrier_ok(probe_netdev))
		return false;
	tag = AIROHA_PON_QDMA_VALID |
		FIELD_PREP(AIROHA_PON_QDMA_GEM_MASK, mapped_service) |
		FIELD_PREP(AIROHA_PON_QDMA_PBIT_MASK, 0xff);
	rcu_read_lock();
	table = rcu_dereference(probe_dev->pon_flow_table);
	matches = table && table->count == 1 &&
		table->entries[0].vlan_id == AIROHA_PON_VID_ANY &&
		table->entries[0].pbit_mask == 0xff && table->entries[0].tag == tag;
	rcu_read_unlock();
	return matches;
}

static int restore(void)
{
	struct airoha_eth *eth = probe_dev->eth;
	unsigned int index;
	u32 value;
	int err;

	if (READ_ONCE(eth->ppe->ct_npu_owner))
		return -EBUSY;
	if (!retained)
		return 0;
	if (READ_ONCE(eth->ct_ifc_pon_ready) || eth->ppe->ct_pon_ifc.saved_valid)
		return -EBUSY;
	if (opened) {
		netif_tx_disable(probe_netdev);
		netif_carrier_off(probe_netdev);
		err = mapping(0, false);
		if (err)
			return err;
	}
	if (registers_saved) {
		spin_lock_bh(&eth->ct_route_lock);
		err = write_verified(eth, REG_GDM_LPBK_CFG(2),
			airoha_fe_rr(eth, REG_GDM_LPBK_CFG(2)) & ~LPBK_EN_MASK);
		spin_unlock_bh(&eth->ct_route_lock);
		if (err)
			return err;
	}
	rtnl_lock();
	if (handler) {
		netdev_rx_handler_unregister(probe_netdev);
		handler = false;
	}
	if (opened) {
		dev_close(probe_netdev);
		opened = false;
	}
	rtnl_unlock();
	if (controller) {
		airoha_eth_pon_unregister_controller(probe_netdev, probe_dev);
		controller = false;
	}
	if (registers_saved) {
		spin_lock_bh(&eth->ct_route_lock);
		for (index = 0; index < ARRAY_SIZE(registers); index++) {
			if (index == 3)
				continue;
			err = write_verified(eth, registers[index], saved_registers[index]);
			if (err)
				goto unlock;
		}
		value = (airoha_fe_rr(eth, REG_FE_VIP_PORT_EN) & ~BIT(2)) | saved_vip;
		err = write_verified(eth, REG_FE_VIP_PORT_EN, value);
		if (err)
			goto unlock;
		spin_lock_bh(&eth->ifc_port_lock);
		eth->ifc_port_desired = (eth->ifc_port_desired & ~BIT(2)) | saved_ifc_desired;
		value = eth->ct_ifc_port_mask ? eth->ifc_port_desired & eth->ct_ifc_port_mask :
			eth->ifc_port_desired;
		err = write_verified(eth, REG_FE_IFC_PORT_EN, value);
		spin_unlock_bh(&eth->ifc_port_lock);
		if (!err)
			err = write_verified(eth, REG_GDM_LPBK_CFG(2), saved_registers[3]);
unlock:
		spin_unlock_bh(&eth->ct_route_lock);
		if (err)
			return err;
		registers_saved = false;
	}
	retained = false;
	module_put(THIS_MODULE);
	return 0;
}

static int prepare(void)
{
	struct airoha_eth *eth = probe_dev->eth;
	unsigned int index;
	u32 value;
	int err;

	err = eligible();
	if (err)
		return err;
	if (retained || READ_ONCE(eth->ppe->ct_npu_owner) ||
	    netif_running(probe_netdev) || probe_dev->pon_link_ops ||
	    eth->ppe->ct_pon_ifc.saved_valid || eth->pon_update_owner ||
	    rcu_access_pointer(probe_dev->pon_flow_table) || probe_dev->pon_qdma_tag ||
	    atomic_read(&probe_dev->pon_tx_pending) ||
	    (airoha_fe_rr(eth, REG_GDM_LPBK_CFG(2)) & LPBK_EN_MASK))
		return -EBUSY;
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
	retained = true;
	for (index = 0; index < ARRAY_SIZE(registers); index++)
		saved_registers[index] = airoha_fe_rr(eth, registers[index]);
	saved_ifc_desired = eth->ifc_port_desired & BIT(2);
	saved_vip = airoha_fe_rr(eth, REG_FE_VIP_PORT_EN) & BIT(2);
	registers_saved = true;
	err = airoha_eth_pon_register_controller(probe_netdev, &controller_ops, probe_dev);
	if (err)
		return err;
	controller = true;
	rtnl_lock();
	err = netdev_rx_handler_register(probe_netdev, receive, NULL);
	if (!err) {
		handler = true;
		err = dev_open(probe_netdev, NULL);
		if (!err)
			opened = true;
	}
	rtnl_unlock();
	if (err)
		return err;
	err = mapping(0x2134, true);
	if (err)
		return err;
	spin_lock_bh(&eth->ct_route_lock);
	err = write_verified(eth, REG_GDM_TXCHN_EN(2), saved_registers[4] | BIT(0));
	if (!err)
		err = write_verified(eth, REG_GDM_RXCHN_EN(2), saved_registers[5] | BIT(0));
	if (!err)
		err = write_verified(eth, REG_GDM_FWD_CFG(2),
			(saved_registers[0] & ~(GENMASK(15, 0) | GDM_STRIP_CRC_MASK)) | 0x5555);
	if (!err && special_tag) {
		u32 words[3] = { saved_registers[6], saved_registers[7], saved_registers[8] & ~BIT(31) };

		for (index = 0; index < 16; index++) {
			unsigned int group = index / 6, shift = index % 6 * 5;

			words[group] = (words[group] & ~(31U << shift)) | ((index + 16) << shift);
		}
		for (index = 0; index < ARRAY_SIZE(words) && !err; index++)
			err = write_verified(eth, 0x1740 + index * 4, words[index]);
		if (!err)
			err = write_verified(eth, 0x174c, (saved_registers[9] & ~15U) | 5);
	}
	value = (saved_registers[3] & ~(LPBK_CHAN_MASK | LPBK_MODE_MASK)) |
		LBK_GAP_MODE_MASK | LBK_LEN_MODE_MASK | LBK_CHAN_MODE_MASK | LPBK_EN_MASK;
	if (!err)
		err = write_verified(eth, REG_GDM_LPBK_CFG(2), value);
	spin_unlock_bh(&eth->ct_route_lock);
	if (!err) {
		netif_carrier_on(probe_netdev);
		netif_tx_wake_all_queues(probe_netdev);
	}
	return err;
}

static int transmit(unsigned int service, unsigned int kind, unsigned int variant)
{
	struct sk_buff *skb;
	struct ethhdr *ethernet;
	struct iphdr *ipv4;
	struct ipv6hdr *ipv6;
	struct udphdr *udp;
	u8 *payload, *frame;
	unsigned int length, network = ETH_HLEN, transport, udp_length;
	__be16 protocol = htons(ETH_P_IP);
	int pending, err;

	if (!retained || !opened ||
	    (service > U16_MAX && service != PROBE_CURRENT_SERVICE) || kind >= PROBE_KIND_COUNT ||
	    variant > 4 || (variant && kind != PROBE_IPV4 && kind != PROBE_IPV6))
		return -EINVAL;
	if (service != PROBE_CURRENT_SERVICE) {
		err = mapping(service, true);
		if (err)
			return err;
	}
	length = kind == PROBE_SHORT ? ETH_HLEN + 56 :
		 kind == PROBE_FRAGMENT ? PROBE_MAX_BYTES : PROBE_BYTES;
	skb = netdev_alloc_skb(probe_netdev, length + NET_IP_ALIGN);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, NET_IP_ALIGN);
	frame = skb_put_zero(skb, length);
	ethernet = (struct ethhdr *)frame;
	ether_addr_copy(ethernet->h_dest, probe_netdev->dev_addr);
	eth_random_addr(ethernet->h_source);
	if (kind == PROBE_VLAN) {
		protocol = htons(ETH_P_8021Q);
		put_unaligned_be16(37, frame + network);
		put_unaligned_be16(ETH_P_IP, frame + network + 2);
		network += VLAN_HLEN;
	} else if (kind == PROBE_PPPOE) {
		protocol = htons(ETH_P_PPP_SES);
		frame[network] = 0x11;
		put_unaligned_be16(1, frame + network + 2);
		put_unaligned_be16(length - network - 6, frame + network + 4);
		put_unaligned_be16(0x21, frame + network + 6);
		network += 8;
	} else if (kind == PROBE_IPV6) {
		protocol = htons(ETH_P_IPV6);
	} else if (kind == PROBE_ARP) {
		protocol = htons(ETH_P_ARP);
	}
	ethernet->h_proto = protocol;
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, network);
	if (kind == PROBE_ARP) {
		payload = frame + network;
		put_unaligned_be16(ARPHRD_ETHER, payload);
		put_unaligned_be16(ETH_P_IP, payload + 2);
		payload[4] = ETH_ALEN;
		payload[5] = 4;
		put_unaligned_be16(ARPOP_REQUEST, payload + 6);
		ether_addr_copy(payload + 8, ethernet->h_source);
		put_unaligned_be32(0xc0000201, payload + 14);
		put_unaligned_be32(0xc0000202, payload + 24);
		payload += 28;
		goto marker;
	}
	transport = network + (kind == PROBE_IPV6 ? sizeof(*ipv6) : sizeof(*ipv4));
	skb_set_transport_header(skb, transport);
	udp_length = length - transport;
	if (kind == PROBE_IPV6) {
		ipv6 = ipv6_hdr(skb);
		ipv6->version = 6;
		ipv6->payload_len = htons(udp_length);
		ipv6->nexthdr = IPPROTO_UDP;
		ipv6->hop_limit = 32;
		ipv6->saddr.s6_addr32[0] = htonl(0x20010db8);
		ipv6->saddr.s6_addr32[3] = htonl(1 + (variant == 1));
		ipv6->daddr.s6_addr32[0] = htonl(0x20010db8);
		ipv6->daddr.s6_addr32[3] = htonl(2 + (variant == 2));
	} else {
		ipv4 = ip_hdr(skb);
		ipv4->version = 4;
		ipv4->ihl = 5;
		ipv4->tot_len = htons(length - network);
		ipv4->id = htons(sequence + 1);
		ipv4->frag_off = htons(kind == PROBE_FRAGMENT ? IP_MF : 0);
		ipv4->ttl = 32;
		ipv4->protocol = IPPROTO_UDP;
		ipv4->saddr = htonl(0xc0000201 + (variant == 1));
		ipv4->daddr = htonl(0xc0000202 + (variant == 2));
		ip_send_check(ipv4);
	}
	udp = udp_hdr(skb);
	udp->source = variant == 3 ? htons(49153) : htons(49152);
	udp->dest = variant == 4 ? htons(49154) : htons(49153);
	udp->len = htons(udp_length + (kind == PROBE_FRAGMENT ? 8 : 0));
	payload = (u8 *)(udp + 1);
marker:
	put_unaligned_be32(PROBE_MAGIC, payload);
	put_unaligned_be32(++sequence, payload + 4);
	put_unaligned_be32(probe_cookie, payload + 8);
	put_unaligned_be32(kind, payload + 12);
	put_unaligned_be32(length, payload + 16);
	if (kind == PROBE_IPV6) {
		ipv6 = ipv6_hdr(skb);
		udp = udp_hdr(skb);
		udp->check = csum_ipv6_magic(&ipv6->saddr, &ipv6->daddr, udp_length,
					   IPPROTO_UDP, csum_partial(udp, udp_length, 0));
		if (!udp->check)
			udp->check = CSUM_MANGLED_0;
	}
	WRITE_ONCE(sent_kind, kind);
	WRITE_ONCE(sent_variant, variant);
	WRITE_ONCE(sent_length, length);
	smp_store_release(&awaiting, true);
	skb->protocol = protocol;
	skb->ip_summed = CHECKSUM_NONE;
	skb->dev = probe_netdev;
	err = dev_queue_xmit(skb);
	if (err) {
		smp_store_release(&awaiting, false);
		return net_xmit_errno(err);
	}
	err = read_poll_timeout(atomic_read, pending, !pending, 1000, 100000,
				false, &probe_dev->pon_tx_pending);
	if (service != PROBE_CURRENT_SERVICE)
		msleep(20);
	if (err || service != PROBE_CURRENT_SERVICE)
		smp_store_release(&awaiting, false);
	return err;
}

static int transmit_current(unsigned int kind)
{
	bool waiting;
	int err;

	if (!retained || !opened || (kind != PROBE_IPV4 && kind != PROBE_IPV6))
		return -EINVAL;
	if (!mapping_current())
		return -ESTALE;
	sent_current = true;
	err = transmit(PROBE_CURRENT_SERVICE, kind, 0);
	if (!err)
		err = read_poll_timeout(smp_load_acquire, waiting, !waiting,
					1000, 100000, false, &awaiting);
	smp_store_release(&awaiting, false);
	if (!err && READ_ONCE(received_sequence) != sequence)
		err = -EPROTO;
	if (err)
		synchronize_net();
	return err;
}

static int status_show(struct seq_file *file, void *unused)
{
	struct airoha_pon_datapath_stats stats;
	struct airoha_eth *eth = probe_dev->eth;
	unsigned int index;

	mutex_lock(&probe_lock);
	airoha_eth_pon_get_datapath_stats(probe_netdev, &stats);
	seq_printf(file, "retained=%u controller=%u opened=%u saved=%u error=%d pending=%d sequence=%u received=%d rx_sequence=%u rx_msg0=%08x rx_msg1=%08x\n",
		retained, controller, opened, registers_saved, last_error,
		atomic_read(&probe_dev->pon_tx_pending), sequence, atomic_read(&received),
		received_sequence, received_msg0, received_msg1);
	seq_printf(file, "tx_kind=%s tx_length=%u rx_kind=%s rx_length=%u\n",
		kind_names[READ_ONCE(sent_kind)], READ_ONCE(sent_length),
		kind_names[READ_ONCE(received_kind)], READ_ONCE(received_length));
	seq_printf(file, "tx_variant=%u\n", READ_ONCE(sent_variant));
	seq_printf(file, "configured=%u mapped_service=%u tx_current=%u npu_owner=%u\n",
		configured, mapped_service, sent_current,
		!!READ_ONCE(eth->ppe->ct_npu_owner));
	seq_printf(file, "submitted=%llu completed=%llu dropped=%llu no_mapping=%llu rx_data=%llu rx_delivered=%llu last_tx=%08x/%08x last_rx=%08x/%08x\n",
		stats.tx_packets_submitted, stats.tx_packets_completed, stats.tx_packets_hw_dropped,
		stats.tx_no_mapping, stats.rx_data_packets, stats.rx_packets_delivered,
		stats.last_tx_msg0, stats.last_tx_msg1, stats.last_rx_msg0, stats.last_rx_msg1);
	for (index = 0; index < ARRAY_SIZE(registers); index++)
		seq_printf(file, "%04x=%08x saved=%08x\n", registers[index],
			airoha_fe_rr(eth, registers[index]), saved_registers[index]);
	for (index = 0; index < AIROHA_NUM_RX_RING; index++) {
		struct airoha_queue *queue = &eth->qdma[1].q_rx[index];

		seq_printf(file, "rx%u head=%u tail=%u queued=%u\n", index,
			READ_ONCE(queue->head), READ_ONCE(queue->tail), READ_ONCE(queue->queued));
	}
	mutex_unlock(&probe_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(status);

static ssize_t command_write(struct file *file, const char __user *buffer,
			      size_t length, loff_t *offset)
{
	char command[64], operation[16] = {}, kind_name[16] = "ipv4", variant_word[16], trailing;
	unsigned int service, kind, variant = 0;
	int err, fields;

	if (!length || length >= sizeof(command) || copy_from_user(command, buffer, length))
		return -EINVAL;
	command[length] = 0;
	mutex_lock(&probe_lock);
	if (sysfs_streq(command, "prepare"))
		err = prepare();
	else if (sysfs_streq(command, "restore"))
		err = restore();
	else if (sscanf(command, "%15s", operation) == 1 && !strcmp(operation, "map")) {
		err = -EINVAL;
		if (sscanf(command, "%*s %15s %c", variant_word, &trailing) == 1 &&
		    !kstrtouint(variant_word, 0, &service))
			err = map_service(service);
	} else if (!strcmp(operation, "send-current")) {
		err = -EINVAL;
		if (sscanf(command, "%*s %15s %c", kind_name, &trailing) == 1) {
			if (!strcmp(kind_name, "ipv4"))
				err = transmit_current(PROBE_IPV4);
			else if (!strcmp(kind_name, "ipv6"))
				err = transmit_current(PROBE_IPV6);
		}
	} else {
		err = -EINVAL;
		fields = sscanf(command, "send %u %15s %15s %c", &service, kind_name, variant_word, &trailing);
		if (fields >= 1 && fields <= 3 && service <= U16_MAX &&
		    (fields < 3 || !kstrtouint(variant_word, 10, &variant))) {
			for (kind = 0; kind < PROBE_KIND_COUNT; kind++) {
				if (!strcmp(kind_name, kind_names[kind])) {
					if (READ_ONCE(probe_dev->eth->ppe->ct_npu_owner))
						err = -EBUSY;
					else {
						sent_current = false;
						err = transmit(service, kind, variant);
					}
					break;
				}
			}
		}
	}
	last_error = err;
	mutex_unlock(&probe_lock);
	return err ?: length;
}

static const struct file_operations command_fops = {
	.owner = THIS_MODULE,
	.write = command_write,
};

static int __init probe_init(void)
{
	int err;

	probe_netdev = dev_get_by_name(&init_net, "pon0");
	if (!probe_netdev)
		return -ENODEV;
	if (!probe_netdev->dev.parent ||
	    !of_device_is_compatible(probe_netdev->dev.parent->of_node, "airoha,en7581-eth")) {
		err = -ENODEV;
		goto release;
	}
	probe_dev = netdev_priv(probe_netdev);
	probe_cookie = get_random_u32();
	err = eligible();
	if (err)
		goto release;
	probe_dir = debugfs_create_dir("ct_pon_loopback", NULL);
	if (IS_ERR(probe_dir)) {
		err = PTR_ERR(probe_dir);
		goto release;
	}
	debugfs_create_file("status", 0400, probe_dir, NULL, &status_fops);
	debugfs_create_file("command", 0200, probe_dir, NULL, &command_fops);
	return 0;
release:
	dev_put(probe_netdev);
	return err;
}

static void __exit probe_exit(void)
{
	WARN_ON(retained || controller || opened || registers_saved);
	debugfs_remove_recursive(probe_dir);
	dev_put(probe_netdev);
}

module_init(probe_init);
module_exit(probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RAM-only HG5585F optical service loopback probe");
