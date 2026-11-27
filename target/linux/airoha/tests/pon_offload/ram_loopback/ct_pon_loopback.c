#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/ip.h>
#include <linux/of.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/unaligned.h>
#include <net/ip.h>
#include "airoha_eth.h"
#include "airoha_regs.h"

#define PROBE_MAGIC 0x4354504e
#define PROBE_BYTES 128
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
static u32 saved_ifc_desired, saved_vip;
static u32 saved_registers[10];
static u32 sequence;
static atomic_t received = ATOMIC_INIT(0);
static u32 received_sequence, received_msg0, received_msg1;
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

static rx_handler_result_t receive(struct sk_buff **packet)
{
	struct sk_buff *skb = *packet;
	u8 payload[8];

	if (skb->protocol != htons(ETH_P_IP) ||
	    skb_copy_bits(skb, sizeof(struct iphdr) + sizeof(struct udphdr),
			  payload, sizeof(payload)) ||
	    get_unaligned_be32(payload) != PROBE_MAGIC)
		return RX_HANDLER_PASS;
	WRITE_ONCE(received_sequence, get_unaligned_be32(payload + 4));
	WRITE_ONCE(received_msg0, READ_ONCE(probe_dev->pon_stats.last_rx_msg0));
	WRITE_ONCE(received_msg1, READ_ONCE(probe_dev->pon_stats.last_rx_msg1));
	atomic_inc(&received);
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

static int mapping(unsigned int service)
{
	int err;

	err = airoha_eth_pon_update_begin(probe_netdev, BIT(0));
	if (err)
		return err;
	err = airoha_eth_pon_configure(probe_netdev, 0, service, !!service);
	if (err)
		return err;
	return airoha_eth_pon_update_end(probe_netdev);
}

static int restore(void)
{
	struct airoha_eth *eth = probe_dev->eth;
	unsigned int index;
	u32 value;
	int err;

	if (!retained)
		return 0;
	if (READ_ONCE(eth->ct_ifc_pon_ready) || eth->ppe->ct_pon_ifc.saved_valid)
		return -EBUSY;
	if (opened) {
		netif_tx_disable(probe_netdev);
		netif_carrier_off(probe_netdev);
		err = mapping(0);
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
	if (retained || netif_running(probe_netdev) || probe_dev->pon_link_ops ||
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
	err = mapping(0x2134);
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

static int transmit(unsigned int service)
{
	struct sk_buff *skb;
	struct ethhdr *ethernet;
	struct iphdr *ipv4;
	struct udphdr *udp;
	u8 *payload;
	int pending, err;

	if (!retained || !opened || !service || service > U16_MAX)
		return -EINVAL;
	err = mapping(service);
	if (err)
		return err;
	skb = netdev_alloc_skb(probe_netdev, PROBE_BYTES + NET_IP_ALIGN);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, NET_IP_ALIGN);
	ethernet = skb_put_zero(skb, PROBE_BYTES);
	ether_addr_copy(ethernet->h_dest, probe_netdev->dev_addr);
	eth_random_addr(ethernet->h_source);
	ethernet->h_proto = htons(ETH_P_IP);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
	skb_set_transport_header(skb, ETH_HLEN + sizeof(*ipv4));
	ipv4 = ip_hdr(skb);
	ipv4->version = 4;
	ipv4->ihl = 5;
	ipv4->tot_len = htons(PROBE_BYTES - ETH_HLEN);
	ipv4->ttl = 32;
	ipv4->protocol = IPPROTO_UDP;
	ipv4->saddr = htonl(0xc0000201);
	ipv4->daddr = htonl(0xc0000202);
	ip_send_check(ipv4);
	udp = udp_hdr(skb);
	udp->source = htons(49152);
	udp->dest = htons(49153);
	udp->len = htons(PROBE_BYTES - ETH_HLEN - sizeof(*ipv4));
	payload = (u8 *)(udp + 1);
	put_unaligned_be32(PROBE_MAGIC, payload);
	put_unaligned_be32(++sequence, payload + 4);
	skb->protocol = htons(ETH_P_IP);
	skb->ip_summed = CHECKSUM_NONE;
	skb->dev = probe_netdev;
	err = dev_queue_xmit(skb);
	if (err)
		return net_xmit_errno(err);
	err = read_poll_timeout(atomic_read, pending, !pending, 1000, 100000,
				false, &probe_dev->pon_tx_pending);
	msleep(20);
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
	char command[40], trailing;
	unsigned int service;
	int err;

	if (!length || length >= sizeof(command) || copy_from_user(command, buffer, length))
		return -EINVAL;
	command[length] = 0;
	mutex_lock(&probe_lock);
	if (sysfs_streq(command, "prepare"))
		err = prepare();
	else if (sysfs_streq(command, "restore"))
		err = restore();
	else if (sscanf(command, "send %u %c", &service, &trailing) == 1)
		err = transmit(service);
	else
		err = -EINVAL;
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
