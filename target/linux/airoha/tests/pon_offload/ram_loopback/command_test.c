#include "loopback_fixture.inc"

#define READ_ONCE(value) (value)
#define smp_load_acquire(address) (*(address))
#define __user
#define AIROHA_PON_VID_ANY 0xffff
#define AIROHA_PON_QDMA_VALID BIT(31)
#define AIROHA_PON_QDMA_EPON BIT(30)
#define AIROHA_PON_QDMA_GEM_MASK 0xffffU
#define AIROHA_PON_QDMA_PBIT_MASK 0x1fe00000U
#define FIELD_PREP(mask, value) (((u32)(value) << __builtin_ctz(mask)) & (mask))
#define LPBK_EN_MASK BIT(0)
#define REG_GDM_LPBK_CFG(port) 3U
#define REG_FE_VIP_PORT_EN 10U
#define REG_FE_IFC_PORT_EN 11U
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define THIS_MODULE NULL
#define VLAN_PRIO_SHIFT 13
#define NETDEV_TX_OK 0
#define NETDEV_TX_BUSY 1
typedef int netdev_tx_t;
struct netdev_queue { int dummy; };
struct airoha_pon_flow_config {
    u16 tcont;
    u16 gem_id;
    u16 vlan_id;
    u8 pbit_mask;
};

#ifdef __APPLE__
typedef off_t loff_t;
#endif
typedef enum { RX_HANDLER_PASS, RX_HANDLER_CONSUMED } rx_handler_result_t;
struct file {};
struct airoha_pon_flow_entry { u16 vlan_id; u8 pbit_mask; u32 tag; };
struct airoha_pon_flow_table { u32 count; struct airoha_pon_flow_entry entries[2]; };
struct airoha_ppe { void *ct_npu_owner; struct { bool saved_valid; } ct_pon_ifc; };
struct airoha_eth {
    struct airoha_ppe *ppe;
    bool ct_ifc_pon_ready;
    u32 ifc_port_desired, ct_ifc_port_mask, registers[16];
    int ct_route_lock, ifc_port_lock;
};

static struct airoha_ppe ppe;
static struct airoha_eth ethernet = { .ppe = &ppe };
static struct airoha_pon_flow_table table;
static struct airoha_pon_flow_table pending_pair;
static bool pair_pending;
static bool controller, handler, registers_saved, sent_current, sent_fixed, sent_alt, sent_wait_rx;
static bool mapped_alt_configured;
static u32 mapped_alt_service;
static u16 last_vlan_tci;
static bool last_vlan_tagged, alt_xmit_busy;
static struct netdev_queue dummy_txq;
static u32 saved_registers[10], saved_ifc_desired, saved_vip;
static const u32 registers[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
static const char * const kind_names[] = { "ipv4", "ipv6", "arp", "vlan", "pppoe", "fragment", "short" };
static int received, last_error, probe_lock;
static u32 received_sequence, received_kind, received_length, received_msg0, received_msg1;
static unsigned int now_us, due_us, delivery_delay, corruption, attempts;
static unsigned int checks, parser_cases, mapping_rejections, receive_cases, owner_cases;
static unsigned int fixed_cases, tx_only_cases, failure_checks;
static unsigned int synchronization_calls, released, closed, unregistered, register_writes;
static unsigned int tx_delay, tx_due_us, last_frame_length;
static u8 last_frame[PROBE_MAX_BYTES];
static bool receive_enabled, repair_packet, tx_in_flight, copy_failed;
static struct sk_buff *queued_packet;

static rx_handler_result_t receive(struct sk_buff **packet);

static void fixture_mapping(unsigned int service, bool enable)
{
    if (pair_pending && enable) {
        table = pending_pair;
        device.pon_flow_table = &table;
        pair_pending = false;
        return;
    }
    pair_pending = false;
    table.count = enable ? 1 : 0;
    table.entries[0] = (struct airoha_pon_flow_entry) {
        .vlan_id = AIROHA_PON_VID_ANY,
        .pbit_mask = 0xff,
        .tag = AIROHA_PON_QDMA_VALID | service | FIELD_PREP(AIROHA_PON_QDMA_PBIT_MASK, 0xff),
    };
    device.pon_flow_table = enable ? &table : NULL;
}

static void mutex_lock(int *lock) { assert(!*lock); *lock = 1; }
static void mutex_unlock(int *lock) { assert(*lock); *lock = 0; }
#define spin_lock_bh mutex_lock
#define spin_unlock_bh mutex_unlock
static void rcu_read_lock(void) {}
static void rcu_read_unlock(void) {}
#define rcu_dereference(pointer) (pointer)
static bool netif_running(struct net_device *dev) { return dev->running; }
static bool netif_carrier_ok(struct net_device *dev) { return dev->carrier; }
static void netif_tx_disable(struct net_device *dev) { assert(dev == probe_netdev); }
static void netif_carrier_off(struct net_device *dev) { dev->carrier = false; }
static void rtnl_lock(void) {}
static void rtnl_unlock(void) {}
static void netdev_rx_handler_unregister(struct net_device *dev) { unregistered++; }
static void dev_close(struct net_device *dev) { closed++; dev->running = false; }
static void airoha_eth_pon_unregister_controller(struct net_device *dev, void *private) { unregistered++; }
static void module_put(void *module) { released++; }
static void synchronize_net(void) { synchronization_calls++; }
static u32 airoha_fe_rr(struct airoha_eth *eth, u32 reg) { return eth->registers[reg]; }
static void airoha_fe_wr(struct airoha_eth *eth, u32 reg, u32 value)
{
    register_writes++;
    eth->registers[reg] = value;
}
static int prepare(void) { return -EOPNOTSUPP; }
static bool sysfs_streq(const char *text, const char *expected)
{
    size_t length = strlen(expected);
    return !strncmp(text, expected, length) &&
        (!text[length] || (text[length] == '\n' && !text[length + 1]));
}
static int kstrtouint(const char *text, unsigned int base, unsigned int *value)
{
    char *end;
    unsigned long parsed;
    if (!*text || *text == '-') return -EINVAL;
    errno = 0;
    parsed = strtoul(text, &end, base);
    if (errno || *end || parsed > UINT32_MAX) return -EINVAL;
    *value = parsed;
    return 0;
}
static int copy_from_user(void *destination, const void *source, size_t bytes)
{
    if (copy_failed) return 1;
    memcpy(destination, source, bytes);
    return 0;
}
static void atomic_inc(int *value) { ++*value; }
static bool skb_vlan_tag_present(struct sk_buff *skb) { return false; }
static int skb_copy_bits(struct sk_buff *skb, unsigned int offset, void *out, unsigned int bytes)
{
    if (offset > skb->len || bytes > skb->len - offset) return -EINVAL;
    memcpy(out, skb->data + offset, bytes);
    return 0;
}
static u16 get_unaligned_be16(const void *address)
{
    u16 value;
    memcpy(&value, address, sizeof(value));
    return ntohs(value);
}
static u32 get_unaligned_be32(const void *address)
{
    u32 value;
    memcpy(&value, address, sizeof(value));
    return ntohl(value);
}
static void dev_kfree_skb_any(struct sk_buff *skb)
{
    free(skb->storage);
    free(skb);
    allocation_count--;
}
static void poll_tick(unsigned int microseconds)
{
    struct sk_buff *packet;
    u8 *marker;
    u32 saved_word = 0;
    now_us += microseconds;
    if (tx_in_flight && now_us >= tx_due_us) {
        device.pon_tx_pending = 0;
        tx_in_flight = false;
    }
    if (!receive_enabled || !queued_packet || now_us < due_us) return;
    packet = queued_packet;
    marker = packet->data + packet->transport + sizeof(struct udphdr);
    if (corruption) {
        memcpy(&saved_word, marker + corruption * 4, sizeof(saved_word));
        put_unaligned_be32(get_unaligned_be32(marker + corruption * 4) + 1,
                          marker + corruption * 4);
    }
    packet->data += ETH_HLEN;
    packet->len -= ETH_HLEN;
    attempts++;
    if (receive(&packet) == RX_HANDLER_CONSUMED) {
        queued_packet = NULL;
    } else {
        packet->data -= ETH_HLEN;
        packet->len += ETH_HLEN;
        if (corruption) memcpy(marker + corruption * 4, &saved_word, sizeof(saved_word));
        if (repair_packet) corruption = 0;
        due_us = now_us + delivery_delay;
    }
}
static void msleep(unsigned int milliseconds)
{
    assert(milliseconds == 20);
    poll_tick(milliseconds * 1000);
}
#undef read_poll_timeout
#define read_poll_timeout(reader, value, condition, delay, timeout, sleep, pointer) \
    ({ unsigned int elapsed = 0; int result; \
       for (;;) { (value) = reader(pointer); if (condition) { result = 0; break; } \
           if (elapsed >= (timeout)) { result = -ETIMEDOUT; break; } \
           poll_tick(delay); elapsed += (delay); } result; })

static int dev_queue_xmit(struct sk_buff *skb)
{
    assert(!queued_packet && configured && awaiting && skb->dev == probe_netdev);
    assert(skb->len <= sizeof(last_frame));
    last_frame_length = skb->len;
    memcpy(last_frame, skb->data, skb->len);
    submissions++;
    if (transmit_error) {
        dev_kfree_skb_any(skb);
        return transmit_error;
    }
    queued_packet = skb;
    due_us = now_us + delivery_delay;
    if (tx_delay) {
        device.pon_tx_pending = 1;
        tx_due_us = now_us + tx_delay;
        tx_in_flight = true;
    }
    return 0;
}

static int airoha_eth_pon_replace_flows(struct net_device *dev,
                                        const struct airoha_pon_flow_config *flows,
                                        size_t count)
{
    assert(dev == probe_netdev && count == 2 && mapping_phase == 1);
    configure_calls++;
    mapping_phase = 2;
    if (failure_phase == 2)
        return -ETIMEDOUT;
    mapping_service = flows[0].gem_id;
    mapping_enable = true;
    pending_pair.count = count;
    for (size_t index = 0; index < count; index++) {
        pending_pair.entries[index].vlan_id = flows[index].vlan_id;
        pending_pair.entries[index].pbit_mask = flows[index].pbit_mask;
        pending_pair.entries[index].tag = AIROHA_PON_QDMA_VALID |
            FIELD_PREP(AIROHA_PON_QDMA_GEM_MASK, flows[index].gem_id) |
            FIELD_PREP(AIROHA_PON_QDMA_PBIT_MASK, flows[index].pbit_mask);
    }
    pair_pending = true;
    return 0;
}

static struct netdev_queue *netdev_get_tx_queue(struct net_device *dev, unsigned int index)
{
    assert(dev == probe_netdev && index == 0);
    return &dummy_txq;
}
static void skb_set_queue_mapping(struct sk_buff *skb, u16 mapping) { assert(mapping == 0); }
static void __vlan_hwaccel_put_tag(struct sk_buff *skb, __be16 proto, u16 tci)
{
    assert(proto == htons(ETH_P_8021Q));
    last_vlan_tagged = true;
    last_vlan_tci = tci;
}
static void local_bh_disable(void) {}
static void local_bh_enable(void) {}
static int smp_processor_id(void) { return 0; }
static void HARD_TX_LOCK(struct net_device *dev, struct netdev_queue *txq, int cpu) { assert(txq == &dummy_txq); }
static void HARD_TX_UNLOCK(struct net_device *dev, struct netdev_queue *txq) { assert(txq == &dummy_txq); }
static netdev_tx_t netdev_start_xmit(struct sk_buff *skb, struct net_device *dev,
                                     struct netdev_queue *txq, bool more)
{
    assert(dev == probe_netdev && txq == &dummy_txq && !more);
    if (alt_xmit_busy)
        return NETDEV_TX_BUSY;
    assert(!dev_queue_xmit(skb));
    return NETDEV_TX_OK;
}

#include "loopback_production.inc"

static void cleanup_packet(void)
{
    if (queued_packet) dev_kfree_skb_any(queued_packet);
    queued_packet = NULL;
    assert(!allocation_count);
}
static void reset(void)
{
    cleanup_packet();
    memset(&device, 0, sizeof(device));
    memset(&ppe, 0, sizeof(ppe));
    memcpy(netdev.dev_addr, "\x02\x12\x34\x56\x78\x9a", ETH_ALEN);
    device.eth = &ethernet;
    netdev.running = netdev.carrier = retained = opened = true;
    handler = controller = registers_saved = false;
    sequence = received_sequence = now_us = attempts = 0;
    received = last_error = transmit_error = 0;
    begin_calls = configure_calls = end_calls = submissions = 0;
    released = closed = unregistered = register_writes = 0;
    synchronization_calls = failure_phase = corruption = 0;
    random_mac_calls = tx_delay = tx_due_us = last_frame_length = 0;
    probe_cookie = 0x10203040;
    awaiting = sent_current = allocation_failed = repair_packet = false;
    sent_fixed = sent_alt = sent_wait_rx = tx_in_flight = copy_failed = false;
    mapped_alt_configured = false;
    pair_pending = false;
    mapped_alt_service = 0;
    last_vlan_tagged = alt_xmit_busy = false;
    last_vlan_tci = 0;
    receive_enabled = true;
    delivery_delay = 40000;
    assert(!mapping(0, true));
    begin_calls = configure_calls = end_calls = 0;
}
static void command(const char *text, int expected)
{
    ssize_t result = command_write(NULL, text, strlen(text), NULL);
    assert(result == (expected ? expected : (ssize_t)strlen(text)));
    assert(last_error == expected && !probe_lock);
    checks++;
}
static void parse_commands(void)
{
    const char *invalid[] = { "", "\n", " \t", "map", "map -1", "map 65536",
        "map 4294967296", "map 0 trailing", "map 0 1", "map 0xg", "mapping 0",
        "send-current", "send-current arp", "send-current IPV4", "send-current ipv4 0",
        "send-current ipv6 extra", "send-currentipv4", "send 65536", "send 4294967295",
        "send 0 ipv4 5", "send 0 ipv4 256", "send 0 ipv4 0 extra",
        "send-fixed", "send-fixed ipv4", "send-fixed ipv4 0", "send-fixed ipv4 rx",
        "send-fixed arp 0 rx", "send-fixed IPV4 0 rx", "send-fixed ipv5 0 tx",
        "send-fixed ipv4 -1 rx", "send-fixed ipv4 5 rx", "send-fixed ipv4 +0 rx",
        "send-fixed ipv4 00 rx", "send-fixed ipv4 0x0 rx", "send-fixed ipv4 256 rx",
        "send-fixed ipv4 4294967296 rx", "send-fixed ipv4 1111111111111111 rx",
        "send-fixed ipv4 0 RX", "send-fixed ipv4 0 TX", "send-fixed ipv4 0 wait",
        "send-fixed ipv4 0 rx extra", "send-fixed ipv6 4 tx 0",
        "send-fixedipv4 0 rx", "send-fixed ipv4 0rx tx" };
    reset();
    for (unsigned int index = 0; index < ARRAY_SIZE(invalid); index++) {
        if (!*invalid[index]) {
            assert(command_write(NULL, invalid[index], 0, NULL) == -EINVAL);
        } else command(invalid[index], -EINVAL);
        parser_cases++;
    }
    assert(!begin_calls && !submissions);
    command("map 0\n", 0);
    command("map 0x8000", 0);
    assert(mapped_service == 0x8000 && mapping_current());
    command("map\t65535\n", 0);
    assert(mapped_service == 65535 && mapping_current());
    for (unsigned int phase = 1; phase <= 3; phase++) {
        reset();
        failure_phase = phase;
        command("map 17", -ETIMEDOUT);
        assert(mapped_service == 0 && retained && opened && device.pon_update_blocked);
        command("send-current ipv4", -ESTALE);
        command("send-fixed ipv4 0 rx", -ESTALE);
        command("send-fixed ipv6 4 tx", -ESTALE);
        assert(!submissions);
        failure_phase = 0;
        command("map 17", 0);
        assert(mapped_service == 17 && mapping_current());
    }
}
static void owners(void)
{
    reset();
    ppe.ct_npu_owner = &ppe;
    command("map 0", -EBUSY);
    command("send 0", -EBUSY);
    command("send 32768 ipv6 4", -EBUSY);
    command("restore", -EBUSY);
    assert(!begin_calls && !submissions && !released && !closed && !register_writes);
    assert(retained && opened);
    retained = opened = false;
    command("restore", -EBUSY);
    retained = opened = true;
    command("send-current ipv4", 0);
    assert(received == 1 && received_sequence == 1 && !begin_calls && ppe.ct_npu_owner == &ppe);
    ppe.ct_npu_owner = NULL;
    command("restore", 0);
    assert(!retained && !opened && !configured && released == 1 && closed == 1);
    owner_cases += 7;
}
static void reject_mapping(void)
{
    for (unsigned int scenario = 0; scenario < 13; scenario++) {
        reset();
        switch (scenario) {
        case 0: configured = false; break;
        case 1: device.pon_update_blocked = true; break;
        case 2: device.pon_qdma_tag = AIROHA_PON_QDMA_VALID | AIROHA_PON_QDMA_EPON; break;
        case 3: device.pon_flow_table = NULL; break;
        case 4: table.count = 0; break;
        case 5: table.count = 2; break;
        case 6: table.entries[0].tag |= AIROHA_PON_QDMA_EPON; break;
        case 7: table.entries[0].tag ^= 0x8000; break;
        case 8: table.entries[0].tag &= ~AIROHA_PON_QDMA_VALID; break;
        case 9: table.entries[0].vlan_id = 37; break;
        case 10: table.entries[0].pbit_mask = 1; break;
        case 11: netdev.running = false; break;
        case 12: netdev.carrier = false; break;
        }
        command("send-current ipv4", -ESTALE);
        command("send-fixed ipv4 0 rx", -ESTALE);
        command("send-fixed ipv6 4 tx", -ESTALE);
        assert(!begin_calls && !submissions && retained && opened);
        mapping_rejections += 3;
    }
    reset();
    retained = false;
    command("map 0", -EINVAL);
    command("send-current ipv4", -EINVAL);
    command("send-fixed ipv4 0 rx", -EINVAL);
    command("send-fixed ipv6 0 tx", -EINVAL);
    retained = true;
    opened = false;
    command("map 0", -EINVAL);
    command("send-current ipv6", -EINVAL);
    command("send-fixed ipv6 0 rx", -EINVAL);
    command("send-fixed ipv4 0 tx", -EINVAL);
    assert(!begin_calls && !submissions);
}
static void marker_wait(void)
{
    const char *families[] = { "send-current ipv4", "send-current ipv6" };
    for (unsigned int family = 0; family < ARRAY_SIZE(families); family++) {
        reset();
        for (unsigned int packet = 0; packet < 16; packet++) {
            command(families[family], 0);
            assert(received_sequence == packet + 1 && received == (int)packet + 1);
            assert(received_kind == family && received_length == 114 && sent_current);
            assert(!sent_fixed && sent_wait_rx && random_mac_calls == packet + 1);
            assert(!begin_calls && !awaiting && !queued_packet && !allocation_count);
            receive_cases++;
        }
        assert(now_us >= 16 * delivery_delay);
        for (unsigned int field = 1; field <= 4; field++) {
            reset();
            corruption = field;
            repair_packet = true;
            command(families[family], 0);
            assert(attempts == 2 && now_us == 80000 && received == 1 && !awaiting);
            receive_cases++;
            reset();
            corruption = field;
            command(families[family], -ETIMEDOUT);
            assert(!received && !awaiting && !begin_calls && synchronization_calls == 1);
            receive_cases++;
        }
    }
    reset();
    receive_enabled = false;
    command("send-current ipv4", -ETIMEDOUT);
    assert(now_us == 100000 && !awaiting && retained && opened);
    reset();
    device.pon_tx_pending = 1;
    command("send-current ipv6", -ETIMEDOUT);
    assert(!awaiting && !begin_calls && retained && opened);
    reset();
    allocation_failed = true;
    command("send-current ipv4", -ENOMEM);
    assert(!submissions && !begin_calls && !awaiting);
    reset();
    transmit_error = 1;
    command("send-current ipv4", -EIO);
    assert(!allocation_count && !begin_calls && !awaiting);
    reset();
    command("send 32768 ipv6 4", 0);
    assert(begin_calls == 1 && mapped_service == 32768 && sent_variant == 4 && !sent_current);
    cleanup_packet();
    command("send-current ipv6", 0);
    assert(begin_calls == 1 && sent_variant == 0 && received_sequence == sequence);
    receive_cases += 6;
}

static void check_frame(unsigned int family, unsigned int variant, bool fixed)
{
    const u8 source[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 1 };
    unsigned int transport = ETH_HLEN + (family == PROBE_IPV6 ? 40 : 20);
    const u8 *network = last_frame + ETH_HLEN;
    const u8 *udp = last_frame + transport;
    const u8 *marker = udp + 8;

    assert(last_frame_length == PROBE_BYTES && last_frame_length <= PROBE_MAX_BYTES);
    assert(!memcmp(last_frame, netdev.dev_addr, ETH_ALEN));
    if (fixed) {
        assert(!memcmp(last_frame + ETH_ALEN, source, ETH_ALEN) && !random_mac_calls);
    } else {
        for (unsigned int index = 0; index < ETH_ALEN - 1; index++)
            assert(last_frame[ETH_ALEN + index] == 0x22);
        assert(last_frame[2 * ETH_ALEN - 1] == random_mac_calls);
    }
    assert(get_unaligned_be16(last_frame + 12) ==
           (family == PROBE_IPV6 ? ETH_P_IPV6 : ETH_P_IP));
    if (family == PROBE_IPV6) {
        assert(network[0] == 0x60 && network[6] == IPPROTO_UDP && network[7] == 32);
        assert(get_unaligned_be16(network + 4) == PROBE_BYTES - transport);
        assert(get_unaligned_be32(network + 8) == 0x20010db8);
        assert(!get_unaligned_be32(network + 12) && !get_unaligned_be32(network + 16));
        assert(get_unaligned_be32(network + 20) == 1U + (variant == 1));
        assert(get_unaligned_be32(network + 24) == 0x20010db8);
        assert(!get_unaligned_be32(network + 28) && !get_unaligned_be32(network + 32));
        assert(get_unaligned_be32(network + 36) == 2U + (variant == 2));
    } else {
        assert(network[0] == 0x45 && network[9] == IPPROTO_UDP && network[8] == 32);
        assert(get_unaligned_be16(network + 2) == PROBE_BYTES - ETH_HLEN);
        assert(get_unaligned_be16(network + 4) == (u16)sequence);
        assert(!get_unaligned_be16(network + 6));
        assert(get_unaligned_be32(network + 12) == 0xc0000201U + (variant == 1));
        assert(get_unaligned_be32(network + 16) == 0xc0000202U + (variant == 2));
    }
    assert(get_unaligned_be16(udp) == (variant == 3 ? 49153 : 49152));
    assert(get_unaligned_be16(udp + 2) == (variant == 4 ? 49154 : 49153));
    assert(get_unaligned_be16(udp + 4) == PROBE_BYTES - transport);
    assert(get_unaligned_be32(marker) == PROBE_MAGIC);
    assert(get_unaligned_be32(marker + 4) == sequence);
    assert(get_unaligned_be32(marker + 8) == probe_cookie);
    assert(get_unaligned_be32(marker + 12) == family);
    assert(get_unaligned_be32(marker + 16) == PROBE_BYTES);
    assert(sent_variant == variant && sent_kind == family && sent_length == PROBE_BYTES);
}

static void fixed_matrix(void)
{
    const unsigned int services[] = { 0, 0x8000, 0xffff };
    char text[64];

    for (unsigned int service = 0; service < ARRAY_SIZE(services); service++)
        for (unsigned int family = PROBE_IPV4; family <= PROBE_IPV6; family++)
            for (unsigned int variant = 0; variant <= 4; variant++)
                for (unsigned int mode = 0; mode < 2; mode++) {
                    struct airoha_pon_flow_table saved_table;
                    u32 saved_tag;

                    reset();
                    assert(!mapping(services[service], true));
                    saved_table = table;
                    saved_tag = device.pon_qdma_tag;
                    begin_calls = configure_calls = end_calls = 0;
                    ppe.ct_npu_owner = &ppe;
                    netdev.dev_addr[5] += service + family;
                    tx_delay = 7000;
                    receive_enabled = mode == 0;
                    sequence = 42;
                    snprintf(text, sizeof(text), "send-fixed %s %u %s",
                             kind_names[family], variant, mode ? "tx" : "rx");
                    command(text, 0);
                    check_frame(family, variant, true);
                    assert(sent_current && sent_fixed && sent_wait_rx == !mode);
                    assert(sequence == 43 && submissions == 1 && !awaiting);
                    assert(now_us == (mode ? tx_delay : delivery_delay));
                    assert(!device.pon_tx_pending && !tx_in_flight);
                    assert(received == (mode ? 0 : 1));
                    assert(received_sequence == (mode ? 0 : sequence));
                    assert(!begin_calls && !configure_calls && !end_calls);
                    assert(!memcmp(&saved_table, &table, sizeof(table)));
                    assert(device.pon_qdma_tag == saved_tag && mapped_service == services[service]);
                    assert(ppe.ct_npu_owner == &ppe && !register_writes && !synchronization_calls);
                    fixed_cases++;
                    if (mode) tx_only_cases++;
                }
}

static void fixed_failures(void)
{
    char text[64];

    for (unsigned int family = PROBE_IPV4; family <= PROBE_IPV6; family++)
        for (unsigned int mode = 0; mode < 2; mode++) {
            snprintf(text, sizeof(text), "send-fixed %s 0 %s", kind_names[family], mode ? "tx" : "rx");
            reset();
            allocation_failed = true;
            command(text, -ENOMEM);
            assert(!submissions && !allocation_count && !sequence && !awaiting && !begin_calls);
            reset();
            transmit_error = 1;
            command(text, -EIO);
            assert(submissions == 1 && !allocation_count && !awaiting && !begin_calls);
            reset();
            receive_enabled = false;
            tx_delay = 101000;
            command(text, -ETIMEDOUT);
            assert(now_us == 100000 && device.pon_tx_pending && !awaiting);
            assert(synchronization_calls == 1 && retained && opened && !begin_calls);
            reset();
            sequence = UINT32_MAX;
            command(text, -EOVERFLOW);
            assert(sequence == UINT32_MAX && !submissions && !random_mac_calls && !begin_calls);
            assert(!awaiting && !allocation_count);
            reset();
            sequence = UINT32_MAX - 1;
            command(text, 0);
            assert(sequence == UINT32_MAX && submissions == 1 && !awaiting);
            cleanup_packet();
            command(text, -EOVERFLOW);
            assert(sequence == UINT32_MAX && submissions == 1 && !begin_calls);
            failure_checks += 6;
        }
}

static void fixed_wait(void)
{
    const char *families[] = { "send-fixed ipv4 0 rx", "send-fixed ipv6 4 rx" };

    for (unsigned int family = 0; family < ARRAY_SIZE(families); family++) {
        reset();
        receive_enabled = false;
        command(families[family], -ETIMEDOUT);
        assert(now_us == 100000 && !received && !awaiting && synchronization_calls == 1);
        receive_cases++;
        for (unsigned int field = 1; field <= 4; field++) {
            reset();
            corruption = field;
            command(families[family], -ETIMEDOUT);
            assert(now_us == 100000 && !received && !awaiting && synchronization_calls == 1);
            reset();
            corruption = field;
            repair_packet = true;
            command(families[family], 0);
            assert(attempts == 2 && now_us == 80000 && received == 1 && !awaiting);
            receive_cases += 2;
        }
    }
    reset();
    tx_delay = 100000;
    receive_enabled = false;
    command("send-fixed ipv4 0 tx", 0);
    assert(now_us == 100000 && !device.pon_tx_pending && !received && !awaiting);
    reset();
    tx_delay = 7000;
    command("send-fixed ipv4 0 tx", 0);
    assert(now_us == 7000 && !received && !attempts && !awaiting);
    poll_tick(delivery_delay);
    assert(!received && attempts == 1 && queued_packet && !awaiting);
    reset();
    tx_delay = 50000;
    command("send-fixed ipv6 0 tx", 0);
    assert(now_us == 50000 && received == 1 && !awaiting && !queued_packet);
    reset();
    tx_delay = 100000;
    delivery_delay = 200000;
    command("send-fixed ipv4 0 rx", 0);
    assert(now_us == 200000 && received_sequence == sequence && !awaiting);
    tx_only_cases += 3;
    receive_cases++;
}

static void command_boundaries(void)
{
    char text[64];
    const char embedded_nul[] = "send-fixed ipv4 0 tx\0 extra";

    reset();
    last_error = -EIO;
    assert(command_write(NULL, embedded_nul, sizeof(embedded_nul) - 1, NULL) == -EINVAL);
    assert(last_error == -EIO && !probe_lock && !submissions);
    memset(text, ' ', sizeof(text));
    memcpy(text, "send-fixed ipv4 0 tx", strlen("send-fixed ipv4 0 tx"));
    assert(command_write(NULL, text, sizeof(text), NULL) == -EINVAL);
    assert(last_error == -EIO && !probe_lock && !submissions);
    text[sizeof(text) - 1] = 0;
    copy_failed = true;
    assert(command_write(NULL, text, strlen(text), NULL) == -EINVAL);
    assert(last_error == -EIO && !probe_lock && !submissions);
    copy_failed = false;
    command(text, 0);
    assert(submissions == 1 && sent_fixed && !sent_wait_rx);
    cleanup_packet();
    command(" \tsend-fixed\tipv6\t4\trx\n", 0);
    assert(submissions == 2 && sent_fixed && sent_wait_rx);
    assert(!begin_calls && !random_mac_calls);
    parser_cases += 5;
}

static void legacy_random(void)
{
    reset();
    command("send-fixed ipv4 0 rx", 0);
    check_frame(PROBE_IPV4, 0, true);
    command("send 32768 ipv6 4", 0);
    check_frame(PROBE_IPV6, 4, false);
    assert(random_mac_calls == 1 && !sent_current && !sent_fixed && !sent_wait_rx);
    assert(begin_calls == 1 && configure_calls == 1 && end_calls == 1 && mapped_service == 32768);
    cleanup_packet();
    command("send-current ipv4", 0);
    check_frame(PROBE_IPV4, 0, false);
    assert(random_mac_calls == 2 && sent_current && !sent_fixed && sent_wait_rx);
    assert(received_sequence == sequence && !awaiting && begin_calls == 1);
    command("send-current ipv6", 0);
    check_frame(PROBE_IPV6, 0, false);
    assert(random_mac_calls == 3 && !sent_fixed && sent_wait_rx);
    assert(received_sequence == sequence && !awaiting && begin_calls == 1);
}

static void pair_and_alt(void)
{
    reset();
    command("map-pair 0 0", -EINVAL);
    command("map-pair 0 65536", -EINVAL);
    command("send-fixed-alt ipv4 0 rx", -EINVAL);
    command("map-pair 0 1", 0);
    assert(mapped_alt_configured && mapped_service == 0 && mapped_alt_service == 1);
    assert(mapping_current());
    table.entries[0].tag ^= 1;
    command("send-fixed-alt ipv4 0 rx", -ESTALE);
    table.entries[0].tag ^= 1;
    table.entries[1].tag ^= 1;
    command("send-fixed-alt ipv4 0 rx", -ESTALE);
    table.entries[1].tag ^= 1;
    command("send-fixed-alt ipv4 00 rx", -EINVAL);
    command("send-fixed-alt ipv4 0 rx extra", -EINVAL);
    ppe.ct_npu_owner = (void *)1;
    command("map-pair 32768 32769", -EBUSY);
    ppe.ct_npu_owner = NULL;
    command("send-fixed-alt ipv4 0 rx", 0);
    assert(sent_fixed && sent_alt && sent_wait_rx && last_vlan_tagged &&
           last_vlan_tci == (7 << VLAN_PRIO_SHIFT));
    check_frame(PROBE_IPV4, 0, true);
    alt_xmit_busy = true;
    command("send-fixed-alt ipv4 0 rx", -EBUSY);
    alt_xmit_busy = false;
    command("map 0", 0);
    assert(!mapped_alt_configured && mapped_alt_service == 0);
    for (unsigned int phase = 1; phase <= 3; phase++) {
        reset();
        failure_phase = phase;
        command("map-pair 32768 32769", -ETIMEDOUT);
        assert(!mapped_alt_configured && device.pon_update_blocked);
        command("send-fixed-alt ipv4 0 rx", -ESTALE);
        assert(!submissions);
        failure_phase = 0;
        command("map-pair 32768 32769", 0);
        assert(mapping_current() && mapped_service == 32768 && mapped_alt_service == 32769);
    }
}

int main(void)
{
    parse_commands();
    owners();
    reject_mapping();
    marker_wait();
    fixed_matrix();
    fixed_failures();
    fixed_wait();
    command_boundaries();
    legacy_random();
    pair_and_alt();
    cleanup_packet();
    printf("{\"passed\":true,\"commands\":%u,\"parser_cases\":%u,\"mapping_rejections\":%u,"
           "\"receive_cases\":%u,\"owner_cases\":%u,\"fixed_cases\":%u,"
           "\"tx_only_cases\":%u,\"failure_checks\":%u}\n",
           checks, parser_cases, mapping_rejections, receive_cases, owner_cases,
           fixed_cases, tx_only_cases, failure_checks);
    return 0;
}
