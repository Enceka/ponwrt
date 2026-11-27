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
static bool controller, handler, registers_saved, sent_current;
static u32 saved_registers[10], saved_ifc_desired, saved_vip;
static const u32 registers[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
static const char * const kind_names[] = { "ipv4", "ipv6", "arp", "vlan", "pppoe", "fragment", "short" };
static int received, last_error, probe_lock;
static u32 received_sequence, received_kind, received_length, received_msg0, received_msg1;
static unsigned int now_us, due_us, delivery_delay, corruption, attempts;
static unsigned int checks, parser_cases, mapping_rejections, receive_cases, owner_cases;
static unsigned int synchronization_calls, released, closed, unregistered, register_writes;
static bool receive_enabled, repair_packet;
static struct sk_buff *queued_packet;

static rx_handler_result_t receive(struct sk_buff **packet);

static void fixture_mapping(unsigned int service, bool enable)
{
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
    submissions++;
    if (transmit_error) {
        dev_kfree_skb_any(skb);
        return transmit_error;
    }
    queued_packet = skb;
    due_us = now_us + delivery_delay;
    return 0;
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
    device.eth = &ethernet;
    netdev.running = netdev.carrier = retained = opened = true;
    handler = controller = registers_saved = false;
    sequence = received_sequence = now_us = attempts = 0;
    received = last_error = transmit_error = 0;
    begin_calls = configure_calls = end_calls = submissions = 0;
    released = closed = unregistered = register_writes = 0;
    synchronization_calls = failure_phase = corruption = 0;
    awaiting = sent_current = allocation_failed = repair_packet = false;
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
        "send 0 ipv4 5", "send 0 ipv4 0 extra" };
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
        assert(!begin_calls && !submissions && retained && opened);
        mapping_rejections++;
    }
    reset();
    retained = false;
    command("map 0", -EINVAL);
    command("send-current ipv4", -EINVAL);
    retained = true;
    opened = false;
    command("map 0", -EINVAL);
    command("send-current ipv6", -EINVAL);
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
int main(void)
{
    parse_commands();
    owners();
    reject_mapping();
    marker_wait();
    cleanup_packet();
    printf("{\"passed\":true,\"commands\":%u,\"parser_cases\":%u,\"mapping_rejections\":%u,"
           "\"receive_cases\":%u,\"owner_cases\":%u}\n",
           checks, parser_cases, mapping_rejections, receive_cases, owner_cases);
    return 0;
}
