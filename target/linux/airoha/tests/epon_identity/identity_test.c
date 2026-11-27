#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); exit(1); } } while (0)
#define BIT(bit) (UINT32_C(1) << (bit))
#define GENMASK(high, low) ((UINT32_MAX >> (31 - (high))) & (UINT32_MAX << (low)))
#define FIELD_GET(mask, value) (((u32)(value) & (mask)) >> __builtin_ctz(mask))
#define FIELD_PREP(mask, value) (((u32)(value) << __builtin_ctz(mask)) & (mask))
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))
#define AIROHA_DEV_F_PON 2
#define AIROHA_NUM_QOS_QUEUES 8
#define test_bit(bit, value) (!!(*(value) & BIT(bit)))
#define netdev_priv(netdev) ((netdev)->priv)
#include "masks.h"

struct mutex { bool held; };
struct airoha_pon_flow_table { unsigned int count; struct { u32 tag; } entries[2]; };
struct airoha_gdm_dev;
struct airoha_eth { struct mutex pon_config_lock; struct airoha_gdm_dev *pon_update_owner; };
struct airoha_gdm_dev {
    struct airoha_eth *eth;
    unsigned long flags;
    bool pon_update_ready;
    u32 pon_update_channels, pon_qdma_tag;
    struct airoha_pon_flow_table *pon_flow_table;
    struct { unsigned int tx_no_mapping; } pon_stats;
};
struct net_device { const void *netdev_ops; struct airoha_gdm_dev *priv; };
struct sk_buff { unsigned int unused; };
static const int airoha_netdev_ops, other_netdev_ops;
static struct mutex flow_offload_mutex;
static int retire_error;
static unsigned int retire_calls, sync_calls, free_calls;
static u32 expected_old_tag;

static void mutex_lock(struct mutex *lock)
{
    CHECK(!lock->held);
    if (lock != &flow_offload_mutex)
        CHECK(flow_offload_mutex.held);
    lock->held = true;
}

static void mutex_unlock(struct mutex *lock)
{
    CHECK(lock->held);
    lock->held = false;
}

#define lockdep_is_held(lock) ((lock)->held)
static struct airoha_pon_flow_table *replace_table(struct airoha_gdm_dev *dev,
                                                 struct airoha_pon_flow_table *table)
{
    struct airoha_pon_flow_table *old = dev->pon_flow_table;
    CHECK(flow_offload_mutex.held && dev->eth->pon_config_lock.held);
    CHECK(dev->pon_qdma_tag == expected_old_tag && !retire_error);
    dev->pon_flow_table = table;
    return old;
}
#define rcu_replace_pointer(target, table, held) (CHECK_HELD(held), replace_table(dev, table))
#define CHECK_HELD(condition) ((condition) ? (void)0 : abort())

static int airoha_ppe_remove_egress_flows(struct airoha_gdm_dev *dev)
{
    CHECK(flow_offload_mutex.held && dev->eth->pon_config_lock.held);
    CHECK(dev->pon_qdma_tag == expected_old_tag);
    retire_calls++;
    return retire_error;
}

static void synchronize_net(void)
{
    CHECK(!flow_offload_mutex.held);
    sync_calls++;
}

static void kfree(void *pointer)
{
    CHECK(!flow_offload_mutex.held);
    if (pointer)
        free_calls++;
}

static u32 airoha_pon_select_flow(struct airoha_gdm_dev *dev, struct sk_buff *skb)
{
    (void)dev;
    (void)skb;
    return 0;
}
#define atomic64_inc(counter) (++*(counter))
#include "api.h"
#include "production.h"
#include "tx.h"

static unsigned int publications;
static void publish(struct net_device *netdev, u8 channel, u16 llid, bool valid,
                    int expected_error)
{
    struct airoha_gdm_dev *dev = netdev->priv;
    struct airoha_pon_flow_table *old = dev->pon_flow_table;
    unsigned int before_sync = sync_calls;
    expected_old_tag = dev->pon_qdma_tag;
    CHECK(airoha_eth_pon_configure_epon(netdev, channel, llid, valid) == expected_error);
    CHECK(!flow_offload_mutex.held && !dev->eth->pon_config_lock.held);
    if (expected_error) {
        CHECK(dev->pon_qdma_tag == expected_old_tag && dev->pon_flow_table == old);
        CHECK(sync_calls == before_sync);
    } else {
        u32 expected = valid ? UINT32_C(0xc0000000) | (u32)channel << 16 | llid : 0;
        CHECK(dev->pon_qdma_tag == expected && !dev->pon_flow_table);
        CHECK(sync_calls == before_sync + 1);
        CHECK(airoha_pon_table_channels(NULL, expected) == (valid ? BIT(channel) : 0));
    }
    publications++;
}

int main(void)
{
    struct airoha_eth eth = {0};
    struct airoha_gdm_dev dev = {.eth = &eth, .flags = BIT(AIROHA_DEV_F_PON)};
    struct net_device netdev = {.netdev_ops = &airoha_netdev_ops, .priv = &dev};
    struct airoha_pon_flow_table previous = {.count = 1, .entries = {{0x80010001}}};
    int (*configure)(struct net_device *, u8, u16, bool) = airoha_eth_pon_configure_epon;
    CHECK(configure(NULL, 0, 1, true) == -EINVAL);
    netdev.netdev_ops = &other_netdev_ops;
    CHECK(configure(&netdev, 0, 1, true) == -EINVAL);
    netdev.netdev_ops = &airoha_netdev_ops;
    dev.flags = 0;
    CHECK(configure(&netdev, 0, 1, true) == -EOPNOTSUPP);
    dev.flags = BIT(AIROHA_DEV_F_PON);
    dev.pon_qdma_tag = 0xc0071234;
    dev.pon_flow_table = &previous;
    publish(&netdev, 7, 0xabcd, true, -EBUSY);
    eth.pon_update_owner = &dev;
    publish(&netdev, 7, 0xabcd, true, -EBUSY);
    dev.pon_update_ready = true;
    publish(&netdev, 7, 0xabcd, true, -EINVAL);
    dev.pon_update_channels = UINT32_MAX;
    for (unsigned int channel = 32; channel <= UINT8_MAX; channel++)
        publish(&netdev, channel, 0xffff, true, -ERANGE);
    CHECK(!retire_calls && !free_calls);
    retire_error = -EIO;
    publish(&netdev, 7, 0xabcd, true, -EIO);
    publish(&netdev, 255, 0xffff, false, -EIO);
    retire_error = 0;
    publish(&netdev, 7, 0xabcd, true, 0);
    CHECK(free_calls == 1);
    publish(&netdev, 7, 0x1234, true, 0);
    publish(&netdev, 255, 0xffff, false, 0);
    for (unsigned int channel = 0; channel < 32; channel++) {
        for (unsigned int llid = 0; llid <= UINT16_MAX; llid++)
            publish(&netdev, channel, llid, true, 0);
        publish(&netdev, channel, 0xffff, false, 0);
    }
    unsigned int tx_cases = 0;
    for (unsigned int channel = 0; channel < 32; channel++) {
        for (unsigned int sample = 0; sample < 18; sample++) {
            u16 llid = sample < 16 ? BIT(sample) : sample == 16 ? 0 : UINT16_MAX;
            publish(&netdev, channel, llid, true, 0);
            for (unsigned int queue = 0; queue < 8; queue++) {
                u32 message = UINT32_MAX;
                u8 nboq = 255;
                CHECK(encode_tx(&dev, queue, &message, &nboq) == 0);
                CHECK(message == (channel << 3 | queue) && nboq == channel);
                tx_cases++;
            }
        }
    }
    publish(&netdev, 0, 0, false, 0);
    u32 message = 0;
    u8 nboq = 0;
    CHECK(encode_tx(&dev, 0, &message, &nboq) == -ENOENT && dev.pon_stats.tx_no_mapping == 1);
    printf("PASS %u publication cases, %u CPU TX vectors, API signature and transaction failures\n",
           publications, tx_cases);
    return 0;
}
