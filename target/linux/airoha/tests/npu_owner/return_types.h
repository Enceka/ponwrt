#ifndef NPU_OWNER_RETURN_TEST_TYPES_H
#define NPU_OWNER_RETURN_TEST_TYPES_H

#include <stddef.h>
#include "npu_eth_return_abi.h"

#define AIROHA_ETH_RETURN_H
#define AIROHA_DEV_F_PON 1
#define AIROHA_GDM2_IDX 2
#define AIROHA_PON_QDMA_VALID (1U << 31)
#define AIROHA_PON_QDMA_EPON (1U << 30)
#define AIROHA_PON_QDMA_GEM_MASK 0xffffU
#define READ_ONCE(value) (value)
#define smp_load_acquire(pointer) (*(pointer))
#define smp_store_release(pointer, value) (*(pointer) = (value))
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
#define to_delayed_work(pointer) container_of(pointer, struct delayed_work, work)
#define msecs_to_jiffies(value) (value)
#define test_bit(bit, pointer) (!!(*(pointer) & (1UL << (bit))))
#define netdev_from_priv(pointer) (&(pointer)->netdev)
#define netif_running(pointer) ((pointer)->running)
#define netif_carrier_ok(pointer) ((pointer)->carrier)
#define INIT_DELAYED_WORK(pointer, callback) (*(pointer) = (struct delayed_work) { .function = callback })

struct device;
struct airoha_eth;
int airoha_ppe_npu_owner_close_locked(struct airoha_eth *eth);
struct er_config;
struct er_message;
struct airoha_er;
struct net_device { bool running, carrier; unsigned int references; };
struct work_struct { int unused; };
struct delayed_work {
    struct work_struct work;
    void (*function)(struct work_struct *);
    bool pending, running;
    unsigned long delay;
    unsigned int scheduled, cancelled;
};
struct airoha_qdma { int index; };
struct airoha_gdm_port { int id, sport; };
struct airoha_pon_flow_table {
    unsigned int count;
    struct { u32 tag; } entries[32];
};
struct airoha_gdm_dev {
    struct airoha_eth *eth;
    struct airoha_gdm_port *port;
    struct airoha_qdma *qdma;
    struct airoha_pon_flow_table *pon_flow_table;
    struct net_device netdev;
    unsigned long flags;
    u32 pon_qdma_tag;
    int nbq;
    bool pon_update_blocked;
};
struct airoha_er_ops {
    int (*command)(void *, struct er_message *);
    int (*quiesce)(void *);
    bool (*binding_matches)(void *, struct net_device *, const struct er_config *, u32);
    void (*fault)(void *, const struct er_config *, u32);
    bool (*access_revoked)(void *, const struct er_config *);
};
struct airoha_er {
    struct er_config config;
    struct net_device *lower;
    const struct airoha_er_ops *ops;
    void *ctx;
};

#endif
