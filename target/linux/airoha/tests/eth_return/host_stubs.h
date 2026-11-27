#ifndef ETH_RETURN_HOST_STUBS_H
#define ETH_RETURN_HOST_STUBS_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t __le32;
typedef uint64_t dma_addr_t;
typedef int64_t ktime_t;
typedef struct { bool held; } spinlock_t;

static inline void spin_lock_init(spinlock_t *lock) { lock->held = false; }
static inline void spin_lock_bh(spinlock_t *lock) { assert(!lock->held); lock->held = true; }
static inline void spin_unlock_bh(spinlock_t *lock) { assert(lock->held); lock->held = false; }

#define min_t(type, left, right) ((type)(left) < (type)(right) ? (type)(left) : (type)(right))

#define EIO 5
#define ENOMEM 12
#define EBUSY 16
#define EINVAL 22
#define ERANGE 34
#define EPROTO 71
#define EOPNOTSUPP 95
#define ETIMEDOUT 110
#define EINPROGRESS 115
#define GFP_KERNEL 0
#define NET_IP_ALIGN 2
#define CHECKSUM_NONE 0
#define NSEC_PER_MSEC 1000000
#define CLOCK_MONOTONIC 1
#define HRTIMER_MODE_REL 0
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define container_of(pointer, type, member) \
	((type *)((char *)(pointer) - offsetof(type, member)))
#define lower_32_bits(value) ((u32)(value))
#define upper_32_bits(value) ((u32)((u64)(value) >> 32))
#define READ_ONCE(value) (*(volatile __typeof__(value) *)&(value))
#define WRITE_ONCE(location, value) do { \
	__typeof__(location) host_value = (value); \
	host_record_write(&(location), (u64)host_value, sizeof(host_value)); \
	*(volatile __typeof__(location) *)&(location) = host_value; \
} while (0)

static inline u32 cpu_to_le32(u32 value)
{
#if defined(TEST_SWAPPED_ENDIAN) || __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return __builtin_bswap32(value);
#else
	return value;
#endif
}

static inline u32 le32_to_cpu(u32 value)
{
	return cpu_to_le32(value);
}

struct device {
	u32 identity;
};

struct net_device {
	u32 identity;
	unsigned int references;
};

struct napi_struct {
	struct net_device *dev;
	int (*poll)(struct napi_struct *napi, int budget);
	bool added, enabled, scheduled;
	unsigned int completions, schedules;
	int last_completed;
};

enum hrtimer_restart { HRTIMER_NORESTART, HRTIMER_RESTART };

struct hrtimer {
	enum hrtimer_restart (*function)(struct hrtimer *timer);
	bool active;
	ktime_t expires;
	unsigned int forwards;
};

struct sk_buff {
	u8 *head, *data;
	size_t capacity, len;
	struct net_device *dev;
	int ip_summed;
	u16 protocol;
};

void host_record_write(void *address, u64 value, size_t size);
void dma_rmb(void);
void dma_wmb(void);
void dma_mb(void);
void rcu_read_lock(void);
void rcu_read_unlock(void);
void *kzalloc(size_t size, int flags);
void kfree(void *pointer);
void *dma_alloc_coherent(struct device *dev, size_t bytes, dma_addr_t *dma, int flags);
void dma_free_coherent(struct device *dev, size_t bytes, void *pointer, dma_addr_t dma);
void dev_hold(struct net_device *dev);
void dev_put(struct net_device *dev);
void netif_napi_add(struct net_device *dev, struct napi_struct *napi,
		    int (*poll)(struct napi_struct *, int));
void netif_napi_del(struct napi_struct *napi);
void napi_enable(struct napi_struct *napi);
void napi_disable(struct napi_struct *napi);
void napi_schedule(struct napi_struct *napi);
bool napi_complete_done(struct napi_struct *napi, int done);
struct sk_buff *napi_alloc_skb(struct napi_struct *napi, unsigned int bytes);
void skb_reserve(struct sk_buff *skb, unsigned int bytes);
void skb_put_data(struct sk_buff *skb, const void *data, unsigned int bytes);
u16 eth_type_trans(struct sk_buff *skb, struct net_device *dev);
void napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb);
void hrtimer_setup(struct hrtimer *timer,
		   enum hrtimer_restart (*function)(struct hrtimer *), int clock, int mode);
void hrtimer_start(struct hrtimer *timer, ktime_t expires, int mode);
int hrtimer_cancel(struct hrtimer *timer);
void hrtimer_forward_now(struct hrtimer *timer, ktime_t interval);
void usleep_range(unsigned long minimum, unsigned long maximum);

static inline ktime_t ns_to_ktime(u64 nanoseconds)
{
	return (ktime_t)nanoseconds;
}

#endif
