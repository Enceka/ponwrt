#include "host_stubs.h"
#include "airoha_eth_return.c"

enum event_kind {
	EVENT_WRITE, EVENT_RMB, EVENT_WMB, EVENT_MB, EVENT_BINDING,
	EVENT_GRO, EVENT_COMMAND, EVENT_QUIESCE, EVENT_FAULT, EVENT_FENCE,
	EVENT_TIMER_CANCEL, EVENT_NAPI_DISABLE, EVENT_NAPI_DEL, EVENT_DEV_PUT,
	EVENT_DMA_FREE, EVENT_FREE,
};

struct event {
	enum event_kind kind;
	const void *pointer;
	u64 value;
};

struct dma_record {
	struct device *dev;
	void *pointer;
	dma_addr_t address;
	size_t bytes;
};

struct delivery {
	struct net_device *dev;
	u16 protocol;
	size_t bytes;
	u8 payload[ER_BUFFER];
};

static struct {
	struct event events[32768];
	size_t event_count;
	struct dma_record dma[8];
	struct napi_struct *napis[8];
	struct delivery deliveries[1024];
	size_t delivery_count;
	unsigned int objects, buffers, skbs, rcu_depth;
	unsigned int object_attempts, dma_attempts, skb_attempts;
	unsigned int sleeps, releases;
	bool fail_object, fail_dma, fail_skb, override_dma, drain_on_sleep;
	dma_addr_t next_dma;
	int drain_budget;
} host;

struct fixture {
	struct airoha_er *ring;
	struct device device;
	struct net_device lower, replacement;
	struct airoha_er_ops ops;
	struct er_config expected;
	struct net_device *live_lower;
	u32 live_sport, live_generation, live_service;
	bool live, quiesced, fence_valid;
	struct er_config fence;
	int command_error[4], quiesce_error;
	unsigned int commands[4], quiesces, bindings, faults, fences;
	u32 last_service, fault_reason;
};

static unsigned int tests_run;
static const char *current_test;

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, \
			current_test ? current_test : "host", #condition); \
		abort(); \
	} \
} while (0)

static void event(enum event_kind kind, const void *pointer, u64 value)
{
	CHECK(host.event_count < ARRAY_SIZE(host.events));
	host.events[host.event_count++] = (struct event) { kind, pointer, value };
}

void host_record_write(void *address, u64 value, size_t size)
{
	CHECK(size == 1 || size == 4 || size == 8);
	event(EVENT_WRITE, address, value);
}

void dma_rmb(void) { event(EVENT_RMB, NULL, 0); }
void dma_wmb(void) { event(EVENT_WMB, NULL, 0); }
void dma_mb(void) { event(EVENT_MB, NULL, 0); }

void rcu_read_lock(void)
{
	CHECK(host.rcu_depth == 0);
	++host.rcu_depth;
}

void rcu_read_unlock(void)
{
	CHECK(host.rcu_depth == 1);
	--host.rcu_depth;
}

void *kzalloc(size_t size, int flags)
{
	void *pointer;

	CHECK(flags == GFP_KERNEL);
	++host.object_attempts;
	if (host.fail_object)
		return NULL;
	pointer = calloc(1, size);
	CHECK(pointer);
	++host.objects;
	return pointer;
}

void kfree(void *pointer)
{
	CHECK(pointer && host.objects);
	event(EVENT_FREE, pointer, 0);
	--host.objects;
	free(pointer);
}

void *dma_alloc_coherent(struct device *dev, size_t bytes, dma_addr_t *dma, int flags)
{
	void *pointer = NULL;
	size_t index;

	CHECK(dev && dma && bytes && flags == GFP_KERNEL);
	++host.dma_attempts;
	if (host.fail_dma)
		return NULL;
	CHECK(posix_memalign(&pointer, 64, bytes) == 0);
	memset(pointer, 0xa5, bytes);
	*dma = host.override_dma ? host.next_dma :
		0x01000000u + (u64)host.dma_attempts * 0x00200000u;
	for (index = 0; index < ARRAY_SIZE(host.dma); ++index) {
		if (!host.dma[index].pointer) {
			host.dma[index] = (struct dma_record) { dev, pointer, *dma, bytes };
			++host.buffers;
			return pointer;
		}
	}
	CHECK(false);
	return NULL;
}

void dma_free_coherent(struct device *dev, size_t bytes, void *pointer, dma_addr_t dma)
{
	size_t index;

	for (index = 0; index < ARRAY_SIZE(host.dma); ++index) {
		if (host.dma[index].pointer == pointer) {
			CHECK(host.dma[index].dev == dev);
			CHECK(host.dma[index].bytes == bytes);
			CHECK(host.dma[index].address == dma);
			CHECK(host.buffers);
			event(EVENT_DMA_FREE, pointer, dma);
			memset(&host.dma[index], 0, sizeof(host.dma[index]));
			--host.buffers;
			++host.releases;
			free(pointer);
			return;
		}
	}
	CHECK(false);
}

void dev_hold(struct net_device *dev) { ++dev->references; }

void dev_put(struct net_device *dev)
{
	CHECK(dev->references > 1);
	event(EVENT_DEV_PUT, dev, 0);
	--dev->references;
}

void netif_napi_add(struct net_device *dev, struct napi_struct *napi,
		    int (*poll)(struct napi_struct *, int))
{
	size_t index;

	CHECK(!napi->added && dev && poll);
	napi->dev = dev;
	napi->poll = poll;
	napi->added = true;
	for (index = 0; index < ARRAY_SIZE(host.napis); ++index) {
		if (!host.napis[index]) {
			host.napis[index] = napi;
			return;
		}
	}
	CHECK(false);
}

void netif_napi_del(struct napi_struct *napi)
{
	size_t index;

	CHECK(napi->added && !napi->enabled);
	event(EVENT_NAPI_DEL, napi, 0);
	napi->added = false;
	for (index = 0; index < ARRAY_SIZE(host.napis); ++index) {
		if (host.napis[index] == napi) {
			host.napis[index] = NULL;
			return;
		}
	}
	CHECK(false);
}

void napi_enable(struct napi_struct *napi)
{
	CHECK(napi->added && !napi->enabled);
	napi->enabled = true;
}

void napi_disable(struct napi_struct *napi)
{
	CHECK(napi->added && napi->enabled);
	event(EVENT_NAPI_DISABLE, napi, 0);
	napi->enabled = false;
	napi->scheduled = false;
}

void napi_schedule(struct napi_struct *napi)
{
	CHECK(napi->added && napi->enabled);
	napi->scheduled = true;
	++napi->schedules;
}

bool napi_complete_done(struct napi_struct *napi, int done)
{
	CHECK(napi->enabled && done >= 0);
	++napi->completions;
	napi->last_completed = done;
	napi->scheduled = false;
	return true;
}

struct sk_buff *napi_alloc_skb(struct napi_struct *napi, unsigned int bytes)
{
	struct sk_buff *skb;

	CHECK(napi->enabled && host.rcu_depth == 1);
	++host.skb_attempts;
	if (host.fail_skb)
		return NULL;
	skb = calloc(1, sizeof(*skb));
	CHECK(skb);
	skb->head = malloc(bytes);
	CHECK(skb->head);
	skb->data = skb->head;
	skb->capacity = bytes;
	skb->ip_summed = -1;
	++host.skbs;
	return skb;
}

void skb_reserve(struct sk_buff *skb, unsigned int bytes)
{
	CHECK(skb->len == 0 && bytes <= skb->capacity);
	skb->data += bytes;
	skb->capacity -= bytes;
}

void skb_put_data(struct sk_buff *skb, const void *data, unsigned int bytes)
{
	CHECK(skb->len + bytes <= skb->capacity);
	memcpy(skb->data + skb->len, data, bytes);
	skb->len += bytes;
}

u16 eth_type_trans(struct sk_buff *skb, struct net_device *dev)
{
	u16 protocol;

	CHECK(skb->dev == dev && skb->len >= 14);
	protocol = (u16)skb->data[12] << 8 | skb->data[13];
	skb->data += 14;
	skb->len -= 14;
	return protocol;
}

void napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
	struct delivery *delivery;

	CHECK(napi->enabled && skb->dev == napi->dev);
	CHECK(skb->ip_summed == CHECKSUM_NONE && host.rcu_depth == 1);
	CHECK(skb->data == skb->head + NET_IP_ALIGN + 14);
	CHECK(host.delivery_count < ARRAY_SIZE(host.deliveries));
	delivery = &host.deliveries[host.delivery_count++];
	delivery->dev = skb->dev;
	delivery->bytes = skb->len + 14;
	delivery->protocol = skb->protocol;
	memcpy(delivery->payload, skb->head + NET_IP_ALIGN, delivery->bytes);
	event(EVENT_GRO, napi, delivery->bytes);
	free(skb->head);
	free(skb);
	CHECK(host.skbs);
	--host.skbs;
}

void hrtimer_setup(struct hrtimer *timer,
		   enum hrtimer_restart (*function)(struct hrtimer *), int clock, int mode)
{
	CHECK(clock == CLOCK_MONOTONIC && mode == HRTIMER_MODE_REL);
	CHECK(function);
	timer->function = function;
}

void hrtimer_start(struct hrtimer *timer, ktime_t expires, int mode)
{
	CHECK(timer->function && mode == HRTIMER_MODE_REL);
	timer->active = true;
	timer->expires = expires;
}

int hrtimer_cancel(struct hrtimer *timer)
{
	int active = timer->active;

	event(EVENT_TIMER_CANCEL, timer, 0);
	timer->active = false;
	return active;
}

void hrtimer_forward_now(struct hrtimer *timer, ktime_t interval)
{
	CHECK(interval == NSEC_PER_MSEC);
	timer->expires += interval;
	++timer->forwards;
}

void usleep_range(unsigned long minimum, unsigned long maximum)
{
	size_t index;

	CHECK(minimum == 1000 && maximum == 2000);
	++host.sleeps;
	if (!host.drain_on_sleep)
		return;
	for (index = 0; index < ARRAY_SIZE(host.napis); ++index) {
		struct napi_struct *napi = host.napis[index];

		if (napi && napi->enabled && napi->scheduled)
			napi->poll(napi, host.drain_budget);
	}
}

static bool config_equal(const struct er_config *left, const struct er_config *right)
{
	return left->dma == right->dma && left->bytes == right->bytes &&
		left->epoch == right->epoch && left->count == right->count &&
		left->sport == right->sport && left->generation == right->generation;
}

static int command(void *opaque, struct er_message *message)
{
	struct fixture *fixture = opaque;
	struct airoha_er *ring = fixture->ring;
	u32 operation = message->w[1] >> 16;
	u32 index;

	CHECK(ring && ring->ctx == fixture && ring->allocation);
	CHECK(operation >= ER_BIND && operation <= ER_UNBIND);
	CHECK(message->w[0] == ER_MAGIC);
	CHECK(message->w[1] == (ER_ABI | operation << 16));
	CHECK(message->w[2] == ring->config.dma);
	CHECK(message->w[3] == ring->config.bytes);
	CHECK(message->w[4] == ring->config.epoch);
	CHECK(message->w[5] == ring->config.count);
	CHECK(message->w[6] == ring->config.sport);
	CHECK(message->w[7] == ring->config.generation);
	CHECK(message->w[8] == (u32)-115);
	for (index = 9; index < ARRAY_SIZE(message->w); ++index)
		CHECK(message->w[index] == 0);
	CHECK(ring->enabled && ring->napi.enabled && ring->timer.active);
	CHECK(ring->lower == &fixture->lower && fixture->lower.references == 2);
	if (operation == ER_BIND) {
		CHECK(ring->config.sport == fixture->expected.sport);
		CHECK(ring->config.generation == fixture->expected.generation);
		CHECK(ring->config.epoch == fixture->expected.epoch);
		CHECK(ring->config.count == fixture->expected.count);
		fixture->expected = ring->config;
	} else {
		CHECK(fixture->quiesced);
		CHECK(config_equal(&fixture->expected, &ring->config));
	}
	if (operation == ER_UNBIND) {
		CHECK(le32_to_cpu(er_ctrl(ring)[ER_C_HOST_ENABLED]) == 0);
		CHECK(ring->consumed == le32_to_cpu(er_ctrl(ring)[ER_C_PRODUCER]));
	}
	event(EVENT_COMMAND, fixture, operation);
	++fixture->commands[operation];
	if (!fixture->command_error[operation] && operation == ER_STOP)
		er_ctrl(ring)[ER_C_STOPPED] = cpu_to_le32(1);
	return fixture->command_error[operation];
}

static int quiesce(void *opaque)
{
	struct fixture *fixture = opaque;
	size_t index;

	CHECK(fixture->ring && host.rcu_depth == 0);
	for (index = 0; index < ARRAY_SIZE(host.napis); ++index)
		if (host.napis[index])
			CHECK(host.napis[index]->enabled);
	event(EVENT_QUIESCE, fixture, 0);
	++fixture->quiesces;
	fixture->quiesced = !fixture->quiesce_error;
	return fixture->quiesce_error;
}

static bool binding_matches(void *opaque, struct net_device *lower,
			    const struct er_config *config, u32 service)
{
	struct fixture *fixture = opaque;

	CHECK(host.rcu_depth == 1);
	CHECK(lower == fixture->ring->lower);
	CHECK(config_equal(config, &fixture->expected));
	++fixture->bindings;
	fixture->last_service = service;
	event(EVENT_BINDING, fixture, service);
	return fixture->live && lower == fixture->live_lower &&
		config->sport == fixture->live_sport &&
		config->generation == fixture->live_generation &&
		service == fixture->live_service;
}

static void fault(void *opaque, const struct er_config *config, u32 reason)
{
	struct fixture *fixture = opaque;

	CHECK(config_equal(config, &fixture->expected));
	CHECK(fixture->ring->protocol_error);
	CHECK(host.rcu_depth == 0);
	CHECK(reason == 1 || reason == 2);
	++fixture->faults;
	fixture->fault_reason = reason;
	event(EVENT_FAULT, fixture, reason);
}

static bool access_revoked(void *opaque, const struct er_config *config)
{
	struct fixture *fixture = opaque;

	CHECK(config_equal(config, &fixture->expected));
	++fixture->fences;
	event(EVENT_FENCE, fixture, config->sport);
	return fixture->fence_valid && config_equal(config, &fixture->fence);
}

static const struct airoha_er_ops operations = {
	.command = command, .quiesce = quiesce, .binding_matches = binding_matches,
	.fault = fault, .access_revoked = access_revoked,
};

static void begin(const char *name)
{
	size_t index;

	CHECK(!host.objects && !host.buffers && !host.skbs && !host.rcu_depth);
	for (index = 0; index < ARRAY_SIZE(host.napis); ++index)
		CHECK(!host.napis[index]);
	memset(&host, 0, sizeof(host));
	host.drain_budget = 2;
	current_test = name;
	++tests_run;
}

static void initialize(struct fixture *fixture, u32 sport)
{
	memset(fixture, 0, sizeof(*fixture));
	fixture->device.identity = sport;
	fixture->lower.identity = sport;
	fixture->lower.references = 1;
	fixture->replacement.references = 1;
	fixture->ops = operations;
	fixture->live = true;
	fixture->live_lower = &fixture->lower;
	fixture->live_sport = sport;
	fixture->live_generation = 17 + sport;
	fixture->live_service = sport == ER_PON ? ER_SERVICE_VALID | 0xbeef : 0;
	fixture->expected = (struct er_config) {
		.sport = sport, .generation = fixture->live_generation,
		.epoch = 100 + sport, .count = ER_MIN_COUNT,
	};
}

static int create(struct fixture *fixture)
{
	return airoha_er_create(&fixture->ring, &fixture->device, &fixture->lower,
		fixture->expected.sport, fixture->expected.generation,
		fixture->expected.epoch, fixture->expected.count, true,
		&fixture->ops, fixture);
}

static void setup(struct fixture *fixture, u32 sport)
{
	initialize(fixture, sport);
	CHECK(create(fixture) == 0);
}

static void destroy(struct fixture *fixture)
{
	CHECK(airoha_er_destroy(&fixture->ring) == 0);
	CHECK(!fixture->ring && fixture->lower.references == 1);
}

static void reset_release(struct fixture *fixture)
{
	fixture->fence = fixture->expected;
	fixture->fence_valid = true;
	CHECK(airoha_er_retire_after_reset(&fixture->ring) == 0);
	CHECK(!fixture->ring && fixture->lower.references == 1);
}

static __le32 *slot_for(struct airoha_er *ring, u32 sequence)
{
	return (void *)((u8 *)ring->allocation + 64 +
		((sequence - 1) % ring->config.count) * 64);
}

static u8 *payload_for(struct airoha_er *ring, u32 sequence)
{
	return (u8 *)ring->allocation + 64 + ring->config.count * 64 +
		((sequence - 1) % ring->config.count) * ER_BUFFER;
}

static void publish(struct fixture *fixture, u32 sequence, u32 bytes, u32 service)
{
	struct airoha_er *ring = fixture->ring;
	__le32 *slot = slot_for(ring, sequence);
	u8 *payload = payload_for(ring, sequence);
	u32 word4 = ((service & 0xffffu) << 14) | 0x80000015u;
	u32 words[16] = {
		ER_DONE | bytes, ring->config.epoch, sequence, ring->config.sport,
		ring->config.generation, service,
		ring->config.dma + (u32)(payload - (u8 *)ring->allocation), 0,
		bytes, 0, 7, 0, word4, 6u << 28, ring->config.sport, 0,
	};
	u32 index;

	CHECK(sequence > ring->consumed && sequence - ring->consumed <= ring->config.count);
	CHECK(slot[0] == 0 && bytes <= ER_BUFFER);
	for (index = 0; index < bytes; ++index)
		payload[index] = (u8)(sequence * 37 + ring->config.sport + index);
	if (bytes >= 14) {
		payload[12] = 0x08;
		payload[13] = 0x00;
	}
	for (index = 0; index < ARRAY_SIZE(words); ++index)
		slot[index] = cpu_to_le32(words[index]);
	er_ctrl(ring)[ER_C_PRODUCER] = cpu_to_le32(sequence);
}

static int poll_ring(struct fixture *fixture, int budget)
{
	napi_schedule(&fixture->ring->napi);
	return er_poll(&fixture->ring->napi, budget);
}

static size_t find_event(size_t start, enum event_kind kind, const void *pointer, u64 value)
{
	size_t index;

	for (index = start; index < host.event_count; ++index)
		if (host.events[index].kind == kind && host.events[index].pointer == pointer &&
		    host.events[index].value == value)
			return index;
	CHECK(false);
	return 0;
}

static void check_return_order(struct fixture *fixture, u32 sequence, size_t start,
			       bool delivered)
{
	struct airoha_er *ring = fixture->ring;
	size_t binding, full_barrier, clear, write_barrier, consumer, consumed;

	binding = find_event(start, EVENT_BINDING, fixture, fixture->last_service);
	if (delivered)
		CHECK(host.events[binding + 1].kind == EVENT_GRO);
	full_barrier = binding + (delivered ? 2 : 1);
	CHECK(host.events[full_barrier].kind == EVENT_MB);
	clear = find_event(full_barrier + 1, EVENT_WRITE, slot_for(ring, sequence), 0);
	CHECK(clear == full_barrier + 1);
	write_barrier = clear + 1;
	CHECK(host.events[write_barrier].kind == EVENT_WMB);
	consumer = find_event(write_barrier + 1, EVENT_WRITE,
		&er_ctrl(ring)[ER_C_CONSUMER], cpu_to_le32(sequence));
	CHECK(consumer == write_barrier + 1);
	consumed = find_event(consumer + 1, EVENT_WRITE, &ring->consumed, sequence);
	CHECK(consumed == consumer + 1);
	CHECK(slot_for(ring, sequence)[0] == 0);
	CHECK(le32_to_cpu(er_ctrl(ring)[ER_C_CONSUMER]) >= sequence);
}

static void check_retained(struct fixture *fixture, struct airoha_er *original,
			    void *allocation, unsigned int releases)
{
	CHECK(fixture->ring == original && fixture->ring->allocation == allocation);
	CHECK(host.releases == releases);
	CHECK(fixture->lower.references == 2);
	CHECK(fixture->ring->napi.added && fixture->ring->napi.enabled);
	CHECK(fixture->ring->timer.active && fixture->ring->enabled);
	CHECK(config_equal(&fixture->expected, &fixture->ring->config));
}

static void check_delivery(size_t index, struct fixture *fixture, u32 sequence, u32 bytes)
{
	struct delivery *delivery = &host.deliveries[index];

	CHECK(index < host.delivery_count);
	CHECK(delivery->dev == &fixture->lower);
	CHECK(delivery->bytes == bytes && delivery->protocol == 0x0800);
	CHECK(!memcmp(delivery->payload, payload_for(fixture->ring, sequence), bytes));
}

static void check_initialization(struct fixture *fixture)
{
	struct airoha_er *ring = fixture->ring;
	u32 expected[16] = {
		ER_MAGIC, ER_ABI, ring->config.epoch, ring->config.count,
		0, 0, 1, 0, 0, ring->config.generation, ring->config.sport,
		ER_BUFFER, 64 + ring->config.count * (64 + ER_BUFFER), 0, 0, 0,
	};
	u32 index, word;

	CHECK(ring->config.bytes == expected[ER_C_BYTES]);
	CHECK(ring->dma == ring->config.dma);
	CHECK(ring->timer.expires == NSEC_PER_MSEC);
	CHECK(ring->napi.poll == er_poll);
	for (word = 0; word < ARRAY_SIZE(expected); ++word)
		CHECK(le32_to_cpu(er_ctrl(ring)[word]) == expected[word]);
	for (index = 1; index <= ring->config.count; ++index) {
		__le32 *slot = slot_for(ring, index);
		u32 payload_dma = ring->config.dma +
			(u32)(payload_for(ring, index) - (u8 *)ring->allocation);

		for (word = 0; word < 16; ++word)
			CHECK(le32_to_cpu(slot[word]) == (word == ER_D_BUFFER ? payload_dma : 0));
		for (word = 0; word < ER_BUFFER; ++word)
			CHECK(payload_for(ring, index)[word] == 0);
	}
}

static void test_two_handles_budget_and_wrap(void)
{
	struct fixture lan, pon;
	struct airoha_er_stats stats;
	size_t start, second;
	u32 sequence;

	begin("two handles, budget, timer, DONE ordering and wrap");
	setup(&lan, ER_LAN1);
	setup(&pon, ER_PON);
	CHECK(lan.ring != pon.ring && lan.ring->allocation != pon.ring->allocation);
	CHECK(lan.ring->dma != pon.ring->dma);
	CHECK(host.objects == 2 && host.buffers == 2);
	check_initialization(&lan);
	check_initialization(&pon);
	CHECK(lan.ring->timer.function(&lan.ring->timer) == HRTIMER_RESTART);
	CHECK(lan.ring->napi.scheduled && lan.ring->timer.forwards == 1);
	CHECK(!pon.ring->napi.scheduled);
	publish(&lan, 1, 64, 0);
	publish(&lan, 2, 128, 0);
	publish(&lan, 3, 1518, 0);
	publish(&pon, 1, 14, pon.live_service);
	start = host.event_count;
	CHECK(poll_ring(&lan, 0) == 0);
	CHECK(lan.ring->consumed == 0 && lan.bindings == 0);
	CHECK(lan.ring->napi.completions == 0 && host.delivery_count == 0);
	CHECK(poll_ring(&lan, 2) == 2);
	CHECK(lan.ring->consumed == 2 && pon.ring->consumed == 0);
	CHECK(lan.ring->napi.completions == 0 && lan.ring->napi.scheduled);
	CHECK(le32_to_cpu(slot_for(lan.ring, 3)[0]) == (ER_DONE | 1518));
	CHECK(host.events[start].kind == EVENT_RMB);
	check_return_order(&lan, 1, start, true);
	second = find_event(start, EVENT_WRITE, &lan.ring->consumed, 1) + 1;
	CHECK(host.events[second].kind == EVENT_RMB);
	check_return_order(&lan, 2, second, true);
	check_delivery(0, &lan, 1, 64);
	check_delivery(1, &lan, 2, 128);
	CHECK(poll_ring(&pon, 4) == 1);
	CHECK(pon.bindings == 1 && pon.last_service == (ER_SERVICE_VALID | 0xbeef));
	CHECK(pon.ring->napi.last_completed == 1 && pon.ring->napi.completions == 1);
	check_delivery(2, &pon, 1, 14);
	CHECK(poll_ring(&lan, 2) == 1);
	CHECK(lan.ring->napi.last_completed == 1 && !lan.ring->napi.scheduled);
	check_delivery(3, &lan, 3, 1518);
	CHECK(poll_ring(&lan, 2) == 0);
	airoha_er_get_stats(lan.ring, &stats);
	CHECK(stats.packets == 3 && stats.bytes == 1710 && stats.dropped == 0);
	CHECK(stats.polls == 3 && stats.empty_polls == 1);
	CHECK(stats.consumed == 3 && stats.fault == 0);
	destroy(&pon);
	CHECK(lan.ring->napi.enabled && lan.ring->timer.active && host.buffers == 1);
	for (sequence = 4; sequence <= 20; ++sequence) {
		publish(&lan, sequence, 64, 0);
		CHECK(poll_ring(&lan, 1) == 1);
		check_delivery(host.delivery_count - 1, &lan, sequence, 64);
	}
	CHECK(lan.ring->consumed == 20 && !lan.faults);
	lan.ring->enabled = false;
	CHECK(lan.ring->timer.function(&lan.ring->timer) == HRTIMER_NORESTART);
	lan.ring->enabled = true;
	destroy(&lan);
}

static void test_live_binding(void)
{
	u32 sources[] = { ER_LAN1, ER_PON };
	size_t source;

	for (source = 0; source < ARRAY_SIZE(sources); ++source) {
		struct fixture fixture;
		struct airoha_er_stats stats;
		u32 mismatch, service;

		begin("RCU live lower/source/generation/full-service binding and revoked mapping");
		setup(&fixture, sources[source]);
		service = fixture.live_service;
		for (mismatch = 0; mismatch < 5; ++mismatch) {
			size_t start = host.event_count;

			fixture.live_lower = &fixture.lower;
			fixture.live_sport = sources[source];
			fixture.live_generation = fixture.expected.generation;
			fixture.live_service = service;
			fixture.live = true;
			switch (mismatch) {
			case 0: fixture.live_lower = &fixture.replacement; break;
			case 1: fixture.live_sport ^= 1; break;
			case 2: ++fixture.live_generation; break;
			case 3: fixture.live_service ^= 0x1000; break;
			case 4: fixture.live = false; break;
			}
			publish(&fixture, mismatch + 1, 64, service);
			CHECK(poll_ring(&fixture, 2) == 1);
			CHECK(fixture.ring->consumed == mismatch + 1);
			CHECK(fixture.bindings == mismatch + 1 && fixture.last_service == service);
			CHECK(!host.delivery_count && !host.skb_attempts && !fixture.faults);
			check_return_order(&fixture, mismatch + 1, start, false);
		}
		fixture.live = true;
		publish(&fixture, 6, 64, service);
		CHECK(poll_ring(&fixture, 2) == 1);
		check_delivery(0, &fixture, 6, 64);
		airoha_er_get_stats(fixture.ring, &stats);
		CHECK(stats.packets == 1 && stats.bytes == 64 && stats.dropped == 5);
		CHECK(stats.consumed == 6 && stats.fault == 0);
		destroy(&fixture);
	}
}

static void check_fault_once(struct fixture *fixture, u32 reason, u32 consumed)
{
	struct airoha_er_stats stats;
	unsigned int schedules = fixture->ring->napi.schedules;
	unsigned int bindings = fixture->bindings;
	unsigned int attempts = host.skb_attempts;
	unsigned int index;

	CHECK(fixture->faults == 1 && fixture->fault_reason == reason);
	CHECK(fixture->ring->protocol_error && fixture->ring->consumed == consumed);
	CHECK(fixture->ring->timer.function(&fixture->ring->timer) == HRTIMER_NORESTART);
	CHECK(fixture->ring->napi.schedules == schedules);
	for (index = 0; index < 3; ++index)
		CHECK(poll_ring(fixture, 8) == 0);
	CHECK(fixture->faults == 1 && fixture->bindings == bindings);
	CHECK(host.skb_attempts == attempts && !host.rcu_depth);
	airoha_er_get_stats(fixture->ring, &stats);
	CHECK(stats.fault == reason && stats.consumed == consumed);
}

static void test_descriptor_faults(void)
{
	static const struct {
		const char *name;
		u32 word, mask;
	} corruptions[] = {
		{ "DONE missing", ER_D_CONTROL, ER_DONE },
		{ "control reserved bits", ER_D_CONTROL, 1u << 16 },
		{ "descriptor epoch", ER_D_EPOCH, 1 },
		{ "descriptor sequence", ER_D_SEQUENCE, 1 },
		{ "descriptor source", ER_D_SPORT, 1 },
		{ "descriptor generation", ER_D_GENERATION, 1 },
		{ "descriptor full service", ER_D_SERVICE, 0x1000 },
		{ "descriptor service flag", ER_D_SERVICE, ER_SERVICE_VALID },
		{ "descriptor buffer", ER_D_BUFFER, 64 },
		{ "descriptor reserved", ER_D_RESERVED, 1 },
		{ "prefix length", ER_D_PREFIX, 1 },
		{ "prefix packet type", ER_D_PREFIX + 2, 1 },
		{ "prefix PON FE word4 service", ER_D_PREFIX + 4, 1u << 26 },
		{ "prefix format", ER_D_PREFIX + 5, 1u << 28 },
		{ "prefix source", ER_D_PREFIX + 6, 1 },
	};
	u32 sources[] = { ER_LAN1, ER_PON };
	size_t source, corruption;

	for (source = 0; source < ARRAY_SIZE(sources); ++source) {
		for (corruption = 0; corruption < ARRAY_SIZE(corruptions); ++corruption) {
			struct fixture fixture;
			__le32 *slot;
			u32 word = corruptions[corruption].word;
			u32 original;

			if (sources[source] == ER_LAN1 && word == ER_D_PREFIX + 4)
				continue;
			begin(corruptions[corruption].name);
			setup(&fixture, sources[source]);
			publish(&fixture, 1, 64, fixture.live_service);
			slot = slot_for(fixture.ring, 1);
			original = slot[word];
			slot[word] = cpu_to_le32(le32_to_cpu(slot[word]) ^ corruptions[corruption].mask);
			CHECK(poll_ring(&fixture, 8) == 0);
			CHECK(!fixture.bindings && !host.skb_attempts && !host.delivery_count);
			CHECK(er_ctrl(fixture.ring)[ER_C_CONSUMER] == 0);
			slot[word] = original;
			check_fault_once(&fixture, 2, 0);
			reset_release(&fixture);
		}
	}
	for (corruption = 0; corruption < 2; ++corruption) {
		struct fixture fixture;
		u32 bytes = corruption ? 1519 : 13;

		begin("invalid Ethernet length before binding or copy");
		setup(&fixture, ER_PON);
		publish(&fixture, 1, bytes, fixture.live_service);
		CHECK(poll_ring(&fixture, 8) == 0);
		CHECK(!fixture.bindings && !host.delivery_count && !host.skb_attempts);
		check_fault_once(&fixture, 2, 0);
		reset_release(&fixture);
	}
}

static void test_control_faults(void)
{
	u32 fields[] = {
		ER_C_MAGIC, ER_C_ABI, ER_C_EPOCH, ER_C_COUNT, ER_C_CONSUMER,
		ER_C_GENERATION, ER_C_SPORT, ER_C_BUFFER, ER_C_BYTES,
		ER_C_FAULT, ER_C_RESERVED0, ER_C_RESERVED1, ER_C_RESERVED2,
		ER_C_HOST_ENABLED, ER_C_STOPPED,
	};
	size_t field;

	for (field = 0; field < ARRAY_SIZE(fields); ++field) {
		struct fixture fixture;
		u32 index = fields[field];
		__le32 original;

		begin("control integrity and boolean flags reject 2");
		setup(&fixture, ER_LAN1);
		publish(&fixture, 1, 64, 0);
		original = er_ctrl(fixture.ring)[index];
		er_ctrl(fixture.ring)[index] = cpu_to_le32(
			(index == ER_C_HOST_ENABLED || index == ER_C_STOPPED) ? 2 :
			le32_to_cpu(original) ^ 1);
		CHECK(poll_ring(&fixture, 8) == 0);
		CHECK(!fixture.bindings && !host.delivery_count && !host.skb_attempts);
		CHECK(le32_to_cpu(slot_for(fixture.ring, 1)[0]) == (ER_DONE | 64));
		er_ctrl(fixture.ring)[index] = original;
		check_fault_once(&fixture, 1, 0);
		reset_release(&fixture);
	}
	for (field = 0; field < 4; ++field) {
		struct fixture fixture;

		begin("control HOST_ENABLED and STOPPED accept 0 and 1 while draining");
		setup(&fixture, ER_PON);
		publish(&fixture, 1, 64, fixture.live_service);
		er_ctrl(fixture.ring)[ER_C_HOST_ENABLED] = cpu_to_le32(field & 1);
		er_ctrl(fixture.ring)[ER_C_STOPPED] = cpu_to_le32(field >> 1);
		CHECK(poll_ring(&fixture, 8) == 1);
		CHECK(!fixture.faults && host.delivery_count == 1 && fixture.ring->consumed == 1);
		destroy(&fixture);
	}
	for (field = 0; field < 2; ++field) {
		struct fixture fixture;

		begin("producer rollback and capacity overrun");
		setup(&fixture, ER_LAN1);
		if (!field) {
			publish(&fixture, 1, 64, 0);
			CHECK(poll_ring(&fixture, 8) == 1);
			er_ctrl(fixture.ring)[ER_C_PRODUCER] = 0;
		} else {
			er_ctrl(fixture.ring)[ER_C_PRODUCER] = cpu_to_le32(ER_MIN_COUNT + 1);
		}
		CHECK(poll_ring(&fixture, 8) == 0);
		check_fault_once(&fixture, 1, field ? 0 : 1);
		reset_release(&fixture);
	}
}

static void test_fault_after_partial_poll(void)
{
	struct fixture lan, pon;
	struct airoha_er *original;
	void *allocation;

	begin("partial poll fault preserves poisoned slot and other source");
	setup(&lan, ER_LAN1);
	setup(&pon, ER_PON);
	publish(&lan, 1, 64, 0);
	publish(&lan, 2, 64, 0);
	slot_for(lan.ring, 2)[ER_D_GENERATION] ^= cpu_to_le32(1);
	CHECK(poll_ring(&lan, 8) == 1);
	CHECK(lan.ring->consumed == 1 && lan.ring->napi.last_completed == 1);
	CHECK(lan.bindings == 1 && host.delivery_count == 1);
	CHECK(slot_for(lan.ring, 1)[0] == 0);
	CHECK(le32_to_cpu(slot_for(lan.ring, 2)[0]) == (ER_DONE | 64));
	check_fault_once(&lan, 2, 1);
	original = lan.ring;
	allocation = lan.ring->allocation;
	CHECK(airoha_er_destroy(&lan.ring) == -EPROTO);
	CHECK(lan.commands[ER_UNBIND] == 0);
	check_retained(&lan, original, allocation, 0);
	publish(&pon, 1, 64, pon.live_service);
	CHECK(poll_ring(&pon, 8) == 1 && pon.faults == 0);
	reset_release(&lan);
	destroy(&pon);
}

static void test_zero_budget(void)
{
	unsigned int state;

	for (state = 0; state < 3; ++state) {
		struct fixture fixture;
		struct airoha_er_stats before = { 0 }, after = { 0 };
		unsigned int faults, completions;
		size_t events;

		begin("budget zero: normal, latched fault, corrupt control");
		setup(&fixture, ER_LAN1);
		publish(&fixture, 1, 64, 0);
		if (state == 1) {
			er_ctrl(fixture.ring)[ER_C_MAGIC] = 0;
			CHECK(poll_ring(&fixture, 8) == 0);
			er_ctrl(fixture.ring)[ER_C_MAGIC] = cpu_to_le32(ER_MAGIC);
		} else if (state == 2) {
			er_ctrl(fixture.ring)[ER_C_HOST_ENABLED] = cpu_to_le32(2);
		}
		airoha_er_get_stats(fixture.ring, &before);
		faults = fixture.faults;
		completions = fixture.ring->napi.completions;
		events = host.event_count;
		CHECK(poll_ring(&fixture, 0) == 0);
		airoha_er_get_stats(fixture.ring, &after);
		CHECK(!memcmp(&before, &after, sizeof(before)));
		CHECK(fixture.faults == faults && fixture.ring->napi.completions == completions);
		CHECK(host.event_count == events && fixture.ring->napi.scheduled);
		CHECK(!fixture.bindings && !host.skb_attempts && !host.delivery_count);
		CHECK(fixture.ring->consumed == 0 && er_ctrl(fixture.ring)[ER_C_CONSUMER] == 0);
		CHECK(le32_to_cpu(slot_for(fixture.ring, 1)[0]) == (ER_DONE | 64));
		reset_release(&fixture);
	}
}

static void check_release_events(size_t start)
{
	static const enum event_kind order[] = {
		EVENT_TIMER_CANCEL, EVENT_NAPI_DISABLE, EVENT_NAPI_DEL,
		EVENT_DEV_PUT, EVENT_DMA_FREE, EVENT_FREE,
	};
	size_t index, cursor = start;

	for (index = 0; index < ARRAY_SIZE(order); ++index) {
		while (cursor < host.event_count && host.events[cursor].kind != order[index])
			++cursor;
		CHECK(cursor < host.event_count);
		if (index)
			CHECK(host.events[cursor - 1].kind == order[index - 1]);
		++cursor;
	}
}

static void test_command_failures(void)
{
	int errors[] = { -EIO, -ETIMEDOUT, -EPROTO };
	u32 operation;
	size_t failure;

	for (operation = ER_BIND; operation <= ER_UNBIND; ++operation) {
		for (failure = 0; failure < ARRAY_SIZE(errors); ++failure) {
			struct fixture fixture;
			struct airoha_er *original;
			void *allocation;
			size_t start, stop_event, unbind_event;

			begin("BIND/STOP/UNBIND failure retains handle/DMA and retries");
			initialize(&fixture, operation == ER_STOP ? ER_PON : ER_LAN1);
			fixture.command_error[operation] = errors[failure];
			CHECK(create(&fixture) == (operation == ER_BIND ? errors[failure] : 0));
			CHECK(fixture.ring && host.objects == 1 && host.buffers == 1);
			original = fixture.ring;
			allocation = fixture.ring->allocation;
			if (operation != ER_BIND)
				CHECK(airoha_er_destroy(&fixture.ring) == errors[failure]);
			check_retained(&fixture, original, allocation, 0);
			CHECK(le32_to_cpu(er_ctrl(fixture.ring)[ER_C_HOST_ENABLED]) ==
			      (operation == ER_UNBIND ? 0u : 1u));
			if (operation == ER_STOP)
				CHECK(fixture.commands[ER_UNBIND] == 0);
			if (operation != ER_UNBIND) {
				publish(&fixture, 1, 64, fixture.live_service);
				host.drain_on_sleep = true;
			} else {
				CHECK(poll_ring(&fixture, 8) == 0 && fixture.faults == 0);
			}
			fixture.command_error[operation] = 0;
			start = host.event_count;
			destroy(&fixture);
			CHECK(!host.objects && !host.buffers && host.releases == 1);
			CHECK(fixture.commands[ER_BIND] == 1);
			CHECK(fixture.commands[ER_STOP] == (operation == ER_BIND ? 1u : 2u));
			CHECK(fixture.commands[ER_UNBIND] == (operation == ER_UNBIND ? 2u : 1u));
			CHECK(host.delivery_count == (operation == ER_UNBIND ? 0u : 1u));
			CHECK(host.events[start].kind == EVENT_QUIESCE);
			stop_event = find_event(start, EVENT_COMMAND, &fixture, ER_STOP);
			unbind_event = find_event(stop_event + 1, EVENT_COMMAND, &fixture, ER_UNBIND);
			CHECK(host.events[unbind_event - 1].kind == EVENT_WMB);
			CHECK(host.events[unbind_event - 2].kind == EVENT_WRITE);
			CHECK(host.events[unbind_event - 2].value == 0);
			check_release_events(unbind_event + 1);
		}
	}
}

static void test_quiesce_failure(void)
{
	struct fixture fixture;
	struct airoha_er *original;
	void *allocation;

	begin("quiesce failure retains ownership before STOP");
	setup(&fixture, ER_PON);
	original = fixture.ring;
	allocation = fixture.ring->allocation;
	fixture.quiesce_error = -EBUSY;
	CHECK(airoha_er_destroy(&fixture.ring) == -EBUSY);
	check_retained(&fixture, original, allocation, 0);
	CHECK(!fixture.commands[ER_STOP] && !fixture.commands[ER_UNBIND]);
	CHECK(le32_to_cpu(er_ctrl(fixture.ring)[ER_C_HOST_ENABLED]) == 1);
	fixture.quiesce_error = 0;
	destroy(&fixture);
	CHECK(fixture.quiesces == 2 && fixture.commands[ER_STOP] == 1);
}

static void test_drain_timeout_retry(void)
{
	struct fixture lan, pon;
	struct airoha_er *original;
	void *allocation;
	size_t start, consumer, unbind;
	u32 sequence;

	begin("drain timeout preserves both active NAPIs and retry drains by budget");
	setup(&lan, ER_LAN1);
	setup(&pon, ER_PON);
	for (sequence = 1; sequence <= ER_MIN_COUNT; ++sequence)
		publish(&lan, sequence, 64, 0);
	publish(&pon, 1, 64, pon.live_service);
	original = lan.ring;
	allocation = lan.ring->allocation;
	CHECK(airoha_er_destroy(&lan.ring) == -ETIMEDOUT);
	check_retained(&lan, original, allocation, 0);
	CHECK(host.sleeps == 999 && lan.ring->napi.schedules == 999);
	CHECK(lan.ring->consumed == 0 && lan.commands[ER_UNBIND] == 0);
	CHECK(le32_to_cpu(er_ctrl(lan.ring)[ER_C_HOST_ENABLED]) == 1);
	CHECK(pon.ring->napi.enabled && pon.ring->timer.active);
	napi_schedule(&pon.ring->napi);
	host.drain_on_sleep = true;
	host.drain_budget = 2;
	start = host.event_count;
	destroy(&lan);
	CHECK(host.sleeps == 1003 && host.delivery_count == ER_MIN_COUNT + 1);
	CHECK(pon.ring->consumed == 1 && pon.ring->napi.enabled);
	consumer = find_event(start, EVENT_WRITE, (u8 *)allocation + ER_C_CONSUMER * 4,
		cpu_to_le32(ER_MIN_COUNT));
	unbind = find_event(consumer + 1, EVENT_COMMAND, &lan, ER_UNBIND);
	check_release_events(unbind + 1);
	CHECK(lan.commands[ER_STOP] == 2 && lan.commands[ER_UNBIND] == 1);
	destroy(&pon);
}

static void test_fault_during_drain(void)
{
	struct fixture fixture;
	struct airoha_er *original;
	void *allocation;

	begin("drain observes protocol fault and retains DMA until reset fence");
	setup(&fixture, ER_PON);
	publish(&fixture, 1, 64, fixture.live_service);
	slot_for(fixture.ring, 1)[ER_D_EPOCH] ^= cpu_to_le32(1);
	original = fixture.ring;
	allocation = fixture.ring->allocation;
	host.drain_on_sleep = true;
	CHECK(airoha_er_destroy(&fixture.ring) == -EPROTO);
	CHECK(host.sleeps == 1 && fixture.faults == 1 && !fixture.commands[ER_UNBIND]);
	check_retained(&fixture, original, allocation, 0);
	CHECK(airoha_er_destroy(&fixture.ring) == -EPROTO);
	CHECK(fixture.faults == 1 && fixture.commands[ER_STOP] == 2);
	reset_release(&fixture);
}

static void test_reset_fences(void)
{
	unsigned int field;

	for (field = 0; field < 7; ++field) {
		struct fixture fixture;
		struct airoha_er *original;
		void *allocation;
		size_t start;

		begin("reset fence matches all six config fields and requires callback");
		setup(&fixture, ER_PON);
		fixture.command_error[ER_STOP] = -ETIMEDOUT;
		CHECK(airoha_er_destroy(&fixture.ring) == -ETIMEDOUT);
		original = fixture.ring;
		allocation = fixture.ring->allocation;
		fixture.fence_valid = true;
		fixture.fence = fixture.expected;
		switch (field) {
		case 0: fixture.fence.dma += 64; break;
		case 1: fixture.fence.bytes += 64; break;
		case 2: --fixture.fence.epoch; break;
		case 3: fixture.fence.count *= 2; break;
		case 4: fixture.fence.sport = ER_LAN1; break;
		case 5: ++fixture.fence.generation; break;
		case 6: fixture.ops.access_revoked = NULL; break;
		}
		CHECK(airoha_er_retire_after_reset(&fixture.ring) == -EBUSY);
		check_retained(&fixture, original, allocation, 0);
		CHECK(fixture.fences == (field == 6 ? 0u : 1u));
		fixture.ops.access_revoked = access_revoked;
		fixture.fence = fixture.expected;
		fixture.fence_valid = false;
		CHECK(airoha_er_retire_after_reset(&fixture.ring) == -EBUSY);
		check_retained(&fixture, original, allocation, 0);
		start = host.event_count;
		reset_release(&fixture);
		CHECK(fixture.commands[ER_BIND] == 1 && fixture.commands[ER_STOP] == 1);
		CHECK(fixture.commands[ER_UNBIND] == 0 && fixture.quiesces == 1);
		CHECK(host.events[start].kind == EVENT_FENCE);
		check_release_events(start + 1);
	}
	{
		struct fixture lan, pon;
		struct airoha_er *original;
		void *allocation;

		begin("reset fence for one source leaves the other source owned and usable");
		setup(&lan, ER_LAN1);
		initialize(&pon, ER_PON);
		pon.expected.epoch = lan.expected.epoch;
		CHECK(create(&pon) == 0);
		original = pon.ring;
		allocation = pon.ring->allocation;
		pon.fence_valid = true;
		pon.fence = pon.expected;
		pon.fence.sport = ER_LAN1;
		CHECK(airoha_er_retire_after_reset(&pon.ring) == -EBUSY);
		check_retained(&pon, original, allocation, 0);
		reset_release(&lan);
		CHECK(host.buffers == 1 && pon.ring == original && pon.ring->napi.enabled);
		pon.fence = pon.expected;
		--pon.fence.epoch;
		CHECK(airoha_er_retire_after_reset(&pon.ring) == -EBUSY);
		check_retained(&pon, original, allocation, 1);
		publish(&pon, 1, 64, pon.live_service);
		CHECK(poll_ring(&pon, 8) == 1 && !pon.faults);
		reset_release(&pon);
	}
}

static void test_allocation_failures(void)
{
	unsigned int failure;
	dma_addr_t bad_dma[] = {
		0, 0x100000000ull, 0x01000001u, ER_WINDOW,
		ER_WINDOW - 64, 0xffffffc0u,
	};
	size_t address;

	for (failure = 0; failure < 2; ++failure) {
		struct fixture fixture;

		begin("allocation failure unwinds unpublished ownership");
		initialize(&fixture, ER_LAN1);
		host.fail_object = !failure;
		host.fail_dma = failure;
		CHECK(create(&fixture) == -ENOMEM);
		CHECK(!fixture.ring && !host.objects && !host.buffers);
		CHECK(fixture.lower.references == 1 && !fixture.commands[ER_BIND]);
		CHECK(host.object_attempts == 1 && host.dma_attempts == failure);
	}
	for (address = 0; address < ARRAY_SIZE(bad_dma); ++address) {
		struct fixture fixture;

		begin("DMA address width, alignment and window bounds");
		initialize(&fixture, ER_PON);
		host.override_dma = true;
		host.next_dma = bad_dma[address];
		CHECK(create(&fixture) == -ERANGE);
		CHECK(!fixture.ring && !host.objects && !host.buffers && host.releases == 1);
		CHECK(fixture.lower.references == 1 && !fixture.commands[ER_BIND]);
	}
	{
		struct fixture fixture;
		struct airoha_er_stats stats;
		size_t start;

		begin("skb allocation failure drops, returns DONE and continues");
		setup(&fixture, ER_PON);
		host.fail_skb = true;
		publish(&fixture, 1, 64, fixture.live_service);
		start = host.event_count;
		CHECK(poll_ring(&fixture, 8) == 1);
		CHECK(fixture.bindings == 1 && host.skb_attempts == 1 && !host.delivery_count);
		check_return_order(&fixture, 1, start, false);
		host.fail_skb = false;
		publish(&fixture, 2, 64, fixture.live_service);
		CHECK(poll_ring(&fixture, 8) == 1);
		airoha_er_get_stats(fixture.ring, &stats);
		CHECK(stats.dropped == 1 && stats.packets == 1 && stats.bytes == 64);
		CHECK(stats.consumed == 2 && !stats.fault && host.delivery_count == 1);
		destroy(&fixture);
	}
}

static void test_parameters(void)
{
	unsigned int parameter;
	u32 invalid_counts[] = { 0, 1, ER_MIN_COUNT - 1, ER_MIN_COUNT + 1, ER_MAX_COUNT + 1 };
	size_t index;

	for (parameter = 0; parameter < 13; ++parameter) {
		struct fixture fixture;
		struct airoha_er **owner;
		struct device *device;
		struct net_device *lower;
		const struct airoha_er_ops *ops;
		u32 source = ER_LAN1, generation = 1, epoch = 1;
		bool enabled = true;
		int expected = -EINVAL;

		begin("create pointer, callback, source and enable validation");
		initialize(&fixture, ER_LAN1);
		owner = &fixture.ring;
		device = &fixture.device;
		lower = &fixture.lower;
		ops = &fixture.ops;
		switch (parameter) {
		case 0: owner = NULL; break;
		case 1: device = NULL; break;
		case 2: lower = NULL; break;
		case 3: ops = NULL; break;
		case 4: fixture.ops.command = NULL; break;
		case 5: fixture.ops.quiesce = NULL; break;
		case 6: fixture.ops.binding_matches = NULL; break;
		case 7: fixture.ops.fault = NULL; break;
		case 8: enabled = false; expected = -EOPNOTSUPP; break;
		case 9: source = 0; expected = -EOPNOTSUPP; break;
		case 10: source = 25; expected = -EOPNOTSUPP; break;
		case 11: generation = 0; break;
		case 12: epoch = 0; break;
		}
		CHECK(airoha_er_create(owner, device, lower, source, generation, epoch,
			ER_MIN_COUNT, enabled, ops, &fixture) == expected);
		CHECK(!fixture.ring && !host.object_attempts && !host.dma_attempts);
		CHECK(fixture.lower.references == 1 && !fixture.commands[ER_BIND]);
	}
	for (index = 0; index < ARRAY_SIZE(invalid_counts); ++index) {
		struct fixture fixture;

		begin("count range and power of two validation");
		initialize(&fixture, ER_PON);
		fixture.expected.count = invalid_counts[index];
		CHECK(create(&fixture) == -EINVAL);
		CHECK(!fixture.ring && !host.object_attempts && !host.dma_attempts);
	}
	{
		struct fixture fixture;
		struct airoha_er *original;
		void *allocation;

		begin("occupied output rejects replacement and maximum count initializes");
		initialize(&fixture, ER_LAN1);
		fixture.expected.count = ER_MAX_COUNT;
		CHECK(create(&fixture) == 0);
		check_initialization(&fixture);
		original = fixture.ring;
		allocation = fixture.ring->allocation;
		CHECK(create(&fixture) == -EINVAL);
		check_retained(&fixture, original, allocation, 0);
		CHECK(host.object_attempts == 1 && host.dma_attempts == 1);
		destroy(&fixture);
		CHECK(airoha_er_destroy(NULL) == -EINVAL);
		CHECK(airoha_er_retire_after_reset(NULL) == -EINVAL);
		CHECK(airoha_er_destroy(&fixture.ring) == 0);
		CHECK(airoha_er_retire_after_reset(&fixture.ring) == 0);
	}
}

int main(void)
{
	size_t index;

	test_parameters();
	test_allocation_failures();
	test_two_handles_budget_and_wrap();
	test_live_binding();
	test_descriptor_faults();
	test_control_faults();
	test_fault_after_partial_poll();
	test_zero_budget();
	test_command_failures();
	test_quiesce_failure();
	test_drain_timeout_retry();
	test_fault_during_drain();
	test_reset_fences();
	CHECK(!host.objects && !host.buffers && !host.skbs && !host.rcu_depth);
	for (index = 0; index < ARRAY_SIZE(host.napis); ++index)
		CHECK(!host.napis[index]);
	printf("PASS %u cases: real 989 consumer, dual source, lifecycle, DONE ordering, "
	       "budget, binding, faults, retry and reset fences\n", tests_run);
	return 0;
}
