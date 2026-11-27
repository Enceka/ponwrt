#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef uint32_t __le32;
typedef unsigned int gfp_t;

#define SZ_8K 8192
#define USEC_PER_MSEC 1000
#define BIT(index) (1U << (index))
#define GENMASK(high, low) ((~0U << (low)) & (~0U >> (31 - (high))))
#define FIELD_PREP(mask, value) (((u32)(value) << __builtin_ctz(mask)) & (mask))
#define FIELD_GET(mask, value) (((value) & (mask)) >> __builtin_ctz(mask))
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define DECLARE_FLEX_ARRAY(type, name) type name[]
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
#define READ_ONCE(value) __atomic_load_n(&(value), __ATOMIC_ACQUIRE)
#define WRITE_ONCE(target, value) __atomic_store_n(&(target), (value), __ATOMIC_RELEASE)
#define smp_load_acquire(pointer) __atomic_load_n((pointer), __ATOMIC_ACQUIRE)
#define dev_err_ratelimited(...) ((void)0)

#ifdef TEST_SWAPPED_ENDIAN
#define cpu_to_le32(value) __builtin_bswap32((u32)(value))
#define le32_to_cpu(value) __builtin_bswap32((u32)(value))
#else
#define cpu_to_le32(value) ((u32)(value))
#define le32_to_cpu(value) ((u32)(value))
#endif

#include "production_constants.h"
#include "airoha_npu_transaction.h"

struct device { void *of_node; };
struct regmap;
struct airoha_npu_core { pthread_mutex_t lock; void *buf; u32 addr; };
struct airoha_npu {
	struct device *dev;
	struct regmap *regmap;
	struct airoha_npu_core cores[1];
	bool wlan_short_guard_started, wlan_short_guard_verified;
};

#include "airoha_npu_er_provider.h"

struct regmap {
	u32 ctrl[4], request[SZ_8K / 4], response[SZ_8K / 4];
	unsigned int accesses, triggers, polls, read_barriers, write_barriers;
	unsigned int fail_at, complete_at, bytes;
	int failure, firmware_error;
	bool apply_failed_write, sticky_done, pending, visible_pending, nack, hold_poll;
};

static struct device device;
static struct airoha_npu_instance instance;
static struct regmap registers;
static u32 bounce[SZ_8K / 4];
static bool initialized;
static atomic_uint checks, lock_arrivals;
static _Thread_local bool transport_lock_held;
static pthread_mutex_t rendezvous = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rendezvous_changed = PTHREAD_COND_INITIALIZER;
static bool poll_entered, release_poll;

#define CHECK(condition) do { assert(condition); atomic_fetch_add(&checks, 1); } while (0)

static void spin_lock_bh(pthread_mutex_t *lock)
{
	atomic_fetch_add(&lock_arrivals, 1);
	CHECK(!pthread_mutex_lock(lock));
	CHECK(!transport_lock_held);
	transport_lock_held = true;
}

static void spin_unlock_bh(pthread_mutex_t *lock)
{
	CHECK(transport_lock_held);
	transport_lock_held = false;
	CHECK(!pthread_mutex_unlock(lock));
}

static void publish_completion(void)
{
	u32 *reply = registers.response + 2;
	u32 function = le32_to_cpu(registers.request[1]);

	CHECK(registers.pending);
	memcpy(registers.response, registers.request, registers.bytes);
	if (function == ER_FUNC) {
		reply[8] = cpu_to_le32(registers.firmware_error);
		reply[9] = cpu_to_le32(ER_CAPS | ER_CAP_SOURCES);
		reply[10] = cpu_to_le32(ER_IDLE);
	} else if (function == AUTH_MBOX_FUNC) {
		reply[AM_STATUS] = cpu_to_le32(registers.firmware_error);
		reply[AM_CAPS] = cpu_to_le32(AUTH_MBOX_CAPS);
	} else if (function == GATE_FUNC) {
		reply[GM_STATUS] = cpu_to_le32(registers.firmware_error);
		reply[GM_CAPS] = cpu_to_le32(GATE_CAPS);
		reply[GM_CLOSED] = cpu_to_le32(1);
		reply[GM_DMA_IDLE] = cpu_to_le32(1);
	} else {
		for (unsigned int index = 0; index < registers.bytes / sizeof(u32); index++)
			registers.response[index] ^= cpu_to_le32(0xa5c39e71);
	}
	registers.ctrl[3] = (registers.ctrl[3] & ~MBOX_MSG_STATUS) |
		MBOX_MSG_DONE | FIELD_PREP(MBOX_MSG_STATUS,
			registers.nack ? NPU_MBOX_ERROR : NPU_MBOX_SUCCESS);
	registers.visible_pending = true;
	registers.pending = false;
}

static int regmap_write(struct regmap *map, u32 address, u32 value)
{
	unsigned int index = (address - REG_CR_MBQ0_CTRL(0)) / 4;
	bool failed;

	CHECK(map == &registers && transport_lock_held && index < 4);
	map->accesses++;
	failed = map->fail_at == map->accesses;
	if (failed && !map->apply_failed_write)
		return map->failure;
	if (index == 2) {
		CHECK(map->write_barriers > 0);
		CHECK(!(map->ctrl[3] & MBOX_MSG_DONE));
		CHECK(map->ctrl[0] == instance.npu.cores[0].addr);
		map->triggers++;
		map->bytes = map->ctrl[1];
		CHECK(map->bytes <= SZ_8K);
		memcpy(map->request, bounce, map->bytes);
		map->pending = true;
		map->polls = 0;
		map->visible_pending = false;
	}
	if (index == 3 && map->sticky_done)
		value |= MBOX_MSG_DONE;
	map->ctrl[index] = value;
	return failed ? map->failure : 0;
}

static int regmap_read(struct regmap *map, u32 address, u32 *value)
{
	unsigned int index = (address - REG_CR_MBQ0_CTRL(0)) / 4;

	CHECK(map == &registers && transport_lock_held && index < 4);
	map->accesses++;
	if (index == 3 && map->pending) {
		map->polls++;
		if (map->hold_poll) {
			CHECK(!pthread_mutex_lock(&rendezvous));
			poll_entered = true;
			CHECK(!pthread_cond_broadcast(&rendezvous_changed));
			while (!release_poll)
				CHECK(!pthread_cond_wait(&rendezvous_changed, &rendezvous));
			CHECK(!pthread_mutex_unlock(&rendezvous));
			map->hold_poll = false;
		}
		if (map->complete_at && map->polls == map->complete_at)
			publish_completion();
	}
	if (map->fail_at == map->accesses)
		return map->failure;
	*value = map->ctrl[index];
	return 0;
}

#define regmap_read_poll_timeout_atomic(map, address, value, condition, delay, timeout) \
({ \
	int poll_result = -ETIMEDOUT; \
	(void)(delay); (void)(timeout); \
	for (unsigned int poll_attempt = 0; poll_attempt < 4; poll_attempt++) { \
		poll_result = regmap_read(map, address, &(value)); \
		if (poll_result || (condition)) break; \
		poll_result = -ETIMEDOUT; \
	} \
	poll_result; \
})

static void dma_wmb(void)
{
	CHECK(transport_lock_held);
	registers.write_barriers++;
}

static void __attribute__((unused)) dma_rmb(void)
{
	CHECK(transport_lock_held && registers.visible_pending);
	CHECK(registers.ctrl[3] & MBOX_MSG_DONE);
	registers.read_barriers++;
	memcpy(bounce, registers.response, registers.bytes);
	registers.visible_pending = false;
}

#include "__airoha_npu_send_msg.inc"
#include "airoha_npu_send_msg.inc"
#include "airoha_npu_wlan_short_guard_ready.inc"

static bool of_property_read_bool(void *node, const char *name)
{
	CHECK(node == device.of_node);
	CHECK(!strcmp(name, "airoha,connac2-rebuilt-ram-lab"));
	return true;
}

#include "airoha_npu_transaction.inc"

enum airoha_npu_wlan_set_cmd { TEST_WLAN_SET = 100 };
enum airoha_npu_wlan_get_cmd { TEST_WLAN_GET = 101 };
#define kzalloc(bytes, flags) ((void)(flags), calloc(1, bytes))
#define kfree(pointer) free(pointer)

#include "airoha_npu_wlan_msg_send.inc"
#include "airoha_npu_wlan_msg_get.inc"

static void fresh_boot(void)
{
	if (initialized) {
		CHECK(!pthread_mutex_destroy(&instance.npu.cores[0].lock));
		CHECK(!pthread_mutex_destroy(&instance.er.lock.native));
	}
	memset(&instance, 0, sizeof(instance));
	memset(&registers, 0, sizeof(registers));
	memset(bounce, 0x65, sizeof(bounce));
	instance.npu.dev = &device;
	instance.npu.regmap = &registers;
	instance.npu.cores[0].buf = bounce;
	instance.npu.cores[0].addr = 0x81000000;
	instance.npu.wlan_short_guard_started = true;
	instance.npu.wlan_short_guard_verified = true;
	CHECK(!pthread_mutex_init(&instance.npu.cores[0].lock, NULL));
	mutex_init(&instance.er.lock);
	registers.ctrl[3] = MBOX_MSG_DONE | FIELD_PREP(MBOX_MSG_STATUS, NPU_MBOX_SUCCESS);
	registers.ctrl[2] = 0x76543210;
	registers.complete_at = 2;
	registers.failure = -EIO;
	atomic_store(&lock_arrivals, 0);
	initialized = true;
}

static struct er_config config(u32 sport)
{
	return (struct er_config) {
		.dma = sport == ER_PON ? 0x01400000 : 0x01000000,
		.bytes = er_bytes(8), .epoch = 5, .count = 8,
		.sport = sport, .generation = 6,
	};
}

static int er_issue(u32 operation, u32 sport)
{
	struct er_message request = { .w = { ER_MAGIC, ER_ABI | operation << 16 } };
	struct er_config current = config(sport);

	if (operation != ER_QUERY)
		memcpy(request.w + 2, &current, sizeof(current));
	request.w[8] = (u32)-EINPROGRESS;
	return airoha_npu_er_command(&instance.npu, &request);
}

static int auth_query(void)
{
	struct npu_auth_message request = { .w = {
		[AM_MAGIC] = AUTH_MBOX_MAGIC, [AM_ABI_OP] = AUTH_MBOX_ABI | AUTH_MBOX_QUERY << 16,
		[AM_BYTES] = AUTH_MBOX_BYTES, [AM_STATUS] = (u32)-EINPROGRESS,
	} };

	return airoha_npu_auth_command(&instance.npu, &request);
}

static int gate_query(void)
{
	struct npu_gate_message request = { .w = {
		[GM_MAGIC] = GATE_MAGIC, [GM_ABI_OP] = GATE_ABI | GATE_QUERY << 16,
		[GM_BYTES] = GATE_BYTES, [GM_STATUS] = (u32)-EINPROGRESS,
	} };

	return airoha_npu_gate_command(&instance.npu, &request);
}

static int raw_issue(int function)
{
	u32 request[4] = { 0x12345678, 0xfedcba98, 0x87654321, 0x01234567 };
	u32 reply[2] = { 0xdeadbeef, 0xdeadbeef };
	int result = __airoha_npu_send_msg(&instance.npu, function,
		request, sizeof(request), reply, sizeof(reply));

	if (!result) {
		CHECK(!memcmp(reply, registers.response + 2, sizeof(reply)));
		CHECK(registers.read_barriers > 0);
	} else {
		CHECK(reply[0] == 0xdeadbeef && reply[1] == 0xdeadbeef);
	}
	return result;
}

static void assert_quarantined(void)
{
	CHECK(instance.transport_quarantined);
	CHECK(!instance.npu.wlan_short_guard_started);
	CHECK(!instance.npu.wlan_short_guard_verified);
	CHECK(!airoha_npu_wlan_short_guard_ready(&instance.npu));
}

static void assert_all_blocked(void)
{
	u32 saved[SZ_8K / 4], payload = 0x12345678;
	unsigned int accesses = registers.accesses, triggers = registers.triggers;
	unsigned int barriers = registers.write_barriers;
	struct airoha_npu_er_exposure saved_sources[2];

	memcpy(saved, bounce, sizeof(saved));
	memcpy(saved_sources, instance.er.sources, sizeof(saved_sources));
	for (int function = NPU_FUNC_WIFI; function <= NPU_FUNC_PPE; function++)
		CHECK(raw_issue(function) == -ESHUTDOWN);
	CHECK(airoha_npu_send_msg(&instance.npu, NPU_FUNC_PPE, &payload, sizeof(payload)) == -ESHUTDOWN);
	CHECK(airoha_npu_wlan_msg_send(&instance.npu, 0, TEST_WLAN_SET,
		&payload, sizeof(payload), 0) == -ESHUTDOWN);
	CHECK(airoha_npu_wlan_msg_get(&instance.npu, 0, TEST_WLAN_GET,
		&payload, sizeof(payload), 0) == -ESHUTDOWN);
	CHECK(payload == 0x12345678);
	CHECK(auth_query() == -EOPNOTSUPP);
	CHECK(gate_query() == -EOPNOTSUPP);
	CHECK(er_issue(ER_QUERY, ER_PON) == -EOPNOTSUPP);
	for (unsigned int source = 0; source < ARRAY_SIZE(instance.er.sources); source++) {
		if (instance.er.sources[source].exposed) {
			u32 sport = instance.er.sources[source].config.sport;

			CHECK(er_issue(ER_STOP, sport) == -EOPNOTSUPP);
			CHECK(er_issue(ER_UNBIND, sport) < 0);
		}
	}
	CHECK(!memcmp(saved, bounce, sizeof(saved)));
	CHECK(!memcmp(saved_sources, instance.er.sources, sizeof(saved_sources)));
	CHECK(registers.accesses == accesses && registers.triggers == triggers);
	CHECK(registers.write_barriers == barriers);
}

static void successful_calls(void)
{
	u32 value = 0x12345678;

	fresh_boot();
	CHECK(raw_issue(NPU_FUNC_PPE) == 0);
	CHECK(registers.triggers == 1 && registers.polls == 2);
	CHECK(registers.read_barriers == 1);
	CHECK(raw_issue(NPU_FUNC_TUNNEL) == 0);
	CHECK(airoha_npu_send_msg(&instance.npu, NPU_FUNC_PPE, &value, sizeof(value)) == 0);
	CHECK(value == (0x12345678 ^ cpu_to_le32(0xa5c39e71)));
	CHECK(auth_query() == 0);
	CHECK(gate_query() == 0);
	CHECK(er_issue(ER_BIND, ER_PON) == 0);
	CHECK(er_issue(ER_BIND, ER_LAN1) == 0);
	CHECK(er_issue(ER_STOP, ER_PON) == 0);
	CHECK(er_issue(ER_UNBIND, ER_PON) == 0);
	CHECK(!instance.er.sources[1].exposed && instance.er.sources[0].exposed);
	CHECK(airoha_npu_wlan_msg_send(&instance.npu, 1, TEST_WLAN_SET, &value, sizeof(value), 0) == 0);
	CHECK(airoha_npu_wlan_msg_get(&instance.npu, 1, TEST_WLAN_GET, &value, sizeof(value), 0) == 0);
	CHECK(value == cpu_to_le32(0xa5c39e71));
	CHECK(!instance.transport_quarantined && airoha_npu_wlan_short_guard_ready(&instance.npu));
	fresh_boot();
	CHECK(__airoha_npu_send_msg(&instance.npu, 0, NULL, SZ_8K + 1, NULL, 0) == -EINVAL);
	CHECK(__airoha_npu_send_msg(&instance.npu, 0, &value, 4, &value, 8) == -EINVAL);
	CHECK(!registers.accesses && !registers.write_barriers);
}

static void setup_errors(void)
{
	const int errors[] = { -EIO, -EAGAIN, -ETIMEDOUT };

	for (unsigned int stage = 1; stage <= 5; stage++) {
		for (unsigned int side_effect = 0; side_effect < 2; side_effect++) {
			for (unsigned int fault = 0; fault < ARRAY_SIZE(errors); fault++) {
				fresh_boot();
				registers.fail_at = stage;
				registers.failure = errors[fault];
				registers.apply_failed_write = side_effect;
				CHECK(raw_issue(NPU_FUNC_WIFI) == errors[fault]);
				CHECK(registers.accesses == stage && registers.triggers == 0);
				CHECK(!instance.transport_quarantined);
				CHECK(airoha_npu_wlan_short_guard_ready(&instance.npu));
				registers.fail_at = 0;
				CHECK(raw_issue(NPU_FUNC_WIFI) == 0);
			}
		}
	}
	fresh_boot();
	registers.sticky_done = true;
	CHECK(raw_issue(NPU_FUNC_WIFI) == -EIO);
	CHECK(registers.triggers == 0 && !instance.transport_quarantined);
	registers.sticky_done = false;
	CHECK(raw_issue(NPU_FUNC_WIFI) == 0);
}

static void ambiguous_errors(void)
{
	const int errors[] = { -EIO, -EAGAIN, -ETIMEDOUT };

	for (unsigned int stage = 6; stage <= 8; stage++) {
		for (unsigned int side_effect = 0; side_effect < 2; side_effect++) {
			for (unsigned int fault = 0; fault < ARRAY_SIZE(errors); fault++) {
				fresh_boot();
				registers.fail_at = stage;
				registers.failure = errors[fault];
				registers.apply_failed_write = side_effect;
				CHECK(raw_issue(NPU_FUNC_WIFI) == errors[fault]);
				CHECK(registers.accesses == stage && !registers.read_barriers);
				assert_quarantined();
				assert_all_blocked();
			}
		}
	}
	fresh_boot();
	registers.nack = true;
	CHECK(raw_issue(NPU_FUNC_PPE) == -EINVAL);
	CHECK(!instance.transport_quarantined && !registers.read_barriers);
	registers.nack = false;
	CHECK(raw_issue(NPU_FUNC_PPE) == 0);
	fresh_boot();
	CHECK(er_issue(ER_BIND, ER_PON) == 0);
	registers.firmware_error = -EAGAIN;
	CHECK(er_issue(ER_STOP, ER_PON) == -EAGAIN);
	CHECK(instance.er.sources[1].exposed && !instance.er.sources[1].stopped);
	CHECK(!instance.transport_quarantined);
	registers.firmware_error = 0;
	CHECK(er_issue(ER_STOP, ER_PON) == 0);
	CHECK(er_issue(ER_UNBIND, ER_PON) == 0);
}

static void late_ack_and_exposure(void)
{
	for (u32 operation = ER_BIND; operation <= ER_UNBIND; operation++) {
		fresh_boot();
		CHECK(er_issue(ER_BIND, ER_LAN1) == 0);
		if (operation != ER_BIND)
			CHECK(er_issue(ER_BIND, ER_PON) == 0);
		if (operation == ER_UNBIND)
			CHECK(er_issue(ER_STOP, ER_PON) == 0);
		registers.complete_at = 0;
		CHECK(er_issue(operation, ER_PON) == -ETIMEDOUT);
		CHECK(instance.er.sources[0].exposed && instance.er.sources[1].exposed);
		CHECK(instance.er.sources[1].stopped == (operation == ER_UNBIND));
		assert_quarantined();
		assert_all_blocked();
		publish_completion();
		memcpy(bounce, registers.response, registers.bytes);
		registers.visible_pending = false;
		assert_all_blocked();
		WRITE_ONCE(instance.npu.wlan_short_guard_started, true);
		WRITE_ONCE(instance.npu.wlan_short_guard_verified, true);
		CHECK(!airoha_npu_wlan_short_guard_ready(&instance.npu));
		assert_all_blocked();
	}
	fresh_boot();
	CHECK(raw_issue(NPU_FUNC_WIFI) == 0);
}

static void each_caller_freezes_transport(void)
{
	for (unsigned int caller = 0; caller < 5; caller++) {
		u32 value = 0x12345678;
		int result;

		fresh_boot();
		registers.complete_at = 0;
		switch (caller) {
		case 0: result = auth_query(); break;
		case 1: result = gate_query(); break;
		case 2: result = er_issue(ER_QUERY, ER_PON); break;
		case 3: result = airoha_npu_wlan_msg_send(&instance.npu, 0,
			TEST_WLAN_SET, &value, sizeof(value), 0); break;
		default: result = airoha_npu_wlan_msg_get(&instance.npu, 0,
			TEST_WLAN_GET, &value, sizeof(value), 0); break;
		}
		CHECK(result == -ETIMEDOUT);
		assert_quarantined();
		assert_all_blocked();
	}
}

static void *concurrent_sender(void *argument)
{
	int *result = argument;

	*result = raw_issue(NPU_FUNC_TUNNEL);
	return NULL;
}

static void queued_caller_is_blocked(void)
{
	pthread_t first, second;
	int first_result = 0, second_result = 0;

	fresh_boot();
	registers.complete_at = 0;
	registers.hold_poll = true;
	poll_entered = release_poll = false;
	CHECK(!pthread_create(&first, NULL, concurrent_sender, &first_result));
	CHECK(!pthread_mutex_lock(&rendezvous));
	while (!poll_entered)
		CHECK(!pthread_cond_wait(&rendezvous_changed, &rendezvous));
	CHECK(!pthread_create(&second, NULL, concurrent_sender, &second_result));
	while (atomic_load(&lock_arrivals) < 2)
		sched_yield();
	release_poll = true;
	CHECK(!pthread_cond_broadcast(&rendezvous_changed));
	CHECK(!pthread_mutex_unlock(&rendezvous));
	CHECK(!pthread_join(first, NULL));
	CHECK(!pthread_join(second, NULL));
	CHECK(first_result == -ETIMEDOUT && second_result == -ESHUTDOWN);
	CHECK(registers.triggers == 1 && registers.write_barriers == 1);
	assert_quarantined();
	assert_all_blocked();
}

int main(void)
{
	successful_calls();
	setup_errors();
	ambiguous_errors();
	late_ack_and_exposure();
	each_caller_freezes_transport();
	queued_caller_is_blocked();
	CHECK(!pthread_mutex_destroy(&instance.npu.cores[0].lock));
	CHECK(!pthread_mutex_destroy(&instance.er.lock.native));
	printf("passed %u checks: production sender, regmap faults, late ACK, ER retention, shared callers, locking\n",
	       atomic_load(&checks));
	return 0;
}
