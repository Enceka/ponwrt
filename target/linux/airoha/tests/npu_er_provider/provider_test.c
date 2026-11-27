#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef uint32_t __le32;

#ifdef TEST_SWAPPED_ENDIAN
#define cpu_to_le32(value) __builtin_bswap32((u32)(value))
#define le32_to_cpu(value) __builtin_bswap32((u32)(value))
#else
#define cpu_to_le32(value) ((u32)(value))
#define le32_to_cpu(value) ((u32)(value))
#endif

#define NPU_OP_SET 1
#define NPU_FUNC_WIFI 0
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))

#include "airoha_npu_transaction.h"

struct device { void *of_node; };
struct airoha_npu {
	struct device *dev;
};

#include "airoha_npu_er_provider.h"

static struct device device;
static struct airoha_npu_instance fixture = { .npu = { &device } };
static bool ready = true, property = true;
static atomic_uint checks, calls;
static _Thread_local int send_error, firmware_error, corrupt_word = -1;
static _Thread_local u32 corrupt_value;

#define CHECK(condition) do { assert(condition); atomic_fetch_add(&checks, 1); } while (0)

static bool airoha_npu_wlan_short_guard_ready(struct airoha_npu *instance)
{
	CHECK(instance == &fixture.npu);
	return ready;
}

static bool of_property_read_bool(void *node, const char *name)
{
	CHECK(node == device.of_node);
	CHECK(!strcmp(name, "airoha,connac2-rebuilt-ram-lab"));
	return property;
}

static int __airoha_npu_send_msg(struct airoha_npu *instance, int function,
				 const void *data, int bytes, void *response,
				 u16 reply_bytes)
{
	const __le32 *packet = data;
	__le32 *reply = response;
	struct er_config config;
	u32 words[16], op;

	CHECK(instance == &fixture.npu && function == NPU_FUNC_WIFI);
	CHECK(bytes == 72 && reply_bytes == 64);
	CHECK(packet[0] == cpu_to_le32(0x10));
	CHECK(packet[1] == cpu_to_le32(ER_FUNC));
	lockdep_assert_held(&fixture.er.lock);
	for (u32 index = 0; index < 16; index++)
		words[index] = le32_to_cpu(packet[index + 2]);
	op = words[1] >> 16;
	memcpy(&config, words + 2, sizeof(config));
	if (op == ER_BIND) {
		struct airoha_npu_er_exposure *source = airoha_npu_er_source(&fixture.er, config.sport);

		CHECK(source->exposed && !source->stopped);
		CHECK(!memcmp(&source->config, &config, sizeof(config)));
	}
	atomic_fetch_add(&calls, 1);
	if (send_error)
		return send_error;
	words[8] = firmware_error;
	words[9] = ER_CAPS | ER_CAP_SOURCES;
	words[10] = ER_IDLE;
	words[11] = op == ER_QUERY ? UINT32_MAX : 0;
	words[12] = words[13] = words[14] = words[15] = 0;
	if (corrupt_word >= 0)
		words[corrupt_word] = corrupt_value;
	for (u32 index = 0; index < 16; index++)
		reply[index] = cpu_to_le32(words[index]);
	return 0;
}

#include "airoha_npu_transaction.inc"

#define provider fixture.er
#define npu fixture.npu

static struct er_config configuration(u32 sport, u32 epoch)
{
	return (struct er_config) {
		.dma = 0x01000000 + (sport == ER_PON ? 0x200000 : 0),
		.bytes = er_bytes(8), .epoch = epoch, .count = 8,
		.sport = sport, .generation = epoch + 1,
	};
}

static struct er_message message(u32 op, const struct er_config *config)
{
	struct er_message result = { .w = { ER_MAGIC, ER_ABI | op << 16 } };

	if (config)
		memcpy(result.w + 2, config, sizeof(*config));
	result.w[8] = (u32)-EINPROGRESS;
	return result;
}

static int issue(u32 op, const struct er_config *config)
{
	struct er_message request = message(op, config), original = request;
	int result = airoha_npu_er_command(&npu, &request);

	if (result && result != firmware_error)
		CHECK(!memcmp(&request, &original, sizeof(request)));
	return result;
}

static void reset(void)
{
	memset(provider.sources, 0, sizeof(provider.sources));
	send_error = firmware_error = 0;
	corrupt_word = -1;
	ready = property = true;
}

static void retire(const struct er_config *config)
{
	CHECK(issue(ER_STOP, config) == 0);
	CHECK(issue(ER_UNBIND, config) == 0);
	CHECK(!airoha_npu_er_source(&provider, config->sport)->exposed);
}

static void lifecycle(void)
{
	struct er_config lan = configuration(ER_LAN1, 1), pon = configuration(ER_PON, 1);
	u32 before;

	reset();
	CHECK(issue(ER_QUERY, NULL) == 0);
	CHECK(issue(ER_BIND, &lan) == 0);
	CHECK(issue(ER_BIND, &pon) == 0);
	before = calls;
	CHECK(issue(ER_BIND, &lan) == -EBUSY);
	CHECK(issue(ER_UNBIND, &lan) == -EBUSY);
	CHECK(calls == before);
	retire(&lan);
	CHECK(provider.sources[1].exposed);
	CHECK(issue(ER_BIND, &lan) == -ESTALE);
	CHECK(issue(ER_STOP, &lan) == 0);
	CHECK(issue(ER_UNBIND, &lan) == 0);
	lan.epoch++;
	lan.generation++;
	CHECK(issue(ER_BIND, &lan) == 0);
	retire(&lan);
	retire(&pon);
	CHECK(issue(ER_QUERY, &pon) == 0);
}

static void identities(void)
{
	for (u32 source = 0; source < 2; source++) {
		for (u32 word = 0; word < 6; word++) {
			struct er_config config = configuration(source ? ER_PON : ER_LAN1, 10);
			struct er_config wrong = config;
			u32 values[6], before;

			reset();
			CHECK(issue(ER_BIND, &config) == 0);
			memcpy(values, &wrong, sizeof(values));
			values[word] ^= word == 0 ? 64 : word == 4 ? 26 : 1;
			memcpy(&wrong, values, sizeof(wrong));
			before = calls;
			CHECK(issue(ER_STOP, &wrong) < 0);
			CHECK(issue(ER_UNBIND, &wrong) < 0);
			CHECK(calls == before);
			CHECK(airoha_npu_er_source(&provider, config.sport)->exposed);
			retire(&config);
		}
	}
	for (u32 aperture = 0; aperture < 4; aperture++) {
		for (u32 shift = 0; shift < 3; shift++) {
			struct er_config lan = configuration(ER_LAN1, 1), pon = configuration(ER_PON, 1);

			reset();
			pon.dma = (lan.dma + (shift == 0 ? 0 : shift == 1 ? 64 : -64)) |
				  aperture * ER_WINDOW;
			CHECK(issue(ER_BIND, &lan) == 0);
			CHECK(issue(ER_BIND, &pon) == -EEXIST);
			retire(&lan);
			CHECK(issue(ER_BIND, &pon) == 0);
			retire(&pon);
		}
	}
	for (u32 source = 0; source < 2; source++) {
		struct er_config first = configuration(source ? ER_PON : ER_LAN1, 1);
		struct er_config second = configuration(source ? ER_LAN1 : ER_PON, 1);

		reset();
		second.dma = first.dma + first.bytes;
		CHECK(issue(ER_BIND, &first) == 0);
		CHECK(issue(ER_BIND, &second) == 0);
		retire(&first);
		retire(&second);
	}
}

static void failure_retention(void)
{
	const int errors[] = { -ETIMEDOUT, -EIO, -EAGAIN, -EINVAL };

	for (u32 operation = ER_BIND; operation <= ER_UNBIND; operation++) {
		for (u32 kind = 0; kind < 2; kind++) {
			for (u32 index = 0; index < ARRAY_SIZE(errors); index++) {
				struct er_config config = configuration(ER_PON, 9);

				reset();
				if (operation != ER_BIND)
					CHECK(issue(ER_BIND, &config) == 0);
				if (operation == ER_UNBIND)
					CHECK(issue(ER_STOP, &config) == 0);
				if (kind)
					firmware_error = errors[index];
				else
					send_error = errors[index];
				CHECK(issue(operation, &config) == errors[index]);
				CHECK(provider.sources[1].exposed);
				CHECK(provider.sources[1].stopped == (operation == ER_UNBIND));
				send_error = firmware_error = 0;
				CHECK(issue(ER_BIND, &config) == -EBUSY);
				CHECK(issue(ER_QUERY, NULL) == 0);
				CHECK(provider.sources[1].exposed);
				retire(&config);
			}
		}
	}
	for (u32 operation = ER_BIND; operation <= ER_UNBIND; operation++) {
		for (u32 word = 0; word < 16; word++) {
			struct er_config config = configuration(ER_LAN1, 5);
			struct er_message original = message(operation, &config);

			if (word == 11)
				continue;
			reset();
			if (operation != ER_BIND)
				CHECK(issue(ER_BIND, &config) == 0);
			if (operation == ER_UNBIND)
				CHECK(issue(ER_STOP, &config) == 0);
			corrupt_word = word;
			corrupt_value = word < 8 ? original.w[word] ^ 1 : word == 10 ? ER_COPYING : 1;
			CHECK(issue(operation, &config) == -EPROTO);
			CHECK(provider.sources[0].exposed);
			CHECK(provider.sources[0].stopped == (operation == ER_UNBIND));
			corrupt_word = -1;
			retire(&config);
		}
	}
}

static void malformed(void)
{
	struct er_config config = configuration(ER_LAN1, 1);
	struct er_message request = message(ER_BIND, &config);
	u32 before;

	reset();
	before = calls;
	request.w[0]++;
	CHECK(airoha_npu_er_command(&npu, &request) == -EINVAL);
	request = message(ER_BIND, &config);
	request.w[1]++;
	CHECK(airoha_npu_er_command(&npu, &request) == -EINVAL);
	CHECK(issue(4, &config) == -EINVAL);
	CHECK(issue(ER_BIND, NULL) == -EINVAL);
	CHECK(issue(ER_STOP, &config) == -ESTALE);
	CHECK(airoha_npu_er_command(NULL, &request) == -EOPNOTSUPP);
	CHECK(airoha_npu_er_command(&npu, NULL) == -EOPNOTSUPP);
	CHECK(calls == before);
	for (u32 field = 0; field < 6; field++) {
		struct er_message invalid = message(ER_BIND, &config);

		invalid.w[field + 2] = 0;
		CHECK(airoha_npu_er_command(&npu, &invalid) == -EINVAL);
	}
	CHECK(calls == before);
	ready = false;
	CHECK(issue(ER_BIND, &config) == -EOPNOTSUPP);
	CHECK(provider.sources[0].exposed);
	ready = true;
	retire(&config);
}

struct race {
	pthread_mutex_t lock;
	pthread_cond_t condition;
	u32 arrived;
	bool start;
};

struct participant {
	struct race *race;
	struct er_config config;
	int result;
};

static void *race_bind(void *argument)
{
	struct participant *participant = argument;
	struct race *race = participant->race;

	pthread_mutex_lock(&race->lock);
	race->arrived++;
	pthread_cond_broadcast(&race->condition);
	while (!race->start)
		pthread_cond_wait(&race->condition, &race->lock);
	pthread_mutex_unlock(&race->lock);
	participant->result = issue(ER_BIND, &participant->config);
	return NULL;
}

static void concurrency(void)
{
	for (u32 iteration = 0; iteration < 64; iteration++) {
		struct race race = { .lock = PTHREAD_MUTEX_INITIALIZER,
			.condition = PTHREAD_COND_INITIALIZER };
		struct participant participants[2] = {
			{ &race, configuration(ER_LAN1, 1), 0 },
			{ &race, configuration(iteration & 1 ? ER_PON : ER_LAN1, 1), 0 },
		};
		pthread_t threads[2];
		u32 winner;

		reset();
		participants[1].config.dma = participants[0].config.dma | ER_WINDOW;
		for (u32 index = 0; index < 2; index++)
			CHECK(!pthread_create(&threads[index], NULL, race_bind, &participants[index]));
		pthread_mutex_lock(&race.lock);
		while (race.arrived != 2)
			pthread_cond_wait(&race.condition, &race.lock);
		race.start = true;
		pthread_cond_broadcast(&race.condition);
		pthread_mutex_unlock(&race.lock);
		for (u32 index = 0; index < 2; index++)
			CHECK(!pthread_join(threads[index], NULL));
		CHECK((participants[0].result == 0) != (participants[1].result == 0));
		winner = participants[0].result ? 1 : 0;
		CHECK(participants[!winner].result == (iteration & 1 ? -EEXIST : -EBUSY));
		retire(&participants[winner].config);
		CHECK(!pthread_cond_destroy(&race.condition));
		CHECK(!pthread_mutex_destroy(&race.lock));
	}
}

int main(void)
{
	mutex_init(&provider.lock);
	lifecycle();
	identities();
	failure_retention();
	malformed();
	concurrency();
	CHECK(!pthread_mutex_destroy(&provider.lock.native));
	printf("checks=%u mailbox_calls=%u races=64\n", checks, calls);
	return 0;
}
