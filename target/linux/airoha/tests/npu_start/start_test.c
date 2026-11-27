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
#define EPROBE_DEFER 517
#define __iomem
#define CONFIG_NET_AIROHA 0
#define CONFIG_NET_AIROHA_NPU 1
#define CONFIG_COMMON_CLK_EN7523 2
#define CONFIG_OF_DYNAMIC 3
#define CONFIG_OF_OVERLAY 4
#define CONFIG_KEXEC 5
#define CONFIG_KEXEC_FILE 6
#define OF_DYNAMIC 1
#define OF_DETACHED 2
#define DL_FLAG_AUTOREMOVE_SUPPLIER 4
#define THIS_MODULE NULL
#define NPU_NUM_CORES 8
#define NPU_EN7581_FIRMWARE_RV32_MAX_SIZE 0x200000
#define WLAN_FUNC_GET_WAIT_NPU_VERSION 15
#define GFP_KERNEL 0
#define REG_CR_NPU_MIB(index) (0x100 + (index) * 4)
#define REG_CR_BOOT_BASE(index) (0x200 + (index) * 4)
#define REG_CR_BOOT_CONFIG 0x300
#define REG_CR_BOOT_TRIGGER 0x304
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))
#define smp_store_release(target, value) (*(target) = (value))
#define IS_BUILTIN(option) (configuration[option] == 1)
#define IS_ENABLED(option) (configuration[option] != 0)
#define ERR_PTR(error) ((void *)(intptr_t)(error))
#define PTR_ERR(pointer) ((intptr_t)(pointer))
#define IS_ERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#define dev_info(...) ((void)0)
#define dev_warn(...) ((void)0)
#define dev_err(...) ((void)0)

static atomic_uint checks;
#define CHECK(condition) do { assert(condition); atomic_fetch_add(&checks, 1); } while (0)

struct device_node {
	struct device_node *parent;
	const char *name;
	int references;
	unsigned int flags;
	bool available, rebuilt, ethernet;
};
struct device_driver { void *owner; bool suppress_bind_attrs; };
struct device {
	struct device_node *of_node;
	struct device_driver *driver;
	pthread_mutex_t lock;
	bool held, bound;
};
struct platform_device { struct device dev; void *data; int references; };
struct airoha_npu {
	struct device *dev;
	void *regmap;
	bool wlan_short_guard_started, wlan_short_guard_verified;
};

#include "airoha_npu_er_provider.h"

struct resource { uint64_t start; };
static struct device_driver resident_driver;
static struct device_node root_node, npu_node, eth_node;
static struct platform_device provider_device;
static struct device consumer;
static struct airoha_npu_instance fixture;
static int configuration[7], module_refs;
static unsigned int writes, triggers, pool_calls, loads, links;
static int fail_write, pool_error, load_error, action_error;
static bool missing_node, missing_device, missing_module, fail_link, ct_profile;
static bool pool_quarantine, initialized;
static u32 register_values[256];
static pthread_mutex_t race_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t race_condition = PTHREAD_COND_INITIALIZER;
static bool pause_boot, boot_waiting, release_boot;

static struct device_node *of_node_get(struct device_node *node)
{
	if (node)
		node->references++;
	return node;
}
static void of_node_put(struct device_node *node)
{
	if (node)
		CHECK(--node->references >= 0);
}
static struct device_node *of_get_next_parent(struct device_node *node)
{
	struct device_node *parent = of_node_get(node->parent);

	of_node_put(node);
	return parent;
}
static bool of_node_check_flag(struct device_node *node, unsigned int flag)
{
	return node->flags & flag;
}
static bool of_device_is_available(struct device_node *node)
{
	return node->available;
}
static bool of_device_is_compatible(struct device_node *node, const char *name)
{
	CHECK(!strcmp(name, "airoha,en7581-eth"));
	return node && node->ethernet;
}
static bool of_property_read_bool(struct device_node *node, const char *name)
{
	CHECK(!strcmp(name, "airoha,connac2-rebuilt-ram-lab"));
	return node && node->rebuilt;
}
static struct device_node *of_parse_phandle(struct device_node *node, const char *name, int index)
{
	CHECK(node == &eth_node && !strcmp(name, "airoha,npu") && !index);
	return missing_node ? NULL : of_node_get(&npu_node);
}
static struct platform_device *of_find_device_by_node(struct device_node *node)
{
	CHECK(node == &npu_node);
	if (missing_device)
		return NULL;
	provider_device.references++;
	return &provider_device;
}
static int device_trylock(struct device *dev)
{
	if (pthread_mutex_trylock(&dev->lock))
		return 0;
	CHECK(!dev->held);
	dev->held = true;
	return 1;
}
static void device_unlock(struct device *dev)
{
	CHECK(dev->held);
	dev->held = false;
	CHECK(!pthread_mutex_unlock(&dev->lock));
}
static void device_lock_assert(struct device *dev)
{
	CHECK(dev->held);
}
static bool device_is_bound(struct device *dev)
{
	device_lock_assert(dev);
	return dev->bound;
}
static bool try_module_get(void *module)
{
	CHECK(!module);
	if (missing_module)
		return false;
	module_refs++;
	return true;
}
static void module_put(void *module)
{
	CHECK(!module && --module_refs >= 0);
}
static void platform_device_put(struct platform_device *pdev)
{
	CHECK(pdev == &provider_device && --pdev->references >= 0);
}
static void *platform_get_drvdata(struct platform_device *pdev)
{
	device_lock_assert(&pdev->dev);
	return pdev->data;
}
static void *device_link_add(struct device *dev, struct device *supplier, int flags)
{
	CHECK(dev == &consumer && supplier == &provider_device.dev);
	CHECK(flags == DL_FLAG_AUTOREMOVE_SUPPLIER);
	device_lock_assert(supplier);
	links++;
	return fail_link ? NULL : &links;
}
static int regmap_write(void *regmap, u32 address, u32 value)
{
	CHECK(regmap == register_values && address / 4 < ARRAY_SIZE(register_values));
	if (fixture.deferred_start) {
		device_lock_assert(&provider_device.dev);
		CHECK(provider_device.dev.bound && fixture.start_attempted);
	}
	writes++;
	if (address == REG_CR_BOOT_TRIGGER)
		triggers++;
	register_values[address / 4] = value;
	return writes == (unsigned int)fail_write ? -EIO : 0;
}
static void msleep(unsigned int delay)
{
	CHECK(delay == 100);
	pthread_mutex_lock(&race_lock);
	if (pause_boot && !boot_waiting) {
		boot_waiting = true;
		pthread_cond_broadcast(&race_condition);
		while (!release_boot)
			pthread_cond_wait(&race_condition, &race_lock);
	}
	pthread_mutex_unlock(&race_lock);
}
static void usleep_range(unsigned int low, unsigned int high)
{
	CHECK(low == 1000 && high == 2000);
}
static bool airoha_npu_is_connac2_ct(struct device *dev)
{
	CHECK(dev == &provider_device.dev);
	return ct_profile;
}
static bool airoha_npu_wlan_short_guard_ready(struct airoha_npu *npu)
{
	return npu->wlan_short_guard_started && npu->wlan_short_guard_verified &&
	       !fixture.transport_quarantined;
}
static void airoha_npu_wlan_short_guard_clear(void *data)
{
	struct airoha_npu *npu = data;

	npu->wlan_short_guard_started = npu->wlan_short_guard_verified = false;
}
static int airoha_npu_connac2_init_pool(struct airoha_npu *npu)
{
	CHECK(npu == &fixture.npu && triggers == 1);
	pool_calls++;
	if (pool_quarantine)
		fixture.transport_quarantined = true;
	return pool_error;
}
static int airoha_npu_wlan_msg_get(struct airoha_npu *npu, int band, int command,
				 void *data, int bytes, int flags)
{
	CHECK(npu == &fixture.npu && !band && command == WLAN_FUNC_GET_WAIT_NPU_VERSION);
	CHECK(bytes == 4 && !flags);
	*(u32 *)data = 0x00020003;
	return 0;
}
static int airoha_npu_run_firmware(struct device *dev, void *base, struct resource *res)
{
	CHECK(dev == &provider_device.dev && !base && res->start == 0x84000000);
	loads++;
	return load_error;
}
static int devm_add_action_or_reset(struct device *dev, void (*action)(void *), void *data)
{
	CHECK(dev == &provider_device.dev && data == &fixture.npu);
	if (action_error)
		action(data);
	return action_error;
}

#include "airoha_npu_start.h"
#include "get.inc"
#include "shutdown.inc"

static void reset(void)
{
	if (initialized) {
		CHECK(!provider_device.references && !module_refs);
		CHECK(!root_node.references && !npu_node.references && !eth_node.references);
		CHECK(!pthread_mutex_destroy(&provider_device.dev.lock));
		CHECK(!pthread_mutex_destroy(&consumer.lock));
	}
	memset(&fixture, 0, sizeof(fixture));
	resident_driver = (struct device_driver) { .suppress_bind_attrs = true };
	root_node = (struct device_node) { .available = true };
	npu_node = (struct device_node) { .parent = &root_node, .available = true,
		.rebuilt = true, .name = "npu" };
	eth_node = (struct device_node) { .parent = &root_node, .available = true,
		.ethernet = true };
	provider_device = (struct platform_device) { .dev = { .of_node = &npu_node,
		.driver = &resident_driver, .bound = true }, .data = &fixture.npu };
	consumer = (struct device) { .of_node = &eth_node, .driver = &resident_driver,
		.bound = true };
	CHECK(!pthread_mutex_init(&provider_device.dev.lock, NULL));
	CHECK(!pthread_mutex_init(&consumer.lock, NULL));
	configuration[0] = configuration[1] = configuration[2] = 1;
	for (unsigned int index = 3; index < ARRAY_SIZE(configuration); index++)
		configuration[index] = 0;
	fixture.npu.dev = &provider_device.dev;
	fixture.npu.regmap = register_values;
	fixture.deferred_start = ct_profile = true;
	writes = triggers = pool_calls = loads = links = 0;
	fail_write = pool_error = load_error = action_error = 0;
	missing_node = missing_device = missing_module = fail_link = false;
	pool_quarantine = pause_boot = boot_waiting = release_boot = false;
	initialized = true;
}
static int prepare(void)
{
	struct resource res = { .start = 0x84000000 };

	return airoha_npu_prepare_firmware(&fixture.npu, NULL, &res);
}
static intptr_t get_result(void)
{
	struct airoha_npu *npu = airoha_npu_get(&consumer);

	if (IS_ERR(npu))
		return PTR_ERR(npu);
	CHECK(npu == &fixture.npu);
	module_put(NULL);
	platform_device_put(&provider_device);
	return 0;
}
static void normal(void)
{
	reset();
	provider_device.dev.bound = false;
	CHECK(!prepare());
	CHECK(loads == 1 && writes == 0 && !fixture.start_attempted);
	CHECK(get_result() == -EPROBE_DEFER && writes == 0);
	provider_device.dev.bound = true;
	CHECK(!get_result());
	CHECK(writes == 14 && triggers == 1 && pool_calls == 1);
	CHECK(fixture.boot_address == 0x84000000 && !fixture.start_error);
	CHECK(airoha_npu_wlan_short_guard_ready(&fixture.npu));
	for (unsigned int iteration = 0; iteration < 10; iteration++)
		CHECK(!get_result());
	CHECK(writes == 14 && pool_calls == 1);
	CHECK(device_trylock(&provider_device.dev));
	airoha_npu_shutdown(&provider_device);
	device_unlock(&provider_device.dev);
	CHECK(get_result() == -ESHUTDOWN && writes == 14);
}
static void failures(void)
{
	for (unsigned int stage = 1; stage <= 14; stage++) {
		reset();
		CHECK(!prepare());
		fail_write = stage;
		CHECK(get_result() == -EIO);
		CHECK(fixture.start_attempted && fixture.start_error == -EIO);
		CHECK(!airoha_npu_wlan_short_guard_ready(&fixture.npu));
		fail_write = 0;
		CHECK(get_result() == -EIO && writes == stage);
		CHECK(!links && !pool_calls);
	}
	reset();
	CHECK(!prepare());
	pool_error = -ETIMEDOUT;
	pool_quarantine = true;
	CHECK(get_result() == -ETIMEDOUT);
	CHECK(get_result() == -ESHUTDOWN && pool_calls == 1);
	reset();
	CHECK(!prepare());
	pool_error = -EINVAL;
	CHECK(get_result() == -EINVAL);
	pool_error = 0;
	CHECK(get_result() == -EINVAL && pool_calls == 1);
	reset();
	load_error = -ENOENT;
	CHECK(prepare() == -ENOENT && !writes);
	reset();
	action_error = -ENOMEM;
	CHECK(prepare() == -ENOMEM && !writes);
	reset();
	CHECK(!prepare());
	fail_link = true;
	CHECK(get_result() == -EINVAL && triggers == 1);
	fail_link = false;
	CHECK(!get_result() && triggers == 1);
}
static void eligibility(void)
{
	for (unsigned int option = 0; option < ARRAY_SIZE(configuration); option++) {
		reset();
		CHECK(!prepare());
		configuration[option] = option < 3 ? 2 : 1;
		CHECK(get_result() == -EOPNOTSUPP && !writes);
	}
	for (unsigned int node = 0; node < 3; node++) {
		for (unsigned int fault = 0; fault < 3; fault++) {
			struct device_node *target;

			reset();
			CHECK(!prepare());
			target = node == 0 ? &root_node : node == 1 ? &npu_node : &eth_node;
			if (fault < 2)
				target->flags = fault ? OF_DETACHED : OF_DYNAMIC;
			else
				target->available = false;
			CHECK(get_result() == -EOPNOTSUPP && !writes);
		}
	}
	for (unsigned int scenario = 0; scenario < 7; scenario++) {
		reset();
		CHECK(!prepare());
		if (scenario == 0) missing_node = true;
		if (scenario == 1) missing_device = true;
		if (scenario == 2) missing_module = true;
		if (scenario == 3) provider_device.data = NULL;
		if (scenario == 4) consumer.bound = false;
		if (scenario == 5) resident_driver.owner = &resident_driver;
		if (scenario == 6) resident_driver.suppress_bind_attrs = false;
		CHECK(get_result() == (scenario < 4 ? -ENODEV : scenario == 4 ?
			-EPROBE_DEFER : -EOPNOTSUPP));
		CHECK(!writes);
	}
}
static void legacy(void)
{
	reset();
	fixture.deferred_start = npu_node.rebuilt = false;
	CHECK(!prepare() && writes == 14);
	CHECK(!get_result() && writes == 14);
	reset();
	fixture.deferred_start = npu_node.rebuilt = false;
	ct_profile = false;
	CHECK(!prepare() && writes == 14 && !pool_calls);
}
static void *first_get(void *unused)
{
	(void)unused;
	CHECK(!get_result());
	return NULL;
}
static void concurrency(void)
{
	pthread_t thread;

	reset();
	CHECK(!prepare());
	pause_boot = true;
	CHECK(!pthread_create(&thread, NULL, first_get, NULL));
	pthread_mutex_lock(&race_lock);
	while (!boot_waiting)
		pthread_cond_wait(&race_condition, &race_lock);
	CHECK(get_result() == -EPROBE_DEFER);
	release_boot = true;
	pthread_cond_broadcast(&race_condition);
	pthread_mutex_unlock(&race_lock);
	CHECK(!pthread_join(thread, NULL));
	CHECK(!get_result() && triggers == 1 && pool_calls == 1);
	CHECK(device_trylock(&provider_device.dev));
	CHECK(get_result() == -EPROBE_DEFER);
	device_unlock(&provider_device.dev);
}
int main(void)
{
	normal();
	failures();
	eligibility();
	legacy();
	concurrency();
	reset();
	printf("passed %u checks: prepare, start, failures, references, configuration, concurrency\n", checks);
	return 0;
}
