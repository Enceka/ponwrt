#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define EPROBE_DEFER 517
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
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define IS_BUILTIN(option) (configuration[option] == 1)
#define IS_ENABLED(option) (configuration[option] != 0)
#define ERR_PTR(error) ((void *)(intptr_t)(error))
#define PTR_ERR(pointer) ((intptr_t)(pointer))
#define IS_ERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#define READ_ONCE(value) (value)
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
#define dev_err(...) ((void)0)

enum { ROOT, SOC, NPU, ETH, SCU, CHIP, WLAN, EXTRA, NODE_COUNT };
enum { CLOCKS, POWER, IOMMUS, INTERCONNECTS, PHYS, HWLOCKS, RESETS, PROPERTY_COUNT };
static unsigned int checks, cases;
#define CHECK(condition) do { assert(condition); checks++; } while (0)

struct device_node {
	struct device_node *parent;
	const char *name, *compatible;
	int references;
	unsigned int flags, properties;
	bool available, rebuilt, syscon;
	int simple_bus_index;
};
struct of_device_id { const char *compatible; const void *data; };
struct device_driver { const char *name; void *owner; bool suppress_bind_attrs;
	const struct of_device_id *of_match_table; };
struct bus_type { int unused; };
struct device {
	struct device_node *of_node;
	struct device_driver *driver;
	struct device *parent;
	const struct bus_type *bus;
	pthread_mutex_t lock;
	bool held, registered, bound;
	int references;
	bool driver_override;
};
struct platform_device { struct device dev; void *data; };
#define to_platform_device(pointer) container_of(pointer, struct platform_device, dev)
struct of_phandle_args { struct device_node *np; int args_count; unsigned int args[1]; };
struct regmap { int unused; };
struct airoha_npu { struct device *dev; };
struct airoha_npu_instance {
	struct airoha_npu npu;
	bool transport_quarantined, stopping, deferred_start, start_attempted;
	int start_error;
};

static const struct bus_type platform_bus_type, other_bus;
static struct device platform_bus;
static struct device_node nodes[NODE_COUNT];
static struct platform_device devices[NODE_COUNT];
static struct device_driver drivers[NODE_COUNT];
static struct of_device_id parent_match;
static struct airoha_npu_instance instance;
static struct device_node *reset_nodes[8], *npu_target, *chip_target;
static struct regmap syscon_map;
static bool present[NODE_COUNT], initialized, scu_link, eth_link;
static bool duplicate_eth, fail_module, fail_scu_link, fail_consumer_link;
static int configuration[7], module_refs, reset_count, reset_names, reset_fail;
static int reset_args[8], missing_reset_name, syscon_error, boot_error;
static unsigned int boots, guard_clears, scu_links, consumer_links;

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
static struct device_node *of_get_parent(struct device_node *node)
{
	return of_node_get(node->parent);
}
static struct device_node *of_get_next_parent(struct device_node *node)
{
	struct device_node *parent = of_get_parent(node);

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
	return node && (!strcmp(node->compatible, name) ||
		       (node->syscon && !strcmp(name, "syscon")));
}
static bool of_node_name_eq(struct device_node *node, const char *name)
{
	return node && !strcmp(node->name, name);
}
static bool of_property_present(struct device_node *node, const char *name)
{
	static const char * const properties[] = {
		"clocks", "power-domains", "iommus", "interconnects", "phys", "hwlocks", "resets",
	};
	unsigned int index;

	for (index = 0; index < ARRAY_SIZE(properties); index++)
		if (!strcmp(name, properties[index]))
			return node->properties & (1u << index);
	CHECK(false);
	return false;
}
static bool of_property_read_bool(struct device_node *node, const char *name)
{
	CHECK(!strcmp(name, "airoha,connac2-rebuilt-ram-lab"));
	return node && node->rebuilt;
}
static struct device_node *of_parse_phandle(struct device_node *node, const char *name, int index)
{
	CHECK(!index);
	if (!strcmp(name, "airoha,npu")) {
		CHECK(node == &nodes[ETH] || node == &nodes[WLAN]);
		return of_node_get(npu_target);
	}
	CHECK(node == &nodes[SCU] && !strcmp(name, "airoha,chip-scu"));
	return of_node_get(chip_target);
}
static struct device_node *of_find_compatible_node(struct device_node *from,
						   const char *type, const char *compatible)
{
	struct device_node *result = NULL;

	CHECK(!type && !strcmp(compatible, "airoha,en7581-eth"));
	if (!from)
		result = &nodes[ETH];
	else if (duplicate_eth && from == &nodes[ETH])
		result = &nodes[EXTRA];
	of_node_put(from);
	return of_node_get(result);
}
static int of_count_phandle_with_args(struct device_node *node, const char *name, const char *cells)
{
	CHECK(node == &nodes[ETH] && !strcmp(name, "resets") && !strcmp(cells, "#reset-cells"));
	return reset_count;
}
static int of_property_count_strings(struct device_node *node, const char *name)
{
	CHECK(node == &nodes[ETH] && !strcmp(name, "reset-names"));
	return reset_names;
}
static int of_property_match_string(struct device_node *node, const char *property, const char *name)
{
	static const char * const names[] = { "fe", "pdma", "qdma" };
	unsigned int index;

	if (!strcmp(property, "compatible")) {
		CHECK(!strcmp(name, "simple-bus"));
		return node->simple_bus_index;
	}
	CHECK(node == &nodes[ETH] && !strcmp(property, "reset-names"));
	for (index = 0; index < ARRAY_SIZE(names); index++)
		if (!strcmp(names[index], name))
			return missing_reset_name == (int)index ? -EINVAL : (int)index;
	CHECK(false);
	return -EINVAL;
}
static int of_parse_phandle_with_args(struct device_node *node, const char *name,
				      const char *cells, int index, struct of_phandle_args *args)
{
	CHECK(node == &nodes[ETH] && !strcmp(name, "resets") && !strcmp(cells, "#reset-cells"));
	CHECK(index >= 0 && index < 8);
	if (reset_fail == index)
		return -EINVAL;
	args->np = of_node_get(reset_nodes[index]);
	args->args_count = reset_args[index];
	args->args[0] = (unsigned int)index;
	return 0;
}
static struct device *get_device(struct device *dev)
{
	CHECK(dev);
	dev->references++;
	return dev;
}
static void put_device(struct device *dev)
{
	CHECK(dev && --dev->references >= 0);
}
static struct platform_device *of_find_device_by_node(struct device_node *node)
{
	unsigned int index;

	for (index = 0; index < NODE_COUNT; index++)
		if (node == &nodes[index] && present[index]) {
			get_device(&devices[index].dev);
			return &devices[index];
		}
	return NULL;
}
static void platform_device_put(struct platform_device *pdev)
{
	put_device(&pdev->dev);
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
static bool device_is_registered(struct device *dev)
{
	device_lock_assert(dev);
	return dev->registered;
}
static bool device_has_driver_override(struct device *dev)
{
	device_lock_assert(dev);
	return dev->driver_override;
}
static bool try_module_get(void *module)
{
	CHECK(!module);
	if (fail_module)
		return false;
	module_refs++;
	return true;
}
static void module_put(void *module)
{
	CHECK(!module && --module_refs >= 0);
}
static void *platform_get_drvdata(struct platform_device *pdev)
{
	device_lock_assert(&pdev->dev);
	return pdev->data;
}
static void *dev_get_drvdata(struct device *dev)
{
	return platform_get_drvdata(to_platform_device(dev));
}
static const struct of_device_id *of_match_device(const struct of_device_id *table,
						 struct device *dev)
{
	device_lock_assert(dev);
	return table;
}
static struct regmap *syscon_regmap_lookup_by_phandle(struct device_node *node, const char *name)
{
	CHECK(node == &nodes[SCU] && !strcmp(name, "airoha,chip-scu"));
	device_lock_assert(&devices[SCU].dev);
	device_lock_assert(&devices[CHIP].dev);
	CHECK(!devices[CHIP].dev.driver);
	return syscon_error ? ERR_PTR(syscon_error) : &syscon_map;
}
static void *device_link_add(struct device *consumer, struct device *supplier, int flags)
{
	CHECK(flags == DL_FLAG_AUTOREMOVE_SUPPLIER);
	device_lock_assert(supplier);
	if (consumer == &devices[NPU].dev) {
		CHECK(supplier == &devices[SCU].dev);
		device_lock_assert(consumer);
		scu_links++;
		if (fail_scu_link)
			return NULL;
		scu_link = true;
		return &scu_link;
	}
	CHECK(supplier == &devices[NPU].dev);
	consumer_links++;
	if (fail_consumer_link)
		return NULL;
	if (consumer == &devices[ETH].dev)
		eth_link = true;
	return &eth_link;
}
static int airoha_npu_boot(struct airoha_npu *npu)
{
	unsigned int index;

	CHECK(npu == &instance.npu && instance.start_attempted);
	CHECK(scu_link);
	for (index = SOC; index <= CHIP; index++)
		device_lock_assert(&devices[index].dev);
	device_lock_assert(&platform_bus);
	boots++;
	return boot_error;
}
static void airoha_npu_wlan_short_guard_clear(void *npu)
{
	CHECK(npu == &instance.npu);
	guard_clears++;
}

#include "fixed.inc"
#include "airoha_npu_resident.h"
#include "start.inc"
#include "get.inc"
#include "put.inc"

static void fixture(void)
{
	static const char * const compatibles[] = {
		"fiberhome,hg5585f-ct", "simple-bus", "airoha,en7581-npu", "airoha,en7581-eth",
		"airoha,en7581-scu", "airoha,en7581-chip-scu", "mediatek,wlan", "airoha,en7581-scu",
	};
	unsigned int index;

	if (initialized) {
		for (index = 0; index < NODE_COUNT; index++)
			CHECK(!pthread_mutex_destroy(&devices[index].dev.lock));
		CHECK(!pthread_mutex_destroy(&platform_bus.lock));
	}
	memset(nodes, 0, sizeof(nodes));
	memset(devices, 0, sizeof(devices));
	memset(drivers, 0, sizeof(drivers));
	memset(&platform_bus, 0, sizeof(platform_bus));
	memset(&instance, 0, sizeof(instance));
	for (index = 0; index < NODE_COUNT; index++) {
		nodes[index].name = index == SOC ? "soc" : "node";
		nodes[index].compatible = compatibles[index];
		nodes[index].available = true;
		nodes[index].parent = index == ROOT ? NULL : &nodes[index == SOC ? ROOT : SOC];
		devices[index].dev.of_node = &nodes[index];
		devices[index].dev.bus = &platform_bus_type;
		devices[index].dev.parent = index == SOC ? &platform_bus : &devices[SOC].dev;
		devices[index].dev.registered = true;
		present[index] = true;
		CHECK(!pthread_mutex_init(&devices[index].dev.lock, NULL));
		drivers[index].suppress_bind_attrs = true;
		drivers[index].name = "unexpected";
	}
	CHECK(!pthread_mutex_init(&platform_bus.lock, NULL));
	platform_bus.registered = true;
	drivers[NPU].name = "airoha-npu";
	drivers[ETH].name = "airoha_eth";
	drivers[SCU].name = "clk-en7523";
	drivers[SOC].name = "simple-pm-bus";
	drivers[SOC].suppress_bind_attrs = false;
	parent_match = (struct of_device_id) { "simple-bus", &parent_match };
	drivers[SOC].of_match_table = &parent_match;
	devices[SOC].dev.driver = &drivers[SOC];
	devices[SOC].dev.bound = true;
	for (index = NPU; index <= SCU; index++) {
		devices[index].dev.driver = &drivers[index];
		devices[index].dev.bound = true;
	}
	for (index = 0; index < ARRAY_SIZE(reset_nodes); index++) {
		reset_nodes[index] = &nodes[SCU];
		reset_args[index] = 1;
	}
	for (index = 0; index < ARRAY_SIZE(configuration); index++)
		configuration[index] = index < 3;
	nodes[NPU].rebuilt = true;
	nodes[CHIP].syscon = true;
	nodes[ETH].properties = 1u << RESETS;
	instance.npu.dev = &devices[NPU].dev;
	instance.deferred_start = true;
	devices[NPU].data = &instance.npu;
	npu_target = &nodes[NPU];
	chip_target = &nodes[CHIP];
	reset_count = reset_names = 8;
	reset_fail = missing_reset_name = -1;
	syscon_error = boot_error = module_refs = 0;
	boots = guard_clears = scu_links = consumer_links = 0;
	scu_link = eth_link = duplicate_eth = fail_module = false;
	fail_scu_link = fail_consumer_link = false;
	initialized = true;
}
static void balanced(void)
{
	unsigned int index;

	CHECK(!module_refs);
	for (index = 0; index < NODE_COUNT; index++) {
		CHECK(!nodes[index].references);
		CHECK(!devices[index].dev.references && !devices[index].dev.held);
	}
	CHECK(!platform_bus.references && !platform_bus.held);
	cases++;
}
static void expect_result(unsigned int caller, int expected)
{
	struct airoha_npu *npu = airoha_npu_get(&devices[caller].dev);

	if (expected) {
		CHECK(IS_ERR(npu) && PTR_ERR(npu) == expected);
	} else {
		CHECK(npu == &instance.npu);
		airoha_npu_put(npu);
	}
	balanced();
}
static void rejected(int expected)
{
	expect_result(ETH, expected);
	CHECK(!boots && !instance.start_attempted);
}
static void test_positive(void)
{
	fixture();
	expect_result(ETH, 0);
	CHECK(boots == 1 && scu_link && eth_link && scu_links == 1);
	expect_result(ETH, 0);
	CHECK(boots == 1);
	fixture();
	expect_result(WLAN, 0);
	CHECK(boots == 1 && scu_link && !eth_link);
	fixture();
	devices[SOC].dev.driver = &drivers[SOC];
	devices[SOC].dev.bound = true;
	expect_result(ETH, 0);
	fixture();
	scu_link = eth_link = true;
	expect_result(ETH, 0);
	fixture();
	nodes[NPU].rebuilt = instance.deferred_start = false;
	present[SCU] = present[CHIP] = false;
	expect_result(ETH, 0);
	CHECK(!boots && !scu_links);
}
static void test_drivers(void)
{
	unsigned int index;

	for (index = NPU; index <= SCU; index++) {
		fixture();
		devices[index].dev.bound = false;
		rejected(-EPROBE_DEFER);
		fixture();
		devices[index].dev.driver = NULL;
		devices[index].dev.bound = false;
		rejected(-EPROBE_DEFER);
		fixture();
		drivers[index].owner = &drivers[index];
		rejected(-EOPNOTSUPP);
		fixture();
		drivers[index].suppress_bind_attrs = false;
		rejected(-EOPNOTSUPP);
		fixture();
		drivers[index].name = "wrong-driver";
		rejected(-EOPNOTSUPP);
		fixture();
		devices[index].dev.bus = &other_bus;
		rejected(-EOPNOTSUPP);
	}
	fixture();
	devices[ETH].dev.bound = false;
	expect_result(WLAN, -EPROBE_DEFER);
	CHECK(!boots);
	fixture();
	devices[CHIP].dev.driver = &drivers[CHIP];
	rejected(-EOPNOTSUPP);
	fixture();
	devices[CHIP].dev.bus = &other_bus;
	rejected(-EOPNOTSUPP);
}
static void test_nodes(void)
{
	unsigned int index, property;

	for (index = ROOT; index <= CHIP; index++) {
		fixture();
		nodes[index].flags = OF_DYNAMIC;
		rejected(-EOPNOTSUPP);
		fixture();
		nodes[index].flags = OF_DETACHED;
		rejected(-EOPNOTSUPP);
		fixture();
		nodes[index].available = false;
		rejected(-EOPNOTSUPP);
	}
	for (index = SOC; index <= CHIP; index++) {
		for (property = 0; property < PROPERTY_COUNT; property++) {
			if (index == ETH && property == RESETS)
				continue;
			fixture();
			nodes[index].properties |= 1u << property;
			rejected(-EOPNOTSUPP);
		}
	}
	for (index = 0; index < ARRAY_SIZE(configuration); index++) {
		fixture();
		configuration[index] = index < 3 ? 2 : 1;
		rejected(-EOPNOTSUPP);
	}
	fixture();
	duplicate_eth = true;
	rejected(-EOPNOTSUPP);
	fixture();
	nodes[CHIP].syscon = false;
	rejected(-EOPNOTSUPP);
	fixture();
	nodes[CHIP].compatible = "syscon";
	rejected(-EOPNOTSUPP);
	fixture();
	chip_target = NULL;
	rejected(-EOPNOTSUPP);
	fixture();
	npu_target = &nodes[EXTRA];
	devices[EXTRA].data = &instance.npu;
	devices[EXTRA].dev.bound = true;
	nodes[EXTRA].rebuilt = true;
	CHECK(device_trylock(&devices[NPU].dev));
	{
		struct airoha_npu_resident_scope scope = {};

		CHECK(airoha_npu_resident_acquire(&instance.npu, NULL, &scope) == -EOPNOTSUPP);
		airoha_npu_resident_release(&scope);
	}
	device_unlock(&devices[NPU].dev);
	balanced();
}
static void test_resets(void)
{
	unsigned int index;

	for (index = 0; index < ARRAY_SIZE(reset_nodes); index++) {
		fixture();
		reset_fail = (int)index;
		rejected(-EOPNOTSUPP);
		fixture();
		reset_args[index] = 2;
		rejected(-EOPNOTSUPP);
		fixture();
		reset_nodes[index] = &nodes[EXTRA];
		rejected(-EOPNOTSUPP);
	}
	for (index = 0; index < 3; index++) {
		fixture();
		missing_reset_name = (int)index;
		rejected(-EOPNOTSUPP);
	}
	fixture();
	reset_count = 2;
	rejected(-EOPNOTSUPP);
	fixture();
	reset_count = -EINVAL;
	rejected(-EOPNOTSUPP);
	fixture();
	reset_names = 7;
	rejected(-EOPNOTSUPP);
	fixture();
	reset_nodes[7] = &nodes[CHIP];
	rejected(-EOPNOTSUPP);
}
static void test_parents(void)
{
	unsigned int index;

	for (index = NPU; index <= CHIP; index++) {
		fixture();
		devices[index].dev.parent = NULL;
		rejected(-EPROBE_DEFER);
		fixture();
		devices[index].dev.parent = &platform_bus;
		rejected(-EOPNOTSUPP);
		fixture();
		devices[index].dev.parent = &devices[EXTRA].dev;
		rejected(-EOPNOTSUPP);
	}
	fixture();
	nodes[EXTRA].name = "soc";
	nodes[EXTRA].compatible = "simple-bus";
	nodes[EXTRA].parent = &nodes[ROOT];
	devices[EXTRA].dev.parent = &platform_bus;
	devices[EXTRA].dev.driver = &drivers[SOC];
	devices[EXTRA].dev.bound = true;
	devices[NPU].dev.parent = &devices[EXTRA].dev;
	rejected(-EOPNOTSUPP);
	fixture();
	devices[SOC].dev.parent = &devices[EXTRA].dev;
	rejected(-EOPNOTSUPP);
	fixture();
	nodes[SOC].name = "other";
	rejected(-EOPNOTSUPP);
	fixture();
	nodes[SOC].compatible = "simple-pm-bus";
	rejected(-EOPNOTSUPP);
	fixture();
	devices[SOC].dev.bus = &other_bus;
	rejected(-EOPNOTSUPP);
	fixture();
	devices[SOC].dev.bound = false;
	rejected(-EPROBE_DEFER);
	fixture();
	devices[SOC].dev.driver = NULL;
	devices[SOC].dev.bound = false;
	rejected(-EPROBE_DEFER);
	fixture();
	drivers[SOC].name = "other-driver";
	drivers[SOC].suppress_bind_attrs = true;
	rejected(-EOPNOTSUPP);
	fixture();
	nodes[SOC].simple_bus_index = 1;
	rejected(-EOPNOTSUPP);
	fixture();
	nodes[SOC].simple_bus_index = -EINVAL;
	rejected(-EOPNOTSUPP);
	fixture();
	devices[SOC].dev.driver_override = true;
	rejected(-EOPNOTSUPP);
	fixture();
	devices[SOC].data = &parent_match;
	rejected(-EOPNOTSUPP);
	fixture();
	drivers[SOC].of_match_table = NULL;
	rejected(-EOPNOTSUPP);
	fixture();
	parent_match.data = NULL;
	rejected(-EOPNOTSUPP);
	fixture();
	parent_match.compatible = "simple-pm-bus";
	rejected(-EOPNOTSUPP);
	fixture();
	devices[SOC].dev.driver = &drivers[SOC];
	devices[SOC].dev.bound = true;
	drivers[SOC].owner = &drivers[SOC];
	rejected(-EOPNOTSUPP);
	fixture();
	platform_bus.parent = &devices[ROOT].dev;
	rejected(-EOPNOTSUPP);
	fixture();
	platform_bus.driver = &drivers[ROOT];
	rejected(-EOPNOTSUPP);
}
static void test_failures(void)
{
	unsigned int index;

	for (index = SOC; index <= CHIP; index++) {
		fixture();
		devices[index].dev.registered = false;
		rejected(-EPROBE_DEFER);
	}
	for (index = NPU; index <= CHIP; index++) {
		fixture();
		present[index] = false;
		rejected(index == NPU ? -ENODEV : -EPROBE_DEFER);
	}
	fixture();
	platform_bus.registered = false;
	rejected(-EPROBE_DEFER);
	fixture();
	syscon_error = -EPROBE_DEFER;
	rejected(-EPROBE_DEFER);
	fixture();
	syscon_error = -EIO;
	rejected(-EIO);
	fixture();
	fail_scu_link = true;
	rejected(-EINVAL);
	fail_scu_link = false;
	expect_result(ETH, 0);
	CHECK(boots == 1);
	fixture();
	fail_consumer_link = true;
	expect_result(ETH, -EINVAL);
	CHECK(boots == 1);
	fail_consumer_link = false;
	expect_result(ETH, 0);
	CHECK(boots == 1);
	fixture();
	boot_error = -EIO;
	expect_result(ETH, -EIO);
	expect_result(ETH, -EIO);
	CHECK(boots == 1 && guard_clears == 1);
	fixture();
	instance.stopping = true;
	rejected(-ESHUTDOWN);
	fixture();
	instance.transport_quarantined = true;
	rejected(-ESHUTDOWN);
	fixture();
	fail_module = true;
	rejected(-ENODEV);
	fixture();
	devices[NPU].data = NULL;
	rejected(-ENODEV);
}

struct contention {
	struct device *dev;
	pthread_mutex_t lock;
	pthread_cond_t condition;
	bool ready, release;
};
static void *hold_device(void *argument)
{
	struct contention *race = argument;

	assert(!pthread_mutex_lock(&race->dev->lock));
	assert(!pthread_mutex_lock(&race->lock));
	race->ready = true;
	assert(!pthread_cond_signal(&race->condition));
	while (!race->release)
		assert(!pthread_cond_wait(&race->condition, &race->lock));
	assert(!pthread_mutex_unlock(&race->lock));
	assert(!pthread_mutex_unlock(&race->dev->lock));
	return NULL;
}
static void test_contention(void)
{
	unsigned int index, caller;

	for (caller = 0; caller < 2; caller++) {
		for (index = SOC; index <= CHIP + 1; index++) {
			struct contention race = {
				.lock = PTHREAD_MUTEX_INITIALIZER,
				.condition = PTHREAD_COND_INITIALIZER,
			};
			pthread_t worker;

			fixture();
			race.dev = index == CHIP + 1 ? &platform_bus : &devices[index].dev;
			CHECK(!pthread_create(&worker, NULL, hold_device, &race));
			CHECK(!pthread_mutex_lock(&race.lock));
			while (!race.ready)
				CHECK(!pthread_cond_wait(&race.condition, &race.lock));
			CHECK(!pthread_mutex_unlock(&race.lock));
			expect_result(caller ? WLAN : ETH, -EPROBE_DEFER);
			CHECK(!boots && !instance.start_attempted);
			CHECK(!pthread_mutex_lock(&race.lock));
			race.release = true;
			CHECK(!pthread_cond_signal(&race.condition));
			CHECK(!pthread_mutex_unlock(&race.lock));
			CHECK(!pthread_join(worker, NULL));
			CHECK(!pthread_mutex_destroy(&race.lock));
			CHECK(!pthread_cond_destroy(&race.condition));
			expect_result(caller ? WLAN : ETH, 0);
			CHECK(boots == 1);
		}
	}
}
static void test_scope(void)
{
	struct airoha_npu_resident_scope scope = {};
	unsigned int index;

	fixture();
	for (index = 0; index < AIROHA_NPU_RESIDENT_DEVICES; index++)
		CHECK(!airoha_npu_resident_hold(&scope, &devices[index].dev, false));
	CHECK(!airoha_npu_resident_hold(&scope, &devices[NPU].dev, false));
	CHECK(airoha_npu_resident_hold(&scope, &platform_bus, false) == -EOPNOTSUPP);
	airoha_npu_resident_release(&scope);
	airoha_npu_resident_release(&scope);
	balanced();
}
int main(void)
{
	test_positive();
	test_drivers();
	test_nodes();
	test_resets();
	test_parents();
	test_failures();
	test_contention();
	test_scope();
	printf("{\"passed\":true,\"cases\":%u,\"checks\":%u,\"contention_cases\":12}\n", cases, checks);
	return 0;
}
