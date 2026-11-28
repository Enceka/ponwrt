#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#define sha256(data, size, digest) CC_SHA256(data, (CC_LONG)(size), digest)
#else
#include <openssl/sha.h>
#define sha256(data, size, digest) SHA256(data, size, digest)
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;
#define __iomem
#define EPROBE_DEFER 517
#define SHA256_DIGEST_SIZE 32
#define REG_NPU_LOCAL_SRAM 0
#define NPU_EN7581_FIRMWARE_RV32_MAX_SIZE 0x200000
#define NPU_EN7581_FIRMWARE_DATA_MAX_SIZE 0x10000
#define NPU_NUM_CORES 8
#define NPU_OP_SET 1
#define NPU_FUNC_WIFI 0
#define WLAN_FUNC_GET_WAIT_NPU_VERSION 15
#define GFP_KERNEL 0
#define ARRAY_SIZE(value) (sizeof(value) / sizeof((value)[0]))
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))
#define smp_load_acquire(pointer) (*(pointer))
#define smp_store_release(pointer, value) (*(pointer) = (value))
#define wmb() ((void)0)
#define dev_err(...) ((void)0)
#define dev_warn(...) ((void)0)
#define dev_info(...) ((void)0)
#define dev_err_probe(dev, error, ...) (error)
#define device_lock_assert(dev) assert((dev)->locked)
#define lockdep_assert_held(lock) ((void)(lock))
#define cpu_to_le16(value) ((__le16)(value))
#define cpu_to_le32(value) ((__le32)(value))
#define le32_to_cpu(value) ((u32)(value))
#define ERR_PTR(error) ((void *)(intptr_t)(error))
#define PTR_ERR(pointer) ((int)(intptr_t)(pointer))
#define IS_ERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#define resource_size(res) ((res)->size)
#define REG_CR_NPU_MIB(index) (100 + (index))
#define REG_CR_BOOT_BASE(index) (200 + (index))
#define REG_CR_BOOT_CONFIG 300
#define REG_CR_BOOT_TRIGGER 301

struct device_node { unsigned int profiles; bool pool; };
struct device { struct device_node *of_node; bool bound, locked; };
struct resource { uint64_t start, size; };
struct firmware { size_t size; const u8 *data; };
struct airoha_npu {
	struct device *dev;
	void *regmap;
	bool wlan_short_guard_started, wlan_short_guard_verified;
};

#include "airoha_npu_transaction.h"
#include "airoha_npu_er_provider.h"
#include "pair.inc"

static struct device_node node = { .profiles = 4, .pool = true };
static struct device device = { .of_node = &node, .bound = true, .locked = true };
static struct airoha_npu_instance instance;
static struct resource region = { .start = 0x84000000, .size = 0x200000 };
static bool product = true, resident = true, corrupt_readback, missing_code, missing_data;
static unsigned int requests, copies, readbacks, releases, sends, boots, pool_calls, mmaps;
static int boot_error, pool_error, action_error;
static char requested[2][128];
static u8 code_memory[0x200000], data_memory[0x10000];
static u8 *code_payload, *data_payload;
static size_t code_size, data_size;
static struct firmware firmware;
static struct airoha_npu_soc_data {
	struct { const char *name; int max_size; } fw_rv32, fw_data;
} soc = { { "soc-code", 0x200000 }, { "soc-data", 0x10000 } };

static bool of_property_read_bool(struct device_node *target, const char *name)
{
	if (!strcmp(name, "airoha,connac2-rebuilt-ram-lab"))
		return target->profiles & 1;
	if (!strcmp(name, "airoha,connac2-ordinary-full-test"))
		return target->profiles & 2;
	assert(!strcmp(name, "airoha,connac2-pon-full"));
	return target->profiles & 4;
}

static bool of_machine_is_compatible(const char *name)
{
	assert(!strcmp(name, "fiberhome,hg5585f-ct"));
	return product;
}

static int of_property_match_string(struct device_node *target, const char *property,
				   const char *value)
{
	assert(!strcmp(property, "memory-region-names") && !strcmp(value, "connac2-pkt"));
	return target->pool ? 0 : -EINVAL;
}

static int of_property_read_string_array(struct device_node *target, const char *property,
					const char **names, size_t count)
{
	(void)target;
	assert(!strcmp(property, "firmware-name") && count == 2);
	names[0] = "stock-code";
	names[1] = "stock-data";
	return 2;
}

static const void *of_device_get_match_data(struct device *dev)
{
	assert(dev == &device);
	return &soc;
}

static void *of_find_property(struct device_node *target, const char *name, void *length)
{
	(void)target;
	(void)length;
	assert(!strcmp(name, "firmware-name"));
	return NULL;
}

static void *devm_ioremap_resource(struct device *dev, struct resource *res)
{
	assert(dev == &device && res == &region);
	mmaps++;
	return code_memory;
}

static int request_firmware_direct(const struct firmware **output, const char *name,
				   struct device *dev)
{
	assert(dev == &device && requests < 2);
	strcpy(requested[requests++], name);
	bool data = strstr(name, "data") != NULL;
	if ((data && missing_data) || (!data && missing_code))
		return -ENOENT;
	firmware.data = data ? data_payload : code_payload;
	firmware.size = data ? data_size : code_size;
	*output = &firmware;
	return 0;
}

static void release_firmware(const struct firmware *fw)
{
	assert(fw == &firmware);
	releases++;
}

static void memcpy_toio(void *destination, const void *source, size_t bytes)
{
	memcpy(destination, source, bytes);
	copies++;
}

static int ct_npu_guard_verify_io(void *address, size_t bytes, const u8 *digest)
{
	u8 actual[32];
	readbacks++;
	sha256(address, bytes, actual);
	return corrupt_readback || memcmp(actual, digest, 32) ? -EIO : 0;
}

static int ct_npu_guard_load(void *address, const struct firmware *fw)
{
	memcpy_toio(address, fw->data, fw->size);
	return 0;
}

#include "loader.inc"
#include "ready.inc"

static int __airoha_npu_send_msg(struct airoha_npu *npu, int function,
				 const void *data, int bytes, void *reply, u16 reply_bytes)
{
	(void)data;
	(void)reply;
	assert(npu == &instance.npu && function == NPU_FUNC_WIFI && bytes > reply_bytes);
	sends++;
	return -EIO;
}

#include "native.inc"
#include "airoha_npu_transaction.inc"

static bool device_is_bound(struct device *dev) { return dev->bound; }
static bool airoha_npu_resident_device(struct device *dev) { (void)dev; return resident; }
static int regmap_write(void *map, int address, u32 value)
{
	(void)map;
	(void)value;
	if (address == REG_CR_BOOT_TRIGGER)
		boots++;
	return boot_error;
}
static void msleep(int duration) { (void)duration; }
static void usleep_range(int low, int high) { (void)low; (void)high; }
static int airoha_npu_connac2_init_pool(struct airoha_npu *npu)
{
	assert(npu == &instance.npu);
	pool_calls++;
	return pool_error;
}
static int airoha_npu_wlan_msg_get(struct airoha_npu *npu, int core, int function,
				   void *data, size_t size, int flags)
{
	(void)npu; (void)core; (void)function; (void)data; (void)size; (void)flags;
	return -EIO;
}
static int devm_add_action_or_reset(struct device *dev, void (*action)(void *), void *data)
{
	(void)dev;
	if (action_error)
		action(data);
	return action_error;
}

#include "startup.inc"
#include "probe.inc"

static void reset(unsigned int profiles)
{
	memset(&instance, 0, sizeof(instance));
	instance.npu.dev = &device;
	node.profiles = profiles;
	node.pool = product = resident = device.bound = true;
	instance.deferred_start = airoha_npu_deferred_profile(&node);
	requests = copies = readbacks = releases = sends = boots = pool_calls = mmaps = 0;
	boot_error = pool_error = action_error = 0;
	corrupt_readback = missing_code = missing_data = false;
	memset(requested, 0, sizeof(requested));
}

static void transport(bool native, bool transaction)
{
	struct airoha_ct_pair_msg pair = {};
	struct npu_auth_message auth = {};
	struct er_message er = { .w = { ER_MAGIC, ER_ABI | ER_QUERY << 16 } };
	struct npu_gate_message gate = {};
	struct airoha_npu_er_provider before = instance.er;
	sends = 0;
	assert(airoha_npu_ct_pair_cmd(&instance.npu, &pair) == (native ? -EIO : -EOPNOTSUPP));
	assert(airoha_npu_auth_command(&instance.npu, &auth) == (transaction ? -EIO : -EOPNOTSUPP));
	assert(airoha_npu_er_command(&instance.npu, &er) == (transaction ? -EIO : -EOPNOTSUPP));
	assert(airoha_npu_gate_command(&instance.npu, &gate) == (transaction ? -EIO : -EOPNOTSUPP));
	assert(sends == (unsigned int)native + 3 * (unsigned int)transaction);
	assert(!memcmp(&before, &instance.er, sizeof(before)));
	if (!transaction) {
		er.w[1] = ER_ABI | ER_BIND << 16;
		er.w[2] = 0x85000000;
		er.w[3] = 0x10000;
		er.w[4] = 8;
		er.w[5] = 1;
		er.w[6] = ER_PON;
		er.w[7] = 1;
		assert(airoha_npu_er_command(&instance.npu, &er) == -EOPNOTSUPP);
		assert(!memcmp(&before, &instance.er, sizeof(before)));
	}
}

static void profiles(void)
{
	const int expected[] = { 0, 1, 2, -EINVAL, 3, -EINVAL, -EINVAL, -EINVAL };
	for (unsigned int mask = 0; mask < 8; mask++) {
		reset(mask);
		assert(airoha_npu_profile(&node) == expected[mask]);
		assert(probe_admission(&device) == (expected[mask] < 0 ? -EINVAL : 0));
		assert(instance.deferred_start == (mask == 1 || mask == 4));
		transport(false, false);
		instance.npu.wlan_short_guard_started = true;
		transport(false, false);
		instance.npu.wlan_short_guard_verified = true;
		instance.npu.wlan_short_guard_started = true;
		transport(mask == 1 || mask == 2 || mask == 4, mask == 1 || mask == 4);
		instance.transport_quarantined = true;
		transport(false, false);
		instance.transport_quarantined = false;
		product = false;
		transport(false, false);
		assert(probe_admission(&device) == (mask ? -EINVAL : 0));
		product = true;
		node.pool = false;
		transport(false, false);
		node.pool = true;
		resident = false;
		assert(probe_admission(&device) == (expected[mask] < 0 ? -EINVAL :
			(mask == 1 || mask == 4) ? -EOPNOTSUPP : 0));
		resident = true;
		if (expected[mask] < 0) {
			assert(airoha_npu_load_firmware_from_dts(&device, code_memory, data_memory) == -EINVAL);
			assert(requests == 0);
		}
	}
	reset(4);
	product = false;
	assert(airoha_npu_run_firmware(&device, data_memory, &region) == -EINVAL);
	assert(requests == 0);
	for (unsigned int mask = 1; mask <= 4; mask *= 2) {
		reset(mask);
		missing_code = true;
		assert(airoha_npu_load_firmware_from_dts(&device, code_memory, data_memory) == -EPROBE_DEFER);
		const char *expected_name = mask == 1 ? "npu_rebuilt_rv32.bin" :
			mask == 2 ? "npu_full_test_rv32.bin" : "npu_pon_full_rv32.bin";
		assert(!strcmp(requested[0] + strlen("airoha/hg5585f-ct/"), expected_name));
		assert(requests == 1 && !copies);
		if (mask != 4) {
			reset(mask);
			assert(airoha_npu_run_firmware(&device, data_memory, &region) == -EBADMSG);
			assert(requests == 1 && !copies);
		}
	}
	reset(0);
	missing_code = true;
	assert(airoha_npu_load_firmware_from_dts(&device, code_memory, data_memory) == -EPROBE_DEFER);
	assert(!strcmp(requested[0], "stock-code"));
}

static void payload(void)
{
	reset(4);
	assert(!airoha_npu_run_firmware(&device, data_memory, &region));
	assert(requests == 2 && releases == 2 && copies == 2 && readbacks == 2);
	assert(!strcmp(requested[0], "airoha/hg5585f-ct/npu_pon_full_rv32.bin"));
	assert(!strcmp(requested[1], "airoha/hg5585f-ct/npu_pon_full_data.bin"));
	assert(!memcmp(code_payload, code_memory, code_size));
	assert(!memcmp(data_payload, data_memory, data_size));
	for (unsigned int part = 0; part < 2; part++) {
		u8 *bytes = part ? data_payload : code_payload;
		size_t *size = part ? &data_size : &code_size;
		size_t saved = *size;
		reset(4);
		bytes[0] ^= 1;
		assert(airoha_npu_run_firmware(&device, data_memory, &region) == -EBADMSG);
		assert(copies == part);
		bytes[0] ^= 1;
		reset(4);
		*size = saved - 1;
		assert(airoha_npu_run_firmware(&device, data_memory, &region) == -EBADMSG);
		assert(copies == part);
		reset(4);
		*size = part ? 5 : 0x18001;
		assert(airoha_npu_run_firmware(&device, data_memory, &region) == -E2BIG);
		assert(copies == part);
		*size = saved;
	}
	reset(4);
	missing_data = true;
	assert(airoha_npu_run_firmware(&device, data_memory, &region) == -EPROBE_DEFER);
	assert(copies == 1 && requests == 2);
	reset(4);
	corrupt_readback = true;
	assert(airoha_npu_run_firmware(&device, data_memory, &region) == -EIO);
	assert(copies == 1 && requests == 1);
}

static void startup(void)
{
	reset(4);
	assert(!airoha_npu_prepare_firmware(&instance.npu, data_memory, &region));
	assert(!boots && !airoha_npu_wlan_short_guard_ready(&instance.npu));
	transport(false, false);
	device.bound = false;
	assert(airoha_npu_start_bound(&instance.npu) == -EPROBE_DEFER);
	device.bound = true;
	resident = false;
	assert(airoha_npu_start_bound(&instance.npu) == -EOPNOTSUPP);
	assert(!boots);
	resident = true;
	assert(!airoha_npu_start_bound(&instance.npu));
	assert(boots == 1 && pool_calls == 1);
	assert(!airoha_npu_start_bound(&instance.npu) && boots == 1);
	transport(true, true);
	instance.transport_quarantined = true;
	assert(airoha_npu_start_bound(&instance.npu) == -ESHUTDOWN);
	transport(false, false);
	reset(4);
	assert(!airoha_npu_prepare_firmware(&instance.npu, data_memory, &region));
	pool_error = -EIO;
	assert(airoha_npu_start_bound(&instance.npu) == -EIO);
	pool_error = 0;
	assert(airoha_npu_start_bound(&instance.npu) == -EIO && boots == 1);
	transport(false, false);
	reset(4);
	code_payload[0] ^= 1;
	assert(airoha_npu_prepare_firmware(&instance.npu, data_memory, &region) == -EBADMSG);
	code_payload[0] ^= 1;
	assert(!instance.npu.wlan_short_guard_verified && !boots);
}

static u8 *read_payload(const char *path, size_t *size)
{
	FILE *stream = fopen(path, "rb");
	assert(stream && !fseek(stream, 0, SEEK_END));
	long length = ftell(stream);
	assert(length > 0 && !fseek(stream, 0, SEEK_SET));
	*size = (size_t)length;
	u8 *bytes = malloc(*size);
	assert(bytes && fread(bytes, 1, *size, stream) == *size);
	fclose(stream);
	return bytes;
}

int main(int argc, char **argv)
{
	assert(argc == 3);
	code_payload = read_payload(argv[1], &code_size);
	data_payload = read_payload(argv[2], &data_size);
	assert(code_size == 39084 && data_size == 4);
	profiles();
	payload();
	startup();
	free(code_payload);
	free(data_payload);
	puts("profile matrix, actual payload, digest/size/readback, transport and deferred startup: PASS");
	return 0;
}
