#ifndef EUCLEAN
#define EUCLEAN 117
#endif
#define __maybe_unused __attribute__((unused))
#define WRITE_ONCE(value, replacement) ((value) = (replacement))
#define max(left, right) ((left) > (right) ? (left) : (right))
#define to_delayed_work(work) container_of(work, struct delayed_work, work)
#define msecs_to_jiffies(value) (value)
#define CT_IFC_DATA(index) (0x210 + 4 * (index))
#define CT_IFC_CONTROL 0x204
#define CT_IFC_DONE BIT(31)
#define CT_IFC_TCAM_BANK 0
#define CT_IFC_ACTION_BANK 2
#define CT_IFC_ACTION_ENABLE BIT(31)
#define CT_IFC_ACTION_STOP BIT(30)
#define REG_FE_CSR_IFC_CFG 0x200
#define FE_IFC_EN_MASK 1
#define XSI_ETH_VIP_PORT_MASK BIT(24)
#define REG_PPE_GLO_CFG(bank) (0x500 + (bank) * 0x100)
#define REG_PPE_PPE_FLOW_CFG(bank) (0x504 + (bank) * 0x100)
#define REG_PPE_TB_CFG(bank) (0x51c + (bank) * 0x100)
#define PPE_TB_CFG_SEARCH_MISS_MASK GENMASK(5, 4)
#define PPE_GLO_CFG_BUSY_MASK BIT(31)
#define PPE_GLO_CFG_EN_MASK BIT(0)
#define read_poll_timeout_atomic(function, value, condition, delay, timeout, sleep, ...) \
	((value) = function(__VA_ARGS__), (condition) ? 0 : -ETIMEDOUT)

static const u8 ct_ifc_action_words[] = { 2, 3, 1 };
static u32 registers[1024], tables[3][64][9][3];
static unsigned mmio_writes, schedules, operation_count[7];
static unsigned firmware_applies;
static void reset(void);
static u32 firmware_epoch, firmware_wired_epoch;
static u32 firmware_wlan_epoch[2][256];
static u64 firmware_generation;
static bool firmware_armed, firmware_quiesced, accept_before_error;
static int write_fail_offset;

static void test_log(const char *format, ...)
{
	(void)format;
}
#define pr_err(...) test_log(__VA_ARGS__)

static int schedule_delayed_work(struct delayed_work *work, unsigned delay)
{
	assert(work && delay == 100);
	schedules++;
	return 0;
}

static bool airoha_ifc_lan_ports_ready(struct airoha_eth *eth)
{
	return !!eth;
}

static int airoha_ct_cpu_fallback(struct airoha_eth *eth)
{
	assert(ppe_lock);
	eth->ct_cpu_fallback = true;
	eth->ct_cpu_routes_ready = true;
	eth->ct_cpu_ifc_disabled = true;
	return 0;
}

static u32 airoha_fe_rr(struct airoha_eth *eth, u32 offset)
{
	assert(eth && ppe_lock && offset < sizeof(registers));
	return registers[offset / 4];
}

static void airoha_fe_wr(struct airoha_eth *eth, u32 offset, u32 value)
{
	assert(eth && ppe_lock && offset < sizeof(registers));
	mmio_writes++;
	if ((int)offset == write_fail_offset)
		return;
	registers[offset / 4] = value;
	if (offset == CT_IFC_CONTROL) {
		unsigned bank = (value >> 4) & 7;
		unsigned row = (value >> 16) & 255;
		unsigned page = (value >> 8) & 15;
		unsigned count = bank == CT_IFC_ACTION_BANK ? ct_ifc_action_words[page] : 2;

		assert((bank == CT_IFC_TCAM_BANK || bank == CT_IFC_ACTION_BANK) &&
		       row >= 54 && row <= 55 && page < 9);
		if (value & 2) {
			memcpy(tables[bank][row][page], &registers[CT_IFC_DATA(0) / 4],
			       count * sizeof(u32));
			if (bank == CT_IFC_TCAM_BANK)
				tables[bank][row][page][0] &= tables[bank][row][page][1];
		} else {
			memcpy(&registers[CT_IFC_DATA(0) / 4], tables[bank][row][page],
			       count * sizeof(u32));
		}
		registers[offset / 4] |= CT_IFC_DONE;
	}
}

static void airoha_fe_rmw(struct airoha_eth *eth, u32 offset, u32 clear, u32 set)
{
	airoha_fe_wr(eth, offset, (airoha_fe_rr(eth, offset) & ~clear) | set);
}

static int mock_send(struct airoha_npu *npu, struct airoha_ct_pair_msg *message)
{
	u16 operation = le16_to_cpu(message->op);
	u32 epoch = le32_to_cpu(message->src_epoch);
	u64 selected_generation = le64_to_cpu(message->generation);
	int error = original_mock_send(npu, message);

	assert(operation < ARRAY_SIZE(operation_count));
	operation_count[operation]++;
	if (error && !accept_before_error)
		return error;
	if (operation == AIROHA_CT_PAIR_FE_QUIESCE || operation == AIROHA_CT_PAIR_FE_ARM) {
		assert(message->src_selector == AIROHA_CT_PAIR_LAN1_SELECTOR);
		assert(le16_to_cpu(message->src_wcid) == AIROHA_CT_PAIR_LAN1_ID);
		assert(!message->slot && !message->token && !message->dst_epoch &&
		       !message->dst_wcid && !message->dst_selector && !message->src_bss &&
		       !message->dst_bss && !message->flags);
		assert(epoch && selected_generation);
		if (operation == AIROHA_CT_PAIR_FE_QUIESCE) {
			if (epoch < firmware_epoch || epoch < firmware_wired_epoch ||
			    selected_generation < firmware_generation ||
			    (epoch == firmware_epoch &&
			     (selected_generation != firmware_generation || firmware_armed)))
				return -ESTALE;
			firmware_epoch = firmware_wired_epoch = epoch;
			firmware_generation = selected_generation;
			firmware_armed = false;
			firmware_quiesced = true;
		} else {
			if (epoch != firmware_epoch || selected_generation != firmware_generation ||
			    !firmware_quiesced || epoch != firmware_wired_epoch)
				return -ESTALE;
			firmware_armed = true;
		}
	} else if (operation == AIROHA_CT_PAIR_FLUSH ||
		   operation == AIROHA_CT_PAIR_ENDPOINT_REVOKE) {
		if (firmware_armed) {
			firmware_armed = false;
			firmware_quiesced = false;
		}
		if (operation == AIROHA_CT_PAIR_ENDPOINT_REVOKE) {
			if (message->src_selector == AIROHA_CT_PAIR_LAN1_SELECTOR)
				firmware_wired_epoch = max(firmware_wired_epoch, epoch);
			else {
				u16 station = le16_to_cpu(message->src_wcid);
				assert(message->src_selector < 2 && station < 256);
				firmware_wlan_epoch[message->src_selector][station] = epoch;
			}
		}
	}
	firmware_applies++;
	return error;
}
