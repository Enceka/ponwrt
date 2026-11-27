#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

typedef uint32_t u32;
#define BIT(bit) (1u << (bit))
#define CT_IFC_CONTROL 0x204
#define CT_IFC_DATA(word) (0x210 + 4 * (word))
#define CT_IFC_DONE BIT(31)
struct airoha_eth { bool ct_ifc_command_pending; };
struct airoha_ppe { struct airoha_eth *eth; };
static int ppe_lock;
static unsigned int commands, data_writes, polls;
static bool stall;
static u32 control, data[3], table[64][3], inflight[3];
static void spin_lock_bh(int *lock) { assert(!*lock); *lock = 1; }
static void spin_unlock_bh(int *lock) { assert(*lock); *lock = 0; }
#define lockdep_assert_held(lock) assert(*(lock))
static void complete(bool effect)
{
    unsigned int row = (control >> 16) & 255;
    assert(row < 64);
    if (control & 2) {
        if (effect)
            memcpy(table[row], inflight, sizeof(inflight));
    } else {
        memcpy(data, table[row], sizeof(data));
    }
    control |= CT_IFC_DONE;
}
static u32 airoha_fe_rr(struct airoha_eth *eth, u32 reg)
{
    assert(eth && ppe_lock);
    if (reg == CT_IFC_CONTROL) {
        polls++;
        return control;
    }
    assert(reg >= CT_IFC_DATA(0) && reg <= CT_IFC_DATA(2));
    return data[(reg - CT_IFC_DATA(0)) / 4];
}
static void airoha_fe_wr(struct airoha_eth *eth, u32 reg, u32 value)
{
    assert(eth && ppe_lock);
    if (reg == CT_IFC_CONTROL) {
        assert(!commands || (control & CT_IFC_DONE));
        assert(eth->ct_ifc_command_pending);
        commands++;
        control = value;
        memcpy(inflight, data, sizeof(inflight));
        if (!stall)
            complete(true);
        return;
    }
    assert(!commands || (control & CT_IFC_DONE));
    assert(reg >= CT_IFC_DATA(0) && reg <= CT_IFC_DATA(2));
    data_writes++;
    data[(reg - CT_IFC_DATA(0)) / 4] = value;
}
#define read_poll_timeout_atomic(op, value, condition, delay, timeout, sleep, ...) \
    ({ (value) = op(__VA_ARGS__); (condition) ? 0 : -ETIMEDOUT; })
#include "airoha_ct_ifc_command.h"
#include "ifc_callers.inc"

static int transfer(struct airoha_eth *eth, unsigned int caller,
                    unsigned int row, bool write, u32 *words)
{
    struct airoha_ppe ppe = { .eth = eth };
    int err;

    assert(!ppe_lock);
    if (!caller)
        return ct_ifc_access(eth, 2, row, 1, write, words, 3);
    spin_lock_bh(&ppe_lock);
    err = airoha_ct_fe_table(&ppe, 2, row, 1, write, words, 3);
    spin_unlock_bh(&ppe_lock);
    return err;
}

int main(void)
{
    unsigned int cases = 0;

    for (unsigned int origin = 0; origin < 2; origin++)
    for (unsigned int successor = 0; successor < 2; successor++)
    for (unsigned int write = 0; write < 2; write++)
    for (unsigned int next_write = 0; next_write < 2; next_write++)
    for (unsigned int effect = 0; effect < 2; effect++) {
        struct airoha_eth eth = {};
        u32 first[] = { 0x12345678, 0x9abcdef0, 0x10203040 };
        u32 next[] = { 0x54637281, 0xabcd1234, 0x98765432 };
        u32 expected[3], before[3];

        commands = data_writes = polls = control = 0;
        memset(data, 0, sizeof(data));
        memset(table, 0x39, sizeof(table));
        memcpy(before, first, sizeof(before));
        stall = true;
        assert(transfer(&eth, origin, 56, write, first) == -ETIMEDOUT);
        assert(eth.ct_ifc_command_pending && commands == 1 && polls == 1);
        assert(!memcmp(first, before, sizeof(first)));
        memcpy(expected, next_write ? next : table[54], sizeof(expected));
        for (unsigned int retry = 0; retry < 3; retry++) {
            unsigned int old_writes = data_writes;
            assert(transfer(&eth, successor, 54, next_write, next) == -ETIMEDOUT);
            assert(eth.ct_ifc_command_pending && commands == 1);
            assert(data_writes == old_writes && polls == retry + 2);
        }
        complete(effect);
        stall = false;
        assert(!transfer(&eth, successor, 54, next_write, next));
        assert(!eth.ct_ifc_command_pending && commands == 2 && polls == 6);
        assert(!memcmp(next_write ? table[54] : next, expected, sizeof(expected)));
        if (write && effect)
            assert(!memcmp(table[56], first, sizeof(first)));
        else
            for (unsigned int word = 0; word < 3; word++)
                assert(table[56][word] == 0x39393939);
        assert(!ppe_lock);
        cases++;
    }
    printf("{\"passed\":true,\"cases\":%u,\"blocked_retries\":%u}\n", cases, cases * 3);
    return 0;
}
