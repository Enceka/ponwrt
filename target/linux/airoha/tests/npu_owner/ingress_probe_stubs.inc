typedef long ssize_t;
struct device { struct airoha_eth *eth; };
struct device_attribute { int unused; };
static bool ingress_rtnl_locked;

static struct airoha_eth *dev_get_drvdata(struct device *dev) { return dev->eth; }
static void rtnl_lock(void) { CHECK(!ingress_rtnl_locked); ingress_rtnl_locked = true; }
static void rtnl_unlock(void) { CHECK(ingress_rtnl_locked); ingress_rtnl_locked = false; }
static bool sysfs_streq(const char *left, const char *right)
{
    size_t length = strlen(right);

    return !strncmp(left, right, length) &&
           (!left[length] || (left[length] == '\n' && !left[length + 1]));
}
static int kstrtouint(const char *word, unsigned int base, unsigned int *value)
{
    char *end;
    unsigned long parsed = strtoul(word, &end, base);

    if (!*word || *end || parsed > U32_MAX)
        return -EINVAL;
    *value = parsed;
    return 0;
}
static int airoha_ct_pon_ifc_route_open(struct airoha_ppe *ppe)
{
    ingress_probe_operations++;
    return 0;
}
static int airoha_ct_pon_ifc_cpu_publish(struct airoha_ppe *ppe, unsigned int slot,
                                       unsigned int service, bool cover)
{
    ingress_probe_operations++;
    return 0;
}
static int airoha_ct_pon_ifc_source_set(struct airoha_ppe *ppe, unsigned int source,
                                      unsigned int mode)
{
    ingress_probe_operations++;
    return 0;
}
static int airoha_ct_pon_ifc_cpu_set(struct airoha_ppe *ppe, unsigned int slot,
                                   unsigned int service)
{
    ingress_probe_operations++;
    return 0;
}
static int airoha_ct_pon_ifc_cpu_tuple(struct airoha_ppe *ppe, unsigned int slot,
                                     unsigned int service)
{
    ingress_probe_operations++;
    return 0;
}
static int airoha_ct_pon_ifc_cpu_clear(struct airoha_ppe *ppe, unsigned int slot)
{
    ingress_probe_operations++;
    return 0;
}

#include "ingress_probe.inc"
