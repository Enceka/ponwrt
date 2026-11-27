static int er_failure = -1, er_fallback_error;
static bool er_allocation_failure, er_bound, er_lose_ack;
static u32 er_caps, er_state, er_fault, er_last_epoch;
static struct er_config er_live_config;
static unsigned int er_calls[4], er_frees, er_fallbacks, er_cancels;

static bool airoha_is_valid_gdm_dev(struct airoha_eth *eth, struct airoha_gdm_dev *dev)
{
    return eth->pon == dev;
}

static int er_get_sport(struct airoha_gdm_port *port, int nbq)
{
    return port->sport;
}

static void schedule_delayed_work(struct delayed_work *work, unsigned int delay)
{
    CHECK(delay == 100);
    work->pending = true;
}

static void cancel_delayed_work_sync(struct delayed_work *work)
{
    CHECK(flow_offload_mutex && !ppe_lock);
    work->pending = false;
    er_cancels++;
}

static int airoha_ct_cpu_fallback(struct airoha_eth *eth)
{
    er_fallbacks++;
    eth->ct_cpu_fallback = true;
    return er_fallback_error;
}

int airoha_npu_er_command(struct airoha_npu *npu, struct er_message *message)
{
    u32 operation = message->w[1] >> 16;
    struct er_config config = { message->w[2], message->w[3], message->w[4],
                                message->w[5], message->w[6], message->w[7] };
    CHECK(npu && flow_offload_mutex && !ppe_lock && operation <= ER_UNBIND);
    er_calls[operation]++;
    if ((int)operation == er_failure && !er_lose_ack)
        return -ETIMEDOUT;
    if (operation != ER_QUERY) {
        CHECK(er_config_valid(&config) && fe_calls && gate_calls[GATE_QUIET]);
        if (operation == ER_BIND) {
            CHECK(!er_bound && config.epoch > er_last_epoch);
            er_bound = true;
            er_live_config = config;
            er_last_epoch = config.epoch;
        } else if (er_bound) {
            CHECK(!memcmp(&config, &er_live_config, sizeof(config)));
            if (operation == ER_UNBIND)
                er_bound = false;
        }
    }
    if ((int)operation == er_failure)
        return -ETIMEDOUT;
    message->w[8] = 0;
    message->w[9] = er_caps;
    message->w[10] = er_state;
    message->w[12] = er_fault;
    return 0;
}

static int er_stub_command(struct airoha_er *ring, u32 operation)
{
    struct er_message message = {
        .w = { ER_MAGIC, ER_ABI | operation << 16, ring->config.dma,
               ring->config.bytes, ring->config.epoch, ring->config.count,
               ring->config.sport, ring->config.generation, (u32)-EINPROGRESS },
    };
    return ring->ops->command(ring->ctx, &message);
}

static int airoha_er_create(struct airoha_er **out, void *dma_dev,
                            struct net_device *lower, u32 sport, u32 generation,
                            u32 epoch, u32 count, bool enabled,
                            const struct airoha_er_ops *ops, void *ctx)
{
    struct airoha_er *ring;
    CHECK(!*out && enabled && lower && ops && ctx);
    if (er_allocation_failure)
        return -ENOMEM;
    ring = calloc(1, sizeof(*ring));
    CHECK(ring);
    ring->config = (struct er_config) { 0x80010000, er_bytes(count), epoch,
                                       count, sport, generation };
    ring->lower = lower;
    ring->ops = ops;
    ring->ctx = ctx;
    lower->references++;
    *out = ring;
    return er_stub_command(ring, ER_BIND);
}

static int airoha_er_destroy(struct airoha_er **out)
{
    struct airoha_er *ring = *out;
    int error;
    if (!ring)
        return 0;
    error = ring->ops->quiesce(ring->ctx);
    if (error)
        return error;
    error = er_stub_command(ring, ER_STOP);
    if (error)
        return error;
    error = er_stub_command(ring, ER_UNBIND);
    if (error)
        return error;
    CHECK(!er_bound && ring->lower->references == 1);
    ring->lower->references--;
    free(ring);
    *out = NULL;
    er_frees++;
    return 0;
}
