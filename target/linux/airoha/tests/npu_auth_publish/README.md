# PON AUTH 发布辅助层

995 patch 新增生产头文件 `drivers/net/ethernet/airoha/airoha_npu_auth_publish.h`，复用现有 `npu_auth_mailbox_abi.h`；ZW 将公共 validator 的 bank 范围对齐为 0/1。实现为 `static inline`，供 owner 授权阶段调用。

```c
struct airoha_npu_auth_rule {
	auth_u32 raw[32];
};

int airoha_npu_auth_publish(auth_u32 epoch, auth_u32 generation,
	const struct airoha_npu_auth_rule *rules, auth_u32 count,
	int (*command)(void *, struct npu_auth_message *), void *ctx);
```

## 调用约束

- 调用者持有 owner 的串行化锁，并在整个同步调用期间保持规则数组有效且不可变。`ctx` 可为空，由 callback 决定其含义。
- 仅在 owner CLOSED 且 ER 绑定有效后调用；调用前完成 routes/GATE 关闭、AUTH disarm 与 inflight 排空、FE quiesce 和所属 bank 排空。保持这些条件直至发布结束；helper 仅操作 AUTH 表。
- 公共 helper 接受 bank0/1。生产 `airoha_ppe_npu_owner_authorize_locked()` 在公共校验后、ready/binding/attempted 操作前逐条要求 bank1，否则返回 `-EOPNOTSUPP`。diag 发布 bank0，绑定时 row=`diag_hash`，其余模式保留占位 row=0。这些调用方策略由 `npu_diag` suite 验证。
- `epoch`、`generation` 均非零，且与每条规则身份一致。调用者选用严格大于固件现有 epoch 的值，禁止回绕；达到最大 epoch 后须重新启动固件以建立新生命周期。
- 发布集合为 1–32 条。空集合、超限、空 rules/callback 均返回 `-EINVAL`，且发送零条命令。清空/撤销 AUTH 由 owner 的关闭流程完成。
- 在首条 BEGIN 前验证整批规则。成功路径为 BEGIN → 按数组顺序逐条 ADD → ARM，共 `count + 2` 次 callback。
- 首个失败立即返回。helper 无重试、补发、撤销或 epoch 自增；调用者在任意发布失败后执行关闭流程并提升 epoch，再决定后续发布。丢 ACK 时，BEGIN/ADD/ARM 可能已经生效，尤其 ARM 丢 ACK 后 AUTH 可能已 enabled。
- helper 自行开启的状态只有 AUTH ARM。GATE/FE 开启、ER ready 和后续 routes 恢复由 owner 继续协调。

## Canonical 规则

规则布局和接受条件以本地固件 `include/npu_ingress_auth.h`、`src/ingress_auth.c` 及 `include/npu_fe_auth.h` 中的 `npu_fe_auth_update_locked` 为依据，验证逻辑独立实现。

| raw word | 约束 |
| --- | --- |
| 0–8 | ABI=1、epoch 匹配、非零 token、bank=0/1、row<8192、domain=PON(4)、producer=2、完整 16 位 endpoint、generation 匹配 |
| 9–10 | IPv4/IPv6；TCP(6)/UDP(17) |
| 11–18 | 源/目标地址数值；IPv4 的两组尾部各三个 word 全零 |
| 19 | 源端口在高 16 位、目标端口在低 16 位，允许完整 32 位组合 |
| 20–22 | 0–2 层 VLAN；有效 TPID 为 0x8100/0x88a8，完整 TCI；未使用的 tag word 全零 |
| 23–24 | 16 位 PPPoE SID；SID=0 时协议为 0，否则 IPv4=0x21、IPv6=0x57 |
| 25–27 | Ethernet dst+src 的三个数值 word；两端均非零且为单播 |
| 28–31 | 全零 |

重复 token、重复 row，以及固件禁止的相同 `raw[9..19]` 硬件 tuple 均返回 `-EEXIST`，即使两条规则位于不同 bank。tuple 判重涵盖 family、L4、完整源/目标地址、ports；不同 endpoint、VLAN、PPPoE、MAC 仍共用这个排他条件。预检失败均发送零条命令。bank/row 是 AUTH 规则元数据，固件实际 TX 目标由转发配置和 route 检查决定。

## Callback 与应答

callback 接收并更新现有 `struct npu_auth_message`。全部 word 采用主机数值：地址、MAC、端口内的字段保持网络报文解析后的数值；现有 AUTH36 transport 负责 mailbox word 的 little-endian 编解码。helper 不预先交换字节。

每个请求从全零 message 构造，状态哨兵固定为 ABI 的 `(auth_u32)-115`，独立于主机 `EINPROGRESS` 数值。BEGIN/ARM 的 `AM_RULE_COUNT=0` 且 rule 区全零；ADD 为 1 并完整携带 32 个 rule word。

callback 负返回原样传递，正返回转换为 `-EPROTO`。只有 callback 返回 0 才消费成功应答，以下项目必须逐项准确匹配，否则返回 `-EPROTO`：

- word 0–39 完整 echo，包括操作、身份、rule count、两个请求保留 word 及整个 rule 区。
- `AM_STATUS=0`、`AM_CAPS=7`、`AM_RESERVED2=0`。
- state epoch/generation 等于本次发布身份。
- BEGIN count=0；第 n 次 ADD count=n；ARM count=传入总数。
- inflight 始终为 0；BEGIN/ADD enabled=0；ARM enabled=1。

返回 0 的 callback 若携带非零固件状态，按应答协议错误处理。负返回后不依赖 response 内容，也不再发命令。

## 主机验证

在主仓库运行：

```sh
cd /Volumes/Workspace/5585f/build/ponwrt
python3 target/linux/airoha/tests/npu_auth_publish/verify.py
```

显式指定本地输入与编译器：

```sh
python3 target/linux/airoha/tests/npu_auth_publish/verify.py \
  --source-snapshot /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/auth-bank-metadata/source \
  --firmware /Volumes/Workspace/5585f/an7581-npu-firmware \
  --output /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/auth-bank-metadata/publish-suite \
  --cc clang
```

验证器用共享 `npu_ingress/source_binding.py` 的 SourceBinding 重建截至 `999-zw-net-airoha-align-pon-auth-bank-metadata.patch` 的有序补丁链；要求 hunk 行号和上下文精确匹配、无 fuzz/offset，重建 header 与快照逐字节一致。从快照读取 mailbox ABI，并检查它与固件 ABI 逐字节一致。测试链接本地固件实际 `src/ingress_auth.c`，使用其 parser、BEGIN/ADD/ARM 和重复检查验证夹具及模拟状态变化，固件保持不变。

`--source` 是 `--source-snapshot` 的别名。输出目录必须新建，位于 ponwrt 外并与快照、固件目录分离；默认在 `build/pon-npu-diag-20261127/auth-bank-metadata/` 下创建带时间戳的目录。保留 baseline、各 mutant、构建/执行日志、精确绑定日志和 `report.json`。报告记录源码、固件、测试文件及 binding helper 的 SHA-256；收尾检查这些输入和补丁链在测试期间保持不变。

编译参数包括 `-std=c11 -O1 -Wall -Wextra -Werror -Wshadow -Wstrict-prototypes -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer`。

覆盖范围：

- Bank0 与 Bank1 各运行完整 IPv4/IPv6、TCP/UDP、0/1/2 层 VLAN、PPPoE、完整 16 位 endpoint 和 row/token/identity 边界矩阵；有效夹具通过真实固件 parser。额外验证混合 bank 的 32 条发布、row 0/1/0x458/8191，以及 bank2/UINT32_MAX 的 kernel 零命令拒绝和固件拒绝。
- 非法参数、末条非法规则与重复规则的零命令拒绝；相同 tuple 携带不同封装/endpoint/MAC 的固件拒绝行为。
- 两 bank 分别覆盖 32 条规则的全部 34 个命令边界：执行前失败、已执行后丢 ACK、负错误透传、正返回归一化；断言实际固件表 count/enabled 与 callback 次数。
- 在每个边界逐个污染 48 个应答 word，并覆盖额外 capability、status、count、enabled、inflight 异常值；失败后 callback 次数立即停止。
- transport 字段的精确主机数值及独立 little-endian 已知字节向量，包含高位身份、16 位 endpoint、地址、ports、TCI、MAC 和状态哨兵。
- 18 个实际编译运行的 mutants：拒绝 bank0/1、接受非法 bank、跨 bank 放过重复 row/token/tuple、改写发布 bank，以及原有零 token、12 位 endpoint、错误 tuple 范围、漏 row 判重、漏 rule echo、接受少计 count、漏 status、正返回、自动重试、ports 字节交换、跳过预检拒绝。每个 mutant 必须编译成功并以退出码 1 触发运行时 CHECK；sanitizer 错误或超时使 suite 失败。

## 文件范围

- `target/linux/airoha/patches-6.18/995-net-airoha-validate-pon-authorization-publication.patch`
- `target/linux/airoha/patches-6.18/999-zw-net-airoha-align-pon-auth-bank-metadata.patch`
- `target/linux/airoha/tests/npu_auth_publish/verify.py`
- `target/linux/airoha/tests/npu_auth_publish/publish_test.c`
- `target/linux/airoha/tests/npu_auth_publish/README.md`
