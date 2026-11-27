# Ethernet Return host 回归

在 ponwrt 主仓库运行：

```sh
python3 target/linux/airoha/tests/eth_return/verify.py
```

依赖 Python 3 和 clang。默认产物位于本目录已忽略的 `out/`，可重复运行。
`--cc` 可选择 clang 路径，`--firmware` 可指定 firmware 仓库；默认使用工作区
`an7581-npu-firmware/include/npu_eth_return_abi.h`。`--output` 可选择输出目录。

runner 从当前 989 patch 的完整新增文件 hunk 提取 `airoha_eth_return.c/.h`，
校验 hunk 行数，并直接 `#include "airoha_eth_return.c"` 编译测试。
ABI 优先取当前 988 patch，并逐字节核对 firmware 头文件；988 尚未包含该头时
直接使用 firmware 头。消费者逻辑、ABI 校验函数、生命周期函数和静态
`er_poll` 全部使用实际源码。

clang 启用 `-Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined`
及 `-fno-sanitize-recover=all -fno-omit-frame-pointer`。测试运行 native 和
swapped 两种模式；swapped 通过交换 `cpu_to_le32/le32_to_cpu` 模拟另一种共享
word 表示，覆盖遗漏字节序转换。当前每种模式 **107 个独立用例**，共 **214 次**。

`out/report.json` 保存编译器版本、988/989 patch、提取源码、测试源码 SHA-256、
ABI 来源和两种模式结果；编译及执行日志位于 `out/*-build.log` 和
`out/native.log`、`out/swapped.log`。runner 若发现运行期间 patch 改变则失败，
要求对完整的新版本重跑。

## 覆盖范围

- 两个独立 LAN/PON handle、DMA、NAPI、timer、lower 引用和包统计；销毁或 fault
  一个 source 后，另一个 source 继续接收。
- LAN service 必须为 0；PON 必须保留完整 service-valid 标记和 FE word4 的
  16-bit service，检查前缀和 descriptor 一致性。descriptor 的 source、epoch、
  generation、sequence、buffer、长度、reserved 及格式错误在 binding/copy 前终止。
- binding 在 RCU 内收到精确 lower/config/full-service；旧 lower、source、
  generation、service 或已撤销映射均 drop 并消费，不分配 skb；有效帧验证
  payload、接收设备、EtherType、CHECKSUM_NONE 和字节统计。
- 正预算限制、满预算保留 NAPI 调度、短批次完成、空 poll、ring 槽复用；
  **budget=0 的正常、已 fault、损坏 control 三态均不消费、不完成、不通知 fault，
  也不增加 poll 统计或执行 DMA 访问事件**。
- 交付或 drop 后的 `dma_mb → 清 DONE → dma_wmb → shared consumer → local consumed`
  精确顺序，以及 fault 时保留损坏槽。
- 全部 control 身份字段、reserved/fault、producer 回退/超容量；HOST_ENABLED 和
  STOPPED 接受 0/1，包括 UNBIND 收尾阶段，并拒绝 2。
- BIND/STOP/UNBIND 的 EIO、ETIMEDOUT、EPROTO 错误各自保留 handle、DMA、lower 引用、
  NAPI 和 timer；quiesce 失败不发 STOP；重试完成 STOP、drain、UNBIND 后释放。
- 999 次确定性等待后的 drain 超时与 retry，按预算推进 drain，同时保持所有
  ring NAPI 可运行；drain 中遇到协议错误转 EPROTO 并保留 DMA。
- reset fence 按 dma、bytes、epoch、count、sport、generation 全部字段匹配；
  缺少 callback、fence 未完成、错误 source、旧 epoch 均保留资源；成功后先停 timer，
  再禁用/删除 NAPI、归还 lower 引用，最后释放 DMA 和 handle。
- handle/DMA/skb 分配失败、DMA 地址宽度/对齐/window 边界、创建参数和必需 callback、
  count 边界、重复创建及空 owner 操作；skb 分配失败仍归还 DONE 并推进 consumer。
- 协议错误仅通知一次；修复共享内容及继续 poll 不会重复通知或恢复交付。

## 回调与调用方契约

1. 调用方串行化每个 handle 的 create/destroy/reset-retire 生命周期，并按 SPORT
   独占管理，每个 source 只有一个有效 owner。
2. `quiesce` 关闭全部相关 FE/channel7 生产路径，同时保持**所有 ring 的 NAPI 运行**，
   供 STOP 后 drain 完成；失败返回错误供调用方重试。
3. `binding_matches` 在 RCU 读侧临界区执行，精确匹配 lower、source、generation 和
   full-service。旧映射撤销后返回 false，消费者 drop 并消费对应 descriptor。
4. `fault` 在原子上下文执行，只安排 worker 处理后续恢复；worker 负责需要睡眠的
   mailbox、quiesce 或 reset 操作。
5. `access_revoked` 只在 reset fence 已覆盖相关 harts、FE 和 DMA 访问时返回 true，
   必须按完整 `er_config` 核对，包括 source 和 epoch。
6. 进入 BIND 时 `*out` 已发布。BIND 返回任意错误后，这个 handle 及 DMA 仍由调用方
   持有；后续 STOP/UNBIND/drain 错误也保持所有权。调用方继续 destroy 重试，或取得
   完整 reset fence 后 retire，直到 API 将 owner 清为 NULL。

模块维持**未自动启用**。本回归只编译 host 二进制，不启用设备生产者。
Linux 编译、生命周期接入和实际硬件上的 fence/barrier 效果由主代理负责验证。

## Host stub 边界

`host_stubs.h` 提供本 C 文件所需的最小 Linux 类型及 API 声明。
`consumer_test.c` 提供可检查所有权的堆/DMA/skb 分配、确定性 NAPI/hrtimer、RCU 深度、
回调 fixture 和 DMA barrier/WRITE_ONCE 事件记录。Linux errno 使用固定数值，
使 macOS host 上的 mailbox 请求仍携带 Linux `-EINPROGRESS`（-115）。

测试显式调用真实 `er_poll`；`usleep_range` 只累计等待次数，并按测试配置执行已调度
NAPI，不实际 sleep。timer 由用例显式触发。DMA 使用独立对齐内存和模拟 DMA 地址，
记录 barrier 与写入的程序顺序。所有用例结束后核对 object、DMA、skb、NAPI 和 RCU
资源账本归零；多线程调度和硬件内存排序属于内核与设备集成验证范围。
