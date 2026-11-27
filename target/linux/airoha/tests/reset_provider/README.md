# EN7581 reset provider 主机测试

运行：

```sh
python3 /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/reset_provider/verify.py
```

依赖 Python 3、clang 和 patch。默认下载 Linux v6.18 的 `clk-en7523.c`，
校验固定 SHA-256，在临时目录应用主仓库中修改该文件的补丁（包括 609-05 和后续 913）。
`--base-source /path/to/clk-en7523.c` 可提供相同散列的离线原始文件。
`--output /path/to/results` 可指定产物目录；默认创建独立临时目录并保留报告和日志。
runner 不操作 Git 索引、设备或 VM，原始源码与仓库内已有补丁只读。

测试从实际展开源码提取 `en7523_reset_update/assert/deassert/status`、reset 结构、
bank offset 数组和寄存器常量。仅 regmap 与 Linux 类型使用 host stub。
609-05 必须以零 fuzz、零 offset 应用，后续补丁允许正常行号偏移。

覆盖普通 RST_CTRL1/2 与反极性 PCIC 三个 bank 的每个 bit；id 是 reset framework
完成 xlate 后的硬件编号。每个 assert/deassert 检查目标值、完整 mask、其它 bit/bank
保持、重复操作幂等和 status；regmap RMW 读失败、写失败及 status 读失败分别注入
Linux `-EIO/-EAGAIN/-ETIMEDOUT`，随后验证重试。

原样提取函数分别使用 clang 自动变量 zero/pattern 初始化模式执行 ASan/UBSan。
另一个测试构建仅将两个 `u32 val;` 声明初始化为运行时种子，交叉枚举 68 个局部初值
和 68 个寄存器初值：全零、全一、交替位、每个单独置位和每个单独清位。
所有分支、regmap 调用和返回逻辑保持实际函数内容。

7 个负对照必须编译成功并触发运行时断言：609-05 前的原函数、恢复 `|=`、丢弃更新错误、
丢弃读取错误、错误 PCIC 极性、覆盖无关位、错误 status 极性。
报告保存上游源码、所有 clock 补丁、实际函数和测试文件散列，以及各构建结果。

这些测试验证 reset provider 的位操作和错误传播；NPU 硬件撤销、设备树接线及
实际复位完成时序属于后续独立实现。

## NPU DMA 访问撤销的硬件依据

2026-11-27 核查采用原厂 SDK 镜像固定版本
`32b5aa356c2406edef8806aaf75451ff0a5286f2`，只读取寄存器接口和控制流程。

- [ecnt_gdma.c](https://github.com/lotusmomo/airoha_sdk/blob/32b5aa356c2406edef8806aaf75451ff0a5286f2/linux/arch/arm64/mach-econet/ecnt_gdma.c)
  的 `WAIT_GDMA_DONE()` 等待通道 CT0 的 bit1 自然清零；通道步长为 `0x10`，
  CT0 偏移 `0x08`，DONE 偏移 `0x204`，DONE 对应 bit 写一清除。
  当前固件使用的 channel3 对应 `0x1fb30038.bit1` 和 `0x1fb30204.bit3`。
- 本项目 `clk-en7523.c` 将 NPU reset 映射到 SCU `+0x830.bit9`，GDMA reset
  映射到 `+0x834.bit14`；两个 master 分别管理断言状态。
- [ecnt_npu.c](https://github.com/lotusmomo/airoha_sdk/blob/32b5aa356c2406edef8806aaf75451ff0a5286f2/linux/arch/arm64/mach-econet/ecnt_npu.c)
  的 `host_set_npu_core_on_off()` 修改 core boot mask，再触发并固定延时。
  `is_npu_dma_done()` 和 `is_npu_idle()` 读取固件 MIB9/MIB8；
  `enable_npu_rbus_decoder()` 管理 L2C SRAM decoder。
- 本项目固件 `src/eth_return.c` 同时存在 hart 直接写 DRAM 和独立 GDMA 路径。
  reset fence 的完成条件须同时覆盖这两类访问和已经发出的总线写事务。

后续硬件核实集中在三点：全部 harts 停止的新访问确认；GDMA abort/reset 的
完成与 outstanding 状态；NPU→host DRAM bridge 的隔离与写缓冲排空条件。
正常完成的 CT0 采样放在主动清位或 reset 之前，分别记录自然完成与强制停机。

provider 实现应在 ER BIND 发出前登记 `dma/bytes/epoch/count/sport/generation`
和分配、运行、reset 代次。超时保留曝光记录。正常退役沿用
QUIESCE→STOP→消费完成→UNBIND；强制退役在硬件完成条件满足后才发布访问撤销。
逐项 assert 保留已经成功的步骤，避免 bulk assert 失败回滚。
待硬件条件补齐期间保留 ring、ctx 和 provider 生命周期，走 CPU fallback；
remove 路径同步处理 devres、timer、NAPI 和 delayed work 的最后引用。

## 驱动解绑与资源保活

2026-11-27 对截至 `999-zc` 的合成源码复核：`airoha_remove()` 是 void
回调，`airoha_ppe_ct_shutdown()` 或后续 `airoha_hw_cleanup()` 失败后返回，
driver core 仍继续解绑并释放 devres。`eth/ppe/QDMA` 元数据和 `dmam_*`
分配会随之释放；普通分配保留的 owner、return path 和 ER ring 仍引用它们。
因此异常退役需要保留整个宿主/provider 生命周期。

成功退役路径已有相应顺序：ER QUIESCE/STOP、消费完成、UNBIND 后停止
hrtimer/NAPI，再释放 ring；随后停止 path fault work，最终停止 owner
health work。普通可重试的 close 错误仍需 NAPI 消费完成，不能提前 park。
若新增终止专用 park，应独立记录状态，避免重复 `napi_disable()`，同时
封住所有 work 重排入口。

当前 HG5585F 配置把 `NET_AIROHA` 和 `NET_AIROHA_NPU` 编为 built-in，
两个 platform driver 均设置 `suppress_bind_attrs=true`。后续可先为专用
镜像强制检查这些条件与固定 DT，保持常驻运行；动态设备/supplier 注销
仍需单独约束。device link 管理解绑顺序，`get_device()` 保留 device 对象，
二者都不承担阻止 driver core 释放 devres 的职责。

源码入口（相对截至 `999-zc` 的内核树）：

- `drivers/net/ethernet/airoha/airoha_eth.c`：`airoha_remove()`、驱动注册。
- `drivers/net/ethernet/airoha/airoha_npu.c`：provider 无 remove 回调，
  shutdown 仅撤 capability，mailbox DMA/MMIO 使用 devres。
- `drivers/net/ethernet/airoha/airoha_eth_return.c`：`er_release()`。
- `drivers/net/ethernet/airoha/airoha_npu_return.h`：return path 销毁。
- `drivers/net/ethernet/airoha/airoha_npu_owner.h`：owner 退役。
- Linux v6.18 `drivers/base/dd.c`：`__device_release_driver()`、
  `device_unbind_cleanup()` 与 `devres_release_all()`。

## 2026-11-27 provider 进展与下一步

`999-zg` 已实现 BIND 前完整配置登记、两来源串行化、低30位 DMA 窗口
重叠检查和精确 STOP/UNBIND 退役。`999-zh` 在触发后出现不确定错误时
冻结整个共享 mailbox，保留 buffer 和 ER 登记，避免迟到响应混入新请求。
对应主机测试位于 `../npu_er_provider` 和 `../npu_mailbox`。

进一步核查固定 SDK 的 `ecnt_rbus.c` 与 `private/tcci/cpu_bus_arm_test.c`
发现 `0x1fa00130 WB_ValidBits`、`0x1fa00110–12c WtBuff` 及
`0x1fa00134–14c DMA_Port`。原厂测试覆盖 host CPU 写缓冲与 DMA 读的
地址冲突控制；NPU→DRAM 写事务的覆盖范围和隔离 ACK 继续核实。
现阶段这些寄存器只作为诊断线索，生产代码沿用正常协议退役。

固定产品的最终配置要求 ETH/NPU/SCU built-in，OF_DYNAMIC、OF_OVERLAY
和 kexec 关闭，provider、supplier 及其父设备常驻。动态释放入口的检查
需在进入 driver core 之前完成。另一个待处理点是启动时序：provider probe
应先完成资源准备，在成功绑定后的显式 start 阶段启动 master；启动后的
故障保留常驻资源。该时序与最终配置准入完成后再推进 PON 资格开放。
