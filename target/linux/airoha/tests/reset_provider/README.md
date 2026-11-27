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
