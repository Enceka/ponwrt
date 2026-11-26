# PON 元数据离线差分

## CT PON 流表撤销

`958` 使业务映射在 CT 硬件流表撤销成功后发布。读取或写入 SRAM 超时会返回错误，并保留旧映射及待重试的 cookie/hash；撤销前核对实时 tuple、GEM/T-CONT 和转发动作，避免覆盖已复用的行。哈希表扩容后重复返回的对象只收集一次。

```sh
python3 verify_lifecycle.py --source /path/to/linux-after-958 \
  --output /path/to/results/lifecycle
```

这组测试执行提取的生产函数，覆盖 38 个场景与 6 个运行期负控制，包括写入已生效但 ACK 超时、部分撤销后的重试、hash 复用、FIN、扩容重启和遍历错误。三份相关驱动已交叉编译，原生卸载回归通过 1,063 项、131,072 个 selector 组合及 19 个负控制。

CT PON 准入仍处于后续接通阶段：控制器需要先同步软件 TX，撤销旧流并按原厂流程关闭、排空通道，再更新 GEM/T-CONT。Alloc-ID 撤销、LOS、EPON 重注册和 OMCI 变更需使用同一事务。

## 原厂元数据对照

`verify_metadata.py` 提取指定 host 源码中的真实 C 函数，并以 Clang 普通构建及 ASan/UBSan 构建执行。同一批成功映射再与 `stock_oracle.py` 执行的原厂 AArch64 函数比较。

```sh
python3 verify_metadata.py --source /path/to/baseline/linux \
  --stock-dir /path/to/stock/lib/modules --output /path/to/results/base --mutations
python3 verify_metadata.py --source /path/to/candidate/linux \
  --stock-dir /path/to/stock/lib/modules --output /path/to/results/candidate --mutations
```

可从任意目录调用脚本，三个路径参数均须显式提供，相对路径按调用目录解析。`--source` 接受内核树根目录或包含 `airoha_ppe.c` / `airoha_eth.h` 的目录。`--stock-dir`（同义参数 `--modules`）指向原厂 `xpon_10g.ko`、`hw_nat.ko`、`qdma_lan.ko`、`qdma_wan.ko` 所在目录。依赖 Python 3、pyelftools、Unicorn 2.1.4、Clang；不执行设备操作。

工具文件：`verify_metadata.py`、`stock_oracle.py`、`metadata_runner.c`、`metadata_stubs.h`。内核源码和原厂模块均作为外部输入，结果写入 `--output` 指定目录。

提取并执行的生产函数：

- `airoha_ppe_pon_lookup_tag()`：精确 VID、VID_ANY 与八个 PCP 查询。
- `airoha_ppe_pon_select_flow()`：EPON 固定 LLID；无映射、缺失 PCP、GEM/T-CONT 分流拒绝。
- `airoha_ppe_foe_entry_prepare()` 及其 bridge 地址 helper：FOE 的 GEM、T-CONT/channel、NBQ、GDM2、IPv4/IPv6、VLAN/双 VLAN、PPPoE session 与 DSCP/ECN 保留。

原厂对照直接执行 SHA 固定的 `.ko` 指令，从 `gwan_prepare_tx_message@0x4b7dc`、`PpeSetPortInfo@0x54bb0` 的函数入口运行到返回，ELF 重定位在模拟内存中完成。函数内部的 PON 映射检查、描述符编码、FOE 修改均由真实二进制执行。输入提供原厂 GEM 表、skb 映射 handle 和已有 VLAN/PPPoE 字段；配置依赖以桩提供：五个局部 QoS/mark helper 保留默认值，`GET_HIR` 提供芯片分支值，TPID helper 提供 VPM，可选 hook 指针保持零，ECNT HQoS 查询明确提供关闭或缺失状态。执行过的桩与指令数写入结果；未知 helper 立即失败。该 oracle 没有使用指令转录公式。

比较字段采用各自实际布局。原厂 type2 使用硬件 L2B，host `prepare` 先生成软件 bridge 模板；这两个结构的 IB2/L2 偏移分别解码。原厂 port mapper 只更新出口字段；PPPoE/VLAN 为前序 parser 的输入，因此测试同时检查它们在 port mapper 执行后保持完整。Host 的队列选择桩固定为 0，队列策略由独立 QoS 验收覆盖。

每次运行生成 `verification.json`、完整输入向量、原始输出、提取源码、编译日志和输入源码 SHA。五个变异分别破坏 GEM、5 位 T-CONT、PCP 一致性、精确 VID 优先级、无映射拒绝；每项都必须由运行期断言检出。构建失败单独报错，不计为变异通过。

基线与候选各通过 2,170 个 host 向量（38 个按预期拒绝）；其中 2,100 个成功映射与原厂函数二进制逐项比较，另有 32 个 EPON 固定 LLID 用例。普通和 ASan/UBSan 两种构建均执行全组。额外覆盖原厂 6 个无效映射/无效 alloc、80 个芯片分支与边界 T-CONT、80 个缺失 HQoS hook 场景，以及 4 个实际 QDMA hook 执行用例。

HQoS 的适用条件已单独核对：`PpeSetPortInfo` 在 HIR `0xc/0xe/0xf/0x10` 查询 group `0x12`（LAN）和 `0x11`（WAN）的 command `0x9c`；原厂 `.data` 分派表此项是 `qdma_get_hqos_en()`。getter 在 `qdmaLanHqosMode` / `qdmaWanHqosMode == 1` 时返回 1，初始 `.bss` 值均为 0。工具实际执行两个 dispatcher 及 getter，验证初始关闭和显式启用两种状态，整个调用无需 helper 桩。PON 使用 WAN 查询结果：启用或 hook 返回 -1 时，T-CONT 0–15 的 FOE channel 加 16，NBQ 保留原 T-CONT；16–31 保持原 channel。HIR `0xa` 不做这两个查询。`stock-chip-layouts.json` 保存每项的原始 80 字节 FOE。原厂 `qdma_dev_hqos_init()` 将此开关写入 QDMA `base+0x90` bit31；未来启用重建 HQoS 时需同步支持这个 channel 变换，当前元数据差分采用原厂初始关闭配置。

覆盖包括映射替换、删除、重建后重新分类的输入序列。并发 FOE 撤销、checked invalidation、quiesce/drain 和 CT PON admission 由本目录其它生命周期工具验收。光链路 O5/DBA、OLT 与线侧加密在光口验收阶段执行。
