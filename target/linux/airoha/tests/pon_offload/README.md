# PON 卸载验证

## 事务、准入与撤销

`959` 将 PON 更新串成同一事务：暂停数据与 OMCI/OAM TX，等待已提交描述符完成，撤销双向 FOE，按原厂流程关闭并退役通道，更新 GEM/T-CONT 或 LLID，发布映射后恢复队列。失败保留 gate、通道快照、映射和 cookie，供后续重试。DSA 来源通过 conduit 和 RX port metadata 核验；实际绑定同时检查输入封装。

Host 使用 `flow_offload_mutex` → `pon_config_lock` 锁序。控制器须在同一 `state_lock` 下调用 begin→更新→end；配套 feed 为 `pon-drivers` 提交 `7639f2f`（airoha-xpon release 71）。仅更新 host 或仅更新 feed 都会缺少配套接口。构建时将本地 feed 作为 `src-link pon_drivers /absolute/path/to/pon-drivers`，再更新并安装对应 feed 包。

```sh
python3 verify_transaction.py --source /path/to/linux-after-959 --output /path/to/results/transaction
python3 verify_tx_gate.py --source /path/to/linux-after-959 --output /path/to/results/tx
python3 verify_admission.py --source /path/to/linux-after-964 --output /path/to/results/admission
python3 verify_pon_flows.py --source /path/to/linux-after-959 --output /path/to/results/flows
python3 verify_retirement.py --source /path/to/linux-after-959 \
  --stock-dir /path/to/stock/lib/modules --output /path/to/results/retirement
```

生产函数测试包括 73 个 host 事务场景（含 27 个 MMIO 写故障位置）、18 个 TX 分片/回收场景及非 PON 回归、721 个准入/绑定场景、62 个双向撤销场景，共 36 个运行期负控制。准入测试涵盖路由无线出口的站点撤销、WCID 复用、代次耗尽与跨频段隔离。原厂退役差分执行 288 个场景，并加测 64 个过期/占用命令和 64 个写故障恢复场景。控制器仓库另有 41 个事务场景和 35 个恢复场景。

当前已实现 routed IPv4/IPv6 TCP/UDP 的 PON 与有线双向准入、WLAN→PON，以及物理 PON 出口的 VLAN/PPPoE 编码。PON 硬件准入默认关闭，等待前置硬件分类器隔离来源、VID 和 PPPoE 会话；现阶段 PON 继续软件转发。HQoS 开启模式、PON→WLAN、PON bridge、入方向封装继续补齐。范围见 `PPE-README.md`。

### RAM 共用路径回归（2026-11-26）

完整内核和配套控制器模块交叉编译通过；模块导入、导出及 vermagic 校验完成。NAND-disabled RAM FIT 的 SHA-256 为 `1dd404bc598f8aae88acd031e75b6fbfd5db88db578e1b7e83f09303663dff1f`，保留已验收的 ABI3/caps63 NPU。四个方向均为 TCP 四流、各 30 秒、接收端速率：

| 方向 | 吞吐 Mbps | HG5585F 整机 CPU |
|---|---:|---:|
| LAN1 → Mac Wi-Fi | 1312.411 | 3.977% |
| Mac Wi-Fi → LAN1 | 943.127 | 1.139% |
| Mac Wi-Fi → CMCC STA | 325.509 | 2.107% |
| CMCC STA → Mac Wi-Fi | 611.256 | 2.588% |

四向均通过 native 表项、软件 CT 计数、NPU 提交/完成、站点身份及错误检查；LAN1 FE fault/drop 增量和测试结束时在途包为零。无线互传允许 LAN1 FE 已正常排空并空闲，同时继续检查无线 TDMA 计数推进。PON 硬件准入保持关闭，光口验收按前述范围继续推进。

原 `958` 的映射提交测试保留在 `verify_lifecycle.py`，用于输入 `linux-after-958`。`959` 将映射提交测试移入 `verify_transaction.py`，双向 FOE 撤销由 `verify_pon_flows.py` 独立覆盖。

## 原厂元数据对照

`verify_rx_service.py` 对照原厂 `qdma_wan.ko` 与 host 接收路径。1,058 个描述符覆盖所有 32×32 组来源端口和 CPU reason，以及 GEM/LLID 的每一位和边界。`msg0[29:14]` 保存完整 16 位服务号。原厂 `qdma_api_get_rxmsg_eth` 输出偏移 `+6` 是 CPU reason（`msg1[20:16]`），`+7` 是来源端口（`msg1[25:21]`）。早期 v6 向量报告将这两个偏移的名称对调；本测试额外执行原厂 INT-2 错误日志的取参指令，核对 `crsn=%X` 实参。GDM2 来源端口 2 位于 `msg1[25:21]`。

```sh
python3 verify_rx_service.py --source /path/to/patched/linux \
  --stock-dir /path/to/stock/lib/modules --output /path/to/results/rx-service
```

`verify_gwan_ingress.py` 运行原厂 `gwan_process_rx_message`，将其产出的完整 skb 原样交给原厂 `PpeGemportCheck`。594 个场景涵盖本机单播、未知单播、广播、组播、channel 32、无效映射、OMCI 和 FOE 槽位复用。工具固定两个模块的 SHA，接收函数内无桩；流表函数的日志和最终硬件删除调用以桩记录。

```sh
python3 verify_gwan_ingress.py --stock-dir /path/to/stock/lib/modules \
  --output /path/to/results/gwan-ingress.json
```

数据路径用 `msg0[29:14]` 查 16 位 GEM 映射表，取 `index & 0x7fff`；有效行号为 0–255。每行 `0xc8` 字节，`+0xc` 为启用字节，`+8` 为 channel，`+4` 为 ANI。普通 channel 接受 ANI ≤ 256，channel 32 走独立分支。成功后 skb 的 `+0xba` 持有完整 GEM，`+0xb8` 区分 channel 32，`+0xc0` 为 ANI 低八位，`+0xbc` 置 `0x400`。默认配置下第四个输出参数保持零；启用行内 `+9` 后，channel 0/31 的此参数置一，channel 32 保持零。`msg0[8]` 置位时按控制器的 OMCC 行计数，保留数据 skb 服务字段；OMCC 未配置时返回 -1。

在同一个 FOE 槽位、两个 VLAN 输入和两个 channel 下，`PpeGemportCheck` 读取生成的 skb `+0xba` 与 `foe_ext[entry]+0x5c` 比较。36 次匹配均保留，36 次仅翻转 GEM 高字节一位的错配均清空服务并请求删除该槽。此验证覆盖原厂 CPU 收包及 FOE 复核；NPU 快路径仍需定位 GDM2 写入 FE32 服务字和类型有效位的硬件来源。

`verify_path_order.py` 从真实 netfilter 路径生成、tuple 反转、action 生成和 Airoha action 解析一路执行到 PON GEM 选择。96 个场景覆盖两个方向、IPv4/IPv6、单/双 VLAN、PPPoE+单 VLAN，以及 PPPoE+双 VLAN 的现有两层容量拒绝，另有两个运行期负控制。IPv6 测试执行驱动的出口准入判断，并检查物理端口、桥接、输入封装键、VLAN 剥离、优先级、保留 VID 和 PPPoE 会话号。

```sh
python3 verify_path_order.py --kernel /path/to/linux-after-963 \
  --ppe /path/to/linux-after-963/drivers/net/ethernet/airoha/airoha_ppe.c \
  --output /path/to/results/path-order
```


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

原厂对照直接执行 SHA 固定的 `.ko` 指令，从 `gwan_prepare_tx_message@0x4b7dc`、`PpeSetPortInfo@0x54bb0` 的函数入口运行到返回，ELF 重定位在模拟内存中完成。函数内部的 PON 映射检查、描述符编码、FOE 修改均由真实二进制执行。输入提供原厂 GEM 表、skb 映射 handle 和已有 VLAN/PPPoE 字段；配置依赖以桩提供：五个局部 QoS/mark helper 保留默认值，`GET_HIR` 提供芯片分支值，TPID→VPM 转换执行原厂函数，可选 hook 指针保持零，ECNT HQoS 查询明确提供关闭或缺失状态。执行过的桩与指令数写入结果；未知 helper 立即失败。该 oracle 没有使用指令转录公式。

比较字段采用各自实际布局。原厂 type2 使用硬件 L2B，host `prepare` 先生成软件 bridge 模板；这两个结构的 IB2/L2 偏移分别解码。原厂 port mapper 只更新出口字段；PPPoE/VLAN 为前序 parser 的输入，因此测试同时检查它们在 port mapper 执行后保持完整。Host 的队列选择桩固定为 0，队列策略由独立 QoS 验收覆盖。

每次运行生成 `verification.json`、完整输入向量、原始输出、提取源码、编译日志和输入源码 SHA。七个变异分别破坏最外层 VID 选择、TPID/VPM 编码、GEM、5 位 T-CONT、PCP 一致性、精确 VID 优先级、无映射拒绝；每项都必须由运行期断言检出。构建失败单独报错，不计为变异通过。

修复后的候选通过 2,172 个 host 向量（38 个按预期拒绝）；其中 2,102 个成功映射与原厂函数二进制逐项比较，另有 32 个 EPON 固定 LLID 用例。普通和 ASan/UBSan 两种构建均执行全组。额外覆盖原厂 6 个无效映射/无效 alloc、80 个芯片分支与边界 T-CONT、80 个缺失 HQoS hook 场景，以及 4 个实际 QDMA hook 执行用例和 8 个真实 TPID 转换/FOE 编码用例。

HQoS 的适用条件已单独核对：`PpeSetPortInfo` 在 HIR `0xc/0xe/0xf/0x10` 查询 group `0x12`（LAN）和 `0x11`（WAN）的 command `0x9c`；原厂 `.data` 分派表此项是 `qdma_get_hqos_en()`。getter 在 `qdmaLanHqosMode` / `qdmaWanHqosMode == 1` 时返回 1，初始 `.bss` 值均为 0。工具实际执行两个 dispatcher 及 getter，验证初始关闭和显式启用两种状态，整个调用无需 helper 桩。PON 使用 WAN 查询结果：启用或 hook 返回 -1 时，T-CONT 0–15 的 FOE channel 加 16，NBQ 保留原 T-CONT；16–31 保持原 channel。HIR `0xa` 不做这两个查询。`stock-chip-layouts.json` 保存每项的原始 80 字节 FOE。原厂 `qdma_dev_hqos_init()` 将此开关写入 QDMA `base+0x90` bit31；未来启用重建 HQoS 时需同步支持这个 channel 变换，当前元数据差分采用原厂初始关闭配置。

覆盖包括映射替换、删除、重建后重新分类的输入序列。并发 FOE 撤销、checked invalidation、quiesce/drain 和 CT PON admission 由本目录其它生命周期工具验收。光链路 O5/DBA、OLT 与线侧加密在光口验收阶段执行。
