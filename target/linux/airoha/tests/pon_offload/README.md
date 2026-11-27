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

EPON 普通数据包（`msg0[8]=0`）走 `ewan_process_rx_message`。原厂按 `msg0[7:3]` 选择 `gpWanPriv + 0x2c930 + channel * 0xc0` 的行。行 `+8` 的 bit23 置位时将 channel 写入 skb `+0xc0`，bit20 置位时计丢弃并返回 -1；通过时按行累计包数和字节数，bit21 可请求清除 skb `+0xa0` 的位 `[7:4]` 并置输出标志。此路径保留 skb `+0xba` 的原值。

```sh
python3 verify_ewan_ingress.py --stock-dir /path/to/stock/lib/modules \
  --output /path/to/results/ewan-ingress.json
```

4,608 个场景从固定 SHA 的原厂函数入口执行至返回。覆盖 32 个 channel、18 种 `msg0[29:14]` 值和全部三位行标志组合，邻行有效位与目标行相反。结果为 1,152 次接收、1,152 次策略丢弃、2,304 次行未启用。此处记录的是 EPON CPU 数据路径；GDM2→FE32 的硬件业务来源和有效条件仍须独立核对。

`971` 在主机 QDMA 收到 PPE 学习请求时，将完整 GEM 与已发布的单播映射比对，EPON 则只比对当前注册的 channel。`973` 同时检查实际接收描述符的队列属于 WAN QDMA1。错误队列、映射更新中、描述符标错、控制包和跨描述符的光侧帧跳过学习，普通收包和控制帧仍按原路交付。RCU 读段覆盖映射查询和学习调用，沿用现有撤流事务的 `synchronize_net()`。运行 `python3 verify_rx_learn.py --source /path/to/linux-after-973` 在两套 QDMA 上核对所有 65,536 个 GEM 值、32×32 对 EPON channel 及异常条件，共 135,332 项；负对照移除队列检查，须捕获错误学习。这项检查用于 CPU 学习入口；已绑定硬件流的逐包业务隔离仍由 FE 分类器负责。

`verify_ifc_service.py --stock-dir /path/to/stock/lib/modules` 执行原厂 `ifc.ko`：在同一 type-0 行组合 GDM2、16 位业务号、EtherType 和无 VLAN/PPPoE 条件，再用第二行隔离仅最高位不同的业务。IPv4/IPv6 各测一轮；按字段正序、逆序写入后核对全部九页，比较 263,168 组输入，并在另一行业务保留时停用、改号、重开第一行。TCAM page 0 的键/掩码是 `4/4`；page 5 是 EtherType/`0xffff`；page 7 是 `service << 16`/`0xffff0430`；page 8 是 `0/0xc0`。匹配检查使用原厂写入模拟 MMIO 的最终表项。

板测分两步。先保持 GDM2 的硬件流关闭，用 `forceCPU` 将仅业务号不同的 A、B 编号包分别送到 WAN CPU 接收环 2、4。它通过动作页 2 `DATA0[28]` 强制送 CPU，页 1 `DATA2[14:10]` 选环；接收端口来自源端口映射。`forcePort(CDM2=5, nbq=2/4)` 是另一种动作，其端口覆盖位在页 1 `DATA1[28]`。脚本分别执行这两个原厂 setter，并对 `forceCPU` 行做 131,072 次 IPv4/IPv6 业务号检查，另测撤销及改号时另一行保持原样。

同一次板上启动须先读回 `REG_SP_DFT_CPORT(0)`（`0x1fb520e0`）的 sport2 字段 `[11:8]` 为 `5`，并确认 QDMA1 接收环 2、4 已分配、索引有效。PPE 默认 CPU 端口和 GDM 默认路由是不同寄存器。实包以相同五元组的独立包号核对来源、收包环和交付；无效业务、撤销后和未匹配包另测。测试中的行号 54/55 是模拟值，实板上这两行由 LAN1 使用；须在现有 IFC 所有权下选择空闲行。LAN1 板测曾发现直接覆盖 GDM 默认 CPU 路由会绕过 IFC（见 `hg5585f-ct/NATIVE_PAIRS.md`）。若在 GDM2 上也出现绕过，应先解决 IFC 与默认 CPU 路由的次序，保留 WAN CPU 回退。

仅在实板确认分类生效、未匹配流量保持 WAN CPU 后，再让一个已配置的非零业务 A 进入独占 PPE 表，检查只有 A 推动绑定行计数并抵达目标。这个方案在 IFC 查表处使用业务号，无需 FE32 向 NPU 透传该字段。原厂字段名为 `GEM_LLID`，EPON 线侧输入值与其 CPU channel 的关系须单独测量。

用目标平台的 C 编译器静态编译 `sport2_rx_snapshot.c`，在设备上先运行 `sport2-rx-snapshot --self-test`，再不带参数运行。工具通过只读映射采集源端口字及环 2、4 的 BASE、SIZE、CPU_IDX、DMA_IDX。2026-11-27 在 HG5585F-CT 普通 RAM 系统上读到 `sport2_map=0x00500500`、`cport=5`；两个环的 SIZE 都是 `0x00100080`，CPU/DMA 索引分别为 `127/2` 和 `0/3`。这次 `pon0_present=0`。带光控制器的测试须在自己的启动周期重新预检，再发送业务探针；环已初始化与编号包命中是两个独立步骤。

`verify_path_order.py` 从真实 netfilter 路径生成、tuple 反转、action 生成和 Airoha action 解析一路执行到 PON GEM 选择。96 个场景覆盖两个方向、IPv4/IPv6、单/双 VLAN、PPPoE+单 VLAN，以及 PPPoE+双 VLAN 的现有两层容量拒绝。IPv6 测试执行驱动的出口准入判断，并检查物理端口、桥接、输入封装键、VLAN 剥离、优先级、保留 VID 和 PPPoE 会话号。

`965` 把入方向 PPPoE 会话号、EtherType 和 PPP 协议加入 flowtable 交给驱动的精确匹配键。184 次入向检查涵盖 IPv4/IPv6、TCP/UDP、相同五元组下仅 SID 高位不同、裸 PPPoE 和外层 802.1Q、硬件处理外层 VLAN，以及保留 SID、倒置和超限封装。Airoha 的 IPv4/IPv6 FOE 当前无法匹配入方向 SID，驱动在发布前拒绝该类规则，保留原有普通 IP 路径和出方向 PPPoE 动作。测试在 CT 和普通 PPE 模式下均检查物理有线出口，另有四个运行期负控制。

```sh
python3 verify_path_order.py --kernel /path/to/linux-after-965 \
  --ppe /path/to/linux-after-965/drivers/net/ethernet/airoha/airoha_ppe.c \
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

## NPU 控制与双来源回送（2026-11-27）

`988` 提供 AUTH36、ER35、GATE37 的内核传输接口，支持旧 LAN 能力 7 与
LAN/PON 双来源能力 15。全零 ER QUERY 保留能力发现用途；所有修改操作校验
source、不可变回显、状态与保留字段。`tests/npu_transaction_transport/` 在
两种字节序下各通过 1,657 项检查，并捕获八项协议校验变异。

`989` 为 SPORT24 和 SPORT2 分别维护 DMA 回送队列、NAPI、timer、lower 引用
与统计。PON 描述符校验完整 16-bit service，并在 RCU 中核对当前映射。
STOP/UNBIND 失败保留 handle 和 DMA，成功排空解绑后释放；reset 释放需匹配
完整配置。`tests/eth_return/` 的两种字节序各通过 107 个 ASan/UBSan 用例。

988/989 在 Linux 6.18.60 上完成 AArch64 驱动编译、模块 modpost/link 和完整
vmlinux 链接。模块检查使用独立内核树，将基线中同一驱动的 17 个 built-in
导出移出外部模块测试的符号清单，保留其余依赖；完整 vmlinux 检查恢复原清单。
模块检查仅保留两个已有的 MODULE_DESCRIPTION 缺失警告，vmlinux 编译无警告。
`hg5585f-ct/prepare-overlay.sh` 已包含这两项补丁及测试，生成内容经 SHA256SUMS
逐文件校验。验收产物位于工作区 `build/pon-er-consumer-20261127/`。

NPU 固件对应的双来源实现已经进入 `an7581-npu-firmware` 主仓库，两个队列
共享 FE/channel7 停止与故障边界，各自维护 epoch、consumer 和 producer。

`990` 实现关闭/重开事务核：先关闭入口与 gate，再用查询得到的旧身份撤销
授权，随后 FE QUIESCE、全局 QUIET 和 PPE drain。每阶段收到有效回执才推进；
失败保留阶段、epoch/generation 及旧授权身份。放弃重开时先 CLOSE 原身份，
再推进 epoch 并重新关闭。CLOSED 阶段的 AUTH_BEGIN/ADD 超时由 owner 显式
分配新 epoch，重新关闭后重建授权。`tests/npu_transaction_core/` 的 366 项
ASan/UBSan 用例已通过，涵盖阶段失败、丢 ACK、身份溢出及两队列排空。
此事务核已随 AArch64 vmlinux 编译；实际入口、寄存器和设备引用由后续 owner
接入，重开期间仍需在各回调检查实时 generation、撤销状态与 ER binding。

`991` 为 bank1 默认路由增加独占所有权。四个 GDM 分别保存请求的 selector，
持有期间把 PPE2 入口导向实际 QDMA CPU 接收者；QDMA 迁移、native 重开、
部分字段更新和 sticky fallback 都继续使用该请求值。旧 PON probe 在任何 IFC
命令前拒绝冲突。恢复失败保留快照并重新关闭入口。74 个 ASan/UBSan 场景及
524,288 个 selector 向量通过，覆盖逐笔 MMIO 故障和恢复。

`992` 增加 native FE 共享所有权，串行化精确 QUIESCE 身份、policy、health、
学习和有线端口事件。`993` 将关闭事务接到 PON 映射更新与驱动退出：使用
flow_offload_mutex 保护 provider 引用，先关闭入口、gate 与旧授权，再排空 FE
和 bank1。首次认领排除旧路由占用，新 epoch 覆盖 gate、FE、wired 和 AUTH；
部分退出失败保留已完成阶段，重试继续释放。持有期间禁止新的 bank1 BIND，
bank0 和 INVALID 撤流继续可用。内部 claim 需显式调用，普通启动不会自动认领。

992 的 96 个生产 C 回归场景、993 的 3,589 项检查及六项运行期负控制均通过
ASan/UBSan。PON 更新事务通过 74 个场景，含 27 个 MMIO 故障位置与六项负控制；
旧版无 owner 路径保留独立回归。991–993 联合通过 Linux 6.18.60 AArch64
vmlinux 编译、modpost 和链接，无警告。验收报告位于上述 build 目录。

下一步完成来源/业务授权、ER 队列生命周期与重开回调，接着隔离同 tuple 的
LAN/PON 软件候选与硬件表项，开放 PON PPE 准入后做实板验收。当前设备沿用
之前通过验收的 RAM 镜像。
