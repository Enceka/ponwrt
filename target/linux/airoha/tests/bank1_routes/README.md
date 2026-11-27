# Bank1 GDM route guard host 回归

`998` 加入持有 owner 的 PON 重开接口，仅开放 GDM2；其它 GDM 的 PPE2
选择器继续送实际 CPU 接收队列。普通镜像、CPU 回退、冲突接收端和撤销状态
均阻止重开。修改路由或发布新 QDMA 之前先关闭 PON，失败保留旧映射；
读回失败立即撤销开放状态。重新 claim 完成关闭后才能再次准备重开。

对包含 `996` 的内核源码运行重开回归：

```sh
python3 target/linux/airoha/tests/bank1_routes/verify.py --reopen \
  --source /absolute/path/to/linux-after-996 \
  --output /absolute/path/to/results/routes-reopen
```

此模式覆盖原有全部回归、118 个场景和 524,288 组选择器组合，使用 ASan/UBSan；
十一个运行时变体覆盖错误 GDM、开放时释放 owner、忽略撤销、忽略 CPU 回退、
遗漏回退选择器、跳过首次 QDMA 发布前关闭、忽略发布后的路由错误及遗漏
QDMA 指针回滚、错误恢复 TX/LRO 状态及遗漏 WAN 标志回滚。发布后失败会
恢复旧指针、等待 RCU，保持 users/IRQ 不变；测试同时覆盖回滚读回失败和
后续重试。报告记录补丁、源码和测试 SHA。

在 ponwrt 主仓库运行：

```sh
python3 target/linux/airoha/tests/bank1_routes/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-ifc-tuple-987-source
```

默认source即上述987源码目录；也可用 `--source` 指定另一份应用至987的kernel源码。
依赖 Python 3、clang和patch。输出默认放在本目录已忽略的 `out/`；`--output` 可指定
产物目录。`--case qdma`、`--case native`、`--case legacy`等可单独运行对应测试组。

runner只读取source，复制相关driver文件到 `out/kernel/`，在副本上应用当前
`991-net-airoha-own-gdm-default-routes-for-bank1-isolation.patch`，要求零offset/fuzz。
988–990涉及的其他文件不参与该构建。重复运行会重新复制基础文件和应用991。

## 使用的真实源码

- 完整include修改后的 `airoha_ct_cpu_fallback.h`、`airoha_bank1_routes.h`，以及真实
  `airoha_ct_ifc_command.h`、`airoha_ct_pon_ifc_words.h`。
- 从修改后的 `airoha_eth.h` 提取真实 `struct airoha_bank1_routes`，核对eth成员和
  `airoha_eth.c`内fallback/guard的include顺序。
- 从driver逐函数原样提取 `airoha_set_gdm_port_fwd_cfg`、`airoha_dev_set_qdma`、
  `airoha_ct_pair_gdm_route/start/stop`、`airoha_ct_fe_table`、
  `airoha_ct_pon_ifc_read`、`airoha_ct_pon_ifc_route_open`并联编。
- 旧PON路径通过真实table/command实现执行读操作，MMIO模型记录其对
  `CT_IFC_CONTROL`的写入。因此“owner存在时零寄存器写”也覆盖分类器读命令。

clang启用 `-Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined`
`-fno-sanitize-recover=all -fno-omit-frame-pointer`。保留kernel源码原有类型，关闭
host构建的sign-compare告警；stub未使用参数关闭unused-parameter告警。

`out/report.json`记录是否整套运行、source路径、基础及应用后文件SHA-256、991哈希、
提取函数哈希、测试源码哈希、编译器与结果。日志为 `out/apply.log`、`out/build.log`、
`out/routes_test.log`。每次开始清除旧报告，只有成功运行才生成新报告；单组报告的
`case`字段为组名，整套为`all`。运行期间991变更会要求重跑。

## 覆盖

- 四个GDM各四个低nibble selector的全部组合，分别运行普通和ordinary策略：
  **524288个selector向量**。检查仅指定PPE路由被过滤，direct、DROP和高16位保留。
- 首次claim在第一笔写入前保存全部四个desired；同owner claim重新写入并回读，
  保留原desired。空指针、空owner、foreign owner、bank1/host PPE缺失检查。
- claim、release恢复及partial update的每个GDM位置分别注入丢写与回读损坏；
  release部分恢复失败后检查四GDM全部重新guard。再注入重新guard阶段的故障，
  确认owner/desired/ready保留并可claim修复后release。
- 所有GDM写入紧跟同寄存器回读；release在bank1 FLOW_CFG非零或GLO BUSY置位时
  保留现场且零写入；FLOW_CFG/BUSY清除后恢复。
- 实际QDMA0/1、无设备、未知QDMA、inactive设备、单active接收者及双active冲突。
  无接收者使用DROP，冲突使用DROP并返回EXDEV，修复receiver后重试。
- 真实QDMA迁移函数在guard独占且未触发sticky fallback时重算CPU目的地；直接locked
  rewrite也使用原desired，不将过滤后的CPU路由误当成请求意图。
- QoS高位和partial-bit mask从desired合并；PPE2 nibble 8部分更新bit0应得到9，
  explicit DROP及原生PPE1→PPE2重写均更新desired；release恢复最新请求。
- 真实native bank start/stop在guard持有期间保留完整未过滤快照。
- guard持有期间触发sticky fallback，从desired记录PPE1/PPE2掩码；release仍应用
  sticky CPU策略。ordinary策略、已有sticky fallback和后续reopen请求继续受保护。
- 旧PON route_owned阻止claim；guard owner阻止真实旧PON route_open，返回EBUSY且
  包括IFC command在内零寄存器写；guard释放后旧路径可正常开放。

## 调用约定与模型

claim/release由持有 `flow_offload_mutex` 的owner串行调用，内部取得`ct_route_lock`。
测试stub检查锁状态及RCU深度，模拟对齐后的寄存器索引、实际QDMA接收者、写入丢失、
回读损坏和确定性的IFC DONE。QoS队列、netdev feature、统计等外围操作用最小stub。
GDM/guard/fallback/native/PON路由逻辑均执行真实driver代码。

release前owner负责完成gate/FE quiet并撤销旧FOE。guard只检查bank1 FLOW_CFG/BUSY并
恢复路由，不重新查询协议；失败后owner及desired仍需保留供重试。模块保持未自动启用。
本测试只生成本机host产物，不访问设备、不修改原source、Git索引或其他测试目录。

`--invalidation` 在 `--reopen` 基础上应用 `999-z` 的公开撤销入口。
入口允许持 `ppe_lock`、未持 flow mutex 的通知路径调用，内部只获取 route lock。
测试检查 foreign owner 零写入、关闭后禁止直接重开、desired 快照保留，以及四个
GDM 的逐笔丢写和读回错误。失败保持 revoked，后续撤销可以重试；显式 claim
负责重新建立关闭态。运行时负对照覆盖错误 owner 和跳过实际路由关闭。

```sh
python3 target/linux/airoha/tests/bank1_routes/verify.py --invalidation \
  --source /absolute/path/to/linux-after-996 \
  --output /absolute/path/to/results/bank1-invalidation
```

## PON NPU ingress 生命周期

`--ingress` 独立使用应用至 `999-zd` 的基线，复制后严格应用
`999-ze-net-airoha-connect-pon-npu-ingress-lifecycle.patch` 中路由测试涉及的文件。
默认基线为 `/Volumes/Workspace/5585f/build/pon-er-consumer-20261127/owner-source-npu-ingress`，
默认产物为本目录的 `out/ingress/`。原有默认、`--reopen`、`--invalidation` 模式
保持各自基线、断言与运行时变体；不能和 `--ingress` 同时指定。

```sh
python3 target/linux/airoha/tests/bank1_routes/verify.py --ingress
```

该模式直接 include 修改后的生产 `airoha_bank1_routes.h`、
`airoha_ct_cpu_fallback.h`、`airoha_npu_ingress.h` 与其 IFC owner/words 头文件，
从生产 `airoha_eth.h` 提取 route 结构体。保留既有 GDM/QDMA/native/旧 PON 函数提取，
另提取 `airoha_ifc_update_ports`、`airoha_ifc_scope_ports`、
`airoha_ifc_scope_update` 和 `airoha_ifc_lan_ports_ready` 的完整函数体。
`ingress_ready(eth, owner)`、`check(eth, owner, opened)`、scope helper 均执行生产实现。

当前包含 **93 个场景、655,360 组 selector 向量、16 个运行时负对照**，启用
ASan/UBSan。覆盖内容包括：

- claim/revoke 在 route lock → IFC port lock 下先关闭 SPORT2 并回读，再写 GDM；
  open 保持 GDM2 四个 selector 为实际 CPU，最后开放 source2。
- 首次 claim、重新 claim、open、revoke 的 scope 丢写和已生效写入后的坏读回；
  open 失败叠加关闭失败、随后重复关闭、重新 prepare/open，保留 owner、desired 和
  真实 ingress rows 的 saved/active/dirty 状态。
- GDM 各位置的丢写/坏读回，以及 release 恢复失败保留 owner 并重新 guard。
  IFC 仍打开 SPORT2 时，即使 FLOW_CFG 已清零也拒绝释放 owner。
- fallback/stopping 中关闭重试，`ct_host_ppe` 已清除时既有 owner 重新 claim，
  错误 scope 位收敛到 LAN1，未建立 scope 但 IFC 开启时拒绝视作成功关闭。
- ingress_ready、原有资格、CPU 接收者、PPE enable/flow、IFC 配置、实际端口读回的
  拒绝路径；公开 check 对硬件/软件状态变化的只读检测。
- 其他 scope_update writer 在 owner 存在时零写入拒绝；scope_ports 阻止新 scope
  及 prepared/open 状态的释放，允许关闭后 shared IFC stop。普通 port writer
  更新 desired 时继续遵循已关闭的 scope。
- 实际 QDMA 切换先完成关闭，失败保留旧指针/users/IRQ；native/QoS 路由更新继续
  保持 CPU default。四 GDM 全 selector 组合覆盖普通策略；另穷举 GDM2 的 QDMA0
  关闭态和 QDMA1 开放态。
- 用真实 ingress 编码结果驱动最小 TCAM 匹配模型：IPv4/IPv6 命中送 NPU port 6，
  short、其他协议、source 不匹配及关闭态走 CPU default；任何默认 selector 都不
  直接送 PPE2，AUTH 前的数据包不会经 GDM default 绕过 NPU。

负对照在复制出的生产函数中分别破坏 CPU default、ingress_ready、scope 回读、
关闭顺序、fallback 重试、owner 检查、硬件 check、其他 scope writer 防护、
SPORT2 释放防护和恢复失败保留 owner 等行为；要求每个变体触发运行时断言。
变体结束恢复原函数，再重新编译并运行完整 ingress 测试。

`out/ingress/report.json` 记录模式、完整生产补丁 SHA-256、基线/应用后源码 SHA、
提取函数 SHA、测试 SHA 和负对照结果；`ingress-routes.patch` 保留实际应用的补丁片段。
运行结束同时核对基线和生产补丁未变化。`--case ingress` 可只执行正向及故障场景，
跳过运行时负对照；失败运行删除旧报告并保留日志供定位。
