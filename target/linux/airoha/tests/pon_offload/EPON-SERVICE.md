# EPON FE service 核查（2026-11-27）

## service0 实现进展（2026-11-27）

基于 ponwrt `860580c`、生成源码到 `999-ze`，新增 `999-zf` 已开放
CPU `set/tuple` 的 service0，tuple 存活检查使用 active、tuple 和 lease
状态，精确零值可与 typed wildcard cover 并存。回环 mapping 显式传入
配置/撤销标志，transmit 接受0。NPU owner 互斥及 PON PPE 资格关闭保持。
生产函数普通版与 ASan/UBSan 均通过生命周期、全16位匹配、超时保留及
旧非零回归；复现方式和逐项计数见 [service0/README.md](service0/README.md)。
本次执行主机测试，RAM 内核的 service0 逐包验收留给后续集成。
下文保留核查时的基线结论及真实 EPON 输入配对方案；其中第1项软件准备已完成。

## 明确结论

**channel0 合法。wire LLID、EPON channel、IFC service、FE service 是四个需要分别记录的量。** 当前单 LLID 控制器使用 channel0，同时从 MAC 注册状态取得完整 16 位 LLID；主线已发布这两个身份。IFC 与 FE 的字段位置已明确，真实 EPON 输入的 `IFC service == FE service == wire LLID` 等式仍待测。

本轮核查基线：ponwrt `f75a2667706bb5662ba48ade14fb44f0e7ece4d1`、pon-drivers `14e90e8104a89b755abdb0ff001e24abc5f239dc`、NPU `faa4e944b8f6b6faf3290a0e32e5642790ce19be`。本轮执行源码、既有记录和原厂指令静态复核，校验原厂模块 SHA 与 SDK 文件 Git blob；文中测试数量来自已有记录。

**当前无光侧/OLT，本地下一步是补齐 service0 的 CPU 诊断及回环生命周期，并复用原厂接口仿真核对 channel/LLID 编码。** 下文保留真实注册输入的最小配对方案，供具备光侧条件时补充验收。分类规则组件可继续复用；EPON 的 FE service 适配按配对结果确定。

## 字段对照

| 量 | 已知编码与用途 | 证据 |
| --- | --- | --- |
| `L`：wire LLID | OLT 注册给出的 16 位值；MAC `LLID0_DISCOVERY_STATUS`（相对 EPON 寄存器窗口 `+0x80`）低16位为值，bit16单独表示有效。控制器读取后保存为 `epon.llid`。 | E1、S1 |
| `C`：EPON channel / LLID index | 本地表索引 `0..31`；普通 QDMA RX 从 `msg0[7:3]` 取出，选择注册行。**0 是第一行**，有效性由注册行标志判断。当前控制器的单 LLID 使用 `C=0`。 | E1、E2、E3 |
| `I`：IFC 输入 service | type0 TCAM bank0/page7（word7）`[31:16]` 为 `GEM_LLID` key/mask。精确匹配0应写 key高16=`0`、mask高16=`0xffff`；mask高16=`0`才是忽略该字段。 | E4、E5、S2 |
| `F`：原始 FE service | 当前 NPU 读取 `(raw_fe[4] >> 14) & 0xffff`。其与真实 EPON `L/C/I` 的关系待配对采样。 | E6 |
| `S`：ER 发布 service | `S = 0x80000000 \| F`；bit31为软件 `ER_SERVICE_VALID`。`F=0`编码为`S=0x80000000`，有效位与数值独立。 | E6 |
| host 注册 tag | 有效 EPON 身份为 `0xc0000000 \| (C << 16) \| L`；撤销时整个 tag 清零。 | E7 |
| FE 传输 channel / SPORT | 当前 FE 输入检查 `raw_fe[2]==7`、`raw_fe[5]>>28==6`、`raw_fe[6]&31==2`。这里的7是 NPU FE 传输通道，2是物理来源 SPORT；二者均与 EPON channel0 分开。 | E6 |

QDMA RX 的16位字段在 SDK 中名为 `gem`，位置也是 `msg0[29:14]`。SDK 的 EPON **OAM分支**将它赋给 `llid_value` 并用于诊断，故 wire LLID 是优先验证候选；普通数据分支始终按 `channel` 查表。应分别记录 QDMA 的 `gem`、channel 和原始 FE 的 `F`（S3、E2）。

## channel0 与零值：证据及当前限制

- 原厂 `xmcs_create_llid@0x5e8b0` 在 `0x5e8d0..0x5e8d4` 用无符号 `index <= 31` 判断范围；`0x5e96c` 从参数 `+2`读取16位 LLID，`0x5e988`存入该索引行的低16位，`0x5ea08`单独置有效 bit23。索引和值从创建入口就是两个字段（E3）。
- 原厂普通 RX 用 `C`选择 `gpWanPriv + 0x2c930 + C*0xc0`，检查行 `+8` bit23；放行后写 `skb+0xc0=C`。已有4,608组向量覆盖全部32个 channel及18种高16位输入，含channel0；改变16位输入不改变普通数据的选行，`skb+0xba`保留原值（E2）。
- 原厂普通 TX 在 `0x4db80`检查索引上界31；`0x4ddc8..0x4dddc`将 `skb+0xc0`写入TX message0 `[7:3]`，`0x4dde8..0x4ddfc`将同值写入message1的NBOQ `[19:15]`（E3）。主线新增LLID发布后，EPON TX继续使用channel；已有身份测试分别检查发布、CPU TX及FOE编码（E7）。
- `I=0`的16位key/mask有明确编码。当前CPU诊断入口另设软件限制：普通 `set`拒绝 `!service`，`tuple`发布和健康检查也拒绝零。纯行编码器接受0。下轮需同时处理这些入口和存活判断，以已有active/tuple/lease状态表示“已配置”（E5、E8）。
- 当前ER ABI接受 `F=0`；基线host ER绑定只支持GPON映射表，要求 `pon_qdma_tag==0`，并过滤EPON条目。EPON接入还需要独立的身份适配与注册代次检查（E6、E9）。

wire LLID的0值按MAC有效位和实际注册结果记录；本方案使用**合法注册的非零L、C=0**来区分候选映射。测试中的`0..65535`遍历检查软件位宽；光侧采用OLT实际允许并分配的LLID。

## 已有试验可复用到哪里

GDM2内部回环已有完整service `0x2134/0xa134`的分类、精确tuple和撤销结果。回环发送器通过GPON配置接口写入service；默认special-tag配置回送0，选择器16..31与RX/TX mode1配置回送指定值。它确定了**配置过的回环路径**如何携带service；真实EPON注册输入是本次剩余测量对象（E10）。

CPU诊断沿用独占SPORT2的SIF `key=4, mask=0xffffffff`。旧`4/4`会放过其他来源。已有CPU实验中service行56/57胜过cover行58/59，命中走RX2、未命中走RX4；每次写入由现有owner完成并读回。原始字和输入类型保持一致，type1的L4有效位与type0字段分别编码（E4、E11）。

## 剩余最小验证方案

以下为后续任务，本轮仅固化文档。第1项可在现有无光纤环境推进；第2–4项需要外部光侧条件，第5项依据所得映射落地。

1. **准备service0诊断。** 在现有CPU探针中分别表示“service值”和“规则已配置”；覆盖`set/tuple`的发布、健康检查、替换、撤销、同值重试及超时恢复。加入`service=0, mask=0xffff`向量和“零mask为通配”的负对照。现有回环工具的`mapping(..., !!service)`及`transmit(!service)`也使用零作撤销/拒绝哨兵；若用其校准service0，须显式区分配置与撤销（E8、E10）。
2. **只用CPU分流测I。** 使用真实EPON注册，记录`C=0`及`L=A`，优先选OLT允许且大于31的A。先读MAC原始注册字和host发布tag；普通WAN CPU路径逐包记录QDMA `msg0/msg1`。安装type0/type1 SPORT2 cover至RX4，用同一组足够长的普通IPv4/UDP编号包，依次测试精确`I=A`、`I=0`、错误值三个规则，命中动作至RX2。每次更换先恢复CPU路由、读回规则后再启用诊断路由；PPE资格保持关闭。记录包号、实际环、QDMA两字和全部TCAM/action读回。
3. **同channel换LLID复测。** 让OLT重新注册为`C=0,L=B`，`B!=A`，重复上步；旧身份先撤销、排空，再发布新代次。若I随A→B变化，得到wire值候选；若I持续0，得到channel/常零候选。完整证明channel映射还需一个实际注册的非零channel。当前控制器的注册命令固定索引0；仅改host发布参数为1不会建立MAC channel1（E1）。若A/0均未命中，先验证同条件service通配行能到RX2，再以16次单bit mask探针恢复I，避免遍历65536个值。
4. **单独配对F。** 对上述两个注册代次，使用现有FE32原始快照格式，在FIFO取包后、任何UDF/发送描述符改写前采集八字及编号载荷。准备受owner约束、只采样并回CPU的诊断路径，保留未匹配流量CPU cover；当前GPON ER绑定继续维持原范围。复用`FE32OBS1`、固定五元组和128字节载荷，每代至少采到3个独立编号；逐项列出`(epoch,C,L,I,QDMA gem,QDMA channel,raw_fe[0..7],F)`。FE路径所需诊断接线是这一阶段的准备项（E6、E12）。
5. **按结果选择适配。** `I=F=L`时使用16位LLID精确匹配，并将C用于注册关联；`I=F=C`时service0为正常键，以注册代次处理channel复用；`I`与`F`不同时分别保存classifier key与ER key。持续常零的F需先解决有效身份来源，再接EPON ER/AUTH。最后补撤销、重注册、旧代次迟到包、OAM及未映射输入；记录在MAC处丢弃的包及计数。

验收交付是上述逐包对照表和确定的转换公式。两个代次的channel0样本即可先区分“跟随wire LLID”与“固定零”；非零channel样本用于收敛channel公式。

## 证据索引

所有本地路径为本轮实际读取位置；源码版本采用开头固定commit。SDK为既有证据清单引用的`LeoooChen/airoha_sdk@32b5aa356c2406edef8806aaf75451ff0a5286f2`，仅补读原始C/头文件，并逐个与本地tree中Git blob核对。

- **E1** `/Volumes/Workspace/5585f/build/pon-drivers/airoha-xpon/src/airoha-xpon-private.h:59`；`/Volumes/Workspace/5585f/build/pon-drivers/airoha-xpon/src/airoha-xpon-epon.c:88`、`:144`、`:824`、`:853`。commit `14e90e8`发布LLID及channel；注册有效位、值和索引0命令分别可见。
- **E2** `/Volumes/Workspace/5585f/build/private-ram-trials/pon-path-readonly-agent/disassembly/xpon_10g.ko/ewan_process_rx_message.txt:22`、`:271`、`:289`；`/Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/pon_offload/verify_ewan_ingress.py:24`；测试commit `4b8442240a32bae4aa5eaebfba54ba7b9d79b250`。既有汇总：同目录`README.md:57`、`:64`。
- **E3** `/Volumes/Workspace/5585f/build/stage2/zip/root/lib/modules/xpon_10g.ko`，本轮SHA256 `aab0b4191f4db514a04035f0e43fbae073eea44ad834345cbcb899136976e860`。ELF `.text`：`xmcs_create_llid@0x5e8b0`、`ewan_prepare_tx_message@0x4d830`；上文列出关键指令偏移。用本机pyelftools/Capstone只读解码，与E2原有RX反汇编交叉核对。
- **E4** `/Volumes/Workspace/5585f/build/private-ram-trials/ct230-ipv6/ifc.dis:6740`、`:6789`、`:6804`、`:14507`；setter/getter为`0x5c7c/0xc5c4`。`/Volumes/Workspace/5585f/build/stage2/zip/root/lib/modules/ifc.ko`本轮SHA256 `d10c1b67b2368a0f2a9255feb851621f8bd73ab16eb6d6a47c9992e4617e3bf7`。完整页布局见`/Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/pon_offload/verify_ifc_service.py:67`及`/Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/pon_offload/IFC-FIELD-LAYOUT.md:54`。
- **E5** `/Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/patches-6.18/975-net-airoha-encode-optical-service-cpu-classifier-rows.patch:21`；commit `718927d55e81658fb2b3e92e628291274350c4f7`。参数验证和page7编码均保留service0。
- **E6** `/Volumes/Workspace/5585f/an7581-npu-firmware/src/ingress_auth.c:201`；`/Volumes/Workspace/5585f/an7581-npu-firmware/include/npu_eth_return_abi.h:23`、`:62`、`:67`、`:74`。ER相关提交`633058be9d271def0484d15cad563ed47da02e2e`；bit31由软件生成，描述符校验比较保存的原始word4。
- **E7** `/Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/patches-6.18/999-zb-net-airoha-publish-epon-registration-identity.patch:16`、`:31`，commit `d9af3fd`；`/Volumes/Workspace/5585f/build/epon-identity-20261127/source/drivers/net/ethernet/airoha/airoha_eth.c:3244`、`:4661`。既有结果`/Volumes/Workspace/5585f/build/epon-identity-20261127/report.json:12`：普通/ASan各2,097,993发布用例、4,608 CPU TX及4,608 PPE向量。
- **E8** `/Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/patches-6.18/987-net-airoha-probe-exact-optical-tuples-with-shared-lut-leases.patch:158`、`:289`、`:313`，commit `6b8696d368a0c9d0e1f32adca53c73b26795317b`。
- **E9** `/Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/patches-6.18/994-net-airoha-own-pon-return-consumer-lifetimes.patch:115`、`:235`；基线合成源码`/Volumes/Workspace/5585f/build/pon-er-consumer-20261127/owner-source-bank1-retire/drivers/net/ethernet/airoha/airoha_npu_return.h:50`、`:85`、`:182`。
- **E10** `/Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/pon_offload/IFC-PROBE.md:186`、`:255`；`/Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/pon_offload/ram_loopback/ct_pon_loopback.c:242`、`:413`。保留编号包的回环与真实EPON采样分别归档。
- **E11** `/Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/patches-6.18/984-net-airoha-mask-all-ports-for-exclusive-ifc-source-selection.patch:9`，commit `8f8a5af46764a53300a486f98782fab99a00f1ca`；`/Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/pon_offload/IFC-COVER.md:30`；`/Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/pon_offload/IFC-PROBE.md:308`为重叠行CPU实测。
- **E12** `/Volumes/Workspace/5585f/an7581-npu-firmware/docs/tunnel-slot1.md:67`、`:75`、`:79`；既有LAN1采集正对照与FE32标记工具。原厂前缀保留/后续改写见`/Volumes/Workspace/5585f/build/private-ram-trials/pon-offload-rebuild-20261126/pon-fe-service-trace-v2/README.md:21`。
- **S1** SDK `private/xpon_10g/inc/epon/xepon_mac_c_header_en7581.h:964`、`:981`：5位`tx_mpcp_llid_idx`及独立16位`llid0_value`/1位`llid0_valid`；Git blob `2a8cc9b30fb29457b3a50216fa18d8d27842b04f`。`private/xpon_10g/inc/epon/epon.h:112`分别定义`llidIndex`与`llid`，blob `2242a9ab45f16e6c3bbce4eef2e8e95e27790c7e`。
- **S2** SDK `private/ifc/ifc_tcam.h:127`、`:149`定义16位`gem_LLID`，Git blob `cdd82d2f6b19b7d79e396249f308d271c7559fd7`；实际AN7581页位置以E4为准。
- **S3** SDK `private/xpon_10g/inc/pwan/xpon_netif.h:116`，blob `300ff0de583fadbe69a70f93b4e11904ed72b6ff`；`private/xpon_10g/src/pwan/epon_wan.c:116`、`:154`、`:196`、`:216`、`:228`，blob `1b90a9697d220f208cb6eff68a46ac72e8814765`。这些是SDK参考实现；HG5585F实际指令由E2/E3核对。

SDK固定来源清单：`/Volumes/Workspace/fctory-op/5585f/private/analysis/ppe-sdk-headers/manifest.json:3`；完整tree及blob：`/Volumes/Workspace/fctory-op/5585f/private/analysis/ppe-sdk-tree.json`。远端原始文件仅在内存读取，本轮唯一写入文件为本文。
