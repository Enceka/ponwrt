# NPU transaction core host 回归

在 ponwrt 主仓库运行：

```sh
python3 target/linux/airoha/tests/npu_transaction_core/verify.py
```

依赖 Python 3 和 clang，可用 `--cc` 选择 clang，`--output` 指定产物目录。
默认产物写入本目录已忽略的 `out/`，可重复运行。

runner 从当前 `990-net-airoha-preserve-npu-lifecycle-transaction-identities.patch`
完整新增 hunk 提取 `airoha_npu_transaction_core.h`，从当前 988 patch 提取
`npu_auth_mailbox_abi.h`、`npu_bank1_gate_abi.h`、`npu_eth_return_abi.h`，校验各 hunk
行数，随后将 `core_test.c` 与真实 header 联编。使用 header 原生 host 分支，
无需 Linux stubs。事务 phase、消息构造、回执校验、身份缓存及推进逻辑全部来自990。

clang 参数包含 `-std=c11 -Wall -Wextra -Werror -O1 -g`
`-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer`。
当前 **366 个用例**通过 ASan/UBSan。`out/report.json` 保存编译器、988/990及四个
提取 header 的 SHA-256、测试源码 SHA-256和执行结果；日志为 `out/build.log`、
`out/core_test.log`。每次开始清除旧成功报告；运行期间 patch 变化会终止该次验证。

## 用例

- mask 1/4/5、legacy LAN gate caps、完整关闭/开放回调顺序、CLOSED/OPEN幂等操作。
- 全部12个回调边界分别注入**执行前失败**和**生效后丢ACK**，组合 ETIMEDOUT、EIO、
  EAGAIN和正返回值；每项连续失败两次再成功。逐次检查 phase、last_error、身份、
  auth缓存、相同请求的全部word及后续回调未被提前调用。正返回值统一为 EPROTO。
- 处理中同id begin保留现场，改变epoch、generation或mask返回 ESTALE；CLOSED或
  OPEN只有更大epoch可开启新事务，同id begin保持幂等。
- READY至ROUTES_OPEN每个开放phase失败后撤回：先 routes_close，再以原id CLOSE；
  ACK成功后才递增epoch并再次CLOSE，随后QUERY、旧身份DISARM和常规关闭。
- 撤回的 routes_close、旧id CLOSE、新id CLOSE各自执行前/后失败，验证重试身份
  稳定；新id CLOSE注入点由实际回调次数选中，整个撤回过程调用真实状态机。
- U32MAX及U32MAX-1：旧id CLOSE丢ACK时先重试原请求；到达上限后停在
  EPOCH_ADVANCE并返回 EOVERFLOW，继续close不重复调用owner，epoch保持上限。
- AUTH QUERY缓存旧epoch/generation，DISARM使用旧身份；DISARM生效后丢ACK仍重发
  相同请求。模拟授权被另一个控制者改动时得到 ESTALE，并保持原缓存和phase。
- 初始无AUTH跳过DISARM；QUIET在LAN、PON两个ring分别排空及AUTH inflight归零前
  保持 EAGAIN，持续保留两ring NAPI，PPE drain在成功QUIET后执行。
- gate前8word和AUTH前40word immutable echo逐word损坏；status pending/-error/正值、
  caps、state身份、reserved、CLOSE/QUIET/OPEN相关快照、AUTH count/inflight/enabled
  范围和零身份一致性；损坏的成功回执返回 EPROTO并停留原phase，之后可重试恢复。
- QUERY pending固定wire `-115`，gate/AUTH请求magic、ABI/op、bytes、identity、mask和
  所有零填充word逐项核对。host errno使用平台值，wire pending单独验证固定数值。
- 非法mask、零epoch/generation、空txn、九个必需callback逐项缺失、非法phase、
  CLOSED之前open、重复begin及epoch回退。
- CLOSED下AUTH BEGIN/ADD部分成功后的owner重建路径；已完成ready后，FE_ARM、
  GATE_OPEN、ROUTES_OPEN失败重试中的实时AUTH撤销和任一ER generation变化。

## Owner 契约

1. 调用方串行化事务并独占相关控制权。新epoch必须高于gate、AUTH、native FE和wired
   当前身份；重试期间使用原事务身份。epoch溢出时保持关闭现场，由owner处理后续恢复。
2. AUTH BEGIN/ADD和ER准备属于owner，在CLOSED阶段执行；ready检查新授权和所需ER已
   匹配当前generation/source。核内只构造AUTH QUERY/DISARM。
3. CLOSED下AUTH BEGIN/ADD失败后若需清理重建，显式调用
   `begin(new_epoch, generation, mask) → close`，再重新准备授权。
   **单独close(CLOSED)及同id begin均幂等，不清理刚准备的部分授权。**
4. FE_ARM/GATE_OPEN/ROUTES_OPEN失败后原phase重试会跳过已完成的ready。
   `fe_arm`和`routes_open`必须再次验证实时撤销状态、generation及ER匹配关系。
   `routes_open`返回负结果时入口必须保持关闭；测试fixture在生效后丢ACK场景中先回收
   入口再返回失败。GATE OPEN回执同时核对当前AUTH身份及开放快照。
5. routes_close先关闭上游入口；fe_quiesce关闭全部相关FE/channel7生产路径，
   **保持两个ER消费者/NAPI持续运行**，使QUIET能等到两ring排空。
   PPE drain在成功QUIET之后，PPE restore和FE arm在成功ready之后。
6. gate/auth callback采用可重试的准确身份事务，返回负错误码或完成的回执。消息内
   pending为wire固定值-115；核对每个成功ACK后才进入下一phase。

## Fixture 范围

`core_test.c`使用真实 `npu_gate_message`、`npu_auth_message`及 `er_message`。
回调fixture模拟gate、授权、FE、PPE、入口和两ER的外部状态，记录请求和生效次数，
注入callback错误及回执损坏。fixture不实现事务phase推进；测试通过真实
begin/close/open驱动执行。非法phase参数用例直接设置待验证输入。

此目录只生成host测试产物，模块保持未自动启用；内核构建、owner接入及设备验证
由主代理处理。运行本测试无需设备、Git索引操作或提交。
