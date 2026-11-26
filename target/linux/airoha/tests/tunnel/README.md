# 原厂 FE 隧道路由与写表

```sh
python3 verify_stock_fe.py --stock-dir /path/to/stock/lib/modules --output /tmp/stock-fe.json
```

测试通过 Unicorn 执行 SHA 固定的 `fe_core.ko`、`hw_nat.ko` 和 `qdma_lan.ko`。寄存器访问、延时、日志和 ECNT 跨模块传递由夹具提供。初始化和 QDMA 分派使用下面注明的指令区间；表的写入、清除及 FE 分派函数从入口执行到返回。

- **端口初始化**。`fe_core.ko` 的 `.init.text+0x444` 从 `GET_HIR` 分支进入路由初始化，在 `+0x4d4` 结束。`HIR=0xa` 先清三个 GDM 寄存器的字段再汇入共同路径。五种 HIR、三种寄存器初值下，四次读改写只更新 `FE+0x2010` 的分片端口 6、队列 3、重组端口 0、队列 22。其余位保留。
- **QDMA 接收**。`qdma_bm_receive_packets_int2` 的 `0x7890` 分支把 ring 21、22 引向 `qdma_fragment_reassemble_handler`。该函数从 `0x254ec` 检查环号和传入描述符 `+0x10` 低三位。ring 21/op1、ring 22/op2 进入各自处理分支。覆盖 32 个环、8 个操作值、两种其余位。这里的操作字段属于 QDMA 描述符；RV32 接收分流读取 FE 描述符 word1 的 `[30:28]`。
- **建表与撤销**。`PpeSetTunnel_table_ToHW` 和 `PpeClearTunnel_table_ToHW` 处理 0–63 号槽，通过 group `0x13` 命令 `0x89` 调用 `ecnt_fe_api_hook` 中的 `fe_api_set_tunnel_cfg`。每行软件记录占 88 字节；依次写 bank 4、0、1、2、3。bank 4 的四字参数为 `0,0,0,word[0]`，后四个 bank 取连续的 `word[1..16]`。每组先按 `FE+0x208c/2088/2084/2080` 写数据，再向 `FE+0x207c` 写 `(bank << 16) | (slot << 8) | 0x11`，清除操作使用相同顺序并将数据置零。原厂 GRE、VXLAN 和 L2TP 建流路径有写表调用，`ppe_update_tunnel_session_list` 调用清表。
- **完成语义**。`feChecConfigDone` 检查控制寄存器 bit 31，最多读三次。三次均未完成会记录超时；外层 FE API 仍回复成功，host 继续余下各 bank。重建驱动接入该路径时需要独立处理部分完成和超时，随后再发布依赖这行的流。测试覆盖首读完成、第三读完成和超时，以及越界槽位零写入。
- **会话引用与回收**。从入口运行 `ppe_add_session_to_tunnel_list` 和 `ppe_update_tunnel_session_list`，由夹具提供分配器和 FOE 绑定状态。两个不同流可引用同一槽，重复登记同一流返回 `-1`。回收扫描槽 32–63，由软件行 `+0x44` 的低两位决定是否处理。仅解除一个绑定时保留另一个引用，不写 FE；最后一个绑定解除后才清五个 bank，并复位链表。97 组对照包含槽 31/32/63、两条流的四种绑定组合和清表超时。原厂在引用分配失败时打印日志、返回 0；清表超时仍清软件行。重建时应将引用分配成功作为发布流的前提，保留未完成清理的槽，直至硬件完成回收。
- **IPv4 GRE 动态建行**。夹具提供已解析的外层 MAC/IPv4 和带 GRE 头的内层 IPv4/UDP 报文，从 `PpeParseGreTunnelInfo` 入口执行至返回，核对解析结果中的槽号、流引用、17 个表字和实际寄存器写序列。无 VLAN/PPPoE 的这一分支中，word0 为 `0x02002600`，word1–3 为两个 MAC，word5 含 TTL、TOS 和外层地址折叠和，word6 高 16 位为 IPv4 ID，word7/8 为外层源/目的地址。第二条流共用槽 32 时不重写；只改外层目的地址时分配槽 33；未知 GRE 协议不写表、不登记流。下一层验收是从解析结果生成 FOE 条目并观察接收端报文。
