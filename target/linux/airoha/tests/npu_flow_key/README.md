# IPv4 PON AUTH identity encoder

`999-zx-net-airoha-encode-pon-ingress-authorization.patch` adds only
`drivers/net/ethernet/airoha/airoha_npu_flow_key.h`. It provides:

```c
struct airoha_npu_ipv4_identity {
    auth_u32 service, source_ip, destination_ip;
    auth_u32 source_port, destination_port, protocol;
    auth_u32 vlan_count, vlan[2], pppoe_session;
    unsigned char destination_mac[6], source_mac[6];
};

static inline int
airoha_npu_auth_encode_ipv4(struct airoha_npu_auth_rule *rule,
    auth_u32 epoch, auth_u32 generation, auth_u32 token, auth_u32 row,
    const struct airoha_npu_ipv4_identity *identity);
```

All numeric fields are host-order values. IPv4 addresses are numeric wire
values, such as `0xc0000201` for 192.0.2.1; no byte swapping is performed.
VLAN words contain `TPID << 16 | TCI`, retaining all PCP/DEI/VID bits.
Unused VLAN words must be zero. PPPoE session zero means no PPPoE; a nonzero
16-bit session encodes PPP protocol 0x21. Only IPv4 TCP/UDP are accepted.
Zero and 65535 ports are valid. Service zero is valid. Both MAC addresses
must be nonzero unicast addresses.

The rule contains ABI1, the supplied epoch/generation/token/row, bank0,
PON domain4 and producer2. The encoder preserves the original ingress tuple,
Ethernet addresses and encapsulation supplied by the caller. NAT output
addresses, ports and rewritten MAC addresses must not replace that identity.
The caller supplies the identity and row association; the encoder neither
parses an skb nor associates cookies, installs rows or sends mailbox commands.

Raw service/port/session bounds, protocol and VLAN count are checked before
packing. The complete local rule is checked with the production
`airoha_npu_auth_rules_validate()`, including identity, row, MAC, TPID and
unused VLAN fields. Success copies the complete rule to the output. Any
failure returns `-EINVAL` and preserves the output bytes; the input identity
is always unchanged.

## Run

```sh
python3 /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_flow_key/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/auth-bank-metadata/source \
  --firmware /Volumes/Workspace/5585f/an7581-npu-firmware \
  --output /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/flow-key/encoder-suite
```

Output must be a new directory outside ponwrt and separate from both input
trees. `--cc` selects the compiler, defaulting to `$CC` or `clang`.
The runner accepts a snapshot through ZW or ZX. For a ZW snapshot, it copies
the AUTH dependencies into the output and applies ZX there. It never changes
the input snapshot. SourceBinding independently reconstructs both the public
AUTH header and encoder through ZX, checking exact hunk positions/context,
zero fuzz/offset and byte equality. An already applied encoder is compared
directly against that reconstructed patch chain.

## Coverage and evidence

- A fixed independent 32-word golden vector, including high MAC bytes,
  asymmetric ports, double VLAN tags and PPPoE, checks the precise ABI layout.
- TCP/UDP, zero/single/double VLAN, both TPIDs, full TCI bits, PPPoE presence,
  16-bit service and port boundaries, zero/full IPv4 addresses, first/last
  row, and maximum epoch/generation/token values.
- Actual unchanged firmware `src/ingress_auth.c` parses independently built
  frames. Parsed keys must equal the encoded rule. Real BEGIN/ADD/ARM,
  `npu_auth_take()` and PON descriptor `npu_auth_fe_take_ex()` exercise domain
  decode, service/generation matching and lease completion.
- Original ingress versus changed NAT source/destination IP, source/destination
  port, either MAC, VLAN stack/TCI, PPPoE session, transport protocol and
  service. Each changed identity is accepted only by its corresponding rule;
  mismatches leave ticket and inflight state empty.
- Null pointers, zero identity fields, row overflow, every upper bit of the
  service/ports/session, malformed protocol/VLAN values, unused tags and
  zero/multicast/broadcast MACs. Failed encoding preserves all output bytes.
- Compiled mutations cover layout, narrowing before validation, missing
  source/destination port guards, omitted tags/MAC bytes, validator bypass
  and premature output updates. A mutation must compile successfully and
  exit with a runtime CHECK failure; sanitizer errors do not count as hits.

The baseline and all mutants use `-Wall -Wextra -Werror`, AddressSanitizer
and UndefinedBehaviorSanitizer. Outputs include extracted/bound headers,
baseline/mutant binaries and logs, patch application logs and `report.json`.
Input, firmware, test and binding-helper SHA-256 values are recorded and
rechecked at the end. Owner sequencing, RX identity parsing and cookie
association are separate integration work.
