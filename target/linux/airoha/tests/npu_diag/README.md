# PON NPU diagnostic host review

This suite exercises production functions from a generated kernel containing
`999-zr-net-airoha-add-pon-ppe-learning-diagnostic.patch`. It reads the tree
without modifying it. All generated includes, binaries, mutation copies and
reports go to a new output directory outside ponwrt.

```sh
python3 -B target/linux/airoha/tests/npu_diag/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/kernel-auth-learn \
  --output /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/npu-diag-learn-host-tests-v2
```

The runner extracts seventeen complete production functions without editing
their bodies: diagnostic identity and FLOW selection, platform admission, diagnostic authorization,
mode-aware start and the legacy empty-AUTH wrapper, snapshot, close/release,
owner retirement, production authorization, readiness, open checks, bank1
restoration, route opening and ER observation/statistics.
The AUTH publish helpers and mailbox ABI headers are copied byte-for-byte.
The shared `npu_ingress/source_binding.py` replays the ordered production
patches through ZR with exact hunks, then byte-compares the complete
`airoha_npu_owner.h`, `airoha_npu_diag.h`, `airoha_npu_reopen.h` and
`airoha_bank1_routes.h` against the generated tree.
The report lists each header's actual patch chain and SHA-256 hashes.
Source and patch hashes are captured before the run and rechecked afterward
to detect a concurrent production update.

Linux OF/netdevice services, MMIO, the underlying owner claim/close state
machine, ER allocation/preparation and return mapping are controlled stubs.
The production diagnostic and retirement decisions execute against those
boundaries. The existing owner/ER suites own the transaction state machine,
DMA protocol, NAPI processing and real return mapping. This suite uses
ASan/UBSan and warnings-as-errors; it performs no VM, device or Git actions.
The learning-start tests connect the open boundary stub to the actual bank1
restore and route-open functions. The close stub records the incoming row
cursor and leaves it unchanged: tests require release to retain the owner
while that cursor is zero, then supply completed row retirement and verify
that the actual diagnostic close/release restores saved registers and frees
the owner once.

## Coverage

- Session identity: owner token, retained netdevice, exact controller and
  private pointer, Ethernet/GDM2/queue identity, running/carrier state,
  DT diagnostic and RAM selectors, qualification and production policy.
- Start admission: foreign netdevice parent, unregistered GDM, absent
  controller, QDMA/tag mismatch, pending TX, missing flow table, loopback
  disabled, existing ownership and fallback/update state.
- TX_DISABLE hog: available node, exact GPIO38 active-high cells, missing
  `gpios`, empty/short/long/unaligned properties and injected read errors.
  Invalid hogs fail both platform admission and diagnostic start before
  owner claim, AUTH, register writes or netdevice reference acquisition.
- Failure retention: owner claim failure with and without published owner,
  ER preparation, identity change, empty AUTH BEGIN/ARM, malformed AUTH
  acknowledgement and failed open. Failures after ownership retain the
  diagnostic netdevice reference and record the error.
- Empty AUTH isolation: BEGIN then ARM without ADD; production authorize
  rejects diagnostic owners. Normal production authorization still accepts
  a valid nonempty rule, while unqualified or empty production admission
  fails. QUERY checks epoch, generation, count, enable and inflight state.
- Nonempty diagnostic AUTH: services 0, 1, 0x8000 and 0xffff, exact
  `ER_SERVICE_VALID | service` binding under RCU, and an independent 32-word
  rule comparison. The fixed IPv4 UDP flow is
  `192.0.2.1:49152 -> 192.0.2.2:49153`, with SMAC
  `02:00:00:00:00:01` and the retained lower device's DMAC. Each service
  uses a different valid DMAC. The trace requires readiness, full binding,
  BEGIN, ADD, ARM, post-ARM readiness, then open. FLOW remains zero until
  learning-mode bank1 restoration; qualification stays off. Explicit
  diagnostic AUTH allows at most one rule in both modes 1 and 2.
- AUTH admission/failures: oversized services in all three modes, low-bit and
  bit-15 binding mismatches, wrong identity/phase/mode, repeated attempts,
  missing return path and invalid DMACs. BEGIN/ADD/ARM timeouts, 16 malformed
  ACK fields per operation, failed ADD status and post-ARM readiness loss
  prevent open and preserve the owner, return path and netdevice reference.
  Production authorization continues to reject all three diagnostic modes.
  Modes 1 and 2 both run the full malformed-ACK/timeout/ADD-failure matrix.
- Close/release: closed ACK, ring destruction and bank1/ingress prerequisites;
  failed close, route release, TB/FLOW restoration and FE release preserve
  owner and device reference. Successful retry releases once, after restored
  registers and successful FE retirement. `close` alone retains ownership.
- Bank1: all diagnostic restores first require FLOW=0, PPE enabled, not
  busy, search-miss=2 and retirement cursor=8192. Modes 0 and 1 keep those
  settings without MMIO writes. Normal production restore and explicit
  final release restore saved values. Every case checks bank0 remains unchanged.
- PPE learning under one AUTH rule (mode 2): only an active owner with both `diag_auth` and
  `diag_learn` selects IPv4 NAPT, exactly BIT(13). Tests use the actual
  search-miss field at bits 5:4. The MMIO trace requires cursor zero before
  the first write, TB miss=3 preserving other bits, exact TB readback,
  FLOW=BIT(13), then exact FLOW readback, all writes/readbacks under the PPE
  lock. Modes 0/1/2 run with services 0, 1, 0x8000 and 0xffff; invalid
  modes fail before acquiring an owner or netdevice reference.
- Learning failures: dropped TB/FLOW writes, corrupted readbacks in both
  relevant and unrelated bits, and a failed post-write identity check keep
  cursor zero, owner and netdevice retained, and routes closed. Failed TB
  readback prevents the FLOW write. Release waits for completed retirement.
- Learning routes: modes 0/1 require exact FLOW=0/miss=2; mode 2 requires
  exact FLOW=BIT(13)/miss=3. The cross-product covers extra/missing/wrong
  FLOW bits and all miss values; disabled/busy PPE and scope/route-write
  failures also reject opening.
- Snapshot: the actual ER observation enable/getter and stats getter feed
  the diagnostic snapshot before close removes the ring.

The single rule describes AUTH admission. PPE learning runs before AUTH:
the board run learned all five IPv4 variants as UNB entries, with zero BND
entries. The matching packet returned through QDMA with hash 2458;
mismatches returned through ER. Board acceptance checks the exact five-tuple
UNB set and requires the matching QDMA hash to identify the real target row,
then verifies that retirement clears every learned row. This host suite
checks the configuration, cursor, route and failure paths supporting that
packet-level acceptance.

All 38 existing separately compiled negative controls remain and must fail assertions. They
remove identity, policy, qualification, netdevice parent and AUTH-count
checks, permit production AUTH in the diagnostic session, ignore restore
errors/closed ACK, leak the retained netdevice, ignore bank1 FLOW/busy, or
bypass hog availability, property length, GPIO number or GPIO flags.
The added controls permit two diagnostic rules, bypass explicit AUTH mode,
CLOSED phase, repeated-attempt and service-range checks, lose the selected
mode, truncate service bit 15, omit service validity, ignore binding failure,
change the fixed IPs/ports/protocol/SMAC, skip post-ARM readiness, lose the
published rule count, or ignore ACK count/rule echo. Start-related mutations
target the actual mode-aware start function; the legacy wrapper remains covered.
ZR controls additionally bypass mode/retirement/admission checks, confuse
learning and AUTH-only modes, widen the FLOW mask, skip or corrupt learning
writes/readbacks, discard the retirement cursor, clobber unrelated TB bits,
skip the post-write state check, and accept extra FLOW bits or the wrong miss
value. Mutations execute copied production functions; originals stay unchanged.

## TX_DISABLE hog regression

`airoha_npu_diag_platform()` requires node availability, exact property
length, a successful GPIO-array read, and GPIO38 with zero flags.
The RAM generator selects `gpios = <38 GPIO_ACTIVE_HIGH>`.

Twelve invalid-hog cases retain the expected path and booleans while
independently disabling the node, selecting GPIO37, setting active-low,
removing `gpios`, supplying zero/one/three cells or an unaligned byte length,
or injecting `-EINVAL`, `-ENODATA`, `-EOVERFLOW` and `-EIO` read failures.
Each case checks platform rejection, start returning `-EPERM`, no owner or
AUTH activity, and balanced OF/netdevice references. The valid two-cell
GPIO38 active-high fixture remains covered by successful platform/start
tests.

The OF stubs model count errors for absent or unaligned properties and
minimum-size array reads. A three-cell property can satisfy a two-cell
array read, so the length negative control specifically verifies the
production exact-count gate. Injected read errors use an otherwise valid
two-cell property and return without writing the output array.

The report separates `regression_passed` from overall `passed`. A functional
matrix pass with an accepted invalid hog produces `passed: false` and exit
status 1. `review-platform.log` contains the twelve-case result. Standalone
reproduction uses the generated binary:

```sh
/absolute/test-output/npu-diag --review-platform
```

The functional matrix preserves all 210 original/ZQ cases and adds 179
learning-mode regressions, for 389 cases and 60 negative controls.
The report records the assertion count, all mutation results, the twelve
invalid-hog admission results and source/patch/test hashes. Successful
completion requires zero accepted invalid hogs and sets both pass fields
to true. Debugfs file permissions, textual formatting, hardware GPIO state
and packet capture in the NAPI loop remain integration checks outside this
host test.
