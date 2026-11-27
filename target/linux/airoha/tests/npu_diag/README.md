# PON NPU diagnostic host review

This suite exercises production functions from a generated kernel containing
`999-zq-net-airoha-add-nonempty-pon-auth-diagnostic.patch`. It reads the tree
without modifying it. All generated includes, binaries, mutation copies and
reports go to a new output directory outside ponwrt.

```sh
python3 -B target/linux/airoha/tests/npu_diag/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/kernel-auth-match \
  --output /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/npu-diag-auth-host-tests-v2
```

The runner extracts sixteen complete production functions without editing
their bodies: diagnostic identity, platform admission, diagnostic authorization,
mode-aware start and the legacy empty-AUTH wrapper, snapshot, close/release,
owner retirement, production authorization, readiness, open checks, bank1
restoration, route opening and ER observation/statistics.
The AUTH publish helpers and mailbox ABI headers are copied byte-for-byte.
The shared `npu_ingress/source_binding.py` replays the ordered production
patches through ZQ with exact hunks, then byte-compares the complete
`airoha_npu_owner.h` and `airoha_npu_diag.h` against the generated tree.
The report lists each header's actual patch chain and SHA-256 hashes.
Source and patch hashes are captured before the run and rechecked afterward
to detect a concurrent production update.

Linux OF/netdevice services, MMIO, the underlying owner claim/close state
machine, ER allocation/preparation and return mapping are controlled stubs.
The production diagnostic and retirement decisions execute against those
boundaries. The existing owner/ER suites own the transaction state machine,
DMA protocol, NAPI processing and real return mapping. This suite uses
ASan/UBSan and warnings-as-errors; it performs no VM, device or Git actions.

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
  BEGIN, ADD, ARM, post-ARM readiness, then open. FLOW remains zero and
  qualification remains off; explicit diagnostic AUTH allows at most one rule.
- AUTH admission/failures: oversized services in both modes, low-bit and
  bit-15 binding mismatches, wrong identity/phase/mode, repeated attempts,
  missing return path and invalid DMACs. BEGIN/ADD/ARM timeouts, 16 malformed
  ACK fields per operation, failed ADD status and post-ARM readiness loss
  prevent open and preserve the owner, return path and netdevice reference.
  Production authorization continues to reject both diagnostic modes.
- Close/release: closed ACK, ring destruction and bank1/ingress prerequisites;
  failed close, route release, TB/FLOW restoration and FE release preserve
  owner and device reference. Successful retry releases once, after restored
  registers and successful FE retirement. `close` alone retains ownership.
- Bank1: diagnostic restore and route opening require FLOW=0, PPE enabled,
  not busy, and search-miss=2. Diagnostic restore leaves saved production
  FLOW disabled. Normal production restore and explicit final release
  restore saved values. Every case checks bank0 remains unchanged.
- Snapshot: the actual ER observation enable/getter and stats getter feed
  the diagnostic snapshot before close removes the ring.

Thirty-eight separately compiled negative controls must fail assertions. They
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

The functional matrix includes the original 116 cases plus 94 nonempty-AUTH
cases, for 210 cases and 38 negative controls.
The report records the assertion count, all mutation results, the twelve
invalid-hog admission results and source/patch/test hashes. Successful
completion requires zero accepted invalid hogs and sets both pass fields
to true. Debugfs file permissions, textual formatting, hardware GPIO state
and packet capture in the NAPI loop remain integration checks outside this
host test.
