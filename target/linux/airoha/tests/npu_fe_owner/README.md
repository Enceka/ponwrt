# Shared native FE owner regression

Run against an unmodified kernel source tree through 991:

```sh
python3 verify.py --source /path/to/kernel-through-991
```

Without `--source`, the runner reads `/workdir/pon-npu-989` with
`orb -m ponwrt cat`. Output defaults to this test directory's `out/`;
`--output` can select another results directory, including one under `build/`.
The runner copies required files into `<output>/kernel` and applies 992 with
zero fuzz and zero offset. It never patches the supplied tree.
`--cc` selects the host compiler.

The harness compiles the entire patched `airoha_ct_native_pair.h`,
`airoha_ct_fe_native.h`, and `airoha_ct_ifc_command.h`, plus the extracted
production policy callbacks and actual FE/FOE/ABI layouts. Existing native
test fixtures provide kernel scaffolding. Mailbox replies, firmware endpoint
state, MMIO, scheduling and fault containment are mocked at their boundaries.
AddressSanitizer and UndefinedBehaviorSanitizer are enabled. Source hashes,
the patch hash, compiler output and results are retained in the output directory.

The 96 cases cover idle configured-native admission, each busy/fault state,
every occupied pair slot, same-owner retry, wrong-owner exclusion, release
before ACK, exact epoch and 64-bit generation, lost ACK after firmware has
accepted QUIESCE, changed-identity rejection, negative/positive transport
errors, owner-held policy/health/frame/bind, wired link changes before and
during QUIESCE, ordinary FLUSH/WLAN revoke after ACK, stopped-driver release,
and native policy/learning/rearming after ownership is released.

## Production API

All three static helpers require `ppe_lock`; no RTNL or allocation is used.

- `airoha_ct_fe_owner_claim(ppe, owner)` accepts a non-null stable owner
  identity when policy, pairs and FE activity/pending state are idle.
  `ct_native_pairs=true` is supported. Reclaiming the same identity succeeds;
  a different identity returns `-EBUSY` without changing state.
- `airoha_ct_fe_owner_quiesce(ppe, owner, u64 generation, u32 epoch)` records
  the exact attempted identity before sending. Any error retains pending
  state; another identity returns `-ESTALE`. Only ACK publishes shared FE
  epoch/generation and `ct_pair_wired_epoch=epoch-1`. Positive transport
  returns become `-EPROTO`; generation remains 64-bit. The lifecycle caller
  must close ingress first and enforce its narrower GATE generation ABI.
- `airoha_ct_fe_owner_release(ppe, owner)` requires an ACK under the current
  claim and no pending/armed/active/dirty/drain state. Wrong or missing owner
  returns `-ESTALE`; incomplete retirement returns `-EBUSY`. Errors retain
  the owner. Release remains available during driver stopping after closure.

Native wired events retain link blocking/recovery but leave shared epochs
alone while claimed. Native revoke before owner QUIESCE ACK is a successful
no-op: claim required an empty native pair set and learning remains blocked.
This lets outer bridge/WLAN callers retire their separate ordinary entries
without treating ownership as a hardware failure. After ACK, normal FLUSH,
bank0 drain and WLAN endpoint revoke execute; wired endpoint revoke stays a
no-op. Firmware only clears the FE ACK on FLUSH/endpoint revoke when FE was
armed, so these operations preserve the owner's already-quiesced identity.

The global lifecycle caller must finish its real close before CT shutdown,
then release after hardware and FOE retirement. These tests exercise the
native revoke used by that path, including a historical pair token; the
full 993 owner-to-shutdown integration is tested by its own suite.
