# PON full-image loader profile

The tests reconstruct the complete loader from SHA256-pinned Linux 6.18.60
`airoha_npu.c` and `airoha_offload.h`, applying every relevant section of the
repository's sorted patch chain with `patch --fuzz=0`. This includes the real
999-zi context refresh and 999-zy; there are no test-only chain replacements.
Historical offsets are recorded; ZY must apply without offsets. No RAM-prepared
loader is used. `binding.json` records each original patch digest, selected
section digest and application output.

```sh
python3 -B target/linux/airoha/tests/npu_pon_full_profile/verify.py \
  --fetch-base \
  --payload-dir /absolute/firmware-repo/build \
  --sdk-source /absolute/full-source \
  --output /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/production-ingress/loader-suite-next
```

For offline runs replace `--fetch-base` with `--base PATH/upstream.c
--offload-base PATH/upstream-offload.h`. Both downloaded base files are saved
in the output directory for reuse. The optional `--sdk-source` compares every
reconstructed loader/transaction/startup/ABI file byte-for-byte with the actual
SDK build sources and records their hashes. Output must be a new directory
outside the ponwrt repository. Payload inputs `ram-npu_rv32.bin` and
`ram-npu_data.bin` are read in place; firmware binaries are never added to Git.
Requirements: Python 3, patch, clang; macOS CommonCrypto or Linux OpenSSL headers
and libcrypto. All C harnesses use ASan and UBSan.

The profile harness compiles extracted production functions and real ABI
headers, with host stubs for DT properties, I/O, firmware requests and mailbox
delivery. It covers all eight NPU selector combinations; probe admission;
stock/RAM/ordinary/PON filename selection; the actual pinned PON code/data;
digest, truncated/oversized, missing payload and readback failures; native
mailbox versus AUTH/ER/GATE admission; and deferred startup, bound/resident
requirements, retained pool errors and quarantine. Denied ER_BIND must leave
the exposure ledger unchanged. The new profile grants transport access while
PON owner qualification remains in the Ethernet lifecycle.

The resident harness reuses `npu_resident_runtime/runtime_test.c` read-only.
Only its host DT-property stub is adapted in the generated fixture so the
same supplier, lock, reference and contention cases execute for RAM and
PON-full against the actual reconstructed getter/startup/resident code.

Nine fault-injection variants must fail runtime assertions: conflicting
profiles, wrong code/data names or digests, missing PON deferred startup,
ordinary transaction access, readiness bypass and missing ER wrapper
admission. Fault injection is confined to generated test inputs and restores
them afterward. `report.json` records the passing baseline, resident results,
rejected variants and source/test/payload identities. This is host validation;
SDK kernel compilation and final config/DT checks use the image build inputs.
