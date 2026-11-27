# ER provider exposure lifecycle

`999-zg` records each source's complete
`dma/bytes/epoch/count/sport/generation` before sending ER BIND. The provider
serializes ER commands with a mutex; its private allocation wraps the public
NPU structure without changing existing field offsets or exported prototypes.

A live or uncertain exposure blocks another BIND for that source. The two
sources also reject overlapping physical windows after applying the NPU's
low-30-bit address mapping. Adjacent allocations remain valid. Retired epochs
remain recorded, so an older identity cannot replace a newer allocation.

STOP and UNBIND require the exact recorded configuration. UNBIND requires a
successful STOP first. Successful mutations must report ER_IDLE and zero
fault; malformed replies and transport or firmware errors preserve exposure.
Only successful UNBIND releases that record. QUERY reports capabilities and
status without releasing records. The consumer still owns allocation,
QUIESCE, descriptor drain, HOST_ENABLED clearing and memory release.

The record belongs to one provider allocation and one firmware runtime.
Firmware reload and standalone reset recovery remain disabled. Shared mailbox
timeout isolation is supplied separately by `999-zh`: after an ambiguous
submission it prevents further buffer reuse, including STOP/UNBIND retries.
An ordinary completed negative response can still be retried.

The supported product uses fixed DT nodes and resident built-in ETH/NPU/SCU
providers, with OF_DYNAMIC, OF_OVERLAY and kexec disabled. Patch `999-zi`
enforces startup admission and activates the rebuilt NPU only after successful
provider binding; see `../npu_start/README.md`. Final configuration and DTB
checks live in `../npu_resident_config/`. Supplier teardown remains excluded
from this resident profile. Hardware reset retirement
still needs the hart, GDMA and DRAM bridge completion protocol described in
`../reset_provider/README.md`.

Run against the prepared driver tree through `999-ze`:

```sh
python3 target/linux/airoha/tests/npu_er_provider/verify.py \
  --source /path/to/prepared-kernel \
  --output /path/to/new-test-output
```

The runner applies `999-zg` with zero fuzz and zero offset and compiles the
actual transport and provider header. Only the mailbox, DT readiness and
kernel mutex API are stubbed; mutexes use real pthread locks. Native and
swapped-endian builds run with ASan/UBSan. Tests include exact identity,
cross-window aliases, adjacent allocations, epoch reuse, all three mutation
operations with transport/firmware errors, malformed acknowledgements, and
64 two-thread BIND races per build. Eight compiled negative controls must
fail at runtime. Reports preserve source, patch and test hashes.

Pass `--patched` when the input already contains `999-zg` and subsequent
patches. Both endian modes also rerun the 1,657-check AUTH/ER/GATE transport
suite against the current exchange functions; only the ER call site switches
to its exchange function so protocol validation can run independently from
the separately tested provider lifecycle.
