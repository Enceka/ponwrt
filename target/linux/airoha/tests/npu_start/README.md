# Bound rebuilt NPU startup

Patch `999-zi` prepares the rebuilt firmware and mailbox allocations during
probe, then starts the NPU once when a consumer obtains the fully bound
provider. Driver-core failures after probe therefore release preparations
before any NPU master starts. Legacy profiles keep their probe-time startup.

The rebuilt profile requires built-in Ethernet, NPU and EN7523 clock drivers,
disabled OF_DYNAMIC/OF_OVERLAY and kexec, fixed available DT ancestors, and
drivers with sysfs bind/unbind suppressed. Ethernet callers must also be
bound. Device trylocks serialize lookup and startup without waiting behind
removal locks; contention returns `-EPROBE_DEFER` for a later attempt.
The final configuration and DTB checker is in `../npu_resident_config/`.

All fourteen startup register writes propagate errors. A failed startup
retains its error and allocations in the bound provider, clears the WLAN
guard, and rejects another boot trigger. Pool initialization failure is
fatal to rebuilt startup. Mailbox quarantine and shutdown block later
activation. There is no standalone reset or reload recovery path.

Run against a prepared driver tree through `999-zh`:

```sh
python3 target/linux/airoha/tests/npu_start/verify.py \
  --source /path/to/prepared-kernel \
  --output /path/to/new-test-output
```

Use `--patched` for a tree already containing `999-zi`. The runner applies
the patch with zero fuzz and offset, includes the production startup header,
and extracts the real get/shutdown functions. It tests preparation without
startup, unbound providers and Ethernet consumers, every register failure,
pool errors, quarantine, device/module references, rejected configurations
and DT ancestors, legacy behavior, and simultaneous acquisitions using real
pthread device locks. Ten compiled negative controls must fail assertions.
The suite runs with ASan/UBSan and records source, patch and test hashes.
Probe integration is checked separately for configuration admission before
allocation and preparation before drvdata publication. Full kernel builds
validate the actual Linux APIs and include environment.

The supported product keeps providers and their suppliers resident until
whole-system reset. Runtime detach/reprobe and standalone reset retirement
remain outside this profile. PON qualification stays closed pending the
remaining integration and board acceptance.
