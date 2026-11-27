# Fixed rebuilt NPU runtime admission

`999-zj-net-airoha-check-resident-npu-suppliers.patch` extends ZI at
`airoha_npu_get()`, before the one-shot startup function. Every rebuilt get
checks the fixed product dependencies, including a WLAN-first get. Ethernet
must have completed binding. Legacy profiles retain their ZI behavior.

## Checked runtime graph

The gate uses the live OF nodes and platform devices, with device mutexes
held while inspecting driver binding:

| Device | Required state |
| --- | --- |
| NPU | `airoha,en7581-npu`, bound `airoha-npu` |
| Ethernet | Unique `airoha,en7581-eth`, bound `airoha_eth`, `airoha,npu` points to this NPU |
| Reset SCU | All Ethernet reset tuples select the same `airoha,en7581-scu`, bound `clk-en7523` |
| Chip-SCU | SCU's explicit `airoha,chip-scu` selects `airoha,en7581-chip-scu` plus `syscon`, no platform driver |
| Actual parents | Each device's actual parent matches its OF parent, the fixed `soc` simple bus, then the actual `platform_bus` singleton |

NPU, Ethernet and SCU drivers require `owner == NULL` and
`suppress_bind_attrs`. The `soc` parent must be bound to the built-in
`simple-pm-bus` transparent branch: `owner == NULL`, first compatible
`simple-bus`, no `driver_override`, NULL drvdata, and the actual OF match
must select `simple-bus` with non-NULL match data. The transparent branch
allocates no driver resources and neither populates nor depopulates its
children on bind/unbind, so its exposed bind attributes are accepted only
for this exact case. An unbound parent returns `-EPROBE_DEFER`; arbitrary
parent drivers are rejected even with bind attributes suppressed.
`platform_bus` must be registered,
driverless and parentless. All participating devices must be registered.
All OF nodes and their ancestors must be fixed and available. ZI's built-in,
dynamic OF, overlay and kexec conditions remain active.

The reset list must be valid, with one cell per tuple, matching names and at
least `fe`, `pdma`, `qdma`. The remaining XSI resets are checked as well.
The SCU is found explicitly from those tuples. An existing ETH-to-SCU device
link is not required. Before startup, the gate adds an NPU-to-SCU managed
`DL_FLAG_AUTOREMOVE_SUPPLIER` link. The existing consumer-to-NPU link remains
in `airoha_npu_get()`. Existing matching links are reused by driver core.
Link allocation failure stops startup and can be retried.

The chip-SCU follows Linux's generic syscon path. The bound `clk-en7523`
initialization has already obtained the phandle's cached regmap; the gate
checks that lookup and its error. Generic syscon uses `regmap_init_mmio(NULL,
...)`, independent of a bound platform driver's devres. No chip-SCU managed
link is added. Clocks, resets and other resource dependencies on that syscon
are rejected. The fixed NPU, SCU and simple bus also reject additional
resource properties; only Ethernet's explicitly checked resets are admitted.

## Locking and errors

ZI already owns the NPU lock and, for an Ethernet caller, the consumer lock.
The scope borrows those locks and obtains every additional lock with
`device_trylock()`. Shared parents are deduplicated. No blocking device lock
acquisition is added. Contention or an unfinished binding returns
`-EPROBE_DEFER`; incompatible topology or policy returns `-EOPNOTSUPP`.
Regmap errors propagate and managed-link allocation failure returns
`-EINVAL`.

All six normal device locks remain held through the real one-shot startup
and consumer link creation. The scope is released on success and every
error path; each OF/device/module reference is paired. Admission failure
leaves `start_attempted` clear. Startup failure retains ZI's error and bound
provider resources; a later get never triggers a second boot.

The gate is sleepable and runs at acquisition, before hardware exposure.
It adds no packet-path traversal and changes no ER mailbox protocol.

## API and lifecycle boundary

The implementation uses public APIs from the target Linux 6.18 build,
including `device_has_driver_override()` from `include/linux/device.h`.
The target carries this helper instead of the `platform_device` field in
the original v6.18 tag. The audited upstream source inputs
are recorded under `build/pon-resident-runtime-20261127/api/`:

- `drivers/base/dd.c`: `device_is_bound()` requires the device mutex and
  becomes true only after driver-core probe completion.
- `drivers/of/platform.c`: `of_find_device_by_node()` takes a device
  reference; `of_platform_device_create()` builds the actual parent chain.
- `drivers/clk/clk-en7523.c` from the local reset-provider tree: successful
  EN7581 binding obtains the chip-SCU syscon and registers `rcdev.dev` and
  `rcdev.of_node` on that same SCU. Ethernet's bound probe has acquired its
  exclusive reset handles from those fixed tuples.
- `drivers/reset/core.c`: reset provider lookup selects `rcdev.of_node`.
  A reset handle has no public accessor exposing its `rcdev`; this patch
  uses the fixed DT mapping and the reviewed bound driver registration.
- `drivers/mfd/syscon.c`: successful generic syscon entries are cached
  outside platform-device devres.
- `drivers/bus/simple-pm-bus.c`: the first `simple-bus` compatible and
  non-NULL match data select the resource-free transparent branch in probe
  and remove. `drivers/bus/Makefile` builds it through `CONFIG_OF`; there is
  no separate `CONFIG_SIMPLE_PM_BUS` switch. The gate checks runtime state.
- `drivers/base/core.c`, `drivers/base/base.h`, `include/linux/device.h`:
  managed-link insertion is public. Supplier-list traversal requires the
  private driver-core SRCU helpers, declared only in `drivers/base/base.h`.

The chosen implementation checks this explicit product graph and creates the
required SCU relationship. It does not reach into driver-core private list
locking or add a general supplier enumeration API. Arbitrary new managed
suppliers, changed resource bindings and runtime device reparenting require
a separate extension of the product graph. The product must keep these
drivers, devices and dependencies resident until whole-system reset;
runtime detach, reprobe, driver unregister and parent depopulation are
unsupported. No reset fence or DRAM retirement protocol is introduced.

Before using a new RAM image, integration must verify the actual `soc`
driver/parent chain and transparent match state. Full-kernel compilation
and board acceptance are performed by the main task; this directory's test
runner never accesses a VM or device.

## Host regression and negative controls

Run from the main ponwrt repository against a generated tree through ZI:

```sh
python3 -B target/linux/airoha/tests/npu_resident_runtime/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-er-consumer-20261127/start-tests-v2/kernel \
  --output /Volumes/Workspace/5585f/build/pon-resident-runtime-20261127/tests-final
```

Use `--patched` for a tree already containing ZJ. The output directory must
be new and outside ponwrt. The runner applies the production patch with zero
fuzz/offset, includes the complete production resident header, and extracts
the unchanged production fixed-node, resident-device, start-bound, get and
put functions. Only Linux services and the low-level boot operation are
host shims. The existing ZI suite covers the boot register sequence.

Clang compiles with ASan/UBSan. The suite covers the driverless syscon and
missing ETH-to-SCU link, ETH/WLAN-first acquisition, every reset tuple,
all actual parent paths, unsupported drivers/resources/configuration,
link and regmap failures, retained startup errors, references and scope
capacity. Twelve real pthread contention cases check deferred return and
successful retry. Compiled negative controls must fail assertions for
skipped admission, driver/parent/reset checks, leaked locks/references and
ignored link failures. Reports include production patch/source/test hashes.
