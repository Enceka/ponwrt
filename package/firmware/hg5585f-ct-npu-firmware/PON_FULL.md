# HG5585F CT PON full-image payload input

`hg5585f-ct-npu-pon-full-firmware` packages the dualbank-owner RAM payload
recorded in `pon-full.json`. The package installs separate
`npu_pon_full_rv32.bin` and `npu_pon_full_data.bin` files under
`/lib/firmware/airoha/hg5585f-ct/`. Selecting the package selects the
`connac2-wed-pon-full` persistent DTS and the pinned PON loader. Both Ethernet
and NPU nodes must carry the same exclusive `airoha,connac2-pon-full` profile.
Optical ingress defaults to WAN CPU until an explicit owner session opens.

The PON profile accepts exact IPv4 TCP/UDP downstream software candidates
from a live GDM2/WAN receiver to a live local wired output. Candidate cookies
retain their original ingress identity and remain excluded from ordinary
host row learning, including after a qualification transition. QDMA reception
and validated production ER returns both feed identity observation. The
production owner must bind and retire these candidates explicitly; candidate
acceptance alone leaves their hardware hash unbound.

Each candidate publication allocates a non-reusable serial. A production worker
can acquire a referenced snapshot of the original key, service mapping and NAT
action, then revalidate the cookie, serial, generation and live endpoints before
acting. The current snapshot contract accepts GPON IPv4 TCP/UDP; EPON candidate
snapshots are deferred until the return mapping supports their identity.
Shared Bank0 helpers check a real UNB row's tuple and install only into a fully
empty row, with SRAM ACK and complete readback verification. A submitted write
retains its cleanup obligation even when completion times out. The diagnostic
bind/install path exercises these helpers. The explicit production session
uses them with exclusive Bank0 ownership. Shared Bank0 ownership with native
WLAN flows remains pending.
The WAN QDMA UNB-rate path now records a consumable hardware learning event
with the candidate serial, generation, original key and GEM service. The
hardware row is kept separate from the software entry's unbound hash.
Withdrawal, identity conflict and Bank0 retirement clear pending events.
The selected worker verifies that row, closes and drains the owned bank, then
performs checked installation before reopening the session.

The source revision is `f121da5f83a870e4fc7f39157db707a7334f7c0d`.
The recorded RAM test exercised Bank0 UNB-to-BND forwarding to LAN1,
cross-GEM isolation and owner restoration. Evidence paths are relative to
the enclosing workspace and are recorded with hashes for retrieval; the
offline verifier uses the committed payload identity and requires no board
or evidence directory access.

The host driver now provides an explicit single-candidate session through
`pon_npu_flow` in the PPE debugfs directory. `start COOKIE SERIAL` selects an
observed GPON IPv4 TCP/UDP downstream candidate. The owner authorizes its
original ingress identity, waits for a trusted WAN hardware learning event,
checks the actual UNB row, then installs the candidate's NAT/output action
through the closed Bank0 transaction. Flow deletion and device/mapping
invalidation close the session; `release` restores the saved bank settings
and releases its references. Failed cleanup retains the owner for retry.
This session requires native pair policy to be disabled and no active native
pairs; the start command returns `EBUSY` while that policy is active. It does
not change the policy itself. Shared PON/WLAN operation and automatic session
selection remain pending. The current milestone covers GPON IPv4 downstream;
EPON, XG-PON, upstream and IPv6 are outside this session's scope. Global
`ct_pon_qualified` stays false. See
`target/linux/airoha/tests/npu_pon_production` for the executable host regression.

Use the NPU repository's pinned toolchain and these build options:

```sh
make CT_BRIDGE_GUARD=2 CT_SHORT_PAD=1 CT_TDMA_BANK=2 CT_NATIVE_PAIRS=1 \
  CT_FE_GENERIC=1 CT_FE_NATIVE=1 CT_FE_SOURCE_PORT=24 CT_FE_MAX_FRAME=1518 \
  CT_FE_PON_GENERIC=1 CT_FE_PON_AUTH=1 CT_FE_PIPELINE=1 \
  CT_FE_AUTH=1 CT_FE_AUTH_MAILBOX=1 CT_BANK1_GATE=1 CT_ETH_RETURN=1 \
  CT_ETH_RETURN_DMA=0 CT_FE_TUNNEL_FLUSH=0 CT_FE_TUNNEL_RX=0 all ram-payload
```

From the ponwrt root, verify an existing build before preparing package inputs:

```sh
python3 -B target/linux/airoha/tests/pon_offload/verify_pon_payload.py \
  --payload-dir /absolute/path/to/npu/build
```

Source mode checks the ELF, code, data and manifest against the committed
identity, including features, ABI, load addresses and SRAM headroom.
The manifest's generic FE selector describes LAN1/PSE8; the PON source
uses PSE4 in this firmware. Code occupies 39,084 bytes and local SRAM has
four bytes of remaining space.

Prepare a full-image overlay from verified stock and PON inputs:

```sh
bash target/linux/airoha/hg5585f-ct/prepare-overlay.sh \
  /absolute/path/to/stock/userfs /absolute/path/to/new-overlay \
  --pon-full /absolute/path/to/npu/build
```

The overlay includes the independent payload pins, platform patches and
full DTS, verifies source and installed payloads, and emits the package
selection in `local.config`. Its empty network seed lets `board.d/02_network`
create LAN1–3 as LAN and LAN4 as the test uplink; configure `pon0` separately.
The DTS retains NAND, factory calibration, BOSA, PCS and xPON. RAM-trial
selection is rejected for this image. Do not commit the binaries.
Package installation runs the same verifier in `--installed-dir` mode and
`sha256sum -c SHA256SUMS.pon-full`. Installed mode checks the exact pinned
binary sizes and digests without requiring an ELF or build manifest.

The package requires the CT target, MT7915 NPU and WED prepare support.
Kconfig dependencies, package conflicts and an installation check reject
selection with the old rebuilt or ordinary full-test firmware. The base
stock firmware remains a dependency. No device selects the new package
by default.

Run the offline negative cases with:

```sh
python3 -B -m unittest discover -s target/linux/airoha/tests/pon_offload \
  -p test_verify_pon_payload.py -v
```

For a payload update, review `pon-full.json` and `SHA256SUMS.pon-full`
together, run source verification, and update the loader pin in the
same integration series. Existing RAM and ordinary full-test identities
remain separate.
