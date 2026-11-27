# HG5585F CT PON full-image payload input

`hg5585f-ct-npu-pon-full-firmware` packages the dualbank-owner RAM payload
recorded in `pon-full.json`. The package installs separate
`npu_pon_full_rv32.bin` and `npu_pon_full_data.bin` files under
`/lib/firmware/airoha/hg5585f-ct/`. Platform loader selection, a persistent
PON DTS and production admission are subsequent integration steps.

The source revision is `f121da5f83a870e4fc7f39157db707a7334f7c0d`.
The recorded RAM test exercised Bank0 UNB-to-BND forwarding to LAN1,
cross-GEM isolation and owner restoration. Evidence paths are relative to
the enclosing workspace and are recorded with hashes for retrieval; the
offline verifier uses the committed payload identity and requires no board
or evidence directory access.

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

Copy the verified code and data into this package's ignored `files/`
directory using the installation names above. Do not commit the binaries.
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
together, run source verification, and update the future loader pin in the
same integration series. Existing RAM and ordinary full-test identities
remain separate.
