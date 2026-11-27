# EPON registration identity

The host API is `airoha_eth_pon_configure_epon(netdev, channel, llid, valid)`.
Apply `999-zb-net-airoha-publish-epon-registration-identity.patch` together
with the matching pon-drivers caller update and rebuild both modules.

Run the independent host suite against a kernel source snapshot before
999-zb. Use a new output directory under build:

```sh
python3 build/ponwrt/target/linux/airoha/tests/epon_identity/verify.py \
  --source build/pon-er-consumer-20261127/owner-source-isolation \
  --output build/epon-identity-validation
python3 build/pon-drivers/tests/test_pon_transactions.py
python3 build/pon-drivers/tests/test_pon_recovery.py --source build/pon-drivers -v
```

The runner copies the required sources, reconstructs the public header from
922 and 959 when absent, and applies 999-zb with zero fuzz. It executes the
production configuration and commit functions across all 32 channels and
65,536 LLIDs, including valid LLID zero, invalid channels, failed retirement,
transaction ownership/readiness, re-registration and full invalidation.
Lock and retirement stand-ins check publication ordering and retention.

CPU TX tests execute the extracted PON descriptor branch. PPE tests reuse
the existing metadata runner with the production FOE encoder, comparing the
entire hardware row across LLIDs, both IP families and four encapsulations.
Plain and ASan/UBSan builds run the vectors. Three behavioral mutations must
fail. The complete public header accepts the four-argument API and rejects
the old three-argument call. The suite uses host processes and no devices.
