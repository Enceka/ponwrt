# Hardware flowtable callback teardown

Run against the kernel source immediately before ZZC:

```sh
python3 -B verify.py --baseline /path/to/baseline --patch-orb-machine ponwrt
```

The source may also be read from the VM with `--orb-machine ponwrt`.
`--patch-orb-machine` runs GNU patch through the VM against the host temporary
directory; the VM kernel tree stays unchanged. On Linux, local GNU patch is
used by default. The runner checks exact hunk positions, the real GNU patch
result and unchanged input files, then extracts 39 kernel functions for the
host harness.

The suite covers table/hook/device teardown, namespace filtering, shared
callbacks, pending ADD/STATS/DEL work, in-flight packet readers and GC work.
It requires hardware destruction before callback removal and checks that
deleted hooks are absent from new route discovery. Normal and sanitizer
builds execute 115 cases. The original kernel and nine mutations must fail.
An additional regression retains the asymmetric hunk that Apple patch accepts
and GNU patch rejects, preventing that packaging error from recurring.

Allocation and driver deletion failures retain their existing kernel behavior;
the harness exercises both alongside the callback ordering change.
