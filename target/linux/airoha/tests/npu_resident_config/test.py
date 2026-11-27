#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]


def main():
    parser = argparse.ArgumentParser(description="Real dtc/fdtdump resident preflight regressions")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--dtc", default=os.environ.get("DTC", "dtc"))
    parser.add_argument("--fdtdump", default=os.environ.get("FDTDUMP", "fdtdump"))
    args = parser.parse_args()
    output = args.output.resolve()
    if output == REPO or REPO in output.parents or output.exists():
        parser.error("--output must be a new directory outside ponwrt")
    output.mkdir(parents=True)
    baseline_config = (HERE / "fixtures/resident.config").read_text()
    baseline_dts = (HERE / "fixtures/resident.dts").read_text()
    results = []

    def command(arguments, data=None):
        return subprocess.run(arguments, input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=45)

    def case(name, config=baseline_config, dts=baseline_dts, expected=0,
             failures=(), kind="dtb", compile_flags=(), extra=(), corrupt=None):
        directory = output / name
        directory.mkdir()
        config_path = directory / "kernel.config"
        source_path = directory / "final.dts"
        report_path = directory / "report.json"
        config_path.write_text(config)
        source_path.write_text(dts)
        dt_path = source_path
        if kind == "dtb":
            dt_path = directory / "final.dtb"
            compiled = command([args.dtc, "-q", *compile_flags, "-I", "dts", "-O",
                                "dtb", "-o", str(dt_path), str(source_path)])
            (directory / "compile.log").write_bytes(compiled.stderr)
            if compiled.returncode:
                results.append({"name": name, "ok": False, "error": "fixture compilation failed"})
                return
            if corrupt:
                dt_path.write_bytes(corrupt(dt_path.read_bytes()))
        if kind == "dump":
            compiled = command([args.dtc, "-q", "-I", "dts", "-O", "dtb",
                                "-o", "-", str(source_path)])
            if compiled.returncode:
                raise RuntimeError(compiled.stderr.decode())
            blob_path = directory / "final.dtb"
            blob_path.write_bytes(compiled.stdout)
            dumped = command([args.fdtdump, str(blob_path)])
            if dumped.returncode:
                raise RuntimeError(dumped.stderr.decode())
            source_path.write_bytes(dumped.stdout)
        invocation = [sys.executable, "-B", str(HERE / "verify.py"),
                      "--config", str(config_path), "--dt", str(dt_path),
                      "--dtc", args.dtc, "--fdtdump", args.fdtdump,
                      "--report", str(report_path), *extra]
        result = command(invocation)
        (directory / "stdout.log").write_bytes(result.stdout)
        (directory / "stderr.log").write_bytes(result.stderr)
        problems = []
        if result.returncode != expected:
            problems.append(f"exit {result.returncode}, expected {expected}")
        report = json.loads(report_path.read_text()) if report_path.exists() else {}
        observed = {item["id"] for item in report.get("failures", [])}
        if not set(failures) <= observed:
            problems.append(f"failure IDs {sorted(observed)}, expected {failures}")
        if report.get("runtime_lifecycle") != "requires-separate-qualification":
            problems.append("missing runtime lifecycle boundary")
        if report.get("exit_code") != expected:
            problems.append("JSON exit code mismatch")
        if report.get("inputs", {}).get("config", {}).get("sha256") != hashlib.sha256(
                config_path.read_bytes()).hexdigest():
            problems.append("configuration hash mismatch")
        if expected == 0 and (observed or report.get("status") != "pass"):
            problems.append("success report contains a failure")
        results.append({"name": name, "ok": not problems, "expected_exit": expected,
                        "actual_exit": result.returncode, "failure_ids": sorted(observed),
                        "errors": problems, "command": invocation,
                        "report": str(report_path)})

    case("valid-dtb")
    case("valid-dts", kind="dts")
    case("valid-fdtdump", extra=("--backend", "fdtdump"))
    case("valid-fdtdump-text", kind="dump")
    case("valid-symbols", compile_flags=("-@",))
    case("valid-legacy-phandles", compile_flags=("-H", "legacy"))
    case("valid-both-phandles", compile_flags=("-H", "both"))
    case("valid-status-omitted", dts=baseline_dts.replace('\t\t\tstatus = "okay";\n', ""))
    case("valid-status-ok", dts=baseline_dts.replace('status = "okay"', 'status = "ok"'))
    case("valid-disabled-absent", config="\n".join(
        line for line in baseline_config.splitlines() if not line.startswith("#")) + "\n")
    case("valid-disabled-explicit-n", config=baseline_config.replace("# CONFIG_", "CONFIG_").replace(
        " is not set", "=n"))
    case("valid-comment-mentions-plugin", dts=baseline_dts + '\n/* /plugin/ is documentation */\n')
    case("valid-unrelated-node", dts=baseline_dts +
         '\n/ { unrelated { status = "disabled"; compatible = "test,unrelated"; }; };\n')

    for symbol in ("NET_AIROHA", "NET_AIROHA_NPU", "COMMON_CLK_EN7523"):
        for value in ("m", "n", '"y"'):
            case(f"config-{symbol}-{value.strip(chr(34))}-" + ("quoted" if '"' in value else "literal"),
                 config=baseline_config.replace(f"CONFIG_{symbol}=y", f"CONFIG_{symbol}={value}"),
                 expected=1, failures=("config." + symbol,))
        case(f"config-{symbol}-absent", config=baseline_config.replace(f"CONFIG_{symbol}=y\n", ""),
             expected=1, failures=("config." + symbol,))
    for symbol in ("OF_DYNAMIC", "OF_OVERLAY", "KEXEC", "KEXEC_FILE"):
        for value in ("y", "m"):
            case(f"config-{symbol}-{value}", config=baseline_config.replace(
                f"# CONFIG_{symbol} is not set", f"CONFIG_{symbol}={value}"),
                expected=1, failures=("config." + symbol,))
    case("config-duplicate", config=baseline_config + "CONFIG_NET_AIROHA_NPU=y\n",
         expected=1, failures=("config.NET_AIROHA_NPU",))
    case("config-contradictory", config=baseline_config + "CONFIG_OF_DYNAMIC=y\n",
         expected=1, failures=("config.OF_DYNAMIC",))
    case("config-malformed", config=baseline_config.replace(
        "# CONFIG_OF_OVERLAY is not set", "CONFIG_OF_OVERLAY = n"),
        expected=1, failures=("config.OF_OVERLAY",))

    changes = [
        ("wrong-board", 'fiberhome,hg5585f-ct', 'fiberhome,hg5585f', "dt.board"),
        ("wrong-npu-compatible", 'airoha,en7581-npu', 'airoha,an7583-npu', "dt.node/soc/npu@1e900000"),
        ("wrong-mmio", '0x313000', '0x300000', "dt.node/soc/npu@1e900000"),
        ("wrong-parent", '\tsoc {', '\tother-bus {', "dt.parents"),
        ("missing-rebuilt", '\t\t\tairoha,connac2-rebuilt-ram-lab;\n', '', "dt.rebuilt-profile"),
        ("valued-rebuilt", 'airoha,connac2-rebuilt-ram-lab;', 'airoha,connac2-rebuilt-ram-lab = <0>;', "dt.rebuilt-profile"),
        ("legacy-profile", '"connac2-pkt"', '"pkt"', "dt.rebuilt-profile"),
        ("missing-npu-link", '\t\t\tairoha,npu = <&npu>;\n', '', "dt.eth-npu"),
        ("wrong-npu-link", 'airoha,npu = <&npu>', 'airoha,npu = <&scuclk>', "dt.eth-npu"),
        ("dangling-npu-link", 'airoha,npu = <&npu>', 'airoha,npu = <0xdeadbeef>', "dt.eth-npu"),
        ("extra-npu-link", 'airoha,npu = <&npu>', 'airoha,npu = <&npu &npu>', "dt.eth-npu"),
        ("wrong-chip-link", 'airoha,chip-scu = <&chip_scu>', 'airoha,chip-scu = <&npu>', "dt.scu-chip-scu"),
        ("wrong-reset-supplier", 'resets = <&scuclk 0>', 'resets = <&npu 0>', "dt.eth-resets"),
        ("dangling-reset-supplier", 'resets = <&scuclk 0>', 'resets = <0xdeadbeef 0>', "dt.eth-resets"),
        ("missing-qdma-reset", '"fe", "pdma", "qdma"', '"fe", "pdma", "other"', "dt.eth-resets"),
        ("duplicate-reset-names", '"fe", "pdma", "qdma"', '"fe", "fe", "qdma"', "dt.eth-resets"),
        ("truncated-reset", ', <&scuclk 2>', '', "dt.eth-resets"),
        ("reset-cell-count", '#reset-cells = <1>', '#reset-cells = <2>', "dt.eth-resets"),
        ("clock-cell-count", '#clock-cells = <1>', '#clock-cells = <2>', "dt.eth-resets"),
        ("dynamic-pool-allocation", 'reg = <0 0x92980000 0 0x80000>', 'size = <0 0x80000>', "dt.rebuilt-profile"),
        ("wrong-pool-link", '<&npu_pkt>', '<&scuclk>', "dt.rebuilt-profile"),
        ("duplicate-pool", '<&npu_host>', '<&npu_pkt>', "dt.rebuilt-profile"),
        ("missing-no-map", '\t\t\tno-map;\n', '', "dt.rebuilt-profile"),
    ]
    for name, before, after, check in changes:
        if before not in baseline_dts:
            raise RuntimeError(f"unused mutation {name}")
        case(name, dts=baseline_dts.replace(before, after), expected=1, failures=(check,))
    for label, path in (("eth", "/soc/ethernet@1fb50000"), ("npu", "/soc/npu@1e900000"),
                        ("scuclk", "/soc/clock-controller@1fb00000"),
                        ("chip_scu", "/soc/syscon@1fa20000")):
        case("disabled-" + label, dts=baseline_dts + f'\n&{label} {{ status = "disabled"; }};\n',
             expected=1, failures=("dt.node" + path,))
    for path in ("/", "/soc"):
        case("disabled-parent-" + path.replace("/", "root"),
             dts=baseline_dts + f'\n&{{{path}}} {{ status = "disabled"; }};\n',
             expected=1, failures=("dt.parents", "dt.node/soc/npu@1e900000"))
    case("disabled-memory-parent", dts=baseline_dts +
         '\n&{/reserved-memory} { status = "disabled"; };\n',
         expected=1, failures=("dt.rebuilt-profile",))
    case("reusable-pool", dts=baseline_dts + '\n&npu_pkt { reusable; };\n',
         expected=1, failures=("dt.rebuilt-profile",))
    case("parent-address-cells", dts=baseline_dts + '\n&{/soc} { #address-cells = <1>; };\n',
         expected=1, failures=("dt.parents",))
    case("parent-ranges", dts=baseline_dts + '\n&{/soc} { ranges = <0 0 0 0x10000000 1 0>; };\n',
         expected=1, failures=("dt.parents",))
    case("duplicate-scu-compatible", dts=baseline_dts +
         '\n/ { other { compatible = "airoha,en7581-scu", "syscon"; }; };\n',
         expected=1, failures=("dt.node/soc/clock-controller@1fb00000",))
    for artifact in ("__fixups__", "__local_fixups__", "__overlay__", "fragment@0"):
        case("overlay-" + artifact, dts=baseline_dts + f'\n/ {{ {artifact} {{ }}; }};\n',
             expected=1, failures=("dt.no-overlay",))
    case("source-plugin", kind="dts", dts=baseline_dts.replace(
        "/dts-v1/;", "/dts-v1/;\n/plugin/;"), expected=1, failures=("dt.no-overlay",))
    case("actual-overlay", dts='''/dts-v1/;
/plugin/;
&external_npu { airoha,connac2-rebuilt-ram-lab; };
''', expected=1, failures=("dt.no-overlay", "dt.board", "dt.eth-npu"))
    case("fdtdump-rejects-wrong-link", dts=baseline_dts.replace(
        "airoha,npu = <&npu>", "airoha,npu = <&scuclk>"),
        extra=("--backend", "fdtdump"), expected=1, failures=("dt.eth-npu",))
    case("multiple-failures", config=baseline_config.replace("CONFIG_NET_AIROHA=y", "CONFIG_NET_AIROHA=m"),
         dts=baseline_dts.replace("airoha,npu = <&npu>", "airoha,npu = <&scuclk>"),
         expected=1, failures=("config.NET_AIROHA", "dt.eth-npu"))
    case("invalid-dts", kind="dts", dts="/dts-v1/; / { broken = ; };",
         expected=2, failures=("input.dt",))
    case("truncated-dtb", corrupt=lambda blob: blob[:32],
         extra=("--format", "dtb"), expected=2, failures=("input.dt",))
    case("bad-dtb-total", corrupt=lambda blob: blob[:4] + struct.pack(">I", len(blob) + 4096) + blob[8:],
         extra=("--backend", "fdtdump"), expected=2, failures=("input.dt",))
    case("bad-reservation-offset", corrupt=lambda blob: blob[:16] + struct.pack(">I", 0) + blob[20:],
         extra=("--backend", "fdtdump"), expected=2, failures=("input.dt",))
    case("missing-tool", extra=("--backend", "dtc", "--dtc", str(output / "missing-dtc")),
         expected=2, failures=("input.dt",))
    case("fdtdump-dts-rejected", kind="dts", extra=("--backend", "fdtdump"),
         expected=2, failures=("input.dt",))
    case("auto-fdtdump-fallback", extra=("--dtc", str(output / "missing-dtc")))

    blocked_report = HERE / "must-not-be-created.json"
    blocked = command([sys.executable, "-B", str(HERE / "verify.py"),
                       "--config", str(HERE / "fixtures/resident.config"),
                       "--dt", str(HERE / "fixtures/resident.dts"),
                       "--report", str(blocked_report)])
    (output / "blocked-output.log").write_bytes(blocked.stderr)
    results.append({"name": "reject-repo-output", "ok": blocked.returncode == 2 and
                    not blocked_report.exists()})
    for filename, option in (("kernel.config", "--config"), ("final.dtb", "--dt")):
        candidate = output / "valid-dtb" / filename
        before = candidate.read_bytes()
        rejected = command([sys.executable, "-B", str(HERE / "verify.py"),
                            "--config", str(output / "valid-dtb/kernel.config"),
                            "--dt", str(output / "valid-dtb/final.dtb"),
                            "--report", str(candidate)])
        results.append({"name": "reject-overwriting-input" + option,
                        "ok": rejected.returncode == 2 and candidate.read_bytes() == before})
    stdout_report = command([sys.executable, "-B", str(HERE / "verify.py"),
                             "--config", str(output / "valid-dtb/kernel.config"),
                             "--dt", str(output / "valid-dtb/final.dtb"),
                             "--dtc", args.dtc, "--report", "-"])
    (output / "stdout-report.json").write_bytes(stdout_report.stdout)
    try:
        stdout_payload = json.loads(stdout_report.stdout)
    except ValueError:
        stdout_payload = {}
    results.append({"name": "json-only-stdout", "ok": stdout_report.returncode == 0 and
                    stdout_payload.get("status") == "pass"})
    failed = [result for result in results if not result["ok"]]
    report = {"status": "fail" if failed else "pass", "total": len(results),
              "passed": len(results) - len(failed), "tests": results,
              "dtc_version": command([args.dtc, "--version"]).stdout.decode().strip(),
              "sources": {str(path.relative_to(HERE)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sorted(HERE.rglob("*")) if path.is_file()}}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    for result in failed:
        print(json.dumps(result))
    print(f"{report['status'].upper()}: {report['passed']}/{report['total']} regressions; "
          f"report: {output / 'report.json'}")
    return int(bool(failed))


if __name__ == "__main__":
    sys.exit(main())
