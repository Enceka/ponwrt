#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys


BUILTIN = ("NET_AIROHA", "NET_AIROHA_NPU", "COMMON_CLK_EN7523")
DISABLED = ("OF_DYNAMIC", "OF_OVERLAY", "KEXEC", "KEXEC_FILE")
ETH = "/soc/ethernet@1fb50000"
NPU = "/soc/npu@1e900000"
SCU = "/soc/clock-controller@1fb00000"
CHIP_SCU = "/soc/syscon@1fa20000"
DEVICES = {
    ETH: (("airoha,en7581-eth",),
          (0, 0x1fb50000, 0, 0x2600, 0, 0x1fb54000, 0, 0x2000,
           0, 0x1fb56000, 0, 0x2000)),
    NPU: (("airoha,en7581-npu",), (0, 0x1e900000, 0, 0x313000)),
    SCU: (("airoha,en7581-scu", "syscon"), (0, 0x1fb00000, 0, 0x970)),
    CHIP_SCU: (("airoha,en7581-chip-scu", "syscon"),
               (0, 0x1fa20000, 0, 0x388)),
}
RUNTIME_REQUIREMENTS = [
    "Under device locks, check bound driver identity, owner == NULL and "
    "suppress_bind_attrs for the admitted devices and relevant suppliers.",
    "Check OF_DYNAMIC/OF_DETACHED flags and availability on live nodes and "
    "ancestors; flattened DT stores properties, not Linux live-node flags or "
    "the history of bootloader/build-time overlay application.",
    "Constrain supplier/parent driver detach, platform depopulation and "
    "provider reprobe. Built-in and suppress_bind_attrs cover module unload "
    "and sysfs bind/unbind respectively; kernel detach callers need their "
    "own lifecycle policy. Managed device links order detach.",
    "Start rebuilt firmware once after successful provider binding; preserve "
    "provider resources, ER exposures and mailbox quarantine after ambiguous "
    "failure. Qualify startup, failure and STOP/UNBIND paths separately.",
]
REPO = Path(__file__).resolve().parents[5]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def artifact_path(value):
    path = Path(value).resolve()
    require(path != REPO and REPO not in path.parents,
            "generated output must be outside the ponwrt repository")
    return path


class Audit:
    def __init__(self):
        self.checks = []

    def check(self, name, function):
        try:
            detail = function()
        except ValueError as error:
            self.checks.append({"id": name, "ok": False, "detail": str(error)})
            return
        self.checks.append({"id": name, "ok": True, "detail": detail})


def check_config(audit, source):
    entries = {name: [] for name in BUILTIN + DISABLED}
    for number, line in enumerate(source.splitlines(), 1):
        match = re.fullmatch(r"CONFIG_([A-Z0-9_]+)=(.*)", line.strip())
        unset = re.fullmatch(r"# CONFIG_([A-Z0-9_]+) is not set", line.strip())
        if match and match[1] in entries:
            entries[match[1]].append((number, match[2]))
        elif unset and unset[1] in entries:
            entries[unset[1]].append((number, "n"))
        else:
            malformed = re.match(r"(?:#\s*)?CONFIG_([A-Z0-9_]+)\b", line.strip())
            if malformed and malformed[1] in entries:
                entries[malformed[1]].append((number, "malformed: " + line))

    def validate(name):
        values = entries[name]
        require(len(values) <= 1, f"CONFIG_{name}: duplicate entries {values}")
        actual = values[0][1] if values else "absent"
        expected = "y" if name in BUILTIN else "n"
        accepted = ("y",) if expected == "y" else ("n", "absent")
        require(actual in accepted,
                f"CONFIG_{name}: expected {expected}, found {actual}")
        return f"CONFIG_{name}={actual}"

    for name in entries:
        audit.check("config." + name, lambda name=name: validate(name))


class FlatTree:
    def __init__(self, blob):
        require(len(blob) >= 40, "truncated FDT header")
        (magic, total, struct_start, strings_start, reserve_start, version,
         compatible_version, _, strings_size, struct_size) = struct.unpack_from(
             ">10I", blob)
        require(magic == 0xd00dfeed, "invalid FDT magic")
        require(version == 17 and compatible_version <= 17,
                "expected FDT v17; normalize older DTBs with dtc first")
        require(40 <= total <= len(blob), "invalid FDT total size")
        require(struct_start % 4 == 0 and reserve_start % 8 == 0,
                "misaligned FDT block")
        require(40 <= struct_start < struct_start + struct_size <= total and
                40 <= strings_start <= strings_start + strings_size <= total,
                "FDT block outside total size")
        require(struct_start + struct_size <= strings_start or
                strings_start + strings_size <= struct_start,
                "overlapping FDT structure and strings")
        reserve_end = reserve_start
        while True:
            require(40 <= reserve_end and reserve_end + 16 <= total,
                    "truncated FDT memory reservation map")
            reservation = struct.unpack_from(">QQ", blob, reserve_end)
            reserve_end += 16
            if reservation == (0, 0):
                break
        for block_start, block_size in ((struct_start, struct_size),
                                        (strings_start, strings_size)):
            require(reserve_end <= block_start or block_start + block_size <= reserve_start,
                    "overlapping FDT memory reservation map")
        structure = blob[struct_start:struct_start + struct_size]
        strings = blob[strings_start:strings_start + strings_size]
        self.nodes = {}
        stack = []
        position = 0

        def word():
            nonlocal position
            require(position + 4 <= len(structure), "truncated FDT token")
            value = struct.unpack_from(">I", structure, position)[0]
            position += 4
            return value

        while position < len(structure):
            token = word()
            if token == 1:
                end = structure.find(b"\0", position)
                require(end >= 0, "unterminated FDT node name")
                name = structure[position:end].decode("ascii")
                position = (end + 4) & ~3
                require("/" not in name and (bool(name) if stack else not name),
                        "invalid FDT node name")
                path = stack[-1].rstrip("/") + "/" + name if stack else "/"
                require(path not in self.nodes, f"duplicate node {path}")
                self.nodes[path] = {}
                stack.append(path)
            elif token == 2:
                require(stack, "unbalanced FDT END_NODE")
                stack.pop()
            elif token == 3:
                require(stack, "FDT property outside node")
                length, name_offset = word(), word()
                end = strings.find(b"\0", name_offset)
                require(name_offset < len(strings) and end >= 0,
                        "invalid FDT property name offset")
                name = strings[name_offset:end].decode("ascii")
                require(name and name not in self.nodes[stack[-1]],
                        f"duplicate or empty property in {stack[-1]}")
                require(position + length <= len(structure),
                        "truncated FDT property value")
                self.nodes[stack[-1]][name] = structure[position:position + length]
                position = (position + length + 3) & ~3
            elif token == 4:
                continue
            elif token == 9:
                require(not stack and "/" in self.nodes, "unbalanced FDT END")
                require(not any(structure[position:]), "data after FDT END")
                return
            else:
                raise ValueError(f"unknown FDT token {token}")
        raise ValueError("missing FDT END")

    def property(self, path, name):
        require(path in self.nodes, f"missing node {path}")
        require(name in self.nodes[path], f"{path}: missing {name}")
        return self.nodes[path][name]

    def cells(self, path, name):
        value = self.property(path, name)
        require(len(value) % 4 == 0, f"{path}:{name}: expected 32-bit cells")
        return struct.unpack(">" + "I" * (len(value) // 4), value)

    def strings(self, path, name):
        value = self.property(path, name)
        require(value.endswith(b"\0"), f"{path}:{name}: expected string list")
        return tuple(item.decode("ascii") for item in value[:-1].split(b"\0"))

    def available(self, path):
        require(path in self.nodes, f"missing node {path}")
        if "status" in self.nodes[path]:
            require(self.strings(path, "status") in (("ok",), ("okay",)),
                    f"{path}: status is not okay/ok")

    def ancestors(self, path):
        while True:
            self.available(path)
            if path == "/":
                break
            path = path.rsplit("/", 1)[0] or "/"

    def phandles(self):
        result = {}
        for path, props in self.nodes.items():
            handles = [self.cells(path, name) for name in ("phandle", "linux,phandle")
                       if name in props]
            if not handles:
                continue
            handle = handles[0]
            require(len(handle) == 1 and handle[0] not in (0, 0xffffffff),
                    f"{path}: invalid phandle")
            require(all(value == handle for value in handles),
                    f"{path}: phandle/linux,phandle mismatch")
            require(handle[0] not in result, f"{path}: duplicate phandle {handle[0]}")
            result[handle[0]] = path
        return result


def check_tree(audit, tree, source_plugin):
    def no_overlay():
        require(not source_plugin, "DTS has /plugin/; supply the final merged tree")
        for path in tree.nodes:
            name = path.rsplit("/", 1)[-1]
            require(name not in ("__fixups__", "__local_fixups__", "__overlay__") and
                    not name.startswith("fragment@"),
                    f"overlay/relocation artifact {path}; supply the final merged tree")
        return "final-tree shape; no plugin/fragments/fixups; __symbols__ permitted"

    def board():
        required = ("fiberhome,hg5585f-ct", "airoha,an7581", "airoha,en7581")
        require(tree.strings("/", "compatible") == required,
                "root compatible must select the fixed HG5585F CT board")
        return ", ".join(required)

    def parent_bus():
        for path in ("/", "/soc"):
            tree.available(path)
            for prop in ("#address-cells", "#size-cells"):
                require(tree.cells(path, prop) == (2,), f"{path}:{prop}: expected 2")
        require("simple-bus" in tree.strings("/soc", "compatible"),
                "/soc: expected simple-bus")
        require(tree.property("/soc", "ranges") == b"", "/soc:ranges must be empty")
        return "fixed /soc parent, identity address translation and available ancestors"

    def device(path, compatible, registers):
        require(tree.strings(path, "compatible") == compatible,
                f"{path}: expected compatible {compatible}")
        matches = [other for other, props in tree.nodes.items()
                   if "compatible" in props and
                   compatible[0] in tree.strings(other, "compatible")]
        require(matches == [path], f"{compatible[0]}: ambiguous nodes {matches}")
        require(tree.cells(path, "reg") == registers, f"{path}: unexpected MMIO reg")
        tree.ancestors(path)
        return path + ": fixed identity, MMIO and available ancestors"

    audit.check("dt.no-overlay", no_overlay)
    audit.check("dt.board", board)
    audit.check("dt.parents", parent_bus)
    for path, (compatible, registers) in DEVICES.items():
        audit.check("dt.node" + path,
                    lambda path=path, compatible=compatible, registers=registers:
                    device(path, compatible, registers))

    handles = {}

    def phandles():
        handles.update(tree.phandles())
        return f"{len(handles)} unique phandles"

    def link(path, prop, destination):
        values = tree.cells(path, prop)
        require(len(values) == 1 and handles.get(values[0]) == destination,
                f"{path}:{prop}: expected one phandle to {destination}")
        return f"{path}:{prop} -> {destination}"

    def resets():
        require(tree.cells(SCU, "#reset-cells") == (1,), "SCU #reset-cells must be 1")
        require(tree.cells(SCU, "#clock-cells") == (1,), "SCU #clock-cells must be 1")
        names = tree.strings(ETH, "reset-names")
        require(len(set(names)) == len(names) and {"fe", "pdma", "qdma"} <= set(names),
                "ETH reset-names must be unique and include fe/pdma/qdma")
        values = tree.cells(ETH, "resets")
        require(len(values) == 2 * len(names), "ETH resets/name count mismatch")
        for offset, name in enumerate(names):
            require(handles.get(values[2 * offset]) == SCU,
                    f"ETH reset {name}: expected supplier {SCU}")
        return "all ETH reset specifiers resolve to the fixed one-cell SCU supplier"

    def rebuilt():
        require(tree.property(NPU, "airoha,connac2-rebuilt-ram-lab") == b"",
                "NPU rebuilt selector must be a boolean")
        names = tree.strings(NPU, "memory-region-names")
        require(names == ("binary", "ba", "connac2-pkt", "connac2-host-rx"),
                "NPU memory-region-names must select the CT Connac2 profile")
        values = tree.cells(NPU, "memory-region")
        require(len(values) == len(names) and len(set(values)) == len(values),
                "NPU memory-region must have four distinct named references")
        for prop in ("#address-cells", "#size-cells"):
            require(tree.cells("/reserved-memory", prop) == (2,),
                    f"/reserved-memory:{prop}: expected 2")
        require(tree.property("/reserved-memory", "ranges") == b"",
                "/reserved-memory:ranges must be empty")
        for name, handle in zip(names, values):
            destination = handles.get(handle, "")
            require(destination.rsplit("/", 1)[0] == "/reserved-memory",
                    f"NPU {name}: expected a fixed /reserved-memory child")
            tree.ancestors(destination)
            require(tree.property(destination, "no-map") == b"",
                    f"{destination}: expected no-map boolean")
            require("reusable" not in tree.nodes[destination],
                    f"{destination}: reusable conflicts with dedicated NPU memory")
            registers = tree.cells(destination, "reg")
            require(len(registers) == 4 and (registers[2] or registers[3]),
                    f"{destination}: expected one nonempty fixed reg range")
        return "rebuilt selector and four static CT Connac2 pool references"

    audit.check("dt.phandles", phandles)
    audit.check("dt.eth-npu", lambda: link(ETH, "airoha,npu", NPU))
    audit.check("dt.scu-chip-scu", lambda: link(SCU, "airoha,chip-scu", CHIP_SCU))
    audit.check("dt.eth-resets", resets)
    audit.check("dt.rebuilt-profile", rebuilt)


def run_tool(command, data=None, cwd=None):
    result = subprocess.run(command, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, cwd=cwd, timeout=30)
    require(result.returncode == 0,
            f"tool exited {result.returncode}: {command[0]}\n" +
            result.stderr.decode(errors="replace")[:8000])
    return result.stdout, result.stderr.decode(errors="replace")


def load_tree(args, raw, metadata):
    input_format = args.format
    if input_format == "auto":
        input_format = "dtb" if raw.startswith(b"\xd0\x0d\xfe\xed") else "dts"
    source_plugin = False
    if input_format == "dts":
        code = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"', "",
                      raw.decode("utf-8"), flags=re.S)
        source_plugin = "/plugin/" in code
    backend = args.backend
    if backend == "auto":
        backend = "dtc" if shutil.which(args.dtc) else "fdtdump"
    if backend == "dtc":
        command = [args.dtc, "-q", "-I", input_format, "-O", "dtb", "-o", "-"]
        for directory in args.include:
            command.extend(("-i", str(Path(directory).resolve())))
        command.append("-")
        metadata["command"] = command
        blob, diagnostics = run_tool(command, raw, args.dt.parent)
    else:
        require(input_format == "dtb", "DTS input requires dtc; fdtdump accepts a DTB")
        command = [args.fdtdump, str(args.dt)]
        metadata["command"] = command
        _, diagnostics = run_tool(command)
        blob = raw
    metadata.update({"backend": backend, "format": input_format,
                     "effective_dtb_sha256": sha256(blob), "diagnostics": diagnostics})
    return FlatTree(blob), source_plugin


def main():
    parser = argparse.ArgumentParser(description="HG5585F CT rebuilt static config/DT preflight")
    parser.add_argument("--config", required=True, type=Path, help="final kernel .config")
    parser.add_argument("--dt", required=True, type=Path, help="final DTB or preprocessed DTS")
    parser.add_argument("--format", choices=("auto", "dtb", "dts"), default="auto")
    parser.add_argument("--backend", choices=("auto", "dtc", "fdtdump"), default="auto")
    parser.add_argument("--dtc", default=os.environ.get("DTC", "dtc"))
    parser.add_argument("--fdtdump", default=os.environ.get("FDTDUMP", "fdtdump"))
    parser.add_argument("-i", "--include", action="append", default=[], help="dtc include directory")
    parser.add_argument("--report", help="JSON output outside ponwrt, or '-' for stdout")
    args = parser.parse_args()
    try:
        report_path = artifact_path(args.report) if args.report and args.report != "-" else None
        require(report_path not in (args.config.resolve(), args.dt.resolve()),
                "report path must differ from both input paths")
    except ValueError as error:
        parser.error(str(error))
    audit = Audit()
    report = {"schema": 1, "scope": "static-config-and-final-dt",
              "profile": "hg5585f-ct-rebuilt", "checks": audit.checks,
              "runtime_lifecycle": "requires-separate-qualification",
              "runtime_requirements": RUNTIME_REQUIREMENTS,
              "checker_sha256": sha256(Path(__file__).read_bytes()), "inputs": {}}
    input_error = False
    for name, path in (("config", args.config), ("dt", args.dt)):
        try:
            path = path.resolve()
            raw = path.read_bytes()
            metadata = {"path": str(path), "sha256": sha256(raw)}
            report["inputs"][name] = metadata
            if name == "config":
                check_config(audit, raw.decode("utf-8"))
            else:
                args.dt = path
                tree, source_plugin = load_tree(args, raw, metadata)
                check_tree(audit, tree, source_plugin)
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            input_error = True
            audit.checks.append({"id": "input." + name, "ok": False, "detail": str(error)})
    failures = [check for check in audit.checks if not check["ok"]]
    exit_code = 2 if input_error else int(bool(failures))
    report.update({"status": "input-error" if input_error else "fail" if failures else "pass",
                   "exit_code": exit_code, "failures": failures})
    encoded = json.dumps(report, indent=2) + "\n"
    if report_path:
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(encoded)
        except OSError as error:
            print(f"ERROR report: {error}", file=sys.stderr)
            return 2
    if args.report == "-":
        print(encoded, end="")
    else:
        for failure in failures:
            print(f"FAIL {failure['id']}: {failure['detail']}")
        print(f"{report['status'].upper()}: static config/DT preflight, "
              f"{len(audit.checks) - len(failures)}/{len(audit.checks)} checks")
        print("REQUIRED BEFORE QUALIFICATION: runtime driver-core detach/lifetime enforcement; "
              "see JSON runtime_requirements and README.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
