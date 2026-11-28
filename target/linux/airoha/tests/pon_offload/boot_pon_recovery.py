#!/usr/bin/env python3
"""Boot a verified PON recovery FIT over TFTP and capture its SSH identity."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
import time

from prepare_npu_ram import require


def preflight(fit, evidence):
    report = json.loads(evidence.read_text())
    data = fit.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    require(report.get('passed') is True and report.get('profile') == 'pon-full',
            'expected passing PON full-image pair evidence')
    require(report['recovery']['sha256'] == digest and
            report['recovery']['bytes'] == len(data), 'recovery image differs from evidence')
    require(report['recovery']['resident_checks'] and
            all(check.get('ok') is True for check in report['recovery']['resident_checks']),
            'resident preflight is incomplete')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.itb', fit.name), 'unsafe TFTP filename')
    return data, digest


def config(args):
    repository = Path(__file__).resolve().parents[5]
    require(not args.output.resolve().is_relative_to(repository), 'output must be outside ponwrt')
    require(not args.output.exists(), 'output must be new')
    require((args.toolkit / 'live.py').is_file(), 'missing factory toolkit live.py')
    for name in ('board_ip', 'host_ip', 'transfer_board_ip', 'transfer_host_ip'):
        require(isinstance(ipaddress.ip_address(getattr(args, name)), ipaddress.IPv4Address),
                'expected IPv4 address: ' + name)
    for name in ('interface', 'transfer_interface'):
        require(re.fullmatch(r'[A-Za-z0-9_.-]+', getattr(args, name)), 'invalid interface')
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', args.previous_boot),
            'invalid previous boot identity')
    require(args.key.is_file() and args.pin.is_file(), 'missing SSH key or host pin')
    require(str(args.serial).startswith('/dev/'), 'expected serial device')
    require(1024 <= args.tftp_port <= 65535, 'expected unprivileged TFTP port')
    for board, host in ((args.board_ip, args.host_ip), (args.transfer_board_ip, args.transfer_host_ip)):
        require(board != host and ipaddress.ip_address(board) in
                ipaddress.ip_network(host + '/24', strict=False), 'endpoints must share a /24')
    control = dict(host=args.board_ip, host_ip=args.host_ip, interface=args.interface,
                   user='root', key=str(args.key.resolve()), known_hosts=str(args.pin.resolve()),
                   serial=str(args.serial), netmask='255.255.255.0', tftp_port=args.tftp_port)
    transfer = dict(control, host=args.transfer_board_ip, host_ip=args.transfer_host_ip,
                    interface=args.transfer_interface)
    return control, transfer


def wait_ssh(device, live, timeout=30):
    deadline = time.monotonic() + timeout
    while True:
        try:
            require(device.run('printf PON_SSH_READY', 5) == b'PON_SSH_READY',
                    'unexpected SSH readiness reply')
            return
        except (live.LiveError, subprocess.TimeoutExpired):
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


def boot(args, data, digest, control, transfer):
    sys.path.insert(0, str(args.toolkit.resolve()))
    spec = importlib.util.spec_from_file_location('pon_recovery_live', args.toolkit / 'live.py')
    live = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = live
    spec.loader.exec_module(live)
    recording = live.Recording(args.output)
    console = server = None
    try:
        recording.save('control-host.txt', live.host_snapshot(control))
        recording.save('transfer-host.txt', live.host_snapshot(transfer))
        device = live.Device(control)
        guard = ('set -e; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + args.previous_boot +
                 '; test "$(cat /tmp/sysinfo/board_name)" = fiberhome,hg5585f-ct; '
                 'test "$(uname -r)" = 6.18.60; '
                 'cat /proc/sys/kernel/random/boot_id /proc/mtd; ip -4 -o addr show dev lan4')
        before = device.run(guard, 10)
        require(re.search(rb'\binet ' + re.escape(transfer['host'].encode()) + rb'/24\b', before),
                'transfer board address is absent')
        recording.save('device-before.txt', before)
        console = live.SerialConsole(control['serial'], recording)
        console.write(b'\r')
        console.read(0.5)
        console.write(b"\x15printf '%s%s\\n' PON_FULL_UART_ READY\r")
        reply = console.read(2)
        require(re.search(rb'(?m)^PON_FULL_UART_READY\r?$', live.visible(reply)),
                'serial communication unavailable')
        server = live.start_tftp(transfer, {'name': args.fit.name}, data, recording, 240)
        live.enter_uboot(console, device, recording)
        live.uboot_command(console, 'setenv ipaddr ' + transfer['host'])
        live.uboot_command(console, 'setenv netmask ' + transfer['netmask'])
        reply = live.uboot_command(console, 'tftpboot 0x90000000 ' +
                                   transfer['host_ip'] + ':' + str(transfer['tftp_port']) +
                                   ':' + args.fit.name, 150)
        require(server.finished.wait(5) and server.result and not server.error and
                f'Bytes transferred = {len(data)} '.encode() in reply, 'incomplete recovery transfer')
        reply = live.uboot_command(console, f'hash sha256 0x90000000 0x{len(data):x}', 30)
        require(live.serial_hash_matches(reply, digest), 'board RAM digest mismatch')
        console.write(b'\x15bootm 0x90000000\r')
        deadline, last_enter, output = time.monotonic() + 150, time.monotonic(), bytearray()
        while time.monotonic() < deadline:
            output.extend(console.read(0.3))
            visible = live.visible(output[-65536:])
            require(b'Kernel panic' not in visible and not live.has_prompt(visible), 'recovery boot failed')
            if re.search(rb'(?m)^root@[^\r\n#>]*#', visible):
                break
            if time.monotonic() - last_enter >= 3:
                console.write(b'\r')
                last_enter = time.monotonic()
        else:
            raise RuntimeError('recovery shell timeout')
        keys = []
        for attempt in range(10):
            console.write(b'\x03\x15\r')
            console.read(0.3)
            console.write(b'\x15test "$(uname -r)" = 6.18.60 && '
                          b'test "$(tr -d "\\0" </proc/device-tree/variant)" = pon-full && '
                          b'grep -q "^tmpfs / tmpfs " /proc/mounts && '
                          b'dropbearkey -y -f /etc/dropbear/dropbear_ed25519_host_key\r')
            reply = console.read(2)
            keys = re.findall(rb'(?m)^ssh-ed25519 (AAAA[A-Za-z0-9+/=]+) ', reply)
            if len(keys) == 1:
                break
        require(len(keys) == 1, 'recovery identity or tmpfs root check failed')
        pin = args.output / 'known-hosts'
        pin.write_bytes(control['host'].encode() + b' ssh-ed25519 ' + keys[0] + b'\n')
        pin.chmod(0o600)
        trial = live.Device(dict(control, known_hosts=str(pin.resolve())))
        wait_ssh(trial, live)
        after = trial.run('set -e; test "$(tr -d "\\0" </proc/device-tree/variant)" = pon-full; '
                          'grep -q "^tmpfs / tmpfs " /proc/mounts; '
                          'cat /proc/sys/kernel/random/boot_id /proc/mtd; '
                          'cat /etc/hg5585f-ct-build.json; '
                          'cat /sys/kernel/debug/ppe/config; '
                          'cat /sys/bus/platform/devices/1fa03000.wireless-offload/status; '
                          'ip -4 addr; iw dev', 20)
        recording.save('device-after.txt', after)
        current = trial.run('cat /proc/sys/kernel/random/boot_id', 5).decode().strip()
        require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', current) and
                current != args.previous_boot, 'invalid or unchanged boot identity')
        return dict(recovery_ready=True, boot_id=current, pin=str(pin.resolve()), fit_sha256=digest,
                    flashed=False, toolkit_sha256=hashlib.sha256((args.toolkit / 'live.py').read_bytes()).hexdigest())
    except Exception as error:
        recording.state(dict(recovery_ready=False, flashed=False, fit_sha256=digest,
                             error=str(error)))
        raise
    finally:
        if server:
            server.stop()
            server.join(3)
        if console:
            console.close()
        recording.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fit', 'evidence', 'key', 'pin', 'toolkit', 'serial', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--previous-boot', required=True)
    parser.add_argument('--board-ip', default='192.168.1.1')
    parser.add_argument('--host-ip', default='192.168.1.120')
    parser.add_argument('--interface', default='en6')
    parser.add_argument('--transfer-board-ip', default='192.168.6.221')
    parser.add_argument('--transfer-host-ip', default='192.168.6.231')
    parser.add_argument('--transfer-interface', default='en4')
    parser.add_argument('--tftp-port', type=int, default=1069)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    data, digest = preflight(args.fit, args.evidence)
    control, transfer = config(args)
    result = dict(fit_sha256=digest, bytes=len(data), previous_boot=args.previous_boot,
                  transfer_host=transfer['host_ip'], transfer_board=transfer['host'], flashed=False)
    if args.run:
        result.update(boot(args, data, digest, control, transfer))
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
