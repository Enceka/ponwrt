"""Check plain GRE delivery and shared-route withdrawal in two Linux netns."""
import errno
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import uuid


def endpoint(mode, source, destination, label):
    payload = label.encode() + bytes(range(256))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(3)
        if mode in ('send', 'noroute'):
            udp.bind((source, 41001))
            try:
                udp.sendto(payload, (destination, 42002))
            except OSError as error:
                if mode == 'noroute' and error.errno == errno.ENETUNREACH:
                    return
                raise
            assert mode == 'send', 'withdrawn route still sends'
            return
        udp.bind((destination, 42002))
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as wire:
            wire.bind(('wire', 0))
            wire.settimeout(3)
            print('ready', flush=True)
            assert udp.recvfrom(2048) == (payload, (source, 41001))
            frame = wire.recv(2048)
            assert frame[12:14] == b'\x08\x00'
            outer = frame[14:]
            assert outer[0] == 0x45 and outer[8:10] == bytes([63, 47])
            outer_pair = ('192.0.2.2', '192.0.2.1') if destination.endswith('.1') else ('192.0.2.1', '192.0.2.2')
            assert outer[12:20] == b''.join(map(socket.inet_aton, outer_pair))
            assert outer[20:24] == b'\0\0\x08\0'
            inner = outer[24:]
            assert inner[0] == 0x45 and inner[9] == 17
            assert inner[12:20] == socket.inet_aton(source) + socket.inet_aton(destination)
            assert struct.unpack_from('!HHH', inner, 20) == (41001, 42002, len(payload) + 8)
            assert inner[28:] == payload


def main():
    prefix = 'gw-' + uuid.uuid4().hex[:10]
    left, right = prefix + 'a', prefix + 'b'
    created = []
    first, second, local = '198.51.100.2', '198.51.100.3', '198.51.100.1'

    def ip(*args):
        subprocess.run(['ip', *args], check=True)

    def command(ns, mode, source, dest, label):
        return ['ip', 'netns', 'exec', ns, sys.executable, str(Path(__file__).resolve()),
                mode, source, dest, label]

    def exchange(tx, rx, source, dest, label):
        proc = subprocess.Popen(command(rx, 'receive', source, dest, label), stdout=subprocess.PIPE)
        try:
            assert select.select([proc.stdout], [], [], 5)[0] and proc.stdout.readline() == b'ready\n'
            subprocess.run(command(tx, 'send', source, dest, label), check=True, timeout=5)
            assert proc.wait(timeout=5) == 0, label
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    try:
        for ns in (left, right):
            ip('netns', 'add', ns)
            created.append(ns)
            ip('-n', ns, 'link', 'set', 'lo', 'up')
        ip('-n', left, 'link', 'add', 'wire', 'type', 'veth', 'peer', 'name', 'wire', 'netns', right)
        for ns, address, peer in ((left, '192.0.2.1', '192.0.2.2'), (right, '192.0.2.2', '192.0.2.1')):
            ip('-n', ns, 'addr', 'add', address + '/30', 'dev', 'wire')
            ip('-n', ns, 'link', 'set', 'wire', 'up')
            ip('-n', ns, 'tunnel', 'add', 'gre1', 'mode', 'gre', 'local', address, 'remote', peer, 'ttl', '63')
            ip('-n', ns, 'link', 'set', 'gre1', 'up')
        for address in (local, first, second):
            ns, other = (left, right) if address == local else (right, left)
            ip('-n', ns, 'addr', 'add', address + '/32', 'dev', 'lo')
            ip('-n', other, 'route', 'add', address + '/32', 'dev', 'gre1')
        exchange(left, right, local, first, 'first')
        exchange(left, right, local, second, 'shared')
        exchange(right, left, second, local, 'reverse')
        ip('-n', left, 'route', 'del', first + '/32', 'dev', 'gre1')
        subprocess.run(command(left, 'noroute', local, first, 'withdrawn'), check=True, timeout=5)
        exchange(left, right, local, second, 'surviving')
        ip('-n', left, 'route', 'add', first + '/32', 'dev', 'gre1')
        exchange(left, right, local, first, 'restored')
        print(json.dumps(dict(verified_wire_and_udp=5, withdrawn_route_errno='ENETUNREACH')))
    finally:
        for ns in reversed(created):
            ip('netns', 'del', ns)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        main()
    else:
        endpoint(*sys.argv[1:])
