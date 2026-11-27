#!/usr/bin/env python3
"""Run stock packet parsing and LUT predicates with bounded process-local memory."""
import argparse
from collections import Counter
from dataclasses import dataclass, replace
import hashlib
import ipaddress
import json
from pathlib import Path
import platform
import struct
import sys

import unicorn
from unicorn import UC_HOOK_MEM_READ

from stock_oracle import R
from verify_ifc_service import Classifier


SYMBOLS = {
    'skb_parser': 0x1bdf4,
    'ifc_get_value_by_field': 0x1c94c,
    'ifc_lut1_rule_parser': 0x1da84,
    'ifc_set_lut1_rules': 0x1261c,
    'ifc_set_field_LUT1_hit': 0x7a98,
}
FORMATS = {8: '>B', 16: '>H', 32: '>I'}


class PacketBounds(Exception):
    """The stock operation requested bytes outside the supplied linear frame."""


class PacketOracle(Classifier):
    arena, arena_size = 0x70000000, 0x4000

    def __init__(self, stock):
        super().__init__(stock)
        self.skb = self.DATA + 0x10000
        self.parsed = self.DATA + 0x11000
        self.rxmsg = self.DATA + 0x12000
        self.next_index = self.DATA + 0x13000
        self.packet_start = self.arena + 0x100
        self.packet_length = 0
        self.watch_packet = False
        self.reads = []
        self.skb_reads = []
        self.executed_instructions = 0
        self.cpu.mem_map(self.arena, self.arena_size)
        self.cpu.hook_add(UC_HOOK_MEM_READ, self._packet_read,
                          begin=self.arena, end=self.arena + self.arena_size - 1)
        self.cpu.hook_add(UC_HOOK_MEM_READ, self._skb_read,
                          begin=self.skb, end=self.skb + 511)
        self.put(self.names['gpIfcPriv'], '<Q', self.DATA + 0x14000)
        self.local_stubs[self.names['write_all_ifc_rule_to_hw']] = (
            'suppress_hardware_flush', lambda module: module.cpu.reg_write(R.UC_ARM64_REG_W0, 0))
        self.fixture_registers = {0xbfb50000: 0x91000000,
                                 0xbfb50040: 0x020000, 0xbfb50044: 1,
                                 0xbfb50f18: 0x8100, 0xbfb50220: 0x00110009}
        for name, offset in SYMBOLS.items():
            assert self.names[name] - self.text == offset, name

    def _check_read(self, address, size, origin):
        if not self.watch_packet or not self.arena <= address < self.arena + self.arena_size:
            return
        offset = address - self.packet_start
        within = 0 <= offset and offset + size <= self.packet_length
        self.reads.append(dict(offset=offset, size=size, within_frame=within,
                               pc=hex(self.cpu.reg_read(R.UC_ARM64_REG_PC) - self.text),
                               origin=origin))
        if not within:
            raise PacketBounds(self.reads[-1])

    def _packet_read(self, cpu, access, address, size, value, opaque):
        self._check_read(address, size, 'instruction')

    def _skb_read(self, cpu, access, address, size, value, opaque):
        if self.watch_packet:
            self.skb_reads.append((address - self.skb, size))

    def _hook(self, cpu, pc, size, opaque):
        self.executed_instructions += 1
        name, tail = self.calls.get(pc, ('', False))
        if name in ('memcpy', 'memset', 'memcmp'):
            self.instructions += 1
            self.stub_calls[name] += 1
            first = cpu.reg_read(R.UC_ARM64_REG_X0)
            second = cpu.reg_read(R.UC_ARM64_REG_X1)
            length = cpu.reg_read(R.UC_ARM64_REG_X2)
            assert length <= 4096, (name, length)
            if name == 'memset':
                cpu.mem_write(first, bytes([second & 255]) * length)
                result = first
            elif name == 'memcpy':
                self._check_read(second, length, name)
                cpu.mem_write(first, bytes(cpu.mem_read(second, length)))
                result = first
            else:
                self._check_read(first, length, name)
                self._check_read(second, length, name)
                left, right = bytes(cpu.mem_read(first, length)), bytes(cpu.mem_read(second, length))
                result = (left > right) - (left < right)
        elif name == 'get_frame_engine_data' and cpu.reg_read(R.UC_ARM64_REG_W0) in self.fixture_registers:
            self.instructions += 1
            self.stub_calls['fixture_register_read'] += 1
            result = self.fixture_registers[cpu.reg_read(R.UC_ARM64_REG_W0)]
        else:
            return super()._hook(cpu, pc, size, opaque)
        cpu.reg_write(R.UC_ARM64_REG_X0, result & ((1 << 64) - 1))
        cpu.reg_write(R.UC_ARM64_REG_PC, cpu.reg_read(R.UC_ARM64_REG_LR) if tail else pc + size)

    def parse(self, packet, service=0x2134, source=2, headroom=0):
        assert len(packet) < 4096 and headroom in (0, 128)
        self.watch_packet = False
        self.cpu.mem_write(self.arena, b'\xa5' * self.arena_size)
        self.packet_start = self.arena + 0x100 + headroom
        self.packet_length = len(packet)
        if packet:
            self.cpu.mem_write(self.packet_start, packet)
        self.cpu.mem_write(self.skb, bytes(512))
        self.put(self.skb + 0x180, '<QQ', self.packet_start - headroom, self.packet_start)
        self.put(self.rxmsg, '<III', service << 14, source << 21, 0)
        self.reads = []
        self.skb_reads = []
        self.watch_packet = True
        try:
            result = self.call('skb_parser', self.skb, self.parsed)
        except PacketBounds:
            return dict(status='bounds', return_value=None, reads=list(self.reads),
                        skb_reads=sorted(set(self.skb_reads)))
        finally:
            self.watch_packet = False
        return dict(status='returned', return_value=result, reads=list(self.reads),
                    skb_reads=sorted(set(self.skb_reads)),
                    flags=list(self.cpu.mem_read(self.parsed + 0x8c, 4)),
                    offsets=list(self.cpu.mem_read(self.parsed + 0x90, 3)),
                    parsed_hex=bytes(self.cpu.mem_read(self.parsed, 0x9c)).hex())

    def value(self, field):
        status = self.call('ifc_get_value_by_field', self.skb, self.rxmsg, self.parsed, field)
        return status, self.cpu.reg_read(R.UC_ARM64_REG_W1)

    def lut(self, index, field, value, width, end=1, operation=0, mask=None):
        if mask is None:
            mask = 0 if width == 32 else 65535
        result = self.call('ifc_set_lut1_rules', index, 1, end, field, operation, mask, 0, value)
        assert result == index + 1, (index, field, result)

    def lut_match(self, index):
        self.watch_packet = True
        try:
            result = self.call('ifc_lut1_rule_parser', self.skb, self.parsed,
                               self.rxmsg, index, self.next_index)
        finally:
            self.watch_packet = False
        assert result in (0, -1), result
        return result == 0

    def install(self, flow):
        self.rows.clear()
        self.cpu.mem_write(self.names['IFC_LUT1_Rule'], bytes(256))
        predicates = flow.predicates()
        for index, (field, offset, width, value) in enumerate(predicates):
            self.lut(index, field, value, width)
        self.lut(30, 32, 20, 16, operation=2, mask=57)
        self.lut(31, 33, 0, 16, operation=2, mask=17)
        assert self.get(self.names['IFC_LUT1_Rule'] + 30 * 8, '<II') == (0xc0a0, 0x00390014)
        assert self.get(self.names['IFC_LUT1_Rule'] + 31 * 8, '<II') == (0xc0a1, 0x00110000)
        tuple_bits = (1 << len(predicates)) - 1
        short_index = 30 if flow.family == 4 else 31
        for row, service in ((56, 0x2134), (57, 0xa134)):
            self.field(row, 'LUT1_hit', 0, 0)
            self.configure(row, service, flow.etype, False)
            self.field(row, 'LUT1_hit', tuple_bits, tuple_bits | (1 << short_index))
            self.force_cpu(row, 1, 2 if row == 56 else 4)
            assert self.rows[0, row, 4] == (tuple_bits, tuple_bits | (1 << short_index))
        return tuple_bits, short_index

    def classify(self, count, short_index):
        hits = 0
        for index in [*range(count), short_index]:
            if self.lut_match(index):
                hits |= 1 << index
        values = {}
        for field in (14, 22, 23):
            status, values[field] = self.value(field)
            assert status == 0, field
        vlan_count = self.get(self.parsed + 0x28, '<H')[0]
        pppoe = self.get(self.parsed + 0x8c, '<B')[0]
        encap = (int(vlan_count > 0) << 4) | (int(vlan_count > 1) << 5) | (pppoe << 10)
        accepted = [row for row in (56, 57) if self.matches(
            row, values[23], values[22], source=values[14], encap=encap, lut_hits=hits)]
        return dict(lut_hits=hits, rows=accepted, service=values[23], source=values[14],
                    etype=values[22], short_hit=bool(hits & (1 << short_index)))


@dataclass(frozen=True)
class Flow:
    family: int
    protocol: int
    source: bytes
    destination: bytes
    sport: int = 12345
    dport: int = 54321

    @property
    def etype(self):
        return 0x0800 if self.family == 4 else 0x86dd

    def predicates(self):
        if self.family == 4:
            result = [(4, 0x40, 32, int.from_bytes(self.source, 'big')),
                      (3, 0x44, 32, int.from_bytes(self.destination, 'big'))]
        else:
            result = [(12 - index, 0x50 + 4 * index, 32, value)
                      for index, value in enumerate(struct.unpack('>4I', self.source))]
            result += [(8 - index, 0x60 + 4 * index, 32, value)
                       for index, value in enumerate(struct.unpack('>4I', self.destination))]
        result += [(24 if self.family == 4 else 25, 0x3d if self.family == 4 else 0x4e,
                    8, self.protocol)]
        ports = 0x70 if self.protocol == 6 else 0x84
        return result + [(29, ports, 16, self.sport), (28, ports + 2, 16, self.dport)]

    def packet(self, fragment=0, extension=None, declared=None, payload=None):
        if payload is None:
            payload = b'IFC tuple oracle' * 3
        if self.protocol == 6:
            transport = struct.pack('>HHIIBBHHH', self.sport, self.dport, 1, 0, 0x50, 0x10, 4096, 0, 0)
            checksum_offset = 16
        else:
            transport = struct.pack('>HHHH', self.sport, self.dport, 8 + len(payload), 0)
            checksum_offset = 6
        transport += payload
        if self.family == 4:
            pseudo = self.source + self.destination + struct.pack('>BBH', 0, self.protocol, len(transport))
        else:
            pseudo = self.source + self.destination + struct.pack('>I3xB', len(transport), self.protocol)
        transport = bytearray(transport)
        struct.pack_into('>H', transport, checksum_offset, checksum(pseudo + transport) or 65535)
        if self.family == 4:
            length = 20 + len(transport) if declared is None else declared
            network = bytearray(struct.pack('>BBHHHBBH4s4s', 0x45, 0, length, 1, fragment,
                                            64, self.protocol, 0, self.source, self.destination))
            struct.pack_into('>H', network, 10, checksum(network))
        else:
            extra = b''
            if extension is not None:
                extra = struct.pack('>BBHI', self.protocol, 0, fragment, 1) if extension == 44 else bytes([self.protocol, 0]) + bytes(6)
            length = len(extra) + len(transport) if declared is None else declared
            network = struct.pack('>IHBB16s16s', 6 << 28, length,
                                  self.protocol if extension is None else extension, 64,
                                  self.source, self.destination) + extra
        return bytes.fromhex('020000000001020000000002') + struct.pack('>H', self.etype) + network + transport


def checksum(data):
    data = bytes(data) + bytes(len(data) % 2)
    total = sum(struct.unpack('>' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ordinary_admission(packet):
    """Candidate software admission reference, separate from stock parser behavior."""
    if len(packet) < 14:
        return 'short_ethernet'
    etype = int.from_bytes(packet[12:14], 'big')
    if etype == 0x0800:
        if len(packet) < 34:
            return 'short_ipv4'
        if packet[14] != 0x45:
            return 'ipv4_version_or_options'
        if int.from_bytes(packet[20:22], 'big') & 0x3fff:
            return 'ipv4_fragment'
        end = 14 + int.from_bytes(packet[16:18], 'big')
        layer4, protocol = 34, packet[23]
    elif etype == 0x86dd:
        if len(packet) < 54:
            return 'short_ipv6'
        if packet[14] >> 4 != 6:
            return 'ipv6_version'
        end = 54 + int.from_bytes(packet[18:20], 'big')
        layer4, protocol = 54, packet[20]
    else:
        return 'ether_type'
    if protocol not in (6, 17):
        return 'protocol_or_extension'
    minimum = 20 if protocol == 6 else 8
    if end > len(packet) or end < layer4 + minimum:
        return 'ip_length'
    if protocol == 6:
        header = (packet[layer4 + 12] >> 4) * 4
        if header < 20 or layer4 + header > end:
            return 'tcp_length'
    else:
        length = int.from_bytes(packet[layer4 + 4:layer4 + 6], 'big')
        if length < 8 or layer4 + length != end:
            return 'udp_length'
    return None


def flows():
    for family, source, destination in ((4, '10.17.34.51', '192.0.2.1'),
                                         (6, '2001:db8:1234:5678:9abc:def0:1234:5678',
                                          '2001:db8:8765:4321:fedc:ba98:7654:3210')):
        for protocol in (6, 17):
            yield Flow(family, protocol, ipaddress.ip_address(source).packed,
                       ipaddress.ip_address(destination).packed)


def parsed_header_cases(oracle):
    records = []
    for flow in flows():
        if flow.protocol != 17:
            continue
        predicates = flow.predicates()
        for chained in (False, True):
            oracle.cpu.mem_write(oracle.parsed, bytes(0x9c))
            oracle.put(oracle.parsed + (0x8d if flow.family == 4 else 0x8e), '<B', 1)
            oracle.cpu.mem_write(oracle.names['IFC_LUT1_Rule'], bytes(256))
            for index, (field, offset, width, value) in enumerate(predicates):
                oracle.put(oracle.parsed + offset, FORMATS[width], value)
                oracle.lut(index, field, value, width, end=int(not chained or index == len(predicates) - 1))
            def matches():
                return all(oracle.lut_match(index) for index in ([0] if chained else range(len(predicates))))
            assert matches(), (flow.family, chained)
            records.append(dict(family=flow.family, chained=chained, mutation=None, matched=True))
            for field, offset, width, value in predicates:
                for bit in range(width):
                    oracle.put(oracle.parsed + offset, FORMATS[width], value ^ (1 << bit))
                    assert not matches(), (flow.family, chained, field, bit)
                    records.append(dict(family=flow.family, chained=chained,
                                        mutation=dict(field=field, bit=bit), matched=False))
                oracle.put(oracle.parsed + offset, FORMATS[width], value)
    assert len(records) == 804, len(records)
    return records


def packet_cases(oracle):
    records = []
    configurations = []
    for flow in flows():
        tuple_bits, short_index = oracle.install(flow)
        predicates = flow.predicates()
        configurations.append(dict(
            family=flow.family, protocol=flow.protocol, predicates=predicates,
            tuple_bits=tuple_bits, short_index=short_index,
            lut_ram=[oracle.get(oracle.names['IFC_LUT1_Rule'] + index * 8, '<II')
                     for index in range(32)],
            tcam={row: [oracle.rows[0, row, page] for page in range(9)] for row in (56, 57)}))
        base = flow.packet()
        minimum = (34 if flow.family == 4 else 54) + (20 if flow.protocol == 6 else 8)
        cases = [('positive', base, 0x2134, 2, [56], None),
                 ('shared_tuple_other_service', base, 0xa134, 2, [57], None),
                 ('wrong_service', base, 0x2135, 2, [], None),
                 ('wrong_source_port', base, 0x2134, 24, [], None)]
        for attribute in ('source', 'destination'):
            original = getattr(flow, attribute)
            for bit in range(len(original) * 8):
                changed = (int.from_bytes(original, 'big') ^ (1 << bit)).to_bytes(len(original), 'big')
                packet = replace(flow, **{attribute: changed}).packet()
                cases.append((f'wrong_{attribute}_bit{bit}', packet, 0x2134, 2, [], None))
        for attribute in ('sport', 'dport'):
            for bit in range(16):
                packet = replace(flow, **{attribute: getattr(flow, attribute) ^ (1 << bit)}).packet()
                cases.append((f'wrong_{attribute}_bit{bit}', packet, 0x2134, 2, [], None))
        alternate = replace(flow, protocol=17 if flow.protocol == 6 else 6).packet()
        cases.append(('wrong_protocol', alternate, 0x2134, 2, [], None))
        if flow.family == 4:
            for fragment in (0x2000, 1, 0x2001, 0x1fff):
                fragment_packet = flow.packet(fragment=fragment, payload=bytes(44 if flow.protocol == 6 else 40))
                cases.append((f'fragment_{fragment:04x}', fragment_packet,
                              0x2134, 2, [56], 'ipv4_fragment'))
            cases.append(('dont_fragment', flow.packet(fragment=0x4000), 0x2134, 2, [56], None))
        else:
            for extension in (0, 43, 44, 60):
                for fragment in ((0, 1, 8) if extension == 44 else (0,)):
                    cases.append((f'extension_{extension}_{fragment}',
                                  flow.packet(extension=extension, fragment=fragment,
                                              payload=bytes(44 if flow.protocol == 6 else 40)),
                                  0x2134, 2, [], 'protocol_or_extension'))
        for declared in (0, 1, 17 if flow.family == 6 else 39):
            expected = [56] if flow.family == 4 and declared < 20 else []
            reason = 'udp_length' if flow.protocol == 17 and declared > (27 if flow.family == 4 else 7) else 'ip_length'
            cases.append((f'declared_short_{declared}', flow.packet(declared=declared),
                          0x2134, 2, expected, reason))
        for declared in ((57, 58) if flow.family == 4 else (17, 18)):
            payload_length = declared - (20 if flow.family == 4 else 0) - (20 if flow.protocol == 6 else 8)
            if payload_length >= 0:
                expected = [] if declared == (57 if flow.family == 4 else 17) else [56]
                cases.append((f'guard_boundary_{declared}', flow.packet(payload=bytes(payload_length)),
                              0x2134, 2, expected, None))
        cases.append(('declared_too_long', flow.packet(declared=4096), 0x2134, 2, [56], 'ip_length'))
        for length in range(len(base)):
            reason = ordinary_admission(base[:length])
            assert reason is not None
            cases.append((f'truncate_{length}', base[:length], 0x2134, 2,
                          None if length < minimum else [56], reason))
        for label, packet, service, source, expected_rows, reason in cases:
            policy = ordinary_admission(packet)
            assert policy == reason, (flow.family, flow.protocol, label, policy, reason)
            parsed = oracle.parse(packet, service, source)
            assert set(parsed['skb_reads']) <= {(0x180, 8), (0x188, 8), (0xae, 2), (0xb0, 2), (0xb2, 2)}
            record = dict(family=flow.family, protocol=flow.protocol, label=label,
                          packet_hex=packet.hex(), service=service, source=source,
                          candidate_admission_rejection=policy, parse=parsed)
            if expected_rows is None:
                assert parsed['status'] == 'bounds', record
                record['classification'] = None
            else:
                assert parsed['status'] == 'returned' and parsed['return_value'] == 0, record
                classification = oracle.classify(len(predicates), short_index)
                assert classification['rows'] == expected_rows, (record, classification, expected_rows)
                assert classification['service'] == service and classification['source'] == source
                assert classification['etype'] == flow.etype
                if label.startswith(('declared_short_', 'guard_boundary_')):
                    assert classification['lut_hits'] & tuple_bits == tuple_bits
                    assert classification['short_hit'] == (expected_rows == [])
                record['classification'] = classification
                record['lookup_reads'] = oracle.reads[len(parsed['reads']):]
                record['candidate_rows'] = classification['rows'] if policy is None else []
                if label == 'positive':
                    assert classification['lut_hits'] & tuple_bits == tuple_bits
                    for field, offset, width, value in predicates:
                        assert oracle.value(field) == (0, value), (field, value)
                    assert parsed['offsets'] == [0, 14, 34 if flow.family == 4 else 54]
            records.append(record)
        parsed = oracle.parse(base, headroom=128)
        assert parsed['status'] == 'returned' and parsed['return_value'] == 0
        classification = oracle.classify(len(predicates), short_index)
        assert classification['rows'] == [56]
        assert oracle.get(oracle.skb + 0xae, '<HHH') == (128 + minimum - (20 if flow.protocol == 6 else 8), 142, 128)
        records.append(dict(family=flow.family, protocol=flow.protocol, label='headroom_128',
                            packet_hex=base.hex(), service=0x2134, source=2, parse=parsed,
                            classification=classification, candidate_admission_rejection=None,
                            lookup_reads=oracle.reads[len(parsed['reads']):], candidate_rows=[56]))
        alternate_flow = replace(flow, dport=flow.dport ^ 0x8000)
        alternate_index = len(predicates)
        oracle.lut(alternate_index, 28, alternate_flow.dport, 16)
        alternate_bits = (tuple_bits & ~(1 << (alternate_index - 1))) | (1 << alternate_index)
        oracle.field(57, 'LUT1_hit', alternate_bits, alternate_bits | (1 << short_index))
        configurations[-1]['distinct_service_tuple'] = dict(
            alternate_index=alternate_index, alternate_dport=alternate_flow.dport,
            alternate_bits=alternate_bits, row57_page4=oracle.rows[0, 57, 4],
            lut_ram=oracle.get(oracle.names['IFC_LUT1_Rule'] + alternate_index * 8, '<II'))
        for service in (0x2134, 0xa134):
            for selected in (flow, alternate_flow):
                expected = [56] if service == 0x2134 and selected == flow else []
                if service == 0xa134 and selected == alternate_flow:
                    expected = [57]
                packet = selected.packet()
                parsed = oracle.parse(packet, service)
                assert parsed['status'] == 'returned' and parsed['return_value'] == 0
                classification = oracle.classify(len(predicates) + 1, short_index)
                assert classification['rows'] == expected, (service, selected, classification)
                records.append(dict(family=flow.family, protocol=flow.protocol,
                                    label=f'cross_service_{service:04x}_dport_{selected.dport}',
                                    packet_hex=packet.hex(), service=service, source=2, parse=parsed,
                                    classification=classification, candidate_admission_rejection=None,
                                    lookup_reads=oracle.reads[len(parsed['reads']):], candidate_rows=expected))
    assert len(records) == 1276, len(records)
    return records, configurations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error('Run without -O: assertions are the test checks')
    oracle = PacketOracle(args.stock_dir / 'ifc.ko')
    parsed_cases = parsed_header_cases(oracle)
    packets, configurations = packet_cases(oracle)
    sources = [Path(__file__), Path(__file__).with_name('stock_oracle.py'),
               Path(__file__).with_name('verify_ifc_service.py')]
    report = dict(passed=True, stock_sha256=oracle.sha256,
                  source_sha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
                  runtime=dict(python=sys.version, executable=sys.executable,
                               unicorn=unicorn.__version__, platform=platform.platform()),
                  entry_offsets={name: hex(offset) for name, offset in SYMBOLS.items()},
                  parsed_header_cases=len(parsed_cases), full_packet_cases=len(packets),
                  parse_outcomes=dict(Counter(case['parse']['status'] for case in packets)),
                  helper_calls=dict(oracle.stub_calls), instructions=oracle.executed_instructions,
                  fixture_registers={hex(address): hex(value) for address, value in oracle.fixture_registers.items()},
                  interfaces=dict(skb_parser='x0=skb, x1=156-byte parsed output',
                                  skb=dict(head='0x180', data='0x188', transport_header='0xae',
                                           network_header='0xb0', mac_header='0xb2'),
                                  lut_parser='x0=skb, x1=parsed, x2=RX message, w3=index, x4=next index output',
                                  field_getter='x0=skb, x1=RX message, x2=parsed, w3=field; w0=status, w1=low value'),
                  model_boundaries=[
                      'Stock skb_parser, isTPID, field getter, LUT setter/parser and TCAM setters execute original instructions.',
                      'memcpy/memset/memcmp and enumerated register reads use process-local adapters; hardware flush is suppressed.',
                      'Every stock frame read and memory-helper frame read is checked against the exact supplied frame length.',
                      'Type0 comparison uses Python masked-key comparison of stock-written nine TCAM pages.',
                      'LUT bitmap assigns one bit per independent END=1 predicate; silicon hit generation is not executed.',
                      'Candidate ordinary_admission is a separate software reference; stock raw matches remain visible.',
                      'RX service/source are explicit descriptor fixtures; this test exercises no optical producer or device.',
                  ])
    report['observations'] = dict(
        parser_required_frame_bytes={'ipv4_tcp': 54, 'ipv4_udp': 42, 'ipv6_tcp': 74, 'ipv6_udp': 62},
        type0_model_matches_excluded_packets=dict(Counter(
            case['candidate_admission_rejection'] for case in packets
            if case.get('classification') and case['classification']['rows']
            and case['candidate_admission_rejection'])),
        short_guard_ranges={'ipv4_total_length': [20, 57], 'ipv6_payload_length': [0, 17]},
        unresolved=['Hardware LUT-hit bitmap and TCAM execution',
                    'Hardware fragment/error/service-validity admission',
                    'Nonlinear skb, checksum validation, and IPv6 extension traversal'])
    assert report['parse_outcomes'] == {'returned': 1044, 'bounds': 232}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    (args.output / 'vectors.json').write_text(json.dumps(dict(configurations=configurations,
                                                             parsed_header=parsed_cases,
                                                             packets=packets), indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
