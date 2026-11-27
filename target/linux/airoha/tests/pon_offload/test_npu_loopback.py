#!/usr/bin/env python3
import struct
import unittest

from run_npu_loopback import check_packet


class PacketTests(unittest.TestCase):
    def fixture(self, service, kind, count=18):
        frame = bytearray(128)
        offset = 14 + (40 if kind == 'ipv6' else 20) + 8
        struct.pack_into('>5I', frame, offset, 0x4354504e, 41, 123, kind == 'ipv6', 128)
        desc = [0x80000080, 7, count, 2, 11, 0x80000000 | service, 0x44001000, 0,
                128, 0x00e00000 | service, 7, 0, 0x05dc7fff, 6 << 28, 2, 0]
        state = dict(owner=1, diagnostic=1, qualified=0, policy=0, fallback=0,
                     route_owner=1, fe_owner=1, ingress=1, phase=15,
                     error=0, invalidated=0, ring=1, auth_count=0, auth_enabled=1,
                     auth_inflight=0, gate_mask=4, gate_closed=0, gate_fault=0,
                     gate_error=0, auth_error=0, er_error=0, er_fault=0,
                     packets=count, consumed=count, dropped=0, fault=0,
                     flow='00000000', tb='83c0cfa4', scope='01000004', ports='01000004',
                     gdm2='07f08888', epoch=7, generation=11,
                     gate_epoch=7, gate_generation=11, auth_epoch=7, auth_generation=11,
                     er_desc='/'.join(f'{word:08x}' for word in desc), er_frame=frame.hex(),
                     observed_produced=count, observed_consumed=count, frame_bytes=128)
        packet = dict(sequence=41, rx_sequence=41, error=0, tx_kind=kind, rx_kind=kind, pending=0)
        return state, packet

    def render(self, values):
        return ' '.join(f'{name}={value}' for name, value in values.items())

    def test_services_and_families(self):
        for service in (0, 1, 32768, 65535):
            for kind in ('ipv4', 'ipv6'):
                state, packet = self.fixture(service, kind)
                result = check_packet(self.render(state), self.render(packet), service, 18, kind, 40)
                self.assertEqual(result['cookie'], 123)

    def test_protocol_and_identity_faults(self):
        state, packet = self.fixture(0, 'ipv4')
        faults = dict(qualified=1, policy=1, invalidated=1, auth_count=1, gate_mask=1,
                      route_owner=0, fe_owner=0, ingress=0, phase=14,
                      consumed=17, observed_produced=17, packets=17, dropped=1, fault=1,
                      flow='00003200', tb='83c0cfb4', scope='01000000', ports='01000000',
                      gdm2='07f05555', epoch=8, generation=12,
                      gate_epoch=8, gate_generation=12, auth_epoch=8, auth_generation=12)
        for name, value in faults.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                check_packet(self.render(dict(state, **{name: value})), self.render(packet), 0, 18, 'ipv4', 40)
        for index in (0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 13, 14):
            words = state['er_desc'].split('/')
            mask = 1 << 28 if index == 13 else 1
            words[index] = f'{int(words[index], 16) ^ mask:08x}'
            with self.subTest(index=index), self.assertRaises(ValueError):
                check_packet(self.render(dict(state, er_desc='/'.join(words))), self.render(packet), 0, 18, 'ipv4', 40)
        for byte in range(42, 62):
            frame = bytearray.fromhex(state['er_frame'])
            if 50 <= byte < 54:
                continue
            frame[byte] ^= 1
            with self.subTest(byte=byte), self.assertRaises(ValueError):
                check_packet(self.render(dict(state, er_frame=frame.hex())), self.render(packet), 0, 18, 'ipv4', 40)


if __name__ == '__main__':
    unittest.main()
