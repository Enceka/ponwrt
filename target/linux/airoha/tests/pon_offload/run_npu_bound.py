import re

from lan_udp_receiver import ReceiverError, receiver
from prepare_npu_ram import require


def run_bound_matrix(remote, write, diag, probe, fields, check_session, check_packet,
                     service, row, host_ip, host_mac, cookie, report):
    prefix = 'service-' + str(service) + '-bound'
    observations = report.setdefault('bound_observations', [])
    with receiver(host_ip) as destination:
        write(prefix + '-install', diag, f'bind-lan1 {row} {host_ip} {host_mac}')
        state = fields(remote(prefix + '-installed', 'cat ' + diag))
        check_session(state, 1, True)
        require(state['bound_mode'] == '1' and int(state['bound_hash'], 16) == row and
                int(state['bound_service']) == service, 'bound session identity mismatch')
        entries = remote(prefix + '-entries', 'cat /sys/kernel/debug/ppe/entries')
        lines = [line for line in entries.splitlines()
                 if (match := re.match(r'^([0-9a-f]+)\s+BND\s+', line)) and
                 int(match[1], 16) == row]
        require(len(lines) == 1 and
                fields(lines[0]).get('orig') == '192.0.2.1:49152->192.0.2.2:49153' and
                fields(lines[0]).get('new') == f'192.0.2.1:49152->{host_ip}:49153',
                'bound row tuple mismatch')
        returned = 0
        alt_service = service ^ 1
        samples = [('ipv4', 0), ('ipv4', 1), ('ipv4', 2), ('ipv4', 3),
                   ('ipv4', 4), ('ipv6', 0), ('ipv4', None), ('ipv4', 'alt'), ('ipv4', 0)]
        for index, (kind, variant) in enumerate(samples):
            label = prefix + '-packet-' + str(index + 1)
            before = fields(remote(label + '-before', 'cat ' + probe + 'status'))
            matched = kind == 'ipv4' and variant == 0
            if variant is None:
                command = 'send-current ' + kind
            elif variant == 'alt':
                command = f'send-fixed-alt {kind} 0 rx'
            else:
                command = f'send-fixed {kind} {variant} ' + ('tx' if matched else 'rx')
            send_error = None
            try:
                write(label + '-send', probe + 'command', command)
            except Exception as error:
                send_error = repr(error)
            observed = remote(label + '-diag', 'cat ' + diag)
            received = remote(label + '-probe', 'cat ' + probe + 'status')
            state, packet = fields(observed), fields(received)
            sequence = int(before['sequence']) + 1
            sample = dict(service=service, sequence=sequence, kind=kind, variant=variant,
                          matched=matched, diag=state, probe=packet, send_error=send_error)
            observations.append(sample)
            try:
                sample['receiver'] = (destination.expect(sequence, cookie) if matched else
                                      destination.expect_silence())
            except ReceiverError as error:
                sample['receiver'] = error.report
                raise
            require(send_error is None, 'bound probe send failed: ' + str(send_error))
            check_session(state, 1, True)
            require(int(packet['sequence']) == sequence and packet['pending'] == '0' and
                    packet['error'] == '0', 'bound TX sequence or completion mismatch')
            require(packet['rx_data'] == before['rx_data'] and
                    packet['rx_delivered'] == before['rx_delivered'],
                    'bound packet unexpectedly reached QDMA CPU receive')
            if matched:
                require(int(state['consumed']) == int(state['packets']) == returned and
                        packet['received'] == before['received'],
                        'bound match unexpectedly reached host receive')
            else:
                returned += 1
                expected_service = alt_service if variant == 'alt' else service
                check_packet(observed, received, expected_service, returned, kind,
                             sequence - 1, 1, True)
        destination.expect_silence()
        after_entries = remote(prefix + '-entries-after', 'cat /sys/kernel/debug/ppe/entries')
        after_lines = [line for line in after_entries.splitlines()
                       if (match := re.match(r'^([0-9a-f]+)\s+BND\s+', line)) and
                       int(match[1], 16) == row]
        require(len(after_lines) == 1, 'bound row disappeared after forwarding matrix')
        report.setdefault('bound_final_entries', []).append(dict(service=service, row=row, line=after_lines[0]))
