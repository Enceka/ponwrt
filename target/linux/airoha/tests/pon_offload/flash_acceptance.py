"""Offline admission of a paired HG5585F CT build from a measured GDM2 run."""
import hashlib
import ipaddress
import json
import re
from uuid import UUID


MODES = ('gdm2-internal-mac-rx-loopback', 'pon-line')
FW_DIR = 'lib/firmware/airoha/hg5585f-ct/'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def integer(value, low, high=None):
    return type(value) is int and value >= low and (high is None or value <= high)


def check_ingress(sample, label):
    require(isinstance(sample, dict) and set(sample) in ({'fe_word6'}, {'qdma_msg1'}),
            label + 'need a probe-matched ingress descriptor')
    field, word = next(iter(sample.items()))
    shift = 0 if field == 'fe_word6' else 21
    require(integer(word, 0, 0xffffffff) and ((word >> shift) & 31) == 2,
            label + 'expected GDM2 SPORT 2')


def check_tuple(fields):
    require(isinstance(fields, list) and len(fields) == 5, 'expected IP five-tuple')
    src, dst, proto, sport, dport = fields
    require(isinstance(src, str) and isinstance(dst, str) and
            ipaddress.ip_address(src).version == ipaddress.ip_address(dst).version and
            proto in ('udp', 'tcp') and integer(sport, 1, 65535) and integer(dport, 1, 65535),
            'invalid IP five-tuple')


def check_measurements(run):
    require(run['board'] == 'fiberhome,hg5585f-ct' and run['mode'] in MODES,
            'expected real CT GDM2 internal MAC RX loopback or PON line')
    require(isinstance(run['boot_id'], str) and UUID(run['boot_id']).version == 4,
            'expected board boot_id')
    services, row, bank = run['services'], run['foe_row'], run['ppe_bank']
    require(isinstance(services, list) and len(services) == 3 and
            all(integer(service, 0, 65535) for service in services) and
            len(set(services)) == 3 and services[0] != 0, 'need distinct A/B/control service IDs and nonzero A')
    require(integer(row, 0, 8191) and integer(bank, 1, 1), 'expected bank 1 and bank-local A row')
    common_tuple = None
    for phase, expected_rows in [('bound', [row]), ('withdraw_a', [])]:
        sample = run[phase]
        require(integer(sample['ppe_bank'], 0) and sample['ppe_bank'] == bank, phase + ': PPE bank changed')
        observed = sample['bound_rows']
        require(isinstance(observed, list) and all(integer(row, 0) for row in observed)
                and observed == expected_rows, phase + ': unexpected FOE readback')
        windows = sample['windows']
        require(isinstance(windows, list) and len(windows) == 3, phase + ': need A/B/control probes')
        for index, window in enumerate(windows):
            label = f'{phase} service {services[index]}: '
            require(integer(window['service'], 0) and window['service'] == services[index],
                    label + 'wrong ingress service')
            check_ingress(window['ingress'], label)
            check_tuple(window['tuple'])
            if common_tuple is None:
                common_tuple = window['tuple']
            require(window['tuple'] == common_tuple, label + 'five-tuple changed')
            sent = window['sent']
            require(integer(sent, 1), label + 'empty probe window')
            accelerated = phase == 'bound' and index == 0
            require(integer(window['foe_hits'], 0) and window['foe_hits'] == (sent if accelerated else 0),
                    label + 'A row hits')
            received = window['receiver_rx']
            require(isinstance(received, list) and all(integer(count, 0) for count in received) and
                    received == [sent if index == 0 else 0, sent if index == 1 else 0], label + 'receiver_rx')
            require(integer(window['wan_cpu_rx'], 0) and window['wan_cpu_rx'] == (0 if accelerated else sent),
                    label + 'WAN CPU fallback count')


def check_acceptance(pair_path, record_path, recovery_path, sysupgrade_sha256):
    """sysupgrade_sha256 must already have been checked against the bytes to stage."""
    try:
        pair = json.loads(pair_path.read_bytes())
        run = json.loads(record_path.read_bytes())
        recovery_sha256 = hashlib.sha256(recovery_path.read_bytes()).hexdigest()
        require(recovery_sha256 == pair['recovery_sha256'] == run['boot_fit_sha256'],
                'tested recovery FIT mismatch')
        require(sysupgrade_sha256 == pair['sysupgrade_sha256'] == run['sysupgrade_sha256'],
                'paired sysupgrade FIT mismatch')
        require(isinstance(pair['sources'], dict) and pair['sources'] and
                pair['sources'] == run['sources'], 'tested build sources mismatch')
        for part in ('rv32', 'data'):
            name = f'npu_full_test_{part}.bin'
            digest = pair['firmware'][FW_DIR + name]
            require(re.fullmatch('[0-9a-f]{64}', digest) and digest == run['firmware'][name],
                    'tested firmware mismatch: ' + name)
        check_measurements(run)
        return run['mode']
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise ValueError(f'PON acceptance: {error}') from error
