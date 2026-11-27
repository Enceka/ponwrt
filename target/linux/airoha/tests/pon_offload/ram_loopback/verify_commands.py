import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_ifc_probe import function


def replace_once(source, before, after):
    assert source.count(before) == 1, before
    return source.replace(before, after, 1)


def generate(directory):
    tests = Path(__file__).resolve().parent
    source = (tests / 'ct_pon_loopback.c').read_text()
    fixture = (tests.parent / 'service0/loopback_test.c').read_text()
    fixture = fixture[:fixture.index('static int dev_queue_xmit(')]
    fixture = replace_once(fixture,
        'struct net_device { u8 dev_addr[6]; };',
        'struct net_device { u8 dev_addr[6]; bool running, carrier; };')
    fixture = replace_once(fixture,
        'struct airoha_gdm_dev { int pon_tx_pending; };',
        '''struct airoha_gdm_dev {
    int pon_tx_pending;
    struct airoha_eth *eth;
    struct airoha_pon_flow_table *pon_flow_table;
    bool pon_update_blocked;
    u32 pon_qdma_tag;
    struct { u32 last_rx_msg0, last_rx_msg1; } pon_stats;
};''')
    fixture = replace_once(fixture,
        'static void msleep(unsigned int milliseconds) { assert(milliseconds == 20); }\n', '')
    fixture = replace_once(fixture, '\tbegin_calls++;',
        '\tbegin_calls++;\n\tdevice.pon_update_blocked = true;')
    fixture = replace_once(fixture, '\tmapped_service = mapping_service;',
        '\tmapped_service = mapping_service;\n\tdevice.pon_update_blocked = false;\n'
        '\tfixture_mapping(mapping_service, mapping_enable);')
    fixture = replace_once(fixture, 'static int airoha_eth_pon_update_begin(',
        'static void fixture_mapping(unsigned int service, bool enable);\n\n'
        'static int airoha_eth_pon_update_begin(')
    enum = re.search(r'enum probe_kind \{.*?\n\};', source, re.S)
    assert enum
    constants = '\n'.join(re.findall(r'(?m)^#define PROBE_.*$', source))
    constants += '\n' + enum.group() + '\n'
    names = ['marker_offset', 'receive', 'write_verified', 'mapping', 'map_service',
             'mapping_current', 'restore', 'transmit', 'transmit_current', 'command_write']
    receiver = re.search(r'(?ms)^static rx_handler_result_t receive\(.*?^}', source)
    assert receiver
    production = ''.join(receiver.group() + '\n' if name == 'receive' else
                         function(source, name) for name in names)
    (directory / 'loopback_constants.inc').write_text(constants)
    (directory / 'loopback_fixture.inc').write_text(fixture)
    (directory / 'loopback_production.inc').write_text(production)
    (directory / 'command_test.c').write_text((tests / 'command_test.c').read_text())
    return source, production


def run(directory, name, sanitized=False, rejected=False):
    executable = directory / name
    command = ['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-parameter', '-Wno-unused-function', '-Wno-unused-variable',
               '-I', str(directory), str(directory / 'command_test.c'), '-o', str(executable)]
    if sanitized:
        command += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-fno-omit-frame-pointer']
    compiled = subprocess.run(command, text=True, capture_output=True)
    if compiled.returncode:
        raise RuntimeError(compiled.stdout + compiled.stderr)
    result = subprocess.run([str(executable)], text=True, capture_output=True)
    if rejected:
        assert result.returncode < 0 and 'assert' in result.stderr.lower(), (name, result)
        return {'name': name, 'rejected': True}
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    report = json.loads(result.stdout)
    assert report['passed']
    return {'name': name, **report}


def main():
    parser = argparse.ArgumentParser(description='Test actual RAM loopback command and RX functions locally')
    parser.parse_args()
    if not __debug__:
        parser.error('run without -O to retain assertions')
    with tempfile.TemporaryDirectory(prefix='pon-loopback-commands-') as temporary:
        directory = Path(temporary)
        source, production = generate(directory)
        reports = [run(directory, 'plain'), run(directory, 'sanitized', sanitized=True)]
        mutations = [
            ('map-owner', 'if (READ_ONCE(probe_dev->eth->ppe->ct_npu_owner))\n\t\treturn -EBUSY;',
             'if (false)\n\t\treturn -EBUSY;'),
            ('send-owner', 'if (READ_ONCE(probe_dev->eth->ppe->ct_npu_owner))\n\t\t\t\t\t\terr = -EBUSY;',
             'if (false)\n\t\t\t\t\t\terr = -EBUSY;'),
            ('restore-owner', 'if (READ_ONCE(eth->ppe->ct_npu_owner))\n\t\treturn -EBUSY;',
             'if (false)\n\t\treturn -EBUSY;'),
            ('mapping-service', 'table->entries[0].tag == tag',
             '!((table->entries[0].tag ^ tag) & ~AIROHA_PON_QDMA_GEM_MASK)'),
            ('mapping-count', 'table->count == 1', 'table->count >= 1'),
            ('rx-timeout', 'if (!err && READ_ONCE(received_sequence) != sequence)',
             'err = 0;\n\tif (false && READ_ONCE(received_sequence) != sequence)'),
        ]
        for name, before, after in mutations:
            (directory / 'loopback_production.inc').write_text(replace_once(production, before, after))
            reports.append(run(directory, name, rejected=True))
        print(json.dumps({'passed': True, 'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
                          'runs': reports}, indent=2))


if __name__ == '__main__':
    main()
