import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_ifc_probe import function


def replace_once(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after, 1)


def generate(headers, tests, output):
    selections = {
        'airoha_ct_ifc.h': ['ct_ifc_access'],
        'airoha_ct_fe_native.h': ['airoha_ct_fe_table', 'airoha_ct_fe_put'],
        'airoha_ct_cpu_fallback.h': [
            'airoha_ct_ifc_cpu_route_close_locked', 'airoha_ct_ifc_cpu_port_change',
            'airoha_ct_ppe_selectors', 'airoha_ct_cpu_selectors', 'airoha_ct_gdm_cpu_locked',
            'airoha_ct_gdm_route_write_locked', 'airoha_ct_gdm_route_locked',
            'airoha_gdm_fwd_cfg_update', 'airoha_ct_cpu_fallback'],
        'airoha_bank1_routes.h': [
            'airoha_bank1_scope_locked', 'airoha_bank1_routes_write_all',
            'airoha_bank1_routes_revoke_locked'],
        'airoha_eth.c': ['airoha_ifc_scope_update', 'airoha_ifc_lan_ports_ready',
                         'airoha_en7581_get_sport'],
    }
    complete = ['airoha_ct_pon_ifc_words.h', 'airoha_ct_pon_ifc_owner.h',
                'airoha_ct_ifc_command.h', 'airoha_ct_ifc_tuple_words.h',
                'airoha_ct_ifc_tuple_pool.h']
    sources = {name: (headers / name).read_text() for name in
               [*selections, *complete, 'airoha_ct_pon_ifc_cpu.h', 'airoha_eth.h']}
    optical = sources['airoha_ct_pon_ifc_cpu.h']
    selections['airoha_ct_pon_ifc_cpu.h'] = [name for name in re.findall(
        r'(?m)^static (?:int|bool|void|u32|ssize_t|struct \w+)\s+(\w+)\(', optical)
        if name not in ('ct_pon_cpu_probe_show', 'airoha_ct_pon_ifc_cpu_init',
                        'airoha_ct_pon_ifc_cpu_deinit')]
    constants = '\n'.join(re.findall(r'(?m)^#define CT_IFC_.*$', sources['airoha_ct_ifc.h']))
    constants += '\n#define PROBE_HAVE_TUPLE_POOL 1\n#define PROBE_HAVE_TUPLE 1\n'
    constants += '#define AIROHA_MAX_NUM_GDM_PORTS 4\n'
    for expression, name in (
        (r'static const struct \{\s*u16 udf, min, max;.*?ct_ifc_guard\[\] = \{.*?\n\};',
         'airoha_ct_ifc.h'),
        (r'static const u8 ct_ifc_action_words\[\] = .*?;', 'airoha_ct_ifc.h'),
        (r'enum\s*\{\s*HSGMII_LAN_7581_PCIE0_SRCPORT.*?\n\};', 'airoha_eth.h'),
        (r'enum\s*\{\s*FE_PSE_PORT_CDM1.*?\n\};', 'airoha_eth.h'),
    ):
        match = re.search(expression, sources[name], re.S)
        assert match, expression
        constants += match.group() + '\n'
    production = '#include "airoha_ct_ifc_command.h"\n'
    production += 'static int airoha_bank1_routes_revoke_locked(struct airoha_eth *eth);\n'
    production += ''.join(function(sources[name], selected)
                          for name, names in selections.items() for selected in names)
    legacy = (tests / 'verify_ifc_probe.c').read_text()
    bank1 = re.search(r'struct airoha_bank1_routes \{.*?\n\};',
                      sources['airoha_eth.h'], re.S)
    assert bank1
    legacy = replace_once(legacy, 'struct airoha_eth {', bank1.group() + '\nstruct airoha_eth {')
    legacy = replace_once(legacy, 'struct airoha_eth {\n',
                          'struct airoha_eth {\n\tstruct airoha_bank1_routes ct_bank1_routes;\n')
    legacy = replace_once(legacy, 'struct airoha_ppe {\n',
                          'struct airoha_ppe {\n\tvoid *ct_npu_owner;\n')
    legacy = replace_once(legacy,
        'assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, 0, 0) == -EINVAL);',
        'assert(airoha_ct_pon_ifc_cpu_set(&fixture.ppe, 0, UINT_MAX) == -EINVAL);')
    tuple_legacy = (tests / 'verify_ifc_probe_tuple.c').read_text()
    tuple_legacy = replace_once(tuple_legacy, '"tuple 0 0",', '"tuple 0 65537",')
    fixture = legacy[:legacy.index('static void lifecycle(void)')]
    fixture += function(legacy, 'store')
    fixture += function(tuple_legacy, 'tuple_original_lut')
    fixture += function(tuple_legacy, 'tuple_prepare')
    fixture += function(tuple_legacy, 'tuple_finish')
    (output / 'probe_constants.inc').write_text(constants)
    (output / 'probe_production.inc').write_text(production)
    (output / 'probe_fixture.inc').write_text(fixture)
    (output / 'legacy.c').write_text(legacy)
    (output / 'verify_ifc_probe_tuple.c').write_text(tuple_legacy)
    for name in complete:
        (output / name).write_text(sources[name])
    for name in ('service0_test.c', 'loopback_test.c'):
        (output / name).write_text((tests / 'service0' / name).read_text())
    loopback = (tests / 'ram_loopback/ct_pon_loopback.c').read_text()
    assert 'mapping(0, false)' in function(loopback, 'restore')
    assert 'mapping(0x2134, true)' in function(loopback, 'prepare')
    kind_enum = re.search(r'enum probe_kind \{.*?\n\};', loopback, re.S)
    assert kind_enum
    (output / 'loopback_constants.inc').write_text(
        '\n'.join(re.findall(r'(?m)^#define PROBE_.*$', loopback)) + '\n' + kind_enum.group() + '\n')
    (output / 'loopback_production.inc').write_text(
        function(loopback, 'mapping') + function(loopback, 'transmit'))
    hashes = {name: hashlib.sha256(text.encode()).hexdigest() for name, text in sources.items()}
    hashes['ram_loopback/ct_pon_loopback.c'] = hashlib.sha256(loopback.encode()).hexdigest()
    return production, hashes


def run(output, name, source, sanitized=False, arguments=(), expected_failure=False):
    executable = output / name
    command = ['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-parameter', '-Wno-unused-function', '-Wno-unused-variable',
               '-I', str(output), str(output / source), '-o', str(executable)]
    if sanitized:
        command += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-fno-omit-frame-pointer']
    (output / (name + '-compile.json')).write_text(json.dumps(command, indent=2) + '\n')
    compiled = subprocess.run(command, text=True, capture_output=True)
    (output / (name + '-compile.log')).write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError(f'{name}: compilation failed; see {name}-compile.log')
    result = subprocess.run([str(executable), *arguments], text=True, capture_output=True)
    (output / (name + '.stdout')).write_text(result.stdout)
    (output / (name + '.stderr')).write_text(result.stderr)
    if expected_failure:
        assert result.returncode < 0, (name, result.returncode, result.stderr)
        return {'name': name, 'rejected': True, 'returncode': result.returncode}
    if result.returncode:
        raise RuntimeError(f'{name}: execution failed; see {name}.stderr')
    data = json.loads(result.stdout)
    assert data['passed']
    return {'name': name, **data}


def main():
    parser = argparse.ArgumentParser(description='Exercise service0 in production CPU probe functions')
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error('run without -O to retain assertions')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    tests = Path(__file__).resolve().parents[1]
    headers = args.source.resolve() / 'drivers/net/ethernet/airoha'
    production, hashes = generate(headers, tests, output)
    results = []
    for mode in ('plain', 'sanitized'):
        for name, source, arguments in (
            ('service0', 'service0_test.c', ()),
            ('loopback', 'loopback_test.c', ()),
            ('legacy', 'legacy.c', ()),
            ('legacy-tuple', 'legacy.c', ('tuple',)),
        ):
            result = run(output, name + '-' + mode, source, mode == 'sanitized', arguments)
            results.append(result)
            print(json.dumps(result), flush=True)
    for index in range(4):
        assert {key: value for key, value in results[index].items() if key != 'name'} == {
            key: value for key, value in results[index + 4].items() if key != 'name'}
    mutations = [
        ('reject-zero-set', 'if (slot >= 2 || service > U16_MAX)',
         'if (slot >= 2 || (!cover && !service) || service > U16_MAX)'),
        ('reject-zero-tuple', 'if (slot || service > U16_MAX)',
         'if (slot || !service || service > U16_MAX)'),
        ('zero-check-sentinel', 'if (!ppe->ct_pon_ifc_tuple || (ppe->ct_pon_ifc.active & 3) != 3 ||',
         'if (!ppe->ct_pon_ifc_tuple || !ppe->ct_pon_ifc_services[0] ||'),
        ('cover-as-zero', '!cover && !(ppe->ct_pon_ifc_cover & BIT(slot ^ 1)) &&', '!cover &&'),
        ('ignore-owner', 'if (ppe->ct_npu_owner)\n\t\terr = -EBUSY;', 'if (false)\n\t\terr = -EBUSY;'),
    ]
    mutation_results = []
    for name, before, after in mutations:
        (output / 'probe_production.inc').write_text(replace_once(production, before, after))
        mutation_results.append(run(output, name, 'service0_test.c', expected_failure=True))
    (output / 'probe_production.inc').write_text(production)
    report = {'passed': True, 'source': str(args.source.resolve()), 'hashes': hashes,
              'runs': results, 'mutations': mutation_results,
              'legacy_adaptations': ['bank1 route and NPU owner fixture fields',
                                    'current production dependency and route functions',
                                    'zero rejection vectors replaced by out-of-range values']}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'report': str(output / 'report.json')}))


if __name__ == '__main__':
    main()
