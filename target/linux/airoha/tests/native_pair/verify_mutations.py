#!/usr/bin/env python3
"""Require successfully compiled safety mutations to fail runtime assertions."""
from pathlib import Path
import hashlib
import json
import shutil
import signal
import subprocess

root = Path(__file__).resolve().parent
build = root / 'build'
native = (build / 'airoha_ct_native_pair.h').read_text()
fe = (build / 'airoha_ct_fe_native.h').read_text()
stop = (build / 'fail_closed.inc').read_text()
cpu_build = build / 'cpu-fallback'
cpu = (cpu_build / 'airoha_ct_cpu_fallback.h').read_text()
extracted = (cpu_build / 'cpu_fallback_extracted.inc').read_text()
health_start = native.index('static void airoha_ct_fe_health_work(struct work_struct *work)\n{')
health_end = native.index('\nstatic bool airoha_ct_pair_key', health_start)
health = native[health_start:health_end]
quiesce = '\t\tairoha_ct_fe_quiesce(ppe, max(ppe->ct_fe.generation,\n\t\t\t\t\t     br_flow_offload_generation()));'
assert health.count(quiesce) == 1
mutations = {
    'ignore_wlan_gate_error': (build, 'fail_closed.inc', stop, stop.replace('if (err)\n\t\t\treturn err;', 'if (false)\n\t\t\treturn err;')),
    'omit_gate_worker_retry': (build, 'airoha_ct_native_pair.h', native, native.replace('!ppe->ct_fe.health_stopping && ppe->ct_pair_failed && !ppe->ct_pair_hw_stopped', 'false')),

    'omit_close_before_hardstop': (build, 'fail_closed.inc', stop, stop.replace('err = airoha_ct_pair_fault_close(ppe);', 'err = 0;')),
    'omit_flush_only_worker_retry': (build, 'airoha_ct_native_pair.h', native, native.replace('!ppe->ct_fe.health_stopping && ppe->ct_pair_failed && ppe->ct_pair_close_pending', 'false')),
    'omit_ppe_drain': (build, 'airoha_ct_fe_native.h', fe, fe[:fe.index('\nstatic int airoha_ct_fe_ppe_drain')] + '\nstatic int airoha_ct_fe_ppe_drain(struct airoha_ppe *ppe) { (void)ppe; return 0; }\n' + fe[fe.index('\nstatic int airoha_ct_fe_ppe_resume'):]),
    'ignore_ppe_busy': (build, 'airoha_ct_fe_native.h', fe, fe.replace('!(status & PPE_GLO_CFG_BUSY_MASK)', 'true')),
    'omit_all_native_flush': (build, 'airoha_ct_native_pair.h', native, native.replace('struct airoha_ct_pair_msg flush = { .op = cpu_to_le16(AIROHA_CT_PAIR_FLUSH) };', 'struct airoha_ct_pair_msg flush = { .op = cpu_to_le16(AIROHA_CT_PAIR_ENDPOINT_REVOKE) };')),
    'omit_fault_health_quiesce': (build, 'airoha_ct_native_pair.h', native, native[:health_start] + health.replace(quiesce, '\t\t(void)ppe;') + native[health_end:]),
    'allow_unarmed_lan_bind': (build, 'airoha_ct_native_pair.h', native, native.replace('(peer || !ppe->ct_fe.armed || !ppe->ct_fe.active ||', '(peer || !ppe->ct_fe.active ||')),
    'allow_drain_pending_arm': (build, 'airoha_ct_fe_native.h', fe, fe.replace('ppe->ct_fe.pending || ppe->ct_fe.drain_pending ||', 'ppe->ct_fe.pending ||')),
    'omit_cpu_cutover': (cpu_build, 'cpu_fallback_extracted.inc', extracted, extracted.replace('route_err = airoha_ct_cpu_fallback(eth);', 'route_err = 0;')),
    'allow_ifc_reenable': (cpu_build, 'cpu_fallback_extracted.inc', extracted, extracted.replace('reg == REG_FE_CSR_IFC_CFG && (value & mask & FE_IFC_EN_MASK) &&', 'reg == REG_FE_CSR_IFC_CFG && false &&')),
    'omit_late_route_retry': (cpu_build, 'airoha_ct_cpu_fallback.h', cpu, cpu.replace('schedule_delayed_work(&eth->ppe->ct_fe.health_work,\n\t\t\t\t\t      msecs_to_jiffies(100));', '(void)eth;')),
    'clear_sticky_latch_on_update': (cpu_build, 'airoha_ct_cpu_fallback.h', cpu, cpu.replace('\terr = airoha_ct_gdm_route_locked(eth, id, cfg);\nunlock:\n\tspin_unlock_bh', '\terr = airoha_ct_gdm_route_locked(eth, id, cfg);\n\teth->ct_cpu_fallback = false;\nunlock:\n\tspin_unlock_bh')),
    'omit_global_ifc_gate': (cpu_build, 'airoha_ct_cpu_fallback.h', cpu, cpu.replace('airoha_fe_clear(eth, REG_FE_CSR_IFC_CFG, FE_IFC_EN_MASK);', '(void)eth;')),
    'discard_fault_ifc_shadow': (cpu_build, 'cpu_fallback_extracted.inc', extracted, extracted.replace('\t\tppe->ct_fe.active = false;\n\t} else {', '\t\tppe->ct_fe.active = false;\n\t\tppe->ct_fe.touched = false;\n\t} else {')),
    'guess_qdma_cpu_port': (cpu_build, 'airoha_ct_cpu_fallback.h', cpu, cpu.replace('next = FE_PSE_PORT_CDM2;', 'next = FE_PSE_PORT_CDM1;')),
    'stop_bank_before_cpu_cutover': (cpu_build, 'cpu_fallback_extracted.inc', extracted, extracted.replace('\t/* Publish the software route before stopping its hardware consumers. */', '\tairoha_fe_wr(eth, REG_PPE_PPE_FLOW_CFG(0), 0);\n\t/* Publish the software route before stopping its hardware consumers. */')),
    'replace_pending_epoch': (cpu_build, 'cpu_fallback_extracted.inc', extracted, extracted.replace('if (!ppe->ct_fe.pending) {', 'if (true) {')),
}
results = []
for name, (source, filename, original, mutated) in mutations.items():
    assert original != mutated, name
    directory = build / 'mutations' / name
    directory.mkdir(parents=True, exist_ok=True)
    for path in source.iterdir():
        if path.suffix in ('.inc', '.h', '.c'):
            shutil.copyfile(path, directory / path.name)
    (directory / filename).write_text(mutated)
    command = ['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
               '-Wno-unused-function', '-fsanitize=address,undefined', '-I' + str(directory),
               str(directory / 'test.c'), '-o', str(directory / 'test')]
    compiled = subprocess.run(command, capture_output=True, text=True)
    (directory / 'compile.log').write_text(compiled.stdout + compiled.stderr)
    assert compiled.returncode == 0, (name, compiled.stderr)
    tested = subprocess.run([str(directory / 'test')], capture_output=True, text=True)
    (directory / 'stdout.txt').write_text(tested.stdout)
    (directory / 'stderr.txt').write_text(tested.stderr)
    assert tested.returncode == -signal.SIGABRT and 'assert' in tested.stderr.lower() and 'failed' in tested.stderr.lower(), (name, tested.returncode, tested.stderr)
    results.append(dict(mutation=name, harness='cpu-fallback' if source == cpu_build else 'source3',
                        compile_passed=True, caught_runtime=True, returncode=tested.returncode,
                        failure=tested.stderr.strip(), mutated_source_sha256=hashlib.sha256(mutated.encode()).hexdigest()))
    print(name, 'caught', flush=True)
report = dict(passed=True, mutations=results,
              baseline_report_sha256={name: hashlib.sha256((build / name).read_bytes()).hexdigest()
                                     for name in ('source3-verification.json', 'cpu-fallback-verification.json')})
(build / 'mutation-verification.json').write_text(json.dumps(report, indent=2) + '\n')
