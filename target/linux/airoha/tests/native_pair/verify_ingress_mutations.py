#!/usr/bin/env python3
import argparse, concurrent.futures, json, shutil, signal, subprocess
from pathlib import Path
r=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
p.add_argument('--kernel',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();source=a.kernel.resolve();output=a.output.resolve();output.mkdir(parents=True,exist_ok=False)
h=source/'drivers/net/ethernet/airoha'
cases=[
('no_source_mask','airoha_ct_ifc_cpu.h','words[0] = words[1] = XSI_ETH_VIP_PORT_MASK;','words[0] = XSI_ETH_VIP_PORT_MASK; words[1] = 0;','ifc'),
('no_type_mask','airoha_ct_ifc_cpu.h','words[1] = CT_IFC_TCAM_TYPE_MASK;','words[1] = 0;','ifc'),
('wrong_vlan_bit','airoha_ct_ifc_cpu.h','{ BIT(5), BIT(4), BIT(10) }','{ BIT(6), BIT(4), BIT(10) }','ifc'),
('missing_etype_cube','airoha_ct_ifc_cpu.h','{ 0x0002, 0x0002 }','{ 0x0002, 0xffff }','ifc'),
('ip_cpu_overlap','airoha_ct_ifc_cpu.h','{ 0x0002, 0x0002 }','{ 0x0800, 0xffff }','ifc'),
('wrong_cpu_action','airoha_ct_ifc_cpu.h','CT_IFC_ACTION_FORCE_CPU }','0 }','ifc'),
('missing_tcam_dirty','airoha_ct_ifc_cpu.h','rule->tcam_dirty |= BIT(page);','rule->tcam_dirty |= 0;','ifc'),
('lost_restore_shadow','airoha_ct_ifc_cpu.h','else\n\t\t\t\trule->tcam_dirty &= ~BIT(page);','/* lost error shadow */\n\t\t\trule->tcam_dirty &= ~BIT(page);','ifc'),
('skip_cpu_restore','airoha_ct_ifc.h','err = ct_ifc_cpu_stop(ppe);','err = 0;','ifc'),
('wrong_qdma_map','airoha_ct_ifc.h','!ct_ifc_cpu_port_matches(eth)','false','ifc'),
('no_gate_readback','airoha_ct_cpu_fallback.h','if (airoha_fe_rr(eth, REG_FE_CSR_IFC_CFG) & FE_IFC_EN_MASK)\n\t\t\terr = -EIO;','if (false)\n\t\t\terr = -EIO;','native'),
('no_gate_close','airoha_ct_cpu_fallback.h','\t\tairoha_fe_clear(eth, REG_FE_CSR_IFC_CFG, FE_IFC_EN_MASK);','\t\t/* missing close */','native'),
('no_gate_worker','airoha_ct_cpu_fallback.h','schedule_delayed_work(&eth->ppe->ct_fe.health_work, 0);','(void)eth;','native'),
('late_map_close','airoha_eth.c','err = airoha_ct_ifc_cpu_port_change(eth, src_port);','err = 0;','source-audit'),
('ignore_qdma_close_error','airoha_eth.c','\t\tif (err)\n\t\t\treturn err;\n\t}\n\n\tif (cur_qdma) {','\t\t(void)err;\n\t}\n\n\tif (cur_qdma) {','source-audit'),
('ignore_migration_latch','airoha_ct_native_pair.h','READ_ONCE(ppe->eth->ct_ifc_cpu_port_failed) && !ppe->ct_pair_failed','false && !ppe->ct_pair_failed','native'),
('scope_no_expected_owner','airoha_eth.c','if (eth->ct_ifc_port_mask != expected) {','if (false) {','ifc'),
('scope_no_pon_authorization','airoha_eth.c','if ((scope & BIT(AIROHA_GDM2_IDX)) && !eth->ct_ifc_pon_ready) {','if (false) {','ifc'),
('scope_allow_foreign_port','airoha_eth.c','if (!(scope & XSI_ETH_VIP_PORT_MASK) || (scope & ~allowed))','if (!(scope & XSI_ETH_VIP_PORT_MASK))','ifc'),
('scope_no_active_gate','airoha_eth.c','!(airoha_fe_rr(eth, REG_FE_CSR_IFC_CFG) & FE_IFC_EN_MASK)) {','false) {','ifc'),
('scope_no_register_audit','airoha_eth.c','if (airoha_fe_rr(eth, REG_FE_IFC_PORT_EN) != previous) {','if (false) {','ifc'),
('scope_skip_rollback','airoha_eth.c','airoha_fe_wr(eth, REG_FE_IFC_PORT_EN, previous);','(void)previous;','ifc'),
('scope_lost_failure_latch','airoha_eth.c','WRITE_ONCE(eth->ct_ifc_cpu_port_failed, true);','WRITE_ONCE(eth->ct_ifc_cpu_port_failed, false);','ifc'),
('scope_no_sticky_fallback','airoha_eth.c','\t\tairoha_ct_cpu_fallback(eth);','\t\t(void)eth;','ifc'),
('scope_lost_recovery_retry','airoha_eth.c','schedule_delayed_work(&eth->ppe->ct_fe.health_work, 0);','(void)eth;','ifc'),
('scope_reversed_lock_order','airoha_eth.c','spin_lock_bh(&eth->ct_route_lock);\n\tspin_lock_bh(&eth->ifc_port_lock);','spin_lock_bh(&eth->ifc_port_lock);\n\tspin_lock_bh(&eth->ct_route_lock);','ifc'),
('scope_release_live_classifier','airoha_eth.c','(airoha_fe_rr(eth, REG_FE_CSR_IFC_CFG) & FE_IFC_EN_MASK)) {','false) {','ifc'),
('scope_discard_desired_ports','airoha_eth.c','eth->ifc_port_desired = ports;','eth->ifc_port_desired = ports & eth->ct_ifc_port_mask;','ifc'),
('lan_ports_accept_extra_ports','airoha_eth.c','airoha_fe_rr(eth, REG_FE_IFC_PORT_EN) == ports;','(airoha_fe_rr(eth, REG_FE_IFC_PORT_EN) & XSI_ETH_VIP_PORT_MASK) != 0;','ifc'),
('native_snapshot_skip_ports','airoha_ct_fe_native.h','if (!airoha_ifc_lan_ports_ready(ppe->eth))','if (false)','native'),
]
def run(c):
 name,file,old,new,which=c;d=output/name;d.mkdir(parents=True,exist_ok=True);k=d/'candidate';mh=k/'drivers/net/ethernet/airoha';shutil.copytree(h,mh,dirs_exist_ok=True)
 for n in ('include','net'):
  if not (k/n).exists():(k/n).symlink_to((source/n).resolve())
 p=mh/file;s=p.read_text();assert old in s,name;p.write_text(s.replace(old,new,1))
 if which=='ifc':cmd=['python3',str(r/'verify_ifc_cpu.py'),'--host',str(mh),'--output',str(d/'build')]
 else:cmd=['python3',str(r/'verify_ingress_native.py'),'--fixtures',str(r),'--kernel',str(k),'--header',str(mh/'airoha_ct_fe_native.h'),'--output',str(d/'build')]
 proc=subprocess.run(cmd,capture_output=True,text=True);(d/'run.log').write_text(proc.stdout+proc.stderr)
 status=d/'build/exit-status.json'
 if which=='source-audit':
  diagnostic='ValueError: substring not found' if name=='late_map_close' else "assert '\\n\\t\\tif (err)\\n\\t\\t\\treturn err;' in body_check"
  assert proc.returncode!=0 and diagnostic in proc.stderr and not status.exists(),(name,proc.stderr)
  assert 'CalledProcessError' not in proc.stderr and 'error: ' not in proc.stderr,(name,proc.stderr)
  return {'name':name,'source_audit_rejected':True,'test':which,'caught_runtime':False,
          'failure':proc.stderr.strip()}
 assert status.is_file(),(name,'no executed C test',proc.stderr)
 tested=json.loads(status.read_text());failure=(d/'build/stderr.txt').read_text()
 assert proc.returncode!=0 and tested['returncode']==-signal.SIGABRT,(name,'mutation survived',proc.stderr,failure)
 assert 'assert' in failure.lower() and 'failed' in failure.lower(),(name,failure)
 return {'name':name,'rejected':True,'test':which,'compile_passed':True,'caught_runtime':True,
         'returncode':tested['returncode'],'failure':failure.strip()}
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:out=list(ex.map(run,cases))
runtime=[result for result in out if result['caught_runtime']]
audits=[result for result in out if result.get('source_audit_rejected')]
assert len(runtime)+len(audits)==len(cases)
(output/'mutations.json').write_text(json.dumps({'passed':True,'runtime_mutations':runtime,'source_audit_mutations':audits},indent=2)+'\n')
print(json.dumps({'passed':True,'runtime_killed':len(runtime),'source_audit_rejected':len(audits)}))
