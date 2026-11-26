#!/usr/bin/env python3
"""Run unmodified production path, tuple reversal, action and PON selection code."""
import argparse, hashlib, json, re, shutil, subprocess
from pathlib import Path
from verify_metadata import function, structure

ROOT=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--ppe',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    files={n:(a.kernel/n).read_text() for n in ['net/netfilter/nf_flow_table_path.c','net/netfilter/nf_flow_table_core.c','net/netfilter/nf_flow_table_offload.c','include/net/netfilter/nf_flow_table.h']}
    ppe=a.ppe.read_text()
    maxline=re.search(r'^#define NF_FLOW_TABLE_ENCAP_MAX\s+\d+',files['include/net/netfilter/nf_flow_table.h'],re.M).group(0)
    (out/'encap_max.inc').write_text(maxline+'\n')
    code=structure(files['net/netfilter/nf_flow_table_path.c'],'nft_forward_info')
    for file,names in [('net/netfilter/nf_flow_table_path.c',['nft_dev_path_info','nft_dev_forward_path']),('net/netfilter/nf_flow_table_core.c',['flow_offload_fill_route']),('net/netfilter/nf_flow_table_offload.c',['nf_flow_rule_route_common'])]:
        code+='\n'.join(function(files[file],name) for name in names)
    code+='\n'.join(function(ppe,name) for name in ['airoha_ppe_pon_lookup_tag','airoha_ppe_pon_select_flow'])
    start=ppe.index('\t\tcase FLOW_ACTION_VLAN_PUSH:',ppe.index('static int airoha_ppe_flow_offload_replace'))
    end=ppe.index('\t\tdefault:',start)
    # Retain the exact three production action cases, changing only the wrapper.
    code+='\nstatic int project_production_actions(struct nf_flow_rule *r,struct airoha_flow_data *out) { struct airoha_flow_data data={}; for(unsigned i=0;i<r->count;i++){ const struct flow_action_entry *act=&r->actions[i]; switch(act->id) {\n'+ppe[start:end]+'default:return -EOPNOTSUPP;}}*out=data;return 0;}\n'
    if 'static bool airoha_ppe_ct_pon_encap_output(' in ppe:
        code+=function(ppe,'airoha_ppe_ct_pon_encap_output')
    start=ppe.index('\tif (eth->ppe->ct_host_ppe && !odev)', end)
    end=ppe.index('\n\tif (bridge) {', start)
    code+='\nstatic int project_output_gate(struct airoha_eth *eth, struct net_device *odev, bool bridge, int addr_type, struct flow_rule *rule, struct airoha_flow_data data) {\n'+ppe[start:end]+'return 0; }\n'
    path=out/'path_functions.inc';path.write_text(code)
    for name in ['path_stubs.h','path_runner.c']:shutil.copyfile(ROOT/name,out/name)
    results=[]
    def run(name,flags=()):
        exe=out/name
        cmd=['clang','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-Wno-enum-conversion','-O1',*flags,'-I'+str(out),str(out/'path_runner.c'),'-o',str(exe)]
        r=subprocess.run(cmd,text=True,capture_output=True);(out/(name+'.build.log')).write_text(r.stdout+r.stderr);r.check_returncode()
        r=subprocess.run([str(exe)],text=True,capture_output=True);(out/(name+'.log')).write_text(r.stdout+r.stderr)
        return r
    for name,flags in [('plain',()),('sanitized',('-fsanitize=address,undefined','-fno-omit-frame-pointer'))]:
        r=run(name,flags);r.check_returncode();results.append({'mode':name,'summary':r.stdout.splitlines()[-1]})
    mutations=[]
    try:
        for name,old,new in [('inner-select','data->vlan.hdr[0].id : AIROHA_PON_VID_ANY;','data->vlan.hdr[data->vlan.num - 1].id : AIROHA_PON_VID_ANY;'),('omit-reverse','i = route->tuple[dir].in.num_encaps - 1; i >= 0; i--','i = 0; i < route->tuple[dir].in.num_encaps; i++')]:
            assert old in code
            path.write_text(code.replace(old,new));r=run(name)
            assert r.returncode!=0,name
            mutations.append({'name':name,'detected':True,'returncode':r.returncode})
    finally:path.write_text(code)
    report={'passed':True,'production_source_sha256':{str(a.kernel/n):hashlib.sha256(t.encode()).hexdigest() for n,t in files.items()},'ppe_source':str(a.ppe),'ppe_sha256':hashlib.sha256(ppe.encode()).hexdigest(),'extracted_sha256':hashlib.sha256(code.encode()).hexdigest(),'results':results,'mutations':mutations,'stubs':'Device-path discovery, Ethernet MAC actions, dst lifetime and RCU; encapsulation path, reversal, action generation, action parsing, lookup and selector execute production C.'}
    (out/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
