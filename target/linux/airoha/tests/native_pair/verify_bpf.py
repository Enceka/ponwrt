from pathlib import Path
import re,subprocess,json
r=Path(__file__).resolve().parent
names=[('net/core/dev.c','dev_xdp_attach'),('net/core/dev.c','bpf_xdp_link_update'),('kernel/bpf/tcx.c','tcx_prog_attach'),('kernel/bpf/tcx.c','tcx_link_attach'),('kernel/bpf/tcx.c','tcx_link_update')]
def func(path,name):
 s=(r/'candidate'/path).read_text();m=re.search(r'(?m)^(?:static )?int '+name+r'\(',s);assert m,name;a=m.start();o=s.index('{',a);z=o+1;d=1
 while d:d+=(s[z]=='{')-(s[z]=='}');z+=1
 return s[a:z]
pre='''#include <assert.h>\n#include <stdbool.h>\n#include <stdint.h>\n#include <errno.h>\n#include <stdio.h>\ntypedef uint32_t u32;\nstruct net_device{int unused;};struct netlink_ext_ack{int unused;};struct bpf_xdp_link{int unused;};struct bpf_prog{int unused;};struct bpf_link{int unused;};union bpf_attr{int unused;};\nstatic int err,calls,begins,ends;\nstatic int nf_native_pair_bpf_begin(void){begins++;return err;}\nstatic void nf_native_pair_bpf_end(void){ends++;}\n'''
functions=[]
for path,name in names:
 f=func(path,name);sig=f[:f.index('{')].replace(name+'(','__native_'+name+'(',1);pre+=sig+'{calls++;return 17;}\n';functions.append(f)
main='''int main(void){unsigned cases=0;struct net_device dev;struct netlink_ext_ack ack;struct bpf_xdp_link xl;struct bpf_prog p,old;struct bpf_link l;union bpf_attr a={0};\n'''
for call in ['dev_xdp_attach(&dev,&ack,&xl,&p,&old,0)','bpf_xdp_link_update(&l,&p,&old)','tcx_prog_attach(&a,&p)','tcx_link_attach(&a,&p)','tcx_link_update(&l,&p,&old)']:
 main+='for(int mode=0;mode<3;mode++){err=mode==0?0:mode==1?-EOPNOTSUPP:-EBUSY;calls=begins=ends=0;assert('+call+'==(err?err:17));assert(begins==1&&ends==!err&&calls==!err);cases++;}\n'
main+='err=-EOPNOTSUPP;calls=begins=ends=0;assert(dev_xdp_attach(&dev,&ack,0,0,&old,0)==17);assert(calls==1&&!begins&&!ends);cases++;printf("PASS %u actual XDP/TCX attach/update wrappers, RAM rejection, lock-busy and detach cases\\n",cases);}\n'
(r/'build/verify_bpf.c').write_text(pre+'\n'.join(functions)+main)
subprocess.run(['clang','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=address,undefined',str(r/'build/verify_bpf.c'),'-o',str(r/'build/verify_bpf')],check=True)
p=subprocess.run([str(r/'build/verify_bpf')],capture_output=True,text=True,check=True);print(p.stdout)
(r/'build/bpf-verification.json').write_text(json.dumps({'passed':True,'result':p.stdout,'sanitizers':['address','undefined']},indent=2)+'\n')
