#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,subprocess
r=Path(__file__).resolve().parent;b=r/'build';b.mkdir(exist_ok=True)
core=(r/'candidate/net/netfilter/core.c').read_text()
a=core.index('/* Serialize explicit authorizations against every nft transaction. */');z=core.index('EXPORT_SYMBOL_GPL(nf_native_pair_bpf_end);',a)+len('EXPORT_SYMBOL_GPL(nf_native_pair_bpf_end);')
(r/'nf_native_pair_core.inc').write_text(core[a:z]+'\n')
subprocess.run(['clang','-std=gnu11','-Wall','-Wextra','-Werror','-pthread','-fsanitize=address,undefined','-I'+str(r),str(r/'verify_policy_core.c'),'-o',str(b/'verify_policy_core')],check=True)
p=subprocess.run([str(b/'verify_policy_core')],capture_output=True,text=True,check=True);print(p.stdout)
(b/'policy-core-verification.json').write_text(json.dumps({'passed':True,'result':p.stdout,'sanitizers':['address','undefined'],'source_sha256':hashlib.sha256((r/'candidate/net/netfilter/core.c').read_bytes()).hexdigest()},indent=2)+'\n')
