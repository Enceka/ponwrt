"""Exercise the actual WLAN station flush and epoch functions after fault cutover."""
from pathlib import Path
import hashlib,json,re,subprocess
r=Path(__file__).resolve().parent
source=(r/'candidate/drivers/net/ethernet/airoha/airoha_ppe.c').read_text()
def function(signature):
 a=source.index(signature);b=source.index('{',a);z=b+1;depth=1
 while depth:depth+=(source[z]=='{')-(source[z]=='}');z+=1
 return source[a:z]+'\n'
functions=''.join(function(s) for s in ('static u32 airoha_ppe_ct_epoch_locked(', 'u32 airoha_ppe_ct_wlan_epoch(', 'int airoha_ppe_ct_flush_wlan('))
(r/'build/station_functions.inc').write_text(functions)
(r/'build/verify_station_fallback.c').write_text((r/'verify_station_fallback.c').read_text())
subprocess.run(['clang','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(r/'build/verify_station_fallback.c'),'-o',str(r/'build/verify_station_fallback')],check=True)
p=subprocess.run([str(r/'build/verify_station_fallback')],capture_output=True,text=True,check=True)
report={'passed':True,'cases':int(re.search(r'PASS (\d+)',p.stdout).group(1)),'result':p.stdout.strip(),'source_sha256':hashlib.sha256(functions.encode()).hexdigest(),'sanitizers':['address','undefined']}
(r/'build/station-fallback-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(p.stdout,end='')
