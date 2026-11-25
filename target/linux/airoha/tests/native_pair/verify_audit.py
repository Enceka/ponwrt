from audit_policy import audit
import copy,json
from pathlib import Path
base={'nftables':[{'metainfo':{}},{'table':{'family':'bridge','name':'fw4'}},{'chain':{'family':'bridge','table':'fw4','name':'forward','hook':'forward','policy':'accept'}},{'rule':{'family':'bridge','table':'fw4','chain':'forward','expr':[{'match':{'op':'==','left':{'meta':{'key':'l4proto'}},'right':{'set':['tcp','udp']}}},{'flow':{'op':'add','flowtable':'ft'}}]}}]}
assert not audit(base);cases=1
for kind in ['drop','reject','accept','jump','queue','mangle','limit','quota','ct','lookup','notrack','tproxy','dup']:
 d=copy.deepcopy(base);d['nftables'][-1]['rule']['expr'].append({kind:None});assert audit(d);cases+=1
for obj in [{'chain':{'family':'bridge','table':'fw4','name':'forward','hook':'forward','policy':'drop'}},{'set':{'family':'bridge'}},{'chain':{'family':'inet','hook':'ingress'}},{'chain':{'family':'netdev','hook':'egress'}},{'table':{'family':'bridge','flags':['owner']}}]:
 d=copy.deepcopy(base);d['nftables'].append(obj);assert audit(d);cases+=1
assert audit({});cases+=1
print(f'PASS {cases} concrete nft whole-MAC policy audit cases')
(Path(__file__).resolve().parent/'build/audit-verification.json').write_text(json.dumps({'passed':True,'cases':cases},indent=2)+'\n')
