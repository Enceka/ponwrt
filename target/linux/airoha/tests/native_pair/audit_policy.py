#!/usr/bin/env python3
"""Offline check of `nft -j list ruleset` for the RAM whole-MAC-IP contract.
Read sysfs generation before collecting this JSON, then write whole-mac-ip with
that same generation only after this check passes. Kernel rejects stale values.
The contract also requires no dynamic TC/XDP changes while enabled; write off
before changing those controls. This script does not write to the device.
"""
import argparse, hashlib, json
from pathlib import Path

def audit(doc):
 errors=[];chains={};bridge_rules=0
 entries=doc.get('nftables')
 if not isinstance(entries,list):return ['missing nftables list']
 for entry in entries:
  if not isinstance(entry,dict):errors.append('invalid entry');continue
  for kind,obj in entry.items():
   if kind=='metainfo':continue
   if not isinstance(obj,dict):errors.append('invalid '+kind);continue
   family=obj.get('family')
   if kind=='chain':
    chains[(family,obj.get('table'),obj.get('name'))]=obj
    if family=='netdev' or (family=='inet' and obj.get('hook')=='ingress'):
     errors.append('ingress/egress nft chain outside bridge contract')
   if family!='bridge':continue
   if kind=='table':
    if obj.get('flags'):errors.append('bridge table flags need removal')
   elif kind=='chain':
    if obj.get('policy','accept')!='accept':errors.append('bridge base policy must be accept')
    if obj.get('hook') not in (None,'forward'):errors.append('only bridge forward base chain supported')
   elif kind not in ('rule','flowtable'):
    errors.append('unsupported bridge object: '+kind)
 for entry in entries:
  obj=entry.get('rule') if isinstance(entry,dict) else None
  if not isinstance(obj,dict) or obj.get('family')!='bridge':continue
  bridge_rules+=1;flow_count=0
  chain=chains.get(('bridge',obj.get('table'),obj.get('chain')))
  if not chain or chain.get('hook')!='forward':errors.append('rule outside bridge forward base chain')
  for expr in obj.get('expr',[]):
   if not isinstance(expr,dict) or len(expr)!=1:errors.append('invalid bridge expression');continue
   kind,value=next(iter(expr.items()))
   if kind=='counter':continue
   if kind=='flow' and isinstance(value,dict) and value.get('op')=='add' and isinstance(value.get('flowtable'),str):flow_count+=1;continue
   if kind=='match' and isinstance(value,dict):
    right=value.get('right',{});allowed=right.get('set') if isinstance(right,dict) else None
    if value.get('op')=='==' and value.get('left')=={'meta':{'key':'l4proto'}} and isinstance(allowed,list) and set(allowed) in ({'tcp','udp'},{6,17}):continue
   errors.append('bridge expression can alter whole-pair policy: '+kind)
  if flow_count!=1:errors.append('bridge rule must only observe TCP/UDP and add one flow')
 return errors

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('ruleset',type=Path);args=parser.parse_args();data=args.ruleset.read_bytes();errors=audit(json.loads(data))
 print(json.dumps({'accepted':not errors,'contract':'whole-mac-ip','ruleset_sha256':hashlib.sha256(data).hexdigest(),'errors':errors},ensure_ascii=False,indent=2))
 raise SystemExit(bool(errors))
