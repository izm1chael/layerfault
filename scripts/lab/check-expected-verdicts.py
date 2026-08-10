#!/usr/bin/env python3
import csv,json,sys
from pathlib import Path
if len(sys.argv)!=3:
    raise SystemExit('usage: check-expected-verdicts.py EXPECTED.tsv OBSERVED.json')
expected={}
with open(sys.argv[1],newline='') as f:
    for row in csv.DictReader(f, delimiter='\t'):
        expected[(row['case'],row['operation'])]=row
observed=json.load(open(sys.argv[2]))
counts={k:0 for k in ['DETECTION_REGRESSION','FALSE_POSITIVE_CANDIDATE','EXPECTED_BLOCK','EXPECTED_WARN','RESOURCE_UNAVAILABLE','RUNTIME_UNAVAILABLE','TIMEOUT','INTEGRITY_ERROR','PASS']}
rows=[]
for item in observed:
    key=(item.get('case',''),item.get('operation','')); state=str(item.get('state','')).upper()
    exp=expected.get(key); classification='PASS'
    if state=='TIMEOUT': classification='TIMEOUT'
    elif state=='RUNTIME_UNAVAILABLE': classification='RUNTIME_UNAVAILABLE'
    elif state=='RESOURCE_UNAVAILABLE': classification='RESOURCE_UNAVAILABLE'
    elif state in {'INTEGRITY_ERROR','INTEGRITY_OR_ERROR'}: classification='INTEGRITY_ERROR'
    elif exp:
        acceptable={x.strip().upper() for x in exp['acceptable_states'].split(',') if x.strip()}
        expected_state=exp['expected_state'].upper()
        if state not in acceptable:
            if expected_state=='BLOCK' and state!='BLOCK': classification='DETECTION_REGRESSION'
            elif expected_state in {'PASS','WARN'} and state=='BLOCK': classification='FALSE_POSITIVE_CANDIDATE'
            else: classification='DETECTION_REGRESSION'
        elif state=='BLOCK': classification='EXPECTED_BLOCK'
        elif state=='WARN': classification='EXPECTED_WARN'
    rows.append({**item,'classification':classification})
    counts[classification]=counts.get(classification,0)+1
print(json.dumps({'summary':counts,'results':rows},indent=2,sort_keys=True))
if counts.get('DETECTION_REGRESSION',0): raise SystemExit(3)
