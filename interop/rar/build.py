#!/usr/bin/env python3
"""Writes out/authorization-details.json and out/rar-reference.json from case 13b's signed specification; verifies. Exit 0 if all pass."""
import json, os, sys
import rar as R

sb, ap, mf = R.load()
spec = json.loads(sb)
rar = R.project(spec)
ref = R.reference(ap['decision_id'], ap['stage_id'], rar, sb)
out = os.path.join(R.HERE, 'out'); os.makedirs(out, exist_ok=True)
open(os.path.join(out, 'authorization-details.json'), 'w').write(json.dumps(rar, indent=2, ensure_ascii=False) + '\n')
open(os.path.join(out, 'rar-reference.json'), 'w').write(json.dumps(ref, indent=2) + '\n')
res = R.check(rar, ref, sb, ap, mf)
summary = {'case': '19', 'built_on': 'case 13b (the real passkey approval of 7 November 2026)',
           'authorization_details_elements': len(rar), 'reference': ref, 'layers': {k: ('pass' if not v else v) for k, v in res.items()},
           'all_verified': all(not v for v in res.values())}
open(os.path.join(out, 'summary.json'), 'w').write(json.dumps(summary, indent=2) + '\n')
for k, v in res.items():
    print('%-24s %s' % (k, 'pass' if not v else 'FAIL ' + '; '.join(v)))
print('all_verified:', summary['all_verified'])
sys.exit(0 if summary['all_verified'] else 1)
