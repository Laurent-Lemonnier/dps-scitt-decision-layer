#!/usr/bin/env python3
"""Nine failing cases. Each says which layer catches it and what the details alone (a resource server's view) would say."""
import copy, json, os, sys
import rar as R

sb, ap, mf = R.load()
spec = json.loads(sb)
good = R.project(spec)
cases = []


def case(name, what, rar=None, ref='recompute', spec_bytes=None, manifest=None, approval=None, expect=()):
    rar = copy.deepcopy(good) if rar is None else rar
    sbytes = sb if spec_bytes is None else spec_bytes
    r = R.reference(ap['decision_id'], ap['stage_id'], rar, sbytes) if ref == 'recompute' else ref
    res = R.check(rar, r, sb if spec_bytes is None else spec_bytes, approval or ap, manifest or mf)
    alone = R.rar_only(rar, manifest or mf)
    failed = sorted(k for k, v in res.items() if v)
    alone_failed = sorted(k for k, v in alone.items() if v)
    cases.append({'case': name, 'what': what, 'failed_layers': failed, 'details_alone_fails': alone_failed,
                  'as_expected': set(expect) == set(failed)})


w = copy.deepcopy(good); w[3]['actions'].append('chat.message.delete')
case('N1 widened actions', 'step 2 may also delete messages (RFC 9396 2.2: the permission is the product of the fields); reference recomputed', rar=w,
     expect=['V2_derived_from_spec'])
a = copy.deepcopy(good); a.append({'type': R.RAR_STEP, 'actions': ['crm.client.delete'], 'identifier': 'urn:example:crm:brokerage-1',
                                   'step_index': 3, 'parameters_digest': 'sha256:' + '0' * 64})
case('N2 extra step described', 'a delete is added to the details; reference recomputed', rar=a, expect=['V2_derived_from_spec', 'V4_execution_covered'])
n = copy.deepcopy(good); n.pop()
case('N3 narrowed details', 'the chat step is dropped from the details; the run still sent the message', rar=n,
     expect=['V2_derived_from_spec', 'V4_execution_covered'])
m = copy.deepcopy(mf); m['steps'][1]['target'] = 'urn:example:crm:other-brokerage'
case('N4 step ran elsewhere', 'the CRM step ran on another target than the one described', manifest=m, expect=['V4_execution_covered'])
m2 = copy.deepcopy(mf); m2['steps'].append({'index': 3, 'operation': 'crm.client.delete', 'target': 'urn:example:crm:brokerage-1'})
case('N5 step beyond the plan', 'a fourth step ran that no detail describes', manifest=m2, expect=['V4_execution_covered'])
case('N6 reference digest altered', 'the record carries the digest of other details', ref=dict(R.reference(ap['decision_id'], ap['stage_id'], good, sb),
     authorization_details_digest='sha256:' + 'f' * 64), expect=['V3_reference'])
s2 = json.loads(sb); s2['parameters']['steps'][1]['parameters']['segment'] = 'enterprise'
sb2 = R.jcs(s2)
case('N7 specification edited after approval', 'a parameter is changed; the details are projected from the edited plan and the reference follows',
     rar=R.project(s2), spec_bytes=sb2, expect=['V1_signed_spec'])
r8 = copy.deepcopy(good); r8[1], r8[2] = r8[2], r8[1]
case('N8 elements reordered', 'steps 0 and 1 swapped in the array; reference recomputed', rar=r8, expect=['V2_derived_from_spec'])
r9 = copy.deepcopy(good); del r9[1]['type']
case('N9 element without type', 'RFC 9396 Section 2: every element has a type', rar=r9,
     expect=['V2_derived_from_spec', 'V4_execution_covered', 'V5_rfc9396_shape'])

# Filtered views (RFC 9396 Sections 7, 9.1, 9.2, 13): what a resource server for one step may be given.
views = []
crm = [e for e in good if e['type'] == R.RAR_STEP and e['step_index'] == 1]
mcrm = dict(mf, steps=[s for s in mf['steps'] if s['index'] == 1])
views.append({'case': 'P1 view for the CRM server (one element, its part of the run)', 'subset_problems': R.is_filtered_view(crm, good),
              'covers_problems': R.covers(crm, mcrm, only_described=True), 'as_expected': not R.is_filtered_view(crm, good) and not R.covers(crm, mcrm, only_described=True)})
bad = copy.deepcopy(crm); bad[0]['actions'] = ['crm.client.create', 'crm.client.delete']
views.append({'case': 'N10 view that says more than the full details', 'subset_problems': R.is_filtered_view(bad, good),
              'covers_problems': R.covers(bad, mcrm, only_described=True), 'as_expected': bool(R.is_filtered_view(bad, good))})
foreign = [{'type': R.RAR_STEP, 'actions': ['crm.client.create'], 'identifier': 'urn:example:crm:brokerage-1', 'step_index': 1, 'parameters_digest': 'sha256:' + '1' * 64}]
views.append({'case': 'N11 view whose parameters digest is not the approved one', 'subset_problems': R.is_filtered_view(foreign, good),
              'covers_problems': R.covers(foreign, mcrm, only_described=True), 'as_expected': bool(R.is_filtered_view(foreign, good)) and not R.covers(foreign, mcrm, only_described=True)})
ok = all(c['as_expected'] for c in cases) and all(v['as_expected'] for v in views)
os.makedirs(os.path.join(R.HERE, 'out'), exist_ok=True)
json.dump({'cases': cases, 'filtered_views': views, 'all_as_expected': ok}, open(os.path.join(R.HERE, 'out', 'negatives.json'), 'w'), indent=2)
for c in cases:
    print('%-40s caught by %-60s details alone: %s %s' % (c['case'], ', '.join(c['failed_layers']),
          ', '.join(c['details_alone_fails']) or 'accepts', '' if c['as_expected'] else '<<< UNEXPECTED'))
for v in views:
    print('%-62s not a subset: %-4s covers: %s %s' % (v['case'], v['subset_problems'], v['covers_problems'] or 'ok', '' if v['as_expected'] else '<<< UNEXPECTED'))
print('%d/%d as expected' % (sum(c['as_expected'] for c in cases) + sum(v['as_expected'] for v in views), len(cases) + len(views)))
sys.exit(0 if ok else 1)
