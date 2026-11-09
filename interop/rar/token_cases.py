#!/usr/bin/env python3
"""Case 19b: nine tokens, each checked by a resource server (token alone) and by an auditor (token + signed specification + approval + run)."""
import copy, json, os, sys
import rar as R
import rar_token as T

sb, ap, mf = R.load()
spec = json.loads(sb)
full = R.project(spec)
sd = R.sha(sb)
iat = T.ts('2026-11-07T09:55:00Z'); exp = iat + 3600
now = T.ts('2026-11-07T09:55:30Z')
dec = ap['decision_id']
step1 = full[2]
rows = []


def row(name, what, tok, expect_rs, expect_audit, wanted=(step1['actions'][0], step1['identifier'])):
    rs = T.resource_server(tok, now, *wanted)
    au = T.auditor(tok, sb, ap, mf)
    af = sorted(k for k, v in au.items() if v)
    ok = (bool(rs) == expect_rs) and (af == sorted(expect_audit))
    rows.append({'case': name, 'what': what, 'resource_server': 'rejects' if rs else 'accepts', 'rs_problems': rs, 'auditor_fails': af, 'as_expected': ok})


good = T.issue(T.claims_for(T.enrich(full, sd), dec, iat, exp))
row('P2 token as issued after the approval, enriched with the approved digest', 'the details of case 19 plus the AS\'s link member', good, False, [])
row('TN1 token with the right details and no link', 'an AS that issued it without any person approval looks the same to a resource server',
    T.issue(T.claims_for(full, dec, iat, exp)), False, ['T3_link_to_approval'])
row('TN2 link to another specification', 'the link names a digest the person did not sign', T.issue(T.claims_for(T.enrich(full, 'f' * 64), dec, iat, exp)), False, ['T3_link_to_approval'])
row('TN3 issued before the approval', 'iat five minutes before the signature', T.issue(T.claims_for(T.enrich(full, sd), dec, T.ts(ap['signed_at']) - 300, T.ts(ap['signed_at']) - 300 + 3600)),
    False, ['T4_time'])
row('TN4 outlives valid_until', 'exp a day after the specification\'s valid_until', T.issue(T.claims_for(T.enrich(full, sd), dec, iat, T.ts(spec['valid_until']) + 86400)), False, ['T4_time'])
w = copy.deepcopy(full); w[3]['actions'].append('chat.message.delete')
row('TN5 widened details, valid AS signature', 'an AS (or its key) that grants more than was approved; the resource server is asked to delete',
    T.issue(T.claims_for(T.enrich(w, sd), dec, iat, exp)), False, ['T2_details_within_spec'], wanted=('chat.message.delete', w[3]['identifier']))
row('TN6 another audience', 'the token was issued for another resource server', T.issue(T.claims_for(T.enrich(full, sd), dec, iat, exp, aud='urn:example:rs:other')), True, [])
bad = good.rsplit('.', 1)[0] + '.' + T.b64(b'\x00' * 64)
row('TN7 tampered signature', 'the signature value replaced', bad, True, ['T1_as_signature'])
row('TN8 run outside the token\'s life', 'the token lived 45 seconds; the second step ended after it', T.issue(T.claims_for(T.enrich(full, sd), dec, iat, iat + 45)), False, ['T4_time'])

ok = all(r['as_expected'] for r in rows)
os.makedirs(os.path.join(R.HERE, 'out'), exist_ok=True)
json.dump({'synthetic_authorization_server': T.AS_KID, 'cases': rows, 'all_as_expected': ok}, open(os.path.join(R.HERE, 'out', 'token-cases.json'), 'w'), indent=2)
for r in rows:
    print('%-72s RS %-8s auditor fails: %-28s %s' % (r['case'], r['resource_server'], ','.join(r['auditor_fails']) or '-', '' if r['as_expected'] else '<<< UNEXPECTED'))
print('%d/%d as expected' % (sum(r['as_expected'] for r in rows), len(rows)))
sys.exit(0 if ok else 1)
