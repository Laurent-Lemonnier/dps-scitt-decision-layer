#!/usr/bin/env python3
"""Case 19c: authorization_evidence (draft-liu-oauth-authorization-evidence-01) from case 13b's approval; seven cases."""
import copy, json, os, sys
import rar as R
import rar_token as T
import rar_evidence as E

sb, ap, mf = R.load()
view_bytes = open(os.path.join(R.CASE, 'signed', 'review-view.txt'), 'rb').read()
view = view_bytes.decode('utf-8')
iat = T.ts('2026-11-07T09:55:00Z')
dec = ap['decision_id']
rows = []


def row(name, what, ev, expect_draft_fail, expect_binding_fail, token_iat=None):
    d = E.draft_checks(ev, iat if token_iat is None else token_iat)
    b = E.person_binding(ev, ap, view_bytes)
    rows.append({'case': name, 'what': what, 'draft_checks': 'rejects' if d else 'accepts', 'draft_problems': d,
                 'person_binding': 'fails' if b else 'holds', 'binding_problems': b,
                 'as_expected': bool(d) == expect_draft_fail and bool(b) == expect_binding_fail})


good = E.evidence(view, ap['signed_at'], dec)
row('P3 evidence as the AS would issue it after the real approval', 'displayed_content = the view the person signed; timestamp = signed_at', good, False, False)
late = E.evidence(view, ap['signed_at'], dec, ts=T.ts(ap['signed_at']) + 840)
row('P4 same, confirmation recorded at the server\'s receipt time (14 min after signed_at, as in case 13b), token issued after it', 'the AS time differs from the person\'s signed_at; still after it; a token issued before the receipt would fail the draft\'s own check (see N15)', late, False, False, token_iat=T.ts(ap['signed_at']) + 900)
row('N12 AS fabricates a confirmation the person never gave', 'valid AS signature over a different text and a time with no signature of the person', E.evidence('Approve any action the agent proposes.', '2026-11-07T09:54:00Z', dec), False, True)
alt = copy.deepcopy(good); alt['user_confirmation']['displayed_content'] = 'Approve any action the agent proposes.'
row('N13 displayed_content altered after signing', 'the AS signature no longer matches', alt, True, True)
row('N14 AS signs another text than the one the person was shown', 'valid AS signature; the view digest the person signed names the real view', E.evidence(view + '\nAlso allowed: delete.', ap['signed_at'], dec), False, True)
row('N15 confirmation after the token was issued', 'timestamp one hour after iat', E.evidence(view, ap['signed_at'], dec, ts=iat + 3600), True, False)
row('N16 confirmation before the person signed', 'the AS records it five minutes before the signature', E.evidence(view, ap['signed_at'], dec, ts=T.ts(ap['signed_at']) - 300), False, True)

ok = all(r['as_expected'] for r in rows)
os.makedirs(os.path.join(R.HERE, 'out'), exist_ok=True)
json.dump({'draft': 'draft-liu-oauth-authorization-evidence-01', 'synthetic_authorization_server': T.AS_KID, 'cases': rows, 'all_as_expected': ok},
          open(os.path.join(R.HERE, 'out', 'evidence-cases.json'), 'w'), indent=2)
for r in rows:
    print('%-92s draft: %-8s person binding: %-6s %s' % (r['case'], r['draft_checks'], r['person_binding'], '' if r['as_expected'] else '<<< UNEXPECTED'))
print('%d/%d as expected' % (sum(r['as_expected'] for r in rows), len(rows)))
sys.exit(0 if ok else 1)
