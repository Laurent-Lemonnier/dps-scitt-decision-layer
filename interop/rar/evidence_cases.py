#!/usr/bin/env python3
"""Case 19c: authorization_evidence (draft-liu-oauth-authorization-evidence-02) from case 13b's approval; nine cases.
Three readers: the draft's own checks (Section 7), the person binding (ours), and the projection check of case 19 (details = what the
signed specification implies)."""
import copy, json, os, sys
import rar as R
import rar_token as T
import rar_evidence as E

sb, ap, mf = R.load()
spec = json.loads(sb)
view_bytes = open(os.path.join(R.CASE, 'signed', 'review-view.txt'), 'rb').read()
view = view_bytes.decode('utf-8')
iat = T.ts('2026-11-07T09:55:00Z')
good = R.project(spec)
person = E.person_member(ap)
rows = []


def row(name, what, ev, details=None, token_iat=None, expect=('accepts', 'holds', 'holds')):
    details = good if details is None else details
    d = E.draft_checks(ev, details, iat if token_iat is None else token_iat)
    b = E.person_binding(ev, ap, view_bytes)
    pr = [] if details == good else ['the details are not what the specification implies']
    got = ('rejects' if d else 'accepts', 'fails' if b else 'holds', 'fails' if pr else 'holds')
    rows.append({'case': name, 'what': what, 'draft_checks': got[0], 'draft_problems': d, 'person_binding': got[1], 'binding_problems': b,
                 'projection_check': got[2], 'as_expected': got == tuple(expect)})


ev = E.evidence(view, ap['signed_at'], ap['decision_id'], good, person=person)
row('P5 evidence as the AS would issue it after the real approval', 'disclosure = the view the person signed; authority_hash over the run element; the person\'s pointers inside the signed record', ev)
row('P6 decision recorded at the server\'s receipt time (14 min after signed_at), token issued after it', 'the AS time differs from the person\'s signed_at; still after it',
    E.evidence(view, ap['signed_at'], ap['decision_id'], good, person=person, ts=T.ts(ap['signed_at']) + 840), token_iat=T.ts(ap['signed_at']) + 900)
row('N17 AS fabricates an approval the person never gave', 'valid AS signature over another text, no pointers to a person\'s signature',
    E.evidence('Approve any action the agent proposes.', '2026-11-07T09:54:00Z', ap['decision_id'], good), expect=('accepts', 'fails', 'holds'))
row('N18 AS signs another text than the one the person was shown', 'pointers to the person\'s signature present; the disclosure has one more line',
    E.evidence(view + 'Also allowed: delete.\n', ap['signed_at'], ap['decision_id'], good, person=person), expect=('accepts', 'fails', 'holds'))
w = copy.deepcopy(good); w[0]['actions'].append('workflow.cancel')
row('N19 run element widened after the approval', 'the bounds object that authority_hash digests is not the one presented', ev, details=w, expect=('rejects', 'holds', 'fails'))
w2 = copy.deepcopy(good); w2[3]['actions'].append('chat.message.delete')
row('N20 a step element widened after the approval', 'authority_hash digests one object (Section 4.4: no digest over a set); the step elements are not committed', ev, details=w2, expect=('accepts', 'holds', 'fails'))
alt = copy.deepcopy(ev); alt['approval']['disclosure']['notices'] = alt['approval']['disclosure']['notices'][:-1]
row('N21 disclosure shortened after signing', 'the signature and content_hash no longer match', alt, expect=('rejects', 'fails', 'holds'))
row('N22 decision recorded before the person signed', 'five minutes before the signature', E.evidence(view, ap['signed_at'], ap['decision_id'], good, person=person, ts=T.ts(ap['signed_at']) - 300),
    expect=('accepts', 'fails', 'holds'))
row('N23 decision after the token was issued', 'one hour after iat', E.evidence(view, ap['signed_at'], ap['decision_id'], good, person=person, ts=iat + 3600), expect=('rejects', 'holds', 'holds'))

ok = all(r['as_expected'] for r in rows)
os.makedirs(os.path.join(R.HERE, 'out'), exist_ok=True)
json.dump({'draft': 'draft-liu-oauth-authorization-evidence-02', 'synthetic_authorization_server': E.KID, 'cases': rows, 'all_as_expected': ok},
          open(os.path.join(R.HERE, 'out', 'evidence-cases.json'), 'w'), indent=2)
for r in rows:
    print('%-100s draft %-8s binding %-6s projection %-6s %s' % (r['case'], r['draft_checks'], r['person_binding'], r['projection_check'], '' if r['as_expected'] else '<<< UNEXPECTED'))
print('%d/%d as expected' % (sum(r['as_expected'] for r in rows), len(rows)))
sys.exit(0 if ok else 1)
