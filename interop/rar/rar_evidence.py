"""Case 19c: the `authorization_evidence` authorization details type of draft-liu-oauth-authorization-evidence-01 (Alibaba, Cisco,
Okta; 23 June 2026), filled from case 13b's real approval, and what the draft's own checks and ours can each say.

Read for this: Sections 1, 1.2, 3.4 to 3.6, 7.1 and 8.1 to 8.6 of the draft's text. The authorization server is SYNTHETIC (the test key of
rar_token.py). The person's passkey signature is case 13b's; it is not re-verified here (case 13b's check did, with the Standard)."""
import hashlib, json, uuid
import rar as R
import rar_token as T


def evidence(view_text, signed_at, decision_id, key=T.KEY, kid=T.AS_KID, user_action='biometric_confirmation', ts=None):
    """Section 3.4/3.5: id, user_confirmation {displayed_content, user_action, timestamp}, as_signature (Section 3.6)."""
    ev = {'id': 'urn:uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'case-19c:' + decision_id)),
          'user_confirmation': {'displayed_content': view_text, 'user_action': user_action,
                                'timestamp': T.ts(signed_at) if ts is None else ts}}
    ev['as_signature'] = sign(ev, key, kid)
    return ev


def signing_input(ev):
    """Section 3.6: JCS of {id, user_confirmation} only; fields beyond those are not covered."""
    return R.jcs({'id': ev['id'], 'user_confirmation': ev['user_confirmation']})


def sign(ev, key, kid):
    h = T.b64(json.dumps({'alg': 'EdDSA', 'kid': kid}, separators=(',', ':')).encode())
    si = h + '.' + T.b64(signing_input(ev))
    return h + '..' + T.b64(key.sign(si.encode()))


def verify_as_signature(ev):
    try:
        h, empty, sig = ev['as_signature'].split('.')
        assert empty == ''
        T.KEY.public_key().verify(T.unb64(sig), (h + '.' + T.b64(signing_input(ev))).encode())
        return []
    except Exception:
        return ['as_signature does not verify']


def draft_checks(ev, token_iat):
    """Section 7.1, what a resource server MAY do: the AS signature, and the confirmation before or at token issuance."""
    p = verify_as_signature(ev)
    if ev['user_confirmation']['timestamp'] > token_iat:
        p.append('the confirmation is after the token was issued')
    return p


def person_binding(ev, approval, view_bytes):
    """Section 8.2 says deployments needing more SHOULD add user-side signatures or independent consent auditing. Ours: the text the AS
    says it displayed is the very text whose digest the person's signature covers, and the confirmation is not before the signature."""
    p = []
    shown = ev['user_confirmation']['displayed_content'].encode('utf-8')
    if hashlib.sha256(shown).hexdigest() != approval['shown_view_digest']:
        p.append('the displayed content is not the view the person signed')
    if hashlib.sha256(view_bytes).hexdigest() != approval['shown_view_digest']:
        p.append('the view held is not the one the approval names')
    if ev['user_confirmation']['timestamp'] < T.ts(approval['signed_at']):
        p.append('the AS records the confirmation before the person signed')
    return p
