"""Case 19c: the `authorization_evidence` authorization details type of draft-liu-oauth-authorization-evidence-02 (Liu, Zhu, Krishnan,
Parecki; 2 November 2026), filled from case 13b's real approval, and what the draft's own checks and ours can each say.

Read for this: Sections 1, 4.1 to 4.5, 5.3, 7 and 9.2 to 9.7 of the draft's text (revision -02). An earlier version of this case was
written on -01 (23 June 2026), which signed only `id` and `user_confirmation`; -02 is a different design (see the README).
The authorization server is SYNTHETIC: a fixed-seed P-256 test key (ES256, which Section 4.5 makes mandatory to support). The
person's passkey signature is case 13b's; it is not re-verified here (case 13b's check did, with the Standard)."""
import base64, copy, hashlib, json, uuid
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
import rar as R
import rar_token as T

N = int('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16)
KEY = ec.derive_private_key(int.from_bytes(hashlib.sha256(b'case-19c synthetic authorization server ES256 key').digest(), 'big') % (N - 1) + 1, ec.SECP256R1())
KID = 'example-as-es256-test-key-1'
EXT = 'person_approval'          # an extension member (Section 4.5: covered by the signature; Section 9.5: where an attestation goes)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def digest_b64u(b):
    return b64u(hashlib.sha256(b).digest())


def bounds_object(details, authority_ref):
    """Section 7 step 4: the authorization details object whose identifier is authority_ref. Section 4.4: where more than one carries it
    the AS MUST NOT include authority_hash; here exactly one does, the run element."""
    found = [e for e in details if e.get('identifier') == authority_ref]
    return found


def disclosure_from_view(view_text, authority_ref):
    """Our mapping of the review view onto the structured disclosure (the draft leaves the content to the deployment): the first
    line is the summary, the other lines are notices. Reconstructing the text is `summary` + newline + the notices joined by newlines."""
    lines = view_text.rstrip('\n').split('\n')
    return {'summary': lines[0], 'authority_ref': authority_ref, 'notices': lines[1:], 'locale': 'en'}


def view_from_disclosure(d):
    return '\n'.join([d['summary']] + list(d.get('notices', []))) + '\n'


def evidence(view_text, signed_at, decision_id, details, person=None, ts=None, decision='approved', action='biometric_confirmation', key=KEY):
    """Section 5.3: disclosure, approval, id, authority_hash, content_hash, as_signature."""
    ref = details[0]['identifier']
    ev = {'id': 'urn:uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'case-19c-02:' + decision_id)),
          'approval': {'decision': decision, 'approver': 'urn:example:approver:pseudonym-17',
                       'disclosure': disclosure_from_view(view_text, ref), 'action': action,
                       'timestamp': T.ts(signed_at) if ts is None else ts}}
    objs = bounds_object(details, ref)
    if len(objs) == 1:
        ev['authority_hash'] = digest_b64u(R.jcs(objs[0]))
    if person is not None:
        ev[EXT] = person
    return finish(ev, key)


def signing_input(ev):
    return R.jcs({k: v for k, v in ev.items() if k not in ('as_signature', 'content_hash')})


def finish(ev, key=KEY):
    si = signing_input(ev)
    ev = dict(ev, content_hash=digest_b64u(si))
    h = b64u(json.dumps({'alg': 'ES256', 'typ': 'evidence+jws', 'kid': KID}, separators=(',', ':')).encode())
    r, s = decode_dss_signature(key.sign((h + '.' + b64u(si)).encode(), ec.ECDSA(hashes.SHA256())))
    ev['as_signature'] = h + '..' + b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
    return ev


def person_member(approval):
    """What we ask the AS to carry inside the signed record (Section 9.5 says an attestation MUST be inside it): pointers to the person's
    own signature, case 13b's `person_approval`."""
    return {'decision_id': approval['decision_id'], 'stage_id': approval['stage_id'], 'shown_view_digest': approval['shown_view_digest'],
            'approved_spec_digest': approval['approved_spec_digest']}


def draft_checks(ev, details, token_iat):
    """Section 7: signature (with typ), content_hash, authority_hash against the bounds object in the token, decision not after iat."""
    p = []
    try:
        h, empty, sig = ev['as_signature'].split('.')
        hdr = json.loads(T.unb64(h))
        assert empty == '' and hdr.get('typ') == 'evidence+jws' and hdr.get('alg') == 'ES256'
        raw = T.unb64(sig)
        KEY.public_key().verify(encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big')),
                                (h + '.' + b64u(signing_input(ev))).encode(), ec.ECDSA(hashes.SHA256()))
    except Exception:
        p.append('as_signature does not verify')
    if ev.get('content_hash') != digest_b64u(signing_input(ev)):
        p.append('content_hash does not match the signing input')
    if 'authority_hash' in ev:
        objs = bounds_object(details, ev['approval']['disclosure']['authority_ref'])
        if len(objs) != 1:
            p.append('no single bounds object carries the authority_ref')
        elif digest_b64u(R.jcs(objs[0])) != ev['authority_hash']:
            p.append('the bounds presented are not the bounds the AS witnessed')
    if ev['approval']['timestamp'] > token_iat:
        p.append('the decision is after the token was issued')
    return p


def person_binding(ev, approval, view_bytes):
    """Ours, on top of Section 9.4's advice to add approver-side signatures: the disclosure is the text whose digest the person's
    signature covers, the member names the person's signature, and the decision is not before it."""
    p = []
    shown = view_from_disclosure(ev['approval']['disclosure']).encode('utf-8')
    if hashlib.sha256(shown).hexdigest() != approval['shown_view_digest']:
        p.append('the disclosure is not the view the person signed')
    if hashlib.sha256(view_bytes).hexdigest() != approval['shown_view_digest']:
        p.append('the view held is not the one the approval names')
    if ev.get(EXT) != person_member(approval):
        p.append('the record does not carry the person\'s signature pointers')
    if ev['approval']['timestamp'] < T.ts(approval['signed_at']):
        p.append('the AS records the decision before the person signed')
    return p
