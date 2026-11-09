"""Case 19b: the same details carried in a JWT access token (RFC 9396 Section 9.1), as an authorization server would issue it,
and what a resource server and an auditor can each say about it.

The authorization server here is SYNTHETIC: a fixed-seed Ed25519 test key (JWS alg EdDSA, RFC 8037). No real AS issued this
token. The person's approval is case 13b's real passkey signature; the token is built after it, from the same specification."""
import base64, copy, datetime, hashlib, json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import rar as R

AS_ISSUER = 'https://as.example.test'
AS_KID = 'example-as-test-key-1'
AUD = 'urn:example:rs:brokerage-1'
SEED = hashlib.sha256(b'case-19b synthetic authorization server key').digest()
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
LINK = 'approved_spec_digest'        # type-specific member of the run element: the AS's enrichment (RFC 9396 Section 7.1)


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def unb64(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def ts(s):
    return int(datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp())


def enrich(details, spec_digest):
    out = copy.deepcopy(details)
    out[0][LINK] = spec_digest
    return out


def strip(details):
    out = copy.deepcopy(details)
    for e in out:
        e.pop(LINK, None)
    return out


def issue(claims, key=KEY):
    h = {'alg': 'EdDSA', 'typ': 'at+jwt', 'kid': AS_KID}
    si = b64(json.dumps(h, separators=(',', ':')).encode()) + '.' + b64(json.dumps(claims, sort_keys=True, separators=(',', ':')).encode())
    return si + '.' + b64(key.sign(si.encode()))


def claims_for(details, decision_id, iat, exp, aud=AUD):
    return {'iss': AS_ISSUER, 'sub': 'laurent-lemonnier', 'aud': aud, 'iat': iat, 'exp': exp, 'txn': decision_id,
            'authorization_details': details}


def parse(tok):
    h, p, s = tok.split('.')
    return json.loads(unb64(h)), json.loads(unb64(p)), h + '.' + p, unb64(s)


def resource_server(tok, now, wanted_action, wanted_identifier):
    """What a resource server does with the token alone (RFC 9396 Section 9.1): signature, audience, time, and that the
    action it is asked to perform on the resource is among the token's details."""
    p = []
    try:
        h, c, si, sig = parse(tok)
    except Exception:
        return ['not a JWT']
    try:
        KEY.public_key().verify(sig, si.encode())
    except InvalidSignature:
        p.append('signature does not verify under the authorization server key')
    if c.get('iss') != AS_ISSUER: p.append('issuer')
    if c.get('aud') != AUD: p.append('audience is not this resource server')
    if not (c.get('iat', 0) <= now < c.get('exp', 0)): p.append('token not valid at this time')
    if not any(wanted_action in e.get('actions', []) and e.get('identifier') == wanted_identifier for e in c.get('authorization_details', [])):
        p.append('no detail allows this action on this resource')
    return p


def auditor(tok, spec_bytes, approval, manifest):
    """What a later reader can say with the token, the signed specification, the approval record and the run."""
    out = {'T1_as_signature': [], 'T2_details_within_spec': [], 'T3_link_to_approval': [], 'T4_time': []}
    try:
        h, c, si, sig = parse(tok)
        KEY.public_key().verify(sig, si.encode())
    except Exception:
        out['T1_as_signature'].append('signature does not verify')
        return out
    spec = json.loads(spec_bytes)
    full = R.project(spec)
    bad = R.is_filtered_view(strip(c['authorization_details']), full)
    if bad:
        out['T2_details_within_spec'].append('elements %s are not among the specification\'s' % bad)
    run = c['authorization_details'][0] if c['authorization_details'] else {}
    if run.get(LINK) is None:
        out['T3_link_to_approval'].append('the token carries no link to an approval')
    elif run[LINK] != approval['approved_spec_digest'] or run[LINK] != R.sha(spec_bytes):
        out['T3_link_to_approval'].append('the link names another specification than the one approved')
    if c['iat'] < ts(approval['signed_at']):
        out['T4_time'].append('token issued before the approval was signed')
    if c['exp'] > ts(spec['valid_until']):
        out['T4_time'].append('token outlives the specification\'s valid_until')
    for s in manifest['steps']:
        if not (c['iat'] <= ts(s['started_at']) and ts(s['ended_at']) <= c['exp']):
            out['T4_time'].append('step %d ran outside the token\'s lifetime' % s['index'])
    return out
