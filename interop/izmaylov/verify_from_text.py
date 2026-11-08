#!/usr/bin/env python3
"""
Independent verifier of draft-izmaylov-agent-permission-receipts-02 (Pavel Izmaylov, 31 October 2026),
written from the draft's TEXT ALONE.

What was read: the draft (draft/draft.txt, sha256 in draft/SHA256SUMS) and, for expected answers only, the
published test vectors of github.com/provared/provared (test-vectors/, README, pinned commit in vectors/PINNED_COMMIT).
Nothing of the author's libraries (JavaScript or Python), kit or tools was read, and none was run.
Every "Section n" below is a section of the draft; readings that the text leaves open are numbered A1, A2, ...
in the comments and listed in README.md ("ambiguity log").

Layout of this file
  1. strict primitives: base64url (11.1), canonical JSON (11.2), times (4.3), Ed25519 (4.6), keys (4.4, 11.2, 11.3)
  2. passkey signatures (4.7)
  3. member rules of the eight kinds of record (4.2, 5, 5.1, 6, 7, 8, 9.2)
  4. records: envelope, labels, content, signatures (4.5, 11.1)
  5. the Merkle tree (9.1, RFC 9162 2.1)
  6. time-stamps, RFC 3161 under the DER rules of 9.3
  7. the log: entries, chains, findings, cancellation, heads, the three answers (6 to 10)

Libraries used for signature mathematics only: `cryptography` (ECDSA P-256/P-384, RSA PKCS#1 v1.5) and `pqcrypto`
(ML-DSA-87 and SLH-DSA-SHA2-256s, pure mode, empty context). Ed25519 is implemented here, because 4.6 sets rules that
libraries are said to differ on. A method can be declared missing (`Methods(without=...)`, `--without`): the verifier then reports
"not verified", as Section 4.5 and 10.1 require.
"""
import base64, hashlib, json, re, sys, math
from datetime import datetime

# --------------------------------------------------------------------------------------------------------------
# 1. primitives
# --------------------------------------------------------------------------------------------------------------

class Refused(Exception):
    """A rule of the draft is broken; `code` is the code of Appendix A."""
    def __init__(self, code, msg=""):
        super().__init__(f"{code}: {msg}")
        self.code, self.msg = code, msg

def sha256(b): return hashlib.sha256(b).digest()

_B64 = re.compile(r'[A-Za-z0-9_-]*\Z')
def b64u_enc(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def b64u_dec(s, code='bad-base64url'):
    """Section 11.1: RFC 4648 section 5 without padding, strict: no padding, no character outside the alphabet,
    no length leaving 1 modulo 4, unused bits zero."""
    if not isinstance(s, str) or not _B64.match(s):
        raise Refused(code, "a character that is not allowed")
    if len(s) % 4 == 1:
        raise Refused(code, "impossible length")
    pad = '=' * (-len(s) % 4)
    b = base64.urlsafe_b64decode(s + pad)
    if b64u_enc(b) != s:           # unused bits not zero
        raise Refused(code, "stray bits")
    return b

def _jcs_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"': out.append('\\"')
        elif ch == '\\': out.append('\\\\')
        elif o == 8: out.append('\\b')
        elif o == 9: out.append('\\t')
        elif o == 10: out.append('\\n')
        elif o == 12: out.append('\\f')
        elif o == 13: out.append('\\r')
        elif o < 0x20: out.append('\\u%04x' % o)
        else: out.append(ch)
    out.append('"')
    return ''.join(out)

def _utf16_key(s): return s.encode('utf-16-be')

def jcs(v):
    """RFC 8785 for the value domain of Section 4.2 (objects, arrays, strings, integers)."""
    if isinstance(v, dict):
        return '{' + ','.join(_jcs_str(k) + ':' + jcs(v[k]) for k in sorted(v, key=_utf16_key)) + '}'
    if isinstance(v, list): return '[' + ','.join(jcs(x) for x in v) + ']'
    if isinstance(v, str): return _jcs_str(v)
    if isinstance(v, bool) or not isinstance(v, int): raise Refused('payload-not-canonical', 'value outside 4.2')
    return str(v)

MAX_INT = 2**53 - 1

def _has_lone_surrogate(s):
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)

def check_domain(v, max_depth=8):
    """The value domain of Section 4.2 / 11.2 for a value already parsed: objects, arrays, text without unpaired
    surrogates, integers 0..2^53-1, at most 8 levels."""
    bad = lambda m: Refused('payload-not-canonical', m)
    def walk(x, depth):
        if isinstance(x, (dict, list)) and depth > max_depth: raise bad('nesting deeper than 8')
        if isinstance(x, dict):
            for k, y in x.items():
                if _has_lone_surrogate(k): raise bad('unpaired surrogate')
                walk(y, depth + 1)
        elif isinstance(x, list):
            for y in x: walk(y, depth + 1)
        elif isinstance(x, str):
            if _has_lone_surrogate(x): raise bad('unpaired surrogate')
        elif isinstance(x, bool) or x is None or not isinstance(x, int): raise bad('value outside 4.2')
        elif not (0 <= x <= MAX_INT): raise bad('number outside 0..2^53-1')
    walk(v, 1)

def parse_canonical(b, max_depth=8, require_object=True):
    """Section 11.2: UTF-8 JSON object in the canonical form of RFC 8785, only objects, arrays, strings and integers
    0..2^53-1, no unpaired surrogate even escaped, at most 8 levels (the content being the first), and re-serialised
    to the same bytes (payload-not-canonical)."""
    bad = lambda m: Refused('payload-not-canonical', m)
    if isinstance(b, str): b = b.encode('utf-8', 'surrogatepass')
    try: text = b.decode('utf-8')           # strict: invalid UTF-8 refused; a BOM stays and fails below
    except UnicodeDecodeError: raise bad('not UTF-8')
    def pairs(ps):
        d = {}
        for k, v in ps:
            if k in d: raise bad('repeated member name')
            d[k] = v
        return d
    def no_const(c): raise bad('constant outside 4.2')
    def no_float(f): raise bad('fraction or exponent')
    try:
        v = json.loads(text, object_pairs_hook=pairs, parse_constant=no_const, parse_float=no_float)
    except Refused: raise
    except Exception: raise bad('not JSON')
    def walk(x, depth):
        if isinstance(x, (dict, list)) and depth > max_depth: raise bad('nesting deeper than 8')
        if isinstance(x, dict):
            for k, y in x.items():
                if _has_lone_surrogate(k): raise bad('unpaired surrogate')
                walk(y, depth + 1)
        elif isinstance(x, list):
            for y in x: walk(y, depth + 1)
        elif isinstance(x, str):
            if _has_lone_surrogate(x): raise bad('unpaired surrogate')
        elif isinstance(x, bool) or x is None or not isinstance(x, int): raise bad('value outside 4.2')
        elif not (0 <= x <= MAX_INT): raise bad('number outside 0..2^53-1')
    if require_object and not isinstance(v, dict): raise bad('not an object')      # A3
    walk(v, 1)
    if jcs(v).encode('utf-8') != b: raise bad('not canonical')
    return v

def count_chars(s): return len(s)    # Python str is a sequence of code points (4.3: "counted in code points")

_TIME = re.compile(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\Z')
def time_text(t):
    """Seconds since 1970 -> "YYYY-MM-DDTHH:MM:SSZ"."""
    return datetime.utcfromtimestamp(t).strftime('%Y-%m-%dT%H:%M:%SZ') if t >= 0 else None

def parse_time(s):
    """Section 4.3 / 11.2: "YYYY-MM-DDTHH:MM:SSZ" denoting a moment that exists (no 24h, no :60, real calendar day).
    Returns whole seconds since 1970 (may be negative for year 0000..1969) or None."""
    if not isinstance(s, str): return None
    m = _TIME.match(s)
    if not m: return None
    y, mo, d, h, mi, se = map(int, m.groups())
    if not (1 <= mo <= 12 and h <= 23 and mi <= 59 and se <= 59): return None
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    dim = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    if not (1 <= d <= dim): return None
    # days from civil (proleptic Gregorian), Howard Hinnant's algorithm
    yy = y - (mo <= 2); era = yy // 400; yoe = yy - era * 400
    doy = (153 * (mo + (-3 if mo > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    return days * 86400 + h * 3600 + mi * 60 + se

# ---------------- Ed25519, Section 4.6 (pure Python, extended coordinates) ----------------
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)           # sqrt(-1)

def _inv(x): return pow(x, _P - 2, _P)
def _add(p, q):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = p, q
    a = (y1 - x1) * (y2 - x2) % _P; b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P; d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)
_ID = (0, 1, 1, 0)
def _mul(n, p):
    r = _ID
    while n:
        if n & 1: r = _add(r, p)
        p = _add(p, p); n >>= 1
    return r
def _enc(p):
    x, y, z, _ = p; zi = _inv(z); x = x * zi % _P; y = y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')
def _eq(p, q): return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0

def _decode(b):
    """RFC 8032 5.1.3: None unless b is the canonical encoding of a point on the curve (y < p, x recovered,
    x = 0 with the sign bit set refused)."""
    if len(b) != 32: return None
    n = int.from_bytes(b, 'little'); sign = n >> 255; y = n & ((1 << 255) - 1)
    if y >= _P: return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P: x = x * _I % _P
    if (x * x - x2) % _P: return None
    if x == 0 and sign: return None
    if (x & 1) != sign: x = _P - x
    return (x, y, 1, x * y % _P)

_BY = 4 * _inv(5) % _P
_BX = None
def _base():
    global _BX
    x2 = (_BY * _BY - 1) * _inv(_D * _BY * _BY + 1) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P: x = x * _I % _P
    if x & 1: x = _P - x
    return (x, _BY, 1, x * _BY % _P)
_B = _base()

def _small_order_ys():
    """y-coordinates of the eight points whose order divides 8 (4.4: "whatever the sign bit")."""
    # a point of exact order 8: clear the large-order part of some curve point
    for y in range(2, 1000):
        p = _decode(y.to_bytes(32, 'little'))
        if p is None: continue
        t = _mul(_L, p)
        if not _eq(_mul(4, t), _ID):
            ys = set()
            q = _ID
            for _ in range(8):
                q = _add(q, t); x, yy, z, _t = q; ys.add(yy * _inv(z) % _P)
            return ys
    raise RuntimeError('no torsion point found')
_SMALL_Y = _small_order_ys()
assert len(_SMALL_Y) == 5   # 8 points, 5 distinct y: 1, -1, 0 (two points) and +-y8 (four points)

def ed25519_key_ok(a32):
    """4.4: refuse y >= p and the y of any of the eight small-order points, whatever the sign bit. (A key that is not
    on the curve is refused too: 4.6 rule 2 for A.)"""
    if len(a32) != 32: return False
    y = int.from_bytes(a32, 'little') & ((1 << 255) - 1)
    if y >= _P: return False
    return y not in _SMALL_Y

def ed25519_verify(a32, sig, msg):
    """Section 4.6, rules 1-4. Returns 'valid' | 'invalid'; raises Refused('bad-key') for a key 4.4 refuses."""
    if not ed25519_key_ok(a32): raise Refused('bad-key', 'Ed25519 key under which anyone can sign, or not a point')
    if len(sig) != 64: return 'invalid'
    r_enc, s_enc = sig[:32], sig[32:]
    s = int.from_bytes(s_enc, 'little')
    if s >= _L: return 'invalid'                                  # rule 1
    A = _decode(a32); R = _decode(r_enc)
    if A is None or R is None: return 'invalid'                   # rule 2 (A, R)
    ry = int.from_bytes(r_enc, 'little') & ((1 << 255) - 1)
    if ry in _SMALL_Y: return 'invalid'                           # rule 3 (R of small order)
    k = int.from_bytes(hashlib.sha512(r_enc + a32 + msg).digest(), 'little') % _L
    lhs = _mul(s, _B)
    # rule 4: S*B = R + k*A, cofactorless: compare encodings of S*B - k*A with R
    neg = lambda p: ((-p[0]) % _P, p[1], p[2], (-p[3]) % _P)
    chk = _add(lhs, neg(_mul(k, A)))
    return 'valid' if _enc(chk) == r_enc else 'invalid'

# ---------------- keys, Section 4.4, 11.2, 11.3 ----------------
KEY_SHAPES = {
    'Ed25519':           ('alg', 'crv', 'kty', 'x'),
    'ML-DSA-87':         ('alg', 'kty', 'pub'),
    'SLH-DSA-SHA2-256s': ('alg', 'kty', 'pub'),
    'ES256':             ('alg', 'crv', 'kty', 'x', 'y'),
    'RS256':             ('alg', 'e', 'kty', 'n'),
}
_P256 = 2**256 - 2**224 + 2**192 + 2**96 - 1
KEY_LEN = {'Ed25519': 32, 'ML-DSA-87': 2592, 'SLH-DSA-SHA2-256s': 64}
THUMB_MEMBERS = {'Ed25519': ('crv', 'kty', 'x'), 'ES256': ('crv', 'kty', 'x', 'y'), 'RS256': ('e', 'kty', 'n'),
                 'ML-DSA-87': ('alg', 'kty', 'pub'), 'SLH-DSA-SHA2-256s': ('alg', 'kty', 'pub')}

def check_key(jwk, allowed):
    """Section 4.4 / 11.2: exactly one of the five JWK shapes, no other member (bad-key); returns (alg, thumbprint)."""
    bad = lambda m: Refused('bad-key', m)
    if not isinstance(jwk, dict): raise bad('not an object')
    alg = jwk.get('alg')
    if not isinstance(alg, str) or alg not in KEY_SHAPES or alg not in allowed: raise bad('method not allowed here')
    if tuple(sorted(jwk)) != tuple(sorted(KEY_SHAPES[alg])): raise bad('members')
    fixed = {'Ed25519': ('crv', 'Ed25519', 'kty', 'OKP'), 'ES256': ('crv', 'P-256', 'kty', 'EC'),
             'RS256': ('kty', 'RSA'), 'ML-DSA-87': ('kty', 'AKP'), 'SLH-DSA-SHA2-256s': ('kty', 'AKP')}[alg]
    for i in range(0, len(fixed), 2):
        if jwk.get(fixed[i]) != fixed[i + 1]: raise bad(f'{fixed[i]} must be {fixed[i+1]}')
    def dec(name):
        try: return b64u_dec(jwk[name])
        except Refused: raise bad(f'{name} is not strict base64url')
    if alg in ('Ed25519',):
        x = dec('x')
        if len(x) != 32: raise bad('x length')
        if not ed25519_key_ok(x): raise bad('weak Ed25519 key')
    elif alg in ('ML-DSA-87', 'SLH-DSA-SHA2-256s'):
        if len(dec('pub')) != KEY_LEN[alg]: raise bad('pub length')
    elif alg == 'ES256':
        x, y = dec('x'), dec('y')
        if len(x) != 32 or len(y) != 32: raise bad('coordinate length')
        if int.from_bytes(x, 'big') >= _P256 or int.from_bytes(y, 'big') >= _P256: raise bad('coordinate not below p')   # A2
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            ec.EllipticCurvePublicNumbers(int.from_bytes(x, 'big'), int.from_bytes(y, 'big'), ec.SECP256R1()).public_key()
        except Exception: raise bad('not a point of P-256')
    elif alg == 'RS256':
        if jwk['e'] != 'AQAB': raise bad('exponent must be 65537')
        n = dec('n')
        if not n or n[0] == 0: raise bad('leading zero byte')
        if not (2048 <= int.from_bytes(n, 'big').bit_length() <= 8192): raise bad('modulus size')
    tp = '{' + ','.join(_jcs_str(k) + ':' + _jcs_str(jwk[k]) for k in THUMB_MEMBERS[alg]) + '}'
    return alg, b64u_enc(sha256(tp.encode()))

def key_set_digest(keys):
    """11.3: SHA-256 of the key set (an array of keys) in the canonical form."""
    check_domain(keys)
    return b64u_enc(sha256(jcs(keys).encode()))


# --------------------------------------------------------------------------------------------------------------
# 2. signature methods and passkeys (Sections 4.5, 4.7)
# --------------------------------------------------------------------------------------------------------------
SIG_LEN = {'Ed25519': 64, 'ML-DSA-87': 4627, 'SLH-DSA-SHA2-256s': 29792}

class Methods:
    """Which signature methods this run can verify. `without` names methods to treat as missing, as on a device
    that lacks them (Section 4.5: "a signature of the right length whose algorithm the verifier lacks is not verified")."""
    def __init__(self, without=()):
        self.without = set(without or ())
        self.have = {'Ed25519', 'ES256', 'RS256'}
        try:
            from pqcrypto.sign import ml_dsa_87 as _m; self._mldsa = _m; self.have.add('ML-DSA-87')
        except Exception: self._mldsa = None
        try:
            from pqcrypto.sign import slh_dsa_sha2_256s as _s; self._slh = _s; self.have.add('SLH-DSA-SHA2-256s')
        except Exception: self._slh = None
        self.have -= self.without
        self.used_missing = set()
    def can(self, m): return m in self.have
    def missing_names(self, wanted=('Ed25519', 'ML-DSA-87', 'SLH-DSA-SHA2-256s', 'ES256', 'RS256')):
        return [m for m in wanted if m not in self.have]
    def pq_verify(self, method, pub, msg, sig):
        mod = self._mldsa if method == 'ML-DSA-87' else self._slh
        try:
            mod.verify(pub, msg, sig)           # pure mode, empty context (4.5)
            return True
        except Exception: return False

def verify_sig(methods, method, jwk, sig, msg):
    """Verify one signature of a record. `jwk` is the key (already checked). Returns 'valid' | 'invalid' |
    'unavailable' (right length, method missing). A wrong length is 'invalid' whether or not the method is available
    (Section 4.5), for Ed25519, ML-DSA-87 and SLH-DSA-SHA2-256s, a passkey's Ed25519 signature included."""
    if method in SIG_LEN and len(sig) != SIG_LEN[method]: return 'invalid'
    if not methods.can(method): methods.used_missing.add(method); return 'unavailable'
    if method == 'Ed25519':
        try: return ed25519_verify(b64u_dec(jwk['x']), sig, msg)
        except Refused: return 'invalid'
    if method in ('ML-DSA-87', 'SLH-DSA-SHA2-256s'):
        return 'valid' if methods.pq_verify(method, b64u_dec(jwk['pub']), msg, sig) else 'invalid'
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils
    from cryptography.exceptions import InvalidSignature
    if method == 'ES256':
        r, s = ecdsa_der_to_rs(sig)
        pk = ec.EllipticCurvePublicNumbers(int.from_bytes(b64u_dec(jwk['x']), 'big'),
                                           int.from_bytes(b64u_dec(jwk['y']), 'big'), ec.SECP256R1()).public_key()
        try: pk.verify(utils.encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256())); return 'valid'
        except InvalidSignature: return 'invalid'
    if method == 'RS256':
        pk = rsa.RSAPublicNumbers(65537, int.from_bytes(b64u_dec(jwk['n']), 'big')).public_key()
        try: pk.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256()); return 'valid'
        except InvalidSignature: return 'invalid'
    raise Refused('check-failed', 'unknown method')

def ecdsa_der_to_rs(der, code='passkey-bad-data'):
    """4.7 item 7: ECDSA-Sig-Value in strict DER: one SEQUENCE with a one-byte length, holding two positive INTEGERs of
    1 to 33 bytes in their shortest form, with nothing after them."""
    bad = lambda m: Refused(code, m)
    if len(der) < 8 or der[0] != 0x30: raise bad('not a SEQUENCE')
    if der[1] >= 0x80: raise bad('length is not one byte')
    if der[1] != len(der) - 2: raise bad('bytes left over or length wrong')
    pos, vals = 2, []
    for _ in range(2):
        if pos + 2 > len(der) or der[pos] != 0x02: raise bad('not an INTEGER')
        ln = der[pos + 1]
        if ln < 1 or ln > 33 or ln >= 0x80: raise bad('INTEGER of 1 to 33 bytes')
        v = der[pos + 2: pos + 2 + ln]
        if len(v) != ln: raise bad('cut short')
        if v[0] & 0x80: raise bad('negative INTEGER')
        if ln > 1 and v[0] == 0 and not (v[1] & 0x80): raise bad('not shortest')
        vals.append(int.from_bytes(v, 'big')); pos += 2 + ln
    if pos != len(der): raise bad('bytes left over')
    if vals[0] == 0 or vals[1] == 0: raise bad('INTEGER is not positive')
    return vals[0], vals[1]

def parse_client_data(b):
    """4.7 item 1: UTF-8, no BOM, a JSON object read by a JSON parser; a repeated member is read as its last occurrence."""
    if b[:3] == b'\xef\xbb\xbf': raise Refused('passkey-bad-data', 'byte order mark')
    try: text = b.decode('utf-8')
    except UnicodeDecodeError: raise Refused('passkey-bad-data', 'not UTF-8')
    try: v = json.loads(text)           # json.loads keeps the last of repeated members
    except Exception: raise Refused('passkey-bad-data', 'not JSON')
    if not isinstance(v, dict): raise Refused('passkey-bad-data', 'not an object')
    return v

def check_passkey(methods, issuer, signing_input_ascii, sig_entry, sig_bytes, trust_keys=None, fail_code=None):
    """Section 4.7. Returns (problems:list of codes, state:'valid'|'invalid'|'unavailable'|'unchecked', alg).
    The seven confirmations are taken in the order of the list; the first that fails is the signature's problem (A8, A28).
    `fail_code`: for an approval or a cancellation every failure is reported as approval-invalid / cancellation-invalid."""
    key = issuer['key']; alg = key['alg']; problems = []
    hdr = sig_entry['header']       # A4: the values of the header are decoded here, at the passkey stage, not at the envelope stage
    try: ad = b64u_dec(hdr['authenticatorData'], 'passkey-bad-data')
    except Refused: ad = None; problems.append('passkey-bad-data')
    try: cd = b64u_dec(hdr['clientDataJSON'], 'passkey-bad-data')
    except Refused: cd = None; problems.append('passkey-bad-data')
    if cd is not None:
        try:
            c = parse_client_data(cd)
            if c.get('type') != 'webauthn.get': problems.append('passkey-wrong-type')
            if c.get('challenge') != b64u_enc(sha256(signing_input_ascii)): problems.append('passkey-challenge-mismatch')
            if c.get('origin') != issuer['origin'] or c.get('crossOrigin') is True: problems.append('passkey-origin-mismatch')
        except Refused: problems.append('passkey-bad-data')
    if ad is not None:
        if len(ad) < 37: problems.append('passkey-bad-data')
        else:
            if ad[:32] != sha256(issuer['rpId'].encode('ascii')): problems.append('passkey-rpid-mismatch')
            fl = ad[32]
            if not fl & 1: problems.append('passkey-user-not-present')
            if not fl & 4: problems.append('passkey-user-not-verified')
            if fl & 0x40: problems.append('passkey-bad-data')            # attested credential data must be clear
            if not fl & 0x80 and len(ad) != 37: problems.append('passkey-bad-data')
    state = 'unchecked'
    if ad is not None and cd is not None:
        data = ad + sha256(cd)
        try:
            if alg == 'ES256':
                if not methods.can('ES256'): state = 'unavailable'; methods.used_missing.add('ES256')
                else:
                    ecdsa_der_to_rs(sig_bytes)            # strict DER; raises passkey-bad-data
                    state = verify_sig(methods, 'ES256', key, sig_bytes, data)
            elif alg == 'RS256':
                state = verify_sig(methods, 'RS256', key, sig_bytes, data)
            else:
                state = verify_sig(methods, 'Ed25519', key, sig_bytes, data)
            if state == 'invalid':
                problems.append('signature-invalid')
        except Refused as e:
            problems.append(e.code); state = 'invalid'
    if trust_keys is not None and not isinstance(trust_keys, (list, tuple, set)):
        trust_keys = []
    problems = problems[:1]   # A8 (changed after the vectors): the confirmations are in the list's order; the first that fails is the signature's problem
    if fail_code:
        problems = [fail_code] if problems else []
    return problems, state, alg


# --------------------------------------------------------------------------------------------------------------
# 3. members of the eight kinds of record
# --------------------------------------------------------------------------------------------------------------
# Appendix B: shared actions by kind, and the rules of conduct (written without the "provared." prefix).
SHARED_KINDS = {
    'reads': ['data.read', 'data.search', 'message.read', 'calendar.read', 'code.read', 'web.read'],
    'changes': ['data.create', 'data.change', 'message.draft', 'calendar.change', 'access.remove', 'code.change',
                'system.configure'],
    'destroys': ['data.delete'],
    'sends': ['data.export', 'message.send', 'post.publish', 'agent.instruct'],
    'commits': ['booking.make', 'booking.cancel', 'order.place', 'order.cancel', 'terms.accept', 'form.submit',
                'account.create'],
    'grants': ['access.grant', 'key.create'],
    'runs': ['code.run', 'code.release'],
    'enters': ['account.sign-in'],
}
CONDUCT = ['impersonate', 'bypass', 'escalate', 'conceal', 'deceive', 'harass', 'disclose', 'continue-after-stop']
SHARED_ACTIONS = {'provared.' + a: k for k, v in SHARED_KINDS.items() for a in v}
NEVER_NAMES = set(SHARED_KINDS) | set(CONDUCT)
RESERVED_DETAIL_NAMES = ['provared.arguments', 'provared.http-request', 'provared.http-response',
                         'provared.trace-id', 'provared.request-id', 'provared.event-id', 'provared.error']
REPEATABLE_DETAIL_NAMES = {'provared.trace-id', 'provared.request-id', 'provared.event-id'}

class Bad(Refused):
    def __init__(self, msg, code='bad-field'): super().__init__(code, msg)

_ACTION = re.compile(r'[a-z0-9][a-z0-9._-]{0,63}\Z')
_UNIT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,15}\Z')
_RPID = re.compile(r'[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?\Z')

def _is_int(v): return isinstance(v, int) and not isinstance(v, bool)
def _need_obj(c, name, required, optional=()):
    if not isinstance(c, dict): raise Bad(f'{name}: not a map')
    for k in required:
        if k not in c: raise Bad(f'{name}: "{k}" is missing')
    for k in c:
        if k not in required and k not in optional: raise Bad(f'{name}: holds a member that is not known')
def _bytes_member(c, k, n):
    v = c[k]
    if not isinstance(v, str): raise Bad(f'{k}: not text')
    try: b = b64u_dec(v)
    except Refused: raise Bad(f'{k}: not strict base64url', 'bad-base64url')      # A5: 11.1 names bad-base64url for a value "in a record's envelope or content"
    if len(b) != n: raise Bad(f'{k}: must be {n} bytes')
def _id(c, k='id'): _bytes_member(c, k, 16)
def _digest(c, k): _bytes_member(c, k, 32)
def _time(c, k):
    if parse_time(c[k]) is None: raise Bad(f'{k}: not a time')
def _name(c, k='name'):
    v = c[k]
    if not isinstance(v, str) or not 1 <= len(v) <= 200: raise Bad(f'{k}: name of 1 to 200 characters')
def _action_name(v, what='action'):
    if not isinstance(v, str) or not _ACTION.match(v): raise Bad(f'{what}: not an action name')
    if v.startswith('provared.') and v not in SHARED_ACTIONS: raise Bad(f'{what}: reserved name not on the shared list')
def _amount(v):
    if not isinstance(v, dict) or set(v) != {'unit', 'value'}: raise Bad('amount: exactly unit and value')
    if not _is_int(v['value']) or not 0 <= v['value'] <= MAX_INT: raise Bad('amount: value')
    if not isinstance(v['unit'], str) or not _UNIT.match(v['unit']): raise Bad('amount: unit')
def _details(v):
    if not isinstance(v, list) or not 1 <= len(v) <= 32: raise Bad('details: 1 to 32 maps')
    seen = set()
    for d in v:
        _need_obj(d, 'details', ('name', 'sha256')); _name(d); _digest(d, 'sha256')
        n = d['name']
        if n.startswith('provared.'):
            if n not in RESERVED_DETAIL_NAMES: raise Bad('details: reserved name')
            if n in seen and n not in REPEATABLE_DETAIL_NAMES: raise Bad('details: reserved name repeated')
            seen.add(n)
def _service_id(v):
    if not isinstance(v, str) or not _ACTION.match(v): raise Bad('with: not an identifier of the form of an action name')

def _keyset(v, kind, allowed_pair):
    """A key set is exactly one Ed25519 key followed by one ML-DSA-87 key (a recorder's adds SLH-DSA-SHA2-256s)."""
    if not isinstance(v, list) or len(v) != len(allowed_pair): raise Bad('keys: wrong number of keys', 'bad-key')
    for k, a in zip(v, allowed_pair): check_key(k, [a])

AGENT_KEYS = ('Ed25519', 'ML-DSA-87'); RECORDER_KEYS = ('Ed25519', 'ML-DSA-87', 'SLH-DSA-SHA2-256s')

_ORIGIN_LABEL = re.compile(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\Z')
def check_origin(text, rpid):
    """Section 5: the form of "origin" (at most 300 characters), and "The host MUST be rpId or end with . followed by rpId"."""
    bad = lambda m: Bad('issuer.origin: ' + m)
    if not isinstance(text, str) or len(text) > 300 or not text.isascii(): raise bad('not the form')
    if text.startswith('https://'): scheme, rest = 'https', text[8:]
    elif text.startswith('http://'): scheme, rest = 'http', text[7:]
    else: raise bad('scheme')
    host, port = rest, None
    if ':' in rest: host, port = rest.split(':', 1)
    if scheme == 'http' and host != 'localhost': raise bad('http only with localhost')
    if not 1 <= len(host) <= 253: raise bad('host length')
    labels = host.split('.')
    if not all(_ORIGIN_LABEL.match(l) for l in labels): raise bad('label')
    if labels[-1].isdigit(): raise bad('the last label is all digits')
    if port is not None:
        if not re.match(r'[1-9][0-9]{0,4}\Z', port) or int(port) > 65535: raise bad('port')
        if int(port) == (443 if scheme == 'https' else 80): raise bad('default port')
    if not (host == rpid or host.endswith('.' + rpid)): raise bad('must be on the website that rpId names')

def _limits(limits, actions, what):
    if not isinstance(limits, list) or len(limits) > 64: raise Bad(f'{what}: 0 to 64 limits')
    seen = set(); units = {}
    for l in limits:
        if not isinstance(l, dict): raise Bad('limit: not a map')
        kinds = [k for k in ('max', 'each', 'count') if k in l]
        if len(kinds) != 1: raise Bad('limit: exactly one of max, each, count')
        kind = kinds[0]
        allowed = {'max': {'action', 'max', 'unit', 'per'}, 'each': {'action', 'each', 'unit'},
                   'count': {'action', 'count', 'per'}}[kind]
        required = {'action', kind} | ({'unit'} if kind != 'count' else set())
        if not required <= set(l) or not set(l) <= allowed: raise Bad('limit: members')
        if not isinstance(l.get('action'), str) or l['action'] not in actions: raise Bad('limit: action not among the actions')
        if not _is_int(l[kind]) or not 0 <= l[kind] <= MAX_INT or (kind == 'count' and l[kind] < 1): raise Bad('limit: value')
        if 'per' in l and (not _is_int(l['per']) or not 1 <= l['per'] <= 31622400): raise Bad('limit: per')
        if 'unit' in l:
            if not isinstance(l['unit'], str) or not _UNIT.match(l['unit']): raise Bad('limit: unit')
            if units.setdefault(l['action'], l['unit']) != l['unit']: raise Bad('limit: two units for one action')
        sig = (l['action'], kind, l.get('per'))
        if sig in seen: raise Bad('limit: the same limit twice')
        seen.add(sig)
    return units

def validate_slip(c):
    """Section 5, 5.1. Raises Bad / Refused('bad-key') at the first problem."""
    _need_obj(c, 'slip', ('type', 'id', 'issuer', 'agent', 'actions', 'limits', 'requires', 'never', 'with',
                          'validFrom', 'validUntil', 'purpose'), ('passes',))
    _id(c)
    iss = c['issuer']; _need_obj(iss, 'issuer', ('key', 'name', 'origin', 'rpId'))
    check_key(iss['key'], ['ES256', 'RS256', 'Ed25519']); _name(iss)
    if not isinstance(iss['rpId'], str) or not _RPID.match(iss['rpId']) or len(iss['rpId']) > 253: raise Bad('issuer.rpId')
    check_origin(iss['origin'], iss['rpId'])
    ag = c['agent']; _need_obj(ag, 'agent', ('keys', 'name'), ('software',))
    _keyset(ag['keys'], 'agent', AGENT_KEYS); _name(ag)
    if 'software' in ag:
        sw = ag['software']
        if not isinstance(sw, list) or not 1 <= len(sw) <= 16: raise Bad('agent.software: 1 to 16')
        for s in sw: _need_obj(s, 'software', ('name', 'sha256')); _name(s); _digest(s, 'sha256')
    acts = c['actions']
    if not isinstance(acts, list) or not 1 <= len(acts) <= 64 or len(set(map(str, acts))) != len(acts): raise Bad('actions: 1 to 64, none repeated')
    for a in acts: _action_name(a, 'actions')
    units = _limits(c['limits'], set(acts), 'limits')
    never = c['never']
    if not isinstance(never, list) or len(never) > 16 or len(set(map(str, never))) != len(never): raise Bad('never: 0 to 16, none repeated')
    for n in never:
        if not isinstance(n, str) or n not in NEVER_NAMES: raise Bad('never: not a name of Appendix B')
    for a in acts:
        if a in SHARED_ACTIONS and SHARED_ACTIONS[a] in never: raise Bad('actions: allows an action of a kind that never names')
    req = c['requires']
    if not isinstance(req, list) or len(req) > 64: raise Bad('requires: 0 to 64')
    seen = set()
    for r in req:
        if not isinstance(r, dict): raise Bad('condition: not a map')
        _need_obj(r, 'condition', ('need',), ('action', 'above', 'unit'))
        if r['need'] not in ('countersignature', 'approval'): raise Bad('condition: need')
        if 'action' in r and (not isinstance(r['action'], str) or r['action'] not in acts): raise Bad('condition: action not among the actions')
        if ('above' in r) != ('unit' in r): raise Bad('condition: above and unit together')
        if 'above' in r:
            if 'action' not in r: raise Bad('condition: above only with action')
            if not _is_int(r['above']) or not 0 <= r['above'] <= MAX_INT: raise Bad('condition: above')
            if not isinstance(r['unit'], str) or not _UNIT.match(r['unit']): raise Bad('condition: unit')
            if units.setdefault(r['action'], r['unit']) != r['unit']: raise Bad('condition: two units for one action')
        sig = (r['need'], r.get('action'))
        if sig in seen: raise Bad('condition: the same need and action twice')
        seen.add(sig)
    w = c['with']
    if not isinstance(w, list) or len(w) > 64: raise Bad('with: 0 to 64 services')
    ids = set()
    for s in w:
        if not isinstance(s, dict) or not {'id', 'name'} <= set(s) or not set(s) <= {'id', 'name', 'keys'}: raise Bad('service: members')
        _service_id(s['id']); _name(s)
        if s['id'] in ids: raise Bad('service: id repeated')
        ids.add(s['id'])
        if 'keys' in s: _keyset(s['keys'], 'service', AGENT_KEYS)
    if 'passes' in c and (not _is_int(c['passes']) or not 1 <= c['passes'] <= 10): raise Bad('passes: 1 to 10')
    _time(c, 'validFrom'); _time(c, 'validUntil')
    if parse_time(c['validUntil']) <= parse_time(c['validFrom']): raise Bad('validUntil is not later than validFrom')
    p = c['purpose']
    if not isinstance(p, str) or not 1 <= len(p) <= 1000: raise Bad('purpose: 1 to 1000 characters')

def validate_stub(c):
    _need_obj(c, 'stub', ('type', 'id', 'slip', 'seq', 'action', 'when'),
              ('previous', 'amount', 'with', 'details', 'approval', 'pass', 'terms'))
    _id(c); _digest(c, 'slip')
    if not _is_int(c['seq']) or not 0 <= c['seq'] <= MAX_INT: raise Bad('seq')
    if (c['seq'] != 0) != ('previous' in c): raise Bad('previous: present if and only if seq is not 0')
    if 'previous' in c: _digest(c, 'previous')
    _action_name(c['action'])
    if 'amount' in c: _amount(c['amount'])
    if 'with' in c: _service_id(c['with'])
    if 'details' in c: _details(c['details'])
    for k in ('approval', 'pass', 'terms'):
        if k in c: _digest(c, k)
    if 'terms' in c and 'with' not in c: raise Bad('terms: only with "with"')
    _time(c, 'when')

def validate_countersignature(c):
    _need_obj(c, 'countersignature', ('type', 'stub', 'when')); _digest(c, 'stub'); _time(c, 'when')

def validate_approval(c):
    _need_obj(c, 'approval', ('type', 'id', 'slip', 'action', 'when'), ('amount', 'with', 'details'))
    _id(c); _digest(c, 'slip'); _action_name(c['action']); _time(c, 'when')
    if 'amount' in c: _amount(c['amount'])
    if 'with' in c: _service_id(c['with'])
    if 'details' in c: _details(c['details'])

def validate_pass(c):
    _need_obj(c, 'pass', ('type', 'id', 'slip', 'to', 'actions', 'limits', 'validFrom', 'validUntil', 'when'), ('from',))
    _id(c); _digest(c, 'slip')
    if 'from' in c: _digest(c, 'from')
    to = c['to']; _need_obj(to, 'to', ('keys', 'name')); _keyset(to['keys'], 'to', AGENT_KEYS); _name(to)
    acts = c['actions']
    if not isinstance(acts, list) or not 1 <= len(acts) <= 64 or len(set(map(str, acts))) != len(acts): raise Bad('actions')
    for a in acts: _action_name(a, 'actions')
    _limits(c['limits'], set(acts), 'limits')
    _time(c, 'validFrom'); _time(c, 'validUntil'); _time(c, 'when')
    if parse_time(c['validUntil']) <= parse_time(c['validFrom']): raise Bad('validUntil is not later than validFrom')

def validate_cancellation(c):
    _need_obj(c, 'cancellation', ('type', 'id', 'slip', 'when')); _id(c); _digest(c, 'slip'); _time(c, 'when')

def validate_acknowledgement(c):
    _need_obj(c, 'acknowledgement', ('type', 'cancellation', 'id', 'slip', 'when'), ('pass',))
    _id(c); _digest(c, 'cancellation'); _digest(c, 'slip'); _time(c, 'when')
    if 'pass' in c: _digest(c, 'pass')

def validate_seal(c):
    _need_obj(c, 'seal', ('type', 'id', 'by', 'size', 'root', 'when'), ('previous',))
    _id(c); _digest(c, 'root'); _time(c, 'when')
    by = c['by']; _need_obj(by, 'by', ('keys', 'name')); _keyset(by['keys'], 'by', RECORDER_KEYS); _name(by)
    if not _is_int(c['size']) or not 1 <= c['size'] <= MAX_INT: raise Bad('size: at least 1')
    if 'previous' in c: _digest(c, 'previous')

VALIDATORS = {'slip': validate_slip, 'stub': validate_stub, 'countersignature': validate_countersignature,
              'approval': validate_approval, 'pass': validate_pass, 'cancellation': validate_cancellation,
              'acknowledgement': validate_acknowledgement, 'seal': validate_seal}


# --------------------------------------------------------------------------------------------------------------
# 4. records: envelope, labels, content, signatures
# --------------------------------------------------------------------------------------------------------------
HYBRID = ('Ed25519', 'ML-DSA-87')
SIGNERS = {'slip': ('passkey',), 'stub': HYBRID, 'countersignature': HYBRID, 'approval': ('passkey',), 'pass': HYBRID,
           'cancellation': ('passkey',), 'acknowledgement': HYBRID, 'seal': HYBRID + ('SLH-DSA-SHA2-256s',)}
ALG_TEXT = {'passkey': 'prova.red/webauthn/v0', 'Ed25519': 'Ed25519', 'ML-DSA-87': 'ML-DSA-87',
            'SLH-DSA-SHA2-256s': 'SLH-DSA-SHA2-256s'}
_PROT = re.compile(rb'\{"typ":"vnd\.provared\.([a-z]+)\.v0\+json","alg":"([^"\\]*)"\}\Z')
MAX_RECORD = 65536

class Rec:
    def __init__(self, kind):
        self.kind = kind; self.problems = []; self.content = None; self.digest = None; self.payload_b64 = None
        self.raw_digest = None  # digest of the payload bytes, known once the payload decodes
        self.sigs = []          # list of dict(method, protected_b64, signature(bytes), entry)
        self.states = []        # per signature: 'valid' | 'invalid' | 'unavailable' | 'unchecked'
        self.encoded_ok = False

def read_record(rec, kind):
    """Sections 4.1, 4.2, 11.1, 11.2: envelope, labels, content and members, in that order; the first problem is the
    only one reported for the record at this stage (10.1). Signatures are checked later (they need keys)."""
    r = Rec(kind); methods = SIGNERS[kind]
    try:
        if not isinstance(rec, dict) or set(rec) != {'payload', 'signatures'}: raise Refused('bad-envelope', 'payload and signatures')
        sigs = rec['signatures']
        if not isinstance(rec['payload'], str) or not isinstance(sigs, list): raise Refused('bad-envelope', 'types')
        total = len(rec['payload'])
        for i, s in enumerate(sigs[:len(methods)]):        # A7: the shape of each signature entry is read at the positions Section 4.1 gives; more entries than that are a layout problem
            want_pk = methods[i] == 'passkey'
            exp = {'protected', 'signature'} | ({'header'} if want_pk else set())
            if not isinstance(s, dict) or set(s) != exp: raise Refused('bad-envelope', 'a signature entry must hold exactly: ' + ', '.join(sorted(exp)))
            if not isinstance(s['protected'], str) or not isinstance(s['signature'], str): raise Refused('bad-envelope', 'types')
            total += len(s['protected']) + len(s['signature'])
            if want_pk:
                h = s['header']
                if not isinstance(h, dict) or set(h) != {'authenticatorData', 'clientDataJSON'}: raise Refused('bad-envelope', 'header members')
                if not isinstance(h['authenticatorData'], str) or not isinstance(h['clientDataJSON'], str): raise Refused('bad-envelope', 'types')
                total += len(h['authenticatorData']) + len(h['clientDataJSON'])
        if total > MAX_RECORD: raise Refused('too-large', 'over 65,536 characters')      # A6: where in the order
        payload = b64u_dec(rec['payload']); r.raw_digest = b64u_enc(sha256(payload))
        for s in sigs:
            s['_prot'] = b64u_dec(s['protected']); s['_sig'] = b64u_dec(s['signature'])
        for i, s in enumerate(sigs[:len(methods)]):
            want = ('{"typ":"vnd.provared.%s.v0+json","alg":"%s"}' % (kind, ALG_TEXT[methods[i]])).encode()
            if s['_prot'] != want:
                m = _PROT.match(s['_prot'])
                known = m and m.group(1).decode() in SIGNERS and m.group(2).decode() in ALG_TEXT.values()
                if known and m.group(1).decode() != kind: raise Refused('payload-type-mismatch', 'label of another kind')
                raise Refused('unknown-type', 'protected header is not a known text')
        if len(sigs) != len(methods): raise Refused('bad-signatures-layout', 'number or order of signatures')
        r.payload_b64 = rec['payload']; digest = b64u_enc(sha256(payload))
        r.sigs = [dict(method=methods[i], protected_b64=s['protected'], signature=s['_sig'], entry=s) for i, s in enumerate(sigs)]
        r.states = ['unchecked'] * len(sigs)
        r.content = parse_canonical(payload)
        if r.content.get('type') != 'provared.%s.v0' % kind: raise Refused('payload-type-mismatch', 'type member')
        r.digest = digest             # the digest of the content is known once the content has been read as canonical and of the right kind
        VALIDATORS[kind](r.content)
        r.encoded_ok = True
    except Refused as e:
        r.problems.append(e.code)
    return r

def signing_input(r, i): return (r.sigs[i]['protected_b64'] + '.' + r.payload_b64).encode('ascii')

def check_hybrid(r, keyset, methods):
    """4.5: every signature must verify with the key at the same position in the applicable key set."""
    out = []
    for i, s in enumerate(r.sigs):
        out.append(verify_sig(methods, s['method'], keyset[i], s['signature'], signing_input(r, i)))
    r.states = out
    return ['signature-invalid'] if 'invalid' in out else []

def check_passkey_record(r, issuer, methods, fail_code=None):
    problems, state, alg = check_passkey(methods, issuer, signing_input(r, 0), r.sigs[0]['entry'], r.sigs[0]['signature'], fail_code=fail_code)
    r.states = [state]
    return problems

def check_slip(record, issuer_keys=None, methods=None, notes=None):
    """One permission, alone (4.7, 5). `issuer_keys`: thumbprints of trusted passkeys, or None."""
    methods = methods or Methods()
    r = read_record(record, 'slip')
    out = {'kind': 'slip', 'fingerprint': r.digest, 'problems': list(r.problems), 'signature': {'method': 'passkey', 'alg': None, 'state': 'unchecked'}}
    if r.problems: return out, r
    iss = r.content['issuer']
    out['issuerKey'] = check_key(iss['key'], ['ES256', 'RS256', 'Ed25519'])[1]
    probs = check_passkey_record(r, iss, methods)
    out['problems'] += probs
    out['signature'] = {'method': 'passkey (%s)' % iss['key']['alg'], 'alg': iss['key']['alg'], 'state': r.states[0]}
    if issuer_keys is not None:
        if not isinstance(issuer_keys, list) or out['issuerKey'] not in issuer_keys: out['problems'].append('issuer-not-expected')
    out['trusted_compared'] = issuer_keys is not None
    return out, r


# --------------------------------------------------------------------------------------------------------------
# 5. the Merkle tree: Section 9.1 (RFC 9162 section 2.1.1 with SHA-256), inclusion and consistency (RFC 9162 2.1.3, 2.1.4)
# --------------------------------------------------------------------------------------------------------------
def leaf_hash(d): return sha256(b'\x00' + d)
def node_hash(l, r): return sha256(b'\x01' + l + r)

def _split(n):
    k = 1
    while k * 2 < n: k *= 2
    return k

def tree_root(leaves):
    """MTH over the leaves (the leaves are the lines' bytes without line feeds)."""
    n = len(leaves)
    if n == 0: return sha256(b'')
    if n == 1: return leaf_hash(leaves[0])
    k = _split(n)
    return node_hash(tree_root(leaves[:k]), tree_root(leaves[k:]))

def inclusion_path(leaves, m):
    if not (0 <= m < len(leaves)): raise Refused('check-failed', 'no such leaf')
    return _inclusion_path(leaves, m)

def _inclusion_path(leaves, m):
    n = len(leaves)
    if n <= 1: return []
    k = _split(n)
    if m < k: return _inclusion_path(leaves[:k], m) + [tree_root(leaves[k:])]
    return _inclusion_path(leaves[k:], m - k) + [tree_root(leaves[:k])]

def verify_inclusion(index, size, leaf, path, root):
    """RFC 9162 2.1.3.2 (the leaf is hashed here)."""
    if index >= size or size < 1: return False
    fn, sn, r = index, size - 1, leaf_hash(leaf)
    for p in path:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0: fn >>= 1; sn >>= 1
        else: r = node_hash(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root

def consistency_proof(m, leaves):
    """RFC 9162 2.1.4.1: SUBPROOF(m, D[n], true)."""
    n = len(leaves)
    if not (0 <= m <= n): raise Refused('check-failed', 'no tree of that size inside this one')
    if m == 0 or m == n: return []
    def sub(m, d, b):
        n = len(d)
        if m == n: return [] if b else [tree_root(d)]
        k = _split(n)
        if m <= k: return sub(m, d[:k], b) + [tree_root(d[k:])]
        return sub(m - k, d[k:], False) + [tree_root(d[:k])]
    return sub(m, leaves, True)

def verify_consistency(m, n, root_m, root_n, proof):
    """RFC 9162 2.1.4.2."""
    if m < 0 or n < m: return False
    if m == n: return not proof and root_m == root_n
    if m == 0: return not proof and root_m == sha256(b'')       # A9: RFC 9162 leaves m = 0 undefined; the empty tree is consistent with any tree
    proof = list(proof)
    if (m & (m - 1)) == 0: proof = [root_m] + proof
    if not proof: return False
    fn, sn = m - 1, n - 1
    while fn & 1: fn >>= 1; sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr); sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0: fn >>= 1; sn >>= 1
        else: sr = node_hash(sr, c)
        fn >>= 1; sn >>= 1
    return fr == root_m and sr == root_n and sn == 0

MAX_TOKEN = 12288
def decode_stamps(stamps):
    """9.3 / 11.4: "stamps" holds 1 to 4 time-stamps, none repeated; a TimeStampToken is a base64url string of at most
    12,288 bytes, a block time-stamp an object of exactly "block" and "proof", each a string in base64url (bad-field;
    base64url read strictly as 11.1 says: bad-base64url)."""
    if not isinstance(stamps, list) or not 1 <= len(stamps) <= 4: raise Bad('stamps: 1 to 4 items')
    out = []
    for s in stamps:
        if isinstance(s, str):
            tok = b64u_dec(s)
            if len(tok) > MAX_TOKEN: raise Bad('stamps: a token is at most 12,288 bytes')
            out.append({'kind': 'service', 'token': tok.hex()})
        elif isinstance(s, dict) and set(s) == {'block', 'proof'} and all(isinstance(v, str) for v in s.values()):
            out.append({'kind': 'block', 'header': b64u_dec(s['block']).hex(), 'proof': b64u_dec(s['proof']).hex()})
        else: raise Bad('stamps: not a time-stamp')
    for i, a in enumerate(out):
        if a in out[:i]: raise Bad('stamps: repeated')
    return out

# --------------------------------------------------------------------------------------------------------------
# 6. time-stamps: RFC 3161 TimeStampToken read under the DER rules of Section 9.3
# --------------------------------------------------------------------------------------------------------------
class DerError(Refused):
    def __init__(self, msg): super().__init__('stamp-bad-data', msg)

def der_header(b, pos, end):
    """One DER element header at pos inside [pos, end): single-byte tag, definite length in its shortest form with a
    length field of at most four bytes, content inside what holds it. Returns (tag, content_start, content_end)."""
    if pos >= end: raise DerError('cut short')
    tag = b[pos]
    if tag & 0x1f == 0x1f: raise DerError('tag of the long form')
    if pos + 1 >= end: raise DerError('cut short')
    l0 = b[pos + 1]
    if l0 < 0x80: ln, cs = l0, pos + 2
    else:
        n = l0 & 0x7f
        if n == 0: raise DerError('indefinite length')
        if n > 4: raise DerError('length field of more than four bytes')
        if pos + 2 + n > end: raise DerError('cut short')
        raw = b[pos + 2: pos + 2 + n]
        if raw[0] == 0: raise DerError('length not in its shortest form')
        ln = int.from_bytes(raw, 'big')
        if ln < 0x80: raise DerError('length not in its shortest form')
        cs = pos + 2 + n
    if cs + ln > end: raise DerError('a part is longer than what holds it')
    return tag, cs, cs + ln

def der_children(b, start, end):
    out = []; pos = start
    while pos < end:
        tag, cs, ce = der_header(b, pos, end)
        out.append((tag, pos, cs, ce)); pos = ce
    return out

def _check_primitive(tag, c):
    if tag == 0x01:
        if len(c) != 1 or c[0] not in (0x00, 0xff): raise DerError('BOOLEAN not 00 or FF')
    elif tag == 0x02:
        if len(c) == 0: raise DerError('empty INTEGER')
        if len(c) > 1 and ((c[0] == 0 and not c[1] & 0x80) or (c[0] == 0xff and c[1] & 0x80)): raise DerError('INTEGER not in its shortest form')
    elif tag == 0x03:
        if len(c) == 0: raise DerError('empty BIT STRING')
        if c[0] > 7 or (len(c) == 1 and c[0] != 0): raise DerError('BIT STRING with more than 7 unused bits')
    elif tag == 0x05:
        if len(c) != 0: raise DerError('NULL not empty')
    elif tag == 0x06:
        if len(c) == 0 or c[-1] & 0x80: raise DerError('OBJECT IDENTIFIER empty or cut short')
        first = True
        for i, x in enumerate(c):
            if (i == 0 or c[i - 1] & 0x80 == 0) and x == 0x80: raise DerError('OBJECT IDENTIFIER not in its shortest form')

def validate_der(b, max_elems=4000, max_depth=24, whole=True):
    """Section 9.3 item 2 over one element and everything inside it: the rules of the list (the order of SET OF
    elements and the omission of DEFAULT values are not checked). A level is a constructed element inside another;
    `whole`: nothing may follow the element (A12)."""
    count = [0]
    def walk(start, end, depth):
        for tag, hs, cs, ce in der_children(b, start, end):
            count[0] += 1
            if count[0] > max_elems: raise DerError('too many parts')
            if tag & 0x20:
                if depth > max_depth: raise DerError('nested too deeply')
                walk(cs, ce, depth + 1)
            elif tag & 0xc0 == 0: _check_primitive(tag, b[cs:ce])
    tag, cs, ce = der_header(b, 0, len(b))
    if whole and ce != len(b): raise DerError('something after the element')
    count[0] = 1
    if tag & 0x20: walk(cs, ce, 2)
    elif tag & 0xc0 == 0: _check_primitive(tag, b[cs:ce])

def _oid(c):
    parts = []; v = 0
    for x in c:
        v = (v << 7) | (x & 0x7f)
        if not x & 0x80: parts.append(v); v = 0
    first = parts[0]; head = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return '.'.join(map(str, head + parts[1:]))

OID_SIGNED_DATA = '1.2.840.113549.1.7.2'; OID_TSTINFO = '1.2.840.113549.1.9.16.1.4'
OID_CT = '1.2.840.113549.1.9.3'; OID_MD = '1.2.840.113549.1.9.4'
OID_ESS2 = '1.2.840.113549.1.9.16.2.47'; OID_ESS1 = '1.2.840.113549.1.9.16.2.12'
HASHES = {'2.16.840.1.101.3.4.2.1': ('sha256', 32), '2.16.840.1.101.3.4.2.2': ('sha384', 48), '2.16.840.1.101.3.4.2.3': ('sha512', 64),
          '1.3.14.3.2.26': ('sha1', 20)}
SIGALGS = {'1.2.840.113549.1.1.11': ('rsa', 'sha256'), '1.2.840.113549.1.1.12': ('rsa', 'sha384'), '1.2.840.113549.1.1.13': ('rsa', 'sha512'),
           '1.2.840.113549.1.1.1': ('rsa', None), '1.2.840.10045.4.3.2': ('ecdsa', 'sha256'), '1.2.840.10045.4.3.3': ('ecdsa', 'sha384'),
           '1.2.840.10045.4.3.4': ('ecdsa', 'sha512'), '1.3.101.112': ('ed25519', None)}

class Tok:
    """A cursor over a DER buffer."""
    def __init__(self, b): self.b = b
    def kids(self, el): return der_children(self.b, el[2], el[3])
    def el(self, start, end):
        tag, cs, ce = der_header(self.b, start, end); return (tag, start, cs, ce)
    def raw(self, el): return self.b[el[1]:el[3]]
    def content(self, el): return self.b[el[2]:el[3]]

def _expect(el, tag, what):
    if el is None or el[0] != tag: raise DerError(f'{what} is missing or of the wrong kind')
    return el

def _alg(t, el):
    _expect(el, 0x30, 'an algorithm identifier')
    k = t.kids(el)
    if not 1 <= len(k) <= 2: raise DerError('an algorithm identifier holds too many items')
    _expect(k[0], 0x06, 'an algorithm identifier')
    return _oid(t.content(k[0])), (k[1] if len(k) == 2 else None)

def _der_time(tag, c):
    """X.690 11.7 / 11.8: GeneralizedTime YYYYMMDDHHMMSS[.f]Z (no trailing zero in the fraction), UTCTime YYMMDDHHMMSSZ;
    denoting a moment that exists. Returns whole seconds since 1970."""
    try: s = c.decode('ascii')
    except UnicodeDecodeError: raise DerError('a time is not ASCII')
    if tag == 0x18:
        m = re.match(r'([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(\.[0-9]*[1-9])?Z\Z', s)
        if not m: raise DerError('a time is not in the form DER gives it')
        y = int(m.group(1))
    elif tag == 0x17:
        m = re.match(r'([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z\Z', s)
        if not m: raise DerError('a time is not in the form DER gives it')
        y = int(m.group(1)); y += 2000 if y < 50 else 1900
    else: raise DerError('a time of an unexpected kind')
    t = parse_time('%04d-%s-%sT%s:%s:%sZ' % (y, m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)))
    if t is None: raise DerError('a time that does not exist')
    return t

def _spki(t, el, strict_key=True):
    """SubjectPublicKeyInfo of the signing certificate, written exactly as its own specification sets out (item 2)."""
    k = t.kids(el)
    if len(k) != 2: raise DerError('the public key of a certificate is not written as its standard sets out')
    oid, params = _alg(t, k[0]); bit = _expect(k[1], 0x03, 'a public key')
    bits = t.content(bit)
    if oid == '1.2.840.113549.1.1.1':                                    # RSA, RFC 3279 2.3.1
        if params is None or params[0] != 0x05 or params[3] != params[2]: raise DerError('the public key of a certificate is not written as its standard sets out')
        if bits[0] != 0: raise DerError('BIT STRING with an unused bit in a public key')
        validate_der(bits[1:], 4000, 24)
        seq = t_el(bits[1:]); tt = Tok(bits[1:]); sk = tt.kids(seq)
        if seq[0] != 0x30 or len(sk) != 2 or sk[0][0] != 0x02 or sk[1][0] != 0x02: raise DerError('the public key of a certificate is not written as its standard sets out')
        n, e = tt.content(sk[0]), tt.content(sk[1])
        if n[0] & 0x80 or e[0] & 0x80: raise DerError('the public key of a certificate is not written as its standard sets out')
        return ('rsa', int.from_bytes(n, 'big'), int.from_bytes(e, 'big'))
    if oid == '1.2.840.10045.2.1':                                       # ECDSA, RFC 5480 2.2
        # A13 (changed after the vectors): item 2 names for ECDSA only the point of RFC 5480 2.2 (for RSA and Ed25519 it states the
        # parameters too), so parameters that are not a named curve are a key "on any other curve" (item 5, stamp-invalid), not a layout defect
        if params is None or params[0] != 0x06: return ('other-curve',)
        curve = _oid(t.content(params))
        size = {'1.2.840.10045.3.1.7': 32, '1.3.132.0.34': 48}.get(curve)
        if size is None: return ('other-curve',)
        if bits[0] != 0: raise DerError('BIT STRING with an unused bit in a public key')
        pt = bits[1:]
        if len(pt) != 1 + 2 * size or pt[0] != 4: raise DerError('the public key of a certificate is not written as its standard sets out')
        return ('ecdsa', size, int.from_bytes(pt[1:1 + size], 'big'), int.from_bytes(pt[1 + size:], 'big'))
    if oid == '1.3.101.112':                                             # Ed25519, RFC 8410 section 4
        if params is not None: raise DerError('the public key of a certificate is not written as its standard sets out')
        if bits[0] != 0 or len(bits) != 33: raise DerError('the public key of a certificate is not written as its standard sets out')
        return ('ed25519', bits[1:])
    return ('other-key',)

def t_el(b):
    tag, cs, ce = der_header(b, 0, len(b)); return (tag, 0, cs, ce)

def _hash_obj(name):
    from cryptography.hazmat.primitives import hashes
    return {'sha1': hashes.SHA1, 'sha256': hashes.SHA256, 'sha384': hashes.SHA384, 'sha512': hashes.SHA512}[name]()

def _need(k, i, tag, what):
    if i >= len(k) or k[i][0] != tag: raise DerError(f'{what} is missing or of the wrong kind')
    return k[i]

def _x509_name(t, el, what):
    """A Name is a SEQUENCE (RFC 5280); its attributes are not examined (A12)."""
    if el is None or el[0] != 0x30: raise DerError(f'{what} is not a sequence')

def _extension_list(t, kids):
    """The Extension elements of Extensions ::= SEQUENCE OF Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
    extnValue OCTET STRING }. Returns True if one is critical."""
    crit = False
    for ex in kids:
        xk = t.kids(ex)
        if ex[0] != 0x30 or not 2 <= len(xk) <= 3 or xk[0][0] != 0x06: raise DerError('an extension is not laid out as its standard sets out')
        if len(xk) == 3:
            if xk[1][0] != 0x01 or xk[2][0] != 0x04: raise DerError('an extension is not laid out as its standard sets out')
            crit = crit or t.content(xk[1]) == b'\xff'
        elif xk[1][0] != 0x04: raise DerError('an extension is not laid out as its standard sets out')
    return crit

def _certificate(t, el):
    """RFC 5280 4.1: Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }.
    Returns (not_before, not_after, spki element)."""
    ck = t.kids(el)
    if len(ck) != 3 or ck[0][0] != 0x30: raise DerError('a certificate is not laid out as its standard sets out')
    bk = t.kids(ck[0]); b = 0
    if b < len(bk) and bk[b][0] == 0xa0:
        vk = t.kids(bk[b])
        if len(vk) != 1 or vk[0][0] != 0x02: raise DerError('the certificate version is not laid out as its standard sets out')
        b += 1
    _need(bk, b, 0x02, 'the serial number'); b += 1
    _need(bk, b, 0x30, 'the signature algorithm'); b += 1
    _x509_name(t, bk[b] if b < len(bk) else None, 'the issuer'); b += 1
    val = _need(bk, b, 0x30, 'the validity'); b += 1
    vk = t.kids(val)
    if len(vk) != 2 or vk[0][0] not in (0x17, 0x18) or vk[1][0] not in (0x17, 0x18): raise DerError('the validity is not laid out as its standard sets out')
    nb, na = _der_time(vk[0][0], t.content(vk[0])), _der_time(vk[1][0], t.content(vk[1]))
    _x509_name(t, bk[b] if b < len(bk) else None, 'the subject'); b += 1
    spki = _need(bk, b, 0x30, 'the public key info'); b += 1
    sk = t.kids(spki)
    if len(sk) != 2 or sk[1][0] != 0x03: raise DerError('the public key of a certificate is not written as its standard sets out')
    _alg(t, sk[0])
    for tag in (0x81, 0x82):
        if b < len(bk) and bk[b][0] == tag: b += 1
    if b < len(bk) and bk[b][0] == 0xa3: b += 1           # "The certificate's extensions are not examined" (9.3 item 6)
    if b != len(bk): raise DerError('a certificate body holds more than it should')
    return nb, na, spki

def _tstinfo(tt, tel):
    """RFC 3161 2.4.2 TSTInfo, in its order, each member at most once. Returns (alg_oid, hashed, gen_time, accuracy_s, critical)."""
    _expect(tel, 0x30, 'the statement'); tk = tt.kids(tel); q = 0
    tv = _need(tk, q, 0x02, 'the statement version'); q += 1
    if tt.content(tv) != b'\x01': raise DerError('the statement is of a version other than 1')
    _need(tk, q, 0x06, 'the policy'); q += 1
    mi = _need(tk, q, 0x30, 'the message imprint'); q += 1
    mik = tt.kids(mi)
    if len(mik) != 2: raise DerError('the message imprint holds the wrong number of items')
    mi_oid, _par = _alg(tt, mik[0]); _expect(mik[1], 0x04, 'the hashed message')     # A10: parameters of the hash algorithm are not examined
    hashed = tt.content(mik[1])
    _need(tk, q, 0x02, 'the serial number'); q += 1
    gt = _need(tk, q, 0x18, 'the generation time'); q += 1
    gen = _der_time(0x18, tt.content(gt))
    acc = 0
    if q < len(tk) and tk[q][0] == 0x30:
        ak = tt.kids(tk[q]); a = 0
        if a < len(ak) and ak[a][0] == 0x02:
            acc = int.from_bytes(tt.content(ak[a]), 'big', signed=True); a += 1
        if a < len(ak) and ak[a][0] == 0x80: a += 1
        if a < len(ak) and ak[a][0] == 0x81: a += 1
        if a != len(ak): raise DerError('the statement says how exact its time is in a way that cannot be read')
        q += 1
    if q < len(tk) and tk[q][0] == 0x01: q += 1
    if q < len(tk) and tk[q][0] == 0x02: q += 1
    if q < len(tk) and tk[q][0] == 0xa0:
        if len(tt.kids(tk[q])) != 1: raise DerError('the service name is not laid out as its standard sets out')
        q += 1
    crit = False
    if q < len(tk) and tk[q][0] == 0xa1:
        exts = tt.kids(tk[q])
        if len(exts) > 16: raise DerError('more than 16 extensions')
        crit = _extension_list(tt, exts); q += 1
    if q != len(tk): raise DerError('the statement holds more than it should')
    return mi_oid, hashed, gen, acc, crit

def _ess(t, el, v2):
    """SigningCertificate / SigningCertificateV2 (RFC 2634 5.4, RFC 5035 3); returns (hash_name, certHash) of the first identifier."""
    if el[0] != 0x30: raise DerError('the signing-certificate attribute is not a sequence')
    k = t.kids(el)
    if not 1 <= len(k) <= 2 or k[0][0] != 0x30: raise DerError('the signing-certificate attribute is not laid out as its standard sets out')
    ids = t.kids(k[0])
    if not ids or len(ids) > 8: raise DerError('the signing-certificate attribute holds none or more than 8 identifiers')
    out = None
    for n, idel in enumerate(ids):
        if idel[0] != 0x30: raise DerError('an identifier is not a sequence')
        ik = t.kids(idel); i = 0; alg = 'sha256' if v2 else 'sha1'
        if v2 and i < len(ik) and ik[i][0] == 0x30:
            oid, _p = _alg(t, ik[i]); alg = HASHES.get(oid, (None,))[0]; i += 1
        h = _need(ik, i, 0x04, 'a certificate hash'); i += 1
        if i < len(ik) and ik[i][0] == 0x30: i += 1                      # issuerSerial: not compared
        if i != len(ik): raise DerError('an identifier holds more than it should')
        if n == 0: out = (alg, t.content(h))
    return out

def check_stamp(token, stamped, trusted=None, methods=None):
    """Section 9.3 for one TimeStampToken `token` (bytes) against `stamped` (the 32-byte digest of the record).
    Returns {'state': 'valid'|'untrusted'|'unavailable', 'time': seconds|None, 'authority': b64u digest of the TSA
    certificate|None}; raises Refused(stamp-bad-data | stamp-wrong-data | stamp-invalid)."""
    methods = methods or Methods()
    if len(token) > MAX_TOKEN: raise DerError('a token is at most 12,288 bytes')
    # ---- 1, 2: layout (RFC 3161, RFC 5652, and the certificates RFC 5652 carries: A12) and the DER rules
    validate_der(token)
    t = Tok(token); ci = t.el(0, len(token))
    _expect(ci, 0x30, 'the wrapper'); k = t.kids(ci)
    if len(k) != 2 or k[0][0] != 0x06 or _oid(t.content(k[0])) != OID_SIGNED_DATA or k[1][0] != 0xa0: raise DerError('the wrapper is missing or of the wrong kind')
    inner = t.kids(k[1])
    if len(inner) != 1: raise DerError('the signed data is missing')
    sd = _expect(inner[0], 0x30, 'the signed data'); sk = t.kids(sd); i = 0
    ver = _need(sk, i, 0x02, 'the version'); i += 1
    if t.content(ver) != b'\x03': raise DerError('the signed data is of a version other than 3')
    dalgs = _need(sk, i, 0x31, 'the digest algorithms'); i += 1
    if len(t.kids(dalgs)) > 8: raise DerError('more than 8 digest algorithms')
    for a in t.kids(dalgs): _alg(t, a)
    eci = _need(sk, i, 0x30, 'the encapsulated content'); i += 1
    ek = t.kids(eci)
    if len(ek) != 2 or ek[0][0] != 0x06 or _oid(t.content(ek[0])) != OID_TSTINFO or ek[1][0] != 0xa0: raise DerError('the kind of content is missing or of the wrong kind')
    ev = t.kids(ek[1])
    if len(ev) != 1 or ev[0][0] != 0x04: raise DerError('the content is missing')
    tst_bytes = t.content(ev[0])
    cert_els = []
    if i < len(sk) and sk[i][0] == 0xa0:
        ch = t.kids(sk[i])
        if len(ch) > 8: raise DerError('more than 8 certificates')
        for c in ch:
            if c[0] == 0x30: cert_els.append(c)       # A12: an element that is not a SEQUENCE is not read as a certificate
        i += 1
    if i < len(sk) and sk[i][0] == 0xa1: i += 1
    sis = _need(sk, i, 0x31, 'the signer information'); i += 1
    if i != len(sk): raise DerError('the signed data holds more than it should')
    sis_k = t.kids(sis)
    if len(sis_k) != 1: raise DerError('the signed data must hold exactly one signer')
    si = _expect(sis_k[0], 0x30, 'the signer information'); ik = t.kids(si); j = 0
    sv = _need(ik, j, 0x02, 'the signer version'); j += 1
    svv = t.content(sv)
    if svv not in (b'\x01', b'\x03'): raise DerError('the signer is of a version other than 1 or 3')
    sid_tag = 0x30 if svv == b'\x01' else 0x80                 # RFC 5652 5.3: version 1 = issuerAndSerialNumber, 3 = subjectKeyIdentifier
    sid = _need(ik, j, sid_tag, 'the signer identifier'); j += 1
    sdig_oid, _p = _alg(t, ik[j] if j < len(ik) else None); j += 1
    sattrs = _need(ik, j, 0xa0, 'the signed attributes'); j += 1
    salg_oid, _p2 = _alg(t, ik[j] if j < len(ik) else None); j += 1
    sig_el = _need(ik, j, 0x04, 'the signature'); j += 1
    if j < len(ik) and ik[j][0] == 0xa1: j += 1
    if j != len(ik): raise DerError('the signer information holds more than it should')
    certs = [(c, _certificate(t, c)) for c in cert_els]     # A12: every certificate is read as RFC 5280 lays it out
    # the TSTInfo, read from its OCTET STRING under the same rules
    validate_der(tst_bytes)
    tt = Tok(tst_bytes)
    mi_oid, hashed, gen_time, accuracy_s, critical = _tstinfo(tt, t_el(tst_bytes))
    # attributes: syntax (SET OF Attribute; at most 16, at most 4 values each)
    attrs = t.kids(sattrs)
    if len(attrs) > 16: raise DerError('more than 16 signed attributes')
    found = {}; dup = None
    for a in attrs:
        ak = t.kids(a)
        if a[0] != 0x30 or len(ak) != 2 or ak[0][0] != 0x06 or ak[1][0] != 0x31: raise DerError('a signed attribute is not laid out as its standard sets out')
        vals = t.kids(ak[1])
        if len(vals) > 4: raise DerError('more than 4 values in an attribute')
        oid = _oid(t.content(ak[0]))
        if oid in (OID_CT, OID_MD, OID_ESS2, OID_ESS1):
            if oid in found: dup = dup or 'an attribute appears twice'
            found[oid] = vals
    # ---- 3: the imprint
    if mi_oid != '2.16.840.1.101.3.4.2.1' or len(hashed) != 32 or hashed != stamped:
        raise Refused('stamp-wrong-data', 'made for something else')
    # ---- 4: signed attributes
    if dup: raise Refused('stamp-invalid', dup)
    for oid in (OID_CT, OID_MD):
        if oid not in found or len(found[oid]) != 1: raise Refused('stamp-invalid', 'content type or message digest attribute missing or not exactly one value')
    ctv, mdv = found[OID_CT][0], found[OID_MD][0]
    if ctv[0] != 0x06 or _oid(t.content(ctv)) != OID_TSTINFO: raise Refused('stamp-invalid', 'content type attribute')
    if sdig_oid not in HASHES or sdig_oid == '1.3.14.3.2.26': raise Refused('stamp-invalid', 'the signer digest algorithm is not SHA-256, SHA-384 or SHA-512')
    hn = HASHES[sdig_oid][0]
    if mdv[0] != 0x04 or t.content(mdv) != hashlib.new(hn, tst_bytes).digest(): raise Refused('stamp-invalid', 'message digest attribute')
    if OID_ESS2 in found:
        if len(found[OID_ESS2]) != 1: raise Refused('stamp-invalid', 'signing-certificate attribute must hold exactly one value')
        ess_alg, cert_hash = _ess(t, found[OID_ESS2][0], True)
    elif OID_ESS1 in found:
        if len(found[OID_ESS1]) != 1: raise Refused('stamp-invalid', 'signing-certificate attribute must hold exactly one value')
        ess_alg, cert_hash = _ess(t, found[OID_ESS1][0], False)
    else: raise Refused('stamp-invalid', 'no signing-certificate attribute')
    if ess_alg not in (('sha256', 'sha384', 'sha512') if OID_ESS2 in found else ('sha1',)): raise Refused('stamp-invalid', 'hash algorithm of the certificate identifier')
    signer = None
    for c, info in certs:
        if hashlib.new(ess_alg, t.raw(c)).digest() == cert_hash: signer = (c, info); break
    if signer is None: raise Refused('stamp-invalid', 'the token does not carry the certificate it says signed it')
    not_before, not_after, spki_el = signer[1]
    pub = _spki(t, spki_el)          # the signing certificate's key, written as its own specification sets out
    # ---- 5: the signature
    alg_kind, alg_hash = SIGALGS.get(salg_oid, (None, None))
    if alg_kind is None: raise Refused('stamp-invalid', 'signature algorithm not accepted')
    if alg_hash is not None and alg_hash != hn: raise Refused('stamp-invalid', 'the signature algorithm does not name the signer digest algorithm')
    signed = b'\x31' + t.b[sattrs[1] + 1: sattrs[3]]
    sig = t.content(sig_el)
    unavailable = False
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
    if pub[0] == 'rsa':
        if alg_kind != 'rsa': raise Refused('stamp-invalid', 'algorithm and key do not agree')
        n, e = pub[1], pub[2]
        if not (2048 <= n.bit_length() <= 8192) or e % 2 == 0 or not (3 <= e <= 2**32 - 1): raise Refused('stamp-invalid', 'an RSA key whose size or public number is not accepted')
        if not methods.can('RS256'): unavailable = True; methods.used_missing.add('RS256')      # A11: the draft names no switch for time-stamp methods
        else:
            try: rsa.RSAPublicNumbers(e, n).public_key().verify(sig, signed, padding.PKCS1v15(), _hash_obj(hn)); ok = True
            except Exception: ok = False
            if not ok: raise Refused('stamp-invalid', "the signature does not fit the certificate it names")
    elif pub[0] == 'ecdsa':
        if alg_kind != 'ecdsa': raise Refused('stamp-invalid', 'algorithm and key do not agree')
        curve = ec.SECP256R1() if pub[1] == 32 else ec.SECP384R1()
        try: pk = ec.EllipticCurvePublicNumbers(pub[2], pub[3], curve).public_key()
        except Exception: raise Refused('stamp-invalid', 'not a point of the curve')
        if not methods.can('ES256'): unavailable = True; methods.used_missing.add('ES256')
        else:
            try: pk.verify(sig, signed, ec.ECDSA(_hash_obj(hn))); ok = True
            except Exception: ok = False
            if not ok: raise Refused('stamp-invalid', 'the signature does not fit the certificate it names')
    elif pub[0] == 'ed25519':
        if alg_kind != 'ed25519': raise Refused('stamp-invalid', 'algorithm and key do not agree')
        if not ed25519_key_ok(pub[1]): raise Refused('stamp-invalid', 'an Ed25519 key under which anyone can sign')
        if not methods.can('Ed25519'): unavailable = True; methods.used_missing.add('Ed25519')
        elif ed25519_verify(pub[1], sig, signed) != 'valid': raise Refused('stamp-invalid', 'the signature does not fit the certificate it names')
    else: raise Refused('stamp-invalid', 'a kind of key that is not accepted')
    # ---- 6
    if not (not_before <= gen_time <= not_after): raise Refused('stamp-invalid', 'genTime outside the validity of the certificate')
    if accuracy_s > 300: raise Refused('stamp-invalid', 'accuracy above 300 seconds')
    if critical: raise Refused('stamp-invalid', 'a critical extension')
    authority = b64u_enc(sha256(t.raw(signer[0])))
    if unavailable: return {'state': 'unavailable', 'time': None, 'authority': None}
    state = 'valid' if isinstance(trusted, list) and authority in trusted else 'untrusted'
    return {'state': state, 'time': gen_time, 'authority': authority}

# --------------------------------------------------------------------------------------------------------------
# 7. the log: entries, chains, findings, cancellation, heads, the three answers (Sections 6 to 10)
# --------------------------------------------------------------------------------------------------------------
MAX_ENTRIES = 100000; MAX_LINE = 131072
ENTRY_SHAPES = [  # (required member, optional members)
    ('slip', ()), ('stub', ('countersignature', 'approval')), ('pass', ()), ('cancellation', ('stamps',)),
    ('acknowledgement', ()), ('seal', ('stamps',))]
FORMAT_ONLY_KINDS = ('refusal', 'terms', 'vouching', 'withdrawal')     # Section 9.1: a core verifier reports unknown-entry
FINDING_ORDER = ['action-not-allowed', 'prohibited', 'party-not-allowed', 'outside-valid-time', 'amount-missing', 'over-limit',
                 'over-each-limit', 'over-count-limit', 'over-period-limit', 'countersignature-missing', 'approval-missing',
                 'after-cancellation', 'pass-not-allowed', 'pass-wider']

class Entry:
    def __init__(self, index, line):
        self.index = index; self.line = line; self.kind = 'unreadable'; self.problems = []; self.findings = []
        self.fingerprint = None; self.rec = None; self.cs = None; self.ap = None; self.compared = False
        self.reached_signatures = False        # read as far as its signatures (10.1 answer 2)
        self.states = []                        # every signature state met in the entry
        self.when = None; self.depth = None; self.stamps = []; self.obj = None
        self.slip_digest = None; self.pass_digest = None; self.sig_ok = False; self.sig_failed = False; self.sound_at_read = False

def _parse_line(line_bytes):
    """11.4: each line is a JSON object in the canonical form, with records as values. Returns (obj | None, code | None)."""
    if line_bytes[:3] == b'\xef\xbb\xbf' or line_bytes == b'': return None, 'not-json'
    try: text = line_bytes.decode('utf-8')
    except UnicodeDecodeError: return None, 'not-json'
    try: v = json.loads(text)
    except Exception: return None, 'not-json'
    if not isinstance(v, dict): return None, 'unknown-entry'                  # A14: a line that is not an object
    try: parse_canonical(line_bytes, max_depth=16)                              # the depth rule of 11.2 is for a record's content
    except Refused: return None, 'line-not-canonical'
    return v, None

def check_log(text, expected_root=None, expected_size=None, trusted_passkeys=None, trusted_recorders=None,
              trusted_tsas=None, methods=None):
    methods = methods or Methods()
    out = {'problems': [], 'notes': [], 'entries': [], 'size': 0, 'root': None}
    if isinstance(text, bytes): text = text.decode('utf-8', 'surrogateescape')
    parts = text.split('\n')
    if parts and parts[-1] == '': parts = parts[:-1]
    if not parts:
        out['problems'].append('not-json'); out['answers'] = _answers(out, [], methods); return out
    if len(parts) > MAX_ENTRIES: out['problems'].append('too-large')
    lines = [p.encode('utf-8', 'surrogateescape') for p in parts]
    leaves = lines
    out['size'] = len(lines); out['root'] = b64u_enc(tree_root(leaves))
    if expected_root is not None and expected_root != out['root']: out['problems'].append('root-mismatch')
    if expected_size is not None and (not _is_int(expected_size) or expected_size != len(lines)): 
        if 'root-mismatch' not in out['problems']: out['problems'].append('root-mismatch')
    entries = [Entry(i, l) for i, l in enumerate(lines)]
    ctx = type('Ctx', (), {})()
    ctx.methods = methods; ctx.trusted_passkeys = trusted_passkeys; ctx.trusted_recorders = trusted_recorders
    ctx.trusted_tsas = trusted_tsas; ctx.ids = {}; ctx.slips = {}; ctx.passes = {}; ctx.approval_ids = {}; ctx.chains = {}
    ctx.cancellations = {}; ctx.seals = []; ctx.entries = entries; ctx.leaves = leaves; ctx.acks = []
    ctx.notes = set()
    # ---------------- reading, in log order
    for e in entries: _read_entry(ctx, e)
    # ---------------- what the whole log settles: acknowledgements, time-stamps and dates
    _settle_acks(ctx); _settle_stamps(ctx)
    # ---------------- comparison with the permission (Sections 7, 8, 10.2)
    _compare(ctx)
    out['entries'] = entries; out['notes'] = sorted(ctx.notes); out['answers'] = _answers(out, entries, methods)
    out['existed_by'] = {i: time_text(t) for i, t in sorted(ctx.existed_by.items())}
    out['last_counted_head'] = ctx.last_counted      # that head's counted time-stamp reaches the entries before it
    return out

def _read_entry(ctx, e):
    if len(e.line) > MAX_LINE: e.problems.append('too-large'); return           # 11.4: checked before the line is read
    obj, code = _parse_line(e.line)
    if code: e.problems.append(code); return
    shape = None
    for req, opt in ENTRY_SHAPES:
        if req in obj and set(obj) <= {req, *opt}: shape = req; break
    if shape is None: e.problems.append('unknown-entry'); return
    e.kind = shape; e.obj = obj
    try:
        {'slip': _read_slip, 'stub': _read_stub, 'pass': _read_pass, 'cancellation': _read_cancellation,
         'acknowledgement': _read_ack, 'seal': _read_seal}[shape](ctx, e, obj)
    except Exception:                       # 10.1, 18: anything unexpected is a problem (check-failed), never a pass, never a crash
        e.problems.append('check-failed'); e.reached_signatures = False
    e.sound_at_read = not e.problems

def _note_state(e, states):
    e.states += list(states)
    if 'invalid' in states: e.sig_failed = True

def _register_id(ctx, e, rec, what):
    i = rec.content['id']
    if i in ctx.ids: e.problems.append('duplicate-id')
    else: ctx.ids[i] = e.index

def _read_slip(ctx, e, obj):
    r = read_record(obj['slip'], 'slip'); e.rec = r; e.fingerprint = r.digest
    if r.problems:
        e.problems += r.problems
        if r.raw_digest and r.raw_digest not in ctx.slips: ctx.slips[r.raw_digest] = e       # named by digest, but not sound: slip-unusable
        return
    e.when = None
    _register_id(ctx, e, r, 'slip')
    if r.digest in ctx.slips: e.problems.append('duplicate-slip')
    iss = r.content['issuer']
    e.problems += check_passkey_record(r, iss, ctx.methods)
    e.reached_signatures = True; _note_state(e, r.states)
    if ctx.trusted_passkeys is not None:
        tp = check_key(iss['key'], ['ES256', 'RS256', 'Ed25519'])[1]
        if tp not in ctx.trusted_passkeys: e.problems.append('issuer-not-expected')
    else: ctx.notes.add('the issuer key of the permission was not compared with a trusted key')
    e.sig_ok = r.states[0] == 'valid'
    if r.digest not in ctx.slips:
        ctx.slips[r.digest] = e

def _slip_for(ctx, e, digest):
    """4.8: the named permission must be earlier in the log and sound."""
    s = ctx.slips.get(digest)
    if s is None or s.index >= e.index: e.problems.append('slip-missing'); return None
    if not s.sound_at_read: e.problems.append('slip-unusable'); return None
    return s

def _pass_for(ctx, e, digest, slip_digest):
    p = ctx.passes.get(digest)
    if p is None or p.index >= e.index or not p.sound_at_read: e.problems.append('pass-missing'); return None
    if p.rec.content['slip'] != slip_digest: e.problems.append('pass-mismatch'); return None
    return p

def _keys_for(ctx, slip, pas):
    return pas.rec.content['to']['keys'] if pas is not None else slip.rec.content['agent']['keys']

def _chain_step(ctx, e, key, r):
    c = r.content; w = parse_time(c['when']); last = ctx.chains.get(key)
    if last is None:
        if c['seq'] != 0: e.problems.append('chain-broken')
    else:
        if c['seq'] != last['seq'] + 1 or c.get('previous') != last['digest']: e.problems.append('chain-broken')
        if w < last['when']: e.problems.append('time-went-backwards')
    ctx.chains[key] = {'seq': c['seq'], 'digest': r.digest, 'when': w}

def _read_stub(ctx, e, obj):
    r = read_record(obj['stub'], 'stub'); e.rec = r; e.fingerprint = r.digest
    if r.problems: e.problems += r.problems; return
    c = r.content; e.when = parse_time(c['when'])
    _register_id(ctx, e, r, 'stub')
    slip = _slip_for(ctx, e, c['slip'])
    if slip is None: return
    pas = None
    if 'pass' in c:
        pas = _pass_for(ctx, e, c['pass'], c['slip'])
        if pas is None: return
    e.slip_digest = c['slip']; e.pass_digest = c.get('pass')
    e.problems += check_hybrid(r, _keys_for(ctx, slip, pas), ctx.methods)
    _note_state(e, r.states)
    _chain_step(ctx, e, (c['slip'], c.get('pass')), r)
    if 'terms' in c: e.problems.append('terms-not-found')
    sc = slip.rec.content
    # ---- countersignature (6)
    cs_ok_read = True
    if 'countersignature' in obj:
        cr = read_record(obj['countersignature'], 'countersignature'); e.cs = cr
        if cr.problems: e.problems += cr.problems
        else:
            if cr.content['stub'] != r.digest: e.problems.append('countersignature-wrong-stub')
            svc = next((s for s in sc['with'] if s['id'] == c.get('with')), None)
            if svc is None or 'keys' not in svc: e.problems.append('countersignature-not-possible')
            else:
                if check_hybrid(cr, svc['keys'], ctx.methods): e.problems.append('countersignature-invalid')
                _note_state(e, cr.states)
    # ---- approval (6)
    has_ap = 'approval' in obj
    if 'approval' in c and not has_ap: e.problems.append('approval-not-found')
    if has_ap:
        ar = read_record(obj['approval'], 'approval'); e.ap = ar
        if 'approval' not in c: e.problems.append('approval-mismatch')
        if ar.problems: e.problems += ar.problems
        else:
            a = ar.content
            if 'approval' in c and c['approval'] != ar.digest: e.problems.append('approval-mismatch')
            for k in ('slip', 'action', 'amount', 'with', 'details'):
                if (k in a) != (k in c) or (k in a and a[k] != c[k]): e.problems.append('approval-mismatch'); break
            i = a['id']
            if i in ctx.approval_ids: e.problems.append('approval-reused')
            elif i in ctx.ids: e.problems.append('duplicate-id')
            else: ctx.ids[i] = e.index
            ctx.approval_ids.setdefault(i, e.index)
            p = check_passkey_record(ar, sc['issuer'], ctx.methods, fail_code='approval-invalid')
            e.problems += p; _note_state(e, ar.states)
            aw = parse_time(a['when'])
            if aw - e.when > 300: e.problems.append('approval-dated-after-stub')      # A19: more than 300 s after the receipt
    e.reached_signatures = True
    e.problems = _dedupe(e.problems)

def _dedupe(l):
    out = []
    for x in l:
        if x not in out: out.append(x)
    return out

def _read_pass(ctx, e, obj):
    r = read_record(obj['pass'], 'pass'); e.rec = r; e.fingerprint = r.digest
    if r.problems:
        e.problems += r.problems
        if r.raw_digest and r.raw_digest not in ctx.passes: ctx.passes[r.raw_digest] = e
        return
    c = r.content; e.when = parse_time(c['when'])
    _register_id(ctx, e, r, 'pass')
    slip = _slip_for(ctx, e, c['slip'])
    if slip is None: return
    parent = None
    if 'from' in c:
        parent = _pass_for(ctx, e, c['from'], c['slip'])
        if parent is None: return
        e.depth = parent.depth + 1
    else: e.depth = 1
    e.slip_digest = c['slip']; e.pass_digest = c.get('from')
    if e.depth > 10: e.problems.append('pass-too-deep')
    e.problems += check_hybrid(r, _keys_for(ctx, slip, parent), ctx.methods)
    _note_state(e, r.states); e.reached_signatures = True
    if r.digest not in ctx.passes: ctx.passes[r.digest] = e
    e.problems = _dedupe(e.problems)

def _read_cancellation(ctx, e, obj):
    r = read_record(obj['cancellation'], 'cancellation'); e.rec = r; e.fingerprint = r.digest
    if r.problems: e.problems += r.problems; return
    c = r.content; e.when = parse_time(c['when'])
    _register_id(ctx, e, r, 'cancellation')
    slip = _slip_for(ctx, e, c['slip'])
    if slip is None: return
    e.slip_digest = c['slip']
    e.problems += check_passkey_record(r, slip.rec.content['issuer'], ctx.methods, fail_code='cancellation-invalid')
    _note_state(e, r.states); e.reached_signatures = True
    e.sig_ok = r.states[0] == 'valid' and slip.sig_ok
    ctx.cancellations[r.digest] = e
    if 'stamps' in obj: _read_stamps(ctx, e, obj['stamps'], r, slip)

def _read_ack(ctx, e, obj):
    r = read_record(obj['acknowledgement'], 'acknowledgement'); e.rec = r; e.fingerprint = r.digest
    if r.problems: e.problems += r.problems; return
    c = r.content; e.when = parse_time(c['when'])
    _register_id(ctx, e, r, 'acknowledgement')
    slip = _slip_for(ctx, e, c['slip'])
    if slip is None: return
    pas = None
    if 'pass' in c:
        pas = _pass_for(ctx, e, c['pass'], c['slip'])
        if pas is None: return
    canc = ctx.cancellations.get(c['cancellation'])
    if canc is None or canc.index >= e.index or canc.rec.content['slip'] != c['slip'] or not canc.sound_at_read:
        e.problems.append('cancellation-not-found')
    e.problems += check_hybrid(r, _keys_for(ctx, slip, pas), ctx.methods)
    _note_state(e, r.states); e.reached_signatures = True
    e.slip_digest = c['slip']; ctx.acks.append(e)
    e.problems = _dedupe(e.problems)

def _settle_acks(ctx):
    """4.8: a cancellation named by an acknowledgement is judged again once the whole log has been read."""
    for e in ctx.acks:
        canc = ctx.cancellations.get(e.rec.content['cancellation'])
        if canc is not None and canc.problems and 'cancellation-not-found' not in e.problems: e.problems.append('cancellation-not-found')

def _read_seal(ctx, e, obj):
    r = read_record(obj['seal'], 'seal'); e.rec = r; e.fingerprint = r.digest
    if r.problems: e.problems += r.problems; return
    c = r.content; e.when = parse_time(c['when'])
    _register_id(ctx, e, r, 'seal')
    e.problems += check_hybrid(r, c['by']['keys'], ctx.methods)
    _note_state(e, r.states); e.reached_signatures = True
    if c['size'] != e.index or c['root'] != b64u_enc(tree_root(ctx.leaves[:e.index])): e.problems.append('seal-mismatch')
    prev = ctx.seals[-1] if ctx.seals else None
    # A24: "size is its own place in the log": the head at index i covers the i entries before it
    if (prev is None and 'previous' in c) or (prev is not None and c.get('previous') != prev.fingerprint): e.problems.append('seal-chain-broken')
    if prev is not None and e.when < prev.when: e.problems.append('time-went-backwards')
    if ctx.trusted_recorders is not None:
        if key_set_digest(c['by']['keys']) not in ctx.trusted_recorders: e.problems.append('sealer-not-expected')
    else: ctx.notes.add('the key sets of recorders were not compared with trusted key sets')
    ctx.seals.append(e)
    if 'stamps' in obj: _read_stamps(ctx, e, obj['stamps'], r, None)
    e.problems = _dedupe(e.problems)

def _read_stamps(ctx, e, stamps, rec, slip):
    """9.3: time-stamps are read only if none of the record's own signatures failed."""
    try: dec = decode_stamps(stamps)
    except Refused as x: e.problems.append(x.code); return
    if 'invalid' in rec.states or any(p in e.problems for p in ('signature-invalid', 'cancellation-invalid')): return
    all_verified = all(s == 'valid' for s in rec.states) and (slip is None or slip.sig_ok)
    digest = b64u_dec(rec.digest)
    for d in dec:
        if d['kind'] == 'block':
            ctx.notes.add('a block time-stamp is not counted by a core verifier'); e.stamps.append({'kind': 'block', 'counted': False}); continue
        try:
            res = check_stamp(bytes.fromhex(d['token']), digest, ctx.trusted_tsas, ctx.methods)
        except Refused as x:
            e.problems.append(x.code); e.stamps.append({'kind': 'service', 'error': x.code}); continue
        counted = res['state'] == 'valid' and all_verified
        if res['state'] == 'unavailable': e.states.append('unavailable')
        e.stamps.append({'kind': 'service', 'state': res['state'], 'time': res['time'], 'counted': counted, 'authority': res['authority']})
    e.problems = _dedupe(e.problems)

def _settle_stamps(ctx):
    """9.3: "existed by", dated-after-stamp."""
    # earliest counted time of each sound head
    head_t = {}
    for h in ctx.seals:
        ts = [s['time'] for s in h.stamps if s.get('counted')]
        if ts and not h.problems: head_t[h.index] = min(ts)
    for e in ctx.entries:
        if e.kind in ('seal', 'cancellation'):
            ts = [s['time'] for s in e.stamps if s.get('counted')]
            if ts and e.when is not None and e.when > min(ts) + 300: e.problems.append('dated-after-stamp')
        if e.rec is not None and e.rec.encoded_ok:
            later = [t for i, t in head_t.items() if i > e.index]
            if later:
                by = min(later); whens = [e.when]
                for sub in (e.cs, e.ap):
                    if sub is not None and sub.content is not None and 'when' in sub.content: whens.append(parse_time(sub.content['when']))
                if any(w is not None and w > by + 300 for w in whens) and 'dated-after-stamp' not in e.problems: e.problems.append('dated-after-stamp')
    for e in ctx.entries: e.problems = _dedupe(e.problems)
    # 9.3: "existed by", never "existed at"; and which entries the last counted time-stamp reaches
    ctx.existed_by = {}
    for e in ctx.entries:
        later = [t for i, t in head_t.items() if i > e.index]
        if later: ctx.existed_by[e.index] = min(later)
    counted = sorted(i for i in head_t)
    ctx.last_counted = (counted[-1] if counted else None)

def _within(when, c): return parse_time(c['validFrom']) <= when < parse_time(c['validUntil'])

def _compare(ctx):
    """Sections 7, 8, 10.2: judge each sound, verified receipt and delegation against its permission."""
    eff = {}
    for e in ctx.entries:
        if e.kind == 'cancellation' and e.sound_at_read and e.sig_ok: eff.setdefault(e.slip_digest, e.index)      # A20: sound when read, passkey verified, and its permission's
    def eligible(e):
        r = e.rec
        return (e.kind in ('stub', 'pass') and r is not None and r.encoded_ok and not e.problems and 'valid' in r.states
                and 'invalid' not in r.states and ctx.slips[e.slip_digest].sig_ok)
    for e in ctx.entries:
        if e.kind in ('stub', 'pass') and eligible(e): e.compared = True
    def chain_of(e):
        out = []; d = e.pass_digest
        while d is not None:
            p = ctx.passes[d]; out.append(p); d = p.pass_digest
        return out                      # nearest delegation first
    totals = {}; counts = {}; compared_stubs = []
    for e in ctx.entries:
        if not e.compared: continue
        slip = ctx.slips[e.slip_digest]; sc = slip.rec.content; c = e.rec.content; f = []
        if e.kind == 'pass':
            parent = ctx.passes[c['from']] if 'from' in c else None
            wr = parent.rec.content if parent else sc
            if e.depth > sc.get('passes', 0): f.append('pass-not-allowed')
            if any(a not in wr['actions'] for a in c['actions']) or parse_time(c['validFrom']) < parse_time(wr['validFrom']) or parse_time(c['validUntil']) > parse_time(wr['validUntil']):
                f.append('pass-wider')
            if not _within(e.when, wr): f.append('outside-valid-time')
            if e.slip_digest in eff and e.index > eff[e.slip_digest]: f.append('after-cancellation')
            e.findings = [x for x in FINDING_ORDER if x in f]
            continue
        chain = chain_of(e); a = c.get('amount'); act = c['action']
        if act not in sc['actions'] or any(act not in p.rec.content['actions'] for p in chain): f.append('action-not-allowed')
        if SHARED_ACTIONS.get(act) in sc['never']: f.append('prohibited')
        if 'with' in c and c['with'] not in [s['id'] for s in sc['with']]: f.append('party-not-allowed')
        if not _within(e.when, sc) or any(not _within(e.when, p.rec.content) for p in chain): f.append('outside-valid-time')
        scopes = [('slip', sc)] + [(p.fingerprint, p.rec.content) for p in chain]
        missing = False
        for sid, cont in scopes:
            counts[(sid, act)] = counts.get((sid, act), 0) + 1
            for lim in cont['limits']:
                if lim['action'] == act and 'unit' in lim and (a is None or a['unit'] != lim['unit']): missing = True
        # accumulate the amount once per scope and unit
        for sid, cont in scopes:
            if a is not None: totals[(sid, act, a['unit'])] = totals.get((sid, act, a['unit']), 0) + a['value']
        for sid, cont in scopes:
            for lim in cont['limits']:
                if lim['action'] != act or 'per' in lim: continue
                if 'max' in lim and a is not None and a['unit'] == lim['unit'] and totals[(sid, act, lim['unit'])] > lim['max']: f.append('over-limit')
                if 'each' in lim and a is not None and a['unit'] == lim['unit'] and a['value'] > lim['each']: f.append('over-each-limit')
                if 'count' in lim and counts[(sid, act)] > lim['count']: f.append('over-count-limit')
        for cond in sc['requires']:
            if 'action' in cond and cond['action'] != act: continue
            if 'above' in cond:
                if a is None or a['unit'] != cond['unit']: missing = True; continue
                if a['value'] <= cond['above']: continue
            if cond['need'] == 'countersignature' and e.cs is None: f.append('countersignature-missing')
            if cond['need'] == 'approval' and e.ap is None: f.append('approval-missing')
        if missing: f.append('amount-missing')
        if e.slip_digest in eff and e.index > eff[e.slip_digest]: f.append('after-cancellation')
        if any('pass-not-allowed' in p.findings for p in chain): f.append('pass-not-allowed')
        e.findings = f; e._scopes = scopes; e._chain = chain; compared_stubs.append(e)
    # period limits are settled once every receipt has been read (10.2); A18: only compared receipts are in a window
    for x in compared_stubs:
        c = x.rec.content; act = c['action']; tx = x.when
        for sid, cont in x._scopes:
            for lim in cont['limits']:
                if lim['action'] != act or 'per' not in lim: continue
                tot = 0; cnt = 0
                for y in compared_stubs:
                    if y.rec.content['action'] != act: continue
                    if sid != 'slip' and sid not in [p.fingerprint for p in y._chain]: continue
                    if sid == 'slip' and y.slip_digest != x.slip_digest: continue
                    ty = y.when
                    if y is x or (tx - lim['per'] < ty < tx) or (ty == tx and y.index < x.index):
                        cnt += 1
                        ya = y.rec.content.get('amount')
                        if ya is not None and 'unit' in lim and ya['unit'] == lim['unit']: tot += ya['value']
                if ('max' in lim and tot > lim['max']) or ('count' in lim and cnt > lim['count']): x.findings.append('over-period-limit')
    for x in compared_stubs:
        fs = x.findings
        x.findings = [k for code in FINDING_ORDER for k in [code] * (fs.count(code) if code == 'over-period-limit' else (1 if code in fs else 0))]

def _answers(out, entries, methods):  # A16: what "read as far as its signatures" covers
    """Section 10.1: the three answers, kept apart."""
    problem_found = bool(out['problems']) or any(e.problems for e in entries)
    missing = sorted(methods.used_missing)
    fully = bool(entries) and all(e.reached_signatures for e in entries) and not missing
    all_compared = all(e.compared for e in entries if e.kind in ('stub', 'pass'))
    no_findings = not any(e.findings for e in entries)
    within = (not problem_found) and all_compared and no_findings and bool(entries)
    ans = {'problem_found': problem_found, 'everything_verified': fully, 'within_permission': within,
           'intact': (not problem_found) and fully, 'methods_missing': missing}
    if not fully:
        ans['third_answer_note'] = 'rests only on the signatures that were verified' + (('; methods lacked: ' + ', '.join(missing)) if missing else '')
    return ans

def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description='Verify a log of draft-izmaylov-agent-permission-receipts-02 (JSON encoding, Section 11.4).')
    ap.add_argument('log'); ap.add_argument('--passkey', action='append', help='thumbprint of a trusted passkey (11.3)')
    ap.add_argument('--recorder', action='append', help='digest of a trusted recorder key set (11.3)')
    ap.add_argument('--tsa', action='append', help='digest of a trusted TSA certificate (9.3)')
    ap.add_argument('--root'); ap.add_argument('--size', type=int)
    ap.add_argument('--without', action='append', default=[], help='treat a signature method as missing (Ed25519, ML-DSA-87, SLH-DSA-SHA2-256s, ES256, RS256)')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args(argv)
    res = check_log(open(a.log, 'rb').read(), a.root, a.size, a.passkey, a.recorder, a.tsa, Methods(without=a.without))
    ans = res['answers']
    if a.json:
        print(json.dumps({'answers': ans, 'problems': res['problems'], 'notes': res['notes'], 'size': res['size'], 'root': res['root'],
                          'entries': [{'index': e.index, 'kind': e.kind, 'problems': e.problems, 'findings': e.findings, 'compared': e.compared} for e in res['entries']]}, indent=1))
    else:
        print('1. problem found:        ', 'yes' if ans['problem_found'] else 'no')
        print('2. everything verified:  ', 'yes' if ans['everything_verified'] else 'no', ('(methods lacked: ' + ', '.join(ans['methods_missing']) + ')') if ans['methods_missing'] else '')
        print('3. within permission:    ', 'yes' if ans['within_permission'] else 'no', ('[' + ans['third_answer_note'] + ']') if 'third_answer_note' in ans else '')
        print('log is intact:           ', 'yes' if ans['intact'] else 'no')
        if res['last_counted_head'] is not None: print(f"the last counted time-stamp is on entry {res['last_counted_head']}: entries 0 to {res['last_counted_head'] - 1} existed by", res['existed_by'].get(0))
        for p in res['problems']: print('log problem:', p)
        for n in res['notes']: print('note:', n)
        for e in res['entries']:
            if e.problems or e.findings: print(f'entry {e.index} ({e.kind}): problems {e.problems} findings {e.findings}')
    return 0 if ans['intact'] else 1

if __name__ == '__main__':
    sys.exit(main())
