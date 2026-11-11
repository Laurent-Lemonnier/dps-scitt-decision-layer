"""Pure-Python Ed25519 (RFC 8032, Section 5.1), written for this checker.

Not constant-time. Demonstration and verification use only; never use it to
protect a real key. Written from the RFC text, no third-party code.
"""
import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

# Base point (RFC 8032 Section 5.1): y = 4/5, x positive (even).
_BY = (4 * pow(5, P - 2, P)) % P


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_BX = _recover_x(_BY, 0)
# Extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, x*y = T/Z.
B = (_BX, _BY, 1, _BX * _BY % P)
IDENTITY = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s, p):
    q = IDENTITY
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


def _encode(p):
    zinv = pow(p[2], P - 2, P)
    x, y = p[0] * zinv % P, p[1] * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _h(m):
    return hashlib.sha512(m).digest()


def _expand(seed):
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = _h(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _encode(_mul(a, B))


def sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(seed)
    A = _encode(_mul(a, B))
    r = int.from_bytes(_h(prefix + msg), "little") % L
    R = _encode(_mul(r, B))
    k = int.from_bytes(_h(R + A + msg), "little") % L
    s = (r + k * a) % L
    return R + int.to_bytes(s, 32, "little")


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    A = _decode(pub)
    R = _decode(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(_h(sig[:32] + pub + msg), "little") % L
    # Cofactored check [8][S]B = [8]R + [8][k]A (RFC 8032 Section 5.1.7).
    left = _mul(8, _mul(s, B))
    right = _mul(8, _add(R, _mul(k, A)))
    return _equal(left, right)
