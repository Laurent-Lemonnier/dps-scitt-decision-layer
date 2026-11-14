"""COSE_Sign1 (RFC 9052), CWT claims in headers (RFC 9597), COSE Key and COSE Key Thumbprint (RFC 9052 section 7,
RFC 9679), Receipts of inclusion (RFC 9942 section 5.2.1), Concise Problem Details (RFC 9290).

Encoding: cbor2 with canonical=True (RFC 8949 section 4.2.1 deterministic encoding: shortest-form integers and
lengths, map keys sorted). Decoding: cbor2, then the structure is checked item by item below.
"""
import base64
import datetime
import hashlib
from collections.abc import Mapping

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

COSE_SIGN1_TAG = 18             # RFC 9052 section 2, table 1: COSE_Sign1 is CBOR tag 18

# RFC 9052 section 3.1 common header parameters (IANA "COSE Header Parameters")
HDR_ALG = 1
HDR_CRIT = 2
HDR_CONTENT_TYPE = 3
HDR_KID = 4
HDR_CWT_CLAIMS = 15             # RFC 9597 section 2
HDR_TYP = 16                    # RFC 9596
HDR_X5CHAIN = 33                # RFC 9360
HDR_X5T = 34                    # RFC 9360
HDR_RECEIPTS = 394              # RFC 9942 section 2: "receipts", array of bstr .cbor Receipt
HDR_VDS = 395                   # RFC 9942 section 2: verifiable data structure algorithm
HDR_VDP = 396                   # RFC 9942 section 2: verifiable data structure proofs (a map by proof type)
VDS_RFC9162_SHA256 = 1          # RFC 9942 section 5.1
VDP_INCLUSION = -1              # RFC 9942 section 4.2 / 5.2.1: inclusion proofs under key -1
VDP_CONSISTENCY = -2            # RFC 9942 section 5.3.1

# CWT claims (RFC 8392 section 3.1, IANA "CWT Claims")
CWT_ISS, CWT_SUB, CWT_AUD, CWT_EXP, CWT_NBF, CWT_IAT, CWT_CTI = 1, 2, 3, 4, 5, 6, 7

# Algorithms (IANA "COSE Algorithms")
ALG_ES256 = -7                  # RFC 9053 section 2.1
ALG_EDDSA = -8                  # RFC 9053 section 2.2 (deprecated by RFC 9864 in favour of the curve-specific labels)
ALG_ED25519 = -19               # RFC 9864 section 3.1: "Ed25519" (fully specified)
ALG_ES384 = -35
ALG_ES512 = -36
ALG_NAMES = {ALG_ES256: "ES256", ALG_EDDSA: "EdDSA", ALG_ED25519: "Ed25519", ALG_ES384: "ES384", ALG_ES512: "ES512"}

# COSE Key (RFC 9052 section 7.1 and RFC 9053 section 7)
KTY, KID, KEY_ALG = 1, 2, 3
KTY_OKP, KTY_EC2 = 1, 2
OKP_CRV, OKP_X, OKP_D = -1, -2, -4
CRV_ED25519 = 6                 # RFC 9053 section 7.1 table 22


def dumps(obj) -> bytes:
    return cbor2.dumps(obj, canonical=True)


def b64url(data: bytes) -> str:
    """RFC 7515 section 2 base64url without padding (SCRAPI section 2.2 names this form for kid values)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---------------------------------------------------------------- Sig_structure, RFC 9052 section 4.4

def sig_structure(protected: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    """RFC 9052 section 4.4: Sig_structure = ["Signature1", body_protected, external_aad, payload], encoded as in
    section 9 (deterministic). The payload is the full payload "independent of how it is transported": for a
    Receipt it is the Merkle tree root even though the Receipt carries nil (RFC 9942 section 5.2.1)."""
    return dumps(["Signature1", protected, external_aad, payload])


class NotCose(ValueError):
    """Bytes this service does not read as a tagged COSE_Sign1, with the reason."""


def _thaw(value):
    """cbor2 decodes arrays and maps nested in a tag as tuples and frozen maps; plain lists and dicts here."""
    if isinstance(value, (list, tuple)):
        return [_thaw(v) for v in value]
    if isinstance(value, Mapping):
        return {k: _thaw(v) for k, v in value.items()}
    return value


def parse_sign1(raw: bytes):
    """A tagged COSE_Sign1 (RFC 9052 section 4.2): tag 18 over [protected: bstr, unprotected: map, payload: bstr/nil,
    signature: bstr]. Returns (protected bytes, protected map, unprotected map, payload or None, signature)."""
    try:
        item = cbor2.loads(raw)
    except Exception as exc:  # cbor2 raises several classes
        raise NotCose(f"not CBOR: {exc}") from None
    if not isinstance(item, cbor2.CBORTag) or item.tag != COSE_SIGN1_TAG:
        raise NotCose("not tagged 18 (COSE_Sign1); RFC 9942 section 4.3 requires the tag, SCRAPI section 2.3 shows it")
    arr = _thaw(item.value)               # cbor2 >= 6 hands back tuples / frozen maps for items inside a tag
    if not (isinstance(arr, list) and len(arr) == 4):
        raise NotCose("COSE_Sign1 is an array of four items (RFC 9052 section 4.2)")
    protected, unprotected, payload, signature = arr
    if not isinstance(protected, bytes):
        raise NotCose("the protected header is not a byte string")
    if not isinstance(unprotected, dict):
        raise NotCose("the unprotected header is not a map")
    if not (payload is None or isinstance(payload, bytes)):
        raise NotCose("the payload is neither a byte string nor nil")
    if not isinstance(signature, bytes):
        raise NotCose("the signature is not a byte string")
    if protected == b"":
        pmap = {}
    else:
        try:
            pmap = cbor2.loads(protected)
        except Exception as exc:
            raise NotCose(f"the protected header is not CBOR: {exc}") from None
        if not isinstance(pmap, dict):
            raise NotCose("the protected header is not a map (RFC 9052 section 3: empty_or_serialized_map)")
    return protected, pmap, unprotected, payload, signature


def encode_sign1(protected: bytes, unprotected: dict, payload, signature: bytes) -> bytes:
    """A tagged COSE_Sign1. The protected header stays the byte string it was signed as (RFC 9052 section 3)."""
    return dumps(cbor2.CBORTag(COSE_SIGN1_TAG, [protected, unprotected, payload, signature]))


# ---------------------------------------------------------------- the service key

class ServiceKey:
    """The Transparency Service's Receipt signing key: Ed25519, alg -19 (RFC 9864), kid = base64url of its COSE Key
    Thumbprint (RFC 9679, SHA-256), as SCRAPI section 2.2 recommends."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey):
        self.private = private_key
        self.public = private_key.public_key()
        self.x = self.public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.kid = b64url(self.thumbprint())
        self.kid_bytes = self.kid.encode("ascii")

    @classmethod
    def generate(cls):
        return cls(ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def load_pem(cls, path: str):
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise ValueError("the service key is not Ed25519")
        return cls(key)

    def private_pem(self) -> bytes:
        return self.private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())

    def public_pem(self) -> bytes:
        return self.public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def thumbprint(self) -> bytes:
        """RFC 9679 sections 3 and 4.1: SHA-256 over the deterministic CBOR of the COSE_Key holding only the required
        parameters of an OKP key: kty (1) = 1, crv (-1), x (-2)."""
        return hashlib.sha256(dumps({KTY: KTY_OKP, OKP_CRV: CRV_ED25519, OKP_X: self.x})).digest()

    def cose_key(self) -> dict:
        """RFC 9052 section 7 / RFC 9053 section 7.1: the public COSE_Key, with kid (2) and alg (3)."""
        return {KTY: KTY_OKP, KID: self.kid_bytes, KEY_ALG: ALG_ED25519, OKP_CRV: CRV_ED25519, OKP_X: self.x}

    def jwk(self) -> dict:
        """RFC 8037 section 2: the same key as a JWK (an aid for JOSE readers; not a SCRAPI resource)."""
        return {"kty": "OKP", "crv": "Ed25519", "x": b64url(self.x), "kid": self.kid, "alg": "EdDSA", "use": "sig"}

    def sign(self, protected: bytes, payload: bytes) -> bytes:
        return self.private.sign(sig_structure(protected, payload))


# ---------------------------------------------------------------- receipts, RFC 9942 section 5.2.1

def build_receipt(key: ServiceKey, *, issuer: str, subject, registered_at: datetime.datetime,
                  tree_size: int, leaf_index: int, path: list, root: bytes) -> bytes:
    """A Receipt of inclusion for RFC9162_SHA256 (RFC 9942 section 5.2.1): a tagged COSE_Sign1 whose protected header
    carries alg (1), kid (4), vds (395) = 1 and the CWT claims (15) RFC 9943 section 6 requires of a Receipt (iss and
    sub), whose unprotected header carries vdp (396) = {-1: [bstr .cbor [tree_size, leaf_index, inclusion_path]]},
    whose payload is detached (nil) and whose signature covers the Merkle tree root at tree_size as payload."""
    claims = {CWT_ISS: issuer, CWT_IAT: int(registered_at.timestamp())}
    if subject is not None:
        claims[CWT_SUB] = subject
    protected = dumps({HDR_ALG: ALG_ED25519, HDR_KID: key.kid_bytes, HDR_VDS: VDS_RFC9162_SHA256,
                       HDR_CWT_CLAIMS: claims})
    proof = dumps([tree_size, leaf_index, list(path)])         # RFC 9942 section 5.2, figure 3
    unprotected = {HDR_VDP: {VDP_INCLUSION: [proof]}}           # RFC 9942 section 5.2.1, figure 5
    signature = key.sign(protected, root)                       # payload = the Merkle Tree Hash
    return encode_sign1(protected, unprotected, None, signature)


def build_checkpoint(key: ServiceKey, *, issuer: str, tree_size: int, root: bytes,
                     issued_at: datetime.datetime) -> bytes:
    """A signed tree head, in COSE. Not a SCRAPI resource and not an RFC 9942 Receipt: the shape is this service's
    (README, ambiguity log A9). Protected header as a Receipt's (alg -19, kid, vds 395 = 1, CWT claims iss = sub = the
    service, iat = issue time); payload ATTACHED = bstr .cbor [tree_size, root]; no proof."""
    protected = dumps({HDR_ALG: ALG_ED25519, HDR_KID: key.kid_bytes, HDR_VDS: VDS_RFC9162_SHA256,
                       HDR_CWT_CLAIMS: {CWT_ISS: issuer, CWT_SUB: issuer, CWT_IAT: int(issued_at.timestamp())}})
    payload = dumps([tree_size, root])
    return encode_sign1(protected, {}, payload, key.sign(protected, payload))


def transparent_statement(statement_raw: bytes, receipts: list) -> bytes:
    """RFC 9943 section 7, figure 7: the Signed Statement with its Receipts in the unprotected header, label 394,
    each as bstr .cbor Receipt. The protected header, payload and signature are carried unchanged."""
    protected, _pmap, _unprotected, payload, signature = parse_sign1(statement_raw)
    return encode_sign1(protected, {HDR_RECEIPTS: list(receipts)}, payload, signature)


# ---------------------------------------------------------------- issuer signature verification (RFC 9943 section 6.3 step 2)

def load_public_key_pem(pem: bytes):
    return serialization.load_pem_public_key(pem)


def verify_issuer_signature(public_key, alg: int, protected: bytes, payload: bytes, signature: bytes) -> bool:
    """RFC 9052 section 4.4 verification with the issuer's key, for the algorithms this service knows:
    -19 / -8 on an Ed25519 key, -7 (ES256, RFC 9053 section 2.1: r || s, 64 bytes) on a P-256 key."""
    tbs = sig_structure(protected, payload)
    try:
        if alg in (ALG_ED25519, ALG_EDDSA):
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                return False
            public_key.verify(signature, tbs)
            return True
        if alg == ALG_ES256:
            if not isinstance(public_key, ec.EllipticCurvePublicKey) or len(signature) != 64:
                return False
            r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            public_key.verify(encode_dss_signature(r, s), tbs, ec.ECDSA(hashes.SHA256()))
            return True
    except InvalidSignature:
        return False
    return False


def es256_sign(private_key, protected: bytes, payload: bytes) -> bytes:
    der = private_key.sign(sig_structure(protected, payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ---------------------------------------------------------------- Concise Problem Details, RFC 9290

def problem(title: str, detail: str) -> bytes:
    """RFC 9290 section 2: a map with title (-1) and detail (-2), unadorned text (language en by default), as SCRAPI
    section 2 requires of every 4xx/5xx body (media type application/concise-problem-details+cbor)."""
    return dumps({-1: title, -2: detail})
