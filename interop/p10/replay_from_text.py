#!/usr/bin/env python3
"""An outside reading of P10 S2b (the replay verifier of draft-nestorov-scitt-p10-underdetermination-02), first pass,
written from the frozen text alone and run on the published vectors.

Read: VolMax-Studio/p10-replay-verifier at v0.1.0-s2b-complete (8eaa91ca), its documents only: README.md, docs/,
frozen/ (S2B_PREREG_v0.1_r7.md, IMPLEMENTATION_SELECTION_v0.md and its JCS amendment, LeafEncodeV0_SPEC.md,
StatementPayloadSchemaV0_r9.md), rules/, profile/, manifest/, and vectors/; the RFCs the prereg cites (8949, 9052,
9162, 9597, 9679, 8785, 9942, 9943); the draft. Nothing under src/, tests/, scripts/, harness/, orchestration/ or
evidence/ was opened, no generator, no history (the boundary agreed with the author on 1 November 2026).

First pass, the replay layer: the physical request (implementation selection section 4), P0 to P7 of the prereg's
section 9.1 (request and frozen configuration, Receipt parsing and target-proof authentication of section 11, index
discipline, LeafEncodeV0 of section 8, the RFC 9162 root of section 10, the authenticated binding checks with
LogIdentityV0 of section 12), the dominance rule, and of P8 what needs no payload schema: SCITT structural reading of
each row (section 13.2), subject classification, and the signature observations of section 14. Not in this pass: the
payload schema r9 (section 13.3: kind, payload, TargetKindMismatch) and the transcript encoding (section 15); each
case whose expected result rests on them is reported as not reached, not as agreement.

Second pass (5 November 2026, `--pass 2`): the payload schema r9, stages 0 to 3 of its section 9, in
schema_from_text.py (kind derivation, the five predicates, projection, and TargetKindMismatch of prereg section 11.2
step 6), and the transcript tB of prereg section 15 in transcript_from_text.py, compared byte for byte with the
expected bytes of every Verified case. `--pass 1` reproduces the first pass unchanged.

Usage: replay_from_text.py --vectors DIR [--pass 1|2] [--report out.json] [--pass1-report report-pass1.json]
"""
import argparse
import hashlib
import json
import pathlib
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from cbor_read import CborError, Map, Tag, decode_exact, encode  # noqa: E402
import schema_from_text as schema  # noqa: E402
import transcript_from_text as transcript  # noqa: E402

AMBIGUITIES = []


def note(where, text):
    if not any(a["where"] == where for a in AMBIGUITIES):
        AMBIGUITIES.append({"where": where, "reading": text})


def sha256(b):
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------- LeafEncodeV0 (LeafEncodeV0_SPEC v1, section 2)

FORMAT_ID = b"application/scitt-statement+cose"
LEAF_PREFIX = b"P10-LeafEncodeV0\x00"


def leaf_input(statement):
    if not isinstance(statement, (bytes, bytearray)) or len(statement) < 1:
        raise ValueError("not encodable: a statement of length 0")
    return LEAF_PREFIX + len(FORMAT_ID).to_bytes(4, "big") + FORMAT_ID + len(statement).to_bytes(8, "big") + bytes(statement)


def decode_leaf_input(b):
    """The conformance decoder of section 8.2: wrong prefix, length, trailing bytes or format_id are refused."""
    if not b.startswith(LEAF_PREFIX):
        raise ValueError("wrong prefix")
    p = len(LEAF_PREFIX)
    if len(b) < p + 4:
        raise ValueError("truncated")
    flen = int.from_bytes(b[p:p + 4], "big")
    p += 4
    if b[p:p + flen] != FORMAT_ID or flen != len(FORMAT_ID):
        raise ValueError("format_id is not the v1 identifier")
    p += flen
    if len(b) < p + 8:
        raise ValueError("truncated")
    slen = int.from_bytes(b[p:p + 8], "big")
    p += 8
    if slen < 1 or len(b) - p != slen:
        raise ValueError("length field does not match the remaining bytes")
    return b[p:]


def leaf_hash(statement):
    return sha256(b"\x00" + leaf_input(statement))


def leaf_encode_spec_artifact_digest(spec_bytes):
    """The rule as the frozen schema r9 quotes it from S2a (section 8.11.1): SHA-256("P10-LeafEncodeSpecArtifact-v0:"
    || "text-markdown-utf-8-v0:" || raw bytes). The S2a text itself was not read; the value reproduces the pin."""
    return sha256(b"P10-LeafEncodeSpecArtifact-v0:" + b"text-markdown-utf-8-v0:" + spec_bytes)


# ---------------------------------------------------------------- RFC 9162 (section 2.1.1 tree, section 2.1.3.2 inclusion)

def node(l, r):
    return sha256(b"\x01" + l + r)


def mth(hashes_):
    n = len(hashes_)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return hashes_[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return node(mth(hashes_[:k]), mth(hashes_[k:]))


def inclusion_root(leaf_index, tree_size, path, lh):
    """RFC 9162 section 2.1.3.2 steps; None when the path does not fit (no candidate root)."""
    if leaf_index >= tree_size:
        return None
    fn, sn, r = leaf_index, tree_size - 1, lh
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = node(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


# ---------------------------------------------------------------- COSE (RFC 9052), COSE_Key thumbprints (RFC 9679), ES256

ALLOWED_RECEIPT_ALGS = {-7}      # prereg section 11.4 (frozen rule spec value)
ALLOWED_STATEMENT_ALGS = {-7}
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def read_cose_key(raw):
    """One complete COSE_Key in a bstr; returns the map or raises."""
    k = decode_exact(raw)
    if not isinstance(k, dict):
        raise CborError("COSE_Key is not a map")
    return k


def thumbprint(key):
    """RFC 9679: SHA-256 over the deterministic CBOR of the required parameters; EC2 = kty, crv, x, y."""
    kty = key.get(1)
    if kty == 2:
        req = {1: 2, -1: key.get(-1), -2: key.get(-2), -3: key.get(-3)}
    elif kty == 1:
        req = {1: 1, -1: key.get(-1), -2: key.get(-2)}
    else:
        raise ValueError("key type without a thumbprint rule here")
    if any(v is None for v in req.values()):
        raise ValueError("required key parameter absent")
    return sha256(encode(req))


def es256_key(key):
    """A P-256 public key from a COSE_Key, or None when its parameters do not fit ES256."""
    if key.get(1) != 2 or key.get(-1) != 1:
        return None
    x, y = key.get(-2), key.get(-3)
    if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
        return None
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    except ValueError:
        return None


def sig_structure(protected_raw, payload):
    return encode(["Signature1", protected_raw, b"", payload])


def es256_verify(pub, signature, message):
    if not isinstance(signature, bytes) or len(signature) != 64:
        return False
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (0 < r < P256_N and 0 < s < P256_N):
        return False
    try:
        pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def cose_sign1(raw, require_tag=True):
    """(protected_raw, protected_map, unprotected, payload, signature) of a COSE_Sign1, or raise."""
    v = decode_exact(raw)
    if isinstance(v, Tag):
        if v.tag != 18:
            raise CborError("tag is not COSE_Sign1 (18)")
        v = v.value
    elif require_tag:
        raise CborError("untagged COSE_Sign1")
    if not isinstance(v, list) or len(v) != 4:
        raise CborError("not a four-element COSE_Sign1 array")
    prot_raw, unprot, payload, sig = v
    if not isinstance(prot_raw, bytes) or not isinstance(unprot, dict) or not (isinstance(payload, bytes) or payload is None) \
            or not isinstance(sig, bytes):
        raise CborError("COSE_Sign1 member types")
    prot = decode_exact(prot_raw) if prot_raw else Map()
    if not isinstance(prot, dict):
        raise CborError("protected header is not a map")
    return prot_raw, prot, unprot, payload, sig


# ---------------------------------------------------------------- JCS (RFC 8785) for the objects of section 12

def jcs(obj):
    """RFC 8785 for objects of strings and small integers: sorted keys (UTF-16 order; ASCII keys here), no
    whitespace, JSON string escaping as ECMAScript JSON.stringify does (short escapes, lowercase \\u00xx, raw UTF-8)."""
    def s(x):
        if isinstance(x, bool) or x is None:
            raise ValueError("not used here")
        if isinstance(x, int):
            return str(x)
        if isinstance(x, str):
            out = ['"']
            for ch in x:
                c = ord(ch)
                if ch == '"':
                    out.append('\\"')
                elif ch == "\\":
                    out.append("\\\\")
                elif ch in "\b\f\n\r\t":
                    out.append({"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
                elif c < 0x20:
                    out.append(f"\\u{c:04x}")
                else:
                    out.append(ch)
            out.append('"')
            return "".join(out)
        if isinstance(x, dict):
            keys = sorted(x, key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(s(k) + ":" + s(x[k]) for k in keys) + "}"
        raise ValueError(f"type {type(x)}")
    return s(obj).encode("utf-8")


def leaf_encoding_profile_digest(spec_digest_hex):
    return sha256(jcs({"rule": "LeafEncodeV0", "spec_digest": spec_digest_hex}))


def log_identity_digest(ts_iss, fingerprint_hex, lep_hex):
    return sha256(jcs({"checkpoint_verification_key_fingerprint": fingerprint_hex,
                       "leaf_encoding_profile_digest": lep_hex, "ts_iss": ts_iss, "vds_algorithm": 1}))


# ---------------------------------------------------------------- the physical request (implementation selection section 4)

class Malformed(Exception):
    pass


def read_request(raw):
    """Section 4.1 and 4.2: one CBOR item, the three-element array, exact label sets and types, no tags around
    envelope values, no duplicate labels or keys. Returns (frozen, material) or raises Malformed(reason)."""
    try:
        v = decode_exact(raw)
    except CborError as e:
        raise Malformed(f"not one well-formed CBOR item: {e}")
    if not isinstance(v, list) or len(v) != 3 or v[0] != "P10-ReplayRequestV0":
        raise Malformed("envelope")
    fz, mt = v[1], v[2]
    for name, m, labels in (("frozen", fz, range(1, 9)), ("material", mt, range(1, 6))):
        if not isinstance(m, dict) or isinstance(m, Tag):
            raise Malformed(f"{name} is not a map")
        if getattr(m, "duplicate", False):
            raise Malformed(f"{name}: duplicate label")
        if set(m) != set(labels):
            raise Malformed(f"{name}: labels {sorted(map(str, m))}")
        for k, x in m.items():
            if isinstance(x, Tag) and not (name == "material" and k == 5):
                raise Malformed(f"{name} label {k}: a tag around an envelope value")

    def b32(x, what):
        if not isinstance(x, bytes) or len(x) != 32:
            raise Malformed(f"{what}: not 32 raw bytes")
        return x

    def pairs(x, what, key_type, uniq=True):
        if not isinstance(x, list):
            raise Malformed(f"{what}: not an array")
        seen = set()
        out = []
        for p in x:
            if not isinstance(p, list) or len(p) != 2 or isinstance(p[0], bool) or not isinstance(p[0], key_type):
                raise Malformed(f"{what}: element")
            if uniq and p[0] in seen:
                raise Malformed(f"{what}: duplicate key")
            seen.add(p[0])
            out.append(p)
        return out

    if not isinstance(fz[1], str):
        raise Malformed("ts_iss is not a tstr")
    rk = fz[2]
    if rk is not None:
        if not isinstance(rk, bytes) or not rk:
            raise Malformed("receipt_key: an empty or non-bstr key is malformed, never absent")
        try:
            read_cose_key(rk)
        except CborError as e:
            raise Malformed(f"receipt_key: {e}")
    if isinstance(fz[4], bool) or not isinstance(fz[4], int) or fz[4] < 0:
        raise Malformed("vds_algorithm is not an unsigned integer")
    if not isinstance(fz[6], bytes):
        raise Malformed("instance_subject is not a bstr")
    frozen = {"ts_iss": fz[1], "receipt_key_raw": rk, "fingerprint": b32(fz[3], "fingerprint"), "vds": fz[4],
              "leaf_spec_digest": b32(fz[5], "leaf_encoding_spec_digest"), "instance_subject": fz[6]}
    frozen["key_resolution"] = {i: b32(f, "key_resolution fingerprint") for i, f in pairs(fz[7], "key_resolution", str)}
    km = {}
    for i, kb in pairs(fz[8], "key_material", str):
        if not isinstance(kb, bytes):
            raise Malformed("key_material: not a bstr")
        try:
            read_cose_key(kb)
        except CborError as e:
            raise Malformed(f"key_material: {e}")
        km[i] = kb
    frozen["key_material"] = km
    for lbl in (1, 2):
        if mt[lbl] is not None and not isinstance(mt[lbl], bytes):
            raise Malformed(f"material label {lbl}: neither bstr nor null")
    leaves = pairs(mt[3], "leaves", int, uniq=False)
    for idx, b in leaves:
        if idx < 0 or idx >= 2 ** 64:
            raise Malformed("leaf index outside uint64")
        if not isinstance(b, bytes) or not b:
            raise Malformed("leaf bytes: not a non-empty bstr")
    dp = pairs(mt[4], "detached_statement_payloads", int)
    for idx, b in dp:
        if idx < 0 or not isinstance(b, bytes):
            raise Malformed("detached payload")
    material = {"receipt": mt[1], "target": mt[2], "leaves": leaves, "detached": {i: b for i, b in dp}}
    return frozen, material


# ---------------------------------------------------------------- FullPrefixReplay, section 9.1, with the dominance rule

ORDER = ["P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8"]


def replay(raw, own_spec_artifact_digest, pass2=False, limitations=None):
    found = []          # (phase, status, class, reason, idx)
    ev = {}

    def out(phase, status, cls, reason, idx=None):
        found.append((ORDER.index(phase), status, cls, reason, idx))

    try:
        frozen, material = read_request(raw)
    except Malformed as e:
        return {"status": "Invalid", "class": "request", "reason": "RequestMalformed", "detail": str(e)}, ev
    # P0
    receipt_key = None
    if frozen["vds"] != 1:
        out("P0", "Invalid", "request", "FrozenConfigMalformed")
    if frozen["receipt_key_raw"] is not None:
        k = read_cose_key(frozen["receipt_key_raw"])
        try:
            tp = thumbprint(k)
        except ValueError:
            tp = None
        if tp != frozen["fingerprint"]:
            out("P0", "Invalid", "request", "KeyMaterialFingerprintMismatch")
        else:
            receipt_key = k
    # P1
    if material["receipt"] is None:
        out("P1", "Unavailable", "material", "ReceiptAbsent")
    if material["target"] is None:
        out("P1", "Unavailable", "material", "TargetStatementAbsent")
    p3_ok = p6_ok = False
    n = leaf_index = r_auth = None
    receipt = None
    # P2
    if material["receipt"] is not None:
        try:
            prot_raw, prot, unprot, payload, sig = cose_sign1(material["receipt"])
            vds = prot.get(395)
            if isinstance(vds, bool) or not isinstance(vds, int):
                raise CborError("VDS (395) not readable in the protected header")
            vdp = unprot.get(396)
            if not isinstance(vdp, dict) or not isinstance(vdp.get(-1), list):
                raise CborError("inclusion proofs (396, -1) not readable")
            proofs = []
            for pb in vdp[-1]:
                if not isinstance(pb, bytes):
                    raise CborError("an inclusion proof is not a bstr")
                p = decode_exact(pb)
                if not (isinstance(p, list) and len(p) == 3 and isinstance(p[0], int) and isinstance(p[1], int)
                        and not isinstance(p[0], bool) and not isinstance(p[1], bool)
                        and isinstance(p[2], list) and all(isinstance(h, bytes) for h in p[2])):
                    raise CborError("inclusion proof shape")
                if p[0] < 1 or p[1] >= p[0]:
                    raise CborError("tree_size < 1 or leaf_index >= tree_size")
                proofs.append(p)
            receipt = {"prot_raw": prot_raw, "prot": prot, "payload": payload, "sig": sig, "vds": vds, "proofs": proofs}
        except CborError as e:
            out("P2", "Invalid", "replay", "ReceiptMalformed")
            ev["receipt_malformed"] = str(e)
    # P5's length rule, ahead of P3 when the target itself is empty: it is not encodable (section 7.7), so no
    # candidate entry exists for P3 to authenticate
    if material["target"] is not None and len(material["target"]) == 0:
        out("P5", "Invalid", "request", "RequestMalformed")
        note("P3/P5, an empty target", "an empty target_registered_statement_bytes is not encodable (section 7.7); "
             "it is reported at P5 as RequestMalformed and P3 is not evaluated, since no candidate entry exists")
    # P3
    if receipt is not None and material["target"]:
        r = receipt
        attached = r["payload"] is not None
        alg_ok = r["prot"].get(1) in ALLOWED_RECEIPT_ALGS
        if r["prot"].get(1) not in ALLOWED_RECEIPT_ALGS:
            note("P3, Receipt algorithm", "a Receipt whose protected alg is not in AllowedReceiptAlgsV0 = {-7} is read "
                 "as a signature that does not verify (ReceiptBadSignature / ReceiptTargetAuthenticationFailure); "
                 "the text lists no separate code for it")
        pub = es256_key(receipt_key) if receipt_key is not None else None
        if receipt_key is not None and receipt_key.get(3) is not None and receipt_key.get(3) != r["prot"].get(1):
            pub = None
        def verify(payload_bytes):
            return pub is not None and alg_ok and es256_verify(pub, r["sig"], sig_structure(r["prot_raw"], payload_bytes))
        if r["vds"] != 1:
            if not attached:
                out("P3", "Invalid", "replay", "ReceiptVdsUnsupported")
            elif receipt_key is None:
                out("P3", "Unavailable", "material", "ReceiptKeyUnavailable")
            elif verify(r["payload"]):
                out("P3", "Invalid", "binding", "VdsAlgorithmMismatch")
            else:
                out("P3", "Invalid", "replay", "ReceiptBadSignature")
        else:
            lh = leaf_hash(material["target"])
            cands = [(p, inclusion_root(p[1], p[0], p[2], lh)) for p in r["proofs"]]
            auth = []            # the proofs that authenticate the target (section 11.2 step 2)
            if attached:
                matching = [(p, c) for p, c in cands if c is not None and c == r["payload"]]
                if not matching:
                    out("P3", "Invalid", "replay", "ReceiptTargetBindingFailure")
                elif frozen["receipt_key_raw"] is None:
                    out("P3", "Unavailable", "material", "ReceiptKeyUnavailable")
                elif receipt_key is not None and not verify(r["payload"]):
                    out("P3", "Invalid", "replay", "ReceiptBadSignature")
                elif receipt_key is not None:
                    auth = matching
            else:
                if frozen["receipt_key_raw"] is None:
                    out("P3", "Unavailable", "material", "ReceiptKeyUnavailable")
                elif receipt_key is not None:
                    auth = [(p, c) for p, c in cands if c is not None and verify(c)]
                    if not auth:
                        out("P3", "Invalid", "replay", "ReceiptTargetAuthenticationFailure")
            if auth:
                if len(auth) > 1:
                    out("P3", "Invalid", "replay", "ReceiptTargetAmbiguous")
                else:
                    (p, c), = auth
                    n, leaf_index, r_auth = p[0], p[1], c
                    p3_ok = True
                    ev["checkpoint_size"] = n
    # P4, P5, P6
    if n is not None:
        by_index = {}
        dup = False
        for idx, b in material["leaves"]:
            if idx in by_index:
                dup = True
            by_index.setdefault(idx, []).append(b)
        if dup:
            out("P4", "Invalid", "replay", "DuplicateIndex")
        if any(i >= n for i in by_index):
            out("P4", "Invalid", "request", "IndexOutOfPrefix")
        missing = [i for i in range(n) if i not in by_index]
        if missing:
            out("P4", "Unavailable", "material", "MissingIndex", missing[0])
        if leaf_index in by_index and len(by_index[leaf_index]) == 1 and by_index[leaf_index][0] != material["target"]:
            out("P5", "Invalid", "replay", "TargetStatementMismatch")
        if not dup and not missing:
            stmts = [by_index[i][0] for i in range(n)]
            root = mth([leaf_hash(s) for s in stmts])
            ev["root"] = root.hex()
            ev["statement_sha256"] = [{"idx": i, "sha256": sha256(s).hex()} for i, s in enumerate(stmts)]
            if root != r_auth:
                out("P6", "Invalid", "replay", "RootMismatch")
            else:
                p6_ok = True
    # P7, only on an authenticated Receipt (P3) and, for the leaf domain, an equal root (P6)
    fp_hex = frozen["fingerprint"].hex()
    lep = leaf_encoding_profile_digest(frozen["leaf_spec_digest"].hex()).hex()
    ev["leaf_encoding_profile_digest"] = lep
    ev["log_identity_digest"] = log_identity_digest(frozen["ts_iss"], fp_hex, lep).hex()
    if p3_ok:
        cwt = receipt["prot"].get(15)
        ts = cwt.get(1) if isinstance(cwt, dict) else None
        if ts != frozen["ts_iss"]:
            out("P7", "Invalid", "binding", "TsIssuerMismatch")
        if frozen["leaf_spec_digest"] != own_spec_artifact_digest:
            out("P7", "Invalid", "binding", "LeafSpecDigestMismatch")
        if p6_ok:
            for i, s in enumerate(stmts):
                try:
                    _, _, unprot, _, _ = cose_sign1(s, require_tag=False)
                except CborError:
                    continue
                if len(unprot) != 0:
                    out("P7", "Invalid", "binding", "LeafInputDomainViolation", i)
                    break
    # P8: rows, subject entries, signature observations; in the second pass also schema stages 0 to 3 and the
    # target's wire kind (prereg section 11.2 step 6)
    tb_rows, detailed = [], []
    target_unobtained = False
    target_kind = None
    if p3_ok and p6_ok:
        rows, unreadable, sigs = [], [], {}
        for i, s in enumerate(stmts):
            try:
                prot_raw, prot, unprot, payload, sig = cose_sign1(s, require_tag=True)
                if getattr(prot, "duplicate", False):
                    raise CborError("duplicate label in the protected header")
                cwt = prot.get(15)
                if not isinstance(cwt, dict) or getattr(cwt, "duplicate", False):
                    raise CborError("CWT Claims (15) not a readable map")
                iss, sub = cwt.get(1), cwt.get(2)
                if not isinstance(iss, str) or not isinstance(sub, str):
                    raise CborError("iss or sub missing or not tstr")
                if pass2:
                    schema.stage0(prot)
            except (CborError, schema.StageFailure):
                unreadable.append(i)
                rows.append(None)
                tb_rows.append((i, None))
                continue
            rows.append(sub)
            if sub.encode("utf-8") != frozen["instance_subject"]:
                tb_rows.append((i, sub.encode("utf-8")))
                continue
            kind = predicate = None
            if pass2:
                body = payload if payload is not None else material["detached"].get(i)
                if body is None:
                    # stage 1 needs the payload bytes: prereg section 14.3 / schema section 9
                    out("P8", "Unavailable", "material", "StatementPayloadUnavailable", i)
                    tb_rows.append((i, None))
                    if i == leaf_index:
                        target_unobtained = True
                    continue
                try:
                    kind, predicate = schema.stage1(prot, body, sub)
                except schema.StageFailure:
                    unreadable.append(i)
                    rows[-1] = None
                    tb_rows.append((i, None))
                    continue
                tb_rows.append((i, sub.encode("utf-8")))
                if i == leaf_index:
                    target_kind = kind
            fp = frozen["key_resolution"].get(iss)
            kb = frozen["key_material"].get(iss)
            if fp is None or kb is None:
                obs = "keyUnavailable"
                if payload is None and i not in material["detached"]:
                    out("P8", "Unavailable", "material", "StatementPayloadUnavailable", i)
                sigs[str(i)] = obs
            else:
                k = read_cose_key(kb)
                try:
                    tpk = thumbprint(k)
                except ValueError:
                    tpk = None
                if tpk != fp:
                    out("P8", "Invalid", "request", "KeyMaterialFingerprintMismatch", i)
                    continue
                body = payload if payload is not None else material["detached"].get(i)
                if body is None:
                    out("P8", "Unavailable", "material", "StatementPayloadUnavailable", i)
                    continue
                alg = prot.get(1)
                pub = es256_key(k)
                if alg not in ALLOWED_STATEMENT_ALGS or pub is None or (k.get(3) is not None and k.get(3) != alg):
                    obs = "badSignature"
                else:
                    obs = "verified" if es256_verify(pub, sig, sig_structure(prot_raw, body)) else "badSignature"
                sigs[str(i)] = obs
            if pass2:
                # stages 2 and 3: a predicate or projection failure keeps the kind with payload = none
                try:
                    projected = schema.stage23(kind, predicate, sub, limitations)
                except schema.StageFailure:
                    projected = None
                detailed.append((i, iss.encode("utf-8"), kind, obs, projected))
        ev["signature_observations"] = sigs
        ev["unreadable_idx"] = unreadable
        ev["subject_rows"] = [i for i, s in enumerate(rows) if s is not None and s.encode("utf-8") == frozen["instance_subject"]]
        if pass2 and not target_unobtained and target_kind != "adjudication":
            out("P8", "Invalid", "request", "TargetKindMismatch", leaf_index)
            ev["target_kind"] = target_kind or ("unavailable row" if rows[leaf_index] is None
                                                else "not a subject entry")
    invalid = sorted(f for f in found if f[1] == "Invalid")
    unavailable = sorted(f for f in found if f[1] == "Unavailable")
    first = invalid[0] if invalid else (unavailable[0] if unavailable else None)
    if first is None:
        if pass2:
            # P9: the transcript of prereg section 15, from the same values (section 15.4)
            krd = transcript.key_resolution_digest(frozen["key_resolution"], schema.jcs)
            try:
                tb = transcript.encode_tb(bytes.fromhex(ev["log_identity_digest"]), krd, n, bytes.fromhex(ev["root"]),
                                          tb_rows, detailed)
                ev["tb"] = tb
                ev["transcript_sha256"] = sha256(tb).hex()
                ev["entries"] = [[i, kind, obs, p is not None] for i, _, kind, obs, p in detailed]
                ev["rows_unavailable"] = sum(1 for _, s in tb_rows if s is None)
            except transcript.TooLarge as e:
                ev["transcript_not_encoded"] = e.size
        return {"status": "Verified", "class": None, "reason": None}, ev
    res = {"status": first[1], "class": first[2], "reason": first[3]}
    if first[4] is not None:
        res["idx"] = first[4]
    res["diagnostics"] = [f"{f[1]}({f[2]}, {f[3]})" for f in (invalid + unavailable)[1:]]
    return res, ev


# ---------------------------------------------------------------- the run

def leaf_vectors():
    """LeafEncodeV0_SPEC section 5, L1 to L8, as the spec prints them."""
    out = {}
    exp = {"L1": (b"\x00", "aa263d9ac89b59f1593d4eaf715d386e2b97d66efd91cead42818ad6978b1eb1"),
           "L2": (b"\xd2", "fc47e9bd265fe22b7c10d675c08a58debfab6077df8fd07dd5eb4eb1162c3eba"),
           "L3": (bytes.fromhex("d28440a0f640"), "1b0beaae426397b4679962a774ac4fa48437fd18b1a2e89e881944a6fadd2131"),
           "L4": (bytes.fromhex("8440a0f640"), "2531f8eb6c09b3b7b1ba438b1d39fa734495cbb4a65b30c5090e6935253f884b"),
           "L5": (bytes(range(256)), "0662f02bffb4f14934debd070b0670a425b31cff9b2fb70192ca7eca7cd48a54")}
    for k, (s, h) in exp.items():
        out[k] = leaf_hash(s).hex() == h
    try:
        leaf_input(b"")
        out["L6"] = False
    except ValueError:
        out["L6"] = True
    out["L7"] = True     # the encoder takes no format_id argument: only the v1 identifier exists (section 2)
    try:
        decode_leaf_input(leaf_input(b"\x00") + b"\x00")
        out["L8"] = False
    except ValueError:
        out["L8"] = True
    l1 = "5031302d4c656166456e636f6465563000000000206170706c69636174696f6e2f73636974742d73746174656d656e742b636f7365000000000000000100"
    out["L1_leaf_input_bytes"] = leaf_input(b"\x00").hex() == l1
    return out


PAYLOAD_LAYER = {"TargetKindMismatch"}
P9_RESOURCE_POLICY = {"VerifierCapabilityUnsupported"}   # with "resource_policy": true in the case: a P9 size cap


STATIC_READINGS = [
    ("section 11.2 step 2, an inclusion path that does not fit", "a proof whose path is too short or too long for its "
     "tree_size and leaf_index (RFC 9162 section 2.1.3.2 ends with sn != 0) gives no candidate root and so does not "
     "authenticate the target; it is not read as ReceiptMalformed, which P2 reserves for unreadable proofs and "
     "leaf_index >= tree_size"),
    ("section 7.3 (b), the leaf-domain check", "a leaf is checked when its COSE_Sign1 array is readable, tagged or "
     "untagged (\"detection needs the COSE_Sign1 array to be readable\"); an unreadable leaf makes no domain claim"),
    ("section 9.1 P4, two Invalid codes at once", "a duplicate index and an index beyond n in the same request: "
     "DuplicateIndex is reported first, as the phase table lists it first; the text orders phases, not codes inside one"),
    ("section 12.4 rule 2, LogIdentityInconsistent", "each of the four LogIdentityV0 components is compared by a more "
     "specific code (TsIssuerMismatch at P7, the key fingerprint at P0, the VDS at P0 and P3, LeafSpecDigestMismatch "
     "at P7), and the physical request has no expected_log_identity_digest; so this reading never emits "
     "LogIdentityInconsistent, and no case expects it"),
    ("section 13.2, the subject comparison", "the CWT sub (a tstr) is compared with instance_subject (a bstr) by the "
     "UTF-8 bytes of the tstr, as section 6.1 says \"byte-compared with row sub\""),
    ("section 9.1 P5, the target at leaf_index", "TargetStatementMismatch is evaluated when exactly one record holds "
     "leaf_index; with two records there, DuplicateIndex already decides"),
    ("section 8.4, LeafEncodeSpecArtifactDigestV0", "the S2b text defines it by reference to S2a section 6b, which "
     "this reading did not open; the rule quoted in StatementPayloadSchemaV0 r9 section 8.11.1 (domain "
     "'P10-LeafEncodeSpecArtifact-v0:', format 'text-markdown-utf-8-v0:', raw bytes) reproduces the pinned value "
     "571765530870e4a6... from frozen/LeafEncodeV0_SPEC.md"),
]


def first_difference(ours, theirs):
    """The first differing byte offset of two transcripts, with the grammar position it falls in."""
    for i, (a, b) in enumerate(zip(ours, theirs)):
        if a != b:
            return i
    return min(len(ours), len(theirs)) if len(ours) != len(theirs) else None


def run(vectors_dir, report_path=None, pass_no=1, pass1_report=None):
    pass2 = pass_no == 2
    for where, text in STATIC_READINGS:
        note(where, text)
    if pass2:
        for where, text in schema.READINGS + transcript.READINGS + PASS2_READINGS:
            note(where, text)
    root = pathlib.Path(vectors_dir)
    man = json.loads((root / "manifest" / "VectorManifestS2bV0.json").read_text())
    report = {"pins": {}, "leaf_vectors": leaf_vectors(), "cases": {}}
    bad = [p for p, h in man["files"].items() if hashlib.sha256((root / p).read_bytes()).hexdigest() != h]
    report["pins"]["vector_files_match_manifest"] = (len(man["files"]), len(bad))
    spec = (root / "frozen" / "LeafEncodeV0_SPEC.md").read_bytes()
    own = leaf_encode_spec_artifact_digest(spec)
    report["pins"]["leaf_encode_spec_artifact_digest"] = own.hex()
    limitations = None
    if pass2:
        schema_file = root / "frozen" / "StatementPayloadSchemaV0_r9.md"
        report["pins"]["statement_payload_schema_r9_sha256"] = hashlib.sha256(schema_file.read_bytes()).hexdigest()
        limitations = schema.limitations_constant(schema_file)
        report["pins"]["limitations_digest_recomputed"] = limitations[1]
    tally = {"agree": 0, "disagree": 0, "not_reached": 0}
    tb_tally = {"verified_cases": 0, "byte_equal": 0, "differ": 0, "not_encoded": 0, "expected_sha256_also_equal": 0}
    for case, exp in sorted(man["expected"].items()):
        d = root / "vectors" / case
        if not (d / "request.cbor").exists():
            report["cases"][case] = {"state": "no request.cbor"}
            tally["not_reached"] += 1
            continue
        full = json.loads((d / "expected.json").read_text())
        res, ev = replay((d / "request.cbor").read_bytes(), own, pass2, limitations)
        want = (exp.get("result"), exp.get("class"), exp.get("reason"))
        got = (res["status"], res["class"], res["reason"])
        entry = {"expected": list(want), "got": list(got)}
        if pass2 and want[0] == "Verified":
            entry["transcript"] = compare_transcript(d, full, exp, ev, got, tb_tally)
        if pass2 and want[2] in PAYLOAD_LAYER and got != want:
            entry["state"] = "disagree"
            entry["detail"] = res.get("detail") or res.get("diagnostics")
            tally["disagree"] += 1
        elif not pass2 and want[2] in PAYLOAD_LAYER:
            entry["state"] = "not_reached: the expected result rests on the payload schema (second pass)"
            tally["not_reached"] += 1
        elif want[2] in P9_RESOURCE_POLICY and full.get("expected", {}).get("resource_policy"):
            entry["state"] = ("not_reached: the expected result is the 64 MiB transcript cap at P9, set by "
                              "authorization/S2B_PHASE_B5_AUTHORIZATION_v1_ADDENDUM_1.txt, not by the frozen text")
            if pass2:
                entry["transcript_length_computed"] = ev.get("transcript_not_encoded")
                entry["state"] += ("; this reading replays it to Verified, computes the transcript length "
                                   "arithmetically and does not allocate it")
            note("P9, transcript size", "the case SPS-12-ok-u64max expects Unavailable(capability, "
                 "VerifierCapabilityUnsupported) from a 64 MiB cap on the encoded transcript; its own note says 'the "
                 "frozen text sets no limit'; the cap is in the B5 authorization addendum 1 (a build capability). A "
                 "reader of the frozen text alone has no limit and would produce a transcript; reported, not counted")
            tally["not_reached"] += 1
        elif got != want:
            entry["state"] = "disagree"
            entry["detail"] = res.get("detail") or res.get("diagnostics")
            tally["disagree"] += 1
        else:
            entry["state"] = "agree"
            tally["agree"] += 1
            if want[0] == "Verified":
                ee = full.get("expected_evidence", {})
                checks = {}
                for k in ("root", "log_identity_digest", "leaf_encoding_profile_digest", "checkpoint_size",
                          "unreadable_idx"):
                    if k in ee:
                        checks[k] = ev.get(k) == ee[k]
                if "statement_sha256" in ee:
                    checks["statement_sha256"] = ev.get("statement_sha256") == ee["statement_sha256"]
                if "signature_observations" in ee:
                    checks["signature_observations"] = ev.get("signature_observations") == ee["signature_observations"]
                if pass2 and "transcript_sha256" in ee:
                    checks["transcript_sha256"] = ev.get("transcript_sha256") == ee["transcript_sha256"]
                entry["evidence"] = checks
                replay_layer = [k for k in checks if k not in ("unreadable_idx", "signature_observations",
                                                                "transcript_sha256")]
                if pass2:
                    tr = entry["transcript"]
                    if not all(checks.values()) and all(checks[k] for k in checks if k != "transcript_sha256"):
                        entry["state"] = "agree on the result and the evidence; the transcript bytes differ"
                        tally["agree"] -= 1
                        tally["transcript_differs"] = tally.get("transcript_differs", 0) + 1
                    elif not all(checks.values()):
                        entry["state"] = "disagree_on_evidence"
                        tally["agree"] -= 1
                        tally["disagree"] += 1
                    elif tr.get("match") is not True:
                        entry["state"] = "agree on the result and the evidence; the transcript bytes differ"
                        tally["agree"] -= 1
                        tally["transcript_differs"] = tally.get("transcript_differs", 0) + 1
                elif not all(checks[k] for k in replay_layer):
                    entry["state"] = "disagree_on_evidence"
                    tally["agree"] -= 1
                    tally["disagree"] += 1
                elif not all(checks.values()):
                    # rows and observations differ: agreement holds only if every differing index is a subject row,
                    # whose readability rests on schema stage 1 (section 13.4, third row), the second pass
                    theirs_un = set(ee.get("unreadable_idx", []))
                    ours_un = set(ev.get("unreadable_idx", []))
                    diff = (theirs_un ^ ours_un) | {int(i) for i in set(ee.get("signature_observations", {})) ^ set(ev.get("signature_observations", {}))}
                    if diff <= set(ev.get("subject_rows", [])):
                        entry["state"] = "agree_on_replay; rows not reached (schema stage 1 on subject rows, second pass)"
                        tally["agree"] -= 1
                        tally["agree_replay_layer_rows_not_reached"] = tally.get("agree_replay_layer_rows_not_reached", 0) + 1
                    else:
                        entry["state"] = "disagree_on_evidence"
                        tally["agree"] -= 1
                        tally["disagree"] += 1
                if entry["state"] != "agree":
                    entry["ours"] = {k: ev.get(k) for k, v in checks.items() if not v}
                    entry["theirs"] = {k: ee.get(k) for k, v in checks.items() if not v}
        report["cases"][case] = entry
    report["tally"] = tally
    if pass2:
        report["transcript"] = tb_tally
        report["payload_schema"] = ("StatementPayloadSchemaV0 r9, stages 0 to 3 of section 9, with TargetKindMismatch "
                                    "(prereg section 11.2 step 6); nothing after S2a ACCEPT (sections 8.8 to 8.11)")
        if pass1_report:
            report["vs_pass1"] = compare_with_pass1(report, pass1_report)
    else:
        report["transcript"] = "not attempted in this pass: section 15 (tB) is the second pass"
        report["payload_schema"] = "not attempted in this pass: section 13.3, StatementPayloadSchemaV0 r9"
    report["ambiguity_log"] = AMBIGUITIES
    if report_path:
        pathlib.Path(report_path).write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n")
    return report


PASS2_READINGS = [
    ("prereg section 11.2 step 6, the target's wire kind", "the target's wire kind is the kind derived at schema stage "
     "1, which runs only for subject entries (schema section 9); a target that is not a subject entry, or whose row is "
     "unavailable, has no derived kind and gives Invalid(request, TargetKindMismatch). When the target's payload bytes "
     "were not obtained, its kind is unknown and no TargetKindMismatch is emitted (StatementPayloadUnavailable "
     "stands). SPS-17-nfc-subject (target sub differs from the Unicode instance subject) expects TargetKindMismatch; "
     "no vector has a target whose payload is not obtained (in S11 the missing payload is not the target's), so that "
     "half of the reading is not separated by the vectors"),
]


def compare_transcript(d, full, exp, ev, got, tb_tally):
    """Byte-for-byte comparison of this reading's tB with the case's expected bytes: expected_tb_hex in
    expected.json, or the tB.expected file of the s2a-t11 and s2a-post families; and with the manifest's tb_sha256."""
    tb_tally["verified_cases"] += 1
    if "expected_tb_hex" in full:
        theirs, source = bytes.fromhex(full["expected_tb_hex"]), "expected.json expected_tb_hex"
    elif (d / "tB.expected").exists():
        theirs, source = (d / "tB.expected").read_bytes(), "tB.expected"
    else:
        theirs, source = None, None
    out = {"expected_source": source}
    ours = ev.get("tb")
    if ours is None:
        tb_tally["not_encoded"] += 1
        out["match"] = None
        out["reason"] = ("not encoded: replay result " + str(got[0]) if got[0] != "Verified" else
                         f"not encoded: {ev.get('transcript_not_encoded')} bytes")
        return out
    out["sha256"] = sha256(ours).hex()
    out["length"] = len(ours)
    out["rows_unavailable"] = ev["rows_unavailable"]
    out["entries"] = ev["entries"]
    t = tb_tally.setdefault("entries", {"total": 0, "payload_none": 0, "by_kind": {}})
    t["rows_unavailable"] = t.get("rows_unavailable", 0) + ev["rows_unavailable"]
    for _, kind, _, has_payload in ev["entries"]:
        t["total"] += 1
        t["payload_none"] += 0 if has_payload else 1
        t["by_kind"][kind] = t["by_kind"].get(kind, 0) + 1
    if theirs is not None and ours == theirs:
        out["match"] = True
        tb_tally["byte_equal"] += 1
    else:
        out["match"] = False
        tb_tally["differ"] += 1
        if theirs is not None:
            off = first_difference(ours, theirs)
            out["first_difference"] = {"offset": off, "ours": ours[off:off + 16].hex(), "theirs": theirs[off:off + 16].hex(),
                                       "expected_length": len(theirs)}
    if exp.get("tb_sha256") is not None:
        out["manifest_tb_sha256_equal"] = exp["tb_sha256"] == out["sha256"]
        if out["manifest_tb_sha256_equal"] and out["match"]:
            tb_tally["expected_sha256_also_equal"] += 1
    if full.get("tb_expected_sha256") is not None:
        out["tb_expected_sha256_equal"] = full["tb_expected_sha256"] == out["sha256"]
        if out["tb_expected_sha256_equal"] and out["match"]:
            tb_tally["tb_expected_sha256_also_equal"] = tb_tally.get("tb_expected_sha256_also_equal", 0) + 1
    return out


def compare_with_pass1(report, pass1_path):
    """Nothing may regress: every case that fully agreed in pass 1 must fully agree now."""
    p1 = json.loads(pathlib.Path(pass1_path).read_text())
    regressed = [c for c, e in p1["cases"].items() if e.get("state") == "agree"
                 and report["cases"].get(c, {}).get("state") != "agree"]
    moved = {c: [e.get("state"), report["cases"].get(c, {}).get("state")] for c, e in p1["cases"].items()
             if e.get("state") != "agree"}
    return {"pass1_tally": p1["tally"], "regressed": regressed, "pass1_non_agreeing_now": moved}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors", required=True)
    ap.add_argument("--report")
    ap.add_argument("--pass", dest="pass_no", type=int, choices=(1, 2), default=1)
    ap.add_argument("--pass1-report")
    a = ap.parse_args()
    rep = run(a.vectors, a.report, a.pass_no, a.pass1_report)
    t = rep["tally"]
    lv = rep["leaf_vectors"]
    if a.pass_no == 1:
        print(f"# P10 S2b outside reading, first pass: L1-L8 {sum(lv.values())}/{len(lv)}; of {sum(t.values())} cases, "
              f"{t['agree']} agree, {t.get('agree_replay_layer_rows_not_reached', 0)} agree on the replay layer with "
              f"their subject rows left to the second pass, {t['not_reached']} not reached, {t['disagree']} disagree")
        sys.exit(0 if t["disagree"] == 0 and all(lv.values()) else 1)
    tb = rep["transcript"]
    print(f"# P10 S2b outside reading, second pass: L1-L8 {sum(lv.values())}/{len(lv)}; of {sum(t.values())} cases, "
          f"{t['agree']} agree fully, {t.get('agree_replay_layer_rows_not_reached', 0)} agree on the replay layer "
          f"only, {t.get('transcript_differs', 0)} agree except for the transcript bytes, {t['not_reached']} not "
          f"reached, {t['disagree']} disagree; tB byte-equal {tb['byte_equal']} of {tb['verified_cases']} Verified "
          f"({tb['differ']} differ, {tb['not_encoded']} not encoded)"
          + (f"; regressions against pass 1: {len(rep['vs_pass1']['regressed'])}" if "vs_pass1" in rep else ""))
    sys.exit(0 if t["disagree"] == 0 and all(lv.values()) and not rep.get("vs_pass1", {}).get("regressed") else 1)
