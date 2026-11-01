#!/usr/bin/env python3
"""Bridge run B3 of PALA-1, from the text alone: the SCITT-bridge Signed Statement, construction v3, read and
reproduced from docs/interop/SCITT-STATEMENT-V3-VERIFICATION-TASK.md, the v2 task it builds on, PALA-1 sections
1.2, 4.1 and 4.3, consistency-proof.md sections 1 and 2, the published vector data, and RFC 9052, 9597, 8032, 8949,
9679, 6962 and 9162. Nothing of the repository's code, generators or history was read (the task's boundary).

What runs, in the task's order: (1) the derived roots over 8 and 12 record hashes, and, stretch, the 12 record
hashes from the published headers and the companion consistency vectors; (2) parse and verify both statements as
the v2 task's steps 1 to 4; (3) the v3 parts: content type, exactly keys 1 to 5, key 5 the root over 0..last_seq;
(4) the consistency proof from the two roots read from the statements, by RFC 9162 section 2.1.4.2, with nothing
but the two statements, the proof and the public key; (5) reproduction byte for byte from the inputs and the seed;
(6) the tamper expectations, and the version rule with statements of our own; (7) the v2 regression; (8) adversarial
cases. Every CBOR and COSE byte here is produced and read by the code below, written from RFC 8949 and RFC 9052;
Ed25519 is the cryptography library's, with the RFC 8032 section 5.1.7 range check on S made explicit.

Usage: verify_statement_v3.py --vectors DIR [--report out.json]   (DIR holds docs/ as fetched from the repository)
"""
import argparse
import hashlib
import json
import os
import pathlib
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

V2_TYPE = "application/vnd.palimpsests.pala1-head+cbor"
V3_TYPE = "application/vnd.palimpsests.pala1-head-v3+cbor"
FORMAT_ID = "pala-1/v1.0"
L_ED25519 = 2 ** 252 + 27742317777372353535851937790883648493
AMBIGUITIES = []


def note(where, text):
    AMBIGUITIES.append({"where": where, "reading": text})


# ---------------------------------------------------------------- CBOR, RFC 8949, deterministic encoding (section 4.2.1)

def _head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def cbor_encode(v):
    if isinstance(v, bool):
        raise ValueError("no booleans here")
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor_encode(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((cbor_encode(k), cbor_encode(x)) for k, x in v.items()), key=lambda kv: (len(kv[0]), kv[0]))
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    if isinstance(v, Tag):
        return _head(6, v.tag) + cbor_encode(v.value)
    raise ValueError(f"cannot encode {type(v)}")


class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


class CborError(ValueError):
    pass


def cbor_decode(data, strict=True):
    """One item and its length. strict: definite lengths only, shortest integer encodings, no duplicate keys, map
    keys in deterministic order (sections 4.2.1 and 4.2.2); the order and duplicate findings are kept apart so a
    caller can say which rule a document broke."""
    pos = 0
    findings = []

    def take(n):
        nonlocal pos
        if pos + n > len(data):
            raise CborError("truncated")
        pos += n
        return data[pos - n:pos]

    def head():
        ib = take(1)[0]
        major, ai = ib >> 5, ib & 0x1F
        if ai < 24:
            return major, ai
        if ai == 24:
            n = take(1)[0]
            if strict and n < 24:
                raise CborError("integer not in shortest form")
            return major, n
        if ai in (25, 26, 27):
            size = {25: 2, 26: 4, 27: 8}[ai]
            n = int.from_bytes(take(size), "big")
            if strict and n < (1 << (8 * size // 2)) and (size > 1):
                raise CborError("integer not in shortest form")
            return major, n
        if ai == 31:
            raise CborError("indefinite length")
        raise CborError("reserved additional information")

    def item():
        major, n = head()
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 2:
            return take(n)
        if major == 3:
            return take(n).decode("utf-8")
        if major == 4:
            return [item() for _ in range(n)]
        if major == 5:
            out, raw_keys = {}, []
            for _ in range(n):
                start = pos
                k = item()
                raw_keys.append(data[start:pos])
                if not isinstance(k, (int, str, bytes)):
                    raise CborError("map key type")
                if k in out:
                    findings.append("duplicate map key")
                out[k] = item()
            if raw_keys != sorted(raw_keys, key=lambda b: (len(b), b)):
                findings.append("map keys not in deterministic order")
            return out
        if major == 6:
            return Tag(n, item())
        raise CborError("simple values and floats are not used here")
    v = item()
    return v, pos, findings


# ---------------------------------------------------------------- the tree (PALA-1 section 4.3) and the proof (RFC 9162 section 2.1.4.2)

def leaf(d):
    return hashlib.sha256(b"\x00" + d).digest()


def node(l, r):
    return hashlib.sha256(b"\x01" + l + r).digest()


def root_promote(hashes):
    """The derived root, bottom-up, an unpaired node promoted, never duplicated; the empty chain's root SHA-256("")."""
    if not hashes:
        return hashlib.sha256(b"").digest()
    level = [leaf(d) for d in hashes]
    while len(level) > 1:
        nxt = [node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def root_rfc6962(hashes):
    """RFC 6962 section 2.1: MTH, recursive, split at the largest power of two smaller than n."""
    n = len(hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf(hashes[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return node(root_rfc6962(hashes[:k]), root_rfc6962(hashes[k:]))


def consistency_verifies(first, second, path, root1, root2):
    """RFC 9162 section 2.1.4.2, after the two pre-checks consistency-proof.md section 2 places before it."""
    if first == second:
        return (not path) and root1 == root2
    if first == 0 or first > second:
        return False
    if not path:
        return False
    path = list(path)
    if first & (first - 1) == 0:          # first is an exact power of two
        path = [root1] + path
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for p in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node(p, fr)
            sr = node(p, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node(sr, p)
        fn >>= 1
        sn >>= 1
    return fr == root1 and sr == root2 and sn == 0


# ---------------------------------------------------------------- COSE_Sign1 (RFC 9052), the construction

def thumbprint(public_key):
    """RFC 9679: SHA-256 over the deterministic CBOR of the required members of the COSE_Key, here OKP/Ed25519."""
    return hashlib.sha256(cbor_encode({1: 1, -1: 6, -2: public_key})).digest()


def protected_header(content_type, kid, issuer, subject):
    return cbor_encode({1: -8, 3: content_type, 4: kid, 15: {1: issuer, 2: subject}})


def payload_bytes(head, first_seq, last_seq, root=None):
    m = {1: head, 2: first_seq, 3: last_seq, 4: FORMAT_ID}
    if root is not None:
        m[5] = root
    return cbor_encode(m)


def sig_structure(protected, payload):
    return cbor_encode(["Signature1", protected, b"", payload])


def build_statement(seed, content_type, issuer, subject, head, first_seq, last_seq, root=None):
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes_raw()
    prot = protected_header(content_type, thumbprint(pk), issuer, subject)
    pay = payload_bytes(head, first_seq, last_seq, root)
    sig = sk.sign(sig_structure(prot, pay))
    return cbor_encode(Tag(18, [prot, {}, pay, sig]))


def read_statement(raw, public_key, chain_hashes=None, expect=None):
    """Parse and verify one statement: the v2 task's steps 1 to 4, then the v3 parts and the version rule.
    Returns a dict of checks (True/False/str) and the values read; never raises on a malformed input."""
    r = {"checks": {}, "read": {}}
    c = r["checks"]
    try:
        v, n, findings = cbor_decode(raw)
    except (CborError, UnicodeDecodeError) as e:
        c["cbor"] = f"not readable: {e}"
        return r
    c["cbor"] = "readable" + ("" if not findings else f" with findings: {findings}")
    c["whole_input_consumed"] = n == len(raw)
    c["tag_18"] = isinstance(v, Tag) and v.tag == 18 and raw[:1] == b"\xd2"
    arr = v.value if isinstance(v, Tag) else v
    c["four_elements"] = isinstance(arr, list) and len(arr) == 4
    if not c["four_elements"]:
        return r
    prot, unprot, pay, sig = arr
    c["protected_is_bstr"] = isinstance(prot, bytes)
    c["unprotected_empty_map"] = isinstance(unprot, dict) and not unprot
    c["payload_attached_bstr"] = isinstance(pay, bytes)
    c["signature_64_bytes"] = isinstance(sig, bytes) and len(sig) == 64
    if not (c["protected_is_bstr"] and c["payload_attached_bstr"] and c["signature_64_bytes"]):
        return r
    # step 2: the signature over the Sig_structure the verifier assembles, with the public key given
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(sig, sig_structure(prot, pay))
        c["signature"] = True
    except InvalidSignature:
        c["signature"] = False
    s_scalar = int.from_bytes(sig[32:], "little")
    c["signature_s_in_range_rfc8032_5_1_7"] = s_scalar < L_ED25519
    # step 4: the protected header, label by label, in ascending order, nothing else
    try:
        ph, _, pfind = cbor_decode(prot)
    except (CborError, UnicodeDecodeError) as e:
        c["protected_header"] = f"not readable: {e}"
        return r
    c["protected_header_deterministic"] = not pfind
    c["protected_labels_exactly_1_3_4_15"] = isinstance(ph, dict) and sorted(ph) == [1, 3, 4, 15] if isinstance(ph, dict) else False
    if not isinstance(ph, dict):
        return r
    c["alg_minus_8"] = ph.get(1) == -8
    c["kid_is_rfc9679_thumbprint"] = ph.get(4) == thumbprint(public_key)
    ctype = ph.get(3)
    r["read"]["content_type"] = ctype
    claims = ph.get(15)
    c["cwt_claims_1_and_2"] = isinstance(claims, dict) and sorted(claims) == [1, 2] and isinstance(claims.get(1), str) and isinstance(claims.get(2), str)
    r["read"]["issuer"] = claims.get(1) if isinstance(claims, dict) else None
    r["read"]["subject"] = claims.get(2) if isinstance(claims, dict) else None
    # step 3: the payload
    try:
        pm, _, pyfind = cbor_decode(pay)
    except (CborError, UnicodeDecodeError) as e:
        c["payload"] = f"not readable: {e}"
        return r
    c["payload_deterministic"] = not pyfind
    keys = sorted(pm) if isinstance(pm, dict) else None
    r["read"]["payload_keys"] = keys
    version = "v3" if ctype == V3_TYPE else "v2" if ctype == V2_TYPE else None
    r["read"]["version"] = version
    if version == "v3":
        c["version_rule"] = keys == [1, 2, 3, 4, 5] and isinstance(pm.get(5), bytes) and len(pm[5]) == 32
    elif version == "v2":
        c["version_rule"] = keys == [1, 2, 3, 4]
    else:
        c["version_rule"] = False
    head = pm.get(1) if isinstance(pm, dict) else None
    c["head_32_bytes"] = isinstance(head, bytes) and len(head) == 32
    c["format_id"] = pm.get(4) == FORMAT_ID if isinstance(pm, dict) else False
    fs, ls = (pm.get(2), pm.get(3)) if isinstance(pm, dict) else (None, None)
    c["range_0_le_first_le_last"] = isinstance(fs, int) and isinstance(ls, int) and 0 <= fs <= ls
    r["read"].update(first_seq=fs, last_seq=ls, head_hex=head.hex() if isinstance(head, bytes) else None)
    c["subject_is_full_head"] = r["read"]["subject"] == ("pala-1:chain:" + head.hex()) if isinstance(head, bytes) else False
    if version == "v3" and c["version_rule"]:
        root = pm[5]
        r["read"]["root_hex"] = root.hex()
        if chain_hashes is not None and isinstance(ls, int) and 0 <= ls < len(chain_hashes):
            c["root_recomputed_over_0_to_last_seq"] = root == root_promote(chain_hashes[:ls + 1])
            c["head_is_record_last_seq_hash"] = head == chain_hashes[ls]
            r["read"]["root_status"] = "recomputed" if c["root_recomputed_over_0_to_last_seq"] else "mismatch"
        else:
            r["read"]["root_status"] = "carried"   # without the chain, the root is carried, never verified
    if expect:
        for k, want in expect.items():
            c[f"matches_{k}"] = r["read"].get(k) == want
    return r


# ---------------------------------------------------------------- the run

def run(vectors_dir, report_path=None):
    t0 = time.time()
    D = pathlib.Path(vectors_dir)
    v3 = json.load(open(D / "docs/interop/scitt-statement-vector-v3.json"))
    v2 = json.load(open(D / "docs/interop/scitt-statement-vector.json"))
    core = json.load(open(D / "docs/specs/pala-1/test-vectors.json"))
    comp = json.load(open(D / "docs/specs/pala-1/consistency-vectors.json"))
    out = {"vector_sha256": hashlib.sha256(open(D / "docs/interop/scitt-statement-vector-v3.json", "rb").read()).hexdigest()}
    seed = bytes.fromhex(v3["key"]["private_seed_hex"])
    pk = bytes.fromhex(v3["key"]["public_key_hex"])
    hashes = [bytes.fromhex(h) for h in v3["subject_chain"]["record_hashes_hex"]]
    issuer = v3["construction"]["issuer"]

    # (1) roots
    r1 = {}
    for name, n in (("earlier", 8), ("later", 12)):
        want = v3["statements"][name]["inputs"]["root_hex"]
        r1[f"root_over_{n}"] = {"promote": root_promote(hashes[:n]).hex() == want, "rfc6962_recursive": root_rfc6962(hashes[:n]).hex() == want}
    r1["kid_matches_vector"] = thumbprint(pk).hex() == v3["construction"]["kid_hex"]
    # stretch: the 12 record hashes from the published headers (PALA-1 section 4.1: record_hash = SHA-256(header_bytes))
    rec = core["records"]
    r1["record_hashes_from_headers"] = all(hashlib.sha256(bytes.fromhex(x["header_hex"])).hexdigest() == x["record_hash"] for x in rec) and \
        [x["record_hash"] for x in rec] == v3["subject_chain"]["record_hashes_hex"]
    # stretch: the companion consistency vectors over the 17-record chain: roots by count and every proof, positive and negative
    comp_leaves = comp.get("record_hashes_hex") or comp.get("leaves_hex") or comp.get("record_hashes")
    roots_ok = None
    if isinstance(comp_leaves, list) and all(isinstance(x, str) and len(x) == 64 for x in comp_leaves):
        cl = [bytes.fromhex(x) for x in comp_leaves]
        roots_ok = all(root_promote(cl[:int(k)]).hex() == vv for k, vv in comp["roots_by_count"].items())
    r1["companion_roots_by_count"] = roots_ok if roots_ok is not None else "not attempted: the companion file names its leaves' source (profiles/inference-vectors.json), which the task's boundary does not list"
    r1["companion_proofs_verify"] = all(consistency_verifies(p["first"], p["second"], [bytes.fromhex(x) for x in p["path"]],
                                                             bytes.fromhex(p["first_root"]), bytes.fromhex(p["second_root"])) for p in comp["proofs"])
    r1["companion_negatives_fail"] = {k: not consistency_verifies(p["first"], p["second"], [bytes.fromhex(x) for x in p["path"]],
                                                                 bytes.fromhex(p["first_root"]), bytes.fromhex(p["second_root"]))
                                      for k, p in comp["negative"].items() if isinstance(p, dict)}
    out["1_roots"] = r1

    # (2) and (3): parse and verify both statements, with the chain held and without it
    r23 = {}
    for name in ("earlier", "later"):
        st = v3["statements"][name]
        raw = bytes.fromhex(st["expected"]["statement_hex"])
        exp = {"head_hex": st["inputs"]["chain_head_hex"], "first_seq": st["inputs"]["first_seq"], "last_seq": st["inputs"]["last_seq"],
               "subject": st["inputs"]["subject"], "issuer": issuer, "content_type": V3_TYPE, "root_hex": st["inputs"]["root_hex"]}
        with_chain = read_statement(raw, pk, hashes, exp)
        without = read_statement(raw, pk, None, exp)
        r23[name] = {"with_chain": with_chain, "without_chain_root_status": without["read"].get("root_status"),
                     "sha256_matches": hashlib.sha256(raw).hexdigest() == st["expected"]["statement_sha256"],
                     "length_matches": len(raw) == st["expected"]["statement_length_bytes"]}
    out["2_3_statements"] = r23

    # (4) the case v3 exists for: the proof from the two roots read from the statements, nothing else
    roots = {name: bytes.fromhex(r23[name]["with_chain"]["read"]["root_hex"]) for name in ("earlier", "later")}
    cons = v3["consistency"]
    path = [bytes.fromhex(x) for x in cons["path"]]
    r4 = {"format": cons["format"] == "pala-consistency-proof/1",
          "verifies_from_statements_roots_only": consistency_verifies(cons["first"], cons["second"], path, roots["earlier"], roots["later"]),
          "inputs_used": "the two statements (their payload roots and signatures), the proof document, the public key; no chain",
          "proof_roots_equal_statement_roots": cons["first_root"] == roots["earlier"].hex() and cons["second_root"] == roots["later"].hex(),
          "what_it_establishes": "a relation between the two roots: the 12-record state extends the 8-record state; nothing about either head"}
    out["4_consistency"] = r4

    # (5) reproduction, byte for byte
    r5 = {}
    for name in ("earlier", "later"):
        st = v3["statements"][name]
        i = st["inputs"]
        mine = build_statement(seed, V3_TYPE, issuer, i["subject"], bytes.fromhex(i["chain_head_hex"]), i["first_seq"], i["last_seq"], bytes.fromhex(i["root_hex"]))
        want = bytes.fromhex(st["expected"]["statement_hex"])
        diff = next((k for k in range(min(len(mine), len(want))) if mine[k] != want[k]), None if len(mine) == len(want) else min(len(mine), len(want)))
        r5[name] = {"byte_identical": mine == want, "first_differing_offset": diff, "length": len(mine)}
    out["5_reproduction"] = r5

    # (6) tamper expectations, and the version rule with statements of our own
    e, l = v3["statements"]["earlier"]["inputs"], v3["statements"]["later"]["inputs"]
    raw_e = bytes.fromhex(v3["statements"]["earlier"]["expected"]["statement_hex"])
    t = {}
    flipped = bytearray(raw_e)
    k = raw_e.rfind(bytes.fromhex(e["root_hex"]))          # the root inside the payload
    flipped[k + 5] ^= 0x01
    t["T1_flip_a_root_bit_signature_fails"] = read_statement(bytes(flipped), pk, hashes)["checks"].get("signature") is False
    wrong_root = hashlib.sha256(b"not the derived root").digest()
    t["T2_root_not_derived_rejected_against_chain"] = read_statement(build_statement(seed, V3_TYPE, issuer, e["subject"], bytes.fromhex(e["chain_head_hex"]), 0, 7, wrong_root), pk, hashes)["checks"].get("root_recomputed_over_0_to_last_seq") is False
    root_8_11 = root_promote(hashes[8:12])
    st_8_11 = build_statement(seed, V3_TYPE, issuer, l["subject"], bytes.fromhex(l["chain_head_hex"]), 8, 11, root_8_11)
    t["T3_root_over_first_to_last_rejected_against_chain"] = read_statement(st_8_11, pk, hashes)["checks"].get("root_recomputed_over_0_to_last_seq") is False
    t["T3_root_over_first_to_last_proof_does_not_verify"] = not consistency_verifies(8, 12, path, roots["earlier"], root_8_11)
    t["T4_root_over_last_seq_records_rejected"] = read_statement(build_statement(seed, V3_TYPE, issuer, l["subject"], bytes.fromhex(l["chain_head_hex"]), 8, 11, root_promote(hashes[:11])), pk, hashes)["checks"].get("root_recomputed_over_0_to_last_seq") is False
    t["T4_root_over_last_seq_plus_2_records_rejected"] = read_statement(build_statement(seed, V3_TYPE, issuer, e["subject"], bytes.fromhex(e["chain_head_hex"]), 0, 7, root_promote(hashes[:10])), pk, hashes)["checks"].get("root_recomputed_over_0_to_last_seq") is False
    v3_no_root = build_statement(seed, V3_TYPE, issuer, e["subject"], bytes.fromhex(e["chain_head_hex"]), 0, 7, None)
    v2_with_root = build_statement(seed, V2_TYPE, issuer, e["subject"], bytes.fromhex(e["chain_head_hex"]), 0, 7, bytes.fromhex(e["root_hex"]))
    rr = read_statement(v3_no_root, pk, hashes)["checks"]
    t["T5_v3_type_without_key_5_refused_though_signature_verifies"] = rr.get("signature") is True and rr.get("version_rule") is False
    rr = read_statement(v2_with_root, pk, hashes)["checks"]
    t["T5_key_5_under_v2_type_refused_though_signature_verifies"] = rr.get("signature") is True and rr.get("version_rule") is False
    t["T6_drop_last_path_node_fails"] = not consistency_verifies(8, 12, path[:-1], roots["earlier"], roots["later"])
    t["T6_swap_roots_fails"] = not consistency_verifies(8, 12, path, roots["later"], roots["earlier"])
    t["T7_without_chain_root_is_carried_not_verified"] = r23["earlier"]["without_chain_root_status"] == "carried"
    out["6_tamper"] = t

    # (7) regression: the v2 statement verifies and reads as v2, no root
    raw2 = bytes.fromhex(v2["expected"]["statement_hex"])
    s2 = read_statement(raw2, bytes.fromhex(v2["key"]["public_key_hex"]), hashes,
                        {"head_hex": v2["subject_chain"]["chain_head_hex"], "first_seq": v2["subject_chain"]["first_seq"],
                         "last_seq": v2["subject_chain"]["last_seq"], "content_type": V2_TYPE})
    out["7_v2_regression"] = {"signature": s2["checks"].get("signature"), "version": s2["read"].get("version"), "version_rule": s2["checks"].get("version_rule"),
                              "no_root": "root_hex" not in s2["read"], "sha256_matches": hashlib.sha256(raw2).hexdigest() == v2["expected"]["statement_sha256"],
                              "all_checks": all(v is True for k, v in s2["checks"].items() if isinstance(v, bool))}

    # (8) adversarial: how a careful verifier treats each
    a = {}
    # payload keys out of order: re-encode the payload map with keys 5,1,2,3,4 and sign it
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    prot = protected_header(V3_TYPE, thumbprint(pk), issuer, e["subject"])
    m = {1: bytes.fromhex(e["chain_head_hex"]), 2: 0, 3: 7, 4: FORMAT_ID, 5: bytes.fromhex(e["root_hex"])}
    unordered = _head(5, 5) + b"".join(cbor_encode(k) + cbor_encode(m[k]) for k in (5, 1, 2, 3, 4))
    st = cbor_encode(Tag(18, [prot, {}, unordered, sk.sign(sig_structure(prot, unordered))]))
    rr = read_statement(st, pk, hashes)["checks"]
    a["payload_keys_out_of_order"] = {"signature": rr.get("signature"), "payload_deterministic": rr.get("payload_deterministic"),
                                      "treatment": "the signature verifies and every value reads; the map is not deterministically encoded (RFC 8949 4.2.1), which a reader that insists on one encoding per value refuses; this reader reports it and keeps the verdict on the values"}
    dup = _head(5, 6) + b"".join(cbor_encode(k) + cbor_encode(m[k]) for k in (1, 2, 3, 4, 5)) + cbor_encode(5) + cbor_encode(wrong_root)
    st = cbor_encode(Tag(18, [prot, {}, dup, sk.sign(sig_structure(prot, dup))]))
    rr = read_statement(st, pk, hashes)["checks"]
    a["payload_key_5_duplicated"] = {"signature": rr.get("signature"), "payload_deterministic": rr.get("payload_deterministic"),
                                     "root_recomputed": rr.get("root_recomputed_over_0_to_last_seq"),
                                     "treatment": "refuse: a duplicate key leaves the root the signature covers ambiguous (this reader keeps the last and flags it; a reader keeping the first would recompute true)"}
    for n_bytes in (31, 33):
        st = build_statement(seed, V3_TYPE, issuer, e["subject"], bytes.fromhex(e["chain_head_hex"]), 0, 7, bytes.fromhex(e["root_hex"])[:31] if n_bytes == 31 else bytes.fromhex(e["root_hex"]) + b"\x00")
        rr = read_statement(st, pk, hashes)["checks"]
        a[f"key_5_of_{n_bytes}_bytes"] = {"version_rule": rr.get("version_rule"), "treatment": "refused by the version rule: key 5 is a 32-byte root or the statement is not a v3 statement"}
    st = build_statement(seed, V3_TYPE, issuer, e["subject"], bytes.fromhex(e["chain_head_hex"]), 9, 7, bytes.fromhex(e["root_hex"]))
    rr = read_statement(st, pk, hashes)["checks"]
    a["first_seq_greater_than_last_seq"] = {"range": rr.get("range_0_le_first_le_last"), "treatment": "refused by the range rule (B3, F4), whatever the signature says"}
    st = build_statement(seed, V3_TYPE, issuer, e["subject"], bytes.fromhex(e["chain_head_hex"]), 0, 7, root_promote(hashes[:8]))
    head_later = build_statement(seed, V3_TYPE, issuer, l["subject"], bytes.fromhex(l["chain_head_hex"]), 0, 7, root_promote(hashes[:8]))
    rr = read_statement(head_later, pk, None)["checks"]
    a["head_of_record_11_with_root_over_0_to_7_without_chain"] = {"accepted_without_chain": all(v is True for v in rr.values() if isinstance(v, bool)),
                                                                    "rejected_with_chain": read_statement(head_later, pk, hashes)["checks"].get("head_is_record_last_seq_hash") is False,
                                                                    "treatment": "without the chain nothing binds key 1 to key 5 (the task's F3): accepted, and the proof between roots never reads a head; with the chain, the head is checked against record last_seq"}
    # each adversarial case states the outcome a careful verifier reaches; the run passes when it reached it
    a["payload_keys_out_of_order"]["as_expected"] = a["payload_keys_out_of_order"]["signature"] is True and a["payload_keys_out_of_order"]["payload_deterministic"] is False
    a["payload_key_5_duplicated"]["as_expected"] = a["payload_key_5_duplicated"]["payload_deterministic"] is False and a["payload_key_5_duplicated"]["root_recomputed"] is False
    a["key_5_of_31_bytes"]["as_expected"] = a["key_5_of_31_bytes"]["version_rule"] is False
    a["key_5_of_33_bytes"]["as_expected"] = a["key_5_of_33_bytes"]["version_rule"] is False
    a["first_seq_greater_than_last_seq"]["as_expected"] = a["first_seq_greater_than_last_seq"]["range"] is False
    a["head_of_record_11_with_root_over_0_to_7_without_chain"]["as_expected"] = a["head_of_record_11_with_root_over_0_to_7_without_chain"]["accepted_without_chain"] is True and a["head_of_record_11_with_root_over_0_to_7_without_chain"]["rejected_with_chain"] is True
    out["8_adversarial"] = a
    out["ambiguity_log"] = AMBIGUITIES
    out["wall_clock_seconds"] = round(time.time() - t0, 2)
    flat = []

    def walk(o, p=""):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, p + "/" + str(k))
        elif isinstance(o, bool):
            flat.append((p, o))
    walk({k: v for k, v in out.items() if k[0].isdigit() and k != "8_adversarial"})
    flat += [("/8_adversarial/" + k + "/as_expected", v["as_expected"]) for k, v in a.items()]
    out["booleans_true"] = sum(1 for _, v in flat if v)
    out["booleans_total"] = len(flat)
    out["booleans_false"] = [p for p, v in flat if not v]
    if report_path:
        json.dump(out, open(report_path, "w"), indent=1)
    return out


note("task, step 2", "'verify both statements as in the v2 task, steps 1-4': the v2 task's step 4 says the four protected labels sit in ascending order and names no fifth; this reader requires exactly the four (1, 3, 4, 15), so a statement adding a label fails 'protected_labels_exactly_1_3_4_15' rather than being read; the text does not say whether a fifth label is a refusal.")
note("task, 'Construction v3'", "'encoded in ascending order' for the protected header, and 'integer keys in ascending order' for the payload: read as RFC 8949 section 4.2.1 deterministic order (length first, then bytes), which for these keys equals numeric order; a reader that takes numeric order would read the same bytes.")
note("task, version rule", "'a v3 statement exactly 1-5 with a 32-byte key 5': a key 5 that is a byte string of another length is refused under the version rule here, not reported as a malformed root; the text names the length in the version rule, so that is where it fails.")
note("task, step 4", "'using nothing but the two statements, the proof and the public key': the proof document carries first_root and second_root beside the path; this reader takes the roots from the statements and reports whether the document's copies equal them, never using the document's roots for the verification, as consistency-proof.md section 3 asks.")
note("RFC 9162 2.1.4.2 vs consistency-proof.md 2", "first == second with an empty path and equal roots, and first == 0, are settled before the RFC algorithm as the companion text says; RFC 9162's own algorithm fails any empty path, so a reader entering it directly for first == second would refuse a proof the companion accepts (the companion's F1).")
note("RFC 8032 5.1.7", "the cryptography library's verify is used for the signature; the range check S < L is made explicit beside it, since the v2 history (B2, F-2) records that libraries differ; both statements pass it.")
note("task, step 8", "'payload keys out of order': RFC 9052 does not require deterministic encoding of a payload; the task's construction does. This reader reports non-deterministic encoding as a finding and does not refuse on it alone, so that the verdict on the values stays separate from the verdict on the encoding; a reader that refuses is also defensible, and the text could say which it wants.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors", required=True)
    ap.add_argument("--report")
    args = ap.parse_args()
    res = run(args.vectors, args.report)
    print(json.dumps({k: v for k, v in res.items() if k not in ("ambiguity_log",)}, indent=1, default=str)[:6000])
    print(f"# PALA-1 bridge run B3: {res['booleans_true']}/{res['booleans_total']} checks true; false: {res['booleans_false']}; {res['wall_clock_seconds']} s")
    sys.exit(0 if not res["booleans_false"] else 1)
