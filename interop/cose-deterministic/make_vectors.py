#!/usr/bin/env python3.12
"""Build our own test vectors for draft-mih-sokolov-cose-deterministic-encodings-00.

Everything is deterministic given demo-key.json (Ed25519 signatures are
deterministic). The key is a DEMONSTRATION key, published on purpose.
"""
import hashlib
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import cbor_det  # noqa: E402
import ed25519_pure  # noqa: E402
from verify_from_text import DEFAULT_LABEL as ENC, sig_structure  # noqa: E402

VEC = os.path.join(HERE, "vectors")
KEY_FILE = os.path.join(HERE, "demo-key.json")


def demo_key():
    if not os.path.exists(KEY_FILE):
        seed = os.urandom(32)
        with open(KEY_FILE, "w") as fh:
            json.dump({
                "warning": "DEMONSTRATION KEY ONLY. Private seed published on purpose. Never trust it.",
                "kty": "OKP", "crv": "Ed25519", "cose_alg": -8,
                "seed_hex": seed.hex(),
                "public_hex": ed25519_pure.public_key(seed).hex(),
            }, fh, indent=2)
            fh.write("\n")
    with open(KEY_FILE) as fh:
        k = json.load(fh)
    return bytes.fromhex(k["seed_hex"]), bytes.fromhex(k["public_hex"])


SEED, PUB = demo_key()
OTHER_SEED = hashlib.sha256(b"not the demo key").digest()


def sign1(protected, payload, unprotected=None, seed=SEED, tagged=True):
    prot_b = cbor_det.encode(protected)
    sig = ed25519_pure.sign(seed, sig_structure(prot_b, payload))
    body = [prot_b, unprotected or {}, payload, sig]
    return cbor_det.encode(cbor_det.Tag(18, body) if tagged else body)


def header(ct="application/cbor", enc=1, loc=None, extra=None):
    h = {1: -8, 258: -16}
    if ct is not None:
        h[259] = ct
    if loc is not None:
        h[260] = loc
    if enc is not None:
        h[ENC] = enc
    if extra:
        h.update(extra)
    return h


def sha256(b):
    return hashlib.sha256(b).digest()


CAPSULE_1 = {
    "capsule": "dps-demo-1",
    "action": "send-quote",
    "actor": "agent:pria",
    "subject": "client:42",
    "decision": "approved",
    "ts": "2026-11-10T09:00:00Z",
    "seq": 1,
}

CAPSULE_2 = {
    "capsule": "dps-demo-2",
    "steps": [{"op": "read", "n": 3}, {"op": "write", "n": -25}],
    "limits": {"max": 1000, "min": -1, "big": 4294967296},
    "score": 0.5,
    "ratio": 1.1,
    "ok": True,
    "note": None,
    "evidence": [],
}

# Mixed int / text keys: bytewise (4.2.1) and length-first (4.2.3) orders differ.
CAPSULE_3 = {"a": 2, 1000: 1, "capsule": "dps-demo-3"}


def non_canonical_capsule_1():
    """Same data model value as CAPSULE_1, encoded in insertion order with the
    "seq" integer and one string length on non-shortest arguments."""
    out = bytearray(b"\xa7")
    for k, v in CAPSULE_1.items():
        out += cbor_det.encode(k)
        if k == "seq":
            out += b"\x18\x01"  # 1 on a uint8 argument
        elif k == "capsule":
            vb = v.encode()
            out += b"\x78" + bytes([len(vb)]) + vb  # length 10 on a uint8 argument
        else:
            out += cbor_det.encode(v)
    return bytes(out)


def write(name, expected, description, envelope, files, args):
    d = os.path.join(VEC, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "envelope.cbor"), "wb") as fh:
        fh.write(envelope)
    for fname, data in files.items():
        mode = "w" if isinstance(data, str) else "wb"
        with open(os.path.join(d, fname), mode) as fh:
            fh.write(data)
    with open(os.path.join(d, "expected.json"), "w") as fh:
        json.dump({"expected_verdict": expected, "description": description,
                   "args": args + ["--pubkey", "demo-key.json"]}, fh, indent=2)
        fh.write("\n")


def jtext(v):
    return json.dumps(v, indent=2, ensure_ascii=False) + "\n"


def main():
    if os.path.isdir(VEC):
        shutil.rmtree(VEC)
    c1 = cbor_det.encode(CAPSULE_1)
    c2 = cbor_det.encode(CAPSULE_2)

    # ---------------- positives
    write("P1-capsule-bytes", "pass",
          "JSON capsule encoded core-deterministic; verifier holds the preimage bytes.",
          sign1(header(loc="capsule-1.cbor"), sha256(c1)),
          {"capsule-1.cbor": c1, "capsule-1.json": jtext(CAPSULE_1)},
          ["--preimage", "capsule-1.cbor"])
    write("P2-capsule-value", "pass",
          "Nested capsule (floats, negative and 33-bit ints, null, empty array) with a +cbor "
          "media type; verifier holds only the JSON value and re-encodes it.",
          sign1(header(ct="application/vnd.example.capsule+cbor"), sha256(c2)),
          {"capsule-2.json": jtext(CAPSULE_2)},
          ["--value-json", "capsule-2.json"])
    write("P3-cf60-stored-noncanonical", "pass",
          "Extra positive: 259 is CoAP Content-Format 60 (application/cbor); the verifier "
          "stored the value in a non-deterministic CBOR form, decodes it and re-encodes it.",
          sign1(header(ct=60), sha256(c1)),
          {"stored-value.cbor": non_canonical_capsule_1()},
          ["--value-cbor", "stored-value.cbor"])

    # ---------------- the four requested negatives
    write("Na-header-absent", "cannot-recompute",
          "(a) deterministic-encodings absent; verifier holds only the structured value.",
          sign1(header(enc=None), sha256(c1)),
          {"capsule-1.json": jtext(CAPSULE_1)},
          ["--value-json", "capsule-1.json"])
    write("Nb-encoding-not-implemented", "unsupported-encoding",
          "(b) deterministic-encodings = 2, a value this checker does not implement "
          "(unassigned in the draft's initial registry).",
          sign1(header(enc=2), sha256(c1)),
          {"capsule-1.json": jtext(CAPSULE_1)},
          ["--value-json", "capsule-1.json"])
    nc = non_canonical_capsule_1()
    write("Nc-preimage-not-canonical", "not-canonical",
          "(c) header says core-deterministic, but the hashed preimage has unsorted keys and "
          "non-shortest arguments; the digest is over those bytes, so only the form is wrong.",
          sign1(header(), sha256(nc)),
          {"preimage.cbor": nc},
          ["--preimage", "preimage.cbor"])
    lf = cbor_det.encode(CAPSULE_3, key_order="length-first")
    write("Nd1-hash-over-length-first", "hash-mismatch",
          "(d) header says core-deterministic, digest computed over the RFC 8949 Section 4.2.3 "
          "length-first serialization; verifier holds the decoded value.",
          sign1(header(), sha256(lf)),
          {"stored-value.cbor": lf},
          ["--value-cbor", "stored-value.cbor"])
    js = json.dumps(CAPSULE_1, separators=(",", ":"), sort_keys=True).encode()
    write("Nd2-hash-over-json-text", "hash-mismatch",
          "(d') header says core-deterministic over application/cbor, digest computed over a "
          "JSON text serialization of the same capsule; verifier holds the JSON value.",
          sign1(header(), sha256(js)),
          {"capsule-1.json": jtext(CAPSULE_1), "hashed-bytes.json": js},
          ["--value-json", "capsule-1.json"])

    # ---------------- extra negatives (header rules, signature)
    write("Xa-header-absent-bytes", "cannot-recompute",
          "Header absent, verifier holds the preimage bytes: RFC 9995 Section 5.3 check "
          "succeeds (draft outcome verified) but this checker never passes without the header.",
          sign1(header(enc=None), sha256(c1)),
          {"capsule-1.cbor": c1}, ["--preimage", "capsule-1.cbor"])
    write("Xe-ct-json", "inconsistent-header",
          "core-deterministic paired with application/json (draft Section 4.2 example).",
          sign1(header(ct="application/json"), sha256(c1)),
          {"capsule-1.json": jtext(CAPSULE_1)}, ["--value-json", "capsule-1.json"])
    write("Xf-ct-absent", "inconsistent-header",
          "deterministic-encodings present, preimage-content-type (259) absent.",
          sign1(header(ct=None), sha256(c1)),
          {"capsule-1.json": jtext(CAPSULE_1)}, ["--value-json", "capsule-1.json"])
    write("Xg-unknown-enc-ct-absent", "inconsistent-header",
          "Unknown value 2 AND 259 absent: Section 4.2 precedence gives failed, not unverified.",
          sign1(header(ct=None, enc=2), sha256(c1)),
          {"capsule-1.json": jtext(CAPSULE_1)}, ["--value-json", "capsule-1.json"])
    write("Xh-label-unprotected", "inconsistent-header",
          "deterministic-encodings in the unprotected header (draft Section 3).",
          sign1(header(enc=None), sha256(c1), unprotected={ENC: 1}),
          {"capsule-1.json": jtext(CAPSULE_1)}, ["--value-json", "capsule-1.json"])
    write("Xi-label-in-crit", "inconsistent-header",
          "deterministic-encodings listed in crit (draft Section 3).",
          sign1(header(extra={2: [ENC]}), sha256(c1)),
          {"capsule-1.json": jtext(CAPSULE_1)}, ["--value-json", "capsule-1.json"])
    write("Xj-cf50-json", "inconsistent-header",
          "259 = CoAP Content-Format 50 (application/json) with core-deterministic.",
          sign1(header(ct=50), sha256(c1)),
          {"capsule-1.json": jtext(CAPSULE_1)}, ["--value-json", "capsule-1.json"])
    write("Xk-bad-signature", "bad-signature",
          "P1 content, signed with another Ed25519 key.",
          sign1(header(loc="capsule-1.cbor"), sha256(c1), seed=OTHER_SEED),
          {"capsule-1.cbor": c1}, ["--preimage", "capsule-1.cbor"])
    print(f"vectors written to {VEC}")


if __name__ == "__main__":
    main()
