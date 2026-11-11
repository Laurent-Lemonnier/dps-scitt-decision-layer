#!/usr/bin/env python3.12
"""Checker for draft-mih-sokolov-cose-deterministic-encodings-00, from its text.

Checks a COSE Hash Envelope (RFC 9995, a COSE_Sign1) that may carry the
deterministic-encodings protected-header parameter (label TBD_1, suggested
value 271) against the content a verifier holds: either the preimage bytes,
or a structured value (JSON or CBOR) that has to be re-encoded.

Verdicts (field "verdict"):
  pass                  content binding established, header consistent,
                        signature valid (or not checked: no key given)
  cannot-recompute      deterministic-encodings absent, or no content held:
                        the binding cannot be re-created. NEVER pass.
  unsupported-encoding  deterministic-encodings names a value this checker
                        does not implement (only 1, core-deterministic)
  not-canonical         preimage bytes are not in the declared encoding
  hash-mismatch         digest of the (re-created) preimage != payload
  inconsistent-header   draft Sections 3 / 4.2 placement or consistency rule
                        violated (draft outcome: failed, no recomputation)
  bad-signature         COSE_Sign1 signature does not verify with the key
  unsupported-hash-alg  payload-hash-alg (258) not implemented here
  cannot-encode-value   the structured value has no core-deterministic
                        encoding here (e.g. duplicate keys, huge integer)
  invalid-envelope      not a well-formed Hash Envelope per RFC 9995 Section 4
  malformed             not decodable as CBOR

"draft_outcome" gives the literal outcome of the draft (verified / failed /
unverified, Section 2) for the same inputs, so that strict choices of this
checker (see README, ambiguity log) stay visible.

Exit status: 0 for pass, 1 otherwise, 2 for usage errors.
"""
import argparse
import csv
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import cbor_det  # noqa: E402
import ed25519_pure  # noqa: E402

DEFAULT_LABEL = 271  # suggested value for TBD_1, draft Section 8.1
LBL_ALG, LBL_CRIT, LBL_CTY = 1, 2, 3
LBL_HASH_ALG, LBL_PREIMAGE_CT, LBL_LOCATION = 258, 259, 260
COSE_SIGN1_TAG = 18
EDDSA = -8

HASH_ALGS = {  # COSE Algorithms registry values implemented here
    -16: ("SHA-256", lambda b: hashlib.sha256(b).digest()),
    -43: ("SHA-384", lambda b: hashlib.sha384(b).digest()),
    -44: ("SHA-512", lambda b: hashlib.sha512(b).digest()),
}

# COSE Deterministic Encodings registry (draft Section 8.2), initial content.
CORE_DETERMINISTIC = 1
ENCODINGS = {
    CORE_DETERMINISTIC: {
        "name": "core-deterministic",
        "media_types": {
            "application/cbor", "application/cbor-seq", "application/cose",
            "application/cose-key", "application/cose-key-set",
            "application/cose-x509", "application/cwt",
            "application/multipart-core",
        },
        "suffixes": {"cbor", "cbor-seq", "cose", "cwt", "sd-cwt"},
    }
}
IMPLEMENTED = {CORE_DETERMINISTIC}


def _load_coap_formats():
    """CoAP Content-Formats snapshot (IANA CSV, fetched 2026-11-10, refs/)."""
    table = {}
    path = os.path.join(HERE, "refs", "coap-content-formats.csv")
    if not os.path.exists(path):
        return table
    with open(path, newline="") as fh:
        for row in csv.reader(fh):
            if len(row) < 4 or not row[3].strip().isdigit():
                continue
            media, coding = row[0].strip(), row[1].strip()
            if "TEMPORARY" in media:
                media = media.split("(")[0].strip()
            table[int(row[3])] = (media, coding)
    return table


COAP_FORMATS = _load_coap_formats()


def _bare_media_type(s):
    return s.split(";", 1)[0].strip().lower()


def content_type_matches(ct, enc_value):
    """Draft Section 4.2 matching of a 259 value against Applicable Content Types."""
    entry = ENCODINGS[enc_value]
    if isinstance(ct, int):
        if ct not in COAP_FORMATS:
            return False, f"Content-Format {ct} not in the CoAP Content-Formats snapshot"
        media, coding = COAP_FORMATS[ct]
        if coding:
            return False, f"Content-Format {ct} has content coding {coding!r}"
        ok, why = content_type_matches(media, enc_value)
        return ok, f"Content-Format {ct} = {media!r}: {why}"
    bare = _bare_media_type(ct)
    if "/" not in bare:
        return False, f"{ct!r} is not a media-type name"
    if bare in entry["media_types"]:
        return True, f"{bare} is listed"
    subtype = bare.split("/", 1)[1]
    if "+" in subtype:
        suffix = subtype.rsplit("+", 1)[1]
        if suffix in entry["suffixes"]:
            return True, f"structured syntax suffix +{suffix} is listed"
    return False, f"{bare} is not an Applicable Content Type of {entry['name']}"


def _is_seq(ct):
    if isinstance(ct, int):
        ct = COAP_FORMATS.get(ct, ("", ""))[0]
    bare = _bare_media_type(ct) if isinstance(ct, str) else ""
    return bare == "application/cbor-seq" or bare.endswith("+cbor-seq")


def sig_structure(protected_bstr, payload, external_aad=b""):
    """RFC 9052 Section 4.4, COSE_Sign1."""
    return cbor_det.encode(["Signature1", protected_bstr, external_aad, payload])


def load_json_value(path):
    def no_dups(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key in JSON object")
        return dict(pairs)

    with open(path, encoding="utf-8") as fh:
        return json.load(fh, object_pairs_hook=no_dups)


def load_pubkey(arg):
    if arg is None:
        return None
    if os.path.exists(arg):
        with open(arg) as fh:
            text = fh.read().strip()
        if text.startswith("{"):
            return bytes.fromhex(json.loads(text)["public_hex"])
        return bytes.fromhex(text)
    return bytes.fromhex(arg)


class Result:
    def __init__(self):
        self.checks = []
        self.signature = "not-checked"

    def log(self, msg):
        self.checks.append(msg)

    def done(self, verdict, reason, draft_outcome):
        return {
            "verdict": verdict,
            "reason": reason,
            "draft_outcome": draft_outcome,
            "signature": self.signature,
            "checks": self.checks,
        }


def verify(envelope_bytes, *, preimage=None, value=None, value_given=False,
           pubkey=None, label=DEFAULT_LABEL, strict_bytes=True):
    """Return a result dict. preimage: bytes or None. value: structured value
    (Python data model of cbor_det) when value_given is True."""
    r = Result()

    # 1. COSE_Sign1 structure (RFC 9052 Section 4.2, RFC 9995 Section 4).
    try:
        env = cbor_det.decode(envelope_bytes)
    except cbor_det.CborError as e:
        return r.done("malformed", f"envelope is not CBOR: {e}", "n/a")
    if isinstance(env, cbor_det.Tag):
        if env.tag != COSE_SIGN1_TAG:
            return r.done("invalid-envelope", f"tag {env.tag}, expected 18 (COSE_Sign1)", "n/a")
        env = env.value
        r.log("tag 18 (COSE_Sign1) present")
    else:
        r.log("untagged COSE_Sign1 accepted (RFC 9995 CDDL uses #6.18; see ambiguity log)")
    if not (isinstance(env, list) and len(env) == 4):
        return r.done("invalid-envelope", "COSE_Sign1 must be an array of 4 elements", "n/a")
    prot_b, unprot, payload, signature = env
    if not isinstance(prot_b, bytes) or not isinstance(signature, bytes):
        return r.done("invalid-envelope", "protected header and signature must be byte strings", "n/a")
    if not isinstance(unprot, (dict, cbor_det.CborMap)):
        return r.done("invalid-envelope", "unprotected header must be a map", "n/a")
    if payload is None:
        return r.done("invalid-envelope", "detached payload (nil): digest not available to this checker", "n/a")
    if not isinstance(payload, bytes):
        return r.done("invalid-envelope", "payload must be a byte string", "n/a")
    try:
        prot = cbor_det.decode(prot_b) if prot_b else {}
    except cbor_det.CborError as e:
        return r.done("malformed", f"protected header: {e}", "n/a")
    if not isinstance(prot, dict):
        return r.done("invalid-envelope", "protected header must be a map with int/tstr labels", "n/a")
    unprot_keys = [k for k, _ in unprot.pairs] if isinstance(unprot, cbor_det.CborMap) else list(unprot)

    # 2. Signature (RFC 9052 Section 4.4). Independent of the content binding
    #    (draft Section 4.3, last paragraph); reported separately.
    if pubkey is not None:
        alg = prot.get(LBL_ALG)
        if alg != EDDSA:
            r.signature = f"unsupported-alg ({alg!r}; this checker implements EdDSA -8 only)"
        else:
            ok = ed25519_pure.verify(pubkey, sig_structure(prot_b, payload), signature)
            r.signature = "valid" if ok else "invalid"
        r.log(f"signature: {r.signature}")
    # A key was given but the signature is invalid OR could not be checked
    # (alg absent / not implemented): never pass in that case.
    sig_bad = pubkey is not None and r.signature != "valid"

    def finish(verdict, reason, outcome):
        if sig_bad and verdict != "malformed":
            return r.done("bad-signature",
                          f"COSE_Sign1 signature {r.signature} (content binding alone: {verdict}: {reason})",
                          outcome)
        return r.done(verdict, reason, outcome)

    # 3. RFC 9995 Section 4 header rules.
    if LBL_HASH_ALG not in prot or type(prot[LBL_HASH_ALG]) is not int:
        return finish("invalid-envelope", "payload-hash-alg (258) missing from protected header or not an int", "n/a")
    for lbl in (LBL_HASH_ALG, LBL_PREIMAGE_CT, LBL_LOCATION):
        if lbl in unprot_keys:
            return finish("invalid-envelope", f"label {lbl} in the unprotected header (RFC 9995 Section 4)", "n/a")
    if LBL_CTY in prot or LBL_CTY in unprot_keys:
        return finish("invalid-envelope", "content_type (3) present (RFC 9995 Section 4)", "n/a")
    ct = prot.get(LBL_PREIMAGE_CT)
    if ct is not None and not ((type(ct) is int and ct >= 0) or isinstance(ct, str)):
        return finish("invalid-envelope", "preimage-content-type (259) must be uint / tstr", "n/a")
    if LBL_LOCATION in prot and not isinstance(prot[LBL_LOCATION], str):
        return finish("invalid-envelope", "payload-location (260) must be tstr", "n/a")
    r.log(f"RFC 9995 header rules hold; 258={prot[LBL_HASH_ALG]}, 259={ct!r}")

    # 4. Draft Section 3 placement rules, then Section 4.2 consistency
    #    (checked first, takes precedence over Section 4.3).
    if label in unprot_keys:
        return finish("inconsistent-header",
                      f"deterministic-encodings (label {label}) in the unprotected header (draft Section 3)", "failed")
    crit = prot.get(LBL_CRIT)
    if isinstance(crit, list) and label in crit:
        return finish("inconsistent-header",
                      f"deterministic-encodings (label {label}) listed in crit (draft Section 3)", "failed")
    has_enc = label in prot
    enc = prot.get(label)
    if has_enc:
        if type(enc) is not int:
            return finish("inconsistent-header", f"deterministic-encodings value {enc!r} is not an int (draft Section 3 CDDL)", "failed")
        if ct is None:
            return finish("inconsistent-header",
                          "deterministic-encodings present but preimage-content-type (259) absent (draft Section 4.2)",
                          "failed")
        if enc in ENCODINGS:
            ok, why = content_type_matches(ct, enc)
            r.log(f"Section 4.2 match of 259 against {ENCODINGS[enc]['name']}: {ok} ({why})")
            if not ok:
                return finish("inconsistent-header", f"259 does not match encoding {enc}: {why} (draft Section 4.2)", "failed")
        else:
            r.log(f"deterministic-encodings={enc} not recognized: Section 4.2 match not applicable")
    else:
        r.log(f"deterministic-encodings (label {label}) absent")

    # 5. Hash algorithm.
    halg = prot[LBL_HASH_ALG]
    if halg not in HASH_ALGS:
        return finish("unsupported-hash-alg", f"payload-hash-alg {halg} not implemented", "unverified")
    hname, hfun = HASH_ALGS[halg]

    # 6. Content binding (draft Section 4.3).
    if preimage is not None:
        digest = hfun(preimage)
        r.log(f"{hname}(preimage bytes) = {digest.hex()}")
        if digest != payload:
            return finish("hash-mismatch", f"{hname} of the preimage bytes does not match the payload", "failed")
        # Draft-literal outcome: verified (RFC 9995 Section 5.3 check).
        if not has_enc:
            return finish("cannot-recompute",
                          "deterministic-encodings absent: the preimage bytes match the payload (RFC 9995 Section 5.3), "
                          "but no declared encoding to check; this checker never passes without the header", "verified")
        if enc not in IMPLEMENTED:
            return finish("unsupported-encoding",
                          f"deterministic-encodings={enc} not implemented; bytes match the payload but the declared "
                          "encoding cannot be checked", "verified")
        if strict_bytes:
            err = cbor_det.check_core_deterministic(preimage, sequence=_is_seq(ct))
            if err is not None:
                return finish("not-canonical" if err.kind == "not-canonical" else "malformed",
                              f"preimage bytes are not core-deterministic: {err}", "verified")
            r.log("preimage bytes satisfy RFC 8949 Section 4.2.1")
        return finish("pass", "preimage bytes match the payload and are in the declared encoding", "verified")

    if value_given:
        if not has_enc:
            return finish("cannot-recompute",
                          "structured value held but deterministic-encodings absent (draft Section 4.3)", "unverified")
        if enc not in IMPLEMENTED:
            return finish("unsupported-encoding",
                          f"deterministic-encodings={enc} not recognized/implemented (draft Section 4.3)", "unverified")
        try:
            if _is_seq(ct):
                if not isinstance(value, list):
                    raise cbor_det.Unencodable("CBOR sequence content needs a list of items")
                recreated = b"".join(cbor_det.encode(v) for v in value)
            else:
                recreated = cbor_det.encode(value)
        except cbor_det.CborError as e:
            return finish("cannot-encode-value", f"value cannot be core-deterministically encoded: {e}", "unverified")
        digest = hfun(recreated)
        r.log(f"re-created preimage ({len(recreated)} bytes) = {recreated.hex()[:80]}{'...' if len(recreated) > 40 else ''}")
        r.log(f"{hname}(re-created preimage) = {digest.hex()}")
        if digest != payload:
            return finish("hash-mismatch", f"{hname} of the re-created preimage does not match the payload", "failed")
        return finish("pass", "re-created preimage matches the payload", "verified")

    return finish("cannot-recompute", "no preimage and no structured value held", "unverified")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("envelope", help="COSE_Sign1 Hash Envelope, binary CBOR file")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--preimage", help="preimage bytes file")
    g.add_argument("--value-json", help="structured value as JSON (objects -> maps, ints -> ints, "
                                        "non-integers -> floats)")
    g.add_argument("--value-cbor", help="structured value as any CBOR file (decoded, then re-encoded)")
    ap.add_argument("--pubkey", help="Ed25519 public key: hex, or file with hex or demo-key JSON")
    ap.add_argument("--label", type=int, default=DEFAULT_LABEL, help="label used for TBD_1 (default 271)")
    ap.add_argument("--rfc9995-bytes-only", action="store_true",
                    help="do not check that held preimage bytes are in the declared encoding")
    a = ap.parse_args(argv)

    with open(a.envelope, "rb") as fh:
        env = fh.read()
    pre, val, given = None, None, False
    try:
        if a.preimage:
            with open(a.preimage, "rb") as fh:
                pre = fh.read()
        elif a.value_json:
            val, given = load_json_value(a.value_json), True
        elif a.value_cbor:
            with open(a.value_cbor, "rb") as fh:
                raw = fh.read()
            val, given = cbor_det.decode(raw), True
    except (ValueError, cbor_det.CborError) as e:
        print(json.dumps({"verdict": "cannot-encode-value", "reason": f"structured value unreadable: {e}",
                          "draft_outcome": "unverified"}, indent=2))
        return 1
    res = verify(env, preimage=pre, value=val, value_given=given, pubkey=load_pubkey(a.pubkey),
                 label=a.label, strict_bytes=not a.rfc9995_bytes_only)
    print(json.dumps(res, indent=2))
    return 0 if res["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
