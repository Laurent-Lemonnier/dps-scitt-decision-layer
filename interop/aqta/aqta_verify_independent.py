#!/usr/bin/env python3
"""Independent verifier for the Seal record formats ATTESTATION-v1 and ACTION-v1
(Aqta-ai/attestation-spec, draft-chueayen-attestation-receipts-05), written from
the specification text only (spec/ATTESTATION-v1.md §4-§7, spec/ACTION-v1.md
§4-§7). It shares no code with the reference verifiers. Used to replay the
published test vectors as a third party, per CONFORMANCE.md "Verifier
conformance".

Usage: aqta_verify_independent.py --profile attestation|action --key <pinned> FILE...
Prints one line per file: valid|invalid, reason, file. Exit 0 if every file's
verdict matches its directory (valid/ -> valid, invalid/ -> invalid), else 1.
"""
import argparse
import base64
import json
import math
import os
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ATTESTATION_FIELDS = {
    "v": int, "attestation_id": str, "trace_id": str, "org_id": str,
    "request_hash": str, "model": str, "outcome": str, "policy_applied": list,
    "cost_prevented_eur": (int, float), "timestamp": str, "public_key": str,
    "signature": str,
}
ACTION_FIELDS = {
    "v": str, "action_id": str, "org_id": str, "session_id": str,
    "intent_hash": str, "agent": str, "tool": str, "args_hash": str,
    "outcome": str, "policy_applied": list, "timestamp": str,
    "public_key": str, "signature": str,
}
ATTESTATION_OUTCOMES = {"ALLOWED", "BLOCKED", "SUPPRESSED", "PASSED"}
ACTION_OUTCOMES = {"ALLOWED", "BLOCKED"}

# Whole-value patterns, ASCII digits only (§7 of both specs). re.fullmatch does
# not match before a trailing line feed; [0-9] excludes other scripts' digits.
HEX64 = re.compile(r"[0-9a-f]{64}")
RFC3339 = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})"
)


class Invalid(Exception):
    pass


def b64url_decode(s, n, what):
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", s):
        raise Invalid(f"{what} decode error: not base64url")
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        raise Invalid(f"{what} decode error: not base64url")
    if len(raw) != n:
        raise Invalid(f"{what} must decode to {n} bytes")
    return raw


def utf16_key(s):
    # RFC 8785 §3.2.3: sort by UTF-16 code units, the order JavaScript's
    # default string sort produces.
    return s.encode("utf-16-be")


def ecma_number_to_string(x):
    # ECMA-262 Number::toString for finite doubles (RFC 8785 §3.2.2.3).
    if x == 0:
        return "0"
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)  # shortest round-trip digits, Python >= 3.1
    sign = "-" if r.startswith("-") else ""
    r = r.lstrip("-")
    if "e" in r or "E" in r:
        mant, exp = r.lower().split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    # decimal exponent n such that value = 0.digits * 10^n
    n = len(ip.lstrip("0")) + exp if ip.strip("0") else exp - (len(fp) - len(fp.lstrip("0")))
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + es
    return sign + s


def canonical(value):
    # §6: keys sorted by UTF-16 code unit, compact separators, literal UTF-8,
    # only RFC 8259 escapes; integers without decimal point; non-integers per
    # ECMA-262 Number::toString.
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: utf16_key(kv[0]))
        return "{" + ",".join(canonical(k) + ":" + canonical(v) for k, v in items) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise Invalid("non-finite number")
        if value == int(value):
            return str(int(value))
        return ecma_number_to_string(value)
    raise Invalid(f"unsupported JSON type {type(value).__name__}")


def load_record(path):
    with open(path, "rb") as f:
        raw = f.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Invalid("not UTF-8")
    try:
        # Reject lone surrogates and duplicate members (the spec sets exact fields).
        def no_dupes(pairs):
            d = {}
            for k, v in pairs:
                if k in d:
                    raise Invalid(f"duplicate member {k!r}")
                d[k] = v
            return d
        rec = json.loads(text, object_pairs_hook=no_dupes)
    except Invalid:
        raise
    except Exception as e:
        raise Invalid(f"not JSON: {e.__class__.__name__}")
    if not isinstance(rec, dict):
        raise Invalid("record must be a JSON object")
    return rec


def check_common(rec, fields):
    unknown = set(rec) - set(fields)
    if unknown:
        raise Invalid(f"unknown field {sorted(unknown)[0]!r}")
    missing = set(fields) - set(rec)
    if missing:
        raise Invalid(f"missing field {sorted(missing)[0]!r}")
    for k, t in fields.items():
        v = rec[k]
        if isinstance(v, bool) or not isinstance(v, t):
            raise Invalid(f"{k} must be {'a string' if t is str else 'an array' if t is list else 'a number' if t is not int else 'an integer'}")
    pol = rec["policy_applied"]
    if not all(isinstance(p, str) for p in pol):
        raise Invalid("policy_applied must contain only strings")
    for p in pol:
        try:
            p.encode("utf-8")
        except UnicodeEncodeError:
            raise Invalid("policy_applied member is not valid Unicode")
    if pol != sorted(pol, key=utf16_key):
        raise Invalid("policy_applied must be sorted by UTF-16 code unit")
    if not RFC3339.fullmatch(rec["timestamp"]):
        raise Invalid("timestamp must be an RFC 3339 datetime with an explicit offset")


def verify_signature(rec, pinned):
    pk = rec["public_key"]
    if pk != pinned:
        raise Invalid("public_key does not match the pinned key")
    pk_raw = b64url_decode(pk, 32, "public_key")
    sig = b64url_decode(rec["signature"], 64, "signature")
    payload = {k: v for k, v in rec.items() if k != "signature"}
    try:
        msg = canonical(payload).encode("utf-8")
    except UnicodeEncodeError:
        raise Invalid("payload contains a lone surrogate")
    try:
        Ed25519PublicKey.from_public_bytes(pk_raw).verify(sig, msg)
    except InvalidSignature:
        raise Invalid("signature check failed")


def verify_attestation(rec, pinned):
    check_common(rec, ATTESTATION_FIELDS)
    if rec["v"] != 1:
        raise Invalid("v must be 1")
    if rec["outcome"] not in ATTESTATION_OUTCOMES:
        raise Invalid("outcome not an ATTESTATION-v1 value")
    if not HEX64.fullmatch(rec["request_hash"]):
        raise Invalid("request_hash must be 64 lowercase hex characters")
    # ATTESTATION-v1 §4 describes policy_applied as "ASCII policy identifiers"
    # but states no MUST on ASCII, and valid/007-non-ascii-policy carries
    # non-ASCII names. Read as descriptive: the UTF-16 sort check above is what
    # the text requires. Reported to the author as an ambiguity (29/10/2026).
    c = rec["cost_prevented_eur"]
    if c < 0 or math.isnan(c) or math.isinf(c):
        raise Invalid("cost_prevented_eur must be a non-negative finite number")
    if round(c, 6) != c:
        raise Invalid("cost_prevented_eur has more than 6 digits of precision")
    verify_signature(rec, pinned)


def verify_action(rec, pinned):
    check_common(rec, ACTION_FIELDS)
    if rec["v"] != "action-1":
        raise Invalid('v must be the string "action-1"')
    if rec["outcome"] not in ACTION_OUTCOMES:
        raise Invalid("outcome not an ACTION-v1 value")
    if not HEX64.fullmatch(rec["args_hash"]):
        raise Invalid("args_hash must be 64 lowercase hex characters")
    if rec["intent_hash"] != "" and not HEX64.fullmatch(rec["intent_hash"]):
        raise Invalid("intent_hash must be '' or 64 lowercase hex characters")
    if rec["tool"] == "":
        raise Invalid("tool must be non-empty")
    if rec["session_id"] == "" and rec["intent_hash"] != "":
        raise Invalid("intent_hash must be '' when session_id is ''")
    verify_signature(rec, pinned)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True, choices=["attestation", "action"])
    ap.add_argument("--key", required=True, help="pinned issuer public key (base64url)")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    verify = verify_attestation if a.profile == "attestation" else verify_action
    mismatches = 0
    for path in a.files:
        try:
            rec = load_record(path)
            verify(rec, a.key)
            verdict, reason = "valid", rec["outcome"]
        except Invalid as e:
            verdict, reason = "invalid", str(e)
        except Exception as e:  # never crash on a malformed record (CONFORMANCE.md)
            verdict, reason = "invalid", f"malformed: {e.__class__.__name__}"
        expected = "valid" if os.path.basename(os.path.dirname(path)) == "valid" else "invalid"
        mark = "ok " if verdict == expected else "MISMATCH"
        if verdict != expected:
            mismatches += 1
        print(f"{mark} {verdict:7} {os.path.basename(path):40} {reason}")
    print(f"# {len(a.files)} vectors, {mismatches} mismatch(es)")
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main()
