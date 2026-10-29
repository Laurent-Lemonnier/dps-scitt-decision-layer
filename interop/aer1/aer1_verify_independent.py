#!/usr/bin/env python3
"""Independent verifier for AER-1 receipts (draft-zambo-aer1-26, Sections 3 to 6
and 10), written from the draft text. Two rules come from the conformance kit's
own documents rather than the draft and are marked KIT below: the binding of the
outer receipt_schema_version and provenance_class to the values the canonical
payload carries (kit verifier README, rule 11; the draft's Implementation Status
names the vectors), and the "disinterested tier" anchor shape (aer-1/profiles/
disinterested-tier.md). The id_verdict and anchor-outcome vocabularies are the
draft's (Section 6).

Scope: the receipt-level fixtures (test-vectors/valid, invalid, invalid-profile,
anchored), unicode-vectors.json, id-binding-vectors.json and anchor-vectors.json.
The chain, commitment and Merkle suites are not covered by this file.

Usage: aer1_verify_independent.py --kit <path to aer-1/> [--report out.json]
"""
import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.parse

PROVENANCE = {"EXECUTED BY ZAMBO", "OBSERVED VIA GATEWAY", "LOGGED BY AGENT"}
UUID_CORE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
UUID_V4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
NIL_UUID = "00000000-0000-0000-0000-000000000000"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
RFC3339 = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(Z|([+-])([0-9]{2}):([0-9]{2}))")
B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")


class Reject(Exception):      # "rejected: <reason>" — the record cannot be fully evaluated
    pass


class Failed(Exception):      # "verification failed" — a recomputed value differs from the committed one
    pass


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def version_tuple(s):
    if not isinstance(s, str) or not re.fullmatch(r"[0-9]+(\.[0-9]+)*", s):
        raise Reject("receipt_schema_version is not a dotted numeric version")
    return tuple(int(x) for x in s.split("."))


def parse_strict(raw):
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise Reject(f"duplicate member name: {k}")
            d[k] = v
        return d
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except Reject:
        raise
    except Exception as e:
        raise Reject(f"not a JSON document ({e.__class__.__name__})")


def check_timestamp(s, what):
    """RFC 3339 syntax, a real calendar date, no leap second (Section 3, Section 6)."""
    if not isinstance(s, str):
        raise Reject(f"{what} is not a string")
    m = RFC3339.fullmatch(s)
    if not m:
        raise Reject(f"{what} is not RFC 3339")
    y, mo, d, h, mi, sec = (int(m.group(i)) for i in range(1, 7))
    if sec == 60:
        raise Reject("leap-second timestamp")
    try:
        datetime.datetime(y, mo, d, h, mi, sec)
    except ValueError:
        raise Reject(f"{what} is not a valid calendar date/time")
    if m.group(8) != "Z" and (int(m.group(10)) > 23 or int(m.group(11)) > 59):
        raise Reject(f"{what} is not a valid calendar date/time (offset out of range)")


def decode_canonical_bytes(s):
    """Strict RFC 4648 base64 with standard padding and zero pad bits (Section 4)."""
    if not isinstance(s, str) or not B64.fullmatch(s) or len(s) % 4:
        raise Reject("canonical_bytes is not valid base64")
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise Reject("canonical_bytes is not valid base64")
    if base64.b64encode(raw).decode() != s:
        raise Reject("canonical_bytes is not the canonical base64 spelling (non-zero pad bits)")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Reject("canonical_bytes is not valid UTF-8")
    return raw


def canonical_json(obj):
    """Section 7.1 serialization: code-point-sorted members, no whitespace, escapes as
    Python's json.dumps(ensure_ascii=True) with lowercase \\u hex digits."""
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return re.sub(r"\\u([0-9A-F]{4})", lambda m: "\\u" + m.group(1).lower(), s)


def verify_receipt(rec, strict_id=False):
    """Core check of Sections 3 to 6. Returns a dict of findings; raises Reject/Failed."""
    out = {"legacy": [], "unbound": False}
    if not isinstance(rec, dict):
        raise Reject("receipt is not a JSON object")
    ver = version_tuple(rec.get("receipt_schema_version"))
    for m in ("id", "receipt_schema_version", "provenance_class", "canonical_bytes", "output_hash", "verification_status"):
        if m not in rec:
            raise Reject(f"missing required member: {m}")
    # id (Section 3): lowercase UUID shape, never the nil UUID; strict tier = v4
    rid = rec["id"]
    if not isinstance(rid, str) or not UUID_CORE.fullmatch(rid):
        raise Reject("id is not a lowercase UUID")
    if rid == NIL_UUID:
        raise Reject("id is the nil UUID")
    if strict_id and not UUID_V4.fullmatch(rid):
        raise Reject("id is not a version 4 UUID with RFC 4122 variant bits (strict tier)")
    # created_at, with the legacy "timestamp" form below 0.4. KIT reading of "legacy": a
    # pre-0.4 receipt carrying "timestamp" instead of created_at; only such a receipt may
    # carry the bare-string tool form and a verification_status other than "verified"
    # (fixture legacy-real-2 accepted, tool-not-object rejected). The draft's Section 6
    # text would also admit a bare-string tool beside created_at; reported to the author.
    legacy = "created_at" not in rec and "timestamp" in rec and ver < (0, 4)
    if "created_at" in rec:
        check_timestamp(rec["created_at"], "created_at")
        created = rec["created_at"]
    elif legacy:
        check_timestamp(rec["timestamp"], "timestamp")
        created = rec["timestamp"]
        out["legacy"].append("timestamp")
    else:
        raise Reject("missing required member: created_at")
    tool = rec.get("tool")
    if isinstance(tool, dict):
        if set(tool) < {"name", "version", "scope"} or not all(isinstance(tool.get(k), str) and tool.get(k) for k in ("name", "version", "scope")):
            raise Reject("tool is not an object with name/version/scope strings")
    elif isinstance(tool, str) and tool and legacy:
        out["legacy"].append("tool")
    else:
        raise Reject("tool is not an object with name/version/scope strings")
    # provenance class (Section 5): exact label, no control characters
    pc = rec["provenance_class"]
    if not isinstance(pc, str) or any(ord(c) < 0x20 or ord(c) == 0x7F for c in pc):
        raise Reject("provenance_class contains a control character")
    if pc not in PROVENANCE:
        raise Reject("provenance_class is not a known class")
    if rec["verification_status"] != "verified":
        if legacy and isinstance(rec["verification_status"], str):
            out["legacy"].append("verification_status")
        else:
            raise Reject("verification_status is not verified")
    # output commitment (Section 4)
    raw = decode_canonical_bytes(rec["canonical_bytes"])
    oh = rec["output_hash"]
    if not isinstance(oh, str) or not DIGEST.fullmatch(oh):
        raise Reject("output_hash is not sha256: + lowercase hex digest")
    if oh[7:] != sha256_hex(raw):
        raise Failed("output_hash does not match sha256(canonical_bytes)")
    # metadata binding (Section 3.1, Section 6 step 4)
    # DISCREPANCY (reported to the author): draft -26 Section 6 step 4 says a "0.4" receipt
    # without metadata_hash MUST fail, but kit v1.5.7 lists 0.4 fixtures without
    # metadata_hash (bound-04, optional-members-18, input-hash-multikey-20) as valid. The
    # kit reading is applied here, and the absence is reported in the findings.
    if "metadata_hash" not in rec and ver >= (0, 4):
        out["metadata_hash_absent_on_04"] = True
    if "metadata_hash" in rec:
        if not isinstance(tool, dict):
            raise Reject("metadata block needs the tool object form")
        block = {"created_at": created, "id": rid, "output_hash": oh, "provenance_class": pc,
                 "receipt_schema_version": rec["receipt_schema_version"],
                 "tool": {"name": tool["name"], "scope": tool["scope"], "version": tool["version"]}}
        mh = rec["metadata_hash"]
        if not isinstance(mh, str) or not DIGEST.fullmatch(mh):
            raise Reject("metadata_hash is not sha256: + lowercase hex digest")
        if mh[7:] != sha256_hex(canonical_json(block).encode("utf-8")):
            raise Failed("metadata_hash does not match the recomputed metadata block")
    else:
        out["unbound"] = True   # 0.3 without metadata_hash: core members not bound to the commitment
    # KIT rule: the payload's own schema version and issuer_claims.provenance_class, when it
    # carries them, must equal the outer members (vectors version-downgrade, tampered-provenance)
    payload = None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        payload = None
    if isinstance(payload, dict):
        if "receipt_schema_version" in payload and payload["receipt_schema_version"] != rec["receipt_schema_version"]:
            raise Failed("receipt_schema_version differs from the version committed in the canonical bytes")
        ic = payload.get("issuer_claims")
        if isinstance(ic, dict) and "provenance_class" in ic and ic["provenance_class"] != pc:
            raise Failed("provenance_class differs from issuer_claims.provenance_class committed in the canonical bytes")
    # optional input commitment (Section 3.3); layout published by the producer: the canonical
    # JSON (code-point-sorted members, compact) of the payload's recorded "inputs" member
    if "input_hash" in rec:
        ih = rec["input_hash"]
        if not isinstance(ih, str) or not DIGEST.fullmatch(ih):
            raise Reject("input_hash is not sha256: + lowercase hex digest")
        if not isinstance(payload, dict) or "inputs" not in payload:
            raise Reject("input_hash present but the recorded inputs cannot be reproduced")
        if ih[7:] != sha256_hex(canonical_json(payload["inputs"]).encode("utf-8")):
            raise Failed("input_hash does not match sha256(canonical JSON of the recorded inputs)")
    out["payload"] = payload
    out["raw"] = raw
    return out


def reference_profile(payload):
    """KIT reference-producer profile: the payload is a JSON object carrying inputs, tool, outputs."""
    return isinstance(payload, dict) and all(k in payload for k in ("inputs", "tool", "outputs"))


def anchor_report(rec, raw, evaluate=True):
    """Section 6 per-anchor report (present / evaluated / outcome) for the KIT disinterested-tier
    anchor shape {log, leaf_hash, anchored_at, proof}."""
    a = rec.get("anchor")
    shape = {"log", "leaf_hash", "anchored_at", "proof"}
    if not isinstance(a, dict) or not (set(a) & shape) or not {"log", "leaf_hash", "anchored_at"} <= set(a):
        return {"present": False, "evaluated": False, "outcome": "absent"}
    if not evaluate:
        return {"present": True, "evaluated": False, "outcome": "not checked"}
    host = urllib.parse.urlparse(str(a.get("log", ""))).hostname or ""
    if host.endswith(".invalid"):
        return {"present": True, "evaluated": True, "outcome": "rejected: unresolvable record"}
    try:
        if "proof" not in a or not isinstance(a["proof"], dict):
            raise Failed("proof is required")
        check_timestamp(a["anchored_at"], "anchored_at")
        if not isinstance(a["leaf_hash"], str) or not DIGEST.fullmatch(a["leaf_hash"]) or a["leaf_hash"][7:] != sha256_hex(raw):
            raise Failed("leaf_hash does not match sha256(canonical_bytes)")
        if not UUID_V4.fullmatch(rec.get("id", "")):
            raise Failed("tier requires a version 4 UUID id")
        return {"present": True, "evaluated": True, "outcome": "verified"}
    except (Failed, Reject) as e:
        return {"present": True, "evaluated": True, "outcome": "verification failed", "reason": str(e)}


def structural(rec, strict_id=False):
    try:
        f = verify_receipt(rec, strict_id)
        return "pass", None, f
    except Failed as e:
        return "verification failed", str(e), None
    except Reject as e:
        return f"rejected: {e}", str(e), None


# ---------------------------------------------------------------- judge

def judge(kit, report_path=None):
    rows = []
    tv = os.path.join(kit, "test-vectors")
    for d, expect in (("valid", "pass"), ("invalid", "fail"), ("invalid-profile", "profile-fail"), ("anchored", "anchored")):
        for fn in sorted(os.listdir(os.path.join(tv, d))):
            if not fn.endswith(".json"):
                continue
            raw = open(os.path.join(tv, d, fn), "rb").read()
            try:
                rec = parse_strict(raw)
                verdict, reason, f = structural(rec)
            except Reject as e:
                rec, verdict, reason, f = None, f"rejected: {e}", str(e), None
            declared = rec.get("rejected_by") if isinstance(rec, dict) else None
            prof = reference_profile(f["payload"]) if f else None
            if expect == "pass":
                ok = verdict == "pass"
            elif expect == "fail":
                ok = verdict != "pass"
            elif expect == "profile-fail":
                ok = verdict == "pass" and prof is False
            else:
                anc = anchor_report(rec, f["raw"], True) if f else None
                ok = verdict == "pass" and anc is not None and (anc["outcome"] == "verified") == (fn == "anchored-valid.json")
                reason = (anc or {}).get("outcome")
            rows.append({"suite": d, "name": fn, "expected": expect, "verdict": verdict, "reason": reason,
                         "declared": declared, "profile": prof, "legacy": f["legacy"] if f else None, "agree": ok})
    # unicode-vectors.json (Section 4)
    for v in json.load(open(os.path.join(kit, "unicode-vectors.json")))["vectors"]:
        got = "match" if sha256_hex(base64.b64decode(v["payload_base64"])) == v["sha256"] else "mismatch"
        rows.append({"suite": "unicode", "name": v["name"], "expected": v["expected"], "verdict": got, "agree": got == v["expected"]})
    # id-binding-vectors.json (Section 6, id_verdict)
    for v in json.load(open(os.path.join(kit, "id-binding-vectors.json")))["vectors"]:
        rec = v["receipt"]
        verdict, reason, f = structural(rec)
        digest = "pass" if verdict == "pass" else "fail"
        resolved = v.get("resolved_record") or v.get("resolved") or v.get("resolution")
        if "id" not in rec:
            idv = "absent"
        elif "expected_id" in v:
            idv = "matched" if v["expected_id"] == rec["id"] else "mismatched"
        elif isinstance(resolved, dict):
            idv = "resolved" if resolved.get("output_hash") == rec.get("output_hash") else "mismatched"
        else:
            idv = "unverified"
        overall = "pass" if verdict == "pass" and idv in ("matched", "resolved", "unverified") else "fail"
        ok = overall == v["expected_verdict"] and idv == v["expected_id_verdict"] and digest == v["expected_digest"]
        rows.append({"suite": "id-binding", "name": v["name"], "expected": f"{v['expected_verdict']}/{v['expected_id_verdict']}", "verdict": f"{overall}/{idv}", "agree": ok})
    # anchor-vectors.json (Section 6, per-anchor report)
    for v in json.load(open(os.path.join(kit, "anchor-vectors.json")))["vectors"]:
        rec = v["receipt"] if "receipt" in v else json.load(open(os.path.join(kit, v["file"])))
        verdict, reason, f = structural(rec)
        raw = f["raw"] if f else base64.b64decode(rec["canonical_bytes"])
        rep = anchor_report(rec, raw, v.get("evaluate", True))
        ok = rep["present"] == v["expected_present"] and rep["evaluated"] == v["expected_evaluated"] and rep["outcome"] == v["expected_anchor_outcome"]
        rows.append({"suite": "anchor", "name": v["name"], "expected": v["expected_anchor_outcome"], "verdict": rep["outcome"], "agree": ok})
    n = len(rows)
    agree = sum(1 for r in rows if r["agree"])
    for r in rows:
        if not r["agree"]:
            print(f"DISAGREE {r['suite']}/{r['name']}: expected {r['expected']} got {r['verdict']} ({r.get('reason')})")
    by = {}
    for r in rows:
        by.setdefault(r["suite"], [0, 0]); by[r["suite"]][1] += 1; by[r["suite"]][0] += r["agree"]
    print("# AER-1 receipt-level, unicode, id-binding and anchor suites: " + ", ".join(f"{k} {a}/{b}" for k, (a, b) in by.items()) + f"; total {agree}/{n}")
    if report_path:
        json.dump({"agree": agree, "total": n, "rows": rows}, open(report_path, "w"), indent=1)
    return 0 if agree == n else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True, help="path to the aer-1/ directory of the conformance kit")
    ap.add_argument("--report")
    a = ap.parse_args()
    sys.exit(judge(a.kit, a.report))
