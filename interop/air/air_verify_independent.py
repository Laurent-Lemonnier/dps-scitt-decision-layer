#!/usr/bin/env python3
"""A verifier of AgentInteractionRecords written from the text of draft-emirdag-scitt-ai-agent-execution-01 (Emirdag,
Feichtinger; 12 October 2026): the CDDL of Section 5.2, the field definitions of 5.3, the COSE encoding of 5.6, the chain
construction of 5.7, the four steps of 5.8, and the registration policy of 6.1, 6.3 and 6.4. It imports nothing from
the authors' code: the draft publishes no vectors or examples, and the EES reference implementation signs a different
structure (the README's ambiguity (b)). Each check carries the section it is read from. The verdict words are the
draft's own: VERIFIED when all steps pass (5.8), FAIL otherwise.

Readings taken where the text leaves a choice (the README's ambiguity log):
  (a) content_hash is the SHA-256 of the bytes inside the payload byte string, not of the CBOR-encoded byte string
      (5.7: "the raw byte string from the COSE structure's payload field");
  (b) the signature is the COSE_Sign1 signature over the RFC 9052 Sig_structure with an empty external_aad, as 5.5 and
      5.8 step 3 say, not the EES envelope's signature over chain_hash alone;
  (c) key_rotation (5.9) is not in Table 2: an action_type without a namespace that Table 2 does not list is refused,
      key_rotation included, and the refusal names the section.
Byte strings in the JSON payload (input_hash, outcome_hash, the hashes of tool calls and redaction receipts,
reasoning_hash) are read as base64url without padding, the provisional encoding of the EES v0.2 schema; the CDDL's
bstr is native and says nothing about JSON.

Not checked, and said: "captured within 300s of submission" (6.3) needs the submission time, which no record carries;
the pre-registration of the signing key (5.4, Level 1) is the verifier's own trust input, the public key given to it;
Levels 2 and 3 (6.2) are not required here. The resolution of external_refs is outside 5.8 (10.1 defines no resolution
rule); the case's build.py does it as an additional step and says so.
"""
import base64
import hashlib
import json
import re
import struct
import uuid
from collections.abc import Mapping

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ZERO32 = b"\x00" * 32
ES256 = -7
TABLE_2 = ("payment_initiation", "payment_execution", "trade_execution", "contract_execution", "regulated_data_access",
           "regulated_data_export", "credit_decision", "configuration_change")           # Section 4.2, Table 2
OUTCOME_STATES = ("completed", "failed", "partially_completed", "reversed", "pending_confirmation")    # 5.3
RETENTION_CLASSES = ("regulatory_7yr", "regulatory_5yr", "regulatory_3yr", "operational_1yr", "custom")  # 5.3
REDACTION_REQUIRED_FOR = ("regulated_data_access", "regulated_data_export", "payment_initiation", "payment_execution",
                          "credit_decision")                                                 # 6.4
BSTR = "bstr"
# Section 5.2: every key of the map is present; REQUIRED members are those the CDDL types without "/ null" (5.3 names
# them REQUIRED), OPTIONAL members are those typed "/ null".
REQUIRED = {"schema_version": str, "record_id": str, "session_id": str, "action_type": str, "action_timestamp_ms": int,
            "captured_timestamp_ms": int, "agent_id": str, "agent_version": str, "operator_id": str,
            "operator_pubkey_id": str, "input_hash": BSTR, "outcome_state": str, "outcome_hash": BSTR, "tool_calls": list,
            "jurisdiction": str, "retention_class": str, "policy_refs": list, "external_refs": list,
            "redaction_receipts": list}
OPTIONAL = {"action_subtype": str, "written_timestamp_ms": int, "agent_did": str, "agent_workload_id": str,
            "principal_id": str, "delegation_chain": list, "intent_attestation": str, "auth_context": dict,
            "input_summary": str, "outcome_summary": str, "parent_record_id": str, "workflow_id": str, "trace_id": str,
            "consumer_instructions": str, "reasoning_hash": BSTR}
TOOL_CALL = {"tool_id": str, "tool_type": str, "input_hash": BSTR, "output_hash": BSTR, "is_write": bool, "timestamp_ms": int}
EXTERNAL_REF = {"ref_type": str, "ref_value": str, "ref_system": (str, type(None))}
REDACTION_RECEIPT = {"field_path": str, "original_hash": BSTR, "policy_id": str, "timestamp_ms": int}
AUTH_CONTEXT = {"token_type": str, "scopes": list, "audience": (str, type(None)), "expires_at_ms": (int, type(None))}
HEADER_LABELS = {1: "alg", 4: "kid", 15: "CWT Claims"}
CWT_LABELS = {1: "iss", 2: "sub"}


class Malformed(Exception):
    """The bytes are not a COSE_Sign1 of the shape Section 5.6 describes; nothing after that can be checked."""


# ---- RFC 8785 for the values this profile carries (no floats: every number here is a uint or an int)
def canonical_json(obj):
    """RFC 8785: members sorted by the UTF-16 code units of their names, no whitespace, strings escaped as Section
    3.2.2.2 asks (which is what json.dumps(ensure_ascii=False) emits, lowercase \\u hex included), integers in full.
    Floats are refused rather than serialised: the profile's numbers are all integers, and Section 3.2.2.3 of the RFC
    (ECMAScript number formatting) is not implemented here."""
    if isinstance(obj, bool) or obj is None:
        return json.dumps(obj)
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        raise ValueError("RFC 8785 number formatting for floats is not implemented; the profile carries integers only")
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in obj) + "]"
    if isinstance(obj, dict):
        keys = sorted(obj, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(canonical_json(k) + ":" + canonical_json(obj[k]) for k in keys) + "}"
    raise TypeError(f"not a JSON value: {type(obj).__name__}")


def canonical_bytes(obj):
    return canonical_json(obj).encode("utf-8")


def b64url(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def unb64url(s):
    """base64url without padding (RFC 4648 Section 5): the alphabet only, no '=', and a length that decodes."""
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s) or len(s) % 4 == 1:
        raise ValueError("not base64url without padding")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def chain_hash(content_hash, prev_chain_hash, action_timestamp_ms, agent_id):
    """Section 5.7: SHA-256(content_hash(32) || prev_chain_hash(32) || action_timestamp_ms as u64 big-endian ||
    u32 big-endian byte length of agent_id in UTF-8 || those bytes); 76 + len(agent_id) bytes in."""
    aid = agent_id.encode("utf-8")
    data = content_hash + prev_chain_hash + struct.pack(">Q", action_timestamp_ms) + struct.pack(">I", len(aid)) + aid
    assert len(data) == 76 + len(aid)
    return hashlib.sha256(data).digest()


def sig_structure(protected_bytes, payload):
    """RFC 9052 Section 4.4, Sig_structure for COSE_Sign1 with an empty external_aad."""
    return cbor2.dumps(["Signature1", protected_bytes, b"", payload])


def parse_cose_sign1(data):
    """The COSE_Sign1 array (RFC 9052 Section 4.2), tag 18 accepted and not required."""
    try:
        obj = cbor2.loads(data)
    except Exception as e:
        raise Malformed(f"not CBOR: {e}")
    if isinstance(obj, cbor2.CBORTag):
        if obj.tag != 18:
            raise Malformed(f"CBOR tag {obj.tag} is not COSE_Sign1 (18)")
        obj = obj.value
    if not isinstance(obj, (list, tuple)) or len(obj) != 4:       # cbor2 gives a tuple for an array under a tag
        raise Malformed("not an array of four (protected, unprotected, payload, signature)")
    protected_bytes, unprotected, payload, signature = obj
    if not isinstance(protected_bytes, bytes) or not isinstance(payload, bytes) or not isinstance(signature, bytes):
        raise Malformed("protected header, payload and signature must be byte strings")
    if not isinstance(unprotected, Mapping):        # cbor2 gives an immutable mapping for a map under a tag
        raise Malformed("unprotected header must be a map")
    try:
        protected = cbor2.loads(protected_bytes) if protected_bytes else {}
    except Exception as e:
        raise Malformed(f"protected header is not CBOR: {e}")
    if not isinstance(protected, Mapping):
        raise Malformed("protected header must be a map")
    return {"protected_bytes": protected_bytes, "protected": dict(protected), "unprotected": dict(unprotected),
            "payload": payload, "signature": signature}


def header_diagnostic(protected):
    """The protected header for the eye: integer labels named (the COSE labels at the top, the CWT claim keys inside
    label 15), byte strings as lowercase hex."""
    def show(v, names):
        if isinstance(v, bytes):
            return "h'" + v.hex() + "'"
        if isinstance(v, Mapping):
            return {f"{k} ({names.get(k, '?')})" if isinstance(k, int) else k: show(x, CWT_LABELS if k == 15 else names)
                    for k, x in v.items()}
        return v
    return show(protected, HEADER_LABELS)


def _is(v, typ):
    if typ is BSTR:
        try:
            return isinstance(v, str) and len(unb64url(v)) == 32
        except ValueError:
            return False
    if typ is int:
        return isinstance(v, int) and not isinstance(v, bool) and v >= 0   # uint
    if isinstance(typ, tuple):
        return any(_is(v, t) for t in typ)
    return isinstance(v, typ) and not (typ is int and isinstance(v, bool))


def _items_ok(items, shape):
    return isinstance(items, list) and all(isinstance(i, dict) and set(i) == set(shape) and all(_is(i[k], t) for k, t in shape.items())
                                           for i in items)


def _uuid_version(s):
    try:
        return uuid.UUID(s).version
    except (ValueError, AttributeError, TypeError):
        return None


def verify_record(data, public_key, prev=None):
    """One record against the text. prev is None for the first record of a chain (sequence 0 expected, zero
    prev_chain_hash) or the dict {"sequence_number", "chain_hash"} of the record before it. Returns the verdict, the
    checks (name, section, ok, detail), the payload as parsed and the protected header as read."""
    checks = []

    def check(name, section, ok, detail=""):
        checks.append({"check": name, "section": section, "ok": bool(ok), **({"detail": detail} if detail and not ok else {})})
        return bool(ok)

    try:
        c = parse_cose_sign1(data)
    except Malformed as e:
        check("COSE_Sign1 of four elements, protected header a byte string holding a map", "5.6; RFC 9052 4.2", False, str(e))
        return {"verdict": "FAIL", "checks": checks, "payload": None, "header": None}
    check("COSE_Sign1 of four elements, protected header a byte string holding a map", "5.6; RFC 9052 4.2", True)
    h = c["protected"]
    check("alg (label 1) is ES256 (-7)", "5.6, 6.1", h.get(1) == ES256, f"alg is {h.get(1)!r}")
    check("kid (label 4) present, a byte string", "5.6, 6.1", isinstance(h.get(4), bytes), f"kid is {type(h.get(4)).__name__}")
    cwt = h.get(15)
    cwt_ok = isinstance(cwt, dict) and isinstance(cwt.get(1), str) and isinstance(cwt.get(2), str)
    check("CWT Claims (label 15) present with iss (1) and sub (2), text strings", "5.6, 6.1; RFC 9943 6; RFC 9597", cwt_ok,
          "CWT Claims absent or iss/sub missing")
    fields_ok = (all(isinstance(h.get(k), bytes) and len(h[k]) == 32 for k in ("content_hash", "prev_chain_hash", "chain_hash"))
                 and _is(h.get("sequence_number"), int) and _is(h.get("action_timestamp_ms"), int)
                 and isinstance(h.get("agent_id"), str))
    check("integrity fields present and typed: content_hash, prev_chain_hash, chain_hash (32-byte bstr), sequence_number, "
          "action_timestamp_ms (uint), agent_id (tstr)", "5.5, 5.6", fields_ok,
          "missing or mistyped: " + ", ".join(k for k in ("content_hash", "prev_chain_hash", "chain_hash", "sequence_number",
                                                           "action_timestamp_ms", "agent_id") if k not in h))
    check("header agent_id equals CWT sub", "5.6", cwt_ok and h.get("agent_id") == cwt.get(2),
          f"agent_id {h.get('agent_id')!r}, sub {cwt.get(2) if isinstance(cwt, dict) else None!r}")
    # ---- 5.8, the four steps
    content = hashlib.sha256(c["payload"]).digest()          # reading (a): the bytes inside the payload bstr
    check("step 1, payload integrity: SHA-256(payload) equals content_hash", "5.8 step 1; 5.7", content == h.get("content_hash"),
          f"computed {content.hex()[:16]}…, header {h.get('content_hash', b'').hex()[:16]}…")
    if fields_ok:
        recomputed = chain_hash(h["content_hash"], h["prev_chain_hash"], h["action_timestamp_ms"], h["agent_id"])
        check("step 2, chain integrity: chain_hash recomputed from the header's content_hash, prev_chain_hash, "
              "action_timestamp_ms and agent_id with the 5.7 encoding", "5.8 step 2; 5.7", recomputed == h["chain_hash"],
              f"computed {recomputed.hex()[:16]}…, header {h['chain_hash'].hex()[:16]}…")
    else:
        check("step 2, chain integrity", "5.8 step 2; 5.7", False, "header fields missing, not recomputable")
    sig_ok = False
    if len(c["signature"]) == 64:
        r, s = int.from_bytes(c["signature"][:32], "big"), int.from_bytes(c["signature"][32:], "big")
        try:
            public_key.verify(encode_dss_signature(r, s), sig_structure(c["protected_bytes"], c["payload"]), ec.ECDSA(hashes.SHA256()))
            sig_ok = True
        except (InvalidSignature, ValueError):
            sig_ok = False
    check("step 3, signature validity: ES256 over the RFC 9052 Sig_structure (Signature1, protected, empty external_aad, "
          "payload) with the operator's public key", "5.8 step 3; RFC 9052 4.4; RFC 9053 2.1", sig_ok,
          "signature does not verify" if len(c["signature"]) == 64 else f"signature is {len(c['signature'])} bytes, not 64")
    seq = h.get("sequence_number")
    if prev is None:
        seq_ok = seq == 0 and h.get("prev_chain_hash") == ZERO32
        detail = f"first record: sequence_number {seq!r}, prev_chain_hash {'zero' if h.get('prev_chain_hash') == ZERO32 else 'not zero'}"
    else:
        seq_ok = seq == prev["sequence_number"] + 1 and h.get("prev_chain_hash") == prev["chain_hash"]
        detail = (f"sequence_number {seq!r} after {prev['sequence_number']}; prev_chain_hash "
                  f"{'equals' if h.get('prev_chain_hash') == prev['chain_hash'] else 'differs from'} the preceding chain_hash")
    check("step 4, sequence completeness: sequence_number is zero with a zero prev_chain_hash, or one more than the "
          "preceding record's with its chain_hash as prev_chain_hash", "5.8 step 4; 5.7; 6.3", seq_ok, detail)
    # ---- the payload against the CDDL (6.1 "valid AIR per CDDL") and the field rules of 5.3
    try:
        p = json.loads(c["payload"].decode("utf-8"))
        parsed = isinstance(p, dict)
    except (UnicodeDecodeError, ValueError):
        p, parsed = None, False
    canon = parsed and canonical_bytes(p) == c["payload"]
    check("payload is a JSON object in RFC 8785 canonical form (re-serialisation gives the same bytes)", "5.6", canon,
          "not a JSON object" if not parsed else "member order or spacing is not canonical")
    if not parsed:
        return {"verdict": "FAIL", "checks": checks, "payload": None, "header": h}
    check("schema_version is \"air-1.0\"", "5.3, 6.1", p.get("schema_version") == "air-1.0", f"{p.get('schema_version')!r}")
    bad_req = [k for k, t in REQUIRED.items() if k not in p or p[k] is None or not _is(p[k], t)]
    check("every REQUIRED member present, non-null and of its CDDL type", "5.2, 5.3, 6.1", not bad_req, "failing: " + ", ".join(bad_req))
    bad_opt = [k for k, t in OPTIONAL.items() if k not in p or (p[k] is not None and not _is(p[k], t))]
    check("every OPTIONAL member present (null when absent) and of its CDDL type when not null", "5.2", not bad_opt,
          "failing: " + ", ".join(bad_opt))
    extra = sorted(set(p) - set(REQUIRED) - set(OPTIONAL))
    check("no member outside the CDDL map", "5.2", not extra, "extra: " + ", ".join(extra))
    at = p.get("action_type")
    at_ok = isinstance(at, str) and (at in TABLE_2 or ("." in at and re.fullmatch(r"[A-Za-z0-9_.-]+", at) is not None
                                                        and not at.startswith(".")))
    check("action_type valid: a Table 2 value, or a reverse-DNS namespaced value", "4.2, 5.3, 6.1", at_ok,
          f"{at!r} is neither in Table 2 nor namespaced (key_rotation of 5.9 is not in Table 2: reading (c))")
    check("outcome_state is one of completed, failed, partially_completed, reversed, pending_confirmation", "5.3",
          p.get("outcome_state") in OUTCOME_STATES, f"{p.get('outcome_state')!r}")
    check("retention_class is one of the five labels (informational labels, 5.3)", "5.3", p.get("retention_class") in RETENTION_CLASSES,
          f"{p.get('retention_class')!r}")
    check("jurisdiction has the form of an ISO 3166-1 alpha-2 code", "5.3", isinstance(p.get("jurisdiction"), str)
          and re.fullmatch(r"[A-Z]{2}", p["jurisdiction"]) is not None, f"{p.get('jurisdiction')!r}")
    check("record_id is a UUID of version 7", "5.3; RFC 9562", _uuid_version(p.get("record_id")) == 7,
          f"{p.get('record_id')!r} (version {_uuid_version(p.get('record_id'))})")
    check("session_id is a UUID", "5.3", _uuid_version(p.get("session_id")) is not None, f"{p.get('session_id')!r}")
    check("input_hash and outcome_hash decode to 32 bytes (base64url without padding, the EES v0.2 provisional encoding)",
          "5.3; EES v0.2 $defs/bytes", _is(p.get("input_hash"), BSTR) and _is(p.get("outcome_hash"), BSTR))
    check("tool_calls items are ToolCallRecord {tool_id, tool_type, input_hash, output_hash, is_write, timestamp_ms}", "5.2, 5.3",
          _items_ok(p.get("tool_calls"), TOOL_CALL))
    check("external_refs items are ExternalRef {ref_type, ref_value, ref_system / null}", "5.2, 5.3",
          _items_ok(p.get("external_refs"), EXTERNAL_REF))
    check("redaction_receipts items are RedactionReceipt {field_path, original_hash, policy_id, timestamp_ms}", "5.2, 5.3",
          _items_ok(p.get("redaction_receipts"), REDACTION_RECEIPT))
    check("auth_context, when present, is AuthContext {token_type, scopes, audience / null, expires_at_ms / null}", "5.2, 5.3",
          p.get("auth_context") is None or _items_ok([p["auth_context"]], AUTH_CONTEXT))
    check("policy_refs and delegation_chain are arrays of text strings", "5.2",
          all(isinstance(x, str) for x in (p.get("policy_refs") or [])) and all(isinstance(x, str) for x in (p.get("delegation_chain") or [])))
    check("payload agent_id equals the header's agent_id and the CWT sub", "5.6", p.get("agent_id") == h.get("agent_id") == (cwt or {}).get(2),
          f"payload {p.get('agent_id')!r}, header {h.get('agent_id')!r}")
    check("payload action_timestamp_ms equals the header's", "5.6", p.get("action_timestamp_ms") == h.get("action_timestamp_ms"),
          f"payload {p.get('action_timestamp_ms')!r}, header {h.get('action_timestamp_ms')!r}")
    check("payload operator_id equals CWT iss; operator_pubkey_id equals kid", "5.3, 5.6",
          cwt_ok and p.get("operator_id") == cwt.get(1) and isinstance(h.get(4), bytes) and isinstance(p.get("operator_pubkey_id"), str)
          and h[4] == p["operator_pubkey_id"].encode("utf-8"))
    check("action_timestamp_ms <= captured_timestamp_ms", "6.3", _is(p.get("action_timestamp_ms"), int)
          and _is(p.get("captured_timestamp_ms"), int) and p["action_timestamp_ms"] <= p["captured_timestamp_ms"],
          f"action {p.get('action_timestamp_ms')!r}, captured {p.get('captured_timestamp_ms')!r}")
    check("at least one RedactionReceipt for the action types 6.4 names", "6.4",
          at not in REDACTION_REQUIRED_FOR or bool(p.get("redaction_receipts")), f"{at!r} with no redaction receipt")
    verdict = "VERIFIED" if all(x["ok"] for x in checks) else "FAIL"
    return {"verdict": verdict, "checks": checks, "payload": p, "header": h}


def verify_chain(records, public_key):
    """The records of one Evidence Chain in order (5.7: one chain per agent_id). Each is verified with the one before it
    as prev; the chain is VERIFIED when every record is and the agent_id is one throughout."""
    results, prev, agents = [], None, set()
    for data in records:
        r = verify_record(data, public_key, prev)
        results.append(r)
        if r["header"] and isinstance(r["header"].get("sequence_number"), int) and isinstance(r["header"].get("chain_hash"), bytes):
            prev = {"sequence_number": r["header"]["sequence_number"], "chain_hash": r["header"]["chain_hash"]}
            agents.add(r["header"].get("agent_id"))
        else:
            prev = {"sequence_number": -2, "chain_hash": b""}       # nothing after a malformed record can continue it
    one_agent = len(agents) == 1
    verdict = "VERIFIED" if results and all(r["verdict"] == "VERIFIED" for r in results) and one_agent else "FAIL"
    return {"verdict": verdict, "records": len(results), "one_agent_id": one_agent, "results": results}


def public_key_from_pem(pem):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(pem)


if __name__ == "__main__":
    import argparse
    import pathlib
    import sys
    ap = argparse.ArgumentParser(description="Verify a chain of AIR COSE_Sign1 files (raw bytes or hex) with the operator's public key.")
    ap.add_argument("--key", required=True, help="operator public key, PEM")
    ap.add_argument("records", nargs="+", help="COSE_Sign1 files in chain order (.cose raw, or .hex)")
    a = ap.parse_args()
    key = public_key_from_pem(pathlib.Path(a.key).read_bytes())
    blobs = []
    for f in a.records:
        raw = pathlib.Path(f).read_bytes()
        blobs.append(bytes.fromhex(raw.decode().strip()) if f.endswith(".hex") else raw)
    out = verify_chain(blobs, key)
    for i, r in enumerate(out["results"]):
        print(f"record {i}: {r['verdict']}" + "".join(f"\n  FAIL {c['section']}: {c['check']} ({c.get('detail', '')})"
                                                        for c in r["checks"] if not c["ok"]))
    print(f"chain: {out['verdict']} ({out['records']} records)")
    sys.exit(0 if out["verdict"] == "VERIFIED" else 1)
