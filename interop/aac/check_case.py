#!/usr/bin/env python3
"""Check one interop case from both sides, and compare with expected.json.

Capsule side (the library of draft-mih-scitt-agent-action-capsule): parse the capsule strictly, verify it, then
resolve each typed digest reference against the DPS document held beside it, as a CPB as-transmitted context does:
hash the bytes received, nothing re-encoded. For the decision record the context is the covered bytes as portable
verification names them: the record's bytes with the seal field's value zeroed, byte for byte; for the attachment, the
attachment's bytes.

Standard side (the reference checks of its repository, unchanged): the record against its schema and its seal; the
attachment against its schema and the action binding reference check; the signatures attachment, when one travels
beside, through the signatures reference check with the trust policy. The Standard is consulted only when every
reference resolved, as a verifier would.

Usage: check_case.py <case folder> [...]. Writes result.json in each folder; exit 0 when every case matches expected.
"""
import importlib.util
import json
import pathlib
import re
import sys

from jsonschema import Draft202012Validator

import importlib

parse = importlib.import_module("agent_action_capsule.parse")
verify = importlib.import_module("agent_action_capsule.verify")

import os
# the Standard's checkout the DPS side runs (main at 007f8c9 since 29 October 2026: #87 and #91 merged)
DPS = pathlib.Path(os.environ.get("DPS_STANDARD", "/root/claude-ops/dps/wt-007f8c9"))
NS = "org.decisionprovenancestandard"
ZEROS = "0" * 64


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ab = load("ab_run_checks", DPS / "extensions/action-binding/tests/run_checks.py")
sig = load("sig_run_checks", DPS / "extensions/signatures/tests/run_checks.py")
SCHEMAS = {
    "record": DPS / "standard/v5.0/schemas/decision-record.schema.json",
    "attachment": DPS / "extensions/action-binding/schemas/execution-evidence.schema.json",
    "signatures": DPS / "extensions/signatures/schemas/signatures-attachment.schema.json",
    "policy": DPS / "extensions/anchoring/schemas/trust-policy.schema.json",
}


def sha256(b):
    import hashlib
    return hashlib.sha256(b).hexdigest()


def schema_errors(which, doc):
    validator = Draft202012Validator(json.loads(SCHEMAS[which].read_text(encoding="utf-8")))
    return [e.message[:160] for e in validator.iter_errors(doc)]


def covered_bytes(record_bytes, seal):
    """The record's covered bytes: its bytes as received with the seal's value replaced by zeros, byte for byte."""
    return re.sub(rb'("seal_hash"\s*:\s*")' + seal.encode() + rb'(")', rb'\g<1>' + ZEROS.encode() + rb'\2', record_bytes, count=1)


def capsule_side(folder, capsule, record_bytes, att_bytes):
    out = {}
    try:
        parse.parse_capsule(capsule)
        out["parse_ok"], out["parse_error"] = True, None
    except Exception as exc:  # the library's own refusal, reported as such
        out["parse_ok"], out["parse_error"] = False, f"{type(exc).__name__}: {exc}"
    result = verify.verify(capsule)
    out["verify_ok"] = bool(getattr(result, "ok", False))
    out["findings"] = [f"{getattr(f, 'severity', getattr(f, 'level', '?'))} {getattr(f, 'code', '')}" for f in getattr(result, "findings", [])]
    record = json.loads(record_bytes)
    held = {f"{NS}.decision_record": sha256(covered_bytes(record_bytes, record.get("seal_hash", ""))),
            f"{NS}.action_binding_attachment": sha256(att_bytes)}
    refs = {}
    for ref in capsule.get("references", []):
        cited = ref["digest"]
        refs[ref["type"]] = {"cited": cited, "held": held.get(ref["type"]), "digest_alg": ref["digest_alg"],
                             "resolved": ref["digest_alg"] == "SHA-256" and held.get(ref["type"]) == cited,
                             "citation_purpose": ref.get("citation_purpose")}
    return out, refs


def statuses(result):
    out = {}
    for k, v in result.items():
        if isinstance(v, (list, tuple)) and len(v) == 2 and isinstance(v[0], str):
            out[k] = v[0]
    if "execution_state" in result:
        out["execution_state"] = result["execution_state"]
    return out


def dps_side(folder, record_bytes, att_bytes):
    record, attachment = json.loads(record_bytes), json.loads(att_bytes)
    out = {"consulted": True}
    out["record"] = {"schema_errors": schema_errors("record", record),
                     "seal_recomputed": sha256(covered_bytes(record_bytes, record.get("seal_hash", ""))) == record.get("seal_hash")}
    binding = ab.check_attachment(attachment, record_bytes)
    out["attachment"] = {"schema_errors": schema_errors("attachment", attachment), **statuses(binding)}
    sig_path, pol_path = folder / "signatures-attachment.json", folder / "trust-policy.json"
    if sig_path.exists() and pol_path.exists():
        signatures, policy = json.loads(sig_path.read_bytes()), json.loads(pol_path.read_bytes())
        policy_result, persons, _seals, _ts = sig.run_context(
            {"policy": policy, "attachment": signatures, "export": None, "action_binding": {record["decision_id"]: attachment}})
        out["signatures"] = {"present": True, "schema_errors": schema_errors("signatures", signatures) + schema_errors("policy", policy),
                             "trust_policy": policy_result.get("status"),
                             "person_approval": {k: persons[0][k]["status"] for k in ("signature", "subject", "key_state", "identity")} if persons else None,
                             "findings": [f for p in persons for d in ("signature", "subject", "key_state", "identity") for f in p[d].get("findings", [])]}
    else:
        out["signatures"] = {"present": False, "note": "no signatures attachment travels beside: the approval's signature is absent, not verified"}
    return out


def subset(expected, got):
    """Every leaf of expected is in got with the same value; 'about' is documentation."""
    if isinstance(expected, dict):
        return all(k == "about" or (k in (got or {}) and subset(v, got[k])) for k, v in expected.items())
    return expected == got


def check(folder):
    folder = pathlib.Path(folder)
    capsule = json.loads((folder / "capsule.json").read_bytes())
    record_bytes = (folder / "decision-record.json").read_bytes()
    att_bytes = (folder / "action-binding-attachment.json").read_bytes()
    cap, refs = capsule_side(folder, capsule, record_bytes, att_bytes)
    result = {"case": folder.name, "capsule": cap, "references": refs}
    if all(r["resolved"] for r in refs.values()):
        result["dps"] = dps_side(folder, record_bytes, att_bytes)
    else:
        result["dps"] = {"consulted": False, "note": "a reference did not resolve: the Standard's documents are not the ones cited, so they are not checked"}
    expected = json.loads((folder / "expected.json").read_bytes())
    result["matches_expected"] = subset(expected, result)
    (folder / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=1, default=str) + "\n", encoding="utf-8")
    return result


def main():
    ok = True
    for arg in sys.argv[1:]:
        r = check(arg)
        ok = ok and r["matches_expected"]
        print(("PASS " if r["matches_expected"] else "FAIL ") + r["case"] + ": capsule " + ("ok" if r["capsule"]["verify_ok"] else "refused")
              + ", references " + ", ".join(f"{k.split('.')[-1]}={'resolved' if v['resolved'] else 'FAILED'}" for k, v in r["references"].items())
              + ", DPS " + (("binding " + str(r["dps"].get("attachment", {}).get("action_binding")) + ", approval "
                             + str((r["dps"].get("signatures") or {}).get("person_approval") or "absent")) if r["dps"].get("consulted") else "not consulted"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
