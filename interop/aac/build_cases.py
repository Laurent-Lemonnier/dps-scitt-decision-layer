#!/usr/bin/env python3
"""Build the five interop cases: an Agent Action Capsule citing, by CPB typed digest references, a decision record and
an action-binding attachment of the Decision Provenance Standard. Each case is a folder: the capsule, the DPS documents
it cites (and the signatures attachment and trust policy that travel beside, when there are any), and expected.json,
what each side is expected to report. check_case.py runs both sides and compares.

Sources: the invoice example (a signed person_approval, verified by the Standard's checks) and the release example
(an unsigned attachment). Run with the DPS venv and the capsule library on PYTHONPATH (see README).
"""
import copy
import hashlib
import json
import pathlib
import shutil
import sys

from agent_action_capsule import canonical

HERE = pathlib.Path(__file__).resolve().parent
CASES = HERE / "cases"
INVOICE = pathlib.Path("/root/claude-ops/luce/dps-export")
RELEASE = pathlib.Path("/root/claude-ops/ietf/public/examples/release-decision")
NS = "org.decisionprovenancestandard"
ZEROS = "0" * 64


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def record_bytes(record):
    """The record as the Standard writes it: compact, carrying its seal; its covered bytes are these with the seal zeroed."""
    return compact(record)


def seal_of(record):
    return sha256(compact({**record, "seal_hash": ZEROS}))


def capsule_for(record, att_bytes, *, action_id, domain, effect_type, response, authority, timestamp, record_digest=None):
    cap = {
        "spec_version": "0.12", "format_version": "4", "canonicalization_id": "jcs",
        "action_id": action_id, "action_type": "decide",
        "operator": "example orchestrator", "developer": "example",
        "timestamp": timestamp, "domain": domain,
        "disposition": {"decision": "accept", "approver": "human", "human_disposed": True,
                        "authority": authority, "verdict_class": "executed"},
        "effect": {"status": "confirmed", "type": effect_type,
                   "request_digest": json.loads(att_bytes)["action_specifications"][0]["spec_digest"],
                   "response_digest": canonical.json_digest(response),
                   "external_ref": action_id + ":confirmation", "irreversibility_class": "one_way_recoverable",
                   "effect_attestation": "host_served_observed"},
        "references": [
            {"type": f"{NS}.decision_record", "digest_alg": "SHA-256", "digest": record_digest or record["seal_hash"],
             "citation_purpose": "ran_under"},
            {"type": f"{NS}.action_binding_attachment", "digest_alg": "SHA-256", "digest": sha256(att_bytes),
             "citation_purpose": "acted_on"},
        ],
    }
    cap["capsule_id"] = canonical.compute_capsule_id(cap)
    return cap


def write(folder, name, data):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_bytes(data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8") + b"\n")


def main():
    if CASES.exists():
        shutil.rmtree(CASES)
    inv_record = json.loads((INVOICE / "decision-record.json").read_bytes())
    assert seal_of(inv_record) == inv_record["seal_hash"], "the invoice record's seal must recompute"
    inv_att = (INVOICE / "action-binding-attachment.json").read_bytes()
    inv_sigs = (INVOICE / "signatures-attachment.json").read_bytes()
    inv_policy = (INVOICE / "verifier-trust-policy.json").read_bytes()
    inv_response = {"status": "created_and_verified", "invoice_ref": 9001, "company_ref": 41}
    inv = dict(action_id="urn:example:invoice:request:0901", domain="invoicing", effect_type="org.example.invoice_create",
               response=inv_response, authority="urn:example:charter:CH-EXAMPLE-BILLING-1#invoice-approval",
               timestamp="2026-10-24T10:05:00Z")

    rel_record = json.loads((RELEASE / "decision-record.json").read_bytes())
    assert seal_of(rel_record) == rel_record["seal_hash"], "the release record's seal must recompute"
    rel_att = (RELEASE / "action-binding-attachment.json").read_bytes()
    rel = dict(action_id="urn:example:deploy:request:0412", domain="software-release", effect_type="org.example.release_deploy",
               response={"deployment": "claims-intake-2.3.1", "status": "confirmed", "observed_at": "2026-10-23T14:25:00Z"},
               authority="urn:example:charter:CH-EXAMPLE-RELEASE-1#release-approval", timestamp="2026-10-23T14:21:10Z")

    # 1. Everything valid: a signed approval, verified by the Standard's checks, cited from the capsule.
    f = CASES / "01-valid"
    write(f, "decision-record.json", record_bytes(inv_record)); write(f, "action-binding-attachment.json", inv_att)
    write(f, "signatures-attachment.json", inv_sigs); write(f, "trust-policy.json", inv_policy)
    write(f, "capsule.json", capsule_for(inv_record, inv_att, **inv))
    write(f, "expected.json", {"about": "everything valid: the capsule verifies, both references resolve, the Standard's checks verify the attachment and the person's signed approval",
                               "capsule": {"verify_ok": True}, "references": {f"{NS}.decision_record": {"resolved": True}, f"{NS}.action_binding_attachment": {"resolved": True}},
                               "dps": {"record": {"seal_recomputed": True}, "attachment": {"action_binding": "verified"},
                                       "signatures": {"present": True, "person_approval": {"signature": "verified", "subject": "verified", "key_state": "verified", "identity": "verified"}}}})

    # 2. A reference whose digest does not match the cited bytes: CPB fails at resolution; the Standard is not consulted.
    f = CASES / "02-altered-reference-digest"
    write(f, "decision-record.json", record_bytes(inv_record)); write(f, "action-binding-attachment.json", inv_att)
    write(f, "signatures-attachment.json", inv_sigs); write(f, "trust-policy.json", inv_policy)
    bad = inv_record["seal_hash"][:-1] + ("0" if inv_record["seal_hash"][-1] != "0" else "1")
    write(f, "capsule.json", capsule_for(inv_record, inv_att, record_digest=bad, **inv))
    write(f, "expected.json", {"about": "the decision record's reference carries a digest one hex digit off: the capsule still verifies as a document, the reference does not resolve, and nothing of the Standard is consulted",
                               "capsule": {"verify_ok": True}, "references": {f"{NS}.decision_record": {"resolved": False}, f"{NS}.action_binding_attachment": {"resolved": True}},
                               "dps": {"consulted": False}})

    # 3. References correct, attachment unsigned: the Standard reports the absence, never "verified".
    f = CASES / "03-unsigned-attachment"
    write(f, "decision-record.json", record_bytes(rel_record)); write(f, "action-binding-attachment.json", rel_att)
    write(f, "capsule.json", capsule_for(rel_record, rel_att, **rel))
    write(f, "expected.json", {"about": "both references resolve; the attachment carries no signature and no signatures attachment travels beside: the binding verifies, the approval's signature is reported absent, not verified",
                               "capsule": {"verify_ok": True}, "references": {f"{NS}.decision_record": {"resolved": True}, f"{NS}.action_binding_attachment": {"resolved": True}},
                               "dps": {"record": {"seal_recomputed": True}, "attachment": {"action_binding": "verified"}, "signatures": {"present": False}}})

    # 4. References resolve to an attachment whose outcome answers a review it does not carry: resolution is not validity.
    f = CASES / "04-attachment-fails-its-own-check"
    broken = json.loads(inv_att)
    for s in broken["stages"]:
        if s["kind"] == "outcome":
            s["review_ref"] = "v9"
    broken_bytes = compact(broken)
    write(f, "decision-record.json", record_bytes(inv_record)); write(f, "action-binding-attachment.json", broken_bytes)
    write(f, "signatures-attachment.json", inv_sigs); write(f, "trust-policy.json", inv_policy)
    write(f, "capsule.json", capsule_for(inv_record, broken_bytes, **inv))
    write(f, "expected.json", {"about": "the cited attachment's outcome stage names a review the attachment does not carry: the capsule verifies and both references resolve (the bytes are the ones cited), and the Standard's own checks fail the binding and the signed approval's subject",
                               "capsule": {"verify_ok": True}, "references": {f"{NS}.decision_record": {"resolved": True}, f"{NS}.action_binding_attachment": {"resolved": True}},
                               "dps": {"record": {"seal_recomputed": True}, "attachment": {"action_binding": "failed"},
                                       "signatures": {"present": True, "person_approval": {"signature": "verified", "subject": "failed"}}}})

    # 5. The record re-encoded (same JSON, other bytes): as-transmitted fails by construction; so does the seal.
    f = CASES / "05-reencoded-record"
    pretty = json.dumps(inv_record, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    write(f, "decision-record.json", pretty); write(f, "action-binding-attachment.json", inv_att)
    write(f, "signatures-attachment.json", inv_sigs); write(f, "trust-policy.json", inv_policy)
    write(f, "capsule.json", capsule_for(inv_record, inv_att, **inv))
    write(f, "expected.json", {"about": "the record travels re-encoded (indented), the same JSON in other bytes; the reference carries the digest of the covered bytes as issued: an as-transmitted context hashes the bytes received, so the reference does not resolve, and the seal does not recompute either",
                               "capsule": {"verify_ok": True}, "references": {f"{NS}.decision_record": {"resolved": False}, f"{NS}.action_binding_attachment": {"resolved": True}},
                               "dps": {"consulted": False}})
    print("built:", ", ".join(sorted(p.name for p in CASES.iterdir())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
