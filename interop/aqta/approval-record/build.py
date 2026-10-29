#!/usr/bin/env python3
"""The example draft-chueayen-attestation-receipts-05 Section 8.3 calls for: an ACTION-v1 action
record (Seal, Aqta) whose ALLOWED decision rests on an approval bound to exact values, where the
approval record is the signed outcome stage of a Decision Provenance Standard action-binding
attachment (action binding 0.3.0 + signatures 0.2.0), referenced by the SHA-256 of its canonical
bytes. The policy that designates the approver (Section 8.2, "Designated approver") is the issuer's
document, signed through the specification: its digest is the specification's policy_version, as the
Standard's Steward read it on issue 93 (29 October 2026); a short validity is the policy's age limit
and the specification's valid_until, checked at the recheck (Section 8.2,
"Designated approver").

Builds every artefact from two test keys (never use them for anything real), then verifies:
  - the action record with the independent ACTION-v1 verifier written from the Seal text;
  - the attachment with the DPS action-binding reference check;
  - the person's signature with the DPS signatures reference check against the trust policy;
  - the cross-bindings of Section 8.2 (exact values, single use, expiry, policy version,
    independence, designated approver, rendering from the canonical action).
Nothing in the Standard or its extensions is changed; the composition sits in a sidecar document.
"""
import base64
import hashlib
import importlib.util
import json
import pathlib
import sys
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import os

HERE = pathlib.Path(__file__).resolve().parent
# the DPS Standard checkout (read only): DPS_STANDARD, else the clone run.sh makes, else the local one
REPO = pathlib.Path(os.environ.get("DPS_STANDARD") or (HERE / "dps-standard" if (HERE / "dps-standard").exists()
                                                       else "/root/claude-ops/dps/standard"))
AQTA = HERE.parent / "aqta_verify_independent.py"             # our ACTION-v1 verifier, written from the text
# a schema-valid Core v5.0 record to model the decision on: this repository's release example
_candidates = [HERE.parents[2] / "examples/release-decision/decision-record.json",
               HERE.parents[3] / "exemple-release/decision-record.json"]
TEMPLATE = pathlib.Path(os.environ.get("DPS_RECORD_TEMPLATE") or next(p for p in _candidates if p.exists()))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AB = load("ab", REPO / "extensions/action-binding/tests/run_checks.py")
SIG = load("sig", REPO / "extensions/signatures/tests/run_checks.py")
AQ = load("aq", AQTA)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def jcs(doc):
    return AQ.canonical(doc).encode("utf-8")        # RFC 8785 member order, literal UTF-8


def b64url(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def key_from_seed(text):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(text.encode()).digest())


def raw_public(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# ---- two test keys: the approver (a person) and the enforcement point (the Seal issuer)
approver = key_from_seed("dps-scitt-decision-layer interop example: approver key (test only)")
issuer = key_from_seed("dps-scitt-decision-layer interop example: enforcement point key (test only)")

# ---- the proposed action, as the enforcement point canonicalises it (ACTION-v1 Section 6 rules)
args = {"repo": "isoluce/claims-intake", "pull_number": "4521", "merge_method": "squash",
        "head_sha": "5d1c9f0e7b2a4c6d8f1a3b5c7d9e0f2a4b6c8d0e", "base": "main"}
args_bytes = jcs(args)
args_hash = sha256(args_bytes)
ORG, TOOL, POLICY = "org-isoluce", "github.merge_pull_request", "production_change_review"

# ---- the designating policy: the issuer's document that names who may approve this operation for
# this target (the Steward's reading on issue 93 of the Standard's repository, 29 October 2026).
# Not the verifier's trust policy. Its digest is written as the specification's policy_version, so
# the person's approval, which signs the specification's digest, signs the policy's words too.
issuer_policy = {
    "policy_id": "urn:isoluce:policy:production_change_review", "version": "2026-10-01",
    "applies_to": {"operation": TOOL, "target_prefix": f"{ORG}/"},
    "approvers": [{"actor_ref": "release-manager-claims", "role": "release manager, claims platform"}],
    "independence": "the approver is neither the proposing agent nor the requesting service",
    "single_use": True,
    "max_approval_age_seconds": 900,
    "recheck": "the executor rechecks this policy before each attempt, on its own clock, and refuses an approval "
               "older than max_approval_age_seconds or past the specification's valid_until",
}
issuer_policy_bytes = compact(issuer_policy)
POLICY_VERSION = "sha256:" + sha256(issuer_policy_bytes)
APPROVED_AT, VALID_UNTIL = "2026-10-29T16:12:00Z", "2026-10-29T16:27:00Z"

# ---- what the approver was shown: rendered by the enforcement point from the canonical argument
# object, never from text supplied by the agent (Section 8.2, "Rendering from the canonical action")
view = ("Merge pull request #4521 of isoluce/claims-intake into main (squash)\n"
        f"head commit {args['head_sha']}\nargument digest sha256:{args_hash}\n"
        f"policy {issuer_policy['policy_id']} version {issuer_policy['version']} ({POLICY_VERSION})\n"
        f"valid until {VALID_UNTIL}\n").encode("utf-8")
view_digest = sha256(view)

# ---- the DPS action specification: the exact values the approval binds (org, tool, args_hash,
# the policy by the digest of its bytes, and the deadline the deployer made material), plus the arguments
spec = {"operation": TOOL, "target": f"{ORG}/isoluce/claims-intake",
        "parameters": {"org_id": ORG, "args_hash": args_hash, "args": args},
        "input_version_refs": ["urn:isoluce:ci:run:9142"], "policy_version": POLICY_VERSION,
        "valid_until": VALID_UNTIL}
spec_bytes = compact(spec)
spec_digest = sha256(spec_bytes)

# ---- the decision record (Core v5.0), modelled on the repository's examples
record = json.loads(TEMPLATE.read_bytes())
record.update({
    "decision_id": "DR-2026-0517", "created_at": "2026-10-29T16:00:00Z",
    "decision_statement": "Merge pull request #4521 of claims-intake (duplicate-attachment fix) into main by squash, "
                          "head 5d1c9f0, CI run 9142 green, under the production change review policy.",
    "context_at_decision": "The fix closes INC-2026-118 and INC-2026-121. The release assistant proposed the merge; "
                           "the enforcement point rendered the proposed call for review.",
    "options_considered": ["Merge now by squash (chosen): CI green, review done, rollback by revert.",
                           "Hold for the month-end freeze: leaves the defect in production.",
                           "Merge without squash: keeps 14 fix-up commits in main's history."],
    "required_inputs_used": ["CI run 9142 (412/412 tests)", "review of the rendered call, view 0517"],
    "affirmation_record": {"timestamp": "2026-10-29T16:12:00Z", "actor_identity": "release-manager-claims",
                           "method": "Ed25519 signature over the DPS person_approval assertion"},
    "accountable_owner_signoff": {"signed_by": "release-manager-claims", "signed_at": "2026-10-29T16:30:00Z"},
    "closed_at": "2026-10-29T16:30:00Z", "record_location": "urn:isoluce:decision-records:DR-2026-0517",
})
record["mode_classification_attestation"]["attestation_timestamp"] = "2026-10-29T16:30:00Z"
record["mode_classification_attestation"]["attestation_text_signed"] = record["mode_classification_attestation"]["attestation_text_signed"].replace("view 0412", "view 0517")
record["seal_hash"] = "0" * 64
record["seal_hash"] = sha256(compact(record))
record_bytes = compact(record)

# ---- the action-binding attachment: proposal -> review (shown digest) -> outcome (approved by a
# person, single use) -> request -> recheck -> attempt (the Seal action record) -> result
ACTION_ID = "6f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f"
attachment = {
    "profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": record["decision_id"],
    "action_specifications": [{
        "spec_digest": spec_digest,
        "representation": {"kind": "original_bytes", "media_type": "application/json"},
        "content": {"availability": "available", "bytes_b64": base64.b64encode(spec_bytes).decode("ascii")},
        "summary": {"operation": TOOL, "target": spec["target"], "policy_version": POLICY_VERSION,
                    "input_version_refs": spec["input_version_refs"]}}],
    "stages": [
        {"stage_id": "p1", "kind": "proposal", "at": "2026-10-29T16:05:00Z", "origin": "ai", "spec_digest": spec_digest,
         "deployer_role_pointer": "urn:isoluce:role:release-drafting", "system_name": "release-assistant", "version": "3"},
        {"stage_id": "v1", "kind": "review", "at": "2026-10-29T16:10:00Z", "reviewer_ref": "release-manager-claims",
         "shown_spec_digest": spec_digest, "proposal_ref": "p1", "shown_view_ref": "urn:isoluce:review-console:view:0517",
         "shown_view_digest": view_digest},
        {"stage_id": "o1", "kind": "outcome", "at": "2026-10-29T16:12:00Z", "review_ref": "v1", "outcome": "approved",
         "actor_ref": "release-manager-claims", "method": "Ed25519 signature over the DPS person_approval assertion",
         "approved_spec_digest": spec_digest, "request_limit": 1,
         "authority": {"authority_ref": issuer_policy["policy_id"] + "#" + issuer_policy["version"]},
         "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": "2026-10-29T16:12:00Z",
                       "text_ref": "urn:isoluce:rationale:0517"},
         "core_ref": {"field": "affirmation_record"}},
        {"stage_id": "q1", "kind": "request", "at": "2026-10-29T16:12:30Z", "request_id": f"urn:aqta:action:{ACTION_ID}",
         "authorised_by": "o1", "spec_digest": spec_digest, "requested_by": "urn:isoluce:service:release-assistant"},
        {"stage_id": "c1", "kind": "recheck", "at": "2026-10-29T16:12:40Z", "request_ref": "q1", "result": "authorised",
         "authority_source_ref": issuer_policy["policy_id"] + "#" + issuer_policy["version"]},
        {"stage_id": "x1", "kind": "attempt", "at": "2026-10-29T16:12:45Z", "request_ref": "q1", "recheck_ref": "c1",
         "spec_digest": spec_digest, "executor_ref": "urn:aqta:enforcement-point:seal", "trace_refs": [f"urn:aqta:action:{ACTION_ID}"]},
        {"stage_id": "r1", "kind": "result", "at": "2026-10-29T16:13:02Z", "attempt_ref": "x1", "observed": "succeeded",
         "basis": "target_response", "evidence_ref": "urn:github:isoluce/claims-intake:pull:4521:merged"},
    ],
}
attachment_bytes = compact(attachment)

# ---- the trust policy (the verifier's own; it designates the approver's key in role person)
policy = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0",
          "policy_ref": "urn:isoluce:trust-policy:verifier-1", "tsas": [], "checkpoint_sources": [],
          "keys": [{"key_ref": "release-manager-claims-key-1", "holder": "release-manager-claims", "role": "person",
                    "algorithm": "Ed25519", "public_key_hex": raw_public(approver).hex(),
                    "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-08-31T23:59:59Z",
                    "identity_source_ref": "urn:isoluce:directory:people"}]}
policy_bytes = compact(policy)

# ---- the approval record: the person's signature over the outcome (signatures 0.2.0)
ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval",
      "decision_id": record["decision_id"], "stage_id": "o1", "outcome": "approved",
      "shown_spec_digest": spec_digest, "shown_view_digest": view_digest, "approved_spec_digest": spec_digest,
      "signed_at": "2026-10-29T16:12:00Z",
      "signature": {"algorithm": "Ed25519", "key_ref": "release-manager-claims-key-1", "value_b64": ""}}
signed = SIG.person_signed_bytes(ps)
ps["signature"]["value_b64"] = base64.b64encode(approver.sign(signed)).decode("ascii")
sig_attachment = {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps],
                  "organisation_seals": [], "timestamps": []}
approval_canonical = jcs(ps)                       # the canonical bytes the action record would reference
approval_hash = sha256(approval_canonical)

# ---- the Seal action record (ACTION-v1), issued by the enforcement point after the approval
action = {"v": "action-1", "action_id": ACTION_ID, "org_id": ORG, "session_id": "sess-0517",
          "intent_hash": "", "agent": "release-assistant/3", "tool": TOOL, "args_hash": args_hash,
          "outcome": "ALLOWED", "policy_applied": [POLICY], "timestamp": "2026-10-29T16:12:45.000Z",
          "public_key": b64url(raw_public(issuer))}
action["signature"] = b64url(issuer.sign(AQ.canonical(action).encode("utf-8")))

# ---- the composition sidecar: what a future ACTION-v1 member would carry (Section 8.3), kept
# outside the v1 record because v1 rejects unknown members
composition = {
    "about": "draft-chueayen-attestation-receipts-05 Section 8.3: the approval record an action record would reference",
    "action_record": {"action_id": ACTION_ID, "args_hash": args_hash, "org_id": ORG, "tool": TOOL, "policy_applied": [POLICY]},
    "approval_record": {"format": "dps-signatures 0.2.0 person_approval over dps-action-binding 0.3.0 stage o1",
                        "canonical_bytes": "RFC 8785 serialisation of the assertion object as issued",
                        "sha256": approval_hash, "decision_id": record["decision_id"], "stage_id": "o1"},
    "designating_policy": {"document": "policy.json", "policy_id": issuer_policy["policy_id"],
                           "version": issuer_policy["version"], "digest": POLICY_VERSION,
                           "signed_via": "the specification's policy_version, under the person's approval "
                                         "(shown_spec_digest and approved_spec_digest); nothing beside it is signed"},
    "binding": {"exact_values": "the approved specification carries org_id, tool, args_hash, the policy by the digest "
                                "of its bytes and valid_until; its digest is what the review showed and what the "
                                "approval signed",
                "spec_digest": spec_digest, "shown_view_digest": view_digest},
}


def policy_checks(spec_read, policy_held, approved_at, attempt_at, outcome_actor):
    """What a verifier holding the issuer's policy can check, each result on its own: the policy is the one the
    specification signs; the attempt is within the policy's age limit and the specification's valid_until; the
    approver is one the policy names. A policy the verifier does not hold leaves the first three not checked,
    never verified."""
    from datetime import datetime
    t = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
    if policy_held is None:
        return {"policy_digest": "not_checked: the policy is not held",
                "approval_age": "not_checked: the policy is not held",
                "valid_until": "verified" if t(attempt_at) <= t(spec_read["valid_until"]) else "failed: attempt after valid_until",
                "designated_approver": "not_checked: the policy is not held"}
    doc = json.loads(policy_held)
    age = (t(attempt_at) - t(approved_at)).total_seconds()
    return {
        "policy_digest": "verified" if "sha256:" + sha256(policy_held) == spec_read["policy_version"]
                         else "failed: the policy held is not the one the specification names",
        "approval_age": "verified" if age <= doc["max_approval_age_seconds"]
                        else f"failed: attempt {int(age)} s after the approval, the policy allows {doc['max_approval_age_seconds']}",
        "valid_until": "verified" if t(attempt_at) <= t(spec_read["valid_until"]) else "failed: attempt after valid_until",
        "designated_approver": "verified" if any(a["actor_ref"] == outcome_actor for a in doc["approvers"])
                               else "failed: the policy does not name this approver",
    }

# ---- write everything
out = HERE / "out"
out.mkdir(exist_ok=True)
for name, data in [("decision-record.json", record_bytes), ("action-binding-attachment.json", attachment_bytes),
                   ("signatures-attachment.json", compact(sig_attachment)), ("trust-policy.json", policy_bytes),
                   ("action-record.json", compact(action)), ("composition.json", compact(composition)),
                   ("specification.bytes.json", spec_bytes), ("arguments.canonical.json", args_bytes),
                   ("review-view.txt", view), ("approval.canonical.json", approval_canonical),
                   ("policy.json", issuer_policy_bytes)]:
    (out / name).write_bytes(data)
(out / "approval.canonical.json").write_bytes(approval_canonical)

# ---- verification, both sides and across
results = {}
# 1. the action record, under the Seal text (pinned key = the enforcement point's)
try:
    AQ.verify_action(json.loads(compact(action)), action["public_key"])
    results["seal_action_record"] = "valid"
except AQ.Invalid as e:
    results["seal_action_record"] = f"invalid: {e}"
# 2. the attachment, under the DPS action-binding reference check
binding = AB.check_attachment(attachment, record_bytes)
results["dps_action_binding"] = {k: (v["status"] if isinstance(v, dict) and "status" in v else v) for k, v in binding.items()}
# 3. the person's signature, under the DPS signatures reference check
policy_result, persons, seals, ts = SIG.run_context({"attachment": sig_attachment, "export": None,
                                                     "action_binding": {record["decision_id"]: attachment}, "policy": policy})
results["dps_trust_policy"] = policy_result["status"]
results["dps_person_approval"] = {k: persons[0][k]["status"] if isinstance(persons[0][k], dict) and "status" in persons[0][k] else persons[0][k]
                                  for k in ("status", "signature", "subject", "key_state", "identity")}
# 4. the bindings Section 8.2 asks for
spec_read = json.loads(base64.b64decode(attachment["action_specifications"][0]["content"]["bytes_b64"]))
o1 = next(s for s in attachment["stages"] if s["stage_id"] == "o1")
x1 = next(s for s in attachment["stages"] if s["stage_id"] == "x1")
pc = policy_checks(spec_read, issuer_policy_bytes, ps["signed_at"], x1["at"], o1["actor_ref"])
results["policy_checks"] = pc
checks = {
    "exact_values: action.args_hash == sha256(canonical args) == spec.parameters.args_hash":
        action["args_hash"] == sha256(args_bytes) == spec_read["parameters"]["args_hash"],
    "exact_values: action.tool/org_id == spec operation/parameters.org_id": action["tool"] == spec_read["operation"] and action["org_id"] == spec_read["parameters"]["org_id"],
    "exact_values: approval signed the digest of those bytes": ps["approved_spec_digest"] == sha256(spec_bytes) == o1["approved_spec_digest"],
    "single_use: the approval states request_limit 1 and one request rests on it": o1.get("request_limit") == 1 and sum(1 for s in attachment["stages"] if s.get("authorised_by") == "o1") == 1,
    "expiry: the attempt is within the policy's age limit and the specification's valid_until, both signed": all(v == "verified" for k, v in pc.items() if k in ("approval_age", "valid_until")),
    "policy_version: spec.policy_version is the digest of the issuer's policy held, and that policy is the one the record applied": pc["policy_digest"] == "verified" and json.loads(issuer_policy_bytes)["policy_id"].endswith(":" + POLICY) and action["policy_applied"] == [POLICY],
    "independence: approver key holder is not the agent nor the requesting service": policy["keys"][0]["holder"] != action["agent"] and policy["keys"][0]["holder"] not in attachment["stages"][3]["requested_by"],
    "designated_approver: the signed policy names the approver, and the verifier's trust policy maps the key to that person": pc["designated_approver"] == "verified" and policy["keys"][0]["role"] == "person" and results["dps_person_approval"]["identity"] == "verified",
    "rendering: the view the approver was shown is derived from the canonical args and its digest is signed": args_hash in view.decode() and ps["shown_view_digest"] == sha256(view),
    "reference: composition.approval_record.sha256 == sha256(RFC 8785 of the assertion as issued)": composition["approval_record"]["sha256"] == sha256(jcs(json.loads((out / "signatures-attachment.json").read_bytes())["person_signatures"][0])),
}
results["section_8_2_properties"] = checks
DIMENSIONS = ("specification_digests", "specification_statements", "record_statements", "action_binding",
              "stage_order", "authorisation_recheck", "observed_results", "rationale_provenance")
binding_ok = all(results["dps_action_binding"][d][0] == "verified" for d in DIMENSIONS) and \
    all(all(c[0] == "verified" for c in spec_checks) for spec_checks in results["dps_action_binding"]["per_spec"])
results["all_verified"] = (results["seal_action_record"] == "valid" and results["dps_trust_policy"] == "verified"
                           and results["dps_person_approval"]["status"] == "verified" and binding_ok and all(checks.values()))
(out / "summary.json").write_text(json.dumps(results, indent=1, ensure_ascii=False))
print(json.dumps(results, indent=1, ensure_ascii=False))
sys.exit(0 if results["all_verified"] else 1)
