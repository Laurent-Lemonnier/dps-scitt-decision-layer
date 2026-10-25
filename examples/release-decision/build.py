"""A software release decision in DPS: a decision record (record schema of the reference files 5.2.0) and an action-binding 0.3.0 attachment
binding the release pipeline's stages to it. Validates both against the repository's schemas and runs the action-binding
reference check on the attachment. No key: the attachment is unsigned (allowed), the record carries its seal_hash."""
import base64
import hashlib
import importlib.util
import json
import pathlib
import sys

from jsonschema import Draft202012Validator

REPO = pathlib.Path(__import__("os").environ.get("DPS_REPO", str(pathlib.Path(__file__).resolve().parents[3] / "standard")))  # a checkout of decision-provenance-standard/standard
HERE = pathlib.Path(__file__).resolve().parent


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# ---- the decision: ship release 2.3.1 of the claims-intake service
record = {
    "decision_id": "DR-2026-0412",
    "charter_id": "CH-ISOLUCE-RELEASE-1",
    "record_type": "decision",
    "record_state": "closed",
    "dispatch_mode": "mode-1-with-embedded-mode-2-summary",
    "created_at": "2026-10-23T14:02:00Z",
    "altitude": "team-leader",
    "decision_statement": "Ship claims-intake 2.3.1 to production on 2026-10-23: build 2.3.1+git.5d1c9f0, SBOM "
                          "sha256:3b7f…, all 412 tests green, dependency audit clean, migration 0042 reversible.",
    "context_at_decision": "Release candidate 2.3.1 fixes the duplicate-attachment defect reported by two brokers "
                           "(INC-2026-118, INC-2026-121). Change freeze for month-end starts 2026-10-27.",
    "options_considered": [
        "Ship 2.3.1 now (chosen): defect fixed, tests green, rollback by redeploying 2.3.0 and reverting migration 0042.",
        "Hold until after month-end freeze: leaves the defect in production for ten more days.",
        "Hotfix 2.3.0.1 with the attachment fix only: smaller change, but migration 0042 would still be needed for the "
        "reporting fix brokers asked for in the same window."],
    "required_inputs_used": ["CI run 8831 (412/412 tests)", "dependency audit 2026-10-23 (0 critical, 0 high)",
                             "SBOM claims-intake-2.3.1.spdx.json sha256 3b7f…", "staging soak 24 h without error"],
    "assumptions_depended_on": ["Migration 0042 is reversible within five minutes, as rehearsed on staging."],
    "success_criteria": ["No duplicate-attachment incident in the seven days after release.",
                         "p95 latency of /claims/intake unchanged (±10 %)."],
    "accountable_owner": {"full_name": "Claire Martin", "role": "Release manager, claims platform", "employer": "iSoluce"},
    "decision_class": "software-release",
    "drafting_authority": {"deployer_role_pointer": "urn:isoluce:role:release-drafting", "system_name": "release-assistant",
                           "version": "3"},
    "consent_posture": {"posture_class": "not-applicable: no personal data processing changes in this release"},
    "affirmation_record": {"timestamp": "2026-10-23T14:20:00Z", "actor_identity": "release-manager-claims",
                           "method": "signed approval in the release console"},
    "mode_classification_attestation": {
        "attestor_full_name": "Claire Martin", "attestor_role_title": "Release manager, claims platform",
        "attestor_employer": "iSoluce", "attestation_timestamp": "2026-10-23T15:05:00Z", "jurisdiction": "EU",
        "attestation_language_version": "v5.0", "attestor_capacity": "employee",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded "
                                   "mode-2 summary under charter CH-ISOLUCE-RELEASE-1: the release assistant "
                                   "(release-assistant, version 3) drafted the deploy proposal from CI run 8831 and the "
                                   "dependency audit of 2026-10-23; I reviewed the proposal as shown in the release "
                                   "console view 0412, weighed the three options recorded here, approved the "
                                   "specification whose digest the attachment names, and I am the accountable owner "
                                   "of this decision in my capacity as an employee of iSoluce."},
    "accountable_owner_signoff": {"signed_by": "release-manager-claims", "signed_at": "2026-10-23T15:05:00Z"},
    "re_decision_trigger": "Any duplicate-attachment incident, or a p95 latency rise above 10 %, within seven days.",
    "record_location": "urn:isoluce:decision-records:DR-2026-0412",
    "seal_algorithm": "SHA-256",
    "supersedes": None,
    "closed_at": "2026-10-23T15:05:00Z",
}
# the seal: SHA-256 of the record with seal_hash's value replaced by 64 zeros, as the repository's governance records do
record["seal_hash"] = "0" * 64
record["seal_hash"] = sha256(compact(record))

# ---- the action: the deploy pipeline's specification, as the approver saw it
spec = {"operation": "release.deploy", "target": "urn:isoluce:service:claims-intake:production",
        "parameters": {"version": "2.3.1", "build": "2.3.1+git.5d1c9f0",
                       "artifact_digest": "sha256:9d4e2c1b0f6a7e3d8c5b4a2910f8e7d6c5b4a3920e1d0c9b8a7f6e5d4c3b2a19",
                       "sbom_digest": "sha256:3b7f0a1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e",
                       "migrations": ["0042"], "rollback": "redeploy 2.3.0, revert 0042"},
        "input_version_refs": ["urn:isoluce:ci:run:8831", "urn:isoluce:audit:deps:2026-10-23"],
        "policy_version": "urn:isoluce:release-policy:7"}
spec_bytes = compact(spec)
spec_digest = sha256(spec_bytes)
attachment = {
    "profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": record["decision_id"],
    "action_specifications": [{
        "spec_digest": spec_digest,
        "representation": {"kind": "original_bytes", "media_type": "application/json"},
        "content": {"availability": "available", "bytes_b64": base64.b64encode(spec_bytes).decode("ascii")},
        "summary": {"operation": spec["operation"], "target": spec["target"],
                    "policy_version": spec["policy_version"], "input_version_refs": spec["input_version_refs"]}}],
    "stages": [
        {"stage_id": "p1", "kind": "proposal", "at": "2026-10-23T14:05:00Z", "origin": "ai",
         "spec_digest": spec_digest, "deployer_role_pointer": "urn:isoluce:role:release-drafting",
         "system_name": "release-assistant", "version": "3"},
        {"stage_id": "v1", "kind": "review", "at": "2026-10-23T14:18:00Z", "reviewer_ref": "release-manager-claims",
         "shown_spec_digest": spec_digest, "proposal_ref": "p1", "shown_view_ref": "urn:isoluce:release-console:view:0412"},
        {"stage_id": "o1", "kind": "outcome", "at": "2026-10-23T14:20:00Z", "review_ref": "v1", "outcome": "approved",
         "actor_ref": "release-manager-claims", "method": "signed approval in the release console",
         "approved_spec_digest": spec_digest,
         "authority": {"authority_ref": "urn:isoluce:charter:CH-ISOLUCE-RELEASE-1#release-approval"},
         "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": "2026-10-23T14:20:00Z",
                       "text_ref": "urn:isoluce:rationale:0412"},
         "core_ref": {"field": "affirmation_record"}},
        {"stage_id": "q1", "kind": "request", "at": "2026-10-23T14:21:00Z", "request_id": "urn:isoluce:deploy:request:0412",
         "authorised_by": "o1", "spec_digest": spec_digest, "requested_by": "urn:isoluce:service:release-orchestrator"},
        {"stage_id": "c1", "kind": "recheck", "at": "2026-10-23T14:21:05Z", "request_ref": "q1", "result": "authorised",
         "authority_source_ref": "urn:isoluce:permission-service:snapshot:0412"},
        {"stage_id": "x1", "kind": "attempt", "at": "2026-10-23T14:21:10Z", "request_ref": "q1", "recheck_ref": "c1",
         "spec_digest": spec_digest, "executor_ref": "urn:isoluce:service:deployer", "trace_refs": ["urn:isoluce:trace:0412"]},
        {"stage_id": "r1", "kind": "result", "at": "2026-10-23T14:29:40Z", "attempt_ref": "x1", "observed": "succeeded",
         "basis": "target_response", "evidence_ref": "urn:isoluce:deploy:confirmation:0412"},
    ],
}

# ---- validate against the repository's schemas, and run the action-binding reference check
rec_schema = json.load(open(REPO / "standard/v5.0/schemas/decision-record.schema.json"))
att_schema = json.load(open(REPO / "extensions/action-binding/schemas/execution-evidence.schema.json"))
rec_errors = [e.message for e in Draft202012Validator(rec_schema).iter_errors(record)]
att_errors = [e.message for e in Draft202012Validator(att_schema).iter_errors(attachment)]
spec_ab = importlib.util.spec_from_file_location("ab", REPO / "extensions/action-binding/tests/run_checks.py")
ab = importlib.util.module_from_spec(spec_ab)
spec_ab.loader.exec_module(ab)
binding = ab.check_attachment(attachment, compact(record))
(HERE / "decision-record.json").write_bytes(compact(record))
(HERE / "action-binding-attachment.json").write_bytes(compact(attachment))
summary = {"record_schema_errors": rec_errors, "attachment_schema_errors": att_errors,
           "record_seal_hash": record["seal_hash"], "attachment_digest": sha256(compact(attachment)),
           "spec_digest": spec_digest,
           "binding_check": {k: (v["status"] if isinstance(v, dict) and "status" in v else v) for k, v in binding.items()}}
json.dump(summary, open(HERE / "summary.json", "w"), indent=1, ensure_ascii=False)
print(json.dumps(summary, indent=1, ensure_ascii=False)[:2500])
