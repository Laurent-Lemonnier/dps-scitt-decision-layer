#!/usr/bin/env python3
"""A verdict record over a signed decision chain, and a decision record over a verdict record: the decision layer
(Decision Provenance Standard, action binding 0.3.0 and signatures 0.2.0) and draft-wright-verdict-record-02, each
citing the other without a change to either text.

  A. Verdict over the chain. A refund of 120.00 EUR (the case of ../aer1-decision, without the AER-1 receipt): a
     decision record, the attachment as issued at the approval (A1), the attachment after execution (A2), the
     support lead's person_approval, the issuer's seals. An auditor who is neither the issuer nor the approver
     writes a verdict record (Wright, Section 2) on the claim "the specification executed equals the one the
     accountable person approved": evidence A1, A2 and the decision record's file, each by the SHA-256 of its exact
     bytes (Section 2.1, Section 7), each with the format that verifies it; rule executed-as-approved:v1, whose
     inputs are all bound to the evidence (Section 2.2); result executed_as_approved. A checker written from
     Wright's text (verdict.py) re-runs the rule: the Standard's action binding reference check over A2 and the
     record, the approved and attempted digests compared. The same checker over the chain where 150.00 EUR was
     executed: a verdict stating not_as_approved is released; one stating executed_as_approved is refused.
  B. Decision over a verdict. The support lead closes the refund case on the strength of the verdict: a second
     decision record whose specification names the verdict record by the digest of its bytes (input_version_refs,
     the shape of ../plan-checkpoint), approved and executed, verified by the Standard's checks; the joins say the
     verdict cited is the one held and released, about this chain, before the decision.
  C. Supersession. The decision record is corrected (DPS: a new record, supersedes = the old decision_id; the
     attachments re-sealed for it; the approved specification unchanged). The auditor writes version 2 of the
     verdict, supersedes = the digest of version 1 (Wright, Section 6). Both remain checkable; the joins say which
     pair is current and that the earlier decision over version 1 is now a citation of a superseded record, which
     Wright's Appendix B leaves open.

Synthetic data, three test keys (approver, issuer, auditor), fixed times; deterministic output.
"""
import base64
import copy
import importlib.util
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PR = load("plan_run_build", HERE.parent / "plan-run" / "build.py")      # the DPS builders and the Standard's checks
V = load("verdict", HERE / "verdict.py")                                 # the checker written from Wright's text
AB, SIG, REPO = PR.AB, PR.SIG, PR.REPO
sha256, compact, b64, raw_public, key_from_seed = PR.sha256, PR.compact, PR.b64, PR.raw_public, PR.key_from_seed
DIMENSIONS = PR.DIMENSIONS

STANDARD_COMMIT = (HERE.parent / "aqta" / "approval-record" / "DPS_STANDARD_COMMIT").read_text().strip()
STANDARD_TREE = f"https://github.com/decision-provenance-standard/standard/tree/{STANDARD_COMMIT}"
FMT_ATTACHMENT = STANDARD_TREE + "/extensions/action-binding"       # Section 7: a URI naming the item's specification
FMT_RECORD = STANDARD_TREE + "/standard/v5.0"
FMT_VERDICT = V.VERSION
RULE = "https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/tree/main/interop/verdict-record#executed-as-approved-v1"

approver_key = key_from_seed("dps-scitt-decision-layer verdict-record: support lead key (test only)")
issuer_key = key_from_seed("dps-scitt-decision-layer verdict-record: issuer seal key (test only)")
auditor_key = key_from_seed("dps-scitt-decision-layer verdict-record: auditor key (test only)")
other_key = key_from_seed("dps-scitt-decision-layer verdict-record: a key of nobody (test only)")
APPROVER, APPROVER_KEY_REF = "support-lead-1", "support-lead-1-key-1"
ISSUER, ISSUER_KEY_REF = "Example Merchant", "example-merchant-seal-1"
AUDITOR, AUDITOR_KEY_REF = "audit.example", "audit-example-key-1"
MERCHANT = "urn:example:payments:merchant-7"
RUN = "urn:example:refund-request:8812-1"

refund_policy = {"policy_id": "urn:example:policy:refunds", "version": "2026-10-01",
                 "applies_to": {"operation": "payments.refund.create", "target": MERCHANT},
                 "approvers": [{"actor_ref": APPROVER, "role": "support lead"}],
                 "limits": {"max_amount_minor_without_finance": 50000}, "single_use": True, "max_approval_age_seconds": 1800}
POLICY_BYTES = compact(refund_policy)
POLICY_VERSION = "sha256:" + sha256(POLICY_BYTES)
POLICY_REF = refund_policy["policy_id"] + "#" + refund_policy["version"]

T = {"proposal": "2026-11-06T09:00:00Z", "review": "2026-11-06T09:03:00Z", "approval": "2026-11-06T09:05:00Z",
     "sealed_a1": "2026-11-06T09:06:00Z", "request": "2026-11-06T09:08:00Z", "recheck": "2026-11-06T09:08:05Z",
     "attempt": "2026-11-06T09:08:10Z", "result": "2026-11-06T09:08:20Z", "closed": "2026-11-06T09:20:00Z",
     "sealed_a2": "2026-11-06T09:21:00Z", "valid_until": "2026-11-06T09:35:00Z",
     "verdict_1": "2026-11-06T10:00:00.000000Z", "intake_1": "2026-11-06T10:05:00.000000Z",
     # part B: the case closed on the verdict
     "b_proposal": "2026-11-06T10:10:00Z", "b_review": "2026-11-06T10:12:00Z", "b_approval": "2026-11-06T10:14:00Z",
     "b_request": "2026-11-06T10:15:00Z", "b_recheck": "2026-11-06T10:15:05Z", "b_attempt": "2026-11-06T10:15:10Z",
     "b_result": "2026-11-06T10:15:20Z", "b_closed": "2026-11-06T10:20:00Z", "b_sealed": "2026-11-06T10:21:00Z",
     "b_valid_until": "2026-11-06T10:45:00Z",
     # part C: the record corrected, the attachments re-sealed, version 2 of the verdict
     "c_corrected": "2026-11-06T11:00:00Z", "c_sealed_a1": "2026-11-06T11:01:00Z", "c_sealed_a2": "2026-11-06T11:02:00Z",
     "verdict_2": "2026-11-06T11:30:00.000000Z", "intake_2": "2026-11-06T11:35:00.000000Z"}


def spec_of(amount_minor):
    return {"operation": "payments.refund.create", "target": MERCHANT,
            "parameters": {"order_ref": "urn:example:order:8812", "amount_minor": amount_minor, "currency": "EUR",
                           "reason": "duplicate charge of 2026-11-02"},
            "input_version_refs": ["urn:example:ticket:4410"], "policy_version": POLICY_VERSION, "valid_until": T["valid_until"]}


def spec_entry(spec):
    sb = compact(spec)
    return {"spec_digest": sha256(sb), "representation": {"kind": "original_bytes", "media_type": "application/json"},
            "content": {"availability": "available", "bytes_b64": b64(sb)},
            "summary": {"operation": spec["operation"], "target": spec["target"], "policy_version": spec["policy_version"],
                        "input_version_refs": spec["input_version_refs"]}}


def view_of(spec):
    p = spec["parameters"]
    return (f"Refund order {p['order_ref']}: {p['amount_minor'] // 100}.{p['amount_minor'] % 100:02d} {p['currency']}, reason: {p['reason']}\n"
            f"merchant {spec['target']}; ticket urn:example:ticket:4410\npolicy {POLICY_REF} ({POLICY_VERSION})\n"
            f"valid until {spec['valid_until']}\n").encode()


def seal(att, key, key_ref, sealed_at):
    att["issuer_signature"] = {"algorithm": "Ed25519", "key_ref": key_ref, "signed_bytes_ref": "dps-signatures 0.2.0 organisation_seal",
                               "sealed_at": sealed_at, "value_b64": "A" * 88}
    att["issuer_signature"]["value_b64"] = b64(key.sign(SIG.seal_signed_bytes(AB.seal_assertion(att))))
    return att


def sealed_record(record):
    record["seal_hash"] = "0" * 64
    record["seal_hash"] = sha256(compact(record))
    return record


def refund_record(decision_id, corrected=False):
    """The decision record of the refund (Core, schema-valid). corrected=True: the same decision, re-issued with the
    inputs named in full and supersedes = the earlier decision_id; the approval and the specification unchanged."""
    record = json.loads(PR.TEMPLATE.read_bytes())
    record.update({
        "decision_id": decision_id, "created_at": T["c_corrected"] if corrected else T["proposal"], "charter_id": "CH-EXAMPLE-SUPPORT-1",
        "record_type": "decision", "record_state": "closed", "dispatch_mode": "mode-1-with-embedded-mode-2-summary",
        "altitude": "individual-professional", "decision_class": "customer-refund",
        "consent_posture": {"posture_class": "the customer's ticket and the order's payment record; no other data read"},
        "decision_statement": "Refund 120.00 EUR on order 8812 for the duplicate charge of 2 November 2026, under the refunds "
                              "policy of 1 October 2026.",
        "context_at_decision": "The support agent proposed the refund from ticket 4410; the support lead reviewed the call as "
                               "rendered and approved it as shown.",
        "options_considered": ["Refund now (chosen): duplicate charge confirmed, amount under the support lead's limit.",
                               "Ask finance first: the customer waits three days for 120.00 EUR.",
                               "Refuse: no ground, the charge is a duplicate."],
        "required_inputs_used": (["ticket urn:example:ticket:4410", "payment record of order 8812 (two captures of 120.00 EUR on 2 November 2026)",
                                  "refunds policy 2026-10-01"] if corrected else
                                 ["ticket urn:example:ticket:4410", "refunds policy 2026-10-01"]),
        "assumptions_depended_on": ["The second capture of 2 November 2026 is a duplicate and not a second order."],
        "success_criteria": ["One refund of 120.00 EUR, and no second one for the same charge."],
        "re_decision_trigger": "A second refund request for the same order.",
        "accountable_owner": {"full_name": "Support Lead One", "role": "Support lead", "employer": ISSUER},
        "affirmation_record": {"timestamp": T["approval"], "actor_identity": APPROVER,
                               "method": "Ed25519 signature over the DPS person_approval assertion"},
        "accountable_owner_signoff": {"signed_by": APPROVER, "signed_at": T["closed"]},
        "review_log": [{"reviewer": APPROVER, "reviewed_at": T["approval"], "outcome": "approved"}],
        "closed_at": T["c_corrected"] if corrected else T["closed"], "record_location": f"urn:example:decision-records:{decision_id}",
        "supersedes": "DR-2026-11068" if corrected else None,
        "drafting_authority": {"deployer_role_pointer": "urn:example:role:support-drafting", "system_name": "support-agent", "version": "5"},
    })
    record["mode_classification_attestation"].update({
        "attestor_full_name": "Support Lead One", "attestor_role_title": "Support lead", "attestor_employer": ISSUER,
        "attestation_timestamp": T["c_corrected"] if corrected else T["closed"], "attestor_capacity": "employee",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 summary "
                                   "under charter CH-EXAMPLE-SUPPORT-1: the support agent (support-agent, version 5) proposed the "
                                   "refund from the ticket; I reviewed the call as rendered, approved it as shown, and I am "
                                   "accountable for this decision." + (" This record corrects DR-2026-11068, whose list of inputs "
                                   "left out the payment record read; the decision and its approval are unchanged." if corrected else "")})
    return sealed_record(record)


def attachments(record, approved, executed=None, sealed=(T["sealed_a1"], T["sealed_a2"])):
    """A1 as issued at the approval; A2 after execution. executed: a specification executed instead of the approved
    one (the mismatch of part A); A2 then carries both and its request and attempt cite the executed one."""
    did = record["decision_id"]
    sd = sha256(compact(approved))
    view = view_of(approved)
    head = [
        {"stage_id": "p0", "kind": "proposal", "at": T["proposal"], "origin": "ai", "spec_digest": sd,
         "deployer_role_pointer": "urn:example:role:support-drafting", "system_name": "support-agent", "version": "5"},
        {"stage_id": "v0", "kind": "review", "at": T["review"], "reviewer_ref": APPROVER, "shown_spec_digest": sd, "proposal_ref": "p0",
         "shown_view_ref": "urn:example:support-console:view:4410", "shown_view_digest": sha256(view)},
        {"stage_id": "o0", "kind": "outcome", "at": T["approval"], "review_ref": "v0", "outcome": "approved", "actor_ref": APPROVER,
         "method": "Ed25519 signature over the DPS person_approval assertion", "approved_spec_digest": sd, "request_limit": 1,
         "authority": {"authority_ref": POLICY_REF},
         "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": T["approval"], "text_ref": "urn:example:rationale:4410"},
         "core_ref": {"field": "review_log", "index": 0}}]
    a1 = seal({"profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": did,
               "action_specifications": [spec_entry(approved)], "stages": copy.deepcopy(head)}, issuer_key, ISSUER_KEY_REF, sealed[0])
    xd = sha256(compact(executed)) if executed else sd
    tail = [
        {"stage_id": "q0", "kind": "request", "at": T["request"], "request_id": RUN, "authorised_by": "o0", "spec_digest": xd,
         "requested_by": "urn:example:service:support-agent"},
        {"stage_id": "c0", "kind": "recheck", "at": T["recheck"], "request_ref": "q0", "result": "authorised", "authority_source_ref": POLICY_REF},
        {"stage_id": "x0", "kind": "attempt", "at": T["attempt"], "request_ref": "q0", "recheck_ref": "c0", "spec_digest": xd,
         "executor_ref": "urn:example:agent-runtime:3.1", "trace_refs": [RUN]},
        {"stage_id": "r0", "kind": "result", "at": T["result"], "attempt_ref": "x0", "observed": "succeeded", "basis": "executor_observation",
         "evidence_ref": "urn:example:payments:refund:R-55120"}]
    specs = [spec_entry(approved)] + ([spec_entry(executed)] if executed else [])
    a2 = seal({"profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": did,
               "action_specifications": specs, "stages": copy.deepcopy(head) + tail}, issuer_key, ISSUER_KEY_REF, sealed[1])
    ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval", "decision_id": did, "stage_id": "o0",
          "outcome": "approved", "shown_spec_digest": sd, "shown_view_digest": sha256(view), "approved_spec_digest": sd,
          "signed_at": T["approval"], "signature": {"algorithm": "Ed25519", "key_ref": APPROVER_KEY_REF, "value_b64": ""}}
    ps["signature"]["value_b64"] = b64(approver_key.sign(SIG.person_signed_bytes(ps)))
    return a1, a2, {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps]}


TRUST = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0", "policy_ref": "urn:example:trust-policy:verifier-1",
         "tsas": [], "checkpoint_sources": [],
         "keys": [{"key_ref": APPROVER_KEY_REF, "holder": APPROVER, "role": "person", "algorithm": "Ed25519",
                   "public_key_hex": raw_public(approver_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                   "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:people"},
                  {"key_ref": ISSUER_KEY_REF, "holder": ISSUER, "role": "organisation", "algorithm": "Ed25519",
                   "public_key_hex": raw_public(issuer_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                   "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:organisations"}]}


# ---------------------------------------------------------------- the checker's own inputs: policy, anchors, format rules, rule

POLICY = {"judgement_kinds": ["model-decision"], "formats": [FMT_ATTACHMENT, FMT_RECORD, FMT_VERDICT],
          "citation_depth": 1, "inputs_from_evidence_only": True}


def anchors(intake):
    """The checker's trust anchors: the auditor's key (writer -> key_ref -> public key), the DPS trust policy the
    format rules read, and the checker's own intake times of the record bytes it was handed (upper time bounds)."""
    return {"writers": {AUDITOR: {AUDITOR_KEY_REF: raw_public(auditor_key).hex()}}, "dps_trust_policy": TRUST, "intake": intake}


def _schema_errors(path, doc):
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.exceptions import NoSuchResource
    from referencing.jsonschema import DRAFT202012

    def local(uri):
        hits = [p for p in REPO.rglob(uri.rsplit("/", 1)[-1]) if ".git" not in p.parts]
        if not hits:
            raise NoSuchResource(ref=uri)
        return Resource.from_contents(json.loads(hits[0].read_text()), default_specification=DRAFT202012)
    return [e.message[:160] for e in Draft202012Validator(json.loads((REPO / path).read_text()), registry=Registry(retrieve=local)).iter_errors(doc)]


def format_attachment(raw, items, anch):
    """The format rules this checker holds for an action-binding attachment (Wright Section 4.3 step 2, 'verified by
    the rules of the format its entry names'): strict JSON; schema-valid; every specification digest recomputes
    from the bytes carried; the issuer's seal verifies under the trust policy the checker holds. The binding
    dimensions (what was requested against what was approved, the recheck, the observed result) are not format
    rules here: they are what the rule of step 3 re-derives. Gives no upper time bound (the seal's time is the
    issuer's statement)."""
    try:
        att = AB.strict_json(raw)
    except ValueError as e:
        return False, f"not strict JSON: {e}", None
    errs = _schema_errors("extensions/action-binding/schemas/execution-evidence.schema.json", att)
    if errs:
        return False, "schema: " + errs[0], None
    got = AB.check_attachment(att)
    if got["specification_digests"][0] != "verified":
        return False, "a specification digest does not recompute", None
    rep = AB.reference_report([att], {}, anch["dps_trust_policy"], None)
    if rep["results"][0]["issuer_signature"].get("status") != "verified":
        return False, "the issuer's seal does not verify under the trust policy held", None
    return True, None, None


def format_record(raw, items, anch):
    """The format rules for a decision record file: strict JSON, schema-valid, seal_hash recomputes over the
    record with seal_hash zeroed (the Standard's rule, as the cases of this repository apply it)."""
    try:
        rec = AB.strict_json(raw)
    except ValueError as e:
        return False, f"not strict JSON: {e}", None
    errs = _schema_errors("standard/v5.0/schemas/decision-record.schema.json", rec)
    if errs:
        return False, "schema: " + errs[0], None
    if rec.get("seal_hash") != sha256(compact({**rec, "seal_hash": "0" * 64})):
        return False, "seal_hash does not recompute", None
    return True, None, None


FORMATS = {FMT_ATTACHMENT: format_attachment, FMT_RECORD: format_record}


def rule_executed_as_approved(inputs):
    """Rule executed-as-approved:v1, as this case specifies it (README, 'The rule'). Inputs: approval (the attachment
    as issued at the approval, whole), attachment (the attachment after execution, whole), record (the decision
    record, whole), approved_spec_digest (string), attempted_spec_digest (string). Result "executed_as_approved"
    when: the Standard's action binding reference check over attachment and record reports every one of its eight
    dimensions verified; the approval's stages are the first stages of attachment, unchanged, for the same
    decision_id; attachment has exactly one attempt, whose specification digest equals the approved one, and
    approved_spec_digest equals attempted_spec_digest; the result stage observes succeeded. Otherwise
    "not_as_approved"."""
    a1, a2, rec = inputs["approval"], inputs["attachment"], inputs["record"]
    try:
        got = AB.check_attachment(a2, compact(rec))
    except Exception:
        return "not_as_approved"
    dims = all(got[d][0] == "verified" for d in DIMENSIONS)
    same_chain = (a1.get("decision_id") == a2.get("decision_id") == rec.get("decision_id")
                  and a2.get("stages", [])[:len(a1.get("stages", []))] == a1.get("stages", []))
    outcomes = [s for s in a1.get("stages", []) if s.get("kind") == "outcome" and s.get("outcome") == "approved"]
    attempts = [s for s in a2.get("stages", []) if s.get("kind") == "attempt"]
    results = [s for s in a2.get("stages", []) if s.get("kind") == "result"]
    ok = (dims and same_chain and len(outcomes) == 1 and len(attempts) == 1
          and attempts[0].get("spec_digest") == outcomes[0].get("approved_spec_digest")
          and inputs["approved_spec_digest"] == inputs["attempted_spec_digest"] == attempts[0].get("spec_digest")
          and any(r.get("observed") == "succeeded" for r in results))
    return "executed_as_approved" if ok else "not_as_approved"


RULES = {RULE: {"inputs": {"approval": "object", "attachment": "object", "record": "object",
                           "approved_spec_digest": "string", "attempted_spec_digest": "string"},
                "run": rule_executed_as_approved}}


# ---------------------------------------------------------------- the verdict record (Wright Section 2) and its container (Section 3)

def verdict(a1_bytes, a2_bytes, record_bytes, result, *, version=1, supersedes=None, act_time=T["verdict_1"],
            attempt_index=5, key="dps/refund-8812/executed-as-approved", inputs=None, body_extra=None, kind="check-run", rule=RULE):
    """The record exactly as Section 2.2 lists it, in the canonical form of Section 2.1. The evidence: A1 (entry
    0), A2 (entry 1), the decision record's file (entry 2, Section 7: the record's own identity is its seal_hash,
    not the digest of its file, so the file is cited as an item of its own). Every rule input bound to evidence."""
    r = {"v": V.VERSION, "kind": kind, "key": key, "version": version, "supersedes": supersedes, "writer": AUDITOR,
         "actor": {"type": "system", "id": "audit-example-checker", "model": "none", "model_version": "0"},
         "act_time": act_time,
         "evidence": [{"sha256": sha256(a1_bytes), "format": FMT_ATTACHMENT},
                      {"sha256": sha256(a2_bytes), "format": FMT_ATTACHMENT},
                      {"sha256": sha256(record_bytes), "format": FMT_RECORD}],
         "check": {"rule": rule,
                   "inputs": inputs if inputs is not None else {
                       "approval": {"evidence": 0, "pointer": ""}, "attachment": {"evidence": 1, "pointer": ""},
                       "record": {"evidence": 2, "pointer": ""},
                       "approved_spec_digest": {"evidence": 0, "pointer": "/stages/2/approved_spec_digest"},
                       "attempted_spec_digest": {"evidence": 1, "pointer": f"/stages/{attempt_index}/spec_digest"}},
                   "result": result},
         "body": {"claim": {"text": "the specification executed for the refund of order 8812 equals the one the accountable "
                                    "person approved, in the decision chain cited"}, **(body_extra or {})}}
    return V.canonical_bytes(r)


def container(raw, key=auditor_key, key_ref=AUDITOR_KEY_REF, writer=AUDITOR):
    """Section 3's container, as this case stands it in: a detached Ed25519 signature over the exact bytes, naming
    the writer and the key. A SCITT Signed Statement with its Receipt would be the real one."""
    return {"kind": "detached-ed25519-signature", "record_sha256": sha256(raw), "writer": writer, "key_ref": key_ref,
            "algorithm": "Ed25519", "signature_b64": b64(key.sign(raw))}


# ---------------------------------------------------------------- part B: a decision record over the verdict

def closing_decision(verdict_bytes, verdict_result, refund_decision_id):
    """The support lead closes the refund case on the verdict: a decision record (Core) and its attachment (approved
    and executed), the specification naming the verdict record among its inputs by the digest of its bytes."""
    vd = sha256(verdict_bytes)
    spec = {"operation": "support.case.close", "target": "urn:example:support-case:8812",
            "parameters": {"refund_decision_id": refund_decision_id, "verdict_sha256": vd, "verdict_result": verdict_result,
                           "release_reserve_minor": 12000},
            "input_version_refs": [f"{FMT_VERDICT}:{vd}", "urn:example:ticket:4410"],
            "policy_version": POLICY_VERSION, "valid_until": T["b_valid_until"]}
    sb = compact(spec)
    sd = sha256(sb)
    view = (f"Close support case 8812 and release the reserve of 120.00 EUR\nverdict record {vd} ({FMT_VERDICT}): result {verdict_result}\n"
            f"refund decision {refund_decision_id}\npolicy {POLICY_REF} ({POLICY_VERSION})\n").encode()
    record = json.loads(PR.TEMPLATE.read_bytes())
    record.update({
        "decision_id": "DR-2026-11069", "created_at": T["b_proposal"], "charter_id": "CH-EXAMPLE-SUPPORT-1",
        "record_type": "decision", "record_state": "closed", "dispatch_mode": "mode-1-with-embedded-mode-2-summary",
        "altitude": "individual-professional", "decision_class": "customer-refund",
        "consent_posture": {"posture_class": "the verdict record and the refund's decision chain; no other data read"},
        "decision_statement": "Close support case 8812 and release the 120.00 EUR reserve, the auditor's verdict record stating "
                              "that the refund executed equals the one approved.",
        "context_at_decision": "The auditor's verdict record over the refund's decision chain was shown with its result; the "
                               "support agent proposed to close the case on it.",
        "options_considered": ["Close the case and release the reserve on the verdict (chosen).",
                               "Keep the reserve until month-end reconciliation: the verdict already re-derives what reconciliation would.",
                               "Close without citing the verdict: no trace of what the closure rested on."],
        "required_inputs_used": [f"verdict record {vd}", f"refund decision {refund_decision_id}", "refunds policy 2026-10-01"],
        "assumptions_depended_on": ["The verdict record's checker held the same chain bytes the support lead was shown."],
        "success_criteria": ["The case is closed once and the reserve released once."],
        "re_decision_trigger": "A later version of the verdict record, or a correction of the refund's decision record.",
        "accountable_owner": {"full_name": "Support Lead One", "role": "Support lead", "employer": ISSUER},
        "affirmation_record": {"timestamp": T["b_approval"], "actor_identity": APPROVER,
                               "method": "Ed25519 signature over the DPS person_approval assertion"},
        "accountable_owner_signoff": {"signed_by": APPROVER, "signed_at": T["b_closed"]},
        "review_log": [{"reviewer": APPROVER, "reviewed_at": T["b_approval"], "outcome": "approved"}],
        "closed_at": T["b_closed"], "record_location": "urn:example:decision-records:DR-2026-11069", "supersedes": None,
        "drafting_authority": {"deployer_role_pointer": "urn:example:role:support-drafting", "system_name": "support-agent", "version": "5"},
    })
    record["mode_classification_attestation"].update({
        "attestor_full_name": "Support Lead One", "attestor_role_title": "Support lead", "attestor_employer": ISSUER,
        "attestation_timestamp": T["b_closed"], "attestor_capacity": "employee",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 summary "
                                   "under charter CH-EXAMPLE-SUPPORT-1: the support agent proposed to close the case on the "
                                   "auditor's verdict record; I reviewed it as rendered, approved it as shown, and I am "
                                   "accountable for this decision."})
    sealed_record(record)
    did = record["decision_id"]
    stages = [
        {"stage_id": "p0", "kind": "proposal", "at": T["b_proposal"], "origin": "ai", "spec_digest": sd,
         "deployer_role_pointer": "urn:example:role:support-drafting", "system_name": "support-agent", "version": "5"},
        {"stage_id": "v0", "kind": "review", "at": T["b_review"], "reviewer_ref": APPROVER, "shown_spec_digest": sd, "proposal_ref": "p0",
         "shown_view_ref": "urn:example:support-console:view:8812-close", "shown_view_digest": sha256(view)},
        {"stage_id": "o0", "kind": "outcome", "at": T["b_approval"], "review_ref": "v0", "outcome": "approved", "actor_ref": APPROVER,
         "method": "Ed25519 signature over the DPS person_approval assertion", "approved_spec_digest": sd, "request_limit": 1,
         "authority": {"authority_ref": POLICY_REF},
         "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": T["b_approval"], "text_ref": "urn:example:rationale:8812-close"},
         "core_ref": {"field": "review_log", "index": 0}},
        {"stage_id": "q0", "kind": "request", "at": T["b_request"], "request_id": "urn:example:support-case:8812:close:1", "authorised_by": "o0",
         "spec_digest": sd, "requested_by": "urn:example:service:support-agent"},
        {"stage_id": "c0", "kind": "recheck", "at": T["b_recheck"], "request_ref": "q0", "result": "authorised", "authority_source_ref": POLICY_REF},
        {"stage_id": "x0", "kind": "attempt", "at": T["b_attempt"], "request_ref": "q0", "recheck_ref": "c0", "spec_digest": sd,
         "executor_ref": "urn:example:agent-runtime:3.1", "trace_refs": ["urn:example:support-case:8812:close:1"]},
        {"stage_id": "r0", "kind": "result", "at": T["b_result"], "attempt_ref": "x0", "observed": "succeeded", "basis": "executor_observation",
         "evidence_ref": "urn:example:support-case:8812:closed"}]
    att = seal({"profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": did,
                "action_specifications": [spec_entry(spec)], "stages": stages}, issuer_key, ISSUER_KEY_REF, T["b_sealed"])
    ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval", "decision_id": did, "stage_id": "o0",
          "outcome": "approved", "shown_spec_digest": sd, "shown_view_digest": sha256(view), "approved_spec_digest": sd,
          "signed_at": T["b_approval"], "signature": {"algorithm": "Ed25519", "key_ref": APPROVER_KEY_REF, "value_b64": ""}}
    ps["signature"]["value_b64"] = b64(approver_key.sign(SIG.person_signed_bytes(ps)))
    return {"record": record, "record_bytes": compact(record), "attachment": att, "attachment_bytes": compact(att),
            "sig_attachment": {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps]}, "spec": spec, "view": view.decode()}


# ---------------------------------------------------------------- the DPS checks, as the other cases run them

NOT_YET = ("authorisation_recheck", "observed_results")


def verify_dps(record_bytes, record, att, sig_att, executed=True):
    out = {}
    out["schema_errors"] = {"record": _schema_errors("standard/v5.0/schemas/decision-record.schema.json", record),
                            "attachment": _schema_errors("extensions/action-binding/schemas/execution-evidence.schema.json", att),
                            "signatures": _schema_errors("extensions/signatures/schemas/signatures-attachment.schema.json", sig_att)}
    ab = AB.check_attachment(att, record_bytes)
    out["dimensions"] = {d: ab[d][0] for d in DIMENSIONS}
    out["findings"] = {d: ab[d][1] for d in DIMENSIONS if ab[d][1]}
    rep = AB.reference_report([att], {record["decision_id"]: record_bytes}, TRUST, sig_att)
    out["issuer_seal"] = rep["results"][0]["issuer_signature"].get("status")
    _p, persons, _s, _t = SIG.run_context({"attachment": sig_att, "export": None, "policy": TRUST, "action_binding": {record["decision_id"]: att}})
    out["person_approvals_verified"] = sum(p["status"] == "verified" for p in persons)
    out["verified"] = (not any(out["schema_errors"].values())
                       and all(v == "verified" or (not executed and d in NOT_YET and v == "not_checked") for d, v in out["dimensions"].items())
                       and out["issuer_seal"] == "verified" and out["person_approvals_verified"] == len(persons) >= 1)
    return out


# ---------------------------------------------------------------- the build

def build():
    """Every part as data; a failing case changes one thing before assembly."""
    return {"approved_amount": 12000, "executed_amount": None,          # part A: None = executed as approved
            "verdict_result": "executed_as_approved", "verdict_kwargs": {},
            "container": "writer",                                      # writer | none | other_key
            "policy": copy.deepcopy(POLICY), "intake": {"1": T["intake_1"], "2": T["intake_2"]},
            "mutate_verdict_bytes": None,                               # a function over the verdict's bytes
            "mutate_a2_bytes": None,                                    # a function over A2's bytes after citation
            "b_cites": "verdict_1",                                     # verdict_1 | altered
            "c_supersedes": "verdict_1",                                # verdict_1 | wrong | null
            "c_record": "corrected"}                                    # corrected | original


def assemble(b):
    art = {"standard_commit": STANDARD_COMMIT}
    # -- part A: the chain
    approved = spec_of(b["approved_amount"])
    executed = spec_of(b["executed_amount"]) if b["executed_amount"] else None
    record = refund_record("DR-2026-11068")
    a1, a2, sig = attachments(record, approved, executed)
    rb, a1b, a2b = compact(record), compact(a1), compact(a2)
    v1 = verdict(a1b, a2b, rb, b["verdict_result"], **b["verdict_kwargs"])
    if b["mutate_verdict_bytes"]:
        v1 = b["mutate_verdict_bytes"](v1)
    c1 = {"writer": container(v1), "none": None, "other_key": container(v1, other_key, AUDITOR_KEY_REF)}[b["container"]]
    a2_held = b["mutate_a2_bytes"](a2b) if b["mutate_a2_bytes"] else a2b
    art["A"] = {"record": record, "record_bytes": rb, "a1": a1, "a1_bytes": a1b, "a2": a2, "a2_bytes": a2b, "a2_held": a2_held,
                "sig_attachment": sig, "verdict_bytes": v1, "container": c1, "approved": approved, "executed": executed}
    # the same checker over the chain where 150.00 EUR was executed, the auditor stating what the re-run gives
    mrecord = record
    _m1, m2, _ms = attachments(mrecord, approved, spec_of(15000))
    m2b = compact(m2)
    vm = verdict(a1b, m2b, rb, "not_as_approved", key="dps/refund-8812/executed-as-approved/mismatch-stated")
    art["A_mismatch"] = {"a2": m2, "a2_bytes": m2b, "verdict_bytes": vm, "container": container(vm)}
    # -- part B: the closing decision over verdict 1 (or over an altered copy, in a failing case)
    cited = v1 if b["b_cites"] == "verdict_1" else verdict(a1b, a2b, rb, b["verdict_result"], act_time="2026-11-06T10:00:01.000000Z")
    art["B"] = closing_decision(cited, b["verdict_result"], record["decision_id"])
    # -- part C: the record corrected, the attachments re-sealed, version 2 of the verdict
    crecord = refund_record("DR-2026-110681", corrected=True) if b["c_record"] == "corrected" else record
    ca1, ca2, csig = attachments(crecord, approved, None, sealed=(T["c_sealed_a1"], T["c_sealed_a2"]))
    crb, ca1b, ca2b = compact(crecord), compact(ca1), compact(ca2)
    sup = {"verdict_1": sha256(v1), "wrong": "7" * 64, "null": None}[b["c_supersedes"]]
    v2 = verdict(ca1b, ca2b, crb, "executed_as_approved", version=2, supersedes=sup, act_time=T["verdict_2"])
    art["C"] = {"record": crecord, "record_bytes": crb, "a1": ca1, "a1_bytes": ca1b, "a2": ca2, "a2_bytes": ca2b, "sig_attachment": csig,
                "verdict_bytes": v2, "container": container(v2)}
    art["policy"], art["intake"] = b["policy"], {sha256(v1): b["intake"]["1"], sha256(vm): b["intake"]["1"], sha256(v2): b["intake"]["2"]}
    return art


def items_of(art):
    """What the presenter hands the checker: every evidence item by its digest, with a container where the item is
    a verdict record."""
    A, C = art["A"], art["C"]
    held = {}
    for raw in (A["a1_bytes"], A["a2_held"], A["record_bytes"], art["A_mismatch"]["a2_bytes"], C["a1_bytes"], C["a2_bytes"], C["record_bytes"]):
        held[sha256(raw)] = (raw, None)
    for part in (A, art["A_mismatch"], C):
        held[sha256(part["verdict_bytes"])] = (part["verdict_bytes"], part["container"])
    return held


def verify(art):
    A, B, C = art["A"], art["B"], art["C"]
    checker = V.Checker(art["policy"], anchors(art["intake"]), RULES, FORMATS)
    items = items_of(art)
    r = {"standard_commit": art["standard_commit"], "checker_inputs": checker.own_inputs()}
    # the DPS side, natively
    r["dps"] = {"A_approval_A1": verify_dps(A["record_bytes"], A["record"], A["a1"], A["sig_attachment"], executed=False),
                "A_executed_A2": verify_dps(A["record_bytes"], A["record"], A["a2"], A["sig_attachment"]),
                "B_closing": verify_dps(B["record_bytes"], B["record"], B["attachment"], B["sig_attachment"]),
                "C_corrected_A1": verify_dps(C["record_bytes"], C["record"], C["a1"], C["sig_attachment"], executed=False),
                "C_corrected_A2": verify_dps(C["record_bytes"], C["record"], C["a2"], C["sig_attachment"])}
    # the verdict records, by the checker written from Wright's text
    r["verdict"] = {"A_version_1": checker.check(A["verdict_bytes"], items, A["container"]),
                    "A_mismatch_stated": checker.check(art["A_mismatch"]["verdict_bytes"], items, art["A_mismatch"]["container"]),
                    "C_version_2": checker.check(C["verdict_bytes"], items, C["container"])}
    r["report_wording"] = {k: V.report_wording_ok(v) for k, v in r["verdict"].items()}
    r["joins"] = joins(art, r)
    r["reported_not_joined"] = reported(art, r)
    r["wright_appendix_a"] = appendix_a()
    r["all_verified"] = (all(d["verified"] for d in r["dps"].values())
                         and r["verdict"]["A_version_1"]["state"] == "released"
                         and r["verdict"]["A_mismatch_stated"]["state"] == "released"
                         and r["verdict"]["C_version_2"]["state"] == "released"
                         and all(r["report_wording"].values())
                         and all(v is True for v in r["joins"].values())
                         and all(v is True for k, v in r["wright_appendix_a"].items() if k.endswith("_digest_agrees")))
    return r


# ---------------------------------------------------------------- Wright's Appendix A, from the text: the canonical form against his digests

A1_CLAIM = b'{"made_by":"builder.example","statement":"Release 2.1 of example-service passed its acceptance suite."}'
A1_RECORD = {"act_time": "2026-10-23T10:00:00.000000Z", "actor": {"id": "checker-7", "model": "example-model", "model_version": "1", "type": "system"},
             "body": {"claim": {"ref": {"format": "application/json", "sha256": "f4747f1fa1ad63eaad90e41b587794f8f5c82f9215b9a8e23a6c204edabc7d48"}}},
             "check": {"result": "supported", "rule": "judgement"},
             "evidence": [{"format": "application/json", "sha256": "f4747f1fa1ad63eaad90e41b587794f8f5c82f9215b9a8e23a6c204edabc7d48"},
                          {"format": "https://datatracker.ietf.org/doc/draft-gruszka-signed-evaluation-receipts/",
                           "sha256": "0c964f45c450a0253fc09eb2316e6ad271944be201c46ebf2c5d40e529f35306"}],
             "key": "verdict-0001", "kind": "model-decision", "supersedes": None, "v": V.VERSION, "version": 1, "writer": "verifier.example"}
A2_PARENT = b'{"expires_at":1793463600,"granted_scopes":["mcp:tool:erp.ledger.read","mcp:max_rows:100"],"issued_at":1793460000}'
A2_CHILD = (b'{"expires_at":1793463600,"granted_scopes":["mcp:tool:erp.ledger.read"],"issued_at":1793460000,'
            b'"parent_record_hash":"1336337e88adc67853b80b4998363210dc5c0797cc7b7c722128cecc56a38c14"}')
A2_FORMAT = "https://datatracker.ietf.org/doc/draft-durga-agenttrust-trace-verification/"
A2_RULE = "urn:example:verdict-record:rule:hop-continuity-attenuation:v1"
A2_RECORD = {"act_time": "2026-10-31T18:00:00.000000Z", "actor": {"id": "agenttrust-trace-checker", "model": "none", "model_version": "0", "type": "system"},
             "body": {"claim": {"text": "hop[1] preserves SHA-256 parent_record_hash continuity and monotonic scope attenuation from hop[0]"}},
             "check": {"inputs": {"child_scopes": {"evidence": 1, "pointer": "/granted_scopes"}, "parent_digest": {"evidence": 0},
                                  "parent_hash": {"evidence": 1, "pointer": "/parent_record_hash"}, "parent_scopes": {"evidence": 0, "pointer": "/granted_scopes"}},
                       "result": "attenuated_and_linked", "rule": A2_RULE},
             "evidence": [{"format": A2_FORMAT, "sha256": "1336337e88adc67853b80b4998363210dc5c0797cc7b7c722128cecc56a38c14"},
                          {"format": A2_FORMAT, "sha256": "8886795d4403b5cd8820eb813ee0724f1d6d5d383124364b09cdc5020639e00c"}],
             "key": "agenttrust/trace/hop-1", "kind": "check-run", "supersedes": None, "v": V.VERSION, "version": 1, "writer": "agenttrust-reference-verifier"}


def rule_hop_continuity(i):
    """The rule of Wright's Appendix A.2, as his text specifies it."""
    linked = i["parent_hash"] == i["parent_digest"] and all(s in i["parent_scopes"] for s in i["child_scopes"])
    return "attenuated_and_linked" if linked else "not_attenuated_or_not_linked"


def appendix_a():
    """The checker's canonical form against the digests Wright publishes in Appendix A (the only vectors his text
    gives), and his A.2 record run through the checker with a format rule for the hops that only parses them, which
    his Appendix B says is not yet defined: the text predicts released for such a checker, held for one that
    requires the signature the hop format requires. The A.2 record's container is synthetic here (a test key)."""
    out = {"A.1_claim_digest_agrees": sha256(A1_CLAIM) == A1_RECORD["evidence"][0]["sha256"],
           "A.1_record_digest_agrees": V.sha256(V.canonical_bytes(A1_RECORD)) == "2a85c94e39c56f50185b3b69b8f56026946364631799774a83b4f93399841c45",
           "A.2_hop_digests_agree": sha256(A2_PARENT) == A2_RECORD["evidence"][0]["sha256"] and sha256(A2_CHILD) == A2_RECORD["evidence"][1]["sha256"],
           "A.2_record_digest_agrees": V.sha256(V.canonical_bytes(A2_RECORD)) == "62017940a8ddddd5ddd7ff46c8ff2a6ce79dfcccb775d767b8dff8db0ebe19ed"}
    raw = V.canonical_bytes(A2_RECORD)
    items = {sha256(A2_PARENT): (A2_PARENT, None), sha256(A2_CHILD): (A2_CHILD, None)}
    writer_key = key_from_seed("dps-scitt-decision-layer verdict-record: a stand-in key for Wright's A.2 writer (test only)")
    anch = {"writers": {A2_RECORD["writer"]: {"k1": raw_public(writer_key).hex()}}, "intake": {sha256(raw): "2026-11-06T00:00:00.000000Z"}}
    cont = container(raw, writer_key, "k1", A2_RECORD["writer"])
    rules = {A2_RULE: {"inputs": {"parent_hash": "string", "parent_digest": "string", "parent_scopes": "array", "child_scopes": "array"}, "run": rule_hop_continuity}}

    def parse_only(raw, items, anch):
        try:
            json.loads(raw)
            return True, None, None
        except ValueError as e:
            return False, str(e), None

    def signature_required(raw, items, anch):
        return False, "the hop carries no signature, which its format requires", None
    pol = {"judgement_kinds": ["model-decision"], "formats": [A2_FORMAT], "citation_depth": 1, "inputs_from_evidence_only": True}
    out["A.2_under_a_parsing_only_hop_format"] = V.Checker(pol, anch, rules, {A2_FORMAT: parse_only}).check(raw, items, cont)["summary"]
    out["A.2_under_a_hop_format_requiring_the_signature"] = V.Checker(pol, anch, rules, {A2_FORMAT: signature_required}).check(raw, items, cont)["summary"]
    widened = A2_CHILD.replace(b'["mcp:tool:erp.ledger.read"]', b'["mcp:tool:erp.ledger.read","mcp:tool:erp.ledger.write"]')
    rec = dict(A2_RECORD, evidence=[A2_RECORD["evidence"][0], {"format": A2_FORMAT, "sha256": sha256(widened)}])
    raw_w = V.canonical_bytes(rec)
    anch_w = dict(anch, intake={sha256(raw_w): "2026-11-06T00:00:00.000000Z"})
    out["A.2_child_scopes_widened"] = V.Checker(pol, anch_w, rules, {A2_FORMAT: parse_only}).check(
        raw_w, {**items, sha256(widened): (widened, None)}, container(raw_w, writer_key, "k1", A2_RECORD["writer"]))["summary"]
    out["A.2_child_hop_not_held"] = V.Checker(pol, anch, rules, {A2_FORMAT: parse_only}).check(raw, {sha256(A2_PARENT): items[sha256(A2_PARENT)]}, cont)["summary"]
    return out


def joins(art, r):
    """What neither side's check says on its own."""
    A, B, C = art["A"], art["B"], art["C"]
    v1, v2 = json.loads(A["verdict_bytes"]), json.loads(C["verdict_bytes"])
    rep1, rep2 = r["verdict"]["A_version_1"], r["verdict"]["C_version_2"]
    j = {}
    # A
    j["A1. the verdict's evidence entries are the digests of the exact bytes of A1, A2 and the decision record's file held, and the "
      "record's file digest is not its seal_hash (Wright Section 7: the payload cited as an item of its own)"] = (
        [e["sha256"] for e in v1["evidence"]] == [sha256(A["a1_bytes"]), sha256(A["a2_bytes"]), sha256(A["record_bytes"])]
        and sha256(A["record_bytes"]) != A["record"]["seal_hash"])
    j["A2. the verdict's rule re-run by the checker gives the result the auditor stated, and that result is what the Standard's checks "
      "say natively (every dimension of A2 verified, the attempt's digest the approved one)"] = (
        rep1["steps"].get("3", {}).get("re_run_result") == v1["check"]["result"] == "executed_as_approved"
        and r["dps"]["A_executed_A2"]["verified"])
    j["A3. every rule input is bound to evidence, none read from body (Wright Section 2.2, Section 4.5): the checker's evidence-only "
      "policy ran step 3"] = (all(isinstance(w, dict) for w in v1["check"]["inputs"].values()) and rep1.get("body_inputs_read") == []
                              and rep1["steps"].get("3", {}).get("result") == "PASS")
    j["A4. over the chain where 150.00 EUR was executed for 120.00 approved, the auditor's verdict stating not_as_approved is "
      "released, and the Standard's action binding dimension fails on that A2"] = (
        r["verdict"]["A_mismatch_stated"]["state"] == "released"
        and AB.check_attachment(art["A_mismatch"]["a2"], A["record_bytes"])["action_binding"][0] == "failed")
    # B
    spec = B["spec"]
    vd = sha256(A["verdict_bytes"])
    j["B1. the closing decision's approved specification names the verdict record held by the digest of its bytes, in "
      "input_version_refs and in its parameters, and that record's state is released"] = (
        spec["parameters"]["verdict_sha256"] == vd and f"{FMT_VERDICT}:{vd}" in spec["input_version_refs"]
        and rep1["state"] == "released" and rep1["record_sha256"] == vd)
    j["B2. the verdict cited is about the chain the closing decision names: its evidence includes the file of the refund's decision "
      "record, whose decision_id the closing specification carries"] = (
        sha256(A["record_bytes"]) in [e["sha256"] for e in v1["evidence"]]
        and spec["parameters"]["refund_decision_id"] == A["record"]["decision_id"])
    j["B3. the result the support lead decided on equals the result the checker re-derived"] = (
        spec["parameters"]["verdict_result"] == rep1["steps"].get("3", {}).get("re_run_result"))
    rev = next(s for s in B["attachment"]["stages"] if s["kind"] == "review")
    j["B4. the verdict was reached (the issuer's act_time) and taken in by the checker (its upper time bound) before the closing "
      "decision was shown and approved"] = (rep1.get("upper_time_bound") is not None
                                           and v1["act_time"][:19] < rep1["upper_time_bound"][:19] < rev["at"][:19])
    # C
    j["C1. version 2 supersedes version 1 by the digest of its exact bytes, under the same key, one version later (Wright Section 6); "
      "both are released"] = (v2["supersedes"] == vd and v2["key"] == v1["key"] and v2["version"] == v1["version"] + 1
                              and rep1["state"] == rep2["state"] == "released")
    j["C2. version 2 cites the corrected decision record, which supersedes (DPS Core) the record version 1 cites: the current pair is "
      "(version 2, corrected record), the earlier pair (version 1, original record)"] = (
        sha256(C["record_bytes"]) in [e["sha256"] for e in v2["evidence"]] and C["record"]["supersedes"] == A["record"]["decision_id"]
        and sha256(A["record_bytes"]) in [e["sha256"] for e in v1["evidence"]] and C["record"]["decision_id"] != A["record"]["decision_id"])
    ps_a, ps_c = A["sig_attachment"]["person_signatures"][0], C["sig_attachment"]["person_signatures"][0]
    j["C3. the correction changed the record, not the action: the approved specification's digest and the view shown are the same in "
      "both pairs; the approver signed again for the corrected record (the person_approval names the decision_id), with the same "
      "key over the same specification and view digests"] = (
        C["a1"]["action_specifications"][0]["spec_digest"] == A["a1"]["action_specifications"][0]["spec_digest"]
        and ps_c["approved_spec_digest"] == ps_a["approved_spec_digest"] and ps_c["shown_view_digest"] == ps_a["shown_view_digest"]
        and ps_c["signature"]["key_ref"] == ps_a["signature"]["key_ref"] and ps_c["decision_id"] != ps_a["decision_id"]
        and ps_c["signature"]["value_b64"] != ps_a["signature"]["value_b64"])
    return j


def reported(art, r):
    """Statements the case reports without joining on them, because Wright's text leaves them open or the Standard
    does not define them."""
    A, B = art["A"], art["B"]
    v1 = json.loads(A["verdict_bytes"])
    return {"the closing decision (part B) cites version 1 of the verdict, which version 2 supersedes; Wright's Appendix B leaves open "
            "how a checker holding version 2 treats a citation of version 1, and Section 6 says the later version does not by itself "
            "change the state of the earlier one": {
                "closing_decision_cites": B["spec"]["parameters"]["verdict_sha256"], "superseded_by": sha256(art["C"]["verdict_bytes"]),
                "state_of_version_1_with_version_2_held": r["verdict"]["A_version_1"]["state"]},
            "supersedes is read by no step of Section 4.3: a version 2 naming a digest of nothing held would be released by the steps; "
            "this case joins on it (C1) outside the checker": True,
            "the rule re-derives nothing about the person: that the approver's person_approval verifies is the Standard's check "
            "(dps.*.person_approvals_verified), not a step of the verdict": r["dps"]["A_executed_A2"]["person_approvals_verified"]}


def write(out, art):
    out.mkdir(parents=True, exist_ok=True)
    A, B, C = art["A"], art["B"], art["C"]
    (out / "A-decision-record.json").write_bytes(A["record_bytes"])
    (out / "A-action-binding-attachment-A1.json").write_bytes(A["a1_bytes"])
    (out / "A-action-binding-attachment-A2.json").write_bytes(A["a2_bytes"])
    (out / "A-signatures-attachment.json").write_bytes(compact(A["sig_attachment"]))
    (out / "A-verdict-record-v1.json").write_bytes(A["verdict_bytes"])
    (out / "A-verdict-record-v1.container.json").write_text(json.dumps(A["container"], indent=1) + "\n")
    (out / "A-mismatch-action-binding-attachment-A2.json").write_bytes(art["A_mismatch"]["a2_bytes"])
    (out / "A-mismatch-verdict-record-stated.json").write_bytes(art["A_mismatch"]["verdict_bytes"])
    (out / "B-closing-decision-record.json").write_bytes(B["record_bytes"])
    (out / "B-closing-action-binding-attachment.json").write_bytes(B["attachment_bytes"])
    (out / "B-closing-signatures-attachment.json").write_bytes(compact(B["sig_attachment"]))
    (out / "B-closing-review-view.txt").write_text(B["view"])
    (out / "C-corrected-decision-record.json").write_bytes(C["record_bytes"])
    (out / "C-corrected-action-binding-attachment-A1.json").write_bytes(C["a1_bytes"])
    (out / "C-corrected-action-binding-attachment-A2.json").write_bytes(C["a2_bytes"])
    (out / "C-verdict-record-v2.json").write_bytes(C["verdict_bytes"])
    (out / "C-verdict-record-v2.container.json").write_text(json.dumps(C["container"], indent=1) + "\n")
    (out / "trust-policy.json").write_bytes(compact(TRUST))
    (out / "checker-policy.json").write_bytes(V.canonical_bytes(art["policy"]))
    (out / "checker-trust-anchors.json").write_bytes(V.canonical_bytes(anchors(art["intake"])))
    (out / "refund-policy.json").write_bytes(POLICY_BYTES)


if __name__ == "__main__":
    parts = build()
    art = assemble(parts)
    write(HERE / "out", art)
    results = verify(art)
    (HERE / "out" / "summary.json").write_text(json.dumps(results, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(results, ensure_ascii=False, indent=1))
    sys.exit(0 if results["all_verified"] else 1)
