#!/usr/bin/env python3
"""A decision record and an AER-1 receipt, composed as the author of draft-zambo-aer1 asked on 29 October 2026: the
Decision Provenance Standard's execution attempt carries the receipt's id and output_hash, and the receipt's
execution_context names the decision record. Built from existing texts and checked by existing code, nothing changed
in either:

  DPS     action binding 0.3.0 and signatures 0.2.0 at main 007f8c9: a refund proposed by an agent, shown to a support
          lead, approved under their signature, requested, rechecked, attempted and observed; the attachment sealed by the
          issuer, so the stage that cites the receipt is under a signature too;
  AER-1   draft-zambo-aer1-26, receipt schema 0.4: the payment gateway's receipt of the call, OBSERVED VIA GATEWAY, with
          metadata_hash, input_hash (Section 3.3) and execution_context (Section 3.2).

What binds, and what only points. The receipt's id and output_hash are in its metadata block, and the tool's inputs
and outputs are in the canonical bytes that output_hash commits to; so the DPS attempt citing id and output_hash is a
binding, and so is the receipt's recorded input carrying the DPS request_id (the executor sends it as the idempotency
key, as the action binding's executor rules say) and the approved values. execution_context is outside metadata_hash
(Section 3.2): it names the decision record, and the report shows that name as the producer's assertion, consistent or
not, never as a binding.

Verifies: the receipt with the AER-1 verifier written from the text (../aer1/aer1_verify_independent.py) and with the
kit's own reference checks (conformance.py: core, version and binding, reference-producer profile); the record, the
attachment, its seal and the person's signature with the Standard's reference checks; then the joins across them.
Synthetic data and test keys; never use them for anything real.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import sys
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = pathlib.Path(__file__).resolve().parent
REPO = pathlib.Path(os.environ.get("DPS_STANDARD") or (HERE / "dps-standard" if (HERE / "dps-standard").exists()
                                                       else "/root/claude-ops/dps/wt-007f8c9"))
KIT = pathlib.Path(os.environ.get("AER1_KIT") or HERE.parent / "aer1" / "zambo" / "base")
_candidates = [HERE.parents[1] / "examples/release-decision/decision-record.json",
               HERE.parents[2] / "exemple-release/decision-record.json"]
TEMPLATE = pathlib.Path(os.environ.get("DPS_RECORD_TEMPLATE") or next(p for p in _candidates if p.exists()))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AB = load("ab", REPO / "extensions/action-binding/tests/run_checks.py")
SIG = load("sig", REPO / "extensions/signatures/tests/run_checks.py")
AER = load("aer_independent", HERE.parent / "aer1" / "aer1_verify_independent.py")
KITC = load("aer_kit_conformance", KIT / "conformance.py") if (KIT / "conformance.py").exists() else None
_REF = KIT.parent / "aer1-verifier" / "aer1_verify.py"
KITREF = load("aer_kit_reference_verifier", _REF) if _REF.exists() else None


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def b64(b):
    return base64.b64encode(b).decode("ascii")


def key_from_seed(text):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(text.encode()).digest())


def raw_public(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def uuid4_from(text):
    """A deterministic id with the version 4 and RFC 4122 variant bits, so the receipt meets AER-1's strict tier."""
    return str(uuid.UUID(bytes=hashlib.sha256(text.encode()).digest()[:16], version=4))


approver_key = key_from_seed("dps-scitt-decision-layer aer1-decision: support lead key (test only)")
issuer_key = key_from_seed("dps-scitt-decision-layer aer1-decision: issuer seal key (test only)")
APPROVER, APPROVER_KEY, ISSUER_KEY = "support-lead-1", "support-lead-1-key-1", "example-merchant-seal-1"
MERCHANT = "urn:example:payments:merchant-7"
DECISION_ID = "DR-2026-1104"
REQUEST_ID = "urn:example:refund-request:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:example:aer1-decision:q1"))
RECEIPT_ID = uuid4_from("aer1-decision receipt 1")

refund_policy = {
    "policy_id": "urn:example:policy:refunds", "version": "2026-10-01",
    "applies_to": {"operation": "payments.refund.create", "target": MERCHANT},
    "approvers": [{"actor_ref": APPROVER, "role": "support lead"}],
    "limits": {"max_amount_minor_without_finance": 50000},
    "single_use": True, "max_approval_age_seconds": 1800,
    "recheck": "the agent runtime rechecks the approval before the call, on its own clock",
    "execution": "through the payment gateway, which issues an AER-1 receipt of every call; the request_id is sent as "
                 "the idempotency key",
}
policy_bytes = compact(refund_policy)
POLICY_VERSION = "sha256:" + sha256(policy_bytes)
POLICY_REF = refund_policy["policy_id"] + "#" + refund_policy["version"]
T = {"proposal": "2026-10-28T14:00:00Z", "review": "2026-10-28T14:05:00Z", "approval": "2026-10-28T14:07:00Z",
     "request": "2026-10-28T14:08:00Z", "recheck": "2026-10-28T14:08:05Z", "attempt": "2026-10-28T14:08:10Z",
     "receipt": "2026-10-28T14:08:11.250Z", "result": "2026-10-28T14:08:20Z", "closed": "2026-10-28T14:20:00Z",
     "sealed": "2026-10-28T14:21:00Z", "valid_until": "2026-10-28T14:37:00Z"}

PARAMS = {"order_ref": "urn:example:order:8812", "amount_minor": 12000, "currency": "EUR",
          "reason": "duplicate charge of 2026-11-02"}
SPEC = {"operation": "payments.refund.create", "target": MERCHANT, "parameters": PARAMS,
        "input_version_refs": ["urn:example:ticket:4410"], "policy_version": POLICY_VERSION, "valid_until": T["valid_until"]}
VIEW = ("Refund order urn:example:order:8812: 120.00 EUR, reason: duplicate charge of 2026-11-02\n"
        f"merchant {MERCHANT}; ticket urn:example:ticket:4410\npolicy {POLICY_REF} ({POLICY_VERSION})\n"
        f"valid until {T['valid_until']}\n").encode()


def make_record():
    record = json.loads(TEMPLATE.read_bytes())
    record.update({
        "decision_id": DECISION_ID, "created_at": T["proposal"], "charter_id": "CH-EXAMPLE-REFUNDS-1",
        "record_type": "decision", "record_state": "closed", "dispatch_mode": "mode-1-with-embedded-mode-2-summary",
        "altitude": "team-leader", "decision_class": "customer-refund",
        "consent_posture": {"posture_class": "contract performance: refund of a charge to the customer who paid it"},
        "decision_statement": "Refund 120.00 EUR on order 8812 for the duplicate charge of 2 November 2026, under the "
                              "refund policy of 1 October 2026, through the payment gateway.",
        "context_at_decision": "Ticket 4410 reports two identical charges; the support agent matched them and proposed "
                               "the refund of the second.",
        "options_considered": ["Refund the duplicate charge now (chosen).",
                               "Wait for the card network's automatic reversal: up to 10 days for the customer.",
                               "Offer a voucher: the customer asked for the money back."],
        "required_inputs_used": ["ticket 4410", "the two charges of order 8812 in the payment ledger"],
        "assumptions_depended_on": ["The second charge is a duplicate, not a second order."],
        "success_criteria": ["One refund of 120.00 EUR, and no second one for the same charge."],
        "accountable_owner": {"full_name": "Support Lead One", "role": "Support lead", "employer": "Example Merchant"},
        "re_decision_trigger": "The customer disputes the charge with the card issuer before the refund settles.",
        "drafting_authority": {"deployer_role_pointer": "urn:example:role:support-drafting",
                               "system_name": "support-agent", "version": "5"},
        "affirmation_record": {"timestamp": T["approval"], "actor_identity": APPROVER,
                               "method": "Ed25519 signature over the DPS person_approval assertion"},
        "accountable_owner_signoff": {"signed_by": APPROVER, "signed_at": T["closed"]},
        "review_log": [{"reviewer": APPROVER, "reviewed_at": T["approval"], "outcome": "approved"}],
        "closed_at": T["closed"], "record_location": f"urn:example:decision-records:{DECISION_ID}", "supersedes": None,
    })
    record["mode_classification_attestation"].update({
        "attestor_full_name": "Support Lead One", "attestor_role_title": "Support lead", "attestor_employer": "Example Merchant",
        "attestation_timestamp": T["closed"], "attestor_capacity": "employee",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 "
                                   "summary under charter CH-EXAMPLE-REFUNDS-1: the support agent (support-agent, version "
                                   "5) drafted the refund proposal from ticket 4410; I reviewed it as shown in the console, "
                                   "approved the specification whose digest the attachment names, and I am the accountable "
                                   "owner of this decision."})
    record["seal_hash"] = "0" * 64
    record["seal_hash"] = sha256(compact(record))
    return record


def make_receipt(record, *, inputs=None, outputs=None, created_at=None, pointer=True):
    """The gateway's AER-1 receipt of the refund call, in the kit's reference-producer layout (Section 7.1 canonical
    JSON of {caller, inputs, issuer_claims, outputs, receipt_schema_version, tool})."""
    inputs = inputs if inputs is not None else {**PARAMS, "idempotency_key": REQUEST_ID}
    outputs = outputs if outputs is not None else {"refund_ref": "urn:example:refund:R-55120", "status": "succeeded",
                                                   "amount_minor": PARAMS["amount_minor"], "currency": "EUR",
                                                   "idempotency_key": inputs.get("idempotency_key")}
    payload = {"caller": {"id": "sha256:" + sha256(b"example agent runtime 3.1"), "type": "service"},
               "inputs": inputs, "issuer_claims": {"provenance_class": "OBSERVED VIA GATEWAY"}, "outputs": outputs,
               "receipt_schema_version": "0.4", "tool": "payments_refund_create"}
    raw = AER.canonical_json(payload).encode("utf-8")
    tool = {"name": "payments_refund_create", "version": "1.2.0", "scope": "merchant"}
    rec = {"id": RECEIPT_ID, "receipt_schema_version": "0.4", "created_at": created_at or T["receipt"], "tool": tool,
           "provenance_class": "OBSERVED VIA GATEWAY", "canonical_byte_length": len(raw), "canonical_bytes": b64(raw),
           "output_hash": "sha256:" + sha256(raw), "verification_status": "verified",
           "input_hash": "sha256:" + sha256(AER.canonical_json(inputs).encode("utf-8"))}
    block = {"created_at": rec["created_at"], "id": rec["id"], "output_hash": rec["output_hash"],
             "provenance_class": rec["provenance_class"], "receipt_schema_version": "0.4",
             "tool": {"name": tool["name"], "scope": tool["scope"], "version": tool["version"]}}
    rec["metadata_hash"] = "sha256:" + sha256(AER.canonical_json(block).encode("utf-8"))
    rec["execution_context"] = {"framework": {"name": "example-agent-runtime", "version": "3.1"}, "source": MERCHANT,
                                "model": None}
    if pointer:  # Section 3.2: outside metadata_hash, the producer's assertion
        rec["execution_context"]["decision_record"] = {"decision_id": record["decision_id"],
                                                       "record_digest": "sha256:" + record["seal_hash"],
                                                       "request_id": REQUEST_ID}
    return rec


def make_attachment(record, receipt):
    spec_bytes = compact(SPEC)
    sd = sha256(spec_bytes)
    att = {
        "profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": record["decision_id"],
        "action_specifications": [{"spec_digest": sd, "representation": {"kind": "original_bytes", "media_type": "application/json"},
                                   "content": {"availability": "available", "bytes_b64": b64(spec_bytes)},
                                   "summary": {"operation": SPEC["operation"], "target": SPEC["target"],
                                               "policy_version": POLICY_VERSION, "input_version_refs": SPEC["input_version_refs"]}}],
        "stages": [
            {"stage_id": "p1", "kind": "proposal", "at": T["proposal"], "origin": "ai", "spec_digest": sd,
             "deployer_role_pointer": "urn:example:role:support-drafting", "system_name": "support-agent", "version": "5"},
            {"stage_id": "v1", "kind": "review", "at": T["review"], "reviewer_ref": APPROVER, "shown_spec_digest": sd,
             "proposal_ref": "p1", "shown_view_ref": "urn:example:support-console:view:4410", "shown_view_digest": sha256(VIEW)},
            {"stage_id": "o1", "kind": "outcome", "at": T["approval"], "review_ref": "v1", "outcome": "approved",
             "actor_ref": APPROVER, "method": "Ed25519 signature over the DPS person_approval assertion",
             "approved_spec_digest": sd, "request_limit": 1, "authority": {"authority_ref": POLICY_REF},
             "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": T["approval"],
                           "text_ref": "urn:example:rationale:4410"},
             "core_ref": {"field": "review_log", "index": 0}},
            {"stage_id": "q1", "kind": "request", "at": T["request"], "request_id": REQUEST_ID, "authorised_by": "o1",
             "spec_digest": sd, "requested_by": "urn:example:service:support-agent"},
            {"stage_id": "c1", "kind": "recheck", "at": T["recheck"], "request_ref": "q1", "result": "authorised",
             "authority_source_ref": POLICY_REF},
            {"stage_id": "x1", "kind": "attempt", "at": T["attempt"], "request_ref": "q1", "recheck_ref": "c1",
             "spec_digest": sd, "executor_ref": "urn:example:agent-runtime:3.1",
             "trace_refs": [f"urn:aer1:receipt:{receipt['id']}"]},
            {"stage_id": "r1", "kind": "result", "at": T["result"], "attempt_ref": "x1", "observed": "succeeded",
             "basis": "independent_observation",
             "evidence_ref": f"urn:aer1:receipt:{receipt['id']}#output_hash={receipt['output_hash']}"},
        ]}
    return att, spec_bytes, sd


def seal(att, key=issuer_key):
    """The issuer's seal of kind attachment (action binding item 7), over the attachment's bytes with the value
    replaced by A, built with the Standard's own functions."""
    att["issuer_signature"] = {"algorithm": "Ed25519", "key_ref": ISSUER_KEY,
                               "signed_bytes_ref": "dps-signatures 0.2.0 organisation_seal", "sealed_at": T["sealed"],
                               "value_b64": "A" * 88}
    att["issuer_signature"]["value_b64"] = b64(key.sign(SIG.seal_signed_bytes(AB.seal_assertion(att))))
    return att


def make_signatures(record, sd):
    ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval",
          "decision_id": record["decision_id"], "stage_id": "o1", "outcome": "approved", "shown_spec_digest": sd,
          "shown_view_digest": sha256(VIEW), "approved_spec_digest": sd, "signed_at": T["approval"],
          "signature": {"algorithm": "Ed25519", "key_ref": APPROVER_KEY, "value_b64": ""}}
    ps["signature"]["value_b64"] = b64(approver_key.sign(SIG.person_signed_bytes(ps)))
    return {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps]}


TRUST = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0", "policy_ref": "urn:example:trust-policy:verifier-1",
         "tsas": [], "checkpoint_sources": [],
         "keys": [{"key_ref": APPROVER_KEY, "holder": APPROVER, "role": "person", "algorithm": "Ed25519",
                   "public_key_hex": raw_public(approver_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                   "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:people"},
                  {"key_ref": ISSUER_KEY, "holder": "Example Merchant", "role": "organisation", "algorithm": "Ed25519",
                   "public_key_hex": raw_public(issuer_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                   "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:organisations"}]}


def build():
    record = make_record()
    receipt = make_receipt(record)
    att, spec_bytes, sd = make_attachment(record, receipt)
    seal(att)
    return {"record": record, "receipt": receipt, "attachment": att, "spec_digest": sd, "sig": make_signatures(record, sd)}


DIMENSIONS = ("specification_digests", "specification_statements", "record_statements", "action_binding",
              "stage_order", "authorisation_recheck", "observed_results", "rationale_provenance")


def schema_errors(art):
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.exceptions import NoSuchResource
    from referencing.jsonschema import DRAFT202012

    def local(uri):
        hits = [p for p in REPO.rglob(uri.rsplit("/", 1)[-1]) if ".git" not in p.parts]
        if not hits:
            raise NoSuchResource(ref=uri)
        return Resource.from_contents(json.loads(hits[0].read_text()), default_specification=DRAFT202012)
    registry = Registry(retrieve=local)
    docs = {"record": ("standard/v5.0/schemas/decision-record.schema.json", art["record"]),
            "attachment": ("extensions/action-binding/schemas/execution-evidence.schema.json", art["attachment"]),
            "signatures": ("extensions/signatures/schemas/signatures-attachment.schema.json", art["sig"]),
            "trust_policy": ("extensions/anchoring/schemas/trust-policy.schema.json", TRUST)}
    return {k: [e.message[:160] for e in Draft202012Validator(json.loads((REPO / p).read_text()), registry=registry).iter_errors(d)]
            for k, (p, d) in docs.items()}


def verify(art):
    r = {"schema_errors": schema_errors(art)}
    rec, att, record = art["receipt"], art["attachment"], art["record"]
    record_bytes = compact(record)
    # ---- AER-1, both verifiers
    verdict, reason, found = AER.structural(json.loads(json.dumps(rec)), strict_id=True)
    r["aer1_independent"] = {"verdict": verdict, "reason": reason,
                             "metadata_bound": bool(found) and not found.get("unbound", True),
                             "input_hash": "confirmed" if found and "input_hash" in rec else "not confirmed"}
    if KITC:
        core = KITC.check(json.loads(json.dumps(rec)))
        _legacy, binding = KITC.check_version_and_binding(json.loads(json.dumps(rec)))
        profile = KITC.check_reference_profile(json.loads(json.dumps(rec)))
        r["aer1_kit"] = {"core": core or "pass", "version_and_binding": binding or "pass", "reference_profile": profile or "pass"}
    else:
        r["aer1_kit"] = "not_checked: the conformance kit is not present"
    if KITREF:
        ok, checks, id_state, _id_verdict = KITREF.verify(json.loads(json.dumps(rec)))
        r["aer1_kit"] = r["aer1_kit"] if isinstance(r["aer1_kit"], dict) else {}
        r["aer1_kit"]["reference_verifier"] = "pass" if ok else [c["check"] + (": " + c["detail"] if c.get("detail") else "")
                                                                 for c in checks if not c.get("ok")]
        r["aer1_kit_id_state"] = id_state
    # ---- DPS: the attachment with its record, seal and the signatures beside
    report = AB.reference_report([att], {record["decision_id"]: record_bytes}, TRUST, art["sig"])
    res = report["results"][0]
    r["dps_trust_policy"] = report["trust_policy"]["status"]
    ab = AB.check_attachment(att, record_bytes)
    r["dps_action_binding"] = {d: ab[d][0] for d in DIMENSIONS}
    r["dps_action_binding_findings"] = {d: ab[d][1] for d in DIMENSIONS if ab[d][1]}
    r["dps_issuer_seal"] = {k: res["issuer_signature"].get(k, {}).get("status") if isinstance(res["issuer_signature"].get(k), dict)
                            else res["issuer_signature"].get(k) for k in ("status", "key_state", "holder", "attests")}
    _pol, persons, _s, _t = SIG.run_context({"attachment": art["sig"], "export": None, "policy": TRUST,
                                             "action_binding": {record["decision_id"]: att}})
    r["dps_person_approval"] = {k: persons[0][k]["status"] if isinstance(persons[0][k], dict) else persons[0][k]
                                for k in ("status", "signature", "subject", "key_state", "identity")}
    # ---- the joins
    r["joins"], r["execution_context_pointer"] = joins(art)
    r["all_verified"] = (not any(r["schema_errors"].values()) and r["aer1_independent"]["verdict"] == "pass"
                         and r["aer1_independent"]["metadata_bound"]
                         and (not KITC or all(v == "pass" for v in r["aer1_kit"].values()))
                         and r["dps_trust_policy"] == "verified" and all(v == "verified" for v in r["dps_action_binding"].values())
                         and r["dps_issuer_seal"]["status"] == "verified" and r["dps_person_approval"]["status"] == "verified"
                         and all(v is True for v in r["joins"].values()))
    return r


def joins(art):
    rec, att, record = art["receipt"], art["attachment"], art["record"]
    st = {s["stage_id"]: s for s in att["stages"]}
    x = next((s for s in att["stages"] if s["kind"] == "attempt"), {})
    res = next((s for s in att["stages"] if s["kind"] == "result" and s.get("attempt_ref") == x.get("stage_id")), {})
    q = st.get(x.get("request_ref"), {})
    spec = json.loads(base64.b64decode(next(s["content"]["bytes_b64"] for s in att["action_specifications"]
                                            if s["spec_digest"] == x.get("spec_digest"))))
    try:
        payload = json.loads(base64.b64decode(rec["canonical_bytes"]))
    except Exception:
        payload = {}
    inputs = dict(payload.get("inputs") or {})
    key = inputs.pop("idempotency_key", None)
    j = {
        "the DPS attempt cites the receipt by its id (in the receipt's metadata block)":
            f"urn:aer1:receipt:{rec.get('id')}" in x.get("trace_refs", []),
        "the DPS result's evidence names the receipt's output_hash, which commits to the canonical bytes":
            res.get("evidence_ref", "").endswith("#output_hash=" + str(rec.get("output_hash")))
            and res.get("evidence_ref", "").startswith(f"urn:aer1:receipt:{rec.get('id')}#"),
        "the receipt's recorded input is the approved specification's parameters, exactly (bound by output_hash)":
            inputs == spec.get("parameters"),
        "the receipt's recorded idempotency key is the DPS request_id (bound by output_hash)": key == q.get("request_id"),
        "the receipt's created_at falls between the DPS attempt and the observed result (issuer and gateway clocks)":
            AB.when(x["at"]) <= AB.when(rec["created_at"]) <= AB.when(res["at"]) if x and res else False,
    }
    ec = (rec.get("execution_context") or {}).get("decision_record")
    if ec is None:
        pointer = "absent (Section 3.2: an omitted member is unknown, never evidence of tampering)"
    elif ec.get("decision_id") == record["decision_id"] and ec.get("record_digest") == "sha256:" + record["seal_hash"] \
            and ec.get("request_id") == q.get("request_id"):
        pointer = "consistent: producer-asserted, outside metadata_hash (Section 3.2), not a binding"
    else:
        pointer = "inconsistent with the bound values: producer-asserted, outside metadata_hash (Section 3.2); the binding does not rest on it"
    return j, pointer


def write(out, art):
    out.mkdir(parents=True, exist_ok=True)
    (out / "decision-record.json").write_bytes(compact(art["record"]))
    (out / "action-binding-attachment.json").write_bytes(compact(art["attachment"]))
    (out / "signatures-attachment.json").write_bytes(compact(art["sig"]))
    (out / "trust-policy.json").write_bytes(compact(TRUST))
    (out / "policy.json").write_bytes(policy_bytes)
    (out / "review-view.txt").write_bytes(VIEW)
    (out / "aer1-receipt.json").write_text(json.dumps(art["receipt"], ensure_ascii=False, indent=1) + "\n")


if __name__ == "__main__":
    art = build()
    write(HERE / "out", art)
    results = verify(art)
    (HERE / "out" / "summary.json").write_text(json.dumps(results, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(results, ensure_ascii=False, indent=1))
    sys.exit(0 if results["all_verified"] else 1)
