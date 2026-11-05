#!/usr/bin/env python3
"""Case 15: an AgentInteractionRecord citing a decision record by typed digest. Built for a call with the author of
draft-emirdag-scitt-ai-agent-execution-01 (12 October 2026), whose Section 10.1 says that "an AIR can carry a reference
to a Permit or equivalent authorisation record in external_refs" and that the profile "does not define the
authorisation record itself". Here the authorisation record is a Decision Provenance Standard record with its action
binding and the person's signature; the execution record is an AIR. Built from existing texts and checked by existing
code, nothing changed in either:

  DPS     action binding 0.3.0 and signatures 0.2.0 at main 007f8c9: the refund of ../aer1-decision, proposed by an
          agent, shown to a support lead, approved under their signature, requested, rechecked, attempted and observed;
          the attachment sealed by the issuer, so the stages that cite the AIR are under a signature too;
  AIR     draft-emirdag-scitt-ai-agent-execution-01: two records of one Evidence Chain by the agent's operator, as
          COSE_Sign1 with ES256 (Section 5.6): sequence 0, a read-only ledger lookup earlier in the session, unrelated to
          the decision; sequence 1, the execution of the approved refund, citing the decision record and the person's
          approval in external_refs by typed digest (Section 10.1), its input_hash being the approved specification's
          bytes and its outcome_hash the gateway's response.

What binds, and what only points. The AIR's payload is under the operator's signature and content_hash, so everything
in external_refs, input_hash and outcome_hash is the operator's signed statement; the DPS attempt and result citing the
AIR's record_id, chain_hash and outcome_hash are under the issuer's seal. The two documents cite each other, but not by
whole-document digest in both directions: the attachment's result stage names the AIR's chain_hash, so the AIR cannot
name the attachment's final bytes (it would have to know a digest that depends on its own). The AIR names what existed
when it was signed: the decision record (closed at the sign-off, before the request), the signatures attachment that
holds the person's approval, and the approved specification by its digest; the attachment names the AIR afterwards.
Neither side's text defines the other's reference: the types are this repository's (the namespace agent-pass and
plan-run use for CPB references), the resolution is an additional step outside Section 5.8, and the README says so.

Verifies: the two AIRs with a verifier written from the text (air_verify_independent.py: the four steps of 5.8 and
the schema rules of 6.1, 6.3, 6.4, each check named with its section) and, as a shape check only, the EES v0.2 JSON
Schema pinned in vectors/ with its integrity envelope excluded (ambiguity (b)); the record, the attachment, its seal and
the person's signature with the Standard's reference checks; then the joins across them. Synthetic data and test keys
(deterministic: fixed seeds, RFC 6979 signatures, fixed UUIDs and times); never use them for anything real.
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
from datetime import datetime, timezone

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = pathlib.Path(__file__).resolve().parent
REPO = pathlib.Path(os.environ.get("DPS_STANDARD") or (HERE / "dps-standard" if (HERE / "dps-standard").exists()
                                                       else "/root/claude-ops/dps/wt-007f8c9"))
_candidates = [HERE.parents[1] / "examples/release-decision/decision-record.json",
               HERE.parents[2] / "exemple-release/decision-record.json"]
TEMPLATE = pathlib.Path(os.environ.get("DPS_RECORD_TEMPLATE") or next(p for p in _candidates if p.exists()))
EES_SCHEMA = HERE / "vectors" / "air.schema.json"       # EES v0.2 air.schema.json, pinned copy (Apache-2.0), see vectors/


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AB = load("ab", REPO / "extensions/action-binding/tests/run_checks.py")
SIG = load("sig", REPO / "extensions/signatures/tests/run_checks.py")
AIR = load("air_independent", HERE / "air_verify_independent.py")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def b64(b):
    return base64.b64encode(b).decode("ascii")


def ms(text):
    """An RFC 3339 UTC time as Unix milliseconds (the AIR's uint timestamps)."""
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ" if "." in text else "%Y-%m-%dT%H:%M:%SZ")
               .replace(tzinfo=timezone.utc).timestamp() * 1000)


def key_from_seed(text):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(text.encode()).digest())


def es256_key_from_seed(text):
    """A P-256 private key from a seed: the test operator key, the same on every run (the seed's SHA-256 reduced into
    [1, n-1], n the order of P-256)."""
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    return ec.derive_private_key(int.from_bytes(hashlib.sha256(text.encode()).digest(), "big") % (n - 1) + 1, ec.SECP256R1())


def raw_public(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def uuid7_from(at_ms, text):
    """A deterministic UUID v7 (RFC 9562): the 48-bit millisecond time, then the version and variant bits over bytes
    drawn from the seed instead of random ones, so the record_id is time-ordered as 5.3 asks and the same on every run."""
    b = bytearray(at_ms.to_bytes(6, "big") + hashlib.sha256(text.encode()).digest()[:10])
    b[6] = 0x70 | (b[6] & 0x0F)
    b[8] = 0x80 | (b[8] & 0x3F)
    return str(uuid.UUID(bytes=bytes(b)))


approver_key = key_from_seed("dps-scitt-decision-layer air: support lead key (test only)")
issuer_key = key_from_seed("dps-scitt-decision-layer air: issuer seal key (test only)")
operator_key = es256_key_from_seed("dps-scitt-decision-layer air: agent operator ES256 key (test only)")
APPROVER, APPROVER_KEY, ISSUER_KEY = "support-lead-1", "support-lead-1-key-1", "example-merchant-seal-1"
MERCHANT = "urn:example:payments:merchant-7"
DECISION_ID = "DR-2026-1105"
REQUEST_ID = "urn:example:refund-request:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:example:air-decision:q1"))
# ---- the AIR side: the operator, the agent deployment, the session (5.3)
OPERATOR_ID = "urn:example:operator:example-merchant-agent-operations"
OPERATOR_KEY_ID = "example-merchant-agent-ops-es256-1"
AGENT_ID = "urn:example:agent:support-agent-5"
AGENT_VERSION = "support-agent 5; model example-llm 2026-09; example-agent-runtime 3.1"
SESSION_ID = str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:example:air-decision:session-4410"))
NS = "org.decisionprovenancestandard"      # the typed-reference namespace of agent-pass and plan-run (CPB references)
REF_SYSTEM = "https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/tree/main/interop/air/out"
EXECUTOR = "urn:example:agent-runtime:3.1"

refund_policy = {
    "policy_id": "urn:example:policy:refunds", "version": "2026-10-01",
    "applies_to": {"operation": "payments.refund.create", "target": MERCHANT},
    "approvers": [{"actor_ref": APPROVER, "role": "support lead"}],
    "limits": {"max_amount_minor_without_finance": 50000},
    "single_use": True, "max_approval_age_seconds": 1800,
    "recheck": "the agent runtime rechecks the approval before the call, on its own clock",
    "execution": "by the agent runtime through the payment gateway; the operator records an AgentInteractionRecord of "
                 "every material action, citing the decision record and the approval it executed under",
}
policy_bytes = compact(refund_policy)
POLICY_VERSION = "sha256:" + sha256(policy_bytes)
POLICY_REF = refund_policy["policy_id"] + "#" + refund_policy["version"]
T = {"lookup": "2026-11-03T09:01:30.000Z", "lookup_captured": "2026-11-03T09:01:30.200Z",
     "proposal": "2026-11-03T09:02:00Z", "review": "2026-11-03T09:05:00Z", "approval": "2026-11-03T09:07:00Z",
     "closed": "2026-11-03T09:07:30Z", "request": "2026-11-03T09:08:00Z", "recheck": "2026-11-03T09:08:05Z",
     "attempt": "2026-11-03T09:08:10Z", "action": "2026-11-03T09:08:12.500Z", "captured": "2026-11-03T09:08:12.900Z",
     "result": "2026-11-03T09:08:20Z", "sealed": "2026-11-03T09:21:00Z", "valid_until": "2026-11-03T09:37:00Z"}

PARAMS = {"order_ref": "urn:example:order:8812", "amount_minor": 12000, "currency": "EUR",
          "reason": "duplicate charge of 2026-11-02"}
SPEC = {"operation": "payments.refund.create", "target": MERCHANT, "parameters": PARAMS,
        "input_version_refs": ["urn:example:ticket:4410"], "policy_version": POLICY_VERSION, "valid_until": T["valid_until"]}
VIEW = ("Refund order urn:example:order:8812: 120.00 EUR, reason: duplicate charge of 2026-11-02\n"
        f"merchant {MERCHANT}; ticket urn:example:ticket:4410\npolicy {POLICY_REF} ({POLICY_VERSION})\n"
        f"valid until {T['valid_until']}\n").encode()
# the raw output of each action, whose SHA-256 is outcome_hash (5.3): the gateway's response, and the ledger's answer
OUTCOME_1 = {"refund_ref": "urn:example:refund:R-55120", "status": "succeeded", "amount_minor": PARAMS["amount_minor"],
             "currency": "EUR", "idempotency_key": REQUEST_ID}
INPUT_0 = {"operation": "payments.ledger.lookup", "order_ref": "urn:example:order:8812"}
OUTCOME_0 = {"order_ref": "urn:example:order:8812", "charges": [{"charge_ref": "urn:example:charge:C-9001", "amount_minor": 12000},
                                                                 {"charge_ref": "urn:example:charge:C-9002", "amount_minor": 12000}]}
INPUT_SUMMARY_ORIGINAL = "Approved specification: refund of 120.00 EUR on order urn:example:order:8812 to Marie Example"
INPUT_SUMMARY_REDACTED = "Approved specification: refund of 120.00 EUR on order urn:example:order:8812 to [customer redacted]"


def make_record():
    record = json.loads(TEMPLATE.read_bytes())
    record.update({
        "decision_id": DECISION_ID, "created_at": T["proposal"], "charter_id": "CH-EXAMPLE-REFUNDS-1",
        "record_type": "decision", "record_state": "closed", "dispatch_mode": "mode-1-with-embedded-mode-2-summary",
        "altitude": "team-leader", "decision_class": "customer-refund",
        "consent_posture": {"posture_class": "contract performance: refund of a charge to the customer who paid it"},
        "decision_statement": "Refund 120.00 EUR on order 8812 for the duplicate charge of 2 November 2026, under the "
                              "refund policy of 1 October 2026, through the payment gateway.",
        "context_at_decision": "Ticket 4410 reports two identical charges; the support agent matched them in the ledger "
                               "and proposed the refund of the second.",
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


def make_signatures(record, sd):
    ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval",
          "decision_id": record["decision_id"], "stage_id": "o1", "outcome": "approved", "shown_spec_digest": sd,
          "shown_view_digest": sha256(VIEW), "approved_spec_digest": sd, "signed_at": T["approval"],
          "signature": {"algorithm": "Ed25519", "key_ref": APPROVER_KEY, "value_b64": ""}}
    ps["signature"]["value_b64"] = b64(approver_key.sign(SIG.person_signed_bytes(ps)))
    return {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps]}


# ---- the AIRs (Sections 5.2, 5.6, 5.7)
def typed_digest(kind, raw):
    """This repository's typed digest reference: the type in the namespace agent-pass and plan-run use, the SHA-256 of
    the exact bytes as "sha256:" + lowercase hex. Neither text defines this form; the README says so."""
    return {"ref_type": f"{NS}.{kind}", "ref_value": "sha256:" + sha256(raw), "ref_system": REF_SYSTEM}


def air_payload_0():
    """Sequence 0: a read-only ledger lookup earlier in the session, a material action of its own (regulated data
    access, 4.1 (c)), unrelated to the decision; it only shows the chain has a record before the one that matters."""
    return {
        "schema_version": "air-1.0", "record_id": uuid7_from(ms(T["lookup"]), "air-0 record id"), "session_id": SESSION_ID,
        "action_type": "regulated_data_access", "action_subtype": "payment_ledger_lookup",
        "action_timestamp_ms": ms(T["lookup"]), "captured_timestamp_ms": ms(T["lookup_captured"]), "written_timestamp_ms": None,
        "agent_id": AGENT_ID, "agent_version": AGENT_VERSION, "agent_did": None,
        "agent_workload_id": "spiffe://example.com/ns/payments/sa/support-agent-5",
        "operator_id": OPERATOR_ID, "operator_pubkey_id": OPERATOR_KEY_ID, "principal_id": None, "delegation_chain": None,
        "intent_attestation": None, "auth_context": None,
        "input_hash": AIR.b64url(hashlib.sha256(AIR.canonical_bytes(INPUT_0)).digest()),
        "input_summary": "Lookup of the charges of order urn:example:order:8812 in the payment ledger",
        "outcome_state": "completed", "outcome_hash": AIR.b64url(hashlib.sha256(AIR.canonical_bytes(OUTCOME_0)).digest()),
        "outcome_summary": "Two charges of 120.00 EUR found",
        "tool_calls": [{"tool_id": "payments.ledger.lookup", "tool_type": "api_call",
                        "input_hash": AIR.b64url(hashlib.sha256(AIR.canonical_bytes(INPUT_0)).digest()),
                        "output_hash": AIR.b64url(hashlib.sha256(AIR.canonical_bytes(OUTCOME_0)).digest()),
                        "is_write": False, "timestamp_ms": ms(T["lookup"])}],
        "jurisdiction": "FR", "retention_class": "regulatory_5yr", "policy_refs": ["urn:example:policy:ledger-access#2026-10-01"],
        "external_refs": [{"ref_type": "order_ref", "ref_value": "urn:example:order:8812", "ref_system": "urn:example:payments:ledger"}],
        "parent_record_id": None, "workflow_id": None, "trace_id": None, "consumer_instructions": None, "reasoning_hash": None,
        "redaction_receipts": [{"field_path": "outcome_summary", "original_hash": AIR.b64url(hashlib.sha256(
            b"Two charges of 120.00 EUR found, card ending 4242, Marie Example").digest()),
            "policy_id": "urn:example:policy:redaction:customer-identity", "timestamp_ms": ms(T["lookup_captured"])}],
    }


def air_payload_1(record_bytes, sig_bytes, spec_bytes, *, input_bytes=None, outcome=None, action_at=None, captured_at=None,
                  external_refs=None):
    """Sequence 1: the execution of the approved refund. input_hash is the SHA-256 of the approved specification's bytes
    (5.3: "the raw input to the agent", read as what the agent was given to execute); outcome_hash the SHA-256 of the
    gateway's response in RFC 8785 form; external_refs the typed digests of the decision record, of the signatures
    attachment holding the person's approval, and of the approved specification (10.1); intent_attestation, an
    unstructured reference in 5.3, is read as the typed digest string of the signatures attachment."""
    input_bytes = spec_bytes if input_bytes is None else input_bytes
    outcome_bytes = AIR.canonical_bytes(OUTCOME_1 if outcome is None else outcome)
    action_at, captured_at = action_at or T["action"], captured_at or T["captured"]
    sig_ref = typed_digest("signatures_attachment", sig_bytes)
    refs = [typed_digest("decision_record", record_bytes), sig_ref,
            {"ref_type": f"{NS}.action_specification", "ref_value": "sha256:" + sha256(spec_bytes), "ref_system": REF_SYSTEM},
            {"ref_type": "refund_ref", "ref_value": OUTCOME_1["refund_ref"], "ref_system": "urn:example:payments:gateway"}]
    # the tool call's input: the specification's parameters with the request_id as idempotency key (the action binding's
    # executor rule), in RFC 8785 form; the raw input bytes themselves when they are not a specification
    try:
        call_input = AIR.canonical_bytes({**json.loads(input_bytes)["parameters"], "idempotency_key": REQUEST_ID})
    except (ValueError, KeyError, TypeError):
        call_input = input_bytes
    return {
        "schema_version": "air-1.0", "record_id": uuid7_from(ms(action_at), "air-1 record id"), "session_id": SESSION_ID,
        "action_type": "payment_execution", "action_subtype": "refund",
        "action_timestamp_ms": ms(action_at), "captured_timestamp_ms": ms(captured_at), "written_timestamp_ms": None,
        "agent_id": AGENT_ID, "agent_version": AGENT_VERSION, "agent_did": None,
        "agent_workload_id": "spiffe://example.com/ns/payments/sa/support-agent-5",
        "operator_id": OPERATOR_ID, "operator_pubkey_id": OPERATOR_KEY_ID, "principal_id": APPROVER, "delegation_chain": None,
        "intent_attestation": f"{sig_ref['ref_type']}:{sig_ref['ref_value']}", "auth_context": None,
        "input_hash": AIR.b64url(hashlib.sha256(input_bytes).digest()), "input_summary": INPUT_SUMMARY_REDACTED,
        "outcome_state": "completed", "outcome_hash": AIR.b64url(hashlib.sha256(outcome_bytes).digest()),
        "outcome_summary": "Refund urn:example:refund:R-55120 succeeded, 120.00 EUR",
        "tool_calls": [{"tool_id": "payments.refund.create", "tool_type": "api_call",
                        "input_hash": AIR.b64url(hashlib.sha256(call_input).digest()),
                        "output_hash": AIR.b64url(hashlib.sha256(outcome_bytes).digest()), "is_write": True, "timestamp_ms": ms(action_at)}],
        "jurisdiction": "FR", "retention_class": "regulatory_5yr", "policy_refs": [POLICY_REF],
        "external_refs": refs if external_refs is None else external_refs,
        "parent_record_id": None, "workflow_id": REQUEST_ID, "trace_id": None, "consumer_instructions": None, "reasoning_hash": None,
        "redaction_receipts": [{"field_path": "input_summary",
                                "original_hash": AIR.b64url(hashlib.sha256(INPUT_SUMMARY_ORIGINAL.encode()).digest()),
                                "policy_id": "urn:example:policy:redaction:customer-identity", "timestamp_ms": ms(captured_at)}],
    }


def protected_header(payload_bytes, payload, seq, prev_chain_hash):
    """Section 5.6: alg, kid, CWT Claims (iss = operator_id, sub = agent_id) and the six integrity fields of 5.5 with
    string labels; content_hash over the bytes inside the payload byte string (reading (a)), chain_hash per 5.7."""
    content = hashlib.sha256(payload_bytes).digest()
    return {1: AIR.ES256, 4: payload["operator_pubkey_id"].encode("utf-8"),
            15: {1: payload["operator_id"], 2: payload["agent_id"]},
            "content_hash": content, "prev_chain_hash": prev_chain_hash,
            "chain_hash": AIR.chain_hash(content, prev_chain_hash, payload["action_timestamp_ms"], payload["agent_id"]),
            "sequence_number": seq, "action_timestamp_ms": payload["action_timestamp_ms"], "agent_id": payload["agent_id"]}


def sign(protected_bytes, payload_bytes, key=operator_key):
    """ES256 over the RFC 9052 Sig_structure (reading (b)), r || s as RFC 9053 2.1 asks; RFC 6979 nonces, so the bytes
    are the same on every run."""
    der = key.sign(AIR.sig_structure(protected_bytes, payload_bytes), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def assemble(protected, payload_bytes, signature=None, key=operator_key):
    """The COSE_Sign1 (tag 18) from its parts; the signature computed unless one is given (the failing cases keep one)."""
    protected_bytes = cbor2.dumps(protected, canonical=True)
    signature = sign(protected_bytes, payload_bytes, key) if signature is None else signature
    cose = cbor2.dumps(cbor2.CBORTag(18, [protected_bytes, {}, payload_bytes, signature]))
    return {"cose": cose, "payload_bytes": payload_bytes, "payload": json.loads(payload_bytes), "protected": protected,
            "signature": signature, "record_id": json.loads(payload_bytes).get("record_id")}


def issue(payload, seq, prev_chain_hash):
    payload_bytes = AIR.canonical_bytes(payload)
    return assemble(protected_header(payload_bytes, payload, seq, prev_chain_hash), payload_bytes)


def reissue(air, *, payload=None, payload_bytes=None, header=None, keep_signature=False):
    """The record as the operator would sign it again from changed parts: header members recomputed from the payload
    bytes unless given explicitly; the old signature kept only when asked (the signature case)."""
    pb = payload_bytes if payload_bytes is not None else (AIR.canonical_bytes(payload) if payload is not None else air["payload_bytes"])
    p = json.loads(pb)
    h = protected_header(pb, p, air["protected"]["sequence_number"], air["protected"]["prev_chain_hash"])
    h.update(header or {})
    return assemble(h, pb, air["signature"] if keep_signature else None)


def make_airs(record_bytes, sig_bytes, spec_bytes, **kw):
    air0 = issue(air_payload_0(), 0, AIR.ZERO32)
    air1 = issue(air_payload_1(record_bytes, sig_bytes, spec_bytes, **kw), 1, air0["protected"]["chain_hash"])
    return [air0, air1]


def air_urn(air):
    return f"urn:air:record:{air['record_id']}"


def air_evidence_ref(air):
    """The DPS result's evidence_ref: the AIR by record_id, with its chain_hash (the position in the Evidence Chain the
    receipt of Section 7 would attest) and its outcome_hash, both as lowercase hex."""
    outcome = AIR.unb64url(air["payload"]["outcome_hash"]).hex()
    return f"{air_urn(air)}#chain_hash={air['protected']['chain_hash'].hex()}&outcome_hash={outcome}"


def make_attachment(record, air1, spec_bytes):
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
             "spec_digest": sd, "executor_ref": EXECUTOR, "trace_refs": [air_urn(air1)]},
            {"stage_id": "r1", "kind": "result", "at": T["result"], "attempt_ref": "x1", "observed": "succeeded",
             "basis": "executor_observation", "evidence_ref": air_evidence_ref(air1)},
        ]}
    return att


def seal(att, key=issuer_key):
    """The issuer's seal of kind attachment (action binding item 7), over the attachment's bytes with the value
    replaced by A, built with the Standard's own functions."""
    att["issuer_signature"] = {"algorithm": "Ed25519", "key_ref": ISSUER_KEY,
                               "signed_bytes_ref": "dps-signatures 0.2.0 organisation_seal", "sealed_at": T["sealed"],
                               "value_b64": "A" * 88}
    att["issuer_signature"]["value_b64"] = b64(key.sign(SIG.seal_signed_bytes(AB.seal_assertion(att))))
    return att


def recite(art):
    """The issuer's attempt and result cite the AIR held now, and the attachment is sealed again: the failure, if any,
    is then in what the AIR binds, not in a stale citation (as ../aer1-decision does with its receipt)."""
    air1 = art["airs"][1]
    for s in art["attachment"]["stages"]:
        if s["stage_id"] == "x1":
            s["trace_refs"] = [air_urn(air1)]
        if s["stage_id"] == "r1":
            s["evidence_ref"] = air_evidence_ref(air1)
    seal(art["attachment"])


TRUST = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0", "policy_ref": "urn:example:trust-policy:verifier-1",
         "tsas": [], "checkpoint_sources": [],
         "keys": [{"key_ref": APPROVER_KEY, "holder": APPROVER, "role": "person", "algorithm": "Ed25519",
                   "public_key_hex": raw_public(approver_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                   "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:people"},
                  {"key_ref": ISSUER_KEY, "holder": "Example Merchant", "role": "organisation", "algorithm": "Ed25519",
                   "public_key_hex": raw_public(issuer_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                   "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:organisations"}]}
OPERATOR_PUBLIC_PEM = operator_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def build():
    record = make_record()
    record_bytes = compact(record)
    spec_bytes = compact(SPEC)
    sig = make_signatures(record, sha256(spec_bytes))
    sig_bytes = compact(sig)
    airs = make_airs(record_bytes, sig_bytes, spec_bytes)
    att = seal(make_attachment(record, airs[1], spec_bytes))
    return {"record": record, "record_bytes": record_bytes, "sig": sig, "sig_bytes": sig_bytes, "spec_bytes": spec_bytes,
            "attachment": att, "airs": airs}


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


def ees_schema_errors(airs):
    """A shape check against the EES v0.2 air.schema.json, pinned in vectors/: its `integrity` envelope (the EES signs
    chain_hash inside the JSON) is excluded, since the draft moves those members to the COSE protected header
    (ambiguity (b)); everything else of the schema applies to the payload as it is. Not a check the draft asks for."""
    from jsonschema import Draft202012Validator
    schema = json.loads(EES_SCHEMA.read_text())
    schema["required"] = [k for k in schema["required"] if k != "integrity"]
    v = Draft202012Validator(schema)
    return {f"air-{i}": [e.message[:160] for e in v.iter_errors(a["payload"])] if a["payload"] else ["payload not JSON"]
            for i, a in enumerate(airs)}


def verify(art):
    r = {"ees_schema": {"source": "THEVERIDIC/VERIDIC standards/ees/v0.2/air.schema.json (Apache-2.0), pinned copy in vectors/",
                        "sha256": sha256(EES_SCHEMA.read_bytes()), "payload_errors": ees_schema_errors(art["airs"]),
                        "note": "shape check with `integrity` excluded (the draft carries those members in the protected header); "
                                "not a check of the draft"},
         "schema_errors": schema_errors(art)}
    att, record, record_bytes = art["attachment"], art["record"], compact(art["record"])
    # ---- the AIRs, the verifier written from the text
    chain = AIR.verify_chain([a["cose"] for a in art["airs"]], operator_key.public_key())
    r["air"] = {f"air-{i}": {"verdict": x["verdict"], "checks": x["checks"]} for i, x in enumerate(chain["results"])}
    r["air"]["chain"] = {"verdict": chain["verdict"], "records": chain["records"], "one_agent_id": chain["one_agent_id"]}
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
    # ---- the joins, an additional step outside Section 5.8
    r["external_refs"], r["binding"], r["joins"] = joins(art, chain)
    r["all_verified"] = (not any(r["schema_errors"].values()) and not any(r["ees_schema"]["payload_errors"].values())
                         and chain["verdict"] == "VERIFIED"
                         and r["dps_trust_policy"] == "verified" and all(v == "verified" for v in r["dps_action_binding"].values())
                         and r["dps_issuer_seal"]["status"] == "verified" and r["dps_person_approval"]["status"] == "verified"
                         and r["binding"].startswith("BOUND") and all(v is True for v in r["joins"].values()))
    return r


KNOWN_TYPES = ("decision_record", "signatures_attachment", "action_specification")


def resolve_refs(refs, held):
    """Each external_refs item classified against the bytes held: resolved (a known type of this namespace whose
    digest is the bytes'), mismatch (known type, other digest), unknown_type (this namespace, a type not known here),
    outside (another system's reference, not resolved here: 10.1 leaves resolution to the Relying Party)."""
    out = []
    for ref in refs or []:
        t, v = ref.get("ref_type", ""), ref.get("ref_value", "")
        if not t.startswith(NS + "."):
            res = "outside: not a reference of this namespace, not resolved here"
        elif t[len(NS) + 1:] not in KNOWN_TYPES:
            res = "unknown_type: this namespace, a type this reader does not know; unresolved"
        elif v == "sha256:" + held[t[len(NS) + 1:]]:
            res = "resolved: the digest of the bytes held"
        else:
            res = "mismatch: a known type, but not the digest of the bytes held"
        out.append({**ref, "resolution": res})
    return out


def joins(art, chain):
    att, record, airs = art["attachment"], art["record"], art["airs"]
    air1, air0 = airs[1], airs[0]
    p1, h1 = air1["payload"], air1["protected"]
    st = {s["stage_id"]: s for s in att["stages"]}
    o1, q1 = next((s for s in att["stages"] if s["kind"] == "outcome"), {}), next((s for s in att["stages"] if s["kind"] == "request"), {})
    x1 = next((s for s in att["stages"] if s["kind"] == "attempt"), {})
    r1 = next((s for s in att["stages"] if s["kind"] == "result" and s.get("attempt_ref") == x1.get("stage_id")), {})
    approved = o1.get("approved_spec_digest")
    spec_bytes = next((base64.b64decode(s["content"]["bytes_b64"]) for s in att["action_specifications"] if s["spec_digest"] == approved), b"")
    held = {"decision_record": sha256(compact(record)), "signatures_attachment": sha256(compact(art["sig"])),
            "action_specification": sha256(spec_bytes)}
    refs = resolve_refs(p1.get("external_refs"), held)
    ours = [x for x in refs if x["ref_type"].startswith(NS + ".")]
    resolved = {x["ref_type"][len(NS) + 1:] for x in ours if x["resolution"].startswith("resolved")}
    if not ours:
        binding = "NOT_BOUND: the AIR carries no reference of this namespace; the join is not established (not an error of either document)"
    elif any(x["resolution"].startswith("mismatch") for x in ours):
        binding = "MISMATCH: a reference of this namespace does not name the bytes held"
    elif "decision_record" not in resolved:
        binding = "UNRESOLVED: references of this namespace, none of them the decision record held; reported, not established"
    else:
        binding = "BOUND: the AIR names the decision record held, under the operator's signature"
    ps = (art["sig"].get("person_signatures") or [{}])[0]
    approver_keys = {k["key_ref"]: k["holder"] for k in TRUST["keys"] if k["role"] == "person"}
    approver = approver_keys.get(ps.get("signature", {}).get("key_ref"))
    input_hash = AIR.unb64url(p1["input_hash"]).hex() if isinstance(p1.get("input_hash"), str) else None
    outcome_hash = AIR.unb64url(p1["outcome_hash"]).hex() if isinstance(p1.get("outcome_hash"), str) else None
    ev = r1.get("evidence_ref", "")
    frag = dict(kv.split("=", 1) for kv in ev.split("#", 1)[1].split("&")) if "#" in ev else {}
    j = {
        "J1 the AIR's external_refs name the decision record, the signatures attachment (the person's approval) and the "
        "approved specification by the digests of the bytes held (10.1; typed digest, this repository's form)":
            (True if {"decision_record", "signatures_attachment", "action_specification"} <= resolved
             else False if any(x["resolution"].startswith("mismatch") for x in ours) or resolved
             else "not established: " + binding) if ours else "not applicable: no reference of this namespace",
        "J2 the AIR's input_hash is the SHA-256 of the approved specification's bytes, the ones o1.approved_spec_digest and "
        "the person's approved_spec_digest name (shown, approved, executed)":
            bool(spec_bytes) and input_hash == sha256(spec_bytes) == approved == ps.get("approved_spec_digest"),
        "J3 the DPS attempt cites the AIR by record_id (trace_refs) and the result names its chain_hash and outcome_hash "
        "(evidence_ref), under the issuer's seal; the outcome_hash is the SHA-256 of the raw output held":
            air_urn(air1) in x1.get("trace_refs", []) and ev.startswith(air_urn(air1) + "#")
            and frag.get("chain_hash") == h1["chain_hash"].hex() and frag.get("outcome_hash") == outcome_hash
            and outcome_hash == sha256(AIR.canonical_bytes(OUTCOME_1)),
        "J4 the action_timestamp_ms of sequence 1 is after the approval, not before the request, and not after the observed "
        "result (issuer and operator clocks, as asserted)":
            bool(o1 and q1 and r1) and ms_of(o1["at"]) < p1["action_timestamp_ms"] and ms_of(q1["at"]) <= p1["action_timestamp_ms"]
            <= ms_of(r1["at"]),
        "J5 the Evidence Chain of two verifies (5.8) and sequence 1's prev_chain_hash is sequence 0's chain_hash":
            chain["verdict"] == "VERIFIED" and h1["prev_chain_hash"] == air0["protected"]["chain_hash"]
            and h1["sequence_number"] == 1 and air0["protected"]["sequence_number"] == 0,
        "J6 the person who approved (the signer named by the trust policy, o1.actor_ref) is neither the operator_id nor the "
        "agent_id; the AIR names them as principal_id (the operator's assertion); the DPS holds their signature":
            approver is not None and approver == o1.get("actor_ref") and approver not in (p1.get("operator_id"), p1.get("agent_id"))
            and p1.get("principal_id") == approver,
    }
    return refs, binding, j


def ms_of(text):
    return ms(text)


def write_airs(out, airs):
    """Each AIR as the COSE_Sign1 bytes (air-N.cose), the same as hex (air-N.cose.hex), the payload for the eye
    (air-N.json), the exact canonical bytes the content_hash covers (air-N.canonical.json), the protected header as a
    diagnostic (air-N.header.json), and the raw input and output whose SHA-256 the payload carries."""
    raws = [(INPUT_0, OUTCOME_0), (None, OUTCOME_1)]
    for i, a in enumerate(airs):
        (out / f"air-{i}.cose").write_bytes(a["cose"])
        (out / f"air-{i}.cose.hex").write_text(a["cose"].hex() + "\n")
        (out / f"air-{i}.canonical.json").write_bytes(a["payload_bytes"])
        (out / f"air-{i}.json").write_text(json.dumps(a["payload"], ensure_ascii=False, indent=1) + "\n")
        (out / f"air-{i}.header.json").write_text(json.dumps(AIR.header_diagnostic(a["protected"]), ensure_ascii=False, indent=1) + "\n")
        inp, outc = raws[i]
        if inp is not None:
            (out / f"air-{i}.input.json").write_bytes(AIR.canonical_bytes(inp))
        (out / f"air-{i}.outcome.json").write_bytes(AIR.canonical_bytes(outc))


def write(out, art):
    out.mkdir(parents=True, exist_ok=True)
    (out / "decision-record.json").write_bytes(compact(art["record"]))
    (out / "action-binding-attachment.json").write_bytes(compact(art["attachment"]))
    (out / "signatures-attachment.json").write_bytes(compact(art["sig"]))
    (out / "trust-policy.json").write_bytes(compact(TRUST))
    (out / "policy.json").write_bytes(policy_bytes)
    (out / "review-view.txt").write_bytes(VIEW)
    (out / "operator-public-key.pem").write_bytes(OPERATOR_PUBLIC_PEM)
    write_airs(out, art["airs"])


if __name__ == "__main__":
    art = build()
    write(HERE / "out", art)
    results = verify(art)
    (HERE / "out" / "summary.json").write_text(json.dumps(results, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(results, ensure_ascii=False, indent=1))
    sys.exit(0 if results["all_verified"] else 1)
