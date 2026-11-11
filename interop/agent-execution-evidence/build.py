#!/usr/bin/env python3
"""Case 16: the proof behind `confirm`. An agent run in the shape of draft-thaha-scitt-agent-execution-evidence-02
(Section 6.7: a hash-chained record of calls, one of them a tool_call with decision confirm, then its allow outcome,
the tool_result and the task_end), and a Decision Provenance Standard decision record with its action-binding
attachment (0.3.0) and the person's approval (signatures 0.2.0) as the record of what the confirmation was.

The author's text says a confirm receipt records that "policy required confirmation from a Principal or operator before
the call could proceed" and that the outcome receipt records allow or block (Section 6.7); who confirmed, what exactly
they confirmed and on what evidence is not a member of either receipt; the draft does not define an approval format
(Section 15, the Implementation Status, mentions "separately recorded approvals" in the authors' implementation; it is
not a design position). The DPS signed outcome stage (person_approval over the exact specification) is offered as one
such separate record. Built from the two texts; nothing in either is changed:

  AEE   synthetic Evidence Chain of six Execution Receipts (seq 0 task_start, 1 inference, 2 tool_call confirm, 3 the
        allow outcome with confirm_seq 2, 4 tool_result, 5 task_end), canonical CBOR, record-hashes per 6.7.1, agent_sig
        on the confirm receipt, each receipt registered individually as a COSE_Sign1 Signed Statement with the header
        of Section 5, all in a Bundle of Section 8 (keys 1 and 2). Synthetic: the author publishes Appendix A vectors
        in diagnostic notation, which aee_verify_from_text.py reproduces, but no vector with a confirmation record.
  DPS   a decision record and the attachment A1 as sealed at the approval (proposal by the agent, review by the finance
        controller, signed approval of the specification whose parameters are the tool arguments the Harness hashed),
        then A2 after the run (request, recheck, attempt citing record-hash(3), result citing record-hash(4) and the
        response digest), sealed by the issuer.
  Join  route 1, a separate Signed Statement (COSE_Sign1, Section 6 of RFC 9943 shape) by the DPS issuer whose payload
        carries typed digest references to A2, to the signatures attachment and to the two receipts (confirm and
        outcome) by their record-hash; registered beside the AEE statements, not inside the Bundle (Section 9 step 3
        would refuse a foreign type there). Route 2, a proposal only: an optional key 30 on the allow outcome receipt
        carrying the same kind of reference to A1 and to the signatures attachment; built as a second rendering of the
        run under out/proposal/, verified only by our verifier with that key accepted.

Synthetic data and test keys (fixed seeds, fixed times); never use them for anything real. Deterministic: two runs
write the same bytes.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = pathlib.Path(__file__).resolve().parent
REPO = pathlib.Path(os.environ.get("DPS_STANDARD") or (HERE / "dps-standard" if (HERE / "dps-standard").exists()
                                                       else "/root/claude-ops/dps/wt-007f8c9"))
TEMPLATE = pathlib.Path(os.environ.get("DPS_RECORD_TEMPLATE") or HERE.parents[1] / "examples/release-decision/decision-record.json")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AB = load("ab", REPO / "extensions/action-binding/tests/run_checks.py")
SIG = load("sig", REPO / "extensions/signatures/tests/run_checks.py")
AEE = load("aee_from_text", HERE / "aee_verify_from_text.py")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def b64(b):
    return base64.b64encode(b).decode("ascii")


def ms(text):
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ" if "." in text else "%Y-%m-%dT%H:%M:%SZ")
               .replace(tzinfo=timezone.utc).timestamp() * 1000)


def iso(ms_):
    return datetime.fromtimestamp(ms_ / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def key_from_seed(text):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(text.encode()).digest())


def raw_public(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# ---- keys and names (test only)
harness_key = key_from_seed("dps-scitt-decision-layer aee: harness evidence service key (test only)")
agent_key = key_from_seed("dps-scitt-decision-layer aee: agent key (test only)")
approver_key = key_from_seed("dps-scitt-decision-layer aee: finance controller key (test only)")
issuer_key = key_from_seed("dps-scitt-decision-layer aee: DPS issuer seal key (test only)")
HARNESS_ISS = "https://harness.example/evidence"            # the Evidence Service, Issuer of the receipts (6.7)
AGENT_ID = "wimse://agents.example.com/agent/invoicing-assistant"
APPROVER, APPROVER_KEY, ISSUER_KEY = "finance-controller-1", "finance-controller-1-key-1", "example-corp-seal-1"
APPROVER_CANONICAL_ID = f"user:{APPROVER}@example.com"     # the person's canonical identifier (Section 3; ambiguity (f))
PEPPER = b"example-corp-harness-pepper-2026-11"             # held by the Harness, never on the TS (Section 10); test value
DECISION_ID = "DR-2026-1104"
REQUEST_ID = "urn:example:invoicing-request:7c1f0a3e-5b1e-4d0d-9a1a-000000000001"
NS = "org.decisionprovenancestandard"
AEE_NS = "org.ietf.draft-thaha-scitt-agent-execution-evidence-02"
REF_SYSTEM = "https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/tree/main/interop/agent-execution-evidence/out"
BINDING_MEDIA = "application/vnd.org.decisionprovenancestandard.binding+cbor"   # ours, not one of his Section 12.1 types
TXN = "txn-2026-1104-0007"

policy = {"policy_id": "urn:example:policy:outbound-invoices", "version": "2026-10-01",
          "applies_to": {"operation": "send_invoice", "target_host": "api.customer.example"},
          "confirmation": {"required_above_minor": 100000, "by": [{"actor_ref": APPROVER, "role": "finance controller"}]},
          "single_use": True, "max_approval_age_seconds": 900,
          "execution": "by the Harness tool door once the confirm receipt's outcome is allow; the DPS attempt and result "
                       "cite the outcome and the tool_result by record-hash"}
policy_bytes = compact(policy)
POLICY_VERSION = "sha256:" + sha256(policy_bytes)
POLICY_REF = policy["policy_id"] + "#" + policy["version"]
PACK_DIGEST = hashlib.sha256(policy_bytes).digest()        # the Policy Pack in force (7): here the same policy bytes
CONFIG_DIGEST = hashlib.sha256(b'[["SYSTEM_PROMPT",[-16,"<digest>"],1],["tools/send_invoice.json",[-16,"<digest>"],6]]').digest()

T = {"task_start": "2026-11-04T10:00:00.000Z", "inference": "2026-11-04T10:00:01.200Z", "confirm": "2026-11-04T10:00:02.500Z",
     "proposal": "2026-11-04T10:00:03Z", "review": "2026-11-04T10:00:40Z", "approval": "2026-11-04T10:01:10Z",
     "closed": "2026-11-04T10:01:11Z", "a1_sealed": "2026-11-04T10:01:12Z", "request": "2026-11-04T10:01:15Z",
     "recheck": "2026-11-04T10:01:16Z", "outcome": "2026-11-04T10:01:18.000Z", "attempt": "2026-11-04T10:01:18Z",
     "tool_result": "2026-11-04T10:01:19.300Z", "task_end": "2026-11-04T10:01:20.000Z", "result": "2026-11-04T10:01:21Z",
     "a2_sealed": "2026-11-04T10:02:00Z", "binding": "2026-11-04T10:03:00Z", "valid_until": "2026-11-04T10:16:10Z"}

PARAMS = {"invoice_ref": "INV-2026-0912", "customer_ref": "urn:example:customer:C-4471", "amount_minor": 480000,
          "currency": "EUR", "due": "2026-12-04"}
ARGS = compact(PARAMS)                                       # the tool arguments as the Harness sees them at the tool door
SPEC = {"operation": "send_invoice", "target": "https://api.customer.example/invoices", "parameters": PARAMS,
        "input_version_refs": ["urn:example:order:O-20261103-18"], "policy_version": POLICY_VERSION, "valid_until": T["valid_until"]}
VIEW = ("Send invoice INV-2026-0912: 4,800.00 EUR to customer urn:example:customer:C-4471, due 2026-12-04\n"
        f"via https://api.customer.example/invoices; policy {POLICY_REF} ({POLICY_VERSION})\nvalid until {T['valid_until']}\n").encode()
PROMPT = b"<prompt bytes: order O-20261103-18 is complete; prepare the invoice>"
COMPLETION = b'<completion bytes: call send_invoice with ' + ARGS + b">"
RESPONSE = compact({"status": "accepted", "invoice_ref": "INV-2026-0912", "customer_ack": "urn:example:ack:A-9931"})


def digest(b):
    return [AEE.SHA256_COSE, hashlib.sha256(b).digest()]


def principal_of(canonical_id, pepper=PEPPER):
    """Section 3: SHA-256 over the Issuer's pepper and the person's canonical identifier."""
    return {1: 1, 2: hashlib.sha256(pepper + canonical_id.encode()).digest()}


# ---- the Evidence Chain (6.7, 6.7.1)
def agent_sig(receipt_without_15):
    """6.7 agent_sig: COSE_Sign1, detached payload = the canonical receipt without key 15, CWT iss and sub the agent."""
    protected = cbor2.dumps({1: AEE.EDDSA, 3: AEE.MEDIA_CBOR, 4: hashlib.sha256(raw_public(agent_key)).digest()[:8],
                             15: {1: AGENT_ID, 2: AGENT_ID}}, canonical=True)
    sig = agent_key.sign(AEE.sig_structure(protected, AEE.canonical(receipt_without_15)))
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, None, sig]))


def make_receipts(principal, *, route2_refs=None, approval_bytes=None):
    """The six receipts of one Task. route2_refs, when given, is the proposed key 30 value for the allow outcome."""
    common = {1: 5, 7: digest(policy_bytes), 8: [AEE.SHA256_COSE, CONFIG_DIGEST], 9: AGENT_ID, 10: principal, 11: 0}
    common[8] = [AEE.SHA256_COSE, CONFIG_DIGEST]
    rs, prev = [], AEE.ZERO32

    def add(r):
        nonlocal prev
        r = {**common, **r, 2: len(rs), 3: prev}
        rs.append(r)
        prev = AEE.record_hash(r)
        return r

    add({4: 1, 6: 1, 14: ms(T["task_start"]), 26: digest(b"<memory state at task start>")})
    add({4: 3, 6: 1, 14: ms(T["inference"]), 12: digest(PROMPT), 13: digest(COMPLETION), 16: "example-model-2026-09", 18: 1})
    call = {4: 4, 5: 1, 6: 3, 12: digest(ARGS), 14: ms(T["confirm"]), 16: "send_invoice", 17: "api.customer.example", 18: 2}
    body = {**common, **call, 2: 2, 3: prev}
    add({**call, 15: agent_sig(body)})
    outcome = {**call, 6: 1, 14: ms(T["outcome"]), 19: 2, 23: [AGENT_ID], 24: hashlib.sha256(b"<delegation token octets>").digest(),
               25: TXN, 29: digest(cbor2.dumps(["POST", "/invoices", hashlib.sha256(ARGS).digest()], canonical=True))}
    if route2_refs is not None:
        outcome[30] = route2_refs
    add(outcome)
    add({4: 5, 5: 3, 6: 1, 13: digest(RESPONSE), 14: ms(T["tool_result"]), 16: "send_invoice", 18: 2})
    add({4: 2, 6: 1, 14: ms(T["task_end"]), 26: digest(b"<memory state at task end>")})
    return rs


def signed_statement(payload_map, key=harness_key, iss=HARNESS_ISS, sub=None, aee_type=None, content_type=AEE.MEDIA_CBOR,
                     kid=None):
    """Section 5: COSE_Sign1 over the canonical payload; protected alg, content type, kid, CWT Claims iss, sub, aee_type."""
    payload = AEE.canonical(payload_map)
    protected = cbor2.dumps({1: AEE.EDDSA, 3: content_type, 4: kid or hashlib.sha256(raw_public(key)).digest()[:8],
                             15: {1: iss, 2: sub, "aee_type": aee_type if aee_type is not None else payload_map[1]}}, canonical=True)
    sig = key.sign(AEE.sig_structure(protected, payload))
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, sig]))


def make_bundle(receipts, extra_statements=()):
    """Section 8: key 1 the statements (here each receipt's own Signed Statement; 6.7.4 permits individual
    registration), key 2 the chain segment in ascending seq. No TS receipts (label 394): these are Signed, not
    Transparent, Statements, and the verifier says so."""
    statements = [signed_statement(r, sub=r[9]) for r in receipts] + list(extra_statements)
    return AEE.canonical({1: statements, 2: receipts})


# ---- the DPS side
def make_record():
    record = json.loads(TEMPLATE.read_bytes())
    record.update({
        "decision_id": DECISION_ID, "created_at": T["proposal"], "charter_id": "CH-EXAMPLE-INVOICING-1",
        "record_type": "decision", "record_state": "closed", "dispatch_mode": "mode-1-with-embedded-mode-2-summary",
        "altitude": "team-leader", "decision_class": "outbound-invoice",
        "consent_posture": {"posture_class": "contract performance: invoicing of a delivered order"},
        "decision_statement": "Send invoice INV-2026-0912 of 4,800.00 EUR to customer C-4471 for order O-20261103-18, "
                              "under the outbound-invoices policy of 1 October 2026, through the customer API.",
        "context_at_decision": "Order O-20261103-18 was delivered on 3 November 2026; the invoicing agent prepared the "
                               "invoice and the policy requires the finance controller's confirmation above 1,000.00 EUR.",
        "options_considered": ["Send the invoice now (chosen).", "Hold it for the monthly batch: 26 days later.",
                               "Split it in two: the customer did not ask for it."],
        "required_inputs_used": ["order O-20261103-18", "the customer's billing record"],
        "assumptions_depended_on": ["The delivery of 3 November 2026 is complete and accepted."],
        "success_criteria": ["One invoice of 4,800.00 EUR accepted by the customer API, and no second one for the same order."],
        "accountable_owner": {"full_name": "Finance Controller One", "role": "Finance controller", "employer": "Example Corp"},
        "re_decision_trigger": "The customer disputes the delivery before the invoice is sent.",
        "drafting_authority": {"deployer_role_pointer": "urn:example:role:invoicing-drafting", "system_name": "invoicing-assistant",
                               "version": "2"},
        "affirmation_record": {"timestamp": T["approval"], "actor_identity": APPROVER,
                               "method": "Ed25519 signature over the DPS person_approval assertion"},
        "accountable_owner_signoff": {"signed_by": APPROVER, "signed_at": T["closed"]},
        "review_log": [{"reviewer": APPROVER, "reviewed_at": T["approval"], "outcome": "approved"}],
        "closed_at": T["closed"], "record_location": f"urn:example:decision-records:{DECISION_ID}", "supersedes": None,
    })
    record["mode_classification_attestation"].update({
        "attestor_full_name": "Finance Controller One", "attestor_role_title": "Finance controller", "attestor_employer": "Example Corp",
        "attestation_timestamp": T["closed"], "attestor_capacity": "employee",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 "
                                   "summary under charter CH-EXAMPLE-INVOICING-1: the invoicing agent (invoicing-assistant, "
                                   "version 2) drafted the invoice from order O-20261103-18; I reviewed it as shown in the "
                                   "finance console, approved the specification whose digest the attachment names, and I am "
                                   "the accountable owner of this decision."})
    record["seal_hash"] = "0" * 64
    record["seal_hash"] = sha256(compact(record))
    return record


def make_signatures(record, sd, *, approved=None, signed_at=None, key=approver_key):
    ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval",
          "decision_id": record["decision_id"], "stage_id": "o1", "outcome": "approved", "shown_spec_digest": sd,
          "shown_view_digest": sha256(VIEW), "approved_spec_digest": approved or sd, "signed_at": signed_at or T["approval"],
          "signature": {"algorithm": "Ed25519", "key_ref": APPROVER_KEY, "value_b64": ""}}
    ps["signature"]["value_b64"] = b64(key.sign(SIG.person_signed_bytes(ps)))
    return {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps]}


def receipt_urn(r):
    return f"urn:aee:{HARNESS_ISS}:receipt:{r[2]}#record_hash={AEE.record_hash(r).hex()}"


def head_stages(sd, approval_at=None):
    approval_at = approval_at or T["approval"]
    return [
        {"stage_id": "p1", "kind": "proposal", "at": T["proposal"], "origin": "ai", "spec_digest": sd,
         "deployer_role_pointer": "urn:example:role:invoicing-drafting", "system_name": "invoicing-assistant", "version": "2"},
        {"stage_id": "v1", "kind": "review", "at": T["review"], "reviewer_ref": APPROVER, "shown_spec_digest": sd,
         "proposal_ref": "p1", "shown_view_ref": "urn:example:finance-console:view:INV-2026-0912", "shown_view_digest": sha256(VIEW)},
        {"stage_id": "o1", "kind": "outcome", "at": approval_at, "review_ref": "v1", "outcome": "approved",
         "actor_ref": APPROVER, "method": "Ed25519 signature over the DPS person_approval assertion",
         "approved_spec_digest": sd, "request_limit": 1, "authority": {"authority_ref": POLICY_REF},
         "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": approval_at,
                       "text_ref": "urn:example:rationale:INV-2026-0912"},
         "core_ref": {"field": "review_log", "index": 0}}]


def tail_stages(sd, receipts, *, with_request=True):
    outcome, result = receipts[3], receipts[4]
    tail = []
    if with_request:
        tail += [{"stage_id": "q1", "kind": "request", "at": T["request"], "request_id": REQUEST_ID, "authorised_by": "o1",
                  "spec_digest": sd, "requested_by": "urn:example:service:invoicing-assistant"},
                 {"stage_id": "c1", "kind": "recheck", "at": T["recheck"], "request_ref": "q1", "result": "authorised",
                  "authority_source_ref": POLICY_REF}]
    attempt = {"stage_id": "x1", "kind": "attempt", "at": T["attempt"], "spec_digest": sd, "executor_ref": HARNESS_ISS,
               "trace_refs": [receipt_urn(outcome), TXN]}
    if with_request:
        attempt.update(request_ref="q1", recheck_ref="c1")
    tail += [attempt,
             {"stage_id": "r1", "kind": "result", "at": T["result"], "attempt_ref": "x1", "observed": "succeeded",
              "basis": "executor_observation",
              "evidence_ref": receipt_urn(result) + "&response_digest=" + result[13][1].hex()}]
    return tail


def attachment(sd, spec_bytes, stages):
    return {"profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": DECISION_ID,
            "action_specifications": [{"spec_digest": sd, "representation": {"kind": "original_bytes", "media_type": "application/json"},
                                       "content": {"availability": "available", "bytes_b64": b64(spec_bytes)},
                                       "summary": {"operation": SPEC["operation"], "target": SPEC["target"],
                                                   "policy_version": POLICY_VERSION, "input_version_refs": SPEC["input_version_refs"]}}],
            "stages": stages}


def seal(att, sealed_at, key=issuer_key):
    att["issuer_signature"] = {"algorithm": "Ed25519", "key_ref": ISSUER_KEY, "signed_bytes_ref": "dps-signatures 0.2.0 organisation_seal",
                               "sealed_at": sealed_at, "value_b64": "A" * 88}
    att["issuer_signature"]["value_b64"] = b64(key.sign(SIG.seal_signed_bytes(AB.seal_assertion(att))))
    return att


# ---- route 1: the separate Signed Statement (our draft, Section 5.4)
def typed_ref(kind, hexdigest, namespace=NS):
    return {1: f"{namespace}.{kind}", 2: "SHA-256", 3: hexdigest}


def binding_statement(refs, decision_id=DECISION_ID, key=issuer_key, issued_at=None):
    """COSE_Sign1 in the shape of RFC 9943 Section 6: alg, content type (ours), kid, CWT Claims iss (the DPS issuer)
    and sub (the decision record), and a CBOR payload: the typed digest references and the moment of issue. Its content
    type is not one of the author's Section 12.1 media types, so his type-keyed Registration Policy does not apply to
    it; a TS accepting it does so under its own policy (our Section 5.4)."""
    payload_map = {1: refs, 2: ms(issued_at or T["binding"]),
                   3: "the DPS signed outcome o1 is the record of the confirmation the confirm receipt (ref 3) required; "
                      "the allow outcome (ref 4) is the call that proceeded on it"}
    payload = AEE.canonical(payload_map)
    protected = cbor2.dumps({1: AEE.EDDSA, 3: BINDING_MEDIA, 4: ISSUER_KEY.encode(),
                             15: {1: "urn:example:issuer:example-corp", 2: f"urn:example:decision-records:{decision_id}"}}, canonical=True)
    sig = key.sign(AEE.sig_structure(protected, payload))
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, sig]))


def make_refs(a2_bytes, sig_bytes, receipts):
    return [typed_ref("action_binding_attachment", sha256(a2_bytes)), typed_ref("signatures_attachment", sha256(sig_bytes)),
            typed_ref("execution_receipt", AEE.record_hash(receipts[2]).hex(), AEE_NS),
            typed_ref("execution_receipt", AEE.record_hash(receipts[3]).hex(), AEE_NS)]


# ---- the build
def build(route2=False):
    record = make_record()
    spec_bytes = compact(SPEC)
    sd = sha256(spec_bytes)
    sig = make_signatures(record, sd)
    sig_bytes = compact(sig)
    a1 = seal(attachment(sd, spec_bytes, head_stages(sd)), T["a1_sealed"])
    a1_bytes = compact(a1)
    principal = principal_of(APPROVER_CANONICAL_ID)
    route2_refs = None
    if route2:
        # the proposal: the allow outcome cites what existed when it was recorded, A1 and the signatures attachment
        route2_refs = [{1: f"{NS}.action_binding_attachment", 2: digest(a1_bytes)}, {1: f"{NS}.signatures_attachment", 2: digest(sig_bytes)}]
    receipts = make_receipts(principal, route2_refs=route2_refs)
    a2 = seal(attachment(sd, spec_bytes, copy.deepcopy(head_stages(sd)) + tail_stages(sd, receipts)), T["a2_sealed"])
    a2_bytes = compact(a2)
    refs = make_refs(a2_bytes, sig_bytes, receipts)
    art = {"record": record, "record_bytes": compact(record), "spec_bytes": spec_bytes, "sig": sig, "sig_bytes": sig_bytes,
           "a1": a1, "a1_bytes": a1_bytes, "a2": a2, "a2_bytes": a2_bytes, "receipts": receipts, "bundle": make_bundle(receipts),
           "binding": binding_statement(refs), "route2": route2, "pepper": PEPPER, "canonical_id": APPROVER_CANONICAL_ID}
    return art


def rebuild_after(art):
    """A2's attempt and result cite the receipts held now, A2 is sealed again, the Bundle and the route 1 statement are
    rebuilt from the artefacts held: a failing case that changes a receipt is then caught where the change is, not in a
    stale citation."""
    sd = sha256(art["spec_bytes"])
    stages = copy.deepcopy(art["a2"]["stages"])
    kinds = {s["kind"] for s in stages}
    head = [s for s in stages if s["kind"] in ("proposal", "review", "outcome")]
    art["a2"] = seal(attachment(sd, art["spec_bytes"], head + tail_stages(sd, art["receipts"], with_request="request" in kinds)),
                     T["a2_sealed"])
    art["a2_bytes"] = compact(art["a2"])
    art["bundle"] = make_bundle(art["receipts"])
    art["binding"] = binding_statement(make_refs(art["a2_bytes"], art["sig_bytes"], art["receipts"]))


TRUST = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0", "policy_ref": "urn:example:trust-policy:verifier-1",
         "tsas": [], "checkpoint_sources": [],
         "keys": [{"key_ref": APPROVER_KEY, "holder": APPROVER, "role": "person", "algorithm": "Ed25519",
                   "public_key_hex": raw_public(approver_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                   "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:people"},
                  {"key_ref": ISSUER_KEY, "holder": "Example Corp", "role": "organisation", "algorithm": "Ed25519",
                   "public_key_hex": raw_public(issuer_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                   "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:organisations"}]}
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
            "a1": ("extensions/action-binding/schemas/execution-evidence.schema.json", art["a1"]),
            "a2": ("extensions/action-binding/schemas/execution-evidence.schema.json", art["a2"]),
            "signatures": ("extensions/signatures/schemas/signatures-attachment.schema.json", art["sig"])}
    return {k: [e.message[:160] for e in Draft202012Validator(json.loads((REPO / p).read_text()), registry=registry).iter_errors(d)]
            for k, (p, d) in docs.items()}


def dps_checks(art, which):
    att = art[which]
    rb = art["record_bytes"]
    try:
        ab = AB.check_attachment(att, rb)
    except Exception as e:                                 # noqa: BLE001  (the Standard's checker on a malformed attachment)
        return {"dimensions": {d: f"error: {type(e).__name__}: {e}" for d in DIMENSIONS}, "findings": {}, "issuer_seal": "not_checked",
                "person_approval": {"status": "not_checked"}, "trust_policy": "not_checked"}
    report = AB.reference_report([att], {DECISION_ID: rb}, TRUST, art["sig"])
    res = report["results"][0]
    _pol, persons, _s, _t = SIG.run_context({"attachment": art["sig"], "export": None, "policy": TRUST, "action_binding": {DECISION_ID: att}})
    person = persons[0] if persons else {"status": "absent: no person signature"}
    return {"dimensions": {d: ab[d][0] for d in DIMENSIONS}, "findings": {d: ab[d][1] for d in DIMENSIONS if ab[d][1]},
            "issuer_seal": res["issuer_signature"].get("status") if isinstance(res["issuer_signature"], dict) else res["issuer_signature"],
            "person_approval": {k: (person[k]["status"] if isinstance(person.get(k), dict) else person.get(k))
                                for k in ("status", "signature", "subject", "key_state", "identity")},
            "trust_policy": report["trust_policy"]["status"]}


def read_binding(data, held):
    """Our side's reading of the route 1 statement: signature by the DPS issuer, payload shape, each reference resolved
    against the bytes held (the attachment and signatures attachment by SHA-256 of exact bytes, the receipts by their
    record-hash, the profile's own value, as our Section 5.4 does for a closed receipt)."""
    out = {"signature": None, "references": []}
    try:
        pb, protected, _u, payload, sig = AEE.parse_cose_sign1(data, "binding statement")
        issuer_key.public_key().verify(sig, AEE.sig_structure(pb, payload))
        out["signature"] = "verified" if protected.get(3) == BINDING_MEDIA and protected.get(15, {}).get(1) == "urn:example:issuer:example-corp" \
            else "verified, but header not ours"
        pay = AEE.decode_canonical(payload, "binding payload")
        for ref in pay[1]:
            t, alg, d = ref[1], ref[2], ref[3]
            if alg != "SHA-256":
                state = "Failed: digest algorithm"
            elif t not in held:
                state = "Unresolved: type not held"
            else:
                state = "Verified" if d in held[t] else "Failed: not the digest of the bytes held"
            out["references"].append({"type": t, "digest": d, "state": state})
        out["sub"] = protected.get(15, {}).get(2)
    except Exception as e:                                 # noqa: BLE001
        out["signature"] = f"failed: {e}"
    out["bound"] = out["signature"] == "verified" and bool(out["references"]) and all(r["state"] == "Verified" for r in out["references"])
    return out


def read_route2(receipts, held):
    """Our side's reading of the proposed key 30 on the allow outcome, verified only here."""
    outcome = receipts[3]
    if 30 not in outcome:
        return {"present": False, "bound": False}
    refs = [{"type": e[1], "digest": e[2][1].hex(), "state": ("Verified" if e[2][1].hex() in held.get(e[1], ()) else "Failed")}
            for e in outcome[30]]
    return {"present": True, "references": refs, "bound": all(r["state"] == "Verified" for r in refs)}


def joins(art, aee):
    rs = art["receipts"]
    if len(rs) < 5:                                        # a chain without the outcome or the tool_result (N11)
        return {"J1..J7": "not evaluated: the chain has no outcome or tool_result to join on"}
    confirm, outcome, result = rs[2], rs[3], rs[4]
    a2, a1 = art["a2"], art["a1"]
    st = {s["stage_id"]: s for s in a2["stages"]}
    o1, q1, x1, r1 = st.get("o1", {}), st.get("q1"), st.get("x1", {}), st.get("r1", {})
    ps = (art["sig"].get("person_signatures") or [{}])[0]
    spec = json.loads(art["spec_bytes"])
    args = compact(spec["parameters"])
    rh = {s: AEE.record_hash(r).hex() for s, r in enumerate(rs)}
    a1_head = [{k: v for k, v in s.items()} for s in a1["stages"]]
    return {
        "J1 the confirm receipt's request_digest is the SHA-256 of the parameters of the approved specification (the tool "
        "arguments the Harness hashed), its target the specification's operation and its egress_host the host of its target":
            confirm[12][1].hex() == sha256(args) and confirm[16] == spec["operation"] and confirm[17] == urlsplit(spec["target"]).hostname
            and o1.get("approved_spec_digest") == sha256(art["spec_bytes"]),
        "J2 the person's approval (verified by the Standard) names the same specification, and was signed after the confirm "
        "receipt and before the allow outcome (6.7: the call did not proceed until the outcome)":
            ps.get("approved_spec_digest") == o1.get("approved_spec_digest") == sha256(art["spec_bytes"])
            and confirm[14] < ms(o1.get("at", T["task_start"])) < outcome[14] and ms(ps.get("signed_at", T["task_start"])) == ms(o1["at"]),
        "J3 the allow outcome resolves the confirm (verifier: confirm_seq, same parent_seq, target, request_digest, Task) and is "
        "recorded after the DPS request stage authorised by o1 (no allow without a request)":
            aee.get("confirm_outcomes", {}).get(2) == 3 and q1 is not None and q1.get("authorised_by") == "o1"
            and ms(q1["at"]) <= outcome[14] and x1.get("request_ref") == "q1",
        "J4 the DPS attempt cites the allow outcome by record-hash (trace_refs) and the result cites the tool_result by "
        "record-hash and response_digest, under the issuer's seal":
            receipt_urn(outcome) in x1.get("trace_refs", []) and r1.get("evidence_ref", "").startswith(receipt_urn(result))
            and r1.get("evidence_ref", "").endswith("response_digest=" + result[13][1].hex())
            and rh[3] in receipt_urn(outcome) and rh[4] in receipt_urn(result),
        "J5 the receipts' principal is SHA-256 over the Harness pepper and the canonical identifier of the person o1 names "
        "(Section 3; pepper obtained from the Harness out of band, test value here)":
            confirm[10] == principal_of(f"user:{o1.get('actor_ref')}@example.com", art["pepper"]) == outcome[10],
        "J6 A2 extends A1: A1's stages (proposal, review, outcome) are A2's first stages unchanged, and the same person "
        "signature stands beside both":
            [{k: v for k, v in s.items()} for s in a2["stages"][:3]] == a1_head and a1["decision_id"] == a2["decision_id"],
        "J7 the agent asked for this call: agent_sig on the confirm receipt verified with the agent key (6.7)":
            15 in confirm and any("agent_sig verified on 1" in c["check"] for c in aee.get("checks", [])),
    }


def verify(art):
    AEE.ACCEPT_PROPOSED_KEYS.clear()
    if art["route2"]:
        AEE.ACCEPT_PROPOSED_KEYS.add(30)
    r = {"route": "2 (proposal: key 30 on the allow outcome)" if art["route2"] else "1 (separate Signed Statement)",
         "schema_errors": schema_errors(art)}
    r["aee"] = AEE.verify_bundle(art["bundle"], issuer_public_key=harness_key.public_key(), agent_public_key=agent_key.public_key())
    r["dps_a1"] = dps_checks(art, "a1")
    r["dps_a2"] = dps_checks(art, "a2")
    held = {f"{NS}.action_binding_attachment": {sha256(art["a2_bytes"]), sha256(art["a1_bytes"])},
            f"{NS}.signatures_attachment": {sha256(art["sig_bytes"])},
            f"{AEE_NS}.execution_receipt": {AEE.record_hash(x).hex() for x in art["receipts"]}}
    r["route1"] = read_binding(art["binding"], held)
    r["route2"] = read_route2(art["receipts"], held)
    r["joins"] = joins(art, r["aee"])
    # why the route 1 statement lives beside the Bundle, not in it: Section 9 step 3 on a foreign type
    probe = AEE.verify_bundle(make_bundle(art["receipts"], [art["binding"]]), issuer_public_key=harness_key.public_key(),
                              agent_public_key=agent_key.public_key())
    r["binding_inside_bundle_probe"] = {"result": probe["result"], "error": probe.get("error"), "detail": probe.get("detail")}
    # A1 has no execution stages yet: its recheck and result dimensions are not_checked by design; A2 must verify on all eight
    dps_ok = all(all(v == "verified" or (k == "dps_a1" and v == "not_checked" and d in ("authorisation_recheck", "observed_results"))
                     for d, v in r[k]["dimensions"].items()) and r[k]["issuer_seal"] == "verified"
                 and r[k]["person_approval"]["status"] == "verified" and r[k]["trust_policy"] == "verified" for k in ("dps_a1", "dps_a2"))
    r["all_verified"] = (not any(r["schema_errors"].values()) and r["aee"]["result"] == "CHECKS_PERFORMED" and dps_ok
                         and r["route1"]["bound"] and (r["route2"]["bound"] if art["route2"] else not r["route2"]["present"])
                         and all(v is True for v in r["joins"].values()))
    AEE.ACCEPT_PROPOSED_KEYS.clear()
    return r


def write(out, art):
    out.mkdir(parents=True, exist_ok=True)
    (out / "decision-record.json").write_bytes(art["record_bytes"])
    (out / "action-binding-attachment-a1.json").write_bytes(art["a1_bytes"])
    (out / "action-binding-attachment-a2.json").write_bytes(art["a2_bytes"])
    (out / "signatures-attachment.json").write_bytes(art["sig_bytes"])
    (out / "action-specification.json").write_bytes(art["spec_bytes"])
    (out / "tool-arguments.json").write_bytes(compact(json.loads(art["spec_bytes"])["parameters"]))
    (out / "tool-response.json").write_bytes(RESPONSE)
    (out / "policy.json").write_bytes(policy_bytes)
    (out / "review-view.txt").write_bytes(VIEW)
    (out / "trust-policy.json").write_bytes(compact(TRUST))
    (out / "harness-pepper.txt").write_bytes(art["pepper"] + b"\n")
    (out / "aee-bundle.cbor").write_bytes(art["bundle"])
    (out / "binding-statement.cose").write_bytes(art["binding"])
    (out / "binding-statement.cose.hex").write_text(art["binding"].hex() + "\n")
    for r in art["receipts"]:
        (out / f"receipt-{r[2]}.cbor").write_bytes(AEE.canonical(r))
    (out / "receipts.diag.json").write_text(json.dumps([diag(r) for r in art["receipts"]], indent=1) + "\n")
    (out / "keys.json").write_text(json.dumps({"harness_evidence_service_ed25519_pub": raw_public(harness_key).hex(),
                                               "agent_ed25519_pub": raw_public(agent_key).hex(),
                                               "finance_controller_ed25519_pub": raw_public(approver_key).hex(),
                                               "dps_issuer_ed25519_pub": raw_public(issuer_key).hex(),
                                               "note": "test keys from fixed seeds; never use them for anything real"}, indent=1) + "\n")


def diag(v):
    if isinstance(v, bytes):
        return "h'" + v.hex() + "'"
    if isinstance(v, dict):
        return {str(k): diag(x) for k, x in v.items()}
    if isinstance(v, list):
        return [diag(x) for x in v]
    return v


if __name__ == "__main__":
    out = HERE / "out"
    art = build()
    write(out, art)
    results = verify(art)
    results["appendix_a_reproduction"] = AEE.appendix_a_reproduction()
    art2 = build(route2=True)
    write(out / "proposal", art2)
    results["proposal_route2"] = verify(art2)
    results["all_verified"] = results["all_verified"] and results["proposal_route2"]["all_verified"] \
        and all(v["agree"] for k, v in results["appendix_a_reproduction"].items() if not k.startswith("_") and v["agree"] is not None)
    (out / "summary.json").write_text(json.dumps(results, ensure_ascii=False, indent=1, default=str) + "\n")
    print(json.dumps(results, ensure_ascii=False, indent=1, default=str))
    sys.exit(0 if results["all_verified"] else 1)
