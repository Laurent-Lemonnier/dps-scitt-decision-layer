#!/usr/bin/env python3
"""A decision and the authority behind it, composed: one synthetic insurance advice in a brokerage firm, recorded
twice.

  Decision Provenance Standard    what the adviser decided, on what, shown what, and the exact recommendation she
                                  approved and that was issued: a decision record, an action-binding attachment
                                  (0.3.0) under the firm's seal, her signature (signatures 0.2.0), at main 007f8c9
  Operating Model Protocol        whether the named adviser held the mandate at that moment: an Audit Trace with
                                  the authority_binding object of draft-veridom-omp-core-00, whose delegation
                                  instrument is the adviser's mandate, built from the text with omp_from_text.py

Two variants, both expected results, neither a failure:
  bound            the mandate is in the firm's authority registry before the decision: BOUND, ALLOWED, issued
  unbound-sealed   the same mandate, time-stamped before the decision, in a firm that keeps no registry:
                   AUTHORITY_UNBOUND, BLOCKED, sealed; the adviser approved, the recheck refused, nothing was issued

Then the joins between the two records (same person, same decision, same instrument, the references, the
permission against the recheck, the moments in order, the instrument against the approved action), and
our own inputs for the twenty conformance cases of core-00 Section 5. The failing cases are in negatives.py.

Everything is synthetic: no firm, person, client, contract or registration here exists. Test keys from fixed seeds,
a test time-stamping authority (the Standard's own test generator): never use them for anything real.
Exit code 0 when both variants give what is expected and every Section 5 case gives what the text states.
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
# the DPS Standard checkout (read only): DPS_STANDARD, else the clone run.sh makes
REPO = pathlib.Path(os.environ.get("DPS_STANDARD") or HERE.parent / "aqta/approval-record/dps-standard")
TEMPLATE = pathlib.Path(os.environ.get("DPS_RECORD_TEMPLATE") or HERE.parents[1] / "examples/release-decision/decision-record.json")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AB = load("ab", REPO / "extensions/action-binding/tests/run_checks.py")
SIG = load("sig", REPO / "extensions/signatures/tests/run_checks.py")
GEN = load("gen", REPO / "extensions/anchoring/tests/generate_vectors.py")     # the Standard's test TSA, nothing else
OMP = load("omp_from_text", HERE / "omp_from_text.py")


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
    return str(uuid.UUID(bytes=hashlib.sha256(text.encode()).digest()[:16], version=4))


# ---------------------------------------------------------------- keys (TEST ONLY) and who is who

FIRM = "Example Brokerage (synthetic)"
PEOPLE = {
    "adviser-1": {"name": "Adviser One (synthetic)", "role": "insurance adviser, non-life",
                  "key": key_from_seed("dps-scitt-decision-layer omp-authority: adviser-1 key (test only)")},
    "adviser-2": {"name": "Adviser Two (synthetic)", "role": "insurance adviser, life",
                  "key": key_from_seed("dps-scitt-decision-layer omp-authority: adviser-2 key (test only)")},
}
ISSUER_KEY_REF, issuer_key = "example-brokerage-seal-1", key_from_seed(
    "dps-scitt-decision-layer omp-authority: firm seal key (test only)")
TSA_KEY = GEN.p256_key("dps-scitt-decision-layer omp-authority: time-stamping authority (test only)")
TSA_CERT = GEN.tsa_certificate(TSA_KEY, 7, 7007)
TRUST = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0",
         "policy_ref": "urn:example:trust-policy:verifier-1", "tsas": [], "checkpoint_sources": [],
         "keys": [{"key_ref": f"{p}-key-1", "holder": p, "role": "person", "algorithm": "Ed25519",
                   "public_key_hex": raw_public(v["key"]).hex(), "not_before": "2026-03-01T00:00:00Z",
                   "not_after": "2027-02-28T23:59:59Z", "identity_source_ref": "urn:example:brokerage:directory:people"}
                  for p, v in PEOPLE.items()]
         + [{"key_ref": ISSUER_KEY_REF, "holder": FIRM, "role": "organisation", "algorithm": "Ed25519",
             "public_key_hex": raw_public(issuer_key).hex(), "not_before": "2026-03-01T00:00:00Z",
             "not_after": "2027-02-28T23:59:59Z", "identity_source_ref": "urn:example:directory:organisations"}]}

# ---------------------------------------------------------------- the scenario (every value synthetic)

DEMANDS_AND_NEEDS = (
    "Client file CF-2026-0042 (synthetic). A bakery with two employees, tenant of its premises.\n"
    "Demands: cover for the premises and the equipment, operating loss after a fire or an oven breakdown, "
    "public and product liability.\nNeeds stated: the oven is nine years old; a closure of more than five days "
    "would threaten the business; budget about 1,500 EUR a year.\n").encode("utf-8")
OPTIONS = {
    "A": {"contract": "Pro Essentials (Insurer A, synthetic)", "product_class": "non-life.professional-multi-risk",
          "annual_premium": 1190, "note": "premises, equipment and liability; no operating loss after a breakdown"},
    "B": {"contract": "Multi-risk Pro, formula 2 (Insurer B, synthetic)", "product_class": "non-life.professional-multi-risk",
          "annual_premium": 1480, "note": "premises, equipment, liability, operating loss after fire and after "
                                          "equipment breakdown, three-day waiting period"},
    "C": {"contract": "Multi-risk Pro Plus (Insurer C, synthetic)", "product_class": "non-life.professional-multi-risk",
          "annual_premium": 2240, "note": "as B with no waiting period and cover for goods in transit, which the "
                                          "client does not need"},
    # used by one failing case only: a product outside the mandate
    "L": {"contract": "Savings Life Plan (Insurer D, synthetic)", "product_class": "life.insurance-based-investment",
          "annual_premium": 3000, "note": "an insurance-based investment product"},
}
REASONS = (
    "Recommended: B. It is the only option within the stated budget that covers operating loss after an equipment "
    "breakdown, the need the client put first given the oven's age. A leaves that need uncovered. C covers it with no "
    "waiting period but exceeds the budget by half for a cover (goods in transit) the client does not use.\n").encode("utf-8")

BASE = {
    "variant": "bound",
    "decision_id": "DR-2026-110901",
    "approver": "adviser-1",            # who reviews, approves and signs on the DPS side
    "officer": "adviser-1",             # the Named Accountable Officer on the OMP side
    "recommended": "B",
    "registry": True,                   # the firm keeps an authority registry
    "selection_mode": "pre_registered",
    "mandate": {"officer_id": "adviser-1", "effective_date": "2026-03-01", "expiry_date": "2027-02-28",
                "product_scope": ["non-life.professional-multi-risk", "non-life.liability"], "max_premium": 5000},
    "registry_status": "ACTIVE",
    "T": {"registered": "2026-03-02T09:00:00.000Z", "registration_token": "2026-03-02T09:00:05Z",
          "received": "2026-11-09T10:02:00.000Z", "created": "2026-11-09T10:02:00.500Z",
          "routed": "2026-11-09T10:02:01.000Z", "selected": "2026-11-09T10:02:01.200Z",
          "binding_token": "2026-11-09T10:02:02Z",
          "proposal": "2026-11-09T10:03:00Z", "review": "2026-11-09T10:10:00Z", "approval": "2026-11-09T10:12:00Z",
          "omp_sealed": "2026-11-09T10:12:05.000Z", "omp_token": "2026-11-09T10:12:06Z",
          "request": "2026-11-09T10:12:30Z", "recheck": "2026-11-09T10:12:40Z", "attempt": "2026-11-09T10:12:45Z",
          "result": "2026-11-09T10:13:00Z", "closed": "2026-11-09T10:20:00Z", "dps_sealed": "2026-11-09T10:20:30Z",
          "valid_until": "2026-11-09T11:12:00Z"},
}
VARIANTS = {
    "bound": {},
    # The firm's situation the author described on 2 November 2026: a mandate, no registry. The mandate's hash is
    # time-stamped before the decision all the same (the question put to him that day, not answered yet).
    "unbound-sealed": {"variant": "unbound-sealed", "decision_id": "DR-2026-110902", "registry": False},
}
DECISION_TYPE = "insurance_advice.personalised_recommendation"
CLIENT_FILE = "urn:example:brokerage:client-file:CF-2026-0042"
SERIALS = {"registration": 9001, "binding": 9002, "trace": 9003}


def scenario(variant="bound", **over):
    s = copy.deepcopy(BASE)
    for src in (VARIANTS[variant], over):
        for k, v in src.items():
            if isinstance(v, dict) and isinstance(s.get(k), dict):
                s[k].update(v)
            else:
                s[k] = copy.deepcopy(v)
    return s


def token(data, at, serial):
    """A time-stamp token of the TEST authority over data, genTime `at`. Deterministic."""
    return GEN.make_token(TSA_KEY, TSA_CERT, data, GEN.when(at), serial)[0]


# ---------------------------------------------------------------- the OMP side

def make_mandate(S):
    """The authority document: the firm's written mandate to one adviser. A JSON document here (A1)."""
    m = S["mandate"]
    return {
        "document": "mandate to give insurance advice in the firm's name (synthetic)",
        "instrument_id": "M-2026-03",
        "issued_by": {"firm": FIRM, "company_registration": "RCS-SYNTHETIC-000000000",
                      "intermediary_registration": "ORIAS-SYNTHETIC-00000000",
                      "signed_by": "the firm's managing director (synthetic)", "issued_on": "2026-02-27"},
        "officer": {"officer_id": m["officer_id"], "name": PEOPLE[m["officer_id"]]["name"],
                    "role": PEOPLE[m["officer_id"]]["role"]},
        "mandate": {"text": "May give personalised recommendations on the contracts in scope to the firm's clients, "
                            "and approve their issue to the client, within the limits below.",
                    "decision_types": [DECISION_TYPE], "jurisdictions": ["FR"], "product_scope": m["product_scope"],
                    "annual_premium_limit": {"currency": "EUR", "max_amount": m["max_premium"]}},
        "effective_date": m["effective_date"], "expiry_date": m["expiry_date"],
    }


def registry_state(S, mandate, as_of=None, registered_at=None):
    """A4: one state of the firm's authority registry, as a JSON document. The firm keeps it: the same party."""
    return {"registry_id": "urn:example:brokerage:authority-registry", "as_of": as_of or S["T"]["routed"],
            "entries": [{"instrument_id": mandate["instrument_id"], "instrument_hash": OMP.instrument_hash(mandate),
                         "registered_at": registered_at or S["T"]["registered"], "status": S["registry_status"]}]}


def candidate_instrument(S, mandate, snapshot):
    """The DelegationInstrument of core-00 section 4.1, read off the mandate and the registry."""
    i = {
        "instrument_id": mandate["instrument_id"],
        "officer_id": mandate["officer"]["officer_id"],
        "role_identifier": mandate["officer"]["role"],
        "mandate_scope": mandate["mandate"]["text"],
        "scope_constraints": {"decision_types": mandate["mandate"]["decision_types"],
                              "jurisdictions": mandate["mandate"]["jurisdictions"],
                              "product_scope": mandate["mandate"]["product_scope"],
                              "monetary_limit": mandate["mandate"]["annual_premium_limit"]},
        "effective_date": mandate["effective_date"], "expiry_date": mandate["expiry_date"],
        # what the emitter writes; the registry state has its own word (a failing case makes the two differ)
        "revocation_status_at_decision": S.get("stated_status") or S["registry_status"],
        # 4.4.2, corporate_delegation: "the corporate registration number and the specific delegation instrument".
        # A17: one string for two things, and no member for the firm's own registration above it.
        "issuing_authority_id": f"{mandate['issued_by']['company_registration']}#{mandate['instrument_id']}",
        "authority_root_type": "corporate_delegation",
        "instrument_hash": OMP.instrument_hash(mandate),
        "instrument_reference": f"urn:example:brokerage:mandates:{mandate['instrument_id']}",
        "instrument_selection_mode": S["selection_mode"],
        "instrument_selected_at": S["T"]["selected"],
    }
    if snapshot is not None:
        i["authority_registry_snapshot_hash"] = OMP.registry_snapshot_hash(snapshot)
        i["registry_inclusion_proof"] = None
    return i


def decision_context(S):
    o = OPTIONS[S["recommended"]]
    return {"decision_type": DECISION_TYPE, "jurisdiction": "FR", "product": o["product_class"],
            "amount": {"currency": "EUR", "value": o["annual_premium"]}}


def make_trace(S, authority_binding, spec_digest, dn_digest):
    """The Audit Trace of omp-00 section 7 with core-00's members, unsealed. The routing is the tree of omp-00 5.1:
    a Watchtower of this synthetic deployment sends every personalised recommendation to a named adviser."""
    T = S["T"]
    weights = {"C_m": 0.5, "C_p": 0.3, "C_d": 0.2}
    comp = {"C_m": 0.9, "C_p": 1.0, "C_d": 0.8, "weights": weights}
    payload = {"client_file": CLIENT_FILE, "request": "advice on professional multi-risk cover",
               "demands_and_needs_digest": "sha256:" + dn_digest}
    officer = S["officer"]
    trace = {
        "trace_id": uuid4_from(f"omp-authority trace {S['decision_id']}"), "trace_version": "1.0",
        "created_at": T["created"], "vertical": "insurance-distribution-fr (synthetic; no such profile is published)",
        "deployment_id": "example-brokerage-1", "schema_version": OMP.SCHEMA_VERSION,
        "interaction_id": uuid4_from(f"omp-authority interaction {S['decision_id']}"),
        "interaction_received": T["received"], "interaction_hash": sha256(OMP.jcs(payload)),
        "channel": "adviser-console", "requester_id": "client-file-CF-2026-0042 (synthetic)",
        "intent_class": DECISION_TYPE, "intent_confidence": 0.94,
        "intent_top3": [{"class": DECISION_TYPE, "confidence": 0.94},
                        {"class": "insurance_information.no_advice", "confidence": 0.04},
                        {"class": "claims.question", "confidence": 0.02}],
        "classifier_version": "synthetic-1",
        "confidence_score": weights["C_m"] * comp["C_m"] + weights["C_p"] * comp["C_p"] + weights["C_d"] * comp["C_d"],
        "confidence_components": comp, "routing_threshold": 0.95,
        "watchtowers_evaluated": [{"watchtower_id": "WT-EX-ADVICE", "triggered": True, "severity": "FORCE_ASSISTED",
                                   "evidence": {"rule": "a personalised recommendation is reviewed by a named adviser"},
                                   "evaluated_at": T["created"]}],
        "watchtower_override": True, "override_watchtower_id": "WT-EX-ADVICE",
        "routing_path": "ASSISTED", "routing_rationale": "omp-00 5.1 step 3: FORCE_ASSISTED from WT-EX-ADVICE",
        "routing_decided_at": T["routed"],
        "autonomous_dispatch": None,
        # A15: omp-00 types this member "object | null" and says of RA-1 only "Officer ID and approval timestamp
        # logged". The digest of the response the officer approved has no member; it is carried here.
        "assisted_resolution": {"resolution_action": "RA-1 APPROVE",
                                "officer_id": S.get("resolution_officer") or S["approver"],
                                "approved_at": T["approval"].replace("Z", ".000Z"),
                                "proposed_response_hash": "sha256:" + spec_digest},
        "escalation_record": None,
        "source_state_hash": None,
        "routing_state": "ASSISTED",
        "authority_binding": authority_binding,
        "decision_context": decision_context(S),
    }
    if authority_binding["authority_binding_result"] == "BOUND":
        trace["named_accountable_officer"] = {"officer_id": officer, "role": PEOPLE[officer]["role"]}
    return trace


def seal_trace(trace, sealed_at, token_at, serial=SERIALS["trace"], previous=None):
    """omp-00 section 8: content hash, time-stamp token over it, chain hash. A18: the institution's signature is
    optional (core-00 3.2) and has no member in section 7; none is made."""
    for k in OMP.SEAL_EXCLUDED_8_2 + OMP.SEAL_EXCLUDED_OURS:
        trace.pop(k, None)
    trace["tst_hash_alg"] = "SHA-256"
    content = OMP.trace_content_hash(trace)
    tok = token(OMP.trace_content_bytes(trace), token_at, serial)
    read = OMP.read_tst(tok, TSA_CERT)
    trace.update({
        "tst_time": OMP.iso_ms(read["gen_time"]), "tst_tsa_identity": read["tsa"], "tst_raw": b64(tok),
        "tst_serial": read["serial"], "tst_message_imprint": content, "tst_certificate": b64(TSA_CERT),
        "trace_content_hash": content,
        "trace_chain_hash": OMP.chain_hash(content, previous or OMP.genesis_hash(trace["deployment_id"])),
        "sealed_at": sealed_at, "seal_version": OMP.SEAL_VERSION})
    return trace


def bind(S, instrument, mandate, snapshot, forced=None):
    """Evaluates Invariant 3 and writes the authority_binding object with its binding token. forced: a result an
    emitter writes whatever the evaluation says (the failing cases); the token and the seal are then valid over a
    record whose content is wrong."""
    ev = OMP.evaluate("ASSISTED", S["officer"], instrument, decision_context(S), OMP.instant(S["T"]["routed"]),
                      authority_document=mandate, registry_snapshot=snapshot,
                      binding_time=GEN.when(S["T"]["binding_token"]))
    shown = dict(ev, authority_binding_result="BOUND", execution_permission="ALLOWED", failure_reasons=[]) \
        if forced == "BOUND" else ev
    ab = OMP.authority_binding_object(shown, instrument, S["officer"])
    tok = token(OMP.binding_subject(ab), S["T"]["binding_token"], SERIALS["binding"])
    OMP.set_binding_timestamp(ab, OMP.tagged(tok))
    return ev, ab, tok


# ---------------------------------------------------------------- the DPS side

def make_spec(S, mandate, dn_digest):
    o = OPTIONS[S["recommended"]]
    return {"operation": "insurance.advice.issue_recommendation", "target": CLIENT_FILE,
            "parameters": {"advice": "personalised recommendation", "jurisdiction": "FR",
                           "demands_and_needs_digest": dn_digest,
                           "options_considered": sorted(k for k in OPTIONS if k != "L" or S["recommended"] == "L"),
                           "recommended": {"option": S["recommended"], "contract": o["contract"],
                                           "product_class": o["product_class"],
                                           "annual_premium": {"currency": "EUR", "value": o["annual_premium"]}},
                           "reasons_digest": sha256(REASONS)},
            "input_version_refs": [CLIENT_FILE + ":demands-and-needs:1"],
            # the mandate, by the hash the OMP instrument carries: the adviser's signature over this
            # specification's digest covers it (the Steward's reading of policy_version, issue 93, 29 October 2026)
            "policy_version": OMP.instrument_hash(mandate),
            "valid_until": S["T"]["valid_until"]}


def make_view(S, spec, mandate):
    o = OPTIONS[S["recommended"]]
    lines = [f"Advice to client file CF-2026-0042: recommend option {S['recommended']}, {o['contract']}, "
             f"{o['annual_premium']} EUR a year"]
    lines += [f"  option {k}: {v['contract']}, {v['annual_premium']} EUR a year: {v['note']}"
              for k, v in OPTIONS.items() if k in spec["parameters"]["options_considered"]]
    lines += ["Reasons: " + REASONS.decode().strip(),
              f"Demands and needs statement: sha256:{spec['parameters']['demands_and_needs_digest']}",
              f"Under mandate {mandate['instrument_id']} ({spec['policy_version']})",
              f"valid until {spec['valid_until']}"]
    return ("\n".join(lines) + "\n").encode("utf-8")


def make_record(S):
    T, who = S["T"], PEOPLE[S["approver"]]
    o = OPTIONS[S["recommended"]]
    record = json.loads(TEMPLATE.read_bytes())
    record.update({
        "decision_id": S["decision_id"], "created_at": T["proposal"], "charter_id": "CH-EXAMPLE-BROKERAGE-ADVICE-1",
        "record_type": "decision", "record_state": "closed", "dispatch_mode": "mode-1-with-embedded-mode-2-summary",
        "altitude": "team-leader", "decision_class": "insurance-advice",
        "consent_posture": {"posture_class": "synthetic case: the client file is invented, no personal data"},
        "decision_statement": f"Recommend option {S['recommended']}, {o['contract']}, {o['annual_premium']} EUR a year, "
                              "to client file CF-2026-0042 for its professional multi-risk cover, and issue the "
                              "advice statement to the client.",
        "context_at_decision": DEMANDS_AND_NEEDS.decode().replace("\n", " ").strip(),
        "options_considered": [f"Option {k}: {v['contract']}, {v['annual_premium']} EUR a year: {v['note']}"
                               + (" (chosen)" if k == S["recommended"] else "")
                               for k, v in OPTIONS.items() if k != "L" or S["recommended"] == "L"],
        "required_inputs_used": ["demands and needs statement 1 of client file CF-2026-0042",
                                 "the three insurers' terms and tariffs as of 2026-11-02 (synthetic)"],
        "assumptions_depended_on": ["The client's statement of the oven's age and of the five-day threshold is accurate."],
        "success_criteria": ["The client receives the advice statement with the reasons before any contract is concluded."],
        "accountable_owner": {"full_name": who["name"], "role": who["role"], "employer": FIRM},
        "re_decision_trigger": "A change in the client's demands and needs, or in the terms of the recommended contract, "
                               "before conclusion.",
        "drafting_authority": {"deployer_role_pointer": "urn:example:brokerage:role:advice-drafting",
                               "system_name": "advice-assistant", "version": "1"},
        "affirmation_record": {"timestamp": T["approval"], "actor_identity": S["approver"],
                               "method": "Ed25519 signature over the DPS person_approval assertion"},
        "accountable_owner_signoff": {"signed_by": S["approver"], "signed_at": T["closed"]},
        "closed_at": T["closed"], "record_location": f"urn:example:brokerage:decision-records:{S['decision_id']}",
        "supersedes": None,
    })
    record["mode_classification_attestation"].update({
        "attestor_full_name": who["name"], "attestor_role_title": who["role"], "attestor_employer": FIRM,
        "attestation_timestamp": T["closed"], "attestor_capacity": "employee",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 "
                                   "summary under charter CH-EXAMPLE-BROKERAGE-ADVICE-1: the advice assistant drafted "
                                   "the recommendation from the client's demands and needs statement, I reviewed it "
                                   "as shown with the options and the reasons, approved the specification whose "
                                   "digest the attachment names, and I am the accountable owner of this decision."})
    record["seal_hash"] = "0" * 64
    record["seal_hash"] = sha256(compact(record))
    return record


def binding_ref(authority_binding):
    """The typed digest reference the DPS outcome's authority member carries: the OMP authority_binding object, by
    the SHA-256 of its RFC 8785 bytes (core-00 Section 5 case 19 speaks of that hash). Fixed when the binding is
    evaluated, before the approval."""
    return "urn:omp:authority-binding:" + OMP.tagged(OMP.jcs(authority_binding))


def trace_ref(trace):
    """The sealed trace, as the recheck names it: its id and its content hash."""
    return f"urn:omp:audit-trace:{trace['trace_id']}#trace_content_hash={trace['trace_content_hash']}"


def make_attachment(S, record, spec_bytes, view, authority_binding, trace):
    T, sd = S["T"], sha256(spec_bytes)
    spec = json.loads(spec_bytes)
    allowed = authority_binding["execution_permission"] == "ALLOWED"
    stages = [
        {"stage_id": "p1", "kind": "proposal", "at": T["proposal"], "origin": "ai", "spec_digest": sd,
         "deployer_role_pointer": "urn:example:brokerage:role:advice-drafting", "system_name": "advice-assistant",
         "version": "1"},
        {"stage_id": "v1", "kind": "review", "at": T["review"], "reviewer_ref": S["approver"], "shown_spec_digest": sd,
         "proposal_ref": "p1", "shown_view_ref": "urn:example:brokerage:adviser-console:view:CF-2026-0042-1",
         "shown_view_digest": sha256(view)},
        {"stage_id": "o1", "kind": "outcome", "at": T["approval"], "review_ref": "v1", "outcome": "approved",
         "actor_ref": S["approver"], "method": "Ed25519 signature over the DPS person_approval assertion",
         "approved_spec_digest": sd, "request_limit": 1, "authority": {"authority_ref": binding_ref(authority_binding)},
         "rationale": {"timing": "contemporaneous", "ai_assisted": True, "recorded_at": T["approval"],
                       "text_ref": CLIENT_FILE + ":advice-reasons:1"},
         "core_ref": {"field": "affirmation_record"}},
        {"stage_id": "q1", "kind": "request", "at": T["request"],
         "request_id": "urn:example:brokerage:advice-request:" + uuid4_from(f"omp-authority request {S['decision_id']}"),
         "authorised_by": "o1", "spec_digest": sd, "requested_by": "urn:example:brokerage:service:advice-assistant"},
        {"stage_id": "c1", "kind": "recheck", "at": T["recheck"], "request_ref": "q1",
         "result": "authorised" if allowed else "not_authorised", "authority_source_ref": trace_ref(trace),
         **({} if allowed else {"detail": "the sealed OMP trace states execution_permission BLOCKED: "
                                          + ", ".join(authority_binding.get("failure_reasons", []))})},
    ]
    if allowed:
        stages += [
            {"stage_id": "x1", "kind": "attempt", "at": T["attempt"], "request_ref": "q1", "recheck_ref": "c1",
             "spec_digest": sd, "executor_ref": "urn:example:brokerage:service:client-documents",
             "trace_refs": [f"urn:omp:audit-trace:{trace['trace_id']}"]},
            {"stage_id": "r1", "kind": "result", "at": T["result"], "attempt_ref": "x1", "observed": "succeeded",
             "basis": "target_response", "evidence_ref": CLIENT_FILE + ":advice-statement:1"}]
    return {"profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": record["decision_id"],
            "action_specifications": [{
                "spec_digest": sd, "representation": {"kind": "original_bytes", "media_type": "application/json"},
                "content": {"availability": "available", "bytes_b64": b64(spec_bytes)},
                "summary": {"operation": spec["operation"], "target": spec["target"],
                            "policy_version": spec["policy_version"], "input_version_refs": spec["input_version_refs"]}}],
            "stages": stages}


def seal(att, sealed_at):
    att["issuer_signature"] = {"algorithm": "Ed25519", "key_ref": ISSUER_KEY_REF,
                               "signed_bytes_ref": "dps-signatures 0.2.0 organisation_seal", "sealed_at": sealed_at,
                               "value_b64": "A" * 88}
    att["issuer_signature"]["value_b64"] = b64(issuer_key.sign(SIG.seal_signed_bytes(AB.seal_assertion(att))))
    return att


def sign_approval(record, att, view, signer):
    o1 = next(s for s in att["stages"] if s["stage_id"] == "o1")
    sd = o1["approved_spec_digest"]
    ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval",
          "decision_id": record["decision_id"], "stage_id": "o1", "outcome": "approved", "shown_spec_digest": sd,
          "shown_view_digest": sha256(view), "approved_spec_digest": sd, "signed_at": o1["at"],
          "signature": {"algorithm": "Ed25519", "key_ref": f"{signer}-key-1", "value_b64": ""}}
    ps["signature"]["value_b64"] = b64(PEOPLE[signer]["key"].sign(SIG.person_signed_bytes(ps)))
    return {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps]}


# ---------------------------------------------------------------- one composed case

def build(S, forced=None, signer=None):
    """Every artefact of one case, from the scenario S. forced="BOUND": the emitter writes BOUND whatever the
    evaluation says. signer: who signs the approval, when not S["approver"]."""
    mandate = make_mandate(S)
    snapshot = registry_state(S, mandate) if S["registry"] else None
    dn_digest = sha256(DEMANDS_AND_NEEDS)
    spec_bytes = compact(make_spec(S, mandate, dn_digest))
    view = make_view(S, json.loads(spec_bytes), mandate)
    record = make_record(S)
    instrument = candidate_instrument(S, mandate, snapshot)
    ev, ab, binding_token = bind(S, instrument, mandate, snapshot, forced)
    trace = seal_trace(make_trace(S, ab, sha256(spec_bytes), dn_digest), S["T"]["omp_sealed"], S["T"]["omp_token"])
    att = seal(make_attachment(S, record, spec_bytes, view, ab, trace), S["T"]["dps_sealed"])
    return {"S": S, "mandate": mandate, "registry_snapshot": snapshot, "instrument": instrument, "evaluation": ev,
            "registration_token": token(OMP.jcs(mandate), S["T"]["registration_token"], SERIALS["registration"]),
            "binding_token": binding_token, "trace": trace, "record": record, "spec_bytes": spec_bytes, "view": view,
            "attachment": att, "sig": sign_approval(record, att, view, signer or S["approver"])}


def reissue_omp(art, mutate=None, *, sealed_at=None, token_at=None, binding_at=None):
    """The emitter writes its trace again: the binding token and the seal are made again over the changed content,
    so that a failure, if any, is in what the record says and not in a broken hash."""
    trace = art["trace"]
    if mutate:
        mutate(trace)
    ab = trace["authority_binding"]
    tok = token(OMP.binding_subject(ab), binding_at or art["S"]["T"]["binding_token"], SERIALS["binding"])
    OMP.set_binding_timestamp(ab, OMP.tagged(tok))
    art["binding_token"] = tok
    seal_trace(trace, sealed_at or trace["sealed_at"], token_at or art["S"]["T"]["omp_token"])
    return art


def reissue_dps(art, mutate_stages=None):
    """The issuer writes the attachment again and seals it again; the person's signature is made again."""
    att = art["attachment"]
    if mutate_stages:
        mutate_stages({s["stage_id"]: s for s in att["stages"]})
    seal(att, att["issuer_signature"]["sealed_at"])
    signer = art["sig"]["person_signatures"][0]["signature"]["key_ref"][:-len("-key-1")]
    art["sig"] = sign_approval(art["record"], att, art["view"], signer)
    return art


# ---------------------------------------------------------------- checks

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


def dps_report(art):
    record, att = art["record"], art["attachment"]
    record_bytes = compact(record)
    r = {"schema_errors": schema_errors(art)}
    report = AB.reference_report([att], {record["decision_id"]: record_bytes}, TRUST, art["sig"])
    res = report["results"][0]
    r["trust_policy"] = report["trust_policy"]["status"]
    ab = AB.check_attachment(att, record_bytes)
    r["action_binding"] = {d: ab[d][0] for d in DIMENSIONS}
    r["action_binding_findings"] = {d: ab[d][1] for d in DIMENSIONS if ab[d][1]}
    r["issuer_seal"] = {k: res["issuer_signature"].get(k, {}).get("status") if isinstance(res["issuer_signature"].get(k), dict)
                        else res["issuer_signature"].get(k) for k in ("status", "key_state", "holder", "attests")}
    _pol, persons, _s, _t = SIG.run_context({"attachment": art["sig"], "export": None, "policy": TRUST,
                                             "action_binding": {record["decision_id"]: att}})
    r["person_approval"] = {k: persons[0][k]["status"] if isinstance(persons[0][k], dict) else persons[0][k]
                            for k in ("status", "signature", "subject", "key_state", "identity")}
    return r


def held_of(art):
    """What a verifier of the OMP side holds beside the trace. An AUTHORITY_UNBOUND trace does not carry the
    instrument that was tried (A14); the case publishes it beside the trace so that the reasons can be evaluated
    again."""
    h = {"tsa_cert_der": TSA_CERT, "binding_token": art["binding_token"], "authority_document": art["mandate"],
         "registry_snapshot": art["registry_snapshot"]}
    if art["trace"]["authority_binding"]["authority_binding_result"] == "AUTHORITY_UNBOUND":
        h["candidate_instrument"] = art["instrument"]
    return h


HOLDS, NOT = "holds", "does not hold"


def joins(art, omp, dps):
    """What ties the two records, each join on its own, with what it rests on. `omp` is check_trace's report."""
    trace, att, record, sig = art["trace"], art["attachment"], art["record"], art["sig"]
    ab = trace["authority_binding"]
    st = {s["stage_id"]: s for s in att["stages"]}
    ps = sig["person_signatures"][0]
    spec = json.loads(base64.b64decode(att["action_specifications"][0]["content"]["bytes_b64"]))
    bound = ab["authority_binding_result"] == "BOUND"
    instrument = ab["delegation_instrument"] if bound else art.get("instrument")
    res = trace.get("assisted_resolution") or {}
    key = next((k for k in TRUST["keys"] if k["key_ref"] == ps["signature"]["key_ref"]), {})
    J = {}

    people = {
        "omp.named_accountable_officer" if bound else "omp.attempted_officer_id":
            trace["named_accountable_officer"]["officer_id"] if bound else ab.get("attempted_officer_id"),
        "omp.instrument.officer_id" + ("" if bound else " (held beside the trace)"): (instrument or {}).get("officer_id"),
        "omp.assisted_resolution.officer_id": res.get("officer_id"),
        "authority_document.officer.officer_id": art["mandate"]["officer"]["officer_id"],
        "dps.review.reviewer_ref": st["v1"]["reviewer_ref"], "dps.outcome.actor_ref": st["o1"]["actor_ref"],
        "dps.record.affirmation_record.actor_identity": record["affirmation_record"]["actor_identity"],
        "dps.person_approval.key_holder (the verifier's trust policy)": key.get("holder"),
    }
    same = len(set(people.values())) == 1 and dps["person_approval"]["status"] == "verified"
    J["J1 same person"] = {
        "status": HOLDS if same else NOT, "values": people,
        "rests_on": "DPS: the person's signature, verified, under a key the verifier's trust policy gives to that "
                    "person. OMP: the emitter's statement, sealed; the instrument's officer_id only if the authority "
                    "document held hashes to instrument_hash",
        **({} if same else {"detail": "the identifiers differ" if len(set(people.values())) > 1
                            else "the person's signature does not verify"})}

    digests = {"omp.assisted_resolution.proposed_response_hash": res.get("proposed_response_hash"),
               "dps.outcome.approved_spec_digest": "sha256:" + st["o1"]["approved_spec_digest"],
               "dps.review.shown_spec_digest": "sha256:" + st["v1"]["shown_spec_digest"],
               "dps.person_approval.approved_spec_digest (signed)": "sha256:" + ps["approved_spec_digest"],
               "sha256 of the specification's bytes": "sha256:" + sha256(base64.b64decode(
                   att["action_specifications"][0]["content"]["bytes_b64"]))}
    ctx = trace.get("decision_context") or {}
    rec = spec["parameters"]["recommended"]
    values = {"decision_type": (ctx.get("decision_type"), DECISION_TYPE if spec["operation"] ==
                                "insurance.advice.issue_recommendation" else spec["operation"]),
              "jurisdiction": (ctx.get("jurisdiction"), spec["parameters"]["jurisdiction"]),
              "product": (ctx.get("product"), rec["product_class"]),
              "amount": (ctx.get("amount"), rec["annual_premium"])}
    ok = len(set(digests.values())) == 1 and all(a == b for a, b in values.values())
    J["J2 same decision"] = {
        "status": HOLDS if ok else NOT, "digests": digests,
        "values_omp_evaluated_vs_dps_approved": {k: {"omp": a, "dps": b} for k, (a, b) in values.items()},
        "rests_on": "DPS: the specification's digest, shown, approved and signed. OMP: a member of this folder's "
                    "(A15, A9), under the trace's seal; the text names no member for what was decided",
        **({} if ok else {"detail": "the digest the OMP trace carries is not the one approved" if len(set(digests.values())) > 1
                          else "the OMP scope was evaluated on other values than the ones approved"})}

    hashes = {"dps.specification.policy_version (under the person's signature)": spec["policy_version"],
              "omp.instrument.instrument_hash" + ("" if bound else " (held beside the trace)"): (instrument or {}).get("instrument_hash"),
              "sha256 of the authority document held (A1)": OMP.instrument_hash(art["mandate"])}
    ok = len(set(hashes.values())) == 1
    J["J3 same instrument"] = {
        "status": HOLDS if ok else NOT, "hashes": hashes,
        "rests_on": "the adviser's signature covers the specification, which names the mandate by its hash: the "
                    "hash was fixed no later than her signature. Non-modification only; nothing about when the "
                    "mandate was written (the author's first point, 2 November 2026)",
        **({} if ok else {"detail": "the mandate the adviser's signature covers, the one the OMP record names and "
                                    "the document held are not one and the same: "
                                    + ", ".join(sorted({str(h)[:23] + "…" for h in hashes.values()}))})}

    refs = {"dps.outcome.authority.authority_ref": (st["o1"]["authority"]["authority_ref"], binding_ref(ab)),
            "dps.recheck.authority_source_ref": (st["c1"]["authority_source_ref"],
                                                 f"urn:omp:audit-trace:{trace['trace_id']}#trace_content_hash="
                                                 f"{OMP.trace_content_hash(trace)}")}
    ok = all(a == b for a, b in refs.values())
    J["J4 the decision record cites this authority record"] = {
        "status": HOLDS if ok else NOT,
        "references": {k: {"carried": a, "recomputed_from_the_trace_held": b} for k, (a, b) in refs.items()},
        "rests_on": "the firm's seal over the attachment (the authority member is not under the person's signature); "
                    "the trace's content hash, recomputed",
        **({} if ok else {"detail": "not the object or the trace held: "
                                    + ", ".join(k for k, (a, b) in refs.items() if a != b)})}

    attempts = [s for s in att["stages"] if s["kind"] == "attempt"]
    perm = ab["execution_permission"]
    ok = (perm == "ALLOWED" and st["c1"]["result"] == "authorised" and len(attempts) == 1) or \
         (perm == "BLOCKED" and st["c1"]["result"] == "not_authorised" and not attempts)
    J["J5 permission and recheck"] = {
        "status": HOLDS if ok else NOT,
        "values": {"omp.execution_permission": perm, "dps.recheck.result": st["c1"]["result"], "dps.attempts": len(attempts)},
        "rests_on": "both are the firm's statements, each under its own seal",
        **({} if ok else {"detail": f"the trace states {perm}; the recheck found {st['c1']['result']} and "
                                    f"{len(attempts)} attempt(s) are recorded"})}

    t = GEN.when
    reg = OMP.read_tst(art["registration_token"], TSA_CERT)
    reg_ok = reg["imprint_hex"] == (instrument or {}).get("instrument_hash", "")[7:]
    moments = [("the mandate's hash time-stamped", reg["gen_time"], "test TSA token over the authority document")]
    moments += [("omp routing_decided_at", OMP.instant(trace["routing_decided_at"]), "the emitter's clock")]
    if omp.get("binding_time"):
        moments.append(("omp binding token", OMP.instant(omp["binding_time"]), "test TSA token (A5)"))
    moments += [("dps review", t(st["v1"]["at"]), "the issuer's clock"),
                ("dps approval = signed_at", t(st["o1"]["at"]), "the issuer's clock"),
                ("omp approved_at", OMP.instant(res["approved_at"]) if res.get("approved_at") else None, "the emitter's clock")]
    if omp.get("seal_time"):
        moments.append(("omp trace token", OMP.instant(omp["seal_time"]), "test TSA token over the trace"))
    moments += [("dps recheck", t(st["c1"]["at"]), "the issuer's clock")]
    moments += [("dps attempt", t(a["at"]), "the issuer's clock") for a in attempts]
    moments += [("dps seal", t(att["issuer_signature"]["sealed_at"]), "the issuer's clock")]
    times = [m[1] for m in moments]
    out_of_order = [f"{moments[k][0]} is before {moments[k - 1][0]}" for k in range(1, len(moments))
                    if times[k] is None or times[k - 1] is None or times[k] < times[k - 1]]
    if not reg_ok:
        out_of_order.append("the registration token is not over the instrument the record names")
    if t(st["o1"]["at"]) != t(ps["signed_at"]) or (res.get("approved_at") and OMP.instant(res["approved_at"]) != t(st["o1"]["at"])):
        out_of_order.append("the approval is not dated the same in the two records and the signature")
    J["J6 moments in order"] = {
        "status": NOT if out_of_order else HOLDS,
        "moments": [{"what": m[0], "at": GEN.iso(m[1]) if m[1] else None, "by": m[2]} for m in moments],
        "rests_on": "three tokens of a TEST time-stamping authority (the mandate's hash, the binding, the trace) and "
                    "the two parties' own clocks between them; with a real authority the tokens would bound the "
                    "clocks from outside, here they show the order only",
        **({"detail": "; ".join(out_of_order)} if out_of_order else {})}

    # The composed question: does the instrument cover what this person approved, when she approved it? Evaluated
    # with the OMP rules on the DPS values: the approver, the approved specification, the approval time.
    again = OMP.evaluate("ASSISTED", st["o1"]["actor_ref"], instrument,
                         {"decision_type": values["decision_type"][1], "jurisdiction": values["jurisdiction"][1],
                          "product": values["product"][1], "amount": values["amount"][1]},
                         t(st["o1"]["at"]), authority_document=art["mandate"],
                         registry_snapshot=art["registry_snapshot"],
                         profile=dict(OMP.PROFILE, binding_window_seconds=None))
    ok = again["authority_binding_result"] == "BOUND"
    J["J7 the instrument covers the approved action at the approval"] = {
        "status": HOLDS if ok else NOT,
        "evaluated": {"officer": st["o1"]["actor_ref"], "at": st["o1"]["at"],
                      "result": again["authority_binding_result"], "failure_reasons": again["failure_reasons"]},
        "rests_on": "Section 3.3's conditions, run on the approver, the specification and the time the DPS record "
                    "states; the mandate and the registry state are the firm's own (core-00 section 8.1)"}
    return J


def verify(art, held=None):
    """Both sides and the joins. Returns the full report and a flat {check: status} view."""
    dps = dps_report(art)
    omp = OMP.check_trace(art["trace"], held_of(art) if held is None else held)
    J = joins(art, omp, dps)
    flat = {"dps.schema": "errors" if any(dps["schema_errors"].values()) else "valid",
            "dps.trust_policy": dps["trust_policy"], "dps.issuer_seal": dps["issuer_seal"]["status"],
            "dps.person_approval": dps["person_approval"]["status"]}
    flat.update({f"dps.{d}": s for d, s in dps["action_binding"].items()})
    flat.update({f"omp.{k}": v["status"] for k, v in omp["checks"].items()})
    flat.update({k.split(" ")[0]: v["status"] for k, v in J.items()})
    return {"dps": dps, "omp": omp, "joins": J, "flat": flat}


GOOD = {"valid", "verified", HOLDS}


def failing(flat):
    """The checks that do not pass. Not among them: a check not made, and what is found about the instrument held
    beside an AUTHORITY_UNBOUND trace (`omp.candidate.*`), which is the reason the record states, not a defect."""
    return sorted(k for k, v in flat.items() if v not in GOOD and v != "not_checked"
                  and not k.startswith("omp.candidate."))


# ---------------------------------------------------------------- Section 5: our inputs for the twenty cases

def section5():
    """core-00 Section 5 lists twenty minimum cases and no vector. These are this folder's inputs for them, run
    through evaluate(); the expected values are the text's."""
    S = scenario("bound")
    mandate = make_mandate(S)
    snap = registry_state(S, mandate)
    base = candidate_instrument(S, mandate, snap)
    ctx, when = decision_context(S), OMP.instant(S["T"]["routed"])
    bt = GEN.when(S["T"]["binding_token"])

    def run(state="ASSISTED", officer="adviser-1", inst=base, decision=ctx, document=mandate, registry=snap,
            binding_time=bt, profile=OMP.PROFILE):
        if inst is not None and inst is not base and registry is snap and inst.get("instrument_hash") == base["instrument_hash"]:
            registry = dict(snap, entries=[dict(snap["entries"][0], status=inst["revocation_status_at_decision"])])
        return OMP.evaluate(state, officer, inst, decision, when, authority_document=document,
                            registry_snapshot=registry, binding_time=bt if binding_time is bt else binding_time,
                            profile=profile)
    w = lambda **kw: dict(base, **kw)
    rows = [
        (1, "AUTONOMOUS routing state", run(state="AUTONOMOUS"), "EXEMPT", "ALLOWED", None),
        (2, "ASSISTED, valid active pre_registered instrument, scope match", run(), "BOUND", "ALLOWED", None),
        (3, "ESCALATED, valid active pre_registered instrument, scope match", run(state="ESCALATED"), "BOUND", "ALLOWED", None),
        (4, "no instrument present", run(inst=None), "AUTHORITY_UNBOUND", "BLOCKED", "NO_VALID_DELEGATION_INSTRUMENT"),
        (5, "officer_id mismatch", run(officer="adviser-2"), "AUTHORITY_UNBOUND", "BLOCKED", "OFFICER_ID_MISMATCH"),
        (6, "effective_date after the decision timestamp", run(inst=w(effective_date="2026-11-10"), document=None),
         "AUTHORITY_UNBOUND", "BLOCKED", "EFFECTIVE_DATE_FUTURE"),
        (7, "expiry_date before the decision timestamp", run(inst=w(expiry_date="2026-11-08"), document=None),
         "AUTHORITY_UNBOUND", "BLOCKED", "INSTRUMENT_EXPIRED"),
        (8, "revocation_status REVOKED", run(inst=w(revocation_status_at_decision="REVOKED")),
         "AUTHORITY_UNBOUND", "BLOCKED", "INSTRUMENT_REVOKED"),
        (9, "revocation_status SUSPENDED", run(inst=w(revocation_status_at_decision="SUSPENDED")),
         "AUTHORITY_UNBOUND", "BLOCKED", "INSTRUMENT_SUSPENDED"),
        (10, "revocation_status UNKNOWN", run(inst=w(revocation_status_at_decision="UNKNOWN")),
         "AUTHORITY_UNBOUND", "BLOCKED", "REVOCATION_STATUS_UNKNOWN"),
        (11, "decision_type not in scope_constraints.decision_types",
         run(decision=dict(ctx, decision_type="claims.settlement")), "AUTHORITY_UNBOUND", "BLOCKED", "MANDATE_SCOPE_MISMATCH"),
        (12, "jurisdiction not in scope_constraints.jurisdictions", run(decision=dict(ctx, jurisdiction="BE")),
         "AUTHORITY_UNBOUND", "BLOCKED", "JURISDICTION_OUT_OF_SCOPE"),
        (13, "value exceeds scope_constraints.monetary_limit",
         run(decision=dict(ctx, amount={"currency": "EUR", "value": 5001})), "AUTHORITY_UNBOUND", "BLOCKED",
         "MONETARY_THRESHOLD_EXCEEDED"),
        (14, "instrument_hash mismatch", run(document=dict(mandate, expiry_date="2028-02-28")),
         "AUTHORITY_UNBOUND", "BLOCKED", "INSTRUMENT_HASH_MISMATCH"),
        (15, "binding_timestamp outside window (our window: 300 s after the routing decision, A6)",
         run(binding_time=GEN.when("2026-11-09T10:30:00Z")), "AUTHORITY_UNBOUND", "BLOCKED", "BINDING_TIMESTAMP_OUTSIDE_WINDOW"),
        (16, "registry_inclusion_proof absent when required (a profile that requires it)",
         run(profile=dict(OMP.PROFILE, registry_inclusion_proof_required=True)), "AUTHORITY_UNBOUND", "BLOCKED",
         "REGISTRY_PROOF_MISSING"),
        (17, "post_hoc_attached (our stand-in profile: AUTHORITY_UNBOUND, A16)",
         run(inst=w(instrument_selection_mode="post_hoc_attached")), "AUTHORITY_UNBOUND", "BLOCKED", "POST_HOC_ATTACHMENT_DETECTED"),
    ]
    out = []
    for n, what, got, result, permission, reason in rows:
        ok = got["authority_binding_result"] == result and got["execution_permission"] == permission and \
            (got["failure_reasons"] == ([reason] if reason else []))
        if n == 17:
            ok = ok and got["review_flag"] is True
        out.append({"case": n, "input": what, "text_expects": [result, permission] + ([reason] if reason else []),
                    "got": [got["authority_binding_result"], got["execution_permission"]] + got["failure_reasons"],
                    **({"review_flag": got["review_flag"]} if n == 17 else {}), "as_the_text_states": ok})
    # 18: an invalid enumeration value: schema validation failure, the record is not emitted (here: the reader refuses it)
    art = build(scenario("bound"))
    bad = copy.deepcopy(art["trace"])
    bad["authority_binding"]["delegation_instrument"]["authority_root_type"] = "corporate_delegation_root"
    f = OMP.schema_findings(bad)
    out.append({"case": 18, "input": "authority_root_type \"corporate_delegation_root\" (the value core-00 section 6 "
                                     "writes for DutyMark, WorkMark and HomeMark; Appendix A has corporate_delegation)",
                "text_expects": ["schema validation failure, record not emitted"], "got": f,
                "as_the_text_states": len(f) == 1 and "authority_root_type" in f[0]})
    # 19: the canonical hash of authority_binding does not depend on member order
    ab = art["trace"]["authority_binding"]
    shuffled = json.loads(json.dumps(ab, sort_keys=True))
    shuffled["delegation_instrument"] = dict(reversed(list(shuffled["delegation_instrument"].items())))
    h1, h2 = OMP.tagged(OMP.jcs(ab)), OMP.tagged(OMP.jcs(dict(reversed(list(shuffled.items())))))
    out.append({"case": 19, "input": "the authority_binding object of the bound variant, members in two orders",
                "text_expects": ["the canonical JSON hash is unchanged"], "got": [h1, h2], "as_the_text_states": h1 == h2})
    # 20: identical inputs, identical result
    a, b = run(), run()
    out.append({"case": 20, "input": "case 2 evaluated twice", "text_expects": ["identical result and permission"],
                "got": [a["authority_binding_result"], a["execution_permission"]], "as_the_text_states": a == b})
    return out


# ---------------------------------------------------------------- writing

def write(out, art, report):
    out.mkdir(parents=True, exist_ok=True)
    pretty = lambda d: (json.dumps(d, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
    files = {
        "authority-document.json": OMP.jcs(art["mandate"]),                 # the bytes instrument_hash is over (A1)
        "registration-token.tsr": art["registration_token"], "binding-token.tsr": art["binding_token"],
        "omp-audit-trace.json": pretty(art["trace"]),
        "decision-record.json": compact(art["record"]), "action-binding-attachment.json": compact(art["attachment"]),
        "signatures-attachment.json": compact(art["sig"]), "specification.bytes.json": art["spec_bytes"],
        "review-view.txt": art["view"], "demands-and-needs.txt": DEMANDS_AND_NEEDS, "reasons.txt": REASONS,
        "report.json": pretty({k: report[k] for k in ("flat", "omp", "joins", "dps")}),
    }
    if art["registry_snapshot"] is not None:
        files["registry-state.json"] = OMP.jcs(art["registry_snapshot"])     # the bytes the snapshot hash is over (A4)
    if art["trace"]["authority_binding"]["authority_binding_result"] == "AUTHORITY_UNBOUND":
        files["candidate-instrument.json"] = pretty(art["instrument"])      # not in the trace (A14)
    for old in out.iterdir():
        if old.is_file() and old.name not in files:
            old.unlink()
    for name, data in files.items():
        (out / name).write_bytes(data)


EXPECTED = {
    "bound": {"omp_result": "BOUND", "not_good": {}},
    # Expected and not a failure: the binding could not be made, the absence is sealed, nothing was issued.
    "unbound-sealed": {"omp_result": "AUTHORITY_UNBOUND",
                       "not_good": {"omp.candidate.registry_snapshot": "failed", "J7": NOT,
                                    "dps.observed_results": "not_checked"}},
}


def as_expected(name, art, report):
    flat = report["flat"]
    ab = art["trace"]["authority_binding"]
    return ab["authority_binding_result"] == EXPECTED[name]["omp_result"] and \
        {k: v for k, v in flat.items() if v not in GOOD} == EXPECTED[name]["not_good"]


def main():
    out = HERE / "out"
    out.mkdir(exist_ok=True)
    summary, ok = {}, True
    for name in VARIANTS:
        art = build(scenario(name))
        report = verify(art)
        write(out / name, art, report)
        good = as_expected(name, art, report)
        ok = ok and good
        ab = art["trace"]["authority_binding"]
        summary[name] = {"as_expected": good,
                         "omp": {"authority_binding_result": ab["authority_binding_result"],
                                 "execution_permission": ab["execution_permission"],
                                 "failure_reasons": ab.get("failure_reasons", []), "verdict": report["omp"]["verdict"],
                                 "checks_on_a_stand_in": sorted(k for k, v in report["omp"]["checks"].items()
                                                                if v["basis"].startswith("stand_in"))},
                         "dps": {k: v for k, v in report["flat"].items() if k.startswith("dps.")},
                         "joins": {k: v["status"] for k, v in report["joins"].items()},
                         "not_verified": {k: v for k, v in report["flat"].items() if v not in GOOD}}
    cases = section5()
    s5 = sum(1 for c in cases if c["as_the_text_states"])
    ok = ok and s5 == len(cases)
    (out / "section5-cases.json").write_text(json.dumps(cases, indent=1, ensure_ascii=False) + "\n")
    (out / "tsa-certificate.TEST.der").write_bytes(TSA_CERT)
    (out / "trust-policy.json").write_bytes(compact(TRUST))
    (out / "profile-stand-in.json").write_text(json.dumps(OMP.PROFILE, indent=1, ensure_ascii=False) + "\n")
    summary["section5"] = {"as_the_text_states": s5, "of": len(cases), "vectors": "our own; the authors had published none"}
    (out / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n")
    print(json.dumps(summary, indent=1, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
