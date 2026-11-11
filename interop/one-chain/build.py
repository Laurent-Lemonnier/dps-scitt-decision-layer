#!/usr/bin/env python3
"""Case 18: one chain. One payment action (a refund of 120.00 EUR on order 8812) runs through four formats, each the
record of a different moment, none changed:

  1. the agent's run, draft-thaha-scitt-agent-execution-evidence-02: six hash-chained Execution Receipts, among them a
     tool_call whose decision is confirm, then its allow outcome (the builders and the verifier written from Thaha's text
     are those of ../agent-execution-evidence, case 17);
  2. the person's decision, Decision Provenance Standard: the decision record, the action-binding attachment as sealed
     at the approval (A1) and after the run (A2), the finance controller's signed approval of the exact tool arguments
     the Harness hashed (the Standard's checks, as the other cases run them);
  3. the auditor's verdict, draft-wright-verdict-record-02: a verdict record over A1, A2 and the record's file, rule
     executed-as-approved:v1, checked by the checker written from Wright's text (../verdict-record, case 16);
  4. the dispute packet, draft-xg-payment-dispute-profile-01 over draft-farley-acta-signed-receipts-03: one decision
     receipt whose scope_conformance states what the verdict re-derived, agent anchors carrying the approval event (the
     event_hash of the ledger's ApprovalGranted event, whose payload carries the typed digest of A1 as an extension) and
     the verdict record's digest, a settlement anchor recording what moved, the ledger slice (with the ScopeEvaluated
     event that records the intent scope and the executed action) and the FRE 901 wrapper; verified by goshi_from_text.py,
     written from the two texts, since 8 November 2026 with the constructions the author gave by mail (see that module).

The same run twice: executed as approved (the verdict positive, the packet in_scope, 120.00 EUR moved), and the stated
negative (150.00 EUR executed for 120.00 approved: the verdict stating not_as_approved released, the packet stating
BREACH:amount_minor with 150.00 EUR moved). Twelve joins across the four links say what no single verifier says.
Synthetic data, test keys from fixed seeds, fixed times; deterministic output. Never use any of it for anything real.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
INTEROP = HERE.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


C17 = load("aee_build", INTEROP / "agent-execution-evidence" / "build.py")   # Thaha run + DPS builders, verifier from his text
C16 = load("verdict_build", INTEROP / "verdict-record" / "build.py")          # Wright verdict builder, rule, format rules
G = load("goshi_from_text", HERE / "goshi_from_text.py")                      # Goshi/Farley verifier from the text
AEE, V, AB, SIG = C17.AEE, C16.V, C17.AB, C17.SIG
sha256, compact, b64, ms = C17.sha256, C17.compact, C17.b64, C17.ms
NS = C17.NS

# ---- the scenario: the refund of ../verdict-record, run through Thaha's confirm/allow pair of ../agent-execution-evidence
# keys of the parameters in sorted order: the tool arguments the Harness hashes (compact JSON) are then also the JCS
# bytes the dispute packet hashes, so one digest names the action in all four links
PARAMS = {"amount_minor": 12000, "currency": "EUR", "order_ref": "urn:example:order:8812", "reason": "duplicate charge of 2026-11-02"}
assert list(PARAMS) == sorted(PARAMS)
OPERATION, TARGET, HOST = "payments.refund.create", "https://payments.example/refunds", "payments.example"
TXN = "txn-2026-1104-8812"
TXN2 = "txn-2026-1104-8812-2"                    # N16: a second transfer resting on the same approval
TXN_UNRECORDED = "txn-2026-1104-0931"            # N17: a transfer the rail shows and no record names
REQUEST_ID_2 = "urn:example:invoicing-request:7c1f0a3e-5b1e-4d0d-9a1a-000000000002"
MERCHANT_KEY_ID = "sb:issuer:example-merchant-dispute-1"
packet_key = C17.key_from_seed("dps-scitt-decision-layer one-chain: merchant dispute desk key (test only)")
other_key = C17.key_from_seed("dps-scitt-decision-layer one-chain: a key of nobody (test only)")
T = dict(C17.T, verdict="2026-11-04T11:00:00.000000Z", intake="2026-11-04T11:05:00.000000Z", settlement="2026-11-04T10:01:30Z",
         ledger_verdict="2026-11-04T11:05:01Z", packet="2026-11-04T12:00:00Z",
         # N16: the second confirm/allow/tool_result triple, between the first tool_result and task_end, and its DPS stages
         confirm2="2026-11-04T10:01:19.400Z", outcome2="2026-11-04T10:01:19.600Z", tool_result2="2026-11-04T10:01:19.800Z",
         request2="2026-11-04T10:01:19Z", recheck2="2026-11-04T10:01:19Z", attempt2="2026-11-04T10:01:19Z", result2="2026-11-04T10:01:22Z",
         settlement2="2026-11-04T10:01:31Z")
TYPE_A = f"{NS}.action_binding_attachment"
TYPE_S = f"{NS}.signatures_attachment"
TYPE_V = f"{C16.FMT_VERDICT}"
TYPE_R = f"{C17.AEE_NS}.execution_receipt"

policy = {"policy_id": "urn:example:policy:refunds", "version": "2026-10-01",
          "applies_to": {"operation": OPERATION, "target_host": HOST},
          "confirmation": {"required_above_minor": 5000, "by": [{"actor_ref": C17.APPROVER, "role": "finance controller"}]},
          "single_use": True, "max_approval_age_seconds": 900,
          "execution": "by the Harness tool door once the confirm receipt's outcome is allow; the DPS attempt and result "
                       "cite the outcome and the tool_result by record-hash"}


def spec_of(params):
    return {"operation": OPERATION, "target": TARGET, "parameters": params, "input_version_refs": ["urn:example:ticket:4410"],
            "policy_version": C17.POLICY_VERSION, "valid_until": T["valid_until"]}


def amount_text(minor):
    return f"{minor // 100}.{minor % 100:02d}"


def set_scenario(approved):
    """Case 17's builders read the specification, the arguments, the view and the response from its module globals:
    they are set to this scenario before the run (the record's wording is set after)."""
    C17.policy, C17.policy_bytes = policy, compact(policy)
    C17.POLICY_VERSION, C17.POLICY_REF = "sha256:" + sha256(C17.policy_bytes), policy["policy_id"] + "#" + policy["version"]
    C17.PACK_DIGEST = hashlib.sha256(C17.policy_bytes).digest()
    spec = spec_of(approved)
    spec["policy_version"] = C17.POLICY_VERSION
    C17.PARAMS, C17.ARGS, C17.SPEC = approved, compact(approved), spec
    C17.VIEW = (f"Refund order urn:example:order:8812: {amount_text(approved['amount_minor'])} {approved['currency']}, reason: "
                f"{approved['reason']}\nvia {TARGET}; policy {C17.POLICY_REF} ({C17.POLICY_VERSION})\nvalid until {T['valid_until']}\n").encode()
    C17.COMPLETION = b"<completion bytes: call payments.refund.create with " + C17.ARGS + b">"
    C17.RESPONSE = compact({"status": "refunded", "refund_ref": "urn:example:payments:refund:R-55120", "txn_ref": TXN})
    C17.TXN = TXN
    return spec


def make_record():
    r = C17.make_record()
    r.update({"decision_class": "customer-refund",
              "consent_posture": {"posture_class": "the customer's ticket and the order's payment record; no other data read"},
              "decision_statement": "Refund 120.00 EUR on order 8812 for the duplicate charge of 2 November 2026, under the refunds "
                                    "policy of 1 October 2026, through the payments API.",
              "context_at_decision": "Ticket 4410 reports a duplicate charge; the invoicing agent prepared the refund and the policy "
                                     "requires the finance controller's confirmation above 50.00 EUR.",
              "options_considered": ["Refund now (chosen): duplicate charge confirmed.", "Ask the customer for a bank statement first.",
                                     "Refuse: no ground, the charge is a duplicate."],
              "required_inputs_used": ["ticket urn:example:ticket:4410", "payment record of order 8812"],
              "assumptions_depended_on": ["The second capture of 2 November 2026 is a duplicate and not a second order."],
              "success_criteria": ["One refund of 120.00 EUR accepted by the payments API, and no second one for the same charge."],
              "re_decision_trigger": "A second refund request for the same order."})
    r["seal_hash"] = "0" * 64
    r["seal_hash"] = sha256(compact(r))
    return r


RESPONSE2 = compact({"status": "refunded", "refund_ref": "urn:example:payments:refund:R-55121", "txn_ref": TXN2})


def make_receipts(principal, args, executed_args, *, second=False):
    """Case 17's six receipts with this scenario's tool: the confirm receipt's request_digest is the SHA-256 of the
    arguments the Harness saw at the tool door (executed_args: the approved ones, or other ones in the mismatch chain).
    second (N16): a second confirm/allow/tool_result triple for the same arguments, between the first tool_result and
    task_end; each receipt is well-formed and the pairing holds, so Thaha's verifier has nothing to say about it."""
    common = {1: 5, 7: C17.digest(C17.policy_bytes), 8: [AEE.SHA256_COSE, C17.CONFIG_DIGEST], 9: C17.AGENT_ID, 10: principal, 11: 0}
    rs, prev = [], AEE.ZERO32

    def add(r):
        nonlocal prev
        r = {**common, **r, 2: len(rs), 3: prev}
        rs.append(r)
        prev = AEE.record_hash(r)
        return r

    def triple(t_confirm, t_outcome, t_result, txn, response):
        call = {4: 4, 5: 1, 6: 3, 12: C17.digest(executed_args), 14: ms(t_confirm), 16: OPERATION, 17: HOST, 18: 2}
        c = add({**call, 15: C17.agent_sig({**common, **call, 2: len(rs), 3: prev})})
        add({**call, 6: 1, 14: ms(t_outcome), 19: c[2], 23: [C17.AGENT_ID], 24: hashlib.sha256(b"<delegation token octets>").digest(),
             25: txn, 29: C17.digest(C17.AEE.cbor2.dumps(["POST", "/refunds", hashlib.sha256(executed_args).digest()], canonical=True))})
        add({4: 5, 5: c[2] + 1, 6: 1, 13: C17.digest(response), 14: ms(t_result), 16: OPERATION, 18: 2})

    add({4: 1, 6: 1, 14: ms(T["task_start"]), 26: C17.digest(b"<memory state at task start>")})
    add({4: 3, 6: 1, 14: ms(T["inference"]), 12: C17.digest(C17.PROMPT), 13: C17.digest(C17.COMPLETION), 16: "example-model-2026-09", 18: 1})
    triple(T["confirm"], T["outcome"], T["tool_result"], TXN, C17.RESPONSE)
    if second:
        triple(T["confirm2"], T["outcome2"], T["tool_result2"], TXN2, RESPONSE2)
    add({4: 2, 6: 1, 14: ms(T["task_end"]), 26: C17.digest(b"<memory state at task end>")})
    return rs


def second_tail_stages(sd, receipts):
    """N16: a second request, recheck, attempt and result resting on the same approval o1 (request_limit 1), citing the
    second allow outcome and tool_result by record-hash; the shape of case 17's tail_stages."""
    outcome, result = receipts[6], receipts[7]
    return [{"stage_id": "q2", "kind": "request", "at": T["request2"], "request_id": REQUEST_ID_2, "authorised_by": "o1",
             "spec_digest": sd, "requested_by": "urn:example:service:invoicing-assistant"},
            {"stage_id": "c2", "kind": "recheck", "at": T["recheck2"], "request_ref": "q2", "result": "authorised",
             "authority_source_ref": C17.POLICY_REF},
            {"stage_id": "x2", "kind": "attempt", "at": T["attempt2"], "spec_digest": sd, "executor_ref": C17.HARNESS_ISS,
             "trace_refs": [C17.receipt_urn(outcome), TXN2], "request_ref": "q2", "recheck_ref": "c2"},
            {"stage_id": "r2", "kind": "result", "at": T["result2"], "attempt_ref": "x2", "observed": "succeeded",
             "basis": "executor_observation", "evidence_ref": C17.receipt_urn(result) + "&response_digest=" + result[13][1].hex()}]


def attachment(entries, stages):
    """The attachment with one or two specifications (the executed one beside the approved one in the mismatch chain)."""
    return {"profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": C17.DECISION_ID,
            "action_specifications": entries, "stages": stages}


def spec_entry(spec_bytes):
    spec = json.loads(spec_bytes)
    return {"spec_digest": sha256(spec_bytes), "representation": {"kind": "original_bytes", "media_type": "application/json"},
            "content": {"availability": "available", "bytes_b64": b64(spec_bytes)},
            "summary": {"operation": spec["operation"], "target": spec["target"], "policy_version": spec["policy_version"],
                        "input_version_refs": spec["input_version_refs"]}}


# ---------------------------------------------------------------- the build: every part as data

def build():
    return {"approved_amount": 12000, "executed_amount": None,       # None: executed as approved
            "approval": "signed",                                    # signed | absent | after_outcome
            "verdict_result": None,                                  # None: what the chain gives; a string: what the auditor states
            "mutate_a2_after_verdict": None,                         # function over A2's bytes, after the verdict cited them
            "a2_seal": "intact",                                     # intact | broken (N22: one byte of the issuer's seal value changed before anything cites A2)
            "packet_scope": None,                                    # None: what the verdict says; a string: what the packet asserts
            "packet_headline_amount": None,                          # None: what moved
            "settlement_amount": None,                               # None: the executed amount
            "settlement": "present",                                 # present | absent ({status: SETTLEMENT_UNANCHORED}) | stale_hash | missing (no block) | unanchored_extra
            "action_packet_hash": None,                              # None: action_hash; a hex: what the ActionExecuted event carries (N18)
            "scope_event": "intact",                                 # intact | executed_altered (the ScopeEvaluated event's executed_action changed, ledger re-chained; N19)
            "approval_action_hash": None,                            # None: the canonical hash of what the person approved; a hex: what the ApprovalGranted event carries (N21)
            "packet_cites_verdict": "this",                          # this | other | altered
            "custody": "bound",                                      # bound | altered
            "ledger": "intact",                                      # intact | altered
            "receipt_key": "merchant",                               # merchant | other
            "receipt_tamper": None,                                  # function over the signed payload
            "issuer_id": None,                                       # None: the kid
            "dispute_reason_code": "duplicate_processing",
            "second_use_of_approval": False,                         # N16: a second confirm/allow pair, request and attempt on o1; the packet cites the approval event twice
            "recorded": "all"}                                       # all | nothing (N17: a settlement with no approval event, no verdict, no execution record)


def chain(p):
    """Links 1 and 2: the Thaha run and the DPS record, A1, A2, approval, route 1 statement (case 17's shape)."""
    approved = dict(PARAMS, amount_minor=p["approved_amount"])
    executed = dict(PARAMS, amount_minor=p["executed_amount"]) if p["executed_amount"] else approved
    spec = set_scenario(approved)
    spec_bytes, xspec_bytes = compact(spec), compact(spec_of(executed) | {"policy_version": C17.POLICY_VERSION})
    sd, xd = sha256(spec_bytes), sha256(xspec_bytes)
    record = make_record()
    approval_at = T["approval"] if p["approval"] != "after_outcome" else "2026-11-04T10:01:19Z"
    sig = C17.make_signatures(record, sd, signed_at=approval_at)
    if p["approval"] == "absent":
        sig["person_signatures"] = []
    sig_bytes = compact(sig)
    head = C17.head_stages(sd, approval_at)
    a1 = C17.seal(attachment([spec_entry(spec_bytes)], copy.deepcopy(head)), T["a1_sealed"])
    receipts = make_receipts(C17.principal_of(C17.APPROVER_CANONICAL_ID), compact(approved), compact(executed), second=p["second_use_of_approval"])
    entries = [spec_entry(spec_bytes)] + ([spec_entry(xspec_bytes)] if xd != sd else [])
    tail = C17.tail_stages(xd, receipts) + (second_tail_stages(xd, receipts) if p["second_use_of_approval"] else [])
    a2 = C17.seal(attachment(entries, copy.deepcopy(head) + tail), T["a2_sealed"])
    if p["a2_seal"] == "broken":
        # N22: the seal value with its first byte changed; every later link cites these bytes, so only the seal fails
        value = bytearray(base64.b64decode(a2["issuer_signature"]["value_b64"]))
        value[0] ^= 0x01
        a2["issuer_signature"]["value_b64"] = b64(bytes(value))
    a1_bytes, a2_bytes = compact(a1), compact(a2)
    art = {"record": record, "record_bytes": compact(record), "spec_bytes": spec_bytes, "xspec_bytes": xspec_bytes, "sig": sig,
           "sig_bytes": sig_bytes, "a1": a1, "a1_bytes": a1_bytes, "a2": a2, "a2_bytes": a2_bytes, "receipts": receipts,
           "bundle": C17.make_bundle(receipts), "binding": C17.binding_statement(C17.make_refs(a2_bytes, sig_bytes, receipts)),
           "route2": False, "pepper": C17.PEPPER, "canonical_id": C17.APPROVER_CANONICAL_ID,
           "approved": approved, "executed": executed}
    return art


def verdict_over(art, result, **kw):
    """Link 3: the auditor's verdict record (case 16's builder; A1's outcome is stage 2, A2's attempt stage 5 here too)."""
    raw = C16.verdict(art["a1_bytes"], art["a2_bytes"], art["record_bytes"], result, act_time=T["verdict"],
                      key="dps/refund-8812/one-chain/executed-as-approved", **kw)
    return raw, C16.container(raw)


def checker(intake):
    anch = {"writers": {C16.AUDITOR: {C16.AUDITOR_KEY_REF: C17.raw_public(C16.auditor_key).hex()}},
            "dps_trust_policy": C17.TRUST, "intake": intake}
    return V.Checker(copy.deepcopy(C16.POLICY), anch, C16.RULES, C16.FORMATS), anch


# ---------------------------------------------------------------- link 4: the dispute packet, from the text

def typed(t, hexdigest):
    return {"type": t, "alg": "SHA-256", "digest": hexdigest}


ACTION_ID = "urn:example:action:refund-8812"                     # the action every event of the slice and the manifest name (the author's action_id)


def ledger_event(events, type_, at, data, action_id=ACTION_ID):
    ev = {"seq": str(len(events)), "action_id": action_id, "type": type_, "at": at, "data": data,
          "prev_hash": events[-1]["event_hash"] if events else "0" * 64}
    ev["event_hash"] = G.event_hash(ev)
    events.append(ev)
    return ev


def rechain(events):
    """Recompute every event_hash and link after an event's data was changed and the ledger re-chained over it (the
    alteration is then invisible to the hash and link checks and must be caught by what the data no longer recompute to)."""
    prev = "0" * 64
    for ev in events:
        ev["prev_hash"] = prev
        ev["event_hash"] = G.event_hash(ev)
        prev = ev["event_hash"]


def settlement_block(anchor):
    """4.3 as the author constructs it: {status: "anchored", anchor, anchor_hash}, anchor_hash the canonical hash of anchor."""
    block = {"status": "anchored", "anchor": anchor, "anchor_hash": None}
    block["anchor_hash"] = G.anchor_hash(block)
    return block


def packet(art, verdict_raw, verdict_result, p, *, cited_digest=None):
    rs = art["receipts"]
    outcome, result = rs[3], rs[4]
    rh3, rh4 = AEE.record_hash(outcome).hex(), AEE.record_hash(result).hex()
    o1 = next(s for s in art["a1"]["stages"] if s["kind"] == "outcome")
    moved = p["settlement_amount"] or art["executed"]["amount_minor"]
    headline_amount = p["packet_headline_amount"] or art["executed"]["amount_minor"]
    scope = p["packet_scope"] or ("in_scope" if verdict_result == "executed_as_approved" else "BREACH:amount_minor")
    vdigest = cited_digest or sha256(verdict_raw)
    intent, executed = art["approved"], art["executed"]
    # the hashes as the author constructs them (8 November 2026): canonical hash of the recorded objects; the approved
    # parameters and the executed arguments are sorted-key compact JSON objects, so these are the digests the other links hash
    scope_hash, action_hash = G.canonical_hash(intent), G.canonical_hash(executed)
    approval_anchor = typed(TYPE_A, sha256(art["a1_bytes"]))
    # the ledger slice: what the merchant's ledger recorded, in order, every event for this action_id
    events = []
    ledger_event(events, "ActorValidated", T["review"], {"actor": art["canonical_id"], "method": "finance console login, directory urn:example:directory:people"})
    # ApprovalGranted: the author's event; its payload carries action_hash, the canonical hash of what the person approved (the
    # approved parameters: equal to the receipt's action_hash when the action executed as approved, to the scope_hash when it
    # did not). Extension beyond -01: dps_approval, the typed digests of A1 and of the signatures attachment, the approval held
    approval_ev = ledger_event(events, "ApprovalGranted", T["a1_sealed"],
                               {"decision_id": art["record"]["decision_id"], "approved_spec_digest": o1["approved_spec_digest"],
                                "action_hash": scope_hash if p["approval_action_hash"] is None else p["approval_action_hash"],
                                "approved_at": o1["at"],
                                "dps_approval": {"note": "extension beyond draft-xg-payment-dispute-profile-01: the approval held outside the ledger",
                                                 "attachment": approval_anchor, "signatures_attachment": typed(TYPE_S, sha256(art["sig_bytes"]))}})
    exec_ev = ledger_event(events, "ActionExecuted", T["result"],
                           {"txn_ref": TXN, "allow_outcome_record_hash": rh3, "tool_result_record_hash": rh4,
                            "response_sha256": result[13][1].hex(), "amount_minor": str(art["executed"]["amount_minor"]), "currency": "EUR",
                            "action_packet_hash": action_hash if p["action_packet_hash"] is None else p["action_packet_hash"]})
    # ScopeEvaluated: the author's event; the intent scope and the executed action recorded, scope_hash and action_hash their
    # canonical hashes, the verdict as the merchant's system evaluated it (the verifier re-derives it from the two objects)
    scope_ev = ledger_event(events, "ScopeEvaluated", T["result"],
                            {"intent_scope": intent, "scope_hash": scope_hash, "executed_action": executed, "action_hash": action_hash,
                             "verdict": scope})
    second = p["second_use_of_approval"]
    if second:                                               # N16: the second transfer, recorded by the ledger like the first
        rh6, rh7 = AEE.record_hash(rs[6]).hex(), AEE.record_hash(rs[7]).hex()
        ledger_event(events, "ActionExecuted", T["result2"],
                     {"txn_ref": TXN2, "allow_outcome_record_hash": rh6, "tool_result_record_hash": rh7,
                      "response_sha256": rs[7][13][1].hex(), "amount_minor": str(art["executed"]["amount_minor"]), "currency": "EUR",
                      "action_packet_hash": action_hash})
    sa, block = None, None
    if p["settlement"] in ("present", "stale_hash"):
        sa = {"rail": "example-rail", "txn_ref": TXN, "finality_status": "final", "amount_minor": str(moved), "currency": "EUR",
              "captured_at": T["settlement"], "network": None, "payer": "urn:example:customer:C-4471",
              "unanchored_fields": ["network"]}
        block = settlement_block(sa)
        if p["settlement"] == "stale_hash":
            sa["amount_minor"] = str(moved + 100)
    elif p["settlement"] == "absent":                        # the author's exact shape of an unanchored packet
        block = dict(G.UNANCHORED)
    elif p["settlement"] == "unanchored_extra":              # N20: states unanchored and carries a field beside status
        block = dict(G.UNANCHORED, txn_ref=TXN)
    # "missing": no block at all
    settle_ev = ledger_event(events, "SettlementObserved", T["settlement"], {"anchor_hash": block["anchor_hash"] if sa else None, "txn_ref": TXN})
    additional, custody_extra = [], []
    if second:
        sa2 = {**sa, "txn_ref": TXN2, "captured_at": T["settlement2"]}
        block2 = settlement_block(sa2)
        settle_ev2 = ledger_event(events, "SettlementObserved", T["settlement2"], {"anchor_hash": block2["anchor_hash"], "txn_ref": TXN2})
        custody_extra = [{"event": "second settlement anchor captured", "at": T["settlement2"], "actor": "urn:example:merchant:rail-feed",
                          "ledger_event_hash": settle_ev2["event_hash"]}]
    verdict_ev = ledger_event(events, "VerdictReceived", T["ledger_verdict"], {"verdict_sha256": vdigest, "format": TYPE_V, "result": verdict_result})
    if p["ledger"] == "altered":
        exec_ev["data"]["amount_minor"] = "9999"             # altered after chaining: its hash no longer recomputes
    if p["scope_event"] == "executed_altered":               # N19: the recorded executed action changed and the ledger re-chained
        scope_ev["data"]["executed_action"] = dict(executed, amount_minor=executed["amount_minor"] + 100)
        rechain(events)
    further = {"verdict_record": typed(TYPE_V, vdigest), "signatures_attachment": typed(TYPE_S, sha256(art["sig_bytes"])),
               "allow_outcome_receipt": typed(TYPE_R, rh3), "tool_result_receipt": typed(TYPE_R, rh4)}
    cited = [approval_ev["event_hash"]] + [r["digest"] for r in further.values()] + ([block["anchor_hash"]] if sa else []) + [exec_ev["event_hash"]]
    if second:
        # the same approval event cited a second time, for the second transfer: the packet says so in the open
        additional = [{"txn_ref": TXN2, "approval_event_hash": approval_ev["event_hash"], "allow_outcome_receipt": typed(TYPE_R, rh6),
                       "tool_result_receipt": typed(TYPE_R, rh7), "settlement_anchor": block2}]
        cited += [approval_ev["event_hash"], rh6, rh7, block2["anchor_hash"]]
    kid = MERCHANT_KEY_ID
    key = packet_key if p["receipt_key"] == "merchant" else other_key
    payload = {"type": G.RECEIPT_TYPE, "issued_at": T["packet"], "issuer_id": p["issuer_id"] or kid,
               "decision": "allow", "reason_code": "approved_by_accountable_person",
               "action_hash": action_hash, "evidence_set_hash": G.evidence_set_hash(cited),
               "ledger_entry_hash": exec_ev["event_hash"], "timestamp": T["outcome"], "mandate_hash": None,
               "rail_anchors_hash": block["anchor_hash"] if sa else None, "scope_conformance": scope, "key_id": kid,
               "signer_pubkey_hash": sha256(C17.raw_public(packet_key))}
    sig_hex = key.sign(G.canonical(payload)).hex()
    if p["receipt_tamper"]:
        payload = p["receipt_tamper"](payload)
    receipt = {"payload": payload, "signature": {"alg": "EdDSA", "kid": kid, "sig": sig_hex}}
    custody = [{"event": "ledger slice exported", "at": T["result"], "actor": "urn:example:merchant:ledger-export", "ledger_event_hash": exec_ev["event_hash"]},
               {"event": "settlement anchor captured", "at": T["settlement"], "actor": "urn:example:merchant:rail-feed", "ledger_event_hash": settle_ev["event_hash"]},
               {"event": "verdict record received", "at": T["ledger_verdict"], "actor": "urn:example:merchant:dispute-desk", "ledger_event_hash": verdict_ev["event_hash"]}]
    custody += custody_extra
    if p["custody"] == "altered":
        custody[1]["ledger_event_hash"] = "e" * 64
    manifest = {"profile": "draft-xg-payment-dispute-profile-01", "base": "draft-farley-acta-signed-receipts-03",
                "constructions": "action_hash, scope_hash, approval event hash, ledger_entry_hash and anchor_hash as given by the author "
                                 "on 8 November 2026 (to appear in -02); ApprovalGranted.data.dps_approval is an extension beyond -01",
                "action_id": ACTION_ID,
                "dispute_reason_code": p["dispute_reason_code"], "receipt_public_key_hex": C17.raw_public(packet_key).hex(),
                "headline": {"scope_conformance": scope, "amount_minor": str(headline_amount), "currency": "EUR"},
                "agent_anchors": {"mandate_hash": None, "agent_id": C17.AGENT_ID, "approval_event_hash": approval_ev["event_hash"],
                                  "receipt_signature": sig_hex, "network_token_id": None, "threeds_acs_result": None},
                "further_anchors": further,
                "intent_scope": intent, "intent_scope_sha256": scope_hash,
                "intent_scope_source": {"attachment": approval_anchor, "spec_digest": o1["approved_spec_digest"], "pointer": "/parameters"},
                "executed_action": executed, "executed_action_sha256": action_hash,
                "executed_action_source": {"receipt": typed(TYPE_R, AEE.record_hash(rs[2]).hex()), "member": "request_digest (key 12)"},
                "settlement_anchor": block,
                "ce3_fpt_categories": {"device_identity": {"populated": False, "value": None, "gap_note": "no device data in the packet"},
                                       "delivery_information": {"populated": False, "value": None, "gap_note": "a refund: nothing delivered"},
                                       "additional_identity_factor": {"populated": True, "value": art["canonical_id"],
                                                                      "gap_note": None, "source": "ActorValidated ledger event"}}}
    if block is None:
        del manifest["settlement_anchor"]
    if additional:
        manifest["additional_executions"] = additional
    fre = {"acquisition": {"captured_by": "urn:example:merchant:dispute-desk", "captured_at": T["packet"], "tool": "one-chain/build.py (synthetic)",
                           "clock_source": "host clock, declared untrusted (no external time anchor)", "gaps": ["no RFC 3161 or SCITT time anchor"]},
           "custody": custody,
           "authentication_statement": {"re_derivable": ["receipt signature over JCS payload", "ledger event hashes and links",
                                                         "scope verdict from intent scope and executed action", "settlement anchor_hash",
                                                         "headline consistency", "agent anchors against the items held"]}}
    return {"receipt": receipt, "manifest": manifest, "ledger_slice": events, "fre901": fre}


def packet_nothing_recorded(p):
    """N17: the dispute desk holds a settlement anchor (120.00 EUR, TXN_UNRECORDED, final) and nothing behind it: no
    approval event, no verdict, no execution record, no agent. The packet says so rather than invent (Goshi 4.1): the
    approval event is null, further_anchors is empty, intent scope and executed action are null (4.2: not_evaluated),
    the ledger slice holds the one event the merchant recorded (the settlement observed), the receipt's decision is
    require_approval, the one value of Farley 3.1.1 that asserts no decision taken: the policy in force required an
    approval, and none is recorded (this reading is ours)."""
    events = []
    action_id = "urn:example:action:unrecorded-" + TXN_UNRECORDED       # the only name the desk has for it: the rail's transaction
    sa = {"rail": "example-rail", "txn_ref": TXN_UNRECORDED, "finality_status": "final", "amount_minor": "12000", "currency": "EUR",
          "captured_at": T["settlement"], "network": None, "payer": "urn:example:customer:C-4471", "unanchored_fields": ["network"]}
    block = settlement_block(sa)
    settle_ev = ledger_event(events, "SettlementObserved", T["settlement"], {"anchor_hash": block["anchor_hash"], "txn_ref": TXN_UNRECORDED}, action_id)
    kid = MERCHANT_KEY_ID
    payload = {"type": G.RECEIPT_TYPE, "issued_at": T["packet"], "issuer_id": kid,
               "decision": "require_approval", "reason_code": "no_decision_record_found",
               "action_hash": None, "evidence_set_hash": G.evidence_set_hash([block["anchor_hash"], settle_ev["event_hash"]]),
               "ledger_entry_hash": settle_ev["event_hash"], "timestamp": T["settlement"], "mandate_hash": None,
               "rail_anchors_hash": block["anchor_hash"], "scope_conformance": "not_evaluated", "key_id": kid,
               "signer_pubkey_hash": sha256(C17.raw_public(packet_key))}
    sig_hex = packet_key.sign(G.canonical(payload)).hex()
    receipt = {"payload": payload, "signature": {"alg": "EdDSA", "kid": kid, "sig": sig_hex}}
    manifest = {"profile": "draft-xg-payment-dispute-profile-01", "base": "draft-farley-acta-signed-receipts-03",
                "constructions": "as in the recorded chain's packet (the author's constructions of 8 November 2026); no ScopeEvaluated "
                                 "and no ApprovalGranted event exist for this transfer, so action_hash and the approval event are null",
                "action_id": action_id,
                "dispute_reason_code": p["dispute_reason_code"], "receipt_public_key_hex": C17.raw_public(packet_key).hex(),
                "headline": {"scope_conformance": "not_evaluated", "amount_minor": "12000", "currency": "EUR"},
                "agent_anchors": {"mandate_hash": None, "agent_id": None, "approval_event_hash": None,
                                  "receipt_signature": sig_hex, "network_token_id": None, "threeds_acs_result": None},
                "further_anchors": {},
                "intent_scope": None, "intent_scope_sha256": None, "intent_scope_source": None,
                "executed_action": None, "executed_action_sha256": None, "executed_action_source": None,
                "settlement_anchor": block,
                "ce3_fpt_categories": {"device_identity": {"populated": False, "value": None, "gap_note": "no device data in the packet"},
                                       "delivery_information": {"populated": False, "value": None, "gap_note": "a transfer: nothing delivered"},
                                       "additional_identity_factor": {"populated": False, "value": None,
                                                                      "gap_note": "no ActorValidated event: nothing is recorded behind the transfer"}}}
    fre = {"acquisition": {"captured_by": "urn:example:merchant:dispute-desk", "captured_at": T["packet"], "tool": "one-chain/build.py (synthetic)",
                           "clock_source": "host clock, declared untrusted (no external time anchor)", "gaps": ["no RFC 3161 or SCITT time anchor"]},
           "custody": [{"event": "settlement anchor captured", "at": T["settlement"], "actor": "urn:example:merchant:rail-feed",
                        "ledger_event_hash": settle_ev["event_hash"]}],
           "authentication_statement": {"re_derivable": ["receipt signature over JCS payload", "ledger event hash", "settlement anchor_hash",
                                                         "headline consistency", "the absence: no approval event, no verdict, no executed action cited"]}}
    return {"receipt": receipt, "manifest": manifest, "ledger_slice": events, "fre901": fre}


# ---------------------------------------------------------------- assembly and verification

def assemble(p):
    art = chain(p)
    native = "executed_as_approved" if p["executed_amount"] in (None, p["approved_amount"]) else "not_as_approved"
    stated = p["verdict_result"] or native
    vraw, vcont = verdict_over(art, stated)
    if p["mutate_a2_after_verdict"]:
        art["a2_held"] = p["mutate_a2_after_verdict"](art["a2_bytes"])
    else:
        art["a2_held"] = art["a2_bytes"]
    other_raw, other_cont = verdict_over(art, "not_as_approved" if stated == "executed_as_approved" else "executed_as_approved",
                                         body_extra={"note": "another verdict about the same chain, stating the other result"})
    altered_raw = C16.verdict(art["a1_bytes"], art["a2_bytes"], art["record_bytes"], stated, act_time="2026-11-04T11:00:01.000000Z",
                              key="dps/refund-8812/one-chain/executed-as-approved")
    cited = {"this": None, "other": sha256(other_raw), "altered": sha256(altered_raw)}[p["packet_cites_verdict"]]
    pk = packet_nothing_recorded(p) if p["recorded"] == "nothing" else packet(art, vraw, stated, p, cited_digest=cited)
    return {"chain": art, "verdict_raw": vraw, "verdict_container": vcont, "verdict_stated": stated, "verdict_native": native,
            "other_verdict_raw": other_raw, "other_verdict_container": other_cont, "packet": pk, "params": p}


def held_items(a):
    art = a["chain"]
    items = {sha256(raw): (raw, None) for raw in (art["a1_bytes"], art["a2_held"], art["record_bytes"])}
    items[sha256(a["verdict_raw"])] = (a["verdict_raw"], a["verdict_container"])
    items[sha256(a["other_verdict_raw"])] = (a["other_verdict_raw"], a["other_verdict_container"])
    return items


def verify(a):
    art, p = a["chain"], a["params"]
    r = {"standard_commit": C16.STANDARD_COMMIT}
    # links 1 and 2: case 17's verification (Thaha's verifier, the Standard's checks, route 1, J1..J7)
    r["link1_2_thaha_dps"] = C17.verify(art)
    # link 3: the checker written from Wright's text
    chk, anch = checker({sha256(a["verdict_raw"]): T["intake"], sha256(a["other_verdict_raw"]): T["intake"]})
    r["checker_inputs"] = chk.own_inputs()
    r["link3_verdict"] = chk.check(a["verdict_raw"], held_items(a), a["verdict_container"])
    r["link3_other_verdict"] = chk.check(a["other_verdict_raw"], held_items(a), a["other_verdict_container"])
    # link 4: the verifier written from Goshi's and Farley's texts
    held = {TYPE_A: {sha256(art["a1_bytes"]), sha256(art["a2_held"])}, TYPE_S: {sha256(art["sig_bytes"])},
            TYPE_V: {sha256(a["verdict_raw"]), sha256(a["other_verdict_raw"])}, TYPE_R: {AEE.record_hash(x).hex() for x in art["receipts"]}}
    r["link4_packet"] = G.verify_packet(a["packet"], public_key_hex=C17.raw_public(packet_key).hex(), held=held)
    r["joins"] = joins(a, r)
    l12 = r["link1_2_thaha_dps"]
    r["all_verified"] = (l12["all_verified"] and r["link3_verdict"]["state"] == "released"
                         and r["link4_packet"]["result"] == "VERIFIED" and all(v is True for v in r["joins"].values()))
    return r


def joins(a, r):
    """What none of the four verifiers says alone: the same action, person, moment and bytes in every link."""
    art, pk = a["chain"], a["packet"]
    rs, l12, rep, gr = art["receipts"], r["link1_2_thaha_dps"], r["link3_verdict"], r["link4_packet"]
    confirm, outcome, result = rs[2], rs[3], rs[4]
    v = json.loads(a["verdict_raw"])
    st = {s["stage_id"]: s for s in art["a2"]["stages"]}
    o1, x1, r1 = st["o1"], st["x1"], st["r1"]
    ps = (art["sig"].get("person_signatures") or [{}])[0]
    pay, man, led, fre = pk["receipt"]["payload"], pk["manifest"], pk["ledger_slice"], pk["fre901"]
    block = man.get("settlement_anchor") or {}
    sa = block.get("anchor") or {}                                   # the anchor object of an anchored block; {} when unanchored or missing
    fa = man.get("further_anchors") or {}
    fd = lambda name: fa.get(name, {}).get("digest")                 # a further anchor's digest, None when the packet cites none (N17)
    xspec = json.loads(art["xspec_bytes"])
    rh3, rh4 = AEE.record_hash(outcome).hex(), AEE.record_hash(result).hex()
    approved_amount, moved = art["approved"]["amount_minor"], int(sa.get("amount_minor", "-1"))
    positive = a["verdict_native"] == "executed_as_approved"
    approval_ev = next((e for e in led if e["type"] == "ApprovalGranted"), {})
    exec_ev = next((e for e in led if e["type"] == "ActionExecuted"), {})
    scope_ev = next((e for e in led if e["type"] == "ScopeEvaluated"), {})
    actor_ev = next((e for e in led if e["type"] == "ActorValidated"), {})
    adata = approval_ev.get("data", {})
    ext = adata.get("dps_approval") or {}                            # extension beyond -01: the approval held, by typed digest
    j = {}
    j["K1 one action digest end to end: the confirm receipt's request_digest (Thaha key 12), the SHA-256 of the parameters of the "
      "specification the DPS attempt names, the packet's action_hash, its executed_action_sha256 and the ScopeEvaluated event's "
      "action_hash (the canonical hash of the executed_action it records) are the same hex; the intent scope the packet re-derives "
      "from is the approved specification's parameters, whose digest the person approved (the event's scope_hash)"] = (
        confirm[12][1].hex() == sha256(compact(xspec["parameters"])) == pay["action_hash"] == man["executed_action_sha256"]
        == scope_ev.get("data", {}).get("action_hash")
        and x1["spec_digest"] == sha256(art["xspec_bytes"])
        and man["intent_scope_sha256"] == scope_ev.get("data", {}).get("scope_hash") == sha256(compact(json.loads(art["spec_bytes"])["parameters"]))
        and o1["approved_spec_digest"] == sha256(art["spec_bytes"]) == ps.get("approved_spec_digest"))
    j["K2 approval before allow in every record of it: the person's signature (signed_at) and o1 are at the same moment, after the "
      "confirm receipt and before the allow outcome; the ledger's ApprovalGranted event names that moment and precedes "
      "ActionExecuted; the ActorValidated event precedes the approval"] = (
        bool(ps) and ms(ps.get("signed_at", T["task_start"])) == ms(o1["at"]) and confirm[14] < ms(o1["at"]) < outcome[14]
        and approval_ev.get("data", {}).get("approved_at") == o1["at"] and actor_ev.get("at", "z") < approval_ev.get("at", "") < exec_ev.get("at", ""))
    j["K3 what executed is cited by record-hash in three places: the DPS attempt (trace_refs) and result (evidence_ref) cite the allow "
      "outcome and the tool_result; the ledger's ActionExecuted event carries the same two record-hashes and the response digest; "
      "the packet's further anchors name them; the settlement txn_ref is the outcome receipt's transaction id (key 25) and the attempt's trace_ref"] = (
        rh3 in x1["trace_refs"][0] and rh4 in r1["evidence_ref"] and exec_ev.get("data", {}).get("allow_outcome_record_hash") == rh3
        and exec_ev["data"]["tool_result_record_hash"] == rh4 and exec_ev["data"]["response_sha256"] == result[13][1].hex()
        and fd("allow_outcome_receipt") == rh3 and fd("tool_result_receipt") == rh4
        and sa.get("txn_ref") == outcome[25] == TXN and TXN in x1["trace_refs"])
    j["K4 the verdict's evidence is the exact bytes held of A1, A2 and the record's file (Wright 2.1, 7), and the route 1 statement "
      "cites A2 and the signatures attachment by the same digests (the Standard's identity of an attachment is its file's SHA-256)"] = (
        [e["sha256"] for e in v["evidence"]] == [sha256(art["a1_bytes"]), sha256(art["a2_bytes"]), sha256(art["record_bytes"])]
        and l12["route1"]["bound"] and {x["digest"] for x in l12["route1"]["references"]} >= {sha256(art["a2_bytes"]), sha256(art["sig_bytes"])})
    j["K5 the verdict's result is the re-run's and the Standard's: executed_as_approved exactly when A2 verifies on all eight dimensions "
      "natively; not_as_approved exactly when the action_binding dimension fails"] = (
        rep["steps"].get("3", {}).get("re_run_result") == v["check"]["result"] == a["verdict_stated"]
        and (all(x == "verified" for x in l12["dps_a2"]["dimensions"].values()) if positive
             else l12["dps_a2"]["dimensions"]["action_binding"] == "failed"))
    j["K6 the packet's approval event is our attachment: agent_anchors.approval_event_hash is the event_hash of the ledger's "
      "ApprovalGranted event, whose payload carries (extension beyond -01) the typed digest of A1's exact bytes, the same hex as the "
      "verdict's evidence[0]; the signatures attachment anchor is the route 1 statement's reference; the packet verifier resolved the "
      "event in the slice and the extension's digest against the bytes held"] = (
        man["agent_anchors"]["approval_event_hash"] == approval_ev.get("event_hash") and approval_ev.get("event_hash") is not None
        and ext.get("attachment") == typed(TYPE_A, sha256(art["a1_bytes"])) and v["evidence"][0]["sha256"] == sha256(art["a1_bytes"])
        and fd("signatures_attachment") == sha256(art["sig_bytes"])
        and any(x["name"] == "approval_event_hash" and x["state"].startswith("resolved in the ledger slice") for x in gr["re_derived"].get("anchors", []))
        and any(x["name"].startswith("approval_event_hash.dps_approval.attachment") and x["state"] == "resolved" for x in gr["re_derived"].get("anchors", [])))
    j["K7 the packet cites the verdict the checker released, by the digest of its bytes, and states as scope_conformance what that "
      "verdict's result says: in_scope for executed_as_approved, BREACH:amount_minor for not_as_approved over a different amount"] = (
        fd("verdict_record") == sha256(a["verdict_raw"]) == rep["record_sha256"] and rep["state"] == "released"
        and pay["scope_conformance"] == ("in_scope" if v["check"]["result"] == "executed_as_approved" else "BREACH:amount_minor")
        and gr["re_derived"].get("scope_conformance") == pay["scope_conformance"])
    j["K8 what moved is what the result stage observed: the settlement anchor's amount is the executed specification's amount, the "
      "amount the ActionExecuted event recorded, and the manifest's headline; equal to the approved amount in the positive chain, "
      "different from it in the negative one, where the BREACH names amount_minor"] = (
        moved == xspec["parameters"]["amount_minor"] == int(exec_ev.get("data", {}).get("amount_minor", -1)) == int(man["headline"]["amount_minor"])
        and r1["observed"] == "succeeded" and ((moved == approved_amount) if positive else (moved != approved_amount and pay["scope_conformance"] == "BREACH:amount_minor")))
    j["K9 the custody chain closes on the ledger: every custody event is bound to a ledger event that recomputes; the receipt's "
      "ledger_entry_hash is the ActionExecuted event of this action, whose action_packet_hash is the receipt's action_hash; the "
      "ApprovalGranted event's payload carries the digests of A1 and the signatures attachment held"] = (
        not any(f["code"] in ("CUSTODY_EVENT_UNBOUND", "LEDGER_EVENT_HASH_MISMATCH", "LEDGER_CHAIN_BROKEN") for f in gr["failures"])
        and pay["ledger_entry_hash"] == exec_ev.get("event_hash") and exec_ev.get("data", {}).get("action_packet_hash") == pay["action_hash"]
        and ext.get("signatures_attachment", {}).get("digest") == sha256(art["sig_bytes"])
        and {c["ledger_event_hash"] for c in fre["custody"]} <= {e["event_hash"] for e in led})
    j["K10 one person in every link: the receipts' principal (Thaha 3) is the pepper hash of the canonical identifier of the person o1 "
      "names; the ledger's ActorValidated event and the packet's identity category name that identifier"] = (
        confirm[10] == C17.principal_of(f"user:{o1['actor_ref']}@example.com", art["pepper"]) == outcome[10]
        and actor_ev.get("data", {}).get("actor") == art["canonical_id"] == man["ce3_fpt_categories"]["additional_identity_factor"]["value"])
    j["K11 the moments are in order across the four: task_end (Thaha) < A2 sealed (DPS) < verdict act_time < the checker's intake "
      "(upper bound) < the packet's issued_at; the settlement was captured after the result stage and before the packet"] = (
        AEE.record_hash(rs[5]) is not None and rs[5][14] < ms(T["a2_sealed"]) and T["a2_sealed"][:19] < v["act_time"][:19] < rep.get("upper_time_bound", "")[:19]
        < pay["issued_at"][:19] and r1["at"] < sa.get("captured_at", "") < pay["issued_at"])
    j["K12 four verifiers, the same bytes: Thaha's reaches CHECKS_PERFORMED over the Bundle, the Standard verifies A2 (or fails its "
      "action_binding dimension in the negative chain), the checker releases the verdict, the packet verifier reports VERIFIED, and "
      "the hex digests they report for A1, A2 and the verdict are identical"] = (
        l12["aee"]["result"] == "CHECKS_PERFORMED" and rep["state"] == "released" and gr["result"] == "VERIFIED"
        and rep["record_sha256"] == fd("verdict_record")
        and (l12["dps_a2"]["issuer_seal"] == "verified"))
    return j


def write(out, a, r=None):
    out.mkdir(parents=True, exist_ok=True)
    art = a["chain"]
    C17.write(out, art)
    if art.get("a2_held", art["a2_bytes"]) != art["a2_bytes"]:
        # A2 changed after the verdict cited it (N13): the directory holds what the checker held, under A2's name, and
        # the bytes the verdict cited beside it, so the case can be re-run from the files alone
        (out / "action-binding-attachment-a2.json").write_bytes(art["a2_held"])
        (out / "action-binding-attachment-a2.as-cited-by-the-verdict.json").write_bytes(art["a2_bytes"])
    (out / "action-specification-executed.json").write_bytes(art["xspec_bytes"])
    (out / "verdict-record.json").write_bytes(a["verdict_raw"])
    (out / "verdict-record.container.json").write_text(json.dumps(a["verdict_container"], indent=1) + "\n")
    (out / "verdict-record-other-result.json").write_bytes(a["other_verdict_raw"])
    (out / "dispute-packet.json").write_text(json.dumps(a["packet"], ensure_ascii=False, indent=1) + "\n")
    (out / "dispute-receipt.canonical-payload.json").write_bytes(G.canonical(a["packet"]["receipt"]["payload"]))
    (out / "packet-keys.json").write_text(json.dumps({"merchant_dispute_desk_ed25519_pub": C17.raw_public(packet_key).hex(),
                                                      "auditor_ed25519_pub": C17.raw_public(C16.auditor_key).hex(),
                                                      "note": "test keys from fixed seeds; never use them for anything real"}, indent=1) + "\n")
    if r is not None:
        (out / "summary.json").write_text(json.dumps(r, ensure_ascii=False, indent=1, default=str) + "\n")


if __name__ == "__main__":
    out = HERE / "out"
    pos = assemble(build())
    res = verify(pos)
    write(out / "positive", pos, res)
    neg_p = dict(build(), executed_amount=15000)
    neg = assemble(neg_p)
    nres = verify(neg)
    write(out / "stated-negative", neg, nres)
    l12 = nres["link1_2_thaha_dps"]
    # the stated negative chain: Thaha's J1 false and the Standard's action_binding failed are what it is about; the verdict
    # stating not_as_approved is released and the packet stating the breach verifies
    neg_as_expected = (l12["joins"][next(k for k in l12["joins"] if k.startswith("J1"))] is False and l12["dps_a2"]["dimensions"]["action_binding"] == "failed"
                       and nres["link3_verdict"]["state"] == "released" and neg["verdict_stated"] == "not_as_approved"
                       and nres["link4_packet"]["result"] == "VERIFIED" and nres["link4_packet"]["re_derived"]["scope_conformance"] == "BREACH:amount_minor"
                       and all(v is True for v in nres["joins"].values()))
    summary = {"positive": {k: res[k] for k in ("all_verified", "joins")}, "positive_link_results": {
                   "thaha": res["link1_2_thaha_dps"]["aee"]["result"], "dps_a2": res["link1_2_thaha_dps"]["dps_a2"]["dimensions"],
                   "verdict": res["link3_verdict"]["summary"], "packet": res["link4_packet"]["result"]},
               "stated_negative": {"as_expected": neg_as_expected, "thaha_J1": l12["joins"][next(k for k in l12["joins"] if k.startswith("J1"))],
                                   "dps_a2_action_binding": l12["dps_a2"]["dimensions"]["action_binding"], "verdict": nres["link3_verdict"]["summary"],
                                   "packet": nres["link4_packet"]["result"], "scope_re_derived": nres["link4_packet"]["re_derived"]["scope_conformance"],
                                   "joins": nres["joins"]},
               "goshi_ambiguities": G.AMBIGUITIES, "all_verified": res["all_verified"] and neg_as_expected}
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1, default=str) + "\n")
    print(json.dumps(summary, ensure_ascii=False, indent=1, default=str))
    sys.exit(0 if summary["all_verified"] else 1)
