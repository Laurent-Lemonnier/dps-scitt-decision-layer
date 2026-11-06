#!/usr/bin/env python3
"""The failing cases of the one chain: each is the valid chain changed in one place, run through the same four verifiers
and the twelve joins (build.verify). A case is as expected when every place it names is among those that fail: "aee"
(Thaha's verifier returns FAIL), "J1".."J7" (case 17's joins between the run and the decision), "dps" (a Standard check
of A1, A2, the seal or the person's approval is not verified), "verdict:refused" / "verdict:held" (the checker written
from Wright's text), "goshi:<CODE>" (the packet verifier written from Goshi's and Farley's texts names that failure),
"K1".."K12" (the joins across the four links). Each case is published under out/negatives/<case>/ with every document
as it was, what.txt and result.json; out/negatives/summary.json gathers the verdicts. Exit 0 when every case is as
expected. Deterministic."""
import json
import pathlib
import sys

import build as B

HERE = pathlib.Path(__file__).resolve().parent
N = {}


def case(name, where, what):
    def deco(fn):
        N[name] = (where, what, fn)
        return fn
    return deco


@case("N1-approval-of-other-arguments-everything-downstream-claims-as-approved", ["J1", "dps", "verdict:refused", "goshi:SCOPE_HEADLINE_MISMATCH", "K5", "K7"],
      "the person approved 120.00 EUR; the tool door hashed and executed 150.00 EUR; the auditor nevertheless states executed_as_approved and the "
      "packet asserts in_scope: Thaha's J1 (confirm digest is not the approved parameters) fails, the Standard's action_binding dimension fails, "
      "the checker refuses the verdict at step 3 (re-run gives not_as_approved), the packet verifier re-derives BREACH:amount_minor and names "
      "SCOPE_HEADLINE_MISMATCH")
def n1(p):
    p.update(executed_amount=15000, verdict_result="executed_as_approved", packet_scope="in_scope")


@case("N2-verdict-altered-after-the-packet-cited-it", ["goshi:ANCHOR_UNRESOLVED", "K7"],
      "the auditor's record was re-issued one second later (act_time) after the packet cited the earlier bytes' digest: no verdict record held "
      "has the digest the packet's anchor names")
def n2(p):
    p["packet_cites_verdict"] = "altered"


@case("N3-settlement-150-with-headline-120", ["goshi:SETTLEMENT_HEADLINE_MISMATCH", "K8"],
      "the settlement rail witnessed 150.00 EUR moving where the packet's headline and the result stage say 120.00: what moved is not what the "
      "chain says moved")
def n3(p):
    p["settlement_amount"] = 15000


@case("N4-confirm-without-approval", ["dps", "J2", "K2"],
      "the signatures attachment carries no person signature while o1 is still claimed: the confirm receipt has no member for who confirmed "
      "(Thaha 6.7), the Standard's person_approval check is where the absence shows, and no later link notices (the packet verifies)")
def n4(p):
    p["approval"] = "absent"


@case("N5-packet-cites-another-verdict-about-the-same-chain", ["K7"],
      "the packet's anchor names a verdict record that is held (so the packet verifier resolves it) but that the checker refuses, since it "
      "states not_as_approved over a chain whose re-run gives executed_as_approved: only the join across links sees that the packet rests on "
      "a verdict the checker did not release")
def n5(p):
    p["packet_cites_verdict"] = "other"


@case("N6-custody-event-altered", ["goshi:CUSTODY_EVENT_UNBOUND", "K9"],
      "one custody event's ledger_event_hash was changed: it is bound to no event of the ledger slice (Goshi 4.4)")
def n6(p):
    p["custody"] = "altered"


@case("N7-ledger-event-altered-after-chaining", ["goshi:LEDGER_EVENT_HASH_MISMATCH", "K8", "K9"],
      "the ActionExecuted event's amount was changed after the slice was chained: its hash no longer recomputes (the next event still links to "
      "the stale hash it carries, so the link check alone would not see it); the join on what moved (K8) fails with it")
def n7(p):
    p["ledger"] = "altered"


@case("N8-settlement-anchor-content-changed-hash-stale", ["goshi:SETTLEMENT_ANCHOR_HASH_MISMATCH", "K8"],
      "the settlement block's amount was changed without recomputing anchor_hash (Goshi 4.3, 5)")
def n8(p):
    p["settlement"] = "stale_hash"


@case("N9-manifest-without-settlement-block", ["goshi:SETTLEMENT_UNANCHORED", "K8"],
      "the manifest has no settlement_anchor: Goshi 4.3 says absence MUST be stated as SETTLEMENT_UNANCHORED and the manifest MUST fail")
def n9(p):
    p["settlement"] = "absent"


@case("N10-receipt-payload-edited-after-signing", ["goshi:RECEIPT_SIGNATURE_INVALID", "goshi:SCOPE_HEADLINE_MISMATCH", "K7"],
      "scope_conformance set to not_evaluated in the payload after the signature was computed: the signature over the canonical payload no longer "
      "verifies (Farley 5.2 step 6) and the headline no longer agrees with the re-derivation")
def n10(p):
    p["receipt_tamper"] = lambda pay: {**pay, "scope_conformance": "not_evaluated"}


@case("N11-receipt-signed-by-a-key-not-the-issuers", ["goshi:RECEIPT_SIGNATURE_INVALID"],
      "the envelope names the merchant's kid but the signature is another key's: the key resolved out of band does not verify it (Farley 5.2, 9.5)")
def n11(p):
    p["receipt_key"] = "other"


@case("N12-issuer-id-not-the-kid", ["goshi:RECEIPT_ISSUER_KID_MISMATCH"],
      "the payload's issuer_id names somebody else while the signature's kid and key_id name the merchant: Farley 2.2 says issuer_id MUST match kid; "
      "the signature itself verifies, since issuer_id is under it")
def n12(p):
    p["issuer_id"] = "sb:issuer:somebody-else"


@case("N13-a2-altered-after-the-verdict-cited-it", ["verdict:held", "K12"],
      "one member of A2 changed (observed succeeded -> failed) after the verdict cited its bytes: the checker holds no item with the cited "
      "digest and holds the verdict; the packet, which anchors on A1, not A2, verifies and says nothing")
def n13(p):
    p["mutate_a2_after_verdict"] = lambda raw: raw.replace(b'"observed":"succeeded"', b'"observed":"failed"')


@case("N14-dispute-reason-code-missing", ["goshi:DISPUTE_REASON_CODE_MISSING"],
      "the manifest carries no dispute reason code: Goshi 4.1 says the mapper MUST raise rather than pass silently")
def n14(p):
    p["dispute_reason_code"] = None


@case("N15-approval-after-the-allow-outcome", ["J2", "K2", "dps", "verdict:refused"],
      "the person signed at 10:01:19, after the allow outcome of 10:01:18 and after the request stage: the call proceeded before the "
      "confirmation it required; Thaha's receipts alone cannot see it (J2 joins on the DPS time), the Standard's stage_order fails, and the "
      "verdict stating executed_as_approved is refused since the rule reads the Standard's dimensions")
def n15(p):
    p["approval"] = "after_outcome"


@case("N16-one-approval-used-twice", ["dps", "verdict:refused", "goshi:APPROVAL_EVENT_CITED_TWICE", "K5"],
      "the same person approval (o1, request_limit 1; the same A1, the same approval event digest) is used for a second refund: a second "
      "confirm/allow/tool_result triple in the run (txn-2026-1104-8812-2), a second DPS request, recheck, attempt and result resting on o1, "
      "and a packet citing the same approval event for two transfers (two settlement anchors): the Standard's action_binding reference "
      "check fails first (q2: o1 covers 1 request, already used by q1; the specification requested twice), the verdict stating "
      "executed_as_approved is refused at step 3 (the re-run gives not_as_approved: no approval covers the second attempt), the packet "
      "verifier names APPROVAL_EVENT_CITED_TWICE. Thaha's receipts each look fine on their own (CHECKS_PERFORMED; two well-formed "
      "confirm/allow pairs) and J1-J6 hold: the run alone cannot see it (J7 reads false only by its wording: it looks for one signed "
      "confirm receipt and the verifier reports two)")
def n16(p):
    p["second_use_of_approval"] = True


@case("N17-money-moved-nothing-recorded", ["goshi:NOTHING_RECORDED", "K3", "K6", "K7"],
      "the settlement anchor records a transfer of 120.00 EUR (txn-2026-1104-0931, final) for which there is no confirm/allow receipt, "
      "no DPS request or attempt and no verdict: the packet's approval event is null, further_anchors is empty, intent scope and executed "
      "action are null (scope not_evaluated), the ledger slice holds the one event the merchant recorded. The packet verifier reports "
      "NOTHING_RECORDED, a result of its own, neither VERIFIED nor a BREACH; the joins fail for want of a record to join (K3, K6, K7); "
      "the receipts, the Standard and the verdict say nothing: their documents (present here, verified, released) are those of the "
      "recorded refund txn-2026-1104-8812 and name no such transfer. Only the dispute layer, holding the settlement, can raise it")
def n17(p):
    p.update(recorded="nothing", dispute_reason_code="unrecognized_transaction")


def failed_places(a, r):
    l12, failed = r["link1_2_thaha_dps"], set()
    if l12["aee"]["result"] != "CHECKS_PERFORMED":
        failed.add("aee")
    for k in ("dps_a1", "dps_a2"):
        dims = l12[k]["dimensions"]
        if [d for d, v in dims.items() if v not in ("verified", "not_checked")] or l12[k]["issuer_seal"] != "verified" \
                or l12[k]["person_approval"]["status"] != "verified":
            failed.add("dps")
    for k, v in l12["joins"].items():
        if v is not True:
            failed.add(k.split(" ")[0])
    if r["link3_verdict"]["state"] != "released":
        failed.add("verdict:" + r["link3_verdict"]["state"])
    for f in r["link4_packet"]["failures"]:
        failed.add("goshi:" + f["code"])
    for k, v in r["joins"].items():
        if v is not True:
            failed.add(k.split(" ")[0])
    return failed


def run_case(name):
    where, what, fn = N[name]
    p = B.build()
    fn(p)
    a = B.assemble(p)
    r = B.verify(a)
    failed = failed_places(a, r)
    out = HERE / "out" / "negatives" / name
    B.write(out, a, r)
    (out / "what.txt").write_text(what + "\n")
    verdict = {"case": name, "expected_to_fail_at": where, "failed_at": sorted(failed), "as_expected": set(where) <= failed,
               "verdict_state": r["link3_verdict"]["state"], "packet": r["link4_packet"]["result"],
               "packet_failures": [f["code"] for f in r["link4_packet"]["failures"]],
               "joins_false": [k.split(" ")[0] for k, v in r["joins"].items() if v is not True]}
    (out / "result.json").write_text(json.dumps(verdict, indent=1, default=str) + "\n")
    return verdict


if __name__ == "__main__":
    verdicts = [run_case(n) for n in N]
    (HERE / "out" / "negatives" / "summary.json").write_text(json.dumps(verdicts, indent=1, default=str) + "\n")
    for v in verdicts:
        print(f"{'ok ' if v['as_expected'] else 'NOT'} {v['case']}: expected {v['expected_to_fail_at']}, failed at {v['failed_at']}")
    print(f"{sum(v['as_expected'] for v in verdicts)}/{len(verdicts)} failing cases caught where expected")
    sys.exit(0 if all(v["as_expected"] for v in verdicts) else 1)
