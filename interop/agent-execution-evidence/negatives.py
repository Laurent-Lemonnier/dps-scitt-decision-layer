#!/usr/bin/env python3
"""The failing cases of the AEE and DPS composition: each is the valid set changed in one place, run through the same
checks (build.verify). A case is as expected when every place it names is among those that fail: "aee" (the verifier
written from the author's text returns FAIL), "dps" (a Standard check of A1, A2, the seal or the person's approval is
not verified), "route1" (the separate Signed Statement does not bind), "route2" (the proposed key does not bind), or a
join by its label (J1..J7 false). Each case is published under out/negatives/<case>/ with the documents as they were
(decision record, A1, A2, signatures attachment, Bundle, binding statement), what.txt and result.json;
out/negatives/summary.json gathers the verdicts. Exit 0 when every case is as expected. Deterministic."""
import copy
import hashlib
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


def resign_receipts_from(art, first_changed):
    """Receipts from first_changed on are re-chained (prev_hash recomputed) as the Evidence Service would record them;
    the confirm receipt's agent_sig is left as it was unless the case changes that receipt itself."""
    rs = art["receipts"]
    for i in range(first_changed, len(rs)):
        if i > 0:
            rs[i][3] = B.AEE.record_hash(rs[i - 1])
    B.rebuild_after(art)


@case("N1-confirm-without-approval", ["dps", "J2"],
      "the signatures attachment carries no person signature and o1 is still claimed: the confirm receipt's outcome has no "
      "record of who confirmed (6.7 has no member for it); the DPS side is where the absence shows")
def n1(art):
    art["sig"] = {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": []}
    art["sig_bytes"] = B.compact(art["sig"])
    B.rebuild_after(art)


@case("N2-approval-of-another-specification", ["dps", "J2"],
      "the person signed another specification's digest (a 4,800.00 EUR invoice to another customer); o1 and the receipts are unchanged")
def n2(art):
    other = B.compact({**B.SPEC, "parameters": {**B.PARAMS, "customer_ref": "urn:example:customer:C-9999"}})
    art["sig"] = B.make_signatures(art["record"], B.sha256(art["spec_bytes"]), approved=B.sha256(other))
    art["sig_bytes"] = B.compact(art["sig"])
    B.rebuild_after(art)


@case("N3-approval-after-the-call", ["dps", "J2"],
      "the approval (o1 and the person's signed_at) is dated after the allow outcome and the tool_result: the call proceeded "
      "before anyone confirmed; 6.7 says the call is to be read as not having proceeded until the outcome, and the outcome "
      "preceded the approval")
def n3(art):
    late = "2026-11-04T10:01:25Z"
    sd = B.sha256(art["spec_bytes"])
    art["sig"] = B.make_signatures(art["record"], sd, signed_at=late)
    art["sig_bytes"] = B.compact(art["sig"])
    head = B.head_stages(sd, approval_at=late)
    art["a1"] = B.seal(B.attachment(sd, art["spec_bytes"], copy.deepcopy(head)), "2026-11-04T10:01:26Z")
    art["a1_bytes"] = B.compact(art["a1"])
    art["a2"]["stages"] = head + [s for s in art["a2"]["stages"] if s["kind"] not in ("proposal", "review", "outcome")]
    B.rebuild_after(art)


@case("N4-record-hash-chain-broken", ["aee"],
      "the allow outcome's prev_hash is another digest: the chain of 6.7.1 breaks at seq 3 (E_CHAIN_HASH); the DPS attempt "
      "still cites the receipt as recorded")
def n4(art):
    art["receipts"][3][3] = hashlib.sha256(b"another record").digest()
    resign_receipts_from(art, 4)


@case("N5-statement-cites-another-attachment", ["route1"],
      "the separate Signed Statement names another attachment's digest (one byte changed): the route 1 reference does not "
      "resolve against the bytes held; everything else verifies")
def n5(art):
    refs = B.make_refs(art["a2_bytes"], art["sig_bytes"], art["receipts"])
    d = refs[0][3]
    refs[0][3] = d[:-1] + ("0" if d[-1] != "0" else "1")
    art["binding"] = B.binding_statement(refs)


@case("N6-person-signature-invalid", ["dps"],
      "one byte of the person's signature changed: the Standard's person_approval check fails; the receipts are unchanged")
def n6(art):
    ps = art["sig"]["person_signatures"][0]
    raw = bytearray(B.base64.b64decode(ps["signature"]["value_b64"]))
    raw[0] ^= 0x01
    ps["signature"]["value_b64"] = B.b64(bytes(raw))
    art["sig_bytes"] = B.compact(art["sig"])
    B.rebuild_after(art)


@case("N7-allow-without-dps-request", ["dps", "J3"],
      "the DPS attachment has no request and no recheck stage: the allow outcome was recorded and executed without the request "
      "the approval authorises; the Standard's action binding and recheck dimensions fail, J3 is false")
def n7(art):
    art["a2"]["stages"] = [s for s in art["a2"]["stages"] if s["kind"] not in ("request", "recheck")]
    B.rebuild_after(art)
    # rebuild_after re-derives the tail from the kinds present: without a request the attempt has no request_ref; the
    # Standard's checker expects one on every attempt (its schema requires it), so the attempt keeps the dangling refs
    for s in art["a2"]["stages"]:
        if s["kind"] == "attempt":
            s.update(request_ref="q1", recheck_ref="c1")
    art["a2"] = B.seal(art["a2"], B.T["a2_sealed"])
    art["a2_bytes"] = B.compact(art["a2"])
    art["binding"] = B.binding_statement(B.make_refs(art["a2_bytes"], art["sig_bytes"], art["receipts"]))


@case("N8-confirm-names-another-person", ["J5"],
      "the receipts' principal is the peppered digest of another person (user:someone-else@example.com) while o1 and the "
      "signature name finance-controller-1: both sides verify alone, the join on the principal is false")
def n8(art):
    other = B.principal_of("user:someone-else@example.com")
    rs = art["receipts"]
    for r in rs:
        r[10] = other
    # the Harness re-chains, and the agent signs the changed confirm receipt again (agent_sig is over the body without 15)
    rs[1][3] = B.AEE.record_hash(rs[0])
    rs[2][3] = B.AEE.record_hash(rs[1])
    rs[2][15] = B.agent_sig({k: v for k, v in rs[2].items() if k != 15})
    resign_receipts_from(art, 3)


@case("N9-tool-result-before-outcome", ["aee"],
      "the tool_result's parent is the confirm receipt (seq 2), not the allow outcome: 6.7 'A tool_result for the call MUST NOT "
      "precede an allow outcome' (E_TASK)")
def n9(art):
    art["receipts"][4][5] = 2
    resign_receipts_from(art, 4)


@case("N10-outcome-for-other-arguments", ["aee"],
      "the allow outcome's request_digest differs from the confirm's (the arguments changed between confirmation and "
      "execution): 6.7 requires the same request_digest (E_TASK); J1 is still true of the confirm receipt, so the aee verdict "
      "is where it shows")
def n10(art):
    art["receipts"][3][12] = B.digest(B.compact({**B.PARAMS, "amount_minor": 980000}))
    resign_receipts_from(art, 3)



@case("N11-task-ends-with-confirm-pending", ["aee"],
      "no outcome for the confirm: the chain goes confirm, task_end; 6.7 'A Task MUST NOT end while a confirm in it awaits "
      "its outcome' (E_TASK). The DPS side is rebuilt to cite what exists; the case is about his rule")
def n11(art):
    rs = art["receipts"]
    art["receipts"] = [rs[0], rs[1], rs[2], {**rs[5], 2: 3}]
    art["receipts"][3][3] = B.AEE.record_hash(rs[2])
    # A2 can only cite what exists: no outcome and no tool_result, so the tail stops at the request and recheck
    sd = B.sha256(art["spec_bytes"])
    stages = B.head_stages(sd) + B.tail_stages(sd, rs)[:2]
    art["a2"] = B.seal(B.attachment(sd, art["spec_bytes"], stages), B.T["a2_sealed"])
    art["a2_bytes"] = B.compact(art["a2"])
    art["bundle"] = B.make_bundle(art["receipts"])
    art["binding"] = B.binding_statement(B.make_refs(art["a2_bytes"], art["sig_bytes"], art["receipts"]))



@case("N12-proposal-key-cites-another-attachment", ["route2"],
      "route 2 (the proposal): key 30 on the allow outcome names another attachment's digest; verified only by our side, "
      "and only there does it fail; the author's text is not involved")
def n12(art):
    art["receipts"][3][30][0][2] = B.digest(b"another attachment")
    resign_receipts_from(art, 3)


def run_case(name):
    where, what, fn = N[name]
    art = B.build(route2=name.startswith("N12"))
    fn(art)
    res = B.verify(art)
    failed = set()
    if res["aee"]["result"] != "CHECKS_PERFORMED":
        failed.add("aee")
    for k in ("dps_a1", "dps_a2"):
        dims = res[k]["dimensions"]
        bad = [d for d, v in dims.items() if v not in ("verified", "not_checked")]   # not_checked: no stage of that kind
        if bad or res[k]["issuer_seal"] != "verified" or res[k]["person_approval"]["status"] != "verified":
            failed.add("dps")
    if not res["route1"]["bound"]:
        failed.add("route1")
    if art["route2"] and not res["route2"]["bound"]:
        failed.add("route2")
    for k, v in res["joins"].items():
        if v is not True:
            failed.add(k.split(" ")[0])
    expected = set(where) <= failed
    out = HERE / "out" / "negatives" / name
    out.mkdir(parents=True, exist_ok=True)
    B.write(out, art)
    (out / "what.txt").write_text(what + "\n")
    verdict = {"case": name, "expected_to_fail_at": where, "failed_at": sorted(failed), "as_expected": expected,
               "aee": {"result": res["aee"]["result"], "error": res["aee"].get("error"), "detail": res["aee"].get("detail")},
               "dps_a2_dimensions": res["dps_a2"]["dimensions"], "dps_person_approval": res["dps_a2"]["person_approval"]["status"],
               "route1_bound": res["route1"]["bound"], "route2": res["route2"], "joins_false": [k for k, v in res["joins"].items() if v is not True]}
    (out / "result.json").write_text(json.dumps(verdict, indent=1, default=str) + "\n")
    return verdict


if __name__ == "__main__":
    verdicts = [run_case(n) for n in N]
    (HERE / "out" / "negatives" / "summary.json").write_text(json.dumps(verdicts, indent=1, default=str) + "\n")
    for v in verdicts:
        print(f"{'ok ' if v['as_expected'] else 'NOT'} {v['case']}: expected {v['expected_to_fail_at']}, failed at {v['failed_at']}"
              + (f" ({v['aee']['error']}: {v['aee']['detail']})" if v['aee']['error'] else ""))
    print(f"{sum(v['as_expected'] for v in verdicts)}/{len(verdicts)} failing cases caught where expected")
    sys.exit(0 if all(v["as_expected"] for v in verdicts) else 1)
