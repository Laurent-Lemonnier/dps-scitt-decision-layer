#!/usr/bin/env python3
"""The failing cases of the DPS and AER-1 composition: each is the valid pair changed in one place, run through the
same checks (build.verify). out/negatives/summary.json records every place that fails; a case is as expected when the
place it names is among them, and a documented case (the execution_context pointer) when everything verifies and the
pointer is reported as it should be. Exit 0 when every case is as expected."""
import copy
import json
import sys

import build as B

N = {}


def case(name, where, what):
    def deco(fn):
        N[name] = (where, what, fn)
        return fn
    return deco


def reissue(art, **kw):
    """The receipt as a producer would issue it again with these changes: every hash recomputed, so the receipt
    verifies on its own; the attachment and its seal are left as they were."""
    art["receipt"] = B.make_receipt(art["record"], **kw)


@case("N1-output-altered", "aer1", "the receipt's outputs say 150.00 EUR; output_hash not recomputed")
def n1(art):
    import base64
    payload = json.loads(base64.b64decode(art["receipt"]["canonical_bytes"]))
    payload["outputs"]["amount_minor"] = 15000
    raw = B.AER.canonical_json(payload).encode()
    art["receipt"].update(canonical_bytes=base64.b64encode(raw).decode(), canonical_byte_length=len(raw))


@case("N2-receipt-reissued-with-other-output", "joins", "the receipt is issued again with a different refund reference; it verifies, but the DPS result names the first output_hash")
def n2(art):
    reissue(art, outputs={"refund_ref": "urn:example:refund:R-55999", "status": "succeeded", "amount_minor": 12000,
                          "currency": "EUR", "idempotency_key": B.REQUEST_ID})


@case("N3-receipt-of-another-request", "joins", "a receipt of the same refund under another idempotency key, cited as this attempt's")
def n3(art):
    reissue(art, inputs={**B.PARAMS, "idempotency_key": "urn:example:refund-request:other"})
    _resign_citing(art)


@case("N4-executed-input-not-approved", "joins", "the gateway recorded 150.00 EUR; the person approved 120.00 EUR")
def n4(art):
    reissue(art, inputs={**B.PARAMS, "amount_minor": 15000, "idempotency_key": B.REQUEST_ID})
    _resign_citing(art)


@case("N5-attempt-cites-another-receipt-unsealed", "dps_issuer_seal", "the attempt is edited to cite another receipt id after the issuer sealed it")
def n5(art):
    x = next(s for s in art["attachment"]["stages"] if s["stage_id"] == "x1")
    x["trace_refs"] = ["urn:aer1:receipt:" + B.uuid4_from("another receipt")]


@case("N5b-attempt-cites-another-receipt-resealed", "joins", "the issuer edits the attempt to cite another receipt id and seals again")
def n5b(art):
    n5(art)
    B.seal(art["attachment"])


@case("N6-metadata-altered", "aer1", "the receipt's created_at is moved; metadata_hash not recomputed")
def n6(art):
    art["receipt"]["created_at"] = "2026-10-28T14:00:00.000Z"


@case("N7-receipt-before-the-attempt", "joins", "the receipt is issued at 14:06Z, before the approval and the attempt (hashes recomputed)")
def n7(art):
    reissue(art, created_at="2026-10-28T14:06:00.000Z")
    _resign_citing(art)


@case("N8-pointer-to-another-record", "documented", "execution_context names another decision record: everything verifies, the pointer is reported inconsistent")
def n8(art):
    art["receipt"]["execution_context"]["decision_record"]["decision_id"] = "DR-2026-9999"


@case("N9-pointer-dropped", "documented", "execution_context carries no decision_record: everything verifies, the pointer is reported absent")
def n9(art):
    del art["receipt"]["execution_context"]["decision_record"]


def _resign_citing(art):
    """The issuer's result cites the receipt it holds now, and the attachment is sealed again: the failure, if any, is
    then in what the receipt binds, not in a stale citation."""
    r = next(s for s in art["attachment"]["stages"] if s["stage_id"] == "r1")
    r["evidence_ref"] = f"urn:aer1:receipt:{art['receipt']['id']}#output_hash={art['receipt']['output_hash']}"
    B.seal(art["attachment"])


def failures(r):
    f = {}
    if any(r["schema_errors"].values()):
        f["schema"] = {k: v[:2] for k, v in r["schema_errors"].items() if v}
    if r["aer1_independent"]["verdict"] != "pass" or (isinstance(r["aer1_kit"], dict) and any(v != "pass" for v in r["aer1_kit"].values())):
        f["aer1"] = {"independent": r["aer1_independent"]["verdict"],
                     "kit": {k: v for k, v in r["aer1_kit"].items() if v != "pass"} if isinstance(r["aer1_kit"], dict) else r["aer1_kit"]}
    bad = {d: s for d, s in r["dps_action_binding"].items() if s != "verified"}
    if bad:
        f["dps_action_binding"] = {d: [s, r["dps_action_binding_findings"].get(d, [])[:2]] for d, s in bad.items()}
    if r["dps_issuer_seal"]["status"] != "verified":
        f["dps_issuer_seal"] = r["dps_issuer_seal"]
    if r["dps_person_approval"]["status"] != "verified":
        f["dps_person_approval"] = r["dps_person_approval"]
    j = [k for k, v in r["joins"].items() if v is not True]
    if j:
        f["joins"] = j
    return f


def main():
    out = B.HERE / "out" / "negatives"
    out.mkdir(parents=True, exist_ok=True)
    summary, ok = {}, True
    for name, (where, what, fn) in N.items():
        art = B.build()
        fn(art)
        r = B.verify(art)
        f = failures(r)
        if where == "documented":
            expected = not f and r["all_verified"] and not r["execution_context_pointer"].startswith("consistent")
        else:
            expected = where in f
        ok = ok and expected
        summary[name] = {"what": what, "caught_by": sorted(f), "expected_place": where, "as_expected": expected,
                         "execution_context_pointer": r["execution_context_pointer"], "detail": f}
        (out / f"{name}.json").write_text(json.dumps(summary[name], ensure_ascii=False, indent=1) + "\n")
        print(("ok   " if expected else "FAIL ") + f"{name}: caught by {', '.join(sorted(f)) or 'nothing'}"
              + ("" if f else f"; pointer {r['execution_context_pointer'].split(':')[0]}"))
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n")
    ok = metadata_probes(out) and ok
    return 0 if ok else 1


def metadata_probes(out):
    """Draft -26 Section 6 step 4: for a receipt carrying metadata_hash, recompute the Section 3.1 metadata block from
    the stored members and fail on a mismatch. Four changes to members that only that block binds, each run through the
    independent verifier (asserted: it must fail them) and the kit's checks at the pinned commit (recorded as found,
    not asserted)."""
    changes = {"created_at moved": lambda r: r.update(created_at="2026-10-28T14:00:00.000Z"),
               "id replaced": lambda r: r.update(id=B.uuid4_from("another id")),
               "tool version changed": lambda r: r["tool"].update(version="9.9.9"),
               "metadata_hash zeroed": lambda r: r.update(metadata_hash="sha256:" + "0" * 64)}
    probes, ok = {}, True
    for name, change in changes.items():
        rec = copy.deepcopy(B.build()["receipt"])
        change(rec)
        independent = B.AER.structural(copy.deepcopy(rec), strict_id=True)
        kit = {}
        if B.KITC:
            kit["conformance.check"] = B.KITC.check(copy.deepcopy(rec)) or "pass"
            kit["conformance.check_version_and_binding"] = B.KITC.check_version_and_binding(copy.deepcopy(rec))[1] or "pass"
        if B.KITREF:
            passed, checks, id_state, _ = B.KITREF.verify(copy.deepcopy(rec))
            kit["aer1_verify.verify"] = "pass" if passed else [c["check"] for c in checks if not c.get("ok")]
            kit["aer1_verify id_state"] = id_state
        probes[name] = {"independent": independent[0], "independent_reason": independent[1], "kit": kit}
        ok = ok and independent[0] == "verification failed"
        print(("ok   " if independent[0] == "verification failed" else "FAIL ") + f"metadata probe, {name}: independent "
              f"{independent[0]}; kit " + ", ".join(f"{k} {v if isinstance(v, str) else 'fail'}" for k, v in kit.items()))
    (out / "metadata-probes.json").write_text(json.dumps(probes, ensure_ascii=False, indent=1) + "\n")
    return ok


if __name__ == "__main__":
    sys.exit(main())
