#!/usr/bin/env python3
"""The failing cases of the real receipt and the decision record: each is a variant of build.py changed in one place and
run through the same checks. A case is located by the places whose verdict differs from its base (flat()); each case
states what must differ, and what must not. The documented cases change nothing that binds, and say so. Exit 0 when
every case is as expected. Layout: out/negatives/<case>/ holds the documents the checks ran on, what.txt and result.json."""
import base64
import copy
import json
import sys

import build as B

N = {}


def case(name, base, what, expect):
    """expect(base_flat, case_flat, changed) -> (ok, note)."""
    def deco(fn):
        N[name] = (base, what, expect, fn)
        return fn
    return deco


def changed_to(*want):
    """The case is caught where it should be: each named place differs from the base, and so does nothing that the
    base held as bound (no place drifts silently)."""
    def ex(b, c, ch):
        missing = [w for w in want if not any(k == w or k.startswith(w + ".") for k in ch)]
        return not missing, ("caught at " + ", ".join(sorted(ch))) if not missing else f"not caught at {missing}"
    return ex


def receipt_payload_edit(rec, fn):
    p = json.loads(base64.b64decode(rec["canonical_bytes"]))
    fn(p)
    raw = B.sorted_utf8(p)
    rec.update(canonical_bytes=base64.b64encode(raw).decode(), canonical_byte_length=len(raw))


@case("L1-receipt-output-altered", "after-the-fact",
      "the real receipt's committed output says $84,135.08 instead of $74,135.08; output_hash not recomputed",
      changed_to("receipt.output_hash"))
def l1(art):
    receipt_payload_edit(art["receipt"], lambda p: p["output"].update(text=p["output"]["text"].replace("74,135.08", "84,135.08")))


@case("L2-receipt-created-at-moved", "after-the-fact",
      "the real receipt's created_at moved to 10:40:00.000Z; metadata_hash not recomputed",
      changed_to("receipt.metadata_hash"))
def l2(art):
    art["receipt"]["created_at"] = "2026-11-10T10:40:00.000Z"


@case("L3-record-cites-another-id", "after-the-fact",
      "the attempt cites another receipt id (the issuer edits it and seals again)",
      changed_to("join.id_cited"))
def l3(art):
    B.reissue(art, lambda st: st["x1"].update(trace_refs=["urn:aer1:receipt:" + B.uuid4_from("another receipt")]))


@case("L4-record-names-another-output-hash", "after-the-fact",
      "the result names another output_hash for this receipt id (the issuer edits it and seals again)",
      changed_to("join.output_hash_named"))
def l4(art):
    other = "sha256:" + B.sha256(b"another output")
    B.reissue(art, lambda st: st["r1"].update(evidence_ref=f"urn:aer1:receipt:{art['receipt']['id']}#output_hash={other}"))


@case("L5-attempt-and-result-before-the-receipt", "after-the-fact",
      "the attempt is dated 10:40:00Z and its result 10:45:00Z, both before the receipt's created_at "
      "(10:51:44.721Z): the result names an output_hash that did not exist yet (sealed again)",
      changed_to("join.result_after_receipt"))
def l5(art):
    B.reissue(art, lambda st: (st["x1"].update(at="2026-11-10T10:40:00Z"), st["r1"].update(at="2026-11-10T10:45:00Z")))


@case("L5b-attempt-after-the-receipt", "after-the-fact",
      "the attempt is dated 10:55:00Z, after the receipt of the call it made (sealed again)",
      changed_to("join.attempt_before_receipt"))
def l5b(art):
    B.reissue(art, lambda st: st["x1"].update(at="2026-11-10T10:55:00Z"))


def backdate(st, view_names_receipt):
    st["p1"]["at"], st["v1"]["at"], st["o1"]["at"] = "2026-11-10T10:40:00Z", "2026-11-10T10:44:00Z", "2026-11-10T10:45:00Z"
    st["o1"]["rationale"]["recorded_at"] = st["o1"]["at"]
    st["q1"]["at"], st["c1"]["at"] = "2026-11-10T10:51:40Z", "2026-11-10T10:51:42Z"
    st["c1"]["result"] = "authorised"
    st["c1"].pop("detail", None)


def backdate_record(art):
    r = art["record"]
    r["affirmation_record"]["timestamp"] = r["review_log"][0]["reviewed_at"] = "2026-11-10T10:45:00Z"
    r["created_at"] = "2026-11-10T10:40:00Z"
    r["seal_hash"] = "0" * 64
    r["seal_hash"] = B.sha256(B.compact(r))


@case("L6-approval-backdated-view-names-the-receipt", "after-the-fact",
      "the after-the-fact record backdated as a whole: proposal, review and approval moved before the call, the request "
      "and an authorising recheck before the attempt, record, seal and the person's signature made again; the view the "
      "reviewer signed still names the receipt",
      lambda b, c, ch: (c["join.review_after_receipt"] == B.NOT_HOLD and c["order"].startswith("contradicted")
                        and c["dps.stage_order"] == "verified",
                        f"the DPS checks pass (stage_order {c['dps.stage_order']}); caught at join.review_after_receipt; "
                        f"order: {c['order']}"))
def l6(art):
    backdate_record(art)
    B.reissue(art, lambda st: backdate(st, True))


@case("L7-after-the-fact-relabelled", "after-the-fact",
      "the request and an authorising recheck re-dated before the attempt, the approval left after the call (sealed "
      "again): the order stays reported as approval after the effect",
      lambda b, c, ch: (c["order"] == "approval_after_effect" and c["dps.stage_order"] == "failed",
                        f"order {c['order']}; stage_order {c['dps.stage_order']} "
                        f"(authorisation_recheck {b['dps.authorisation_recheck']} -> {c['dps.authorisation_recheck']})"))
def l7(art):
    def edit(st):
        st["q1"]["at"], st["c1"]["at"], st["c1"]["result"] = "2026-11-10T10:51:40Z", "2026-11-10T10:51:42Z", "authorised"
        st["c1"].pop("detail", None)
    B.reissue(art, edit)


@case("L8-fully-backdated-view-silent", "after-the-fact",
      "documented limit: the record backdated as in L6, and the view rewritten so that it no longer names the receipt; "
      "everything verifies, and the order is reported as the issuer's statement, never as verified",
      lambda b, c, ch: (c["order"] == "issuer_dated_before_effect" and c["join.review_after_receipt"] == B.NA
                        and all(c[k] in ("verified", "valid") for k in c if k.startswith("dps.")),
                        f"order {c['order']} (time basis: the issuer's clock; no independent timestamp)"))
def l8(art):
    backdate_record(art)
    view = art["view"].decode().split("This call was already made")[0].encode()
    B.reissue(art, lambda st: backdate(st, False), view=view)


@case("L9-pointer-added-by-a-holder", "after-the-fact",
      "documented: someone holding the real receipt adds execution_context.decision_record naming this record; no "
      "receipt check changes (Section 3.2), and the request_id is still absent from the committed bytes",
      lambda b, c, ch: (set(ch) == {"join.pointer_to_record"} and c["join.request_id_committed"] == B.ABSENT,
                        "only the pointer changes: " + ", ".join(f"{k} {b[k]} -> {c[k]}" for k in sorted(ch))))
def l9(art):
    q = next(s for s in art["attachment"]["stages"] if s["stage_id"] == "q1")
    art["receipt"]["execution_context"]["decision_record"] = {"decision_id": art["record"]["decision_id"],
                                                              "record_digest": "sha256:" + art["record"]["seal_hash"],
                                                              "request_id": q["request_id"]}


@case("L10-input-hash-replaced", "after-the-fact",
      "documented: the real receipt's input_hash replaced by the digest of {\"symbol\":\"ETH\"}; output_hash and "
      "metadata_hash still verify (input_hash is outside both), only the consistency with the approved parameters turns",
      lambda b, c, ch: (set(ch) == {"join.input_is_approved"},
                        "only " + ", ".join(f"{k} {b[k]} -> {c[k]}" for k in sorted(ch))))
def l10(art):
    art["receipt"]["input_hash"] = "sha256:" + B.sha256(B.sorted_utf8({"symbol": "ETH"}))


@case("L11-synthetic-receipt-of-another-request", "under-the-decision",
      "(b) a synthetic receipt of the same read under another request_id, cited by the attempt and the result (sealed "
      "again): it verifies on its own; the committed request_id is not this request's",
      changed_to("join.request_id_committed"))
def l11(art):
    art["receipt"] = B.synthetic_receipt(B.VARIANTS["under-the-decision"], art["record"],
                                         request_id="urn:example:valuation-request:other", pointer=True)
    rid, oh = art["receipt"]["id"], art["receipt"]["output_hash"]
    B.reissue(art, lambda st: (st["x1"].update(trace_refs=[f"urn:aer1:receipt:{rid}"]),
                               st["r1"].update(evidence_ref=f"urn:aer1:receipt:{rid}#output_hash={oh}")))


def publish(d, art, what, entry):
    d.mkdir(parents=True, exist_ok=True)
    (d / "receipt.json").write_text(json.dumps(art["receipt"], ensure_ascii=False, indent=1) + "\n")
    (d / "record.json").write_bytes(B.compact(art["record"]))
    (d / "attachment.json").write_bytes(B.compact(art["attachment"]))
    (d / "sig.json").write_bytes(B.compact(art["sig"]))
    (d / "review-view.txt").write_bytes(art["view"])
    (d / "what.txt").write_text(what + "\n")
    (d / "result.json").write_text(json.dumps(entry, ensure_ascii=False, indent=1) + "\n")


def main():
    out = B.HERE / "out" / "negatives"
    out.mkdir(parents=True, exist_ok=True)
    bases = {name: B.flat(B.summarize(name, B.build(name))) for name in B.VARIANTS}
    summary, ok = {}, True
    for name, (base, what, expect, fn) in N.items():
        art = B.build(base)
        fn(art)
        r = B.summarize(base, art)
        c = B.flat(r)
        ch = {k: c[k] for k in c if c[k] != bases[base].get(k)}
        good, note = expect(bases[base], c, ch)
        ok = ok and good
        summary[name] = {"base": base, "what": what, "as_expected": good, "verdict": note,
                         "changed": {k: [bases[base].get(k), v] for k, v in ch.items()},
                         "order": r["order"], "receipt_verifier_as_is": r["receipt"]["independent_verifier_as_is"]["verdict"]}
        publish(out / name, art, what, summary[name])
        print(("ok   " if good else "FAIL ") + f"{name}: {note}")
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
