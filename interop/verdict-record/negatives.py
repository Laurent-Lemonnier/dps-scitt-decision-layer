#!/usr/bin/env python3
"""The failing cases: each is the valid case changed in one place, run through the same checks (build.verify), with
the state or the join expected written beside what was observed. Exit 0 when every case is as expected. Each case's
directory under out/negatives/ holds the verdict record(s) as bytes, their containers, every evidence item by its
digest, the checker's policy and anchors, and result.json: enough to re-run the checker on them."""
import copy
import json
import sys

import build as B

N = {}


def case(name, what, expect):
    def deco(fn):
        N[name] = (what, fn, expect)
        return fn
    return deco


def v(r, name):
    return r["verdict"][name]


# ---- part A: the verdict over the chain

@case("N1-executed-150-approved-120-verdict-says-as-approved",
      "A2 requests and attempts a specification of 150.00 EUR where 120.00 was approved; the auditor's verdict still states "
      "executed_as_approved: the re-run gives not_as_approved",
      lambda r: v(r, "A_version_1")["state"] == "refused" and v(r, "A_version_1")["first_failed_step"] == "3"
      and v(r, "A_version_1")["steps"]["3"]["re_run_result"] == "not_as_approved"
      and not r["dps"]["A_executed_A2"]["verified"] and r["dps"]["A_executed_A2"]["dimensions"]["action_binding"] == "failed")
def n1(p):
    p["executed_amount"] = 15000


@case("N2-evidence-bytes-altered-after-citation",
      "one member of A2 changed after the verdict cited it (observed succeeded -> failed): no item held has the cited digest",
      lambda r: v(r, "A_version_1")["state"] == "held" and v(r, "A_version_1")["first_not_run_step"] == "2"
      and v(r, "A_version_1")["steps"]["2"]["needs"] == "evidence[1]" and v(r, "A_version_1")["steps"]["2"]["items"][1]["held"] is False)
def n2(p):
    p["mutate_a2_bytes"] = lambda raw: raw.replace(b'"observed":"succeeded"', b'"observed":"failed"')


@case("N3-no-container-writer-signature-absent",
      "the record's bytes arrive without a container: no key shown to bind them to the writer (Wright Section 3)",
      lambda r: v(r, "A_version_1")["state"] == "held" and v(r, "A_version_1")["container"]["shows_the_record"] is False
      and all(s["result"] == "PASS" for s in v(r, "A_version_1")["steps"].values()))
def n3(p):
    p["container"] = "none"


@case("N4-container-signed-by-a-key-not-the-writers",
      "the container names the writer's key reference but the signature is another key's",
      lambda r: v(r, "A_version_1")["state"] == "held" and v(r, "A_version_1")["container"]["shows_the_record"] is False
      and "does not verify" in v(r, "A_version_1")["container"]["reason"])
def n4(p):
    p["container"] = "other_key"


@case("N5-record-not-in-canonical-form",
      "a space after the first comma: re-serializing the parsed record does not give the same bytes (Section 2.1)",
      lambda r: v(r, "A_version_1")["state"] == "refused" and "canonical" in v(r, "A_version_1").get("before_steps", ""))
def n5(p):
    p["mutate_verdict_bytes"] = lambda raw: raw.replace(b",", b", ", 1)


@case("N6-a-member-this-document-does-not-define",
      "a member 'note' added to the record (Section 2.2: no other member is allowed)",
      lambda r: v(r, "A_version_1")["state"] == "refused" and "no other member" in v(r, "A_version_1").get("before_steps", ""))
def n6(p):
    def add(raw):
        d = json.loads(raw)
        d["note"] = "the auditor's remark"
        return B.V.canonical_bytes(d)
    p["mutate_verdict_bytes"] = add


@case("N7-judgement-on-a-check-run",
      "rule judgement on a record of kind check-run, which the checker's policy does not list for judgement (step 1)",
      lambda r: v(r, "A_version_1")["state"] == "refused" and v(r, "A_version_1")["first_failed_step"] == "1")
def n7(p):
    p["verdict_kwargs"] = {"rule": "judgement", "inputs": {}}


@case("N8-evidence-format-not-in-the-checkers-policy",
      "the checker's policy does not list the action-binding format: the items are held but not relied on (step 2)",
      lambda r: v(r, "A_version_1")["state"] == "held" and v(r, "A_version_1")["first_not_run_step"] == "2"
      and v(r, "A_version_1")["steps"]["2"]["items"][0]["format_rules"] == "not in the checker's policy")
def n8(p):
    p["policy"]["formats"] = [f for f in p["policy"]["formats"] if f != B.FMT_ATTACHMENT]


@case("N9-pointer-does-not-resolve",
      "the attempted digest is bound to /stages/9/spec_digest; A2 has seven stages (step 3 FAILs, not a result of the rule)",
      lambda r: v(r, "A_version_1")["state"] == "refused" and v(r, "A_version_1")["first_failed_step"] == "3"
      and "does not resolve" in v(r, "A_version_1")["steps"]["3"]["why"])
def n9(p):
    p["verdict_kwargs"] = {"attempt_index": 9}


def _body_copy(p):
    sd = B.sha256(B.compact(B.spec_of(12000)))
    inputs = {"approval": {"evidence": 0, "pointer": ""}, "attachment": {"evidence": 1, "pointer": ""}, "record": {"evidence": 2, "pointer": ""},
              "approved_spec_digest": {"evidence": 0, "pointer": "/stages/2/approved_spec_digest"}, "attempted_spec_digest": "attempted"}
    p["verdict_kwargs"] = {"inputs": inputs, "body_extra": {"attempted": sd}}


@case("N10-an-input-copied-into-body-under-an-evidence-only-policy",
      "attempted_spec_digest copied into body instead of bound to A2; the checker reads inputs from evidence only (Section 4.5): step 3 NOT RUN",
      lambda r: v(r, "A_version_1")["state"] == "held" and v(r, "A_version_1")["first_not_run_step"] == "3"
      and "read from body" in v(r, "A_version_1")["steps"]["3"]["why"])
def n10(p):
    _body_copy(p)


@case("N10b-the-same-copy-under-the-default-policy-released-and-named",
      "the same record under the default policy: released, the report naming the input read from body (Section 4.2, Section 4.4). "
      "Expected by Wright's text, not a failure: it shows what the evidence-only policy adds",
      lambda r: v(r, "A_version_1")["state"] == "released" and v(r, "A_version_1")["body_inputs_read"] == ["attempted_spec_digest"])
def n10b(p):
    _body_copy(p)
    p["policy"]["inputs_from_evidence_only"] = False


# ---- part B: the decision over the verdict

@case("N11-the-verdict-cited-by-the-closing-decision-altered-after-citation",
      "the closing decision names the digest of a verdict record whose act_time is one second later than the one held: the DPS "
      "checks of the closing decision verify (they do not read the citation), the join does not",
      lambda r: r["dps"]["B_closing"]["verified"] and r["joins"][next(k for k in r["joins"] if k.startswith("B1."))] is False
      and v(r, "A_version_1")["state"] == "released")
def n11(p):
    p["b_cites"] = "altered"


# ---- part C: supersession

@case("N12-version-2-supersedes-a-digest-of-nothing-held",
      "version 2 names another digest in supersedes: the steps of Section 4.3 do not read supersedes, the record is released; the "
      "join on the pair does not hold",
      lambda r: v(r, "C_version_2")["state"] == "released" and r["joins"][next(k for k in r["joins"] if k.startswith("C1."))] is False)
def n12(p):
    p["c_supersedes"] = "wrong"


@case("N13-version-2-with-supersedes-null",
      "version 2 with supersedes null (Section 2.2: for a later version, the digest of the previous version): refused before any step",
      lambda r: v(r, "C_version_2")["state"] == "refused" and "supersedes" in v(r, "C_version_2").get("before_steps", ""))
def n13(p):
    p["c_supersedes"] = "null"


# ---- citation of a verdict record by a verdict record (Section 4.3 step 2, Section 6)

def reassessment(cited_bytes, result="unsupported"):
    """A record by another party's checker reassessing the auditor's verdict: kind model-decision, rule judgement, the
    earlier record cited under the format verdict-record/1 (Section 6: released only while the earlier one is)."""
    r = {"v": B.V.VERSION, "kind": "model-decision", "key": "reassessment/refund-8812", "version": 1, "supersedes": None,
         "writer": B.AUDITOR, "actor": {"type": "system", "id": "reassessor", "model": "example-model", "model_version": "1"},
         "act_time": "2026-11-06T12:00:00.000000Z",
         "evidence": [{"sha256": B.sha256(cited_bytes), "format": B.FMT_VERDICT}],
         "check": {"rule": "judgement", "result": result},
         "body": {"claim": {"text": "the auditor's verdict on the refund of order 8812 stands"}}}
    return B.V.canonical_bytes(r)


@case("N14-a-verdict-citing-a-refused-verdict-record",
      "a reassessment record cites, under the format verdict-record/1, the verdict of N1 (refused): the cited record is checked as a "
      "record of its own and is not released, so step 2 is NOT RUN (Section 4.3, Section 6)",
      lambda r: r["extra"]["state"] == "held" and r["extra"]["first_not_run_step"] == "2"
      and r["extra"]["steps"]["2"]["items"][0]["cited_record"]["state"] == "refused")
def n14(p):
    p["executed_amount"] = 15000
    p["extra"] = ("reassess", 1)


@case("N15-a-verdict-citing-a-verdict-beyond-the-citation-depth",
      "the same reassessment over the released verdict of part A, the checker's policy following citations to depth 0: step 2 NOT RUN",
      lambda r: r["extra"]["state"] == "held" and "beyond the citation depth" in r["extra"]["steps"]["2"]["items"][0]["format_rules"]
      and v(r, "A_version_1")["state"] == "released")
def n15(p):
    p["extra"] = ("reassess", 0)


def run(p):
    extra = p.pop("extra", None)
    art = B.assemble(p)
    r = B.verify(art)
    if extra:
        _, depth = extra
        cited = art["A"]["verdict_bytes"]
        raw = reassessment(cited)
        cont = B.container(raw)
        items = B.items_of(art)
        items[B.sha256(raw)] = (raw, cont)
        intake = dict(art["intake"], **{B.sha256(raw): "2026-11-06T12:05:00.000000Z"})
        policy = dict(art["policy"], citation_depth=depth)
        checker = B.V.Checker(policy, B.anchors(intake), B.RULES, B.FORMATS)
        r["extra"] = checker.check(raw, items, cont)
        art["extra"] = {"verdict_bytes": raw, "container": cont, "policy": policy, "intake": intake}
    return art, r


def publish(d, art, what, entry, r):
    d.mkdir(parents=True, exist_ok=True)
    items = B.items_of(art)
    (d / "items").mkdir(exist_ok=True)
    for digest, (raw, cont) in items.items():
        (d / "items" / f"{digest}.bin").write_bytes(raw)
    for part, name in (("A", "A-verdict-record-v1"), ("A_mismatch", "A-mismatch-verdict-record-stated"), ("C", "C-verdict-record-v2"), ("extra", "reassessment-verdict-record")):
        if part in art:
            (d / f"{name}.json").write_bytes(art[part]["verdict_bytes"])
            (d / f"{name}.container.json").write_text(json.dumps(art[part]["container"], indent=1) + "\n")
    (d / "A-action-binding-attachment-A2.as-held.json").write_bytes(art["A"]["a2_held"])
    (d / "B-closing-action-binding-attachment.json").write_bytes(art["B"]["attachment_bytes"])
    (d / "checker-policy.json").write_bytes(B.V.canonical_bytes(art.get("extra", {}).get("policy") or art["policy"]))
    (d / "checker-trust-anchors.json").write_bytes(B.V.canonical_bytes(B.anchors(art.get("extra", {}).get("intake") or art["intake"])))
    (d / "what.txt").write_text(what + "\n")
    (d / "result.json").write_text(json.dumps(entry, ensure_ascii=False, indent=1) + "\n")
    (d / "summary.json").write_text(json.dumps(r, ensure_ascii=False, indent=1) + "\n")


def main():
    out = B.HERE / "out" / "negatives"
    out.mkdir(parents=True, exist_ok=True)
    summary, ok = {}, True
    for name, (what, fn, expect) in N.items():
        p = B.build()
        fn(p)
        art, r = run(p)
        as_expected = bool(expect(r))
        ok = ok and as_expected
        states = {k: x["state"] for k, x in r["verdict"].items()}
        if "extra" in r:
            states["reassessment"] = r["extra"]["state"]
        entry = {"what": what, "as_expected": as_expected, "states": states,
                 "dps_verified": {k: x["verified"] for k, x in r["dps"].items()},
                 "joins_false": [k[:4].rstrip(". ") for k, x in r["joins"].items() if x is not True]}
        summary[name] = entry
        publish(out / name, art, what, entry, r)
        print(("ok   " if as_expected else "FAIL ") + f"{name}: states {states}; dps not verified: "
              f"{[k for k, x in entry['dps_verified'].items() if not x]}; joins false: {entry['joins_false']}")
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n")
    print(f"{sum(e['as_expected'] for e in summary.values())} of {len(summary)} cases as expected")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
