#!/usr/bin/env python3
"""The failing cases of the composed case (build.py): the four agreed with the author of the Operating Model
Protocol on 2 November 2026 (a revoked instrument, an instrument outside its mandate_scope, a mismatched hash,
post_hoc_attached), the ones this composition adds (the approver is not the officer the instrument names, no
registry state, a sealed AUTHORITY_UNBOUND relabelled), and the joins broken one at a time.

Each case states where it is expected to fail, as the exact set of checks that do not pass (build.verify's flat
view: `omp.*` from the reader written from the text, `dps.*` from the Standard's reference checks, `J1` to `J7` the
joins). A case is as expected only when the set found is that set: one check more or one less is a failure of this
script. Where an emitter lies, the record is made again with valid seals, tokens and signatures, so that what
fails is what the record says, never a broken hash, unless the case is about the hash.

P1 is not a failing case: it is what an emitter that follows the text writes for a post-hoc attachment.

Layout: out/negatives/<case>/ holds the documents the checks ran on, what.txt and result.json.
Exit code 0 when every case is as expected. Run after build.py.
"""
import copy
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build as B   # noqa: E402

OMP = B.OMP
OUT = HERE / "out" / "negatives"
CASES = []


def case(name, what, expected, documented=False):
    def deco(fn):
        CASES.append((name, what, set(expected), documented, fn))
        return fn
    return deco


def forge_bound(art, instrument):
    """The emitter writes BOUND over this instrument, whatever the evaluation says."""
    S = art["S"]
    ab = {"authority_binding_result": "BOUND", "execution_permission": "ALLOWED",
          "delegation_instrument": dict(instrument)}

    def mutate(trace):
        trace["authority_binding"] = ab
        trace["named_accountable_officer"] = {"officer_id": S["officer"], "role": B.PEOPLE[S["officer"]]["role"]}
    return mutate


def recite(art):
    """The DPS attachment is written again to cite the trace as it now is (the firm's seal and the person's
    signature made again)."""
    def stages(st):
        st["o1"]["authority"]["authority_ref"] = B.binding_ref(art["trace"]["authority_binding"])
        st["c1"]["authority_source_ref"] = B.trace_ref(art["trace"])
    return B.reissue_dps(art, stages)


# ---------------------------------------------------------------- post_hoc_attached

@case("N1-post-hoc-attached-stated-bound",
      "The record states instrument_selection_mode post_hoc_attached and BOUND, ALLOWED. core-00 4.4.1: the value "
      "MUST trigger a review flag and SHOULD NOT be treated as fully BOUND; 8.3: it cannot receive BOUND status.",
      {"omp.invariant3", "J7"})
def n1():
    return B.build(B.scenario("bound", selection_mode="post_hoc_attached"), forced="BOUND"), None


@case("P1-post-hoc-attached-as-the-text-has-it",
      "Not a failure: the same attachment, written by an emitter that follows the text under this folder's stand-in "
      "profile. AUTHORITY_UNBOUND, POST_HOC_ATTACHMENT_DETECTED, BLOCKED, review flag; the adviser approved, the "
      "recheck refused, nothing was issued.",
      {"J7"}, documented=True)
def p1():
    return B.build(B.scenario("bound", selection_mode="post_hoc_attached", decision_id="DR-2026-110903")), None


@case("N2-post-hoc-relabelled-pre-registered",
      "After the decision, on 20 November, the firm writes a wider mandate, enters it in its registry with a "
      "registration date in March, and issues the trace again as BOUND, pre_registered, instrument_selected_at and "
      "sealed_at written as on 9 November. The time-stamping authority does not backdate: the binding token and the "
      "trace token are of 20 November. The decision record, sealed on 9 November, still names the first mandate, the "
      "first binding and the first trace.",
      {"omp.invariant3", "J3", "J4", "J6"})
def n2():
    art = B.build(B.scenario("bound"))
    S2 = B.scenario("bound", mandate={"product_scope": ["non-life.professional-multi-risk", "non-life.liability",
                                                        "life.insurance-based-investment"]})
    mandate2 = B.make_mandate(S2)
    mandate2["issued_by"]["issued_on"] = "2026-02-27"            # written on 20 November, dated as the first one
    snapshot2 = B.registry_state(S2, mandate2)                   # the firm's own registry, rewritten
    instrument2 = B.candidate_instrument(S2, mandate2, snapshot2)
    art.update(mandate=mandate2, registry_snapshot=snapshot2, instrument=instrument2,
               registration_token=B.token(OMP.jcs(mandate2), "2026-11-20T09:00:00Z", B.SERIALS["registration"]))
    B.reissue_omp(art, forge_bound(art, instrument2), binding_at="2026-11-20T09:05:00Z",
                  token_at="2026-11-20T09:05:10Z")
    return art, None


@case("N2b-post-hoc-relabelled-everything-reissued",
      "As N2, and the firm issues the decision record again as well: the specification names the wider mandate, the "
      "adviser signs again, the attachment is sealed again, every time written as on 9 November. The two records now "
      "agree with each other (J3 and J4 hold). What is left is what the firm does not control: the tokens.",
      {"omp.invariant3", "J6"})
def n2b():
    S = B.scenario("bound", decision_id="DR-2026-110908",
                   mandate={"product_scope": ["non-life.professional-multi-risk", "non-life.liability",
                                              "life.insurance-based-investment"]},
                   T={"registration_token": "2026-11-20T09:00:00Z", "binding_token": "2026-11-20T09:05:00Z",
                      "omp_token": "2026-11-20T09:05:10Z"})
    return B.build(S, forced="BOUND"), None


# ---------------------------------------------------------------- the instrument

@case("N3-instrument-altered-after-hashing",
      "The mandate held today is not the one that was hashed: its product scope was widened afterwards. The record "
      "and the decision record carry the first hash.",
      {"omp.instrument_hash", "omp.invariant3", "J3", "J7"})
def n3():
    art = B.build(B.scenario("bound"))
    art["mandate"] = copy.deepcopy(art["mandate"])
    art["mandate"]["mandate"]["product_scope"].append("life.insurance-based-investment")
    return art, None


@case("N4-no-registry-state-bound-stated",
      "The firm keeps no authority registry, so no registry state exists at decision time, and the record states "
      "BOUND all the same, without authority_registry_snapshot_hash. (What an emitter that follows the text writes "
      "is the unbound-sealed variant of build.py.)",
      {"omp.schema", "omp.registry_snapshot", "omp.invariant3", "J7"})
def n4():
    return B.build(B.scenario("unbound-sealed", decision_id="DR-2026-110904"), forced="BOUND"), None


@case("N6-instrument-revoked",
      "The registry state at decision time says the mandate is REVOKED; the record states ACTIVE and BOUND.",
      {"omp.invariant3", "J7"})
def n6():
    return B.build(B.scenario("bound", registry_status="REVOKED", stated_status="ACTIVE"), forced="BOUND"), None


@case("N7-outside-mandate-scope",
      "The adviser, whose mandate covers non-life contracts, approves the recommendation of an insurance-based "
      "investment product; the record states BOUND. Every DPS check verifies: she approved exactly what was issued.",
      {"omp.invariant3", "J7"})
def n7():
    return B.build(B.scenario("bound", recommended="L", decision_id="DR-2026-110907"), forced="BOUND"), None


# ---------------------------------------------------------------- the person

@case("N5a-approver-is-not-the-officer-named",
      "adviser-2 reviews, approves and signs, with her own key, which the verifier's trust policy lists. The OMP "
      "trace names adviser-1, whose mandate it binds, as the officer and as the one who resolved. Each record "
      "verifies alone.",
      {"J1", "J7"})
def n5a():
    return B.build(B.scenario("bound", approver="adviser-2", resolution_officer="adviser-1",
                              decision_id="DR-2026-110905")), None


@case("N5b-officer-named-is-not-the-instruments",
      "The trace names adviser-2, who approved, as the Named Accountable Officer, bound to adviser-1's mandate, and "
      "states BOUND.",
      {"omp.invariant3", "J1", "J7"})
def n5b():
    return B.build(B.scenario("bound", approver="adviser-2", officer="adviser-2", decision_id="DR-2026-110906"),
                   forced="BOUND"), None


# ---------------------------------------------------------------- the seal and the joins

@case("N8-sealed-unbound-relabelled",
      "The sealed AUTHORITY_UNBOUND trace of the unbound-sealed variant, with execution_permission changed to "
      "ALLOWED afterwards and nothing recomputed.",
      {"omp.seal.content_hash", "omp.axes", "omp.binding_timestamp", "omp.invariant3", "J4", "J5", "J7"})
def n8():
    art = B.build(B.scenario("unbound-sealed"))
    art["trace"]["authority_binding"]["execution_permission"] = "ALLOWED"
    return art, None


@case("N9-another-decision",
      "The OMP trace carries the digest of another recommendation (option C) and evaluated the scope on its "
      "premium; the adviser approved option B. Both records are otherwise as issued, the decision record citing "
      "this trace.",
      {"J2"})
def n9():
    art = B.build(B.scenario("bound"))
    other = B.scenario("bound", recommended="C")
    other_spec = B.compact(B.make_spec(other, art["mandate"], B.sha256(B.DEMANDS_AND_NEEDS)))

    def mutate(trace):
        trace["assisted_resolution"]["proposed_response_hash"] = "sha256:" + B.sha256(other_spec)
        trace["decision_context"] = B.decision_context(other)
    B.reissue_omp(art, mutate)
    return recite(art), None


@case("N10-authority-result-sealed-after-the-issue",
      "The trace is sealed at 10:15, after the recommendation was issued at 10:12:45; the recheck of 10:12:40 "
      "cites it.",
      {"J6"})
def n10():
    art = B.build(B.scenario("bound"))
    B.reissue_omp(art, sealed_at="2026-11-09T10:14:59.000Z", token_at="2026-11-09T10:15:00Z")
    return recite(art), None


@case("N11-decision-record-cites-another-binding",
      "The decision record's authority reference names another authority_binding object (the one of the "
      "unbound-sealed variant).",
      {"J4"})
def n11():
    art = B.build(B.scenario("bound"))
    other = B.build(B.scenario("unbound-sealed"))["trace"]["authority_binding"]

    def stages(st):
        st["o1"]["authority"]["authority_ref"] = B.binding_ref(other)
    return B.reissue_dps(art, stages), None


# ---------------------------------------------------------------- run

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    summary, ok = {}, True
    for name, what, expected, documented, fn in CASES:
        art, held = fn()
        report = B.verify(art, held)
        flat = report["flat"]
        found = set(B.failing(flat))
        good = found == expected
        ok = ok and good
        ab = art["trace"]["authority_binding"]
        inv = report["omp"]["invariant3"]
        result = {
            "what": what, **({"documented_expected_result": True} if documented else {}),
            "expected_to_fail_at": sorted(expected), "failed_at": sorted(found), "as_expected": good,
            "omp_stated": [ab["authority_binding_result"], ab["execution_permission"]] + ab.get("failure_reasons", []),
            "omp_evaluated_again": ([inv["recomputed"]["authority_binding_result"], inv["recomputed"]["execution_permission"]]
                                    + inv["recomputed"]["failure_reasons"]) if inv.get("recomputed") else None,
            "review_flag": inv.get("review_flag"), "omp_verdict": report["omp"]["verdict"],
            "details": {**{k: report["omp"]["checks"][k[4:]]["detail"] for k in sorted(found) if k.startswith("omp.")},
                        **{k: next(v for j, v in report["joins"].items() if j.startswith(k + " ")).get(
                            "detail", next(v for j, v in report["joins"].items() if j.startswith(k + " ")).get("evaluated"))
                           for k in sorted(found) if k.startswith("J")},
                        **{k: report["dps"]["action_binding_findings"].get(k[4:]) for k in sorted(found) if k.startswith("dps.")}},
            "not_checked": sorted(k for k, v in flat.items() if v == "not_checked"),
        }
        d = OUT / name
        B.write(d, art, report)
        (d / "what.txt").write_text(what + "\n")
        (d / "result.json").write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n")
        summary[name] = {k: result[k] for k in ("expected_to_fail_at", "failed_at", "as_expected", "omp_stated",
                                                "omp_evaluated_again", "review_flag")}
        if documented:
            summary[name]["documented_expected_result"] = True
    for old in OUT.iterdir():
        if old.is_dir() and old.name not in summary:
            for f in old.iterdir():
                f.unlink()
            old.rmdir()
    (OUT / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n")
    print(json.dumps(summary, indent=1, ensure_ascii=False))
    n = sum(1 for v in summary.values() if v["as_expected"])
    print(f"# {n}/{len(summary)} cases as expected")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
