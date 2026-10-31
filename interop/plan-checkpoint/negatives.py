#!/usr/bin/env python3
"""The failing cases of the checkpoint: each is the valid run changed in one place, run through the same checks
(build.verify). The plan case's own failing cases (../plan-run/negatives.py) are not repeated here. Exit 0 when every
case is as expected."""
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


def capsule(art, i):
    return next(c for c in art["capsules"] if c["action_id"].endswith(f":step:{i}"))


@case("N15-resumed-without-the-decision", "joins", "the steps after the checkpoint cite the plan's approval only: nothing says who decided to resume")
def n15(parts):
    parts["checkpoint_cites"] = False


@case("N16-decided-on-another-state", "joins", "the checkpoint decision names the context state before step 0, not the state after it")
def n16(parts):
    parts["checkpoint_context_override"] = B.PR.context_chain(B.PR.INITIAL_CONTEXT, [])[0]


@case("N17-adjudication-of-another-claim", "joins", "the specification names another claim than the one the adjudication held is about")
def n17(parts):
    parts["checkpoint_claim_override"] = B.sha256(B.jcs({"claim": "the client's address is current", "client_ref": B.CLIENT}))


@case("N18-decided-after-the-step-ran", "joins", "the checkpoint decision is approved after the CRM record was created")
def n18(parts):
    T = parts["checkpoint_at"]
    for k, v in (("shown", B.at(37, 30)), ("approved", B.at(38)), ("requested", B.at(38, 5)), ("rechecked", B.at(38, 10)),
                 ("attempted", B.at(38, 15)), ("resumed", B.at(38, 20))):
        T[k] = v


@case("N19-witnesses-agree", "joins", "the two witness worlds give the claim the same value: a determined claim presented as undetermined")
def n19(parts):
    parts["witnesses"][1]["restricted_match"] = True
    parts["witnesses"][1]["provider_a_reads"] = "true positive, second reading"


@case("N20-adjudication-digests-do-not-recompute", "joins", "the adjudication's evidence digest is not that of the evidence beside it")
def n20(art, parts):
    art["fixture"]["evidence"][0]["result"] = "no match"
    B.reserialize(art)


@case("N21-approval-over-another-resumption", "checkpoint_signatures", "the manager's signature names another specification than the one the stage approved")
def n21(art, parts):
    ck = art["checkpoint"]
    ck["sig_attachment"]["person_signatures"][0]["approved_spec_digest"] = "4" * 64
    B.reserialize(art)


@case("N22-step-before-the-checkpoint-cites-it", "joins", "step 0's capsule cites the checkpoint decision, which did not exist when it ran")
def n22(art, parts):
    ck = art["checkpoint"]
    capsule(art, 0)["references"].append({"type": f"{B.NS}.decision_record", "digest_alg": "SHA-256", "digest": ck["record"]["seal_hash"],
                                          "citation_purpose": "ran_under"})
    B.rechain(art["capsules"], art["manifest"])
    B.reserialize(art)


def failures(r):
    f = {}
    if any(r["schema_errors"].values()):
        f["schema"] = {k: v[:2] for k, v in r["schema_errors"].items() if v}
    bad = {d: s for d, s in r["dps_action_binding"].items() if s != "verified"}
    if bad or r["dps_per_spec"] != "verified":
        f["dps_action_binding"] = {d: [s, r["dps_action_binding_findings"].get(d, [])[:2]] for d, s in bad.items()}
    if r["dps_person_signatures"]["failed"]:
        f["dps_person_signatures"] = r["dps_person_signatures"]["failed"][:2]
    if r.get("dps_issuer_seal", {}).get("status") != "verified":
        f["dps_issuer_seal"] = r.get("dps_issuer_seal")
    if r["capsules"]["problems"] or (B.PR.CAP_PARSE and r["capsules"]["verified"] != r["capsules"]["of"]):
        f["capsules"] = r["capsules"]["problems"][:2] or [f"verified {r['capsules']['verified']} of {r['capsules']['of']}"]
    c = r["checkpoint"]
    if any(c["schema_errors"].values()):
        f["checkpoint_schema"] = {k: v[:2] for k, v in c["schema_errors"].items() if v}
    cbad = {d: s for d, s in c["dps_action_binding"].items() if s != "verified"}
    if cbad:
        f["checkpoint_action_binding"] = {d: [s, c["dps_action_binding_findings"].get(d, [])[:2]] for d, s in cbad.items()}
    if c["dps_issuer_seal"]["status"] != "verified":
        f["checkpoint_seal"] = c["dps_issuer_seal"]
    if c["dps_person_signatures"]["failed"]:
        f["checkpoint_signatures"] = c["dps_person_signatures"]["failed"][:2]
    j = [k for k, v in r["joins"].items() if v is not True]
    if j:
        f["joins"] = j
    return f


def main():
    out = B.HERE / "out" / "negatives"
    out.mkdir(parents=True, exist_ok=True)
    summary, ok = {}, True
    for name, (where, what, fn) in N.items():
        parts = B.build()
        art_level = fn.__code__.co_argcount == 2
        if not art_level:
            fn(parts)
        art = B.assemble(parts)
        if art_level:
            fn(art, parts)
        r = B.verify(art, parts)
        f = failures(r)
        expected = where in f
        ok = ok and expected
        summary[name] = {"what": what, "caught_by": sorted(f), "expected_place": where, "as_expected": expected, "detail": f}
        (out / f"{name}.json").write_text(json.dumps(summary[name], ensure_ascii=False, indent=1) + "\n")
        print(("ok   " if expected else "FAIL ") + f"{name}: caught by {', '.join(sorted(f)) or 'nothing'}")
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
