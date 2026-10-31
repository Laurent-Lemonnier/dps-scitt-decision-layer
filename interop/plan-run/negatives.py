#!/usr/bin/env python3
"""The failing cases of the plan run: each is the valid run changed in one place, run through the same checks
(build.verify). out/negatives/summary.json records, for each, every place that fails; the case is as expected when
the place it names is among them. Exit 0 when every case is as expected."""
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


def rechain(art):
    """After a capsule changed or moved, the capsules that follow it name its new identifier; the manifest follows."""
    prev = None
    for c in art["capsules"]:
        if prev:
            c["chain"] = {"parent_capsule_id": prev, "relation": "follows"}
        else:
            c.pop("chain", None)
        B.recap(c)
        prev = c["capsule_id"]
    ids = {c["action_id"]: c["capsule_id"] for c in art["capsules"]}
    for m in art["manifest"]["steps"]:
        m["capsule_id"] = ids.get(f"{B.RUN_ID}:step:{m['index']}", m["capsule_id"])
    B.reserialize(art)


@case("N1-step-missing", "joins", "the CRM step (1) has no capsule: the manifest lists it, nothing executed it")
def n1(art, parts):
    art["capsules"].remove(capsule(art, 1))
    rechain(art)


@case("N2-steps-reordered", "joins", "the message (2) is sent before the CRM record (1) exists; the capsules and the manifest say so")
def n2(parts):
    parts["order"] = [0, 2, 1]


@case("N3-capsule-of-another-plan", "joins", "a capsule citing this decision executes a step of another client's plan")
def n3(art, parts):
    other = copy.deepcopy(capsule(art, 0))
    other["action_id"] = "urn:example:plan-run:2026-11-06-0472:step:0"
    other["effect"]["request_digest"] = B.sha256(B.jcs({"operation": "drive.document.create",
                                                          "target": "urn:example:drive:folder:clients/C-4472",
                                                          "parameters": {"template_ref": "urn:example:drive:template:onboarding-v7",
                                                                         "client_ref": "urn:example:client:C-4472", "title": "Onboarding C-4472"}}))
    other.pop("chain", None)
    art["capsules"].append(B.recap(other))
    B.reserialize(art)


@case("N4-step-arguments-changed", "joins", "the CRM record is created with another legal name than the plan approved")
def n4(parts):
    req = B.resolve(parts["spec"]["parameters"]["steps"][1], {0: parts["recorded_outputs"][0]})
    req["parameters"]["legal_name"] = "Example Client 4471 Holding SAS"
    parts["executed"][1] = req


@case("N5-plan-hash-not-of-the-steps", "joins", "the plan the person approved carries a plan_hash that is not the hash of its steps")
def n5(parts):
    parts["spec"]["parameters"]["plan_hash"] = "0" * 64


@case("N6-manifest-not-the-one-named", "joins", "the DPS result names another manifest than the one held")
def n6(art, parts):
    for s in art["attachment"]["stages"]:
        if s["kind"] == "result":
            s["evidence_ref"] = "urn:example:plan-run-manifest:sha256:" + "1" * 64
    B.reserialize(art)


@case("N7-recorded-output-substituted", "joins", "the manifest records another document than step 0's capsule committed to; "
                                                   "the CRM record and the message carry that other document")
def n7(parts):
    parts["recorded_outputs"][0] = {"document_ref": "urn:example:drive:document:D-99999"}


@case("N8-step-executed-twice", "joins", "the CRM step runs twice: two capsules, one plan step")
def n8(art, parts):
    again = copy.deepcopy(capsule(art, 1))
    again["action_id"] += ":again"
    again["timestamp"] = B.at(31, 30)
    art["capsules"].append(again)
    rechain(art)


@case("N9-person-disposed-of-a-resolved-step", "joins", "the message's capsule says a person disposed of it, though two of its arguments "
                                                        "were resolved at run time")
def n9(art, parts):
    capsule(art, 2)["disposition"]["human_disposed"] = True
    rechain(art)


@case("N10-plan-run-twice", "dps_action_binding", "a second request of the plan under the same approval, which allows one")
def n10(parts):
    parts["extra_requests"] = 1


@case("N11-fourth-step", "joins", "a fourth step, not in the plan, runs after the third and cites the decision")
def n11(art, parts):
    extra = copy.deepcopy(capsule(art, 2))
    extra["action_id"] = f"{B.RUN_ID}:step:3"
    extra["timestamp"] = B.at(31, 40)
    extra["effect"].update(type="org.example.mail_message_send",
                           request_digest=B.sha256(B.jcs({"operation": "mail.message.send", "target": "urn:example:mail:brokerage-1",
                                                           "parameters": {"to": "urn:example:client:C-4471", "text": "Welcome."}})))
    art["capsules"].append(extra)
    rechain(art)


@case("N12-capsule-cites-another-record", "capsules", "the CRM step's capsule cites a decision record that is not the one held")
def n12(art, parts):
    capsule(art, 1)["references"][0]["digest"] = "2" * 64
    rechain(art)


@case("N13-capsule-cites-a-stale-context", "joins", "the message's capsule cites the context before the CRM step, not the state after it")
def n13(art, parts):
    stale = next(m for m in art["manifest"]["steps"] if m["index"] == 1)["context_before"]
    next(r for r in capsule(art, 2)["references"] if r["type"] == B.CONTEXT_TYPE)["digest"] = stale
    rechain(art)


@case("N14-context-link-broken", "joins", "the manifest's context after the CRM step is not the state before it plus that step's outputs")
def n14(art, parts):
    next(m for m in art["manifest"]["steps"] if m["index"] == 1)["context_after"] = "3" * 64
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
    if r["capsules"]["problems"] or (B.CAP_PARSE and r["capsules"]["verified"] != r["capsules"]["of"]):
        f["capsules"] = r["capsules"]["problems"][:2] or [f"verified {r['capsules']['verified']} of {r['capsules']['of']}"]
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
        summary[name] = {"what": what, "caught_by": sorted(f), "expected_place": where, "as_expected": expected,
                         "detail": f}
        (out / f"{name}.json").write_text(json.dumps(summary[name], ensure_ascii=False, indent=1) + "\n")
        print(("ok   " if expected else "FAIL ") + f"{name}: caught by {', '.join(sorted(f)) or 'nothing'}")
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
