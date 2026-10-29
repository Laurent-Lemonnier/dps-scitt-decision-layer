#!/usr/bin/env python3
"""The failing cases of the agent pass: each is the valid pass changed in one place, run through the same checks
(build.verify). out/negatives/summary.json records, for each, every place that fails; the case is as expected when
the place it names is among them. Exit 0 when every case is as expected."""
import base64
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


def stage(parts, sid):
    return next(s for s in parts["stages"] if s["stage_id"] == sid)


def execution(parts, via_prefix, k=0):
    """The k-th action whose authority starts with via_prefix (sa L, sa I, or o for an exact approval)."""
    return [a for a in parts["actions"] if a["outcome"] == "ALLOWED" and a["via"].startswith(via_prefix)][k]


def respec(parts, action, change):
    """Make the request and the attempt of this action carry a changed specification; the Seal record follows it."""
    sp = copy.deepcopy(parts["specs"][action["spec"]][1])
    change(sp)
    raw = B.compact(sp)
    d = B.sha256(raw)
    parts["specs"][d] = (raw, sp)
    n = action["stage"][1:]
    stage(parts, f"q{n}")["spec_digest"] = stage(parts, f"x{n}")["spec_digest"] = d
    action.update(spec=d, args=sp["parameters"])


@case("N1-like-outside-bounds", "dps_action_binding", "a like on a post the standing approval does not list")
def n1(parts):
    respec(parts, execution(parts, "saL"), lambda sp: sp["parameters"].update(post_ref="urn:example:social:post:7999"))


@case("N2-twenty-first-like", "dps_action_binding", "a 21st like under bounds that allow 20 (the first post liked twice)")
def n2(parts):
    first = execution(parts, "saL")
    t = 90 * 60 + 40 * 60
    aid = B.uid("action", "extra")
    parts["stages"] += [
        {"stage_id": "q99", "kind": "request", "at": B.at(0, t), "request_id": f"urn:aqta:action:{aid}", "authorised_by": "saL",
         "spec_digest": first["spec"], "requested_by": "urn:example:service:engagement-routine"},
        {"stage_id": "c99", "kind": "recheck", "at": B.at(0, t + 5), "request_ref": "q99", "result": "authorised",
         "authority_source_ref": B.POLICY_REF},
        {"stage_id": "x99", "kind": "attempt", "at": B.at(0, t + 10), "request_ref": "q99", "recheck_ref": "c99",
         "spec_digest": first["spec"], "executor_ref": B.GATE, "trace_refs": [f"urn:aqta:action:{aid}"]},
        {"stage_id": "r99", "kind": "result", "at": B.at(0, t + 25), "attempt_ref": "x99", "observed": "succeeded",
         "basis": "executor_observation", "evidence_ref": first["evidence"]}]
    parts["actions"].append({**first, "action_id": aid, "timestamp": B.at(0, t + 10)[:-1] + ".000Z", "stage": "x99"})


@case("N3-like-after-the-period", "dps_action_binding", "a like requested and attempted at 12:40Z, after the bounds' valid_until (12:25Z)")
def n3(parts):
    a = execution(parts, "saL", 19)
    n = a["stage"][1:]
    for k, sid in enumerate(("q", "c", "x", "r")):
        stage(parts, f"{sid}{n}")["at"] = B.at(220, 5 * k)
    a["timestamp"] = B.at(220, 10)[:-1] + ".000Z"


@case("N4-comment-changed-after-approval", "dps_action_binding", "the comment published is not the text the holder approved")
def n4(parts):
    respec(parts, execution(parts, "o"), lambda sp: sp["parameters"].update(text=sp["parameters"]["text"] + " Let's talk soon!"))


@case("N5-likes-after-revocation", "dps_action_binding", "the holder withdraws the likes' standing approval at 10:36:30Z; the routine goes on liking")
def n5(parts):
    i = parts["stages"].index(stage(parts, "q10"))
    parts["stages"].insert(i, {"stage_id": "rvL", "kind": "standing_revocation", "at": B.at(96, 30), "revokes_ref": "saL",
                               "actor_ref": B.OWNER, "method": "withdrawn in the review console",
                               "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": B.at(96, 30),
                                             "text_ref": "urn:example:rationale:pass-a-revocation"}})


@case("N6-capsule-claims-a-person-disposed-of-a-like", "joins", "a like's capsule says human_disposed true, though only bounds were approved")
def n6(art, parts):
    like = execution(parts, "saL", 3)
    c = next(c for c in art["capsules"] if c["action_id"] == f"urn:aqta:action:{like['action_id']}")
    c["disposition"]["human_disposed"] = True
    c.pop("capsule_id")
    c["capsule_id"] = B.CAP_CANON.compute_capsule_id(c) if B.CAP_CANON else B.sha256(B.jcs(c))


@case("N7-blocked-member-invited-anyway", "dps_action_binding", "an invitation sent to the member the routine's rule R-DECLINED had blocked")
def n7(parts):
    respec(parts, execution(parts, "saI"), lambda sp: sp["parameters"].update(profile_ref="urn:example:social:member:5390"))


@case("N8-standing-signature-over-other-bounds", "dps_person_signatures", "the holder's signature names bounds of 30 likes, the stage carries 20")
def n8(parts):
    other = copy.deepcopy(parts["standing"]["L"]["bounds"])
    other["max_requests"] = 30
    next(s for s in parts["sigs"] if s["stage_id"] == "saL")["bounds_digest"] = B.sha256(B.compact(other))


@case("N9-rejected-comment-published", "dps_action_binding", "the comment the holder rejected is requested and published, citing the rejection")
def n9(parts):
    o = next(s for s in parts["stages"] if s.get("outcome") == "rejected")
    spec = next(s for s in parts["stages"] if s["stage_id"] == o["review_ref"])["shown_spec_digest"]
    a = execution(parts, "o", 2)
    n = a["stage"][1:]
    stage(parts, f"q{n}").update(authorised_by=o["stage_id"], spec_digest=spec)
    stage(parts, f"x{n}")["spec_digest"] = spec
    a.update(spec=spec, args=parts["specs"][spec][1]["parameters"], via=o["stage_id"])


@case("N10-comments-under-bounds", "joins", "two comments approved as bounds (two posts, two texts) and published with the texts swapped")
def n10(parts):
    posts, texts = B.COMMENT_POSTS[:2], B.COMMENT_TEXT[:2]
    bounds = B.bounds_of("social.comment.create", {"post_ref": {"one_of": posts}, "text": {"one_of": texts}}, 2)
    bb = B.compact(bounds)
    view = B.view_for_bounds("Comment on these 2 posts with these 2 texts", posts + texts, 2)
    i = parts["stages"].index(stage(parts, "p0"))
    parts["stages"][i:i] = [
        {"stage_id": "vC", "kind": "review", "at": B.at(80, 30), "reviewer_ref": B.OWNER, "shown_bounds_digest": B.sha256(bb),
         "shown_view_ref": "urn:example:review-console:bounds-C", "shown_view_digest": B.sha256(view)},
        {"stage_id": "saC", "kind": "standing_approval", "at": B.at(85, 30), "review_ref": "vC", "actor_ref": B.OWNER,
         "method": "Ed25519 signature over the DPS person_standing_approval assertion", "authority": {"authority_ref": B.POLICY_REF},
         "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": B.at(85, 30), "text_ref": "urn:example:rationale:pass-a-C"},
         "bounds_digest": B.sha256(bb), "bounds": {"availability": "available", "bytes_b64": base64.b64encode(bb).decode()}}]
    parts["sigs"].append({"assertion": "person_standing_approval", "decision_id": None, "stage_id": "saC",
                          "bounds_digest": B.sha256(bb), "shown_view_digest": B.sha256(view), "signed_at": B.at(85, 30)})
    targets = [execution(parts, "o", 0), execution(parts, "o", 1)]
    for a, (post, text) in zip(targets, ((posts[0], texts[1]), (posts[1], texts[0]))):
        sp = {"operation": "social.comment.create", "target": B.ACCOUNT, "parameters": {"post_ref": post, "text": text},
              "input_version_refs": [B.PASS_REF], "policy_version": B.POLICY_VERSION}
        raw = B.compact(sp)
        d = B.sha256(raw)
        parts["specs"][d] = (raw, sp)
        n = a["stage"][1:]
        stage(parts, f"q{n}").update(authorised_by="saC", spec_digest=d)
        stage(parts, f"x{n}")["spec_digest"] = d
        a.update(spec=d, args=sp["parameters"], via="saC")
    # the two exact approvals these comments had are no longer used; drop them so nothing else differs
    for k in (0, 1):
        for sid in (f"o{k}",):
            o = stage(parts, sid)
            parts["stages"].remove(o)
            parts["sigs"] = [s for s in parts["sigs"] if s["stage_id"] != sid]
            v = stage(parts, o["review_ref"])
            parts["stages"].remove(v)
            parts["stages"].remove(stage(parts, v["proposal_ref"]))


def failures(r):
    f = {}
    if any(r["schema_errors"].values()):
        f["schema"] = {k: v[:2] for k, v in r["schema_errors"].items() if v}
    if r["seal_action_records"]["invalid"]:
        f["seal_action_records"] = r["seal_action_records"]["invalid"][:2]
    bad = {d: s for d, s in r["dps_action_binding"].items() if s != "verified"}
    if bad or r["dps_per_spec"] != "verified":
        f["dps_action_binding"] = {d: [s, r["dps_action_binding_findings"].get(d, [])[:2]] for d, s in bad.items()}
    if r["dps_person_signatures"]["failed"]:
        f["dps_person_signatures"] = r["dps_person_signatures"]["failed"][:2]
    if r["capsules"]["problems"]:
        f["capsules"] = r["capsules"]["problems"][:2]
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
