#!/usr/bin/env python3
"""Independent verifier for approval-binding/v1, written from the corpus's own contract text (the README of
vectors-approval-binding in agent-evidence-vectors: "The checks, in order", 1 to 16, and "Renewal by replacement",
as the text stands at release 0.35.0 and in PR #472's wording of check 4) and nothing else: it imports nothing from
the package and shares no code with its reference reader (approvalbinding.py, check_vectors.py, gen_vectors.py and
the tests were not read). A verifier names the first check that fails.

First written on 1 November 2026 from the eleven checks of release 0.31.0 (23 cases); extended on 7 November 2026
to the sixteen checks of 0.35.0 (36 cases) and PR #472 (37). The five checks added by the text are 3, 6, 7, 8 and 14.

Contract, as read:
  1  the record carries contractId                                    contract_id_missing
  2  contractId is .../contract/approval-binding/v1                   contract_id_unknown
  3  the use's approvalId is the approval's approvalId (a use naming
     another approval, or none, is not judged against this one)       approval_not_cited
  4  no other presentedApprovals entry has the approval's approvalId
     and differs from it in any member, compared as parsed JSON
     values over the whole object, unread members included (the same
     approval twice, with equal values, is not ambiguous)             approval_id_ambiguous
  5  approvalId is not in consumedApprovalIds                          approval_replayed
  6  no replacement accepted at or before usedAt has taken the
     approval's place                                                  approval_superseded
  7  a use claiming authorityForm renewed has a transition accepted
     at or before usedAt whose successor is the approval (one
     accepted after the use does not establish the renewal)           renewal_transition_missing
  8  that transition binds the successor to its predecessor; the
     presented records under the predecessor's identifier agree       renewal_binding_invalid
  9  trustedKeys[approver] is the approval's keyId                     key_not_bound
 10  the use's principal is the approval's (a matching clientId does
     not stand in for the user)                                        principal_mismatch
 11  the use's event and phase are the approved ones                   event_phase_mismatch
 12  the used tool, target and payload bytes are the approved ones     payload_mismatch
 13  usedAt is at or after issuedAt and before expiresAt               approval_outside_validity
 14  the effect the use's effectKey names is not CONSUMED or
     UNCERTAIN_CLOSE in effectRegistry                                 effect_already_closed
 15  policyRelease.lookup is ok                                        comparison_unavailable
 16  the release's firstServedAt is at or before decisionTime, and its
     lastServedAt plus graceSeconds is at or after it                  release_not_served_at_decision
A record that passes all sixteen is allow, reason bound.

Readings the text leaves to the verifier, stated so they can be checked:
  - "the approval" is record.approval; a use with no approvalId member, or one that is not a string equal to the
    approval's, fails check 3 (the text: "names another approval, or none");
  - checks 4 and 8 compare presented records as parsed JSON values over the whole object, as PR #472's check 4
    says; under check 8 the text says only that the records "must agree", and the same comparison is taken;
  - a replacement (checks 6 and 7) is an entry of record.transitions whose status is the string "accepted" and
    whose acceptedAt is a readable time at or before usedAt; the text says a transition "counts from acceptedAt
    on", so an entry with another status, no acceptedAt, or an unreadable one counts never, and an unreadable
    usedAt places no transition at or before the use (check 6 then passes, check 7 fails, check 13 fails later
    on the same member); mode is read as this suite's only policy (exclusive-replacement) and is not tested,
    the text offering no other value to test against;
  - check 6 looks at transitions whose predecessorApprovalId is the approval's approvalId; check 7 at those whose
    successorApprovalId is it; check 7 applies only when use.authorityForm is exactly the string "renewed";
  - check 8, from "Renewal by replacement": every accepted transition that establishes the approval under check 7
    must bind, and binding means (a) at least one presented record carries the predecessor's identifier and all
    that do are equal, (b) the transition's predecessorDecisionId is that record's decisionId and its
    successorDecisionId is the approval's, (c) the two decisionIds are present and distinct (equal bounds, the same
    decision and the same effect are "three different identities"), (d) the predecessor and the approval agree on
    event, payloadSha256, phase, principal, target and tool; the validity window is the successor's own and is not
    compared;
  - check 14 passes when the use names no effectKey or the registry has no entry for it: the text forbids
    reopening a closed effect, and names nothing about a missing one;
  - the payload bytes are the file use.payloadFile names, read beside the record, hashed with SHA-256 and compared
    to the approval's payloadSha256 (lowercase hex);
  - times are RFC 3339 and compared as instants; a malformed time fails the check that reads it.

Usage: approval_binding_verify_independent.py record.json --json        (exit 0 allow, 1 deny)
       approval_binding_verify_independent.py --corpus DIR [--report out.json]
"""
import argparse
import datetime
import hashlib
import json
import os
import sys

CONTRACT = "https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v1"


def t(s):
    if not isinstance(s, str):
        raise ValueError("not a time")
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


BOUNDS = ("event", "payloadSha256", "phase", "principal", "target", "tool")   # "Renewal by replacement"


def accepted_at_or_before(tr, used):
    """A transition counts from acceptedAt on: status accepted and a readable acceptedAt at or before the use."""
    if not isinstance(tr, dict) or tr.get("status") != "accepted" or used is None:
        return False
    try:
        return t(tr.get("acceptedAt")) <= used
    except Exception:
        return False


def renewal_binds(tr, a, presented):
    """Check 8: the accepted transition binds the successor (the approval) to its predecessor."""
    pred_id = tr.get("predecessorApprovalId")
    preds = [p for p in presented if isinstance(p, dict) and p.get("approvalId") == pred_id]
    if not preds or any(p != preds[0] for p in preds[1:]):
        return False
    pred = preds[0]
    if pred.get("decisionId") is None or a.get("decisionId") is None or pred.get("decisionId") == a.get("decisionId"):
        return False
    if tr.get("predecessorDecisionId") != pred.get("decisionId") or tr.get("successorDecisionId") != a.get("decisionId"):
        return False
    return all(pred.get(k) == a.get(k) for k in BOUNDS)


def verify(record, base_dir):
    """The sixteen checks in order; returns {"decision", "reason"}."""
    if not isinstance(record, dict) or "contractId" not in record:
        return {"decision": "deny", "reason": "contract_id_missing"}
    if record["contractId"] != CONTRACT:
        return {"decision": "deny", "reason": "contract_id_unknown"}
    a = record.get("approval") if isinstance(record.get("approval"), dict) else {}
    use = record.get("use") if isinstance(record.get("use"), dict) else {}
    aid = a.get("approvalId")
    if not isinstance(use.get("approvalId"), str) or use.get("approvalId") != aid:
        return {"decision": "deny", "reason": "approval_not_cited"}
    presented = record.get("presentedApprovals") if isinstance(record.get("presentedApprovals"), list) else []
    for other in presented:
        if isinstance(other, dict) and other.get("approvalId") == aid and other != a:
            return {"decision": "deny", "reason": "approval_id_ambiguous"}
    if aid in (record.get("consumedApprovalIds") or []):
        return {"decision": "deny", "reason": "approval_replayed"}
    try:
        used = t(use.get("usedAt"))
    except Exception:
        used = None
    transitions = [x for x in (record.get("transitions") or []) if isinstance(x, dict)] if isinstance(record.get("transitions"), list) else []
    if any(tr.get("predecessorApprovalId") == aid and accepted_at_or_before(tr, used) for tr in transitions):
        return {"decision": "deny", "reason": "approval_superseded"}
    if use.get("authorityForm") == "renewed":
        establishing = [tr for tr in transitions if tr.get("successorApprovalId") == aid and accepted_at_or_before(tr, used)]
        if not establishing:
            return {"decision": "deny", "reason": "renewal_transition_missing"}
        if not all(renewal_binds(tr, a, presented) for tr in establishing):
            return {"decision": "deny", "reason": "renewal_binding_invalid"}
    keys = record.get("trustedKeys") if isinstance(record.get("trustedKeys"), dict) else {}
    if a.get("keyId") is None or keys.get(a.get("approver")) != a.get("keyId"):
        return {"decision": "deny", "reason": "key_not_bound"}
    if use.get("principal") is None or use.get("principal") != a.get("principal"):
        return {"decision": "deny", "reason": "principal_mismatch"}
    if use.get("event") != a.get("event") or use.get("phase") != a.get("phase"):
        return {"decision": "deny", "reason": "event_phase_mismatch"}
    try:
        with open(os.path.join(base_dir, use["payloadFile"]), "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
    except Exception:
        digest = None
    if use.get("tool") != a.get("tool") or use.get("target") != a.get("target") or digest is None or digest != a.get("payloadSha256"):
        return {"decision": "deny", "reason": "payload_mismatch"}
    try:
        used, issued, expires = t(use.get("usedAt")), t(a.get("issuedAt")), t(a.get("expiresAt"))
    except Exception:
        return {"decision": "deny", "reason": "approval_outside_validity"}
    if not (issued <= used < expires):
        return {"decision": "deny", "reason": "approval_outside_validity"}
    registry = record.get("effectRegistry") if isinstance(record.get("effectRegistry"), dict) else {}
    if isinstance(use.get("effectKey"), str) and registry.get(use["effectKey"]) in ("CONSUMED", "UNCERTAIN_CLOSE"):
        return {"decision": "deny", "reason": "effect_already_closed"}
    rel = record.get("policyRelease") if isinstance(record.get("policyRelease"), dict) else {}
    if rel.get("lookup") != "ok":
        return {"decision": "deny", "reason": "comparison_unavailable"}
    try:
        decision_time = t(record.get("decisionTime"))
        first, last = t(rel.get("firstServedAt")), t(rel.get("lastServedAt"))
        grace = rel.get("graceSeconds")
        if not isinstance(grace, (int, float)) or isinstance(grace, bool):
            raise ValueError
    except Exception:
        return {"decision": "deny", "reason": "release_not_served_at_decision"}
    if not (first <= decision_time and last + datetime.timedelta(seconds=grace) >= decision_time):
        return {"decision": "deny", "reason": "release_not_served_at_decision"}
    return {"decision": "allow", "reason": "bound"}


def judge(corpus, report_path=None):
    m = json.load(open(os.path.join(corpus, "MANIFEST.json")))
    rows, agree = [], 0
    for v in m["vectors"]:
        d = os.path.join(corpus, v["path"])
        record = json.load(open(os.path.join(d, "record.json")))
        got = verify(record, d)
        ok = got == v["expected"]
        agree += ok
        rows.append({"id": v["id"], "expected": v["expected"], "got": got, "agree": ok, "edit": v.get("edit", "")})
        if not ok:
            print(f"DISAGREE {v['id']}: expected {v['expected']} got {got}")
    n = len(rows)
    print(f"# {m['suite']}: {agree}/{n} cases agree with MANIFEST on decision and reason")
    if report_path:
        json.dump({"corpus": m["suite"], "contractId": m.get("contractId"), "corpusDigest": m.get("corpusDigest"),
                   "counts": m.get("counts"), "checks": 16, "cases": n, "agree": agree, "rows": rows},
                  open(report_path, "w"), indent=1)
    return 0 if agree == n else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("record", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--corpus")
    ap.add_argument("--report")
    a = ap.parse_args()
    if a.corpus:
        sys.exit(judge(a.corpus, a.report))
    if not a.record:
        ap.error("record.json or --corpus")
    out = verify(json.load(open(a.record)), os.path.dirname(os.path.abspath(a.record)))
    print(json.dumps(out))
    sys.exit(0 if out["decision"] == "allow" else 1)
