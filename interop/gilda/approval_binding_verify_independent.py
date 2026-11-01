#!/usr/bin/env python3
"""Independent verifier for approval-binding/v1, written from the corpus's own contract text (the README of
vectors-approval-binding in agent-evidence-vectors: "The checks, in order", 1 to 11) and nothing else: it imports
nothing from the package and shares no code with its reference reader. A verifier names the first check that fails.

Contract, as read:
  1  the record carries contractId                                    contract_id_missing
  2  contractId is .../contract/approval-binding/v1                   contract_id_unknown
  3  no other presentedApprovals entry has the approval's approvalId
     with different content (the same approval twice is not ambiguous)  approval_id_ambiguous
  4  approvalId is not in consumedApprovalIds                          approval_replayed
  5  trustedKeys[approver] is the approval's keyId                     key_not_bound
  6  the use's principal is the approval's (a matching clientId does
     not stand in for the user)                                        principal_mismatch
  7  the use's event and phase are the approved ones                   event_phase_mismatch
  8  the used tool, target and payload bytes are the approved ones     payload_mismatch
  9  usedAt is at or after issuedAt and before expiresAt               approval_outside_validity
 10  policyRelease.lookup is ok                                        comparison_unavailable
 11  the release's firstServedAt is at or before decisionTime, and its
     lastServedAt plus graceSeconds is at or after it                  release_not_served_at_decision
A record that passes all eleven is allow, reason bound.

Readings the text leaves to the verifier, stated so they can be checked:
  - "the approval" is record.approval; the use's approvalId is compared to it under check 3 only through
    presentedApprovals, as the text says; a use naming another identifier than record.approval is not a check the
    text lists, so it is not refused here;
  - "different content" in check 3 compares every member of the two approval objects;
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


def verify(record, base_dir):
    """The eleven checks in order; returns {"decision", "reason"}."""
    if not isinstance(record, dict) or "contractId" not in record:
        return {"decision": "deny", "reason": "contract_id_missing"}
    if record["contractId"] != CONTRACT:
        return {"decision": "deny", "reason": "contract_id_unknown"}
    a = record.get("approval") if isinstance(record.get("approval"), dict) else {}
    use = record.get("use") if isinstance(record.get("use"), dict) else {}
    aid = a.get("approvalId")
    for other in record.get("presentedApprovals", []) if isinstance(record.get("presentedApprovals"), list) else []:
        if isinstance(other, dict) and other.get("approvalId") == aid and other != a:
            return {"decision": "deny", "reason": "approval_id_ambiguous"}
    if aid in (record.get("consumedApprovalIds") or []):
        return {"decision": "deny", "reason": "approval_replayed"}
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
                   "cases": n, "agree": agree, "rows": rows}, open(report_path, "w"), indent=1)
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
