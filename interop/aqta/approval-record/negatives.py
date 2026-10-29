#!/usr/bin/env python3
"""The failing cases Anya Chueayen asked for on 2026-10-29, beside the worked example of build.py:
  N1  an altered value: the arguments the action record carries differ from the ones the person approved
      (args_hash changes; the approval's digest no longer matches the specification the record executes);
  N2  a reused single-use approval: a second request rests on the same approval, whose request_limit is 1;
  N3  an approver outside the trust policy: the outcome is signed by a key the verifier's policy does not list.
Each case is built from the valid example, changed in one place, written under out/negatives/<case>/, and run through
the same three verifications. The point is which check fails and what it says, so the report records that.
Run after build.py (it reads out/).
"""
import base64
import copy
import hashlib
import json
import os
import pathlib
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = pathlib.Path(__file__).resolve().parent
sys.argv = [sys.argv[0]]
# reuse build.py's loaders and keys by executing it as a module (it writes out/ again, identically)
ns = {"__name__": "build_module", "__file__": str(HERE / "build.py")}
src = (HERE / "build.py").read_text()
src = src.split("# ---- verification, both sides and across")[0]      # the construction only
exec(compile(src, str(HERE / "build.py"), "exec"), ns)
AB, SIG, AQ = ns["AB"], ns["SIG"], ns["AQ"]
sha256, compact, jcs, b64url, raw_public = ns["sha256"], ns["compact"], ns["jcs"], ns["b64url"], ns["raw_public"]
approver, issuer = ns["approver"], ns["issuer"]
record, attachment, policy, ps, action = ns["record"], ns["attachment"], ns["policy"], ns["ps"], ns["action"]
record_bytes, spec, spec_bytes = ns["record_bytes"], ns["spec"], ns["spec_bytes"]
issuer_policy, issuer_policy_bytes, policy_checks = ns["issuer_policy"], ns["issuer_policy_bytes"], ns["policy_checks"]
OUT = HERE / "out" / "negatives"


def run_all(att, sig_att, pol, act, pinned_key, policy_held=None, use_issuer_policy=True):
    res = _run_all(att, sig_att, pol, act, pinned_key)
    held = issuer_policy_bytes if (use_issuer_policy and policy_held is None) else policy_held
    spec_read = json.loads(base64.b64decode(att["action_specifications"][0]["content"]["bytes_b64"]))
    attempts = [s for s in att["stages"] if s["kind"] == "attempt"]
    outcome = next(s for s in att["stages"] if s["stage_id"] == "o1")
    res["policy_checks"] = policy_checks(spec_read, held, sig_att["person_signatures"][0]["signed_at"], attempts[-1]["at"],
                                         outcome["actor_ref"])
    return res


def _run_all(att, sig_att, pol, act, pinned_key):
    res = {}
    try:
        AQ.verify_action(json.loads(compact(act)), pinned_key)
        res["seal_action_record"] = "valid"
    except AQ.Invalid as e:
        res["seal_action_record"] = f"invalid: {e}"
    binding = AB.check_attachment(att, record_bytes)
    res["dps_action_binding"] = {k: list(v) for k, v in binding.items()
                                 if isinstance(v, (list, tuple)) and len(v) == 2 and isinstance(v[0], str) and v[0] in ("verified", "failed", "not_checked", "indeterminate")}
    res["dps_executed"] = [list(x) for x in binding.get("executed", [])]   # how each executed specification was reached
    res["dps_action_binding_failed"] = [k for k, v in res["dps_action_binding"].items() if v[0] != "verified"]
    res["dps_action_binding_findings"] = {k: v[1] for k, v in res["dps_action_binding"].items() if v[0] != "verified"}
    policy_result, persons, seals, ts = SIG.run_context({"attachment": sig_att, "export": None,
                                                         "action_binding": {record["decision_id"]: att}, "policy": pol})
    p0 = persons[0]
    res["dps_person_approval"] = {k: p0[k]["status"] if isinstance(p0[k], dict) and "status" in p0[k] else p0[k]
                                  for k in ("status", "signature", "subject", "key_state", "identity")}
    res["dps_person_approval_findings"] = {k: p0[k].get("findings") for k in ("signature", "subject", "key_state", "identity")
                                           if isinstance(p0[k], dict) and p0[k].get("findings")}
    # the cross-binding a verifier of the composition makes: the record's args_hash against the approved specification
    spec_read = json.loads(base64.b64decode(att["action_specifications"][0]["content"]["bytes_b64"]))
    res["composition_args_hash_bound"] = act["args_hash"] == spec_read["parameters"]["args_hash"]
    return res


def sign_action(act, key):
    a = dict(act)
    a.pop("signature", None)
    a["public_key"] = b64url(raw_public(key))
    a["signature"] = b64url(key.sign(AQ.canonical(a).encode("utf-8")))
    return a


sig_att = {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps], "organisation_seals": [], "timestamps": []}
cases = {}

# ---- N1: the executed arguments differ from the approved ones (pull_number 4521 -> 4522)
args2 = dict(ns["args"], pull_number="4522")
args2_hash = sha256(jcs(args2))
act1 = sign_action(dict(action, args_hash=args2_hash), issuer)
# the enforcement point records what it executed; the attachment's attempt stage names a specification of the executed call
spec2 = copy.deepcopy(spec); spec2["parameters"]["args_hash"] = args2_hash; spec2["parameters"]["args"] = args2
spec2_bytes = compact(spec2); spec2_digest = sha256(spec2_bytes)
att1 = copy.deepcopy(attachment)
att1["action_specifications"].append({"spec_digest": spec2_digest, "representation": {"kind": "original_bytes", "media_type": "application/json"},
                                      "content": {"availability": "available", "bytes_b64": base64.b64encode(spec2_bytes).decode("ascii")},
                                      "summary": {"operation": spec2["operation"], "target": spec2["target"], "policy_version": spec2["policy_version"],
                                                  "input_version_refs": spec2["input_version_refs"]}})
for s in att1["stages"]:
    if s["stage_id"] in ("q1", "x1"):
        s["spec_digest"] = spec2_digest          # requested and attempted: the changed call; approved: the original
cases["N1-altered-value"] = {"what": "the request and the attempt carry a specification (pull_number 4522) that differs from the one the person was shown and approved (4521); the action record's args_hash is the executed one",
                             "result": run_all(att1, sig_att, policy, act1, act1["public_key"])}

# ---- N2: a second request rests on the same single-use approval
att2 = copy.deepcopy(attachment)
stages = att2["stages"]
i = next(i for i, s in enumerate(stages) if s["stage_id"] == "r1")
q2 = {"stage_id": "q2", "kind": "request", "at": "2026-10-29T16:20:00Z", "request_id": "urn:aqta:action:6f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e60",
      "authorised_by": "o1", "spec_digest": spec["parameters"] and sha256(spec_bytes), "requested_by": "urn:isoluce:service:release-assistant"}
c2 = {"stage_id": "c2", "kind": "recheck", "at": "2026-10-29T16:20:05Z", "request_ref": "q2", "result": "authorised", "authority_source_ref": issuer_policy["policy_id"] + "#" + issuer_policy["version"]}
x2 = {"stage_id": "x2", "kind": "attempt", "at": "2026-10-29T16:20:10Z", "request_ref": "q2", "recheck_ref": "c2", "spec_digest": sha256(spec_bytes),
      "executor_ref": "urn:aqta:enforcement-point:seal", "trace_refs": ["urn:aqta:action:6f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e60"]}
r2 = {"stage_id": "r2", "kind": "result", "at": "2026-10-29T16:20:30Z", "attempt_ref": "x2", "observed": "succeeded", "basis": "target_response",
      "evidence_ref": "urn:github:isoluce/claims-intake:pull:4521:merged-again"}
stages[i + 1:i + 1] = [q2, c2, x2, r2]
cases["N2-reused-single-use-approval"] = {"what": "a second request (q2), recheck, attempt and result rest on approval o1, whose request_limit is 1",
                                          "result": run_all(att2, sig_att, policy, action, action["public_key"])}

# ---- N3: the outcome is signed by a key the trust policy does not list
stranger = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"dps-scitt-decision-layer interop example: a key the policy does not list (test only)").digest())
ps3 = copy.deepcopy(ps)
ps3["signature"]["key_ref"] = "someone-else-key-1"
ps3["signature"]["value_b64"] = base64.b64encode(stranger.sign(SIG.person_signed_bytes(ps3))).decode("ascii")
sig3 = dict(sig_att, person_signatures=[ps3])
cases["N3-approver-outside-trust-policy"] = {"what": "the approval is a valid Ed25519 signature by a key (someone-else-key-1) that the verifier's trust policy does not list",
                                             "result": run_all(attachment, sig3, policy, action, action["public_key"])}
# N3b: the same, with the key listed but in role organisation, not person
pol3 = copy.deepcopy(policy)
pol3["keys"].append({"key_ref": "someone-else-key-1", "holder": "Some issuer", "role": "organisation", "algorithm": "Ed25519",
                     "public_key_hex": raw_public(stranger).hex(), "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-08-31T23:59:59Z"})
cases["N3b-approver-key-in-wrong-role"] = {"what": "the same signature, the key listed in the policy but in role organisation: an organisation's key cannot approve as a person",
                                           "result": run_all(attachment, sig3, pol3, action, action["public_key"])}

# ---- the cases the Standard's Steward listed on issue 93 (29 October 2026)
# N4: the verifier holds a policy whose bytes are not the ones the specification names (edited after the approval)
edited = dict(issuer_policy, max_approval_age_seconds=86400)
cases["N4-policy-digest-mismatch"] = {"what": "the policy held allows a day where the signed one allowed 900 s: its digest is not the specification's policy_version",
                                      "result": run_all(attachment, sig_att, policy, action, action["public_key"], policy_held=compact(edited))}
# N5: the verifier does not hold the policy
cases["N5-policy-not-held"] = {"what": "the verifier holds no copy of the issuer's policy: what it alone can show is not checked, never verified",
                               "result": run_all(attachment, sig_att, policy, action, action["public_key"], use_issuer_policy=False)}
# N6: the attempt comes after the policy's age limit and after the specification's valid_until; the recheck still says authorised
att6 = copy.deepcopy(attachment)
late = {"q1": "2026-10-29T16:39:30Z", "c1": "2026-10-29T16:39:40Z", "x1": "2026-10-29T16:40:00Z", "r1": "2026-10-29T16:40:20Z"}
for s in att6["stages"]:
    if s["stage_id"] in late:
        s["at"] = late[s["stage_id"]]
act6 = sign_action(dict(action, timestamp="2026-10-29T16:40:00.000Z"), issuer)
cases["N6-attempt-after-policy-limit"] = {"what": "the attempt is 28 minutes after the approval: past the signed policy's 900 s and past valid_until; the executor's recheck recorded 'authorised' anyway",
                                          "result": run_all(att6, sig_att, policy, act6, act6["public_key"])}
# N7: relabelling the policy in the specification after the person signed
spec7 = copy.deepcopy(spec); spec7["policy_version"] = "sha256:" + sha256(compact(edited))
spec7_bytes = compact(spec7); spec7_digest = sha256(spec7_bytes)
att7 = copy.deepcopy(attachment)
old_digest = att7["action_specifications"][0]["spec_digest"]
att7["action_specifications"][0].update({"spec_digest": spec7_digest,
                                         "content": {"availability": "available", "bytes_b64": base64.b64encode(spec7_bytes).decode("ascii")},
                                         "summary": dict(att7["action_specifications"][0]["summary"], policy_version=spec7["policy_version"])})
for s in att7["stages"]:
    for k in ("spec_digest", "shown_spec_digest", "approved_spec_digest"):
        if s.get(k) == old_digest:
            s[k] = spec7_digest
cases["N7-policy-relabelled-in-specification"] = {"what": "the issuer rewrites the attachment so that the specification names another policy; the person's signature still covers the original digests",
                                                  "result": run_all(att7, sig_att, policy, action, action["public_key"], policy_held=compact(edited))}
# N7b (documented, not a failure): the outcome's authority_ref changed after signing. It is the issuer's statement,
# outside the person's signature, as the Steward checked on main; the policy the signature covers is the one above.
att7b = copy.deepcopy(attachment)
next(s for s in att7b["stages"] if s["stage_id"] == "o1")["authority"]["authority_ref"] = "urn:isoluce:policy:something-else#2026-10-29"
cases["N7b-authority-ref-relabelled"] = {"what": "authority_ref changed after signing: the person's signature stays verified, by design; authority_ref is the issuer's statement and only policy_version is under the signature",
                                         "documented_pass": True,
                                         "result": run_all(att7b, sig_att, policy, action, action["public_key"])}

OUT.mkdir(parents=True, exist_ok=True)
for name, c in cases.items():
    (OUT / f"{name}.json").write_text(json.dumps(c, indent=1, ensure_ascii=False))
summary = {name: {"what": c["what"], "seal_action_record": c["result"]["seal_action_record"],
                  "dps_action_binding_failed": c["result"]["dps_action_binding_failed"],
                  "dps_person_approval": c["result"]["dps_person_approval"],
                  "policy_checks": c["result"]["policy_checks"],
                  "composition_args_hash_bound": c["result"]["composition_args_hash_bound"],
                  **({"documented_pass": True} if c.get("documented_pass") else {})} for name, c in cases.items()}
(OUT / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False))
print(json.dumps(summary, indent=1, ensure_ascii=False))


def caught(r):
    """A negative is caught when a check fails, or when what it alone could show is reported not checked."""
    return bool(r["dps_action_binding_failed"] or r["dps_person_approval"]["status"] != "verified"
                or not r["composition_args_hash_bound"]
                or any(not v.startswith("verified") for v in r["policy_checks"].values()))


# every negative is caught, never in the Seal record itself; the documented case passes everything
ok = all(caught(c["result"]) for c in cases.values() if not c.get("documented_pass")) and \
    all(not caught(c["result"]) for c in cases.values() if c.get("documented_pass"))
sys.exit(0 if ok else 1)
