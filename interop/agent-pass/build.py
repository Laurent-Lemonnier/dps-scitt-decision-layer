#!/usr/bin/env python3
"""One pass of an agent acting on a professional social network for one account holder, with every action carried
three ways, all from existing texts and checked by existing code, nothing changed in any of them:

  WHO  the Decision Provenance Standard, action binding 0.3.0 + signatures 0.2.0: the account holder approves the
       likes and the invitations once, as bounds (a standing approval: the exact posts and profiles, a count and a
       period), and each comment on its own (an exact approval of its text); one comment is edited before approval,
       one is rejected; each approval is signed;
  CAN  Seal ACTION-v1 (draft-chueayen-attestation-receipts-05): the enforcement point's ALLOWED record for each
       action it let through, and a BLOCKED record for each one the routine's own rules stopped;
  WHAT Agent Action Capsule format 4 (draft-mih-scitt-agent-action-capsule, library 0.12.0): one capsule per action,
       citing the decision record and the attachment by CPB typed digest references.

Synthetic data, modelled on the shape of a real pass (35 effects, 5 refusals, one approval of the batch), with no
real person, post or text in it. Two test keys; never use them for anything real.

Verifies: every Seal record under the ACTION-v1 verifier written from the text; the attachment under the DPS
action-binding reference check; the thirteen signatures under the DPS signatures reference check; each capsule under
the capsule library (parse, verify) and its references against the bytes held; then the joins across the three, which
no single one of them checks: each ALLOWED record has its attempt and its result, each BLOCKED one has no request, and
a capsule says a person disposed of an action only where an approval of that exact action exists.
"""
import base64
import copy
import hashlib
import importlib
import importlib.util
import json
import os
import pathlib
import sys
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = pathlib.Path(__file__).resolve().parent
REPO = pathlib.Path(os.environ.get("DPS_STANDARD") or (HERE / "dps-standard" if (HERE / "dps-standard").exists()
                                                       else "/root/claude-ops/dps/wt-007f8c9"))
AQTA = HERE.parent / "aqta" / "aqta_verify_independent.py"
_candidates = [HERE.parents[1] / "examples/release-decision/decision-record.json",
               HERE.parents[2] / "exemple-release/decision-record.json"]
TEMPLATE = pathlib.Path(os.environ.get("DPS_RECORD_TEMPLATE") or next(p for p in _candidates if p.exists()))
NS = "org.decisionprovenancestandard"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AB = load("ab", REPO / "extensions/action-binding/tests/run_checks.py")
SIG = load("sig", REPO / "extensions/signatures/tests/run_checks.py")
AQ = load("aq", AQTA)
try:  # the capsule library is optional: without it the capsule side is reported not checked, never verified
    CAP_PARSE = importlib.import_module("agent_action_capsule.parse")
    CAP_VERIFY = importlib.import_module("agent_action_capsule.verify")
    CAP_CANON = importlib.import_module("agent_action_capsule.canonical")
except ImportError:
    CAP_PARSE = CAP_VERIFY = CAP_CANON = None


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def jcs(doc):
    return AQ.canonical(doc).encode("utf-8")


def b64(b):
    return base64.b64encode(b).decode("ascii")


def b64url(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def key_from_seed(text):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(text.encode()).digest())


def raw_public(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def uid(*parts):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:example:agent-pass:" + ":".join(parts)))


def at(minute, second=0):
    """A time on the pass day, 5 November 2026, from 09:00Z."""
    total = minute * 60 + second
    return f"2026-11-05T{9 + total // 3600:02d}:{total // 60 % 60:02d}:{total % 60:02d}Z"


owner_key = key_from_seed("dps-scitt-decision-layer agent-pass: account holder key (test only)")
gate_key = key_from_seed("dps-scitt-decision-layer agent-pass: enforcement point key (test only)")
OWNER, OWNER_KEY_REF = "account-holder-1", "account-holder-1-key-1"
ACCOUNT = "urn:example:social:account:holder-1"
PASS_REF = "urn:example:agent-pass:2026-11-05-a"
AGENT, GATE = "engagement-assistant/2", "urn:example:enforcement-point:social"
ORG = "org-example"

# ---- the routine's policy, the issuer's document: who approves what, and how (the reading of issue 93: its digest
# is every specification's and every bound's policy_version, so each approval signs its words)
routine_policy = {
    "policy_id": "urn:example:policy:social-engagement-routine", "version": "2026-11-01",
    "applies_to": {"account": ACCOUNT},
    "approvers": [{"actor_ref": OWNER, "role": "account holder"}],
    "exact_approval_for": ["social.comment.create"],
    "bounded_approval_for": ["social.reaction.like", "social.invitation.send"],
    "per_pass_limits": {"social.reaction.like": 20, "social.comment.create": 10, "social.invitation.send": 5},
    "rules": {
        "R-DECLINED": "no action toward a person who declined contact",
        "R-NOT-READ": "no comment on a post not read in full with its replies",
        "R-RELATION": "no invitation to an existing first-degree relation",
        "R-ROLE-UNCONFIRMED": "no invitation while the person's current role is not confirmed: wait",
    },
    "max_approval_age_seconds": 7200,
    "recheck": "the enforcement point rechecks the approval or the bounds before each attempt, on its own clock",
}
policy_bytes = compact(routine_policy)
POLICY_VERSION = "sha256:" + sha256(policy_bytes)
POLICY_REF = routine_policy["policy_id"] + "#" + routine_policy["version"]
VALID_FROM, VALID_UNTIL = at(85), at(205)          # 10:25Z to 12:25Z

POSTS = [f"urn:example:social:post:{7101 + i}" for i in range(20)]
PROFILES = [f"urn:example:social:member:{5301 + i}" for i in range(5)]
COMMENT_POSTS = [f"urn:example:social:post:{7201 + i}" for i in range(11)]
TOPICS = ["the site report", "the safety audit results", "the new storage building", "the training season",
          "the energy retrofit", "the tender award", "the quarterly figures", "the apprentice programme",
          "the client visit", "the warehouse opening", "the hiring plan"]
COMMENT_TEXT = [f"Thank you for sharing {t}: the detail on timing is useful, and congratulations to the team."
                for t in TOPICS]
EDITED = 4                      # the holder rewrote this one before approving it
REJECTED = 7                    # and turned this one down
EDITED_TEXT = "Congratulations on the energy retrofit: the before-and-after figures make the case clearly."
DISCARDS = [  # what the routine's rules stopped before any proposal reached the holder
    ("social.invitation.send", {"profile_ref": "urn:example:social:member:5390"}, "R-DECLINED", "denied"),
    ("social.comment.create", {"post_ref": "urn:example:social:post:7290", "text": "Interesting point."}, "R-NOT-READ", "denied"),
    ("social.invitation.send", {"profile_ref": "urn:example:social:member:5391"}, "R-RELATION", "denied"),
    ("social.invitation.send", {"profile_ref": "urn:example:social:member:5392"}, "R-ROLE-UNCONFIRMED", "needs_decision"),
    ("social.invitation.send", {"profile_ref": "urn:example:social:member:5393"}, "R-ROLE-UNCONFIRMED", "needs_decision"),
]


def spec_of(operation, parameters, extra_refs=(), valid_until=None):
    s = {"operation": operation, "target": ACCOUNT, "parameters": parameters,
         "input_version_refs": [PASS_REF, *extra_refs], "policy_version": POLICY_VERSION}
    if valid_until:
        s["valid_until"] = valid_until
    return s


def bounds_of(operation, parameters, max_requests):
    return {"operation": operation, "target": ACCOUNT, "policy_version": POLICY_VERSION,
            "input_version_refs": [PASS_REF], "parameters": parameters, "max_requests": max_requests,
            "valid_from": VALID_FROM, "valid_until": VALID_UNTIL}


def view_for_bounds(title, items, max_requests):
    return ("\n".join([title, f"account {ACCOUNT}", f"policy {POLICY_REF} ({POLICY_VERSION})",
                       f"at most {max_requests}, from {VALID_FROM} until {VALID_UNTIL}", *items]) + "\n").encode()


def view_for_comment(spec):
    p = spec["parameters"]
    return (f"Comment on {p['post_ref']} as {ACCOUNT}\n---\n{p['text']}\n---\n"
            f"policy {POLICY_REF} ({POLICY_VERSION}); valid until {spec['valid_until']}\n").encode()


def build():
    """Every artefact of the pass, as dicts and bytes; the negative cases mutate a copy."""
    specs = {}                                      # spec digest -> (bytes, dict)

    def add_spec(spec):
        b = compact(spec)
        d = sha256(b)
        specs[d] = (b, spec)
        return d

    stages, sigs, executions = [], [], []
    # -- the bounds: likes and invitations, each a standing approval of an exact list, a count and a period
    standing = {}
    for key, (op, param, items, n, title) in {
        "L": ("social.reaction.like", "post_ref", POSTS, 20, "Like these 20 posts"),
        "I": ("social.invitation.send", "profile_ref", PROFILES, 5, "Invite these 5 members, without a note"),
    }.items():
        params = {param: {"one_of": items}}
        if op == "social.reaction.like":
            params["reaction"] = {"exact": "like"}
        bounds = bounds_of(op, params, n)
        bb = compact(bounds)
        view = view_for_bounds(title, items, n)
        k = len(standing)
        stages.append({"stage_id": f"v{key}", "kind": "review", "at": at(80, 10 * k), "reviewer_ref": OWNER,
                       "shown_bounds_digest": sha256(bb), "shown_view_ref": f"urn:example:review-console:bounds-{key}",
                       "shown_view_digest": sha256(view)})
        stages.append({"stage_id": f"sa{key}", "kind": "standing_approval", "at": at(85, 10 * k), "review_ref": f"v{key}",
                       "actor_ref": OWNER, "method": "Ed25519 signature over the DPS person_standing_approval assertion",
                       "authority": {"authority_ref": POLICY_REF},
                       "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": at(85, 10 * k),
                                     "text_ref": f"urn:example:rationale:pass-a-{key}"},
                       "bounds_digest": sha256(bb), "bounds": {"availability": "available", "bytes_b64": b64(bb)}})
        sigs.append({"assertion": "person_standing_approval", "decision_id": None, "stage_id": f"sa{key}",
                     "bounds_digest": sha256(bb), "shown_view_digest": sha256(view), "signed_at": at(85, 10 * k)})
        standing[key] = {"op": op, "param": param, "items": items, "bounds": bounds, "bytes": bb, "view": view}
        for i, item in enumerate(items):
            p = {param: item, **({"reaction": "like"} if op == "social.reaction.like" else {})}
            executions.append({"via": f"sa{key}", "spec": add_spec(spec_of(op, p)), "kind": op})
    # -- the comments: each proposed by the agent, shown, and approved or rejected on its own
    for i, (post, text) in enumerate(zip(COMMENT_POSTS, COMMENT_TEXT)):
        proposed = spec_of("social.comment.create", {"post_ref": post, "text": text},
                           [f"urn:example:social:read:{post.rsplit(':', 1)[1]}"], VALID_UNTIL)
        pd = add_spec(proposed)
        shown, sd, edited = proposed, pd, None
        if i == EDITED:
            shown = copy.deepcopy(proposed)
            shown["parameters"]["text"] = EDITED_TEXT
            sd, edited = add_spec(shown), OWNER
        view = view_for_comment(shown)
        stages.append({"stage_id": f"p{i}", "kind": "proposal", "at": at(58, i), "origin": "ai", "spec_digest": pd,
                       "deployer_role_pointer": "urn:example:role:engagement-drafting", "system_name": "engagement-assistant",
                       "version": "2"})
        review = {"stage_id": f"v{i}", "kind": "review", "at": at(81, 20 * i), "reviewer_ref": OWNER,
                  "shown_spec_digest": sd, "proposal_ref": f"p{i}", "shown_view_ref": f"urn:example:review-console:comment-{i}",
                  "shown_view_digest": sha256(view)}
        if edited:
            review["edited_by"] = edited
        stages.append(review)
        outcome = "rejected" if i == REJECTED else "approved"
        o = {"stage_id": f"o{i}", "kind": "outcome", "at": at(86, 10 * i), "review_ref": f"v{i}", "outcome": outcome,
             "actor_ref": OWNER, "method": "Ed25519 signature over the DPS person_" + ("review" if outcome == "rejected" else "approval") + " assertion",
             "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": at(86, 10 * i),
                           "text_ref": f"urn:example:rationale:pass-a-comment-{i}"}}
        if outcome == "approved":
            o.update(approved_spec_digest=sd, request_limit=1, authority={"authority_ref": POLICY_REF})
            executions.append({"via": f"o{i}", "spec": sd, "kind": "social.comment.create"})
        stages.append(o)
        sig = {"assertion": "person_approval" if outcome == "approved" else "person_review", "decision_id": None,
               "stage_id": f"o{i}", "outcome": outcome, "shown_spec_digest": sd, "shown_view_digest": sha256(view),
               "signed_at": at(86, 10 * i)}
        if outcome == "approved":
            sig["approved_spec_digest"] = sd
        sigs.append(sig)
    # -- the executions, one after the other from 10:30Z: request, recheck, attempt, observed result
    actions = []
    for n, e in enumerate(executions):
        t = 90 * 60 + 40 * n
        aid = uid("action", str(n))
        sp = specs[e["spec"]][1]
        sfx = str(n)
        evidence = f"urn:example:social:effect:{sha256(compact(sp['parameters']))[:16]}"
        stages += [
            {"stage_id": f"q{sfx}", "kind": "request", "at": at(0, t), "request_id": f"urn:aqta:action:{aid}",
             "authorised_by": e["via"], "spec_digest": e["spec"], "requested_by": "urn:example:service:engagement-routine"},
            {"stage_id": f"c{sfx}", "kind": "recheck", "at": at(0, t + 5), "request_ref": f"q{sfx}", "result": "authorised",
             "authority_source_ref": POLICY_REF},
            {"stage_id": f"x{sfx}", "kind": "attempt", "at": at(0, t + 10), "request_ref": f"q{sfx}", "recheck_ref": f"c{sfx}",
             "spec_digest": e["spec"], "executor_ref": GATE, "trace_refs": [f"urn:aqta:action:{aid}"]},
            {"stage_id": f"r{sfx}", "kind": "result", "at": at(0, t + 25), "attempt_ref": f"x{sfx}", "observed": "succeeded",
             "basis": "executor_observation", "evidence_ref": evidence},
        ]
        actions.append({"action_id": aid, "outcome": "ALLOWED", "tool": sp["operation"], "args": sp["parameters"],
                        "policy_applied": ["social_engagement_routine"], "timestamp": at(0, t + 10)[:-1] + ".000Z",
                        "spec": e["spec"], "via": e["via"], "evidence": evidence, "stage": f"x{sfx}"})
    for n, (op, args, rule, verdict) in enumerate(DISCARDS):
        actions.append({"action_id": uid("blocked", str(n)), "outcome": "BLOCKED", "tool": op, "args": args,
                        "policy_applied": [rule], "timestamp": at(59, 30 + n)[:-1] + ".000Z", "rule": rule,
                        "verdict": verdict})
    return {"specs": specs, "stages": stages, "sigs": sigs, "actions": actions, "standing": standing}


def assemble(b):
    """Bytes and documents from the parts: record, attachment, signatures, trust policy, Seal records, capsules."""
    record = json.loads(TEMPLATE.read_bytes())    # a schema-valid Core v5.0 record; every field below is this pass's
    record.update({
        "decision_id": "DR-2026-1105", "created_at": at(55), "charter_id": "CH-EXAMPLE-ENGAGEMENT-1",
        "record_type": "decision", "record_state": "closed", "dispatch_mode": "mode-1-with-embedded-mode-2-summary",
        "altitude": "individual-professional", "decision_class": "external-communication",
        "consent_posture": {"posture_class": "public professional content only: posts, comments and member profiles "
                                             "as the network shows them; no private messages read"},
        "success_criteria": ["Every reply received in the pass is answered or set aside with a reason.",
                             "No action toward a member who declined contact."],
        "assumptions_depended_on": ["The pass reading is complete for the feed, the replies and the invitations."],
        "accountable_owner": {"full_name": "Account Holder One", "role": "Account holder", "employer": "Example Org"},
        "re_decision_trigger": "A member declines contact, or a comment draws a complaint, before the next pass.",
        "supersedes": None,
        "decision_statement": "Engage for account holder-1 in pass 2026-11-05-a: like 20 listed posts and invite 5 listed "
                              "members within the stated bounds, and publish the comments approved one by one, under the "
                              "social engagement routine policy of 1 November 2026.",
        "context_at_decision": "The engagement assistant read the account's feed and replies (pass 2026-11-05-a) and "
                               "proposed likes, invitations and comments; its rules set five aside before review.",
        "options_considered": ["Approve the likes and invitations as bounds and each comment on its own (chosen).",
                               "Approve every action one by one: 35 reviews for likes that carry no text.",
                               "Skip this pass: the replies of the last pass stay unanswered."],
        "required_inputs_used": ["pass 2026-11-05-a reading (feed, replies, invitations)", "routine policy 2026-11-01"],
        "affirmation_record": {"timestamp": at(88), "actor_identity": OWNER,
                               "method": "Ed25519 signatures over the DPS person assertions of this pass"},
        "accountable_owner_signoff": {"signed_by": OWNER, "signed_at": at(240)},
        "closed_at": at(240), "record_location": "urn:example:decision-records:DR-2026-1105-A",
        "drafting_authority": {"deployer_role_pointer": "urn:example:role:engagement-drafting",
                               "system_name": "engagement-assistant", "version": "2"},
    })
    # the core review log: one entry for each decision a person took in this pass, which the stage names (core_ref)
    record["review_log"] = []
    for s in b["stages"]:
        if s["kind"] in ("standing_approval", "outcome"):
            s["core_ref"] = {"field": "review_log", "index": len(record["review_log"])}
            record["review_log"].append({"reviewer": s["actor_ref"], "reviewed_at": s["at"],
                                         "outcome": s.get("outcome", "approved")})
    record["mode_classification_attestation"].update({
        "attestor_full_name": "Account Holder One", "attestor_role_title": "Account holder",
        "attestor_employer": "Example Org", "attestation_timestamp": at(240), "attestor_capacity": "employee",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 "
                                   "summary under charter CH-EXAMPLE-ENGAGEMENT-1: the engagement assistant "
                                   "(engagement-assistant, version 2) drafted the proposals from pass 2026-11-05-a; I "
                                   "approved the likes and the invitations as the bounds shown to me, and each comment as "
                                   "shown, edited one and rejected one, and I am the accountable owner of this decision."})
    record["seal_hash"] = "0" * 64
    record["seal_hash"] = sha256(compact(record))
    record_bytes = compact(record)
    did = record["decision_id"]
    used = {s.get("spec_digest") for s in b["stages"]} | {s.get("shown_spec_digest") for s in b["stages"]} | \
           {s.get("approved_spec_digest") for s in b["stages"]}
    attachment = {
        "profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": did,
        "action_specifications": [{
            "spec_digest": d, "representation": {"kind": "original_bytes", "media_type": "application/json"},
            "content": {"availability": "available", "bytes_b64": b64(raw)},
            "summary": {"operation": sp["operation"], "target": sp["target"], "policy_version": sp["policy_version"],
                        "input_version_refs": sp["input_version_refs"]}}
            for d, (raw, sp) in b["specs"].items() if d in used],
        "stages": b["stages"]}
    attachment_bytes = compact(attachment)
    persons = []
    for s in b["sigs"]:
        ps = {"profile": "dps-signatures", "profile_version": "0.2.0", **{k: v for k, v in s.items() if v is not None},
              "decision_id": did, "signature": {"algorithm": "Ed25519", "key_ref": OWNER_KEY_REF, "value_b64": ""}}
        ps["signature"]["value_b64"] = b64(owner_key.sign(SIG.person_signed_bytes(ps)))
        persons.append(ps)
    sig_attachment = {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": persons}
    trust = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0", "policy_ref": "urn:example:trust-policy:verifier-1",
             "tsas": [], "checkpoint_sources": [],
             "keys": [{"key_ref": OWNER_KEY_REF, "holder": OWNER, "role": "person", "algorithm": "Ed25519",
                       "public_key_hex": raw_public(owner_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                       "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:people"}]}
    seal_records = []
    for a in b["actions"]:
        rec = {"v": "action-1", "action_id": a["action_id"], "org_id": ORG, "session_id": "pass-2026-11-05-a",
               "intent_hash": "", "agent": AGENT, "tool": a["tool"], "args_hash": sha256(jcs(a["args"])),
               "outcome": a["outcome"], "policy_applied": sorted(a["policy_applied"]), "timestamp": a["timestamp"],
               "public_key": b64url(raw_public(gate_key))}
        rec["signature"] = b64url(gate_key.sign(AQ.canonical(rec).encode("utf-8")))
        seal_records.append(rec)
    capsules = [capsule_for(a, record, attachment_bytes, b) for a in b["actions"]]
    rejected = next(s for s in b["stages"] if s.get("outcome") == "rejected")
    capsules.append(capsule_for({"action_id": uid("rejected", rejected["stage_id"]), "outcome": "REJECTED_BY_HOLDER",
                                 "tool": "social.comment.create", "stage": rejected["stage_id"]}, record, attachment_bytes, b))
    return {"record": record, "record_bytes": record_bytes, "attachment": attachment, "attachment_bytes": attachment_bytes,
            "sig_attachment": sig_attachment, "trust": trust, "seal_records": seal_records, "capsules": capsules}


def capsule_for(a, record, attachment_bytes, b):
    refs = [{"type": f"{NS}.decision_record", "digest_alg": "SHA-256", "digest": record["seal_hash"], "citation_purpose": "ran_under"}]
    cap = {"spec_version": "0.12", "format_version": "4", "canonicalization_id": "jcs",
           "action_id": f"urn:aqta:action:{a['action_id']}", "action_type": "decide", "operator": "example engagement routine",
           "developer": "example", "timestamp": a.get("timestamp", at(86, 70)).replace(".000Z", "Z"), "domain": "social_engagement"}
    if a["outcome"] == "ALLOWED":
        exact = a["via"].startswith("o")
        # a person holds the authority either way; only an exact approval means a person disposed of this action
        cap["disposition"] = {"decision": "accept", "approver": "human", "human_disposed": exact,
                              "authority": POLICY_REF + "#" + a["via"], "verdict_class": "executed"}
        cap["effect"] = {"status": "confirmed", "type": "org.example." + a["tool"].replace(".", "_"),
                         "request_digest": a["spec"],
                         "response_digest": json_digest({"evidence_ref": a["evidence"], "observed": "succeeded"}),
                         "external_ref": a["evidence"],
                         "irreversibility_class": "two_way" if a["tool"] == "social.reaction.like" else "one_way_recoverable",
                         "effect_attestation": "runtime_claimed"}
        refs.append({"type": f"{NS}.action_binding_attachment", "digest_alg": "SHA-256", "digest": sha256(attachment_bytes),
                     "citation_purpose": "acted_on"})
    elif a["outcome"] == "BLOCKED":
        verdict = a["verdict"]
        cap["disposition"] = {"decision": "reject" if verdict == "denied" else "needs_input", "approver": "policy",
                              "human_disposed": False, "authority": POLICY_REF + "#" + a["rule"], "verdict_class": verdict,
                              "reason_digest": json_digest({"rule": a["rule"], "text": routine_policy["rules"][a["rule"]]})}
    else:  # the comment the holder rejected: a person's decision, signed, and no effect
        cap["disposition"] = {"decision": "reject", "approver": "human", "human_disposed": True,
                              "authority": POLICY_REF + "#" + a["stage"], "verdict_class": "denied"}
        refs.append({"type": f"{NS}.action_binding_attachment", "digest_alg": "SHA-256", "digest": sha256(attachment_bytes),
                     "citation_purpose": "responds_to"})
    cap["references"] = refs
    cap["capsule_id"] = CAP_CANON.compute_capsule_id(cap) if CAP_CANON else sha256(jcs(cap))
    return cap


def json_digest(v):
    return CAP_CANON.json_digest(v) if CAP_CANON else sha256(jcs(v))


DIMENSIONS = ("specification_digests", "specification_statements", "record_statements", "action_binding",
              "stage_order", "authorisation_recheck", "observed_results", "rationale_provenance")


def verify(art, b):
    """Each side on its own, then the joins across them. Returns the results; nothing here trusts another side."""
    r = {}
    seal = []
    for rec in art["seal_records"]:
        try:
            AQ.verify_action(json.loads(compact(rec)), b64url(raw_public(gate_key)))
            seal.append("valid")
        except AQ.Invalid as e:
            seal.append(f"invalid: {e}")
    r["seal_action_records"] = {"valid": seal.count("valid"), "of": len(seal),
                                "allowed": sum(x["outcome"] == "ALLOWED" for x in art["seal_records"]),
                                "blocked": sum(x["outcome"] == "BLOCKED" for x in art["seal_records"]),
                                "invalid": [s for s in seal if s != "valid"]}
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.exceptions import NoSuchResource
    from referencing.jsonschema import DRAFT202012

    def local(uri):
        """A schema the Standard's schemas reference ($ref), read from the checkout by file name, never fetched."""
        hits = [p for p in REPO.rglob(uri.rsplit("/", 1)[-1]) if ".git" not in p.parts]
        if not hits:
            raise NoSuchResource(ref=uri)
        return Resource.from_contents(json.loads(hits[0].read_text()), default_specification=DRAFT202012)
    registry = Registry(retrieve=local)
    schemas = {"record": ("standard/v5.0/schemas/decision-record.schema.json", art["record"]),
               "attachment": ("extensions/action-binding/schemas/execution-evidence.schema.json", art["attachment"]),
               "signatures": ("extensions/signatures/schemas/signatures-attachment.schema.json", art["sig_attachment"]),
               "trust_policy": ("extensions/anchoring/schemas/trust-policy.schema.json", art["trust"])}
    r["schema_errors"] = {k: [e.message[:160] for e in Draft202012Validator(json.loads((REPO / p).read_text()), registry=registry).iter_errors(doc)]
                          for k, (p, doc) in schemas.items()}
    ab = AB.check_attachment(art["attachment"], art["record_bytes"])
    r["dps_action_binding"] = {d: ab[d][0] for d in DIMENSIONS}
    r["dps_action_binding_findings"] = {d: ab[d][1] for d in DIMENSIONS if ab[d][1]}
    r["dps_per_spec"] = "verified" if all(all(c[0] == "verified" for c in s) for s in ab["per_spec"]) else ab["per_spec"]
    r["dps_executed_how"] = {k: sum(1 for _, how in ab["executed"] if how == k) for k in sorted({how for _, how in ab["executed"]})}
    r["dps_execution_state"] = ab["execution_state"]
    pol, persons, _seals, _ts = SIG.run_context({"attachment": art["sig_attachment"], "export": None, "policy": art["trust"],
                                                 "action_binding": {art["record"]["decision_id"]: art["attachment"]}})
    r["dps_trust_policy"] = pol["status"]
    r["dps_person_signatures"] = {"verified": sum(p["status"] == "verified" for p in persons), "of": len(persons),
                                  "failed": [{"stage": art["sig_attachment"]["person_signatures"][i]["stage_id"],
                                              **{k: p[k]["status"] for k in ("signature", "subject", "key_state", "identity")}}
                                             for i, p in enumerate(persons) if p["status"] != "verified"]}
    held = {f"{NS}.decision_record": sha256(compact({**art["record"], "seal_hash": "0" * 64})),
            f"{NS}.action_binding_attachment": sha256(art["attachment_bytes"])}
    caps = {"parsed": 0, "verified": 0, "references_resolved": 0, "of": len(art["capsules"]), "problems": []}
    for c in art["capsules"]:
        if CAP_PARSE:
            try:
                CAP_PARSE.parse_capsule(c)
                caps["parsed"] += 1
            except Exception as e:
                caps["problems"].append(f"{c['action_id']}: parse {type(e).__name__}: {e}")
            res = CAP_VERIFY.verify(c)
            caps["verified"] += bool(getattr(res, "ok", False))
        if all(held.get(ref["type"]) == ref["digest"] for ref in c["references"]):
            caps["references_resolved"] += 1
        else:
            caps["problems"].append(f"{c['action_id']}: a reference does not resolve against the bytes held")
    if not CAP_PARSE:
        caps["library"] = "not_checked: agent_action_capsule is not installed"
    r["capsules"] = caps
    r["joins"] = joins(art, ab)
    ok = (not any(r["schema_errors"].values()) and r["seal_action_records"]["valid"] == r["seal_action_records"]["of"]
          and all(v == "verified" for v in r["dps_action_binding"].values()) and r["dps_per_spec"] == "verified"
          and r["dps_trust_policy"] == "verified"
          and r["dps_person_signatures"]["verified"] == r["dps_person_signatures"]["of"]
          and caps["references_resolved"] == caps["of"] and (not CAP_PARSE or caps["parsed"] == caps["verified"] == caps["of"])
          and all(v is True for v in r["joins"].values()))
    r["all_verified"] = ok
    return r


def joins(art, ab):
    """What none of the three checks alone: the CAN record, the DPS stages and the WHAT capsule say the same thing."""
    stages = art["attachment"]["stages"]
    by_id = {s["stage_id"]: s for s in stages}
    attempts = {t: s for s in stages if s["kind"] == "attempt" for t in s.get("trace_refs", [])}
    results = {s["attempt_ref"]: s for s in stages if s["kind"] == "result"}
    specs = {s["spec_digest"]: json.loads(base64.b64decode(s["content"]["bytes_b64"])) for s in art["attachment"]["action_specifications"]}
    requested_args = {sha256(jcs(specs[s["spec_digest"]]["parameters"])) for s in stages if s["kind"] == "request" and s["spec_digest"] in specs}
    caps = {c["action_id"]: c for c in art["capsules"]}
    j = {}
    allowed = [x for x in art["seal_records"] if x["outcome"] == "ALLOWED"]
    blocked = [x for x in art["seal_records"] if x["outcome"] == "BLOCKED"]

    def allowed_ok(x):
        x_att = attempts.get(f"urn:aqta:action:{x['action_id']}")
        if not x_att or x_att["spec_digest"] not in specs:
            return False
        sp = specs[x_att["spec_digest"]]
        res = results.get(x_att["stage_id"])
        return sp["operation"] == x["tool"] and sha256(jcs(sp["parameters"])) == x["args_hash"] and bool(res) and res["observed"] == "succeeded"
    j["every ALLOWED Seal record has its DPS attempt, with the same tool and args_hash, and an observed result"] = all(allowed_ok(x) for x in allowed)
    j["no BLOCKED Seal record's arguments were requested in the DPS attachment"] = all(x["args_hash"] not in requested_args for x in blocked)

    def capsule_ok(x):
        c = caps.get(f"urn:aqta:action:{x['action_id']}")
        x_att = attempts.get(f"urn:aqta:action:{x['action_id']}")
        if not c or not x_att:
            return False
        q = by_id.get(x_att["request_ref"], {})
        via = by_id.get(q.get("authorised_by"), {})
        exact = via.get("kind") == "outcome"
        res = results.get(x_att["stage_id"], {})
        return (c["effect"]["request_digest"] == x_att["spec_digest"] and c["effect"]["external_ref"] == res.get("evidence_ref")
                and c["disposition"]["human_disposed"] is exact)
    j["every executed capsule cites the executed specification and the observed evidence, and says a person disposed "
      "of it only where an approval of that exact specification exists"] = all(capsule_ok(x) for x in allowed)
    j["every BLOCKED Seal record has a capsule with a never-dispatch verdict and no effect"] = all(
        (c := caps.get(f"urn:aqta:action:{x['action_id']}")) is not None and "effect" not in c
        and c["disposition"]["verdict_class"] in ("denied", "needs_decision") for x in blocked)
    def kind_of_authority(x):
        q = by_id.get(attempts.get(f"urn:aqta:action:{x['action_id']}", {}).get("request_ref"), {})
        return by_id.get(q.get("authorised_by"), {}).get("kind")
    via = {x["action_id"]: kind_of_authority(x) for x in allowed}
    j["the DPS report says how each execution was authorised, as the stages record it (shown to a reviewer, or via a "
      "standing approval)"] = [how for _, how in ab["executed"]].count("via_standing_approval") == \
        list(via.values()).count("standing_approval")
    # the routine policy, held and matching every policy_version, says which operations need an exact approval
    j["every operation the routine policy lists under exact_approval_for rests on an exact approval, never on bounds"] = all(
        via.get(x["action_id"]) == "outcome" for x in allowed if x["tool"] in routine_policy["exact_approval_for"])
    j["every specification and every bound names the routine policy by the digest of the policy held"] = all(
        sp["policy_version"] == "sha256:" + sha256(policy_bytes) for sp in specs.values()) and all(
        json.loads(base64.b64decode(s["bounds"]["bytes_b64"]))["policy_version"] == "sha256:" + sha256(policy_bytes)
        for s in stages if s["kind"] == "standing_approval")
    return j


def write(out, art):
    out.mkdir(parents=True, exist_ok=True)
    (out / "decision-record.json").write_bytes(art["record_bytes"])
    (out / "action-binding-attachment.json").write_bytes(art["attachment_bytes"])
    (out / "signatures-attachment.json").write_bytes(compact(art["sig_attachment"]))
    (out / "trust-policy.json").write_bytes(compact(art["trust"]))
    (out / "policy.json").write_bytes(policy_bytes)
    (out / "seal-action-records.json").write_text(json.dumps(art["seal_records"], ensure_ascii=False, indent=1) + "\n")
    (out / "capsules.json").write_text(json.dumps(art["capsules"], ensure_ascii=False, indent=1) + "\n")


if __name__ == "__main__":
    parts = build()
    art = assemble(parts)
    write(HERE / "out", art)
    results = verify(art, parts)
    (HERE / "out" / "summary.json").write_text(json.dumps(results, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(results, ensure_ascii=False, indent=1))
    sys.exit(0 if results["all_verified"] else 1)
