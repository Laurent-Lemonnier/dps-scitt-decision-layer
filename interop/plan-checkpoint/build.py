#!/usr/bin/env python3
"""A human checkpoint in the middle of a plan, under a claim the evidence left undecided. Built on the plan case
(../plan-run): the same plan of three steps approved as a whole, the same capsules, manifest and context chain, plus:

  after step 0, before the CRM record is created, the runtime screens the client against a restricted-parties list;
  two sources answer, one "possible match", one "no data"; the claim "no match" is left undecided by that evidence.
  An adjudication of that fact, in the shape of the P10 underdetermination profile (draft-nestorov-scitt-p10-
  underdetermination-02, Section 9), is held beside the run: two witness worlds compatible with the same closed
  evidence set, giving the claim different values, outcome NotDemonstrated(reason=underdetermined). The run halts.
  The office manager decides to resume: a second decision record (Core) with its own action binding attachment, whose
  one specification names, by digest, the state of the run's context she decided on (the state after step 0) and the
  adjudication she decided under. The run resumes; the capsules of the steps after the checkpoint cite that decision
  as well as the plan's. The manifest records the checkpoint between the steps.

The adjudication here is synthetic: built in this directory in the shape Section 9 lists, with the digests of its
claim, evidence and witnesses recomputable from the objects beside it, and marked so. It is not issued, registered or
verified by the P10 chain, and nothing here claims conformance to that profile. The executed instance of the
profile's Appendix B is named beside it, for the shape a real one takes: its adjudication statement (leaf 7 of the
instance's log) is cited by its bytes as the author published them (repository, tag, path, length, SHA-256), and a
copy pinned under vectors/ is checked against that digest. The decision layer is what this case adds: what the person
knew was undecided, and decided anyway, and why.
"""
import base64
import copy
import importlib.util
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PR = load("plan_run_build", HERE.parent / "plan-run" / "build.py")
sha256, compact, jcs, b64, at = PR.sha256, PR.compact, PR.jcs, PR.b64, PR.at
NS, CONTEXT_TYPE, RUN_ID, CLIENT = PR.NS, PR.CONTEXT_TYPE, PR.RUN_ID, PR.CLIENT
ADJ_TYPE = "net.isoluce.p10_adjudication_shape"   # provisional, this repository's: an adjudication in the shape of P10 Section 9

# ---- the screening fixture: a claim, the evidence closed before the checkpoint, two witness worlds
CLAIM = {"claim": "the client has no match on the restricted-parties list", "client_ref": CLIENT,
         "list_ref": "urn:example:screening:list:2026-11-05"}
EVIDENCE = [{"source": "urn:example:screening:provider-a", "result": "possible match", "score_percent": 61, "at": at(30, 22)},
            {"source": "urn:example:screening:provider-b", "result": "no data", "at": at(30, 23)}]
WITNESSES = [{"restricted_match": True, "provider_a_reads": "true positive", "provider_b_reads": "coverage gap"},
             {"restricted_match": False, "provider_a_reads": "false positive", "provider_b_reads": "coverage gap"}]
EXECUTED_INSTANCE = {  # the profile's own executed instance: its adjudication statement cited by its bytes, as the author published them
    "source": "draft-nestorov-scitt-p10-underdetermination-02, Appendix B and Appendix C.3 (C09); locator as corrected by "
              "the author on 1 November 2026",
    "log_identity_digest": "6a510bcf3a122ae9af2714939d60a6a4e997ff9751836024dd480ebd60cd37c9",
    "adjudication_leaf_index": 7, "checkpoint_size": 8,
    "repository": "VolMax-Studio/p10-scitt-transparency-s3", "tag": "v0.1.0-s3-accepted",
    "commit": "5acc277a13dc122e39fcb5f9f3e646b06cc95009",
    "path": "ts-prototype/evidence/s3b-capture/capture/prefix/000007.cose", "role": "p10-target",
    "length": 7516, "sha256": "73273d96f81aebfa35ff2298f99198328664a1ab6bec442ba5f4ce0003f8a16e"}
EXECUTED_INSTANCE_COPY = HERE / "vectors" / "000007.cose"   # the copy pinned beside the case (vectors/PINNED_COMMIT.txt, SHA256SUMS)


def executed_instance_held():
    """The pinned copy of the executed instance's adjudication statement against the citation: its length and SHA-256.
    A check of the pin, not a join between this case's documents: the case's adjudication stays synthetic."""
    if not EXECUTED_INSTANCE_COPY.exists():
        return "not_checked: no copy held"
    raw = EXECUTED_INSTANCE_COPY.read_bytes()
    ok = len(raw) == EXECUTED_INSTANCE["length"] and sha256(raw) == EXECUTED_INSTANCE["sha256"]
    return "verified" if ok else "failed: the copy held is not the object cited"


def compatible(evidence, world):
    """The fixture's compatibility relation: a world with a match needs a source that saw one; a world without a
    match needs no source that confirmed one. Both worlds fit "possible match" beside "no data"."""
    results = {e["result"] for e in evidence}
    return ("possible match" in results or "match" in results) if world["restricted_match"] else ("match" not in results)


def evaluate(claim, world):
    """The fixture's claim evaluation: "no match" is true exactly in a world without a match."""
    return not world["restricted_match"]


def adjudication_of(claim, evidence, witnesses):
    """An adjudication in the shape of P10 Section 9, over the fixture, with every structured digest recomputable
    (Section 8: SHA-256 over JCS bytes). Synthetic: issued and verified by nobody; marked in its limitations."""
    limitations = ["synthetic: built in dps-scitt-decision-layer/interop/plan-checkpoint, not issued, registered or "
                   "verified by the P10 chain; no claim of conformance to the profile",
                   "a two-source screening fixture: the compatibility relation and the evaluation are the fixture's",
                   "underdetermination relative to the declared fixture only; identifies no actual world and "
                   "establishes neither claim value"]
    return {"shape_of": "draft-nestorov-scitt-p10-underdetermination-02, Section 9", "synthetic": True,
            "instance_commitment_ref": "urn:example:p10:instance:screening-C-4471",
            "profile_commitment_ref": "urn:example:p10:profile:two-source-screening-v0",
            "evidence_admission_refs": [f"urn:example:p10:admission:{i}" for i in range(len(evidence))],
            "evidence_closure_ref": "urn:example:p10:closure:screening-C-4471",
            "preclosure_transcript_digest": sha256(jcs([e["source"] for e in evidence])),
            "instance_subject": "p10s2sub:" + sha256(jcs(claim))[:16],
            "log_identity_digest": sha256(b"urn:example:log:screening"),
            "claim_digest": sha256(jcs(claim)), "evidence_digest": sha256(jcs(evidence)),
            "codec_digest": sha256(b"jcs-sha256-v0"),
            "witness_0_digest": sha256(jcs(witnesses[0])), "witness_1_digest": sha256(jcs(witnesses[1])),
            "capability_proof_digest": sha256(b"synthetic: no capability proof"),
            "proof_digest": sha256(b"synthetic: no proof object"),
            "verifier_digest": sha256(b"synthetic: no verifier manifest"),
            "limitations_digest": sha256(jcs(limitations)), "limitations": limitations,
            "outcome": "NotDemonstrated(reason=underdetermined)"}


def build():
    b = PR.build()
    b["step_at"] = [(30, 12), (36, 40), (37, 5)]    # steps 1 and 2 run after the checkpoint
    b.update({"claim": copy.deepcopy(CLAIM), "evidence": copy.deepcopy(EVIDENCE), "witnesses": copy.deepcopy(WITNESSES),
              "checkpoint_at": {"adjudicated": at(30, 25), "proposed": at(30, 26), "shown": at(33), "approved": at(35),
                                "requested": at(35, 5), "rechecked": at(35, 10), "attempted": at(35, 15), "resumed": at(35, 20)},
              "checkpoint_context_override": None,     # a negative case names another state
              "checkpoint_claim_override": None,       # a negative case names another claim in the specification
              "checkpoint_cites": True})               # a negative case resumes without the decision
    return b


def view_for_checkpoint(spec, claim, evidence, adj):
    lines = [f"Resume plan run {RUN_ID} at step {spec['parameters']['resume_at']}", f"policy {PR.POLICY_REF} ({PR.POLICY_VERSION})",
             f"context state decided on: {spec['parameters']['context_state']}",
             f"claim: {claim['claim']} ({spec['parameters']['claim_digest']})",
             *[f"evidence: {e['source']} says {e['result']}" for e in evidence],
             f"adjudication: {adj['outcome']} ({spec['parameters']['adjudication_digest']})"]
    return ("\n".join(lines) + "\n").encode()


def checkpoint(b, ctx_state):
    """The checkpoint's adjudication, decision record, attachment and signature, for the context state given."""
    T = b["checkpoint_at"]
    adj = adjudication_of(b["claim"], b["evidence"], b["witnesses"])
    adj_bytes = jcs(adj)
    adj_digest = sha256(adj_bytes)
    claim_digest = b["checkpoint_claim_override"] or adj["claim_digest"]
    spec = {"operation": "workflow.resume", "target": RUN_ID,
            "parameters": {"resume_at": 1, "context_state": b["checkpoint_context_override"] or ctx_state,
                           "adjudication_digest": adj_digest, "claim_digest": claim_digest},
            "input_version_refs": [f"{CONTEXT_TYPE}:{b['checkpoint_context_override'] or ctx_state}", f"{ADJ_TYPE}:{adj_digest}", PR.USECASE_REF],
            "policy_version": PR.POLICY_VERSION, "valid_until": PR.VALID_UNTIL}
    spec_bytes = compact(spec)
    sd = sha256(spec_bytes)
    view = view_for_checkpoint(spec, b["claim"], b["evidence"], adj)
    record = json.loads(PR.TEMPLATE.read_bytes())
    record.update({
        "decision_id": "DR-2026-11061", "created_at": T["proposed"], "charter_id": "CH-EXAMPLE-ONBOARDING-1",
        "record_type": "decision", "record_state": "closed", "dispatch_mode": "mode-1-with-embedded-mode-2-summary",
        "altitude": "individual-professional", "decision_class": "client-onboarding",
        "consent_posture": {"posture_class": "the client's brief and two screening answers about the client; no other data read"},
        "success_criteria": ["The plan completes and the screening is reviewed within 48 hours.",
                             "What was undecided at the checkpoint is on record."],
        "assumptions_depended_on": ["The two screening sources are the ones the policy names; neither confirmed a match."],
        "accountable_owner": {"full_name": "Office Manager One", "role": "Office manager", "employer": "Example Brokerage"},
        "re_decision_trigger": "The screening review concludes, or a source answers with a match.",
        "supersedes": None,
        "decision_statement": "Resume the onboarding plan at step 1, the CRM record, the screening claim being undecided by "
                              "the evidence closed before the checkpoint: one source says possible match at 61 percent, one "
                              "has no data; review the screening within 48 hours.",
        "context_at_decision": "Step 0 produced the onboarding document; the runtime halted before the CRM record on an "
                               "adjudication that the restricted-parties claim is underdetermined; the state of the run's "
                               "context after step 0 and the adjudication were shown.",
        "options_considered": ["Resume the plan now, the claim undecided, and review the screening within 48 hours (chosen).",
                               "Stop the plan until the screening is decided: the client waits for a document already produced.",
                               "Resume without recording what was undecided: no trace of what was known."],
        "required_inputs_used": [f"context state after step 0 ({ctx_state})", f"adjudication of the screening claim ({adj_digest})",
                                 "onboarding plans policy 2026-11-01"],
        "affirmation_record": {"timestamp": T["approved"], "actor_identity": PR.OWNER,
                               "method": "Ed25519 signature over the DPS person_approval assertion of the resumption"},
        "accountable_owner_signoff": {"signed_by": PR.OWNER, "signed_at": at(40)},
        "closed_at": at(40), "record_location": "urn:example:decision-records:DR-2026-11061",
        "drafting_authority": {"deployer_role_pointer": "urn:example:role:onboarding-drafting",
                               "system_name": "onboarding-assistant", "version": "3"},
        "review_log": [{"reviewer": PR.OWNER, "reviewed_at": T["approved"], "outcome": "approved"}],
    })
    record["mode_classification_attestation"].update({
        "attestor_full_name": "Office Manager One", "attestor_role_title": "Office manager",
        "attestor_employer": "Example Brokerage", "attestation_timestamp": at(40), "attestor_capacity": "employee",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 "
                                   "summary under charter CH-EXAMPLE-ONBOARDING-1: the onboarding assistant proposed to "
                                   "resume the plan; I decided to resume it knowing the screening claim was undecided, on the "
                                   "context state and the adjudication shown, and I am the accountable owner of this decision."})
    record["seal_hash"] = "0" * 64
    record["seal_hash"] = sha256(compact(record))
    did = record["decision_id"]
    stages = [
        {"stage_id": "p0", "kind": "proposal", "at": T["proposed"], "origin": "ai", "spec_digest": sd,
         "deployer_role_pointer": "urn:example:role:onboarding-drafting", "system_name": "onboarding-assistant", "version": "3"},
        {"stage_id": "v0", "kind": "review", "at": T["shown"], "reviewer_ref": PR.OWNER, "shown_spec_digest": sd, "proposal_ref": "p0",
         "shown_view_ref": "urn:example:review-console:checkpoint-0471-1", "shown_view_digest": sha256(view)},
        {"stage_id": "o0", "kind": "outcome", "at": T["approved"], "review_ref": "v0", "outcome": "approved", "actor_ref": PR.OWNER,
         "method": "Ed25519 signature over the DPS person_approval assertion", "approved_spec_digest": sd, "request_limit": 1,
         "authority": {"authority_ref": PR.POLICY_REF},
         "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": T["approved"], "text_ref": "urn:example:rationale:checkpoint-0471-1"},
         "core_ref": {"field": "review_log", "index": 0}},
        {"stage_id": "q0", "kind": "request", "at": T["requested"], "request_id": f"{RUN_ID}:resume:1", "authorised_by": "o0",
         "spec_digest": sd, "requested_by": "urn:example:service:onboarding-routine"},
        {"stage_id": "c0", "kind": "recheck", "at": T["rechecked"], "request_ref": "q0", "result": "authorised", "authority_source_ref": PR.POLICY_REF},
        {"stage_id": "x0", "kind": "attempt", "at": T["attempted"], "request_ref": "q0", "recheck_ref": "c0", "spec_digest": sd,
         "executor_ref": PR.EXECUTOR, "trace_refs": [f"{RUN_ID}:resume:1"]},
        {"stage_id": "r0", "kind": "result", "at": T["resumed"], "attempt_ref": "x0", "observed": "succeeded",
         "basis": "executor_observation", "evidence_ref": f"urn:example:plan-run:resumed:{RUN_ID}:step:1"},
    ]
    attachment = {"profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": did,
                  "action_specifications": [{"spec_digest": sd, "representation": {"kind": "original_bytes", "media_type": "application/json"},
                                             "content": {"availability": "available", "bytes_b64": b64(spec_bytes)},
                                             "summary": {"operation": spec["operation"], "target": spec["target"], "policy_version": spec["policy_version"],
                                                         "input_version_refs": spec["input_version_refs"]}}],
                  "stages": stages}
    attachment["issuer_signature"] = {"algorithm": "Ed25519", "key_ref": PR.ISSUER_KEY_REF,
                                      "signed_bytes_ref": "dps-signatures 0.2.0 organisation_seal", "sealed_at": at(35, 30), "value_b64": "A" * 88}
    attachment["issuer_signature"]["value_b64"] = b64(PR.issuer_key.sign(PR.SIG.seal_signed_bytes(PR.AB.seal_assertion(attachment))))
    ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval", "decision_id": did, "stage_id": "o0",
          "outcome": "approved", "shown_spec_digest": sd, "shown_view_digest": sha256(view), "approved_spec_digest": sd,
          "signed_at": T["approved"], "signature": {"algorithm": "Ed25519", "key_ref": PR.OWNER_KEY_REF, "value_b64": ""}}
    ps["signature"]["value_b64"] = b64(PR.owner_key.sign(PR.SIG.person_signed_bytes(ps)))
    return {"adjudication": adj, "adjudication_bytes": adj_bytes, "record": record, "record_bytes": compact(record),
            "attachment": attachment, "attachment_bytes": compact(attachment),
            "sig_attachment": {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps]}}


def rechain(capsules, manifest):
    """Capsules changed after assembly: identifiers and chain links follow, and the manifest follows them."""
    prev = None
    for c in capsules:
        if prev:
            c["chain"] = {"parent_capsule_id": prev, "relation": "follows"}
        else:
            c.pop("chain", None)
        PR.recap(c)
        prev = c["capsule_id"]
    ids = {c["action_id"]: c["capsule_id"] for c in capsules}
    for m in manifest["steps"]:
        m["capsule_id"] = ids.get(f"{RUN_ID}:step:{m['index']}", m["capsule_id"])


def assemble(b):
    ck = {}

    def extend(b, record, capsules, manifest):
        ctx_state = next(m["context_after"] for m in manifest["steps"] if m["index"] == 0)
        ck.update(checkpoint(b, ctx_state))
        if b["checkpoint_cites"]:
            for c in capsules:
                if not c["action_id"].endswith(":step:0"):
                    c["references"].append({"type": f"{NS}.decision_record", "digest_alg": "SHA-256",
                                            "digest": ck["record"]["seal_hash"], "citation_purpose": "ran_under"})
        rechain(capsules, manifest)
        manifest["checkpoints"] = [{"after_step": 0, "context_state": ctx_state, "decision_id": ck["record"]["decision_id"],
                                    "decision_record": ck["record"]["seal_hash"], "adjudication_digest": sha256(ck["adjudication_bytes"]),
                                    "claim_digest": ck["adjudication"]["claim_digest"], "outcome": ck["adjudication"]["outcome"],
                                    "decided_at": b["checkpoint_at"]["approved"], "resumed_at": b["checkpoint_at"]["resumed"]}]
    art = PR.assemble(b, extend=extend)
    art["checkpoint"] = ck
    art["fixture"] = {"claim": b["claim"], "evidence": b["evidence"], "witnesses": b["witnesses"], "executed_instance": EXECUTED_INSTANCE}
    return art


def reserialize(art):
    PR.reserialize(art)
    ck = art["checkpoint"]
    ck["attachment_bytes"] = compact(ck["attachment"])
    ck["record_bytes"] = compact(ck["record"])
    ck["adjudication_bytes"] = jcs(ck["adjudication"])
    return art


def verify(art, b=None):
    ck = art["checkpoint"]
    r = PR.verify(art, b, held_extra={ck["record"]["seal_hash"]})
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.exceptions import NoSuchResource
    from referencing.jsonschema import DRAFT202012

    def local(uri):
        hits = [p for p in PR.REPO.rglob(uri.rsplit("/", 1)[-1]) if ".git" not in p.parts]
        if not hits:
            raise NoSuchResource(ref=uri)
        return Resource.from_contents(json.loads(hits[0].read_text()), default_specification=DRAFT202012)
    registry = Registry(retrieve=local)
    c = {}
    schemas = {"record": ("standard/v5.0/schemas/decision-record.schema.json", ck["record"]),
               "attachment": ("extensions/action-binding/schemas/execution-evidence.schema.json", ck["attachment"]),
               "signatures": ("extensions/signatures/schemas/signatures-attachment.schema.json", ck["sig_attachment"])}
    c["schema_errors"] = {k: [e.message[:160] for e in Draft202012Validator(json.loads((PR.REPO / p).read_text()), registry=registry).iter_errors(doc)]
                          for k, (p, doc) in schemas.items()}
    ab = PR.AB.check_attachment(ck["attachment"], ck["record_bytes"])
    c["dps_action_binding"] = {d: ab[d][0] for d in PR.DIMENSIONS}
    c["dps_action_binding_findings"] = {d: ab[d][1] for d in PR.DIMENSIONS if ab[d][1]}
    report = PR.AB.reference_report([ck["attachment"]], {ck["record"]["decision_id"]: ck["record_bytes"]}, art["trust"], ck["sig_attachment"])
    res = report["results"][0]
    c["dps_issuer_seal"] = {k: res["issuer_signature"].get(k, {}).get("status") if isinstance(res["issuer_signature"].get(k), dict)
                            else res["issuer_signature"].get(k) for k in ("status", "key_state", "holder")}
    _pol, persons, _s, _t = PR.SIG.run_context({"attachment": ck["sig_attachment"], "export": None, "policy": art["trust"],
                                                "action_binding": {ck["record"]["decision_id"]: ck["attachment"]}})
    c["dps_person_signatures"] = {"verified": sum(p["status"] == "verified" for p in persons), "of": len(persons),
                                  "failed": [{k: p[k]["status"] for k in ("signature", "subject", "key_state", "identity")}
                                             for p in persons if p["status"] != "verified"]}
    c["executed_instance_held"] = executed_instance_held()
    r["checkpoint"] = c
    r["joins"].update(joins(art))
    r["all_verified"] = (r["all_verified"] and not any(c["schema_errors"].values())
                         and all(v == "verified" for v in c["dps_action_binding"].values())
                         and c["dps_issuer_seal"]["status"] == "verified"
                         and c["dps_person_signatures"]["verified"] == c["dps_person_signatures"]["of"] == 1
                         and c["executed_instance_held"] == "verified"
                         and all(v is True for v in r["joins"].values()))
    return r


def joins(art):
    """What the plan case's joins do not say: that the decision at the checkpoint was taken on the state the run was
    in and under the adjudication held, that the adjudication is undecided on its own terms, that every step after
    the checkpoint ran under that decision and none before it, and that the manifest records it where it happened."""
    ck, man, fx = art["checkpoint"], art["manifest"], art["fixture"]
    j = {}
    outcome = next((s for s in ck["attachment"]["stages"] if s["kind"] == "outcome"), {})
    specs = {s["spec_digest"]: json.loads(base64.b64decode(s["content"]["bytes_b64"])) for s in ck["attachment"]["action_specifications"]}
    spec = specs.get(outcome.get("approved_spec_digest"), {})
    p = spec.get("parameters", {})
    cps = man.get("checkpoints", [])
    cp = cps[0] if cps else {}
    ctx_after_0 = next((m["context_after"] for m in man["steps"] if m["index"] == 0), None)
    adj = ck["adjudication"]
    adj_digest = sha256(jcs(adj))
    j["the checkpoint decision's specification names, by digest, the state of the run's context after step 0 as the manifest "
      "records it, the adjudication held and its claim; the manifest's checkpoint entry names the same"] = (
        p.get("context_state") == ctx_after_0 == cp.get("context_state") and p.get("adjudication_digest") == adj_digest == cp.get("adjudication_digest")
        and p.get("claim_digest") == adj.get("claim_digest") == cp.get("claim_digest") and spec.get("target") == RUN_ID and p.get("resume_at") == 1)
    claim, evidence, witnesses = fx["claim"], fx["evidence"], fx["witnesses"]
    j["the adjudication is undecided on its own terms: its claim, evidence, witness and limitations digests recompute from the "
      "objects beside it, both witnesses are compatible with the closed evidence under the fixture's relation, and they give "
      "the claim different values"] = (
        adj.get("claim_digest") == sha256(jcs(claim)) and adj.get("evidence_digest") == sha256(jcs(evidence))
        and adj.get("witness_0_digest") == sha256(jcs(witnesses[0])) and adj.get("witness_1_digest") == sha256(jcs(witnesses[1]))
        and adj.get("limitations_digest") == sha256(jcs(adj.get("limitations", [])))
        and adj.get("witness_0_digest") != adj.get("witness_1_digest")
        and all(compatible(evidence, w) for w in witnesses) and evaluate(claim, witnesses[0]) != evaluate(claim, witnesses[1])
        and adj.get("outcome") == "NotDemonstrated(reason=underdetermined)")
    ck_digest = ck["record"]["seal_hash"]
    by_index = {}
    for c in art["capsules"]:
        try:
            by_index[int(c["action_id"].rsplit(":", 1)[1])] = c
        except ValueError:
            pass

    def cites_checkpoint(c):
        return any(ref["type"] == f"{NS}.decision_record" and ref["digest"] == ck_digest and ref.get("citation_purpose") == "ran_under"
                   for ref in c.get("references", []))
    j["every step after the checkpoint cites the checkpoint decision as ran_under, and no step before it does"] = (
        0 in by_index and not cites_checkpoint(by_index[0]) and all(i in by_index and cites_checkpoint(by_index[i]) for i in (1, 2)))
    t_approved = outcome.get("at", "")
    j["the checkpoint decision was approved after step 0's capsule and before step 1's, and the resumption was requested after "
      "the approval (the issuer's times)"] = (
        0 in by_index and 1 in by_index and by_index[0]["timestamp"] < t_approved < by_index[1]["timestamp"]
        and all(s["at"] >= t_approved for s in ck["attachment"]["stages"] if s["kind"] in ("request", "recheck", "attempt", "result")))
    j["the manifest's checkpoint entry names the checkpoint record held, by its seal digest, and the record names this run and "
      "the state it decided on among its inputs"] = (
        cp.get("decision_record") == ck_digest and cp.get("decision_id") == ck["record"]["decision_id"]
        and any(ctx_after_0 in s for s in ck["record"].get("required_inputs_used", []))
        and any(adj_digest in s for s in ck["record"].get("required_inputs_used", [])))
    return j


def write(out, art):
    PR.write(out, art)
    ck = art["checkpoint"]
    (out / "checkpoint-decision-record.json").write_bytes(ck["record_bytes"])
    (out / "checkpoint-action-binding-attachment.json").write_bytes(ck["attachment_bytes"])
    (out / "checkpoint-signatures-attachment.json").write_bytes(compact(ck["sig_attachment"]))
    (out / "adjudication.json").write_bytes(ck["adjudication_bytes"])
    (out / "screening-fixture.json").write_text(json.dumps(art["fixture"], ensure_ascii=False, indent=1) + "\n")


if __name__ == "__main__":
    parts = build()
    art = assemble(parts)
    write(HERE / "out", art)
    results = verify(art, parts)
    (HERE / "out" / "summary.json").write_text(json.dumps(results, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(results, ensure_ascii=False, indent=1))
    sys.exit(0 if results["all_verified"] else 1)
