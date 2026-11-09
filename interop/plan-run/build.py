#!/usr/bin/env python3
"""One plan, approved as a whole, executed as steps: a person approves a compiled plan of three steps once, exactly,
and the runtime executes it as three actions, each carried as its own unit of evidence. Everything from existing
texts and existing code, nothing changed in any of them:

  WHO   the Decision Provenance Standard, action binding 0.3.0 + signatures 0.2.0: one specification, the plan (its
        steps and their hash), shown, approved and signed once, with one request, one recheck, one attempt and one
        observed result for the plan as a whole;
  WHAT  Agent Action Capsule format 4 (draft-mih-scitt-agent-action-capsule, library 0.16.0 since 9 November 2026, 0.15.0 from 7 November, 0.12.0 before): one capsule per step,
        citing the decision record, each chained to the step before it (chain.relation follows);
  the mother: a run manifest beside them (a provisional shape of this repository, net.isoluce.plan_run, not of either
        text), which names the approved specification and lists, for each step of the plan, the capsule that executed
        it and the outputs it recorded; the DPS result names the manifest by its digest.

The granularity of the authorisation (the plan) and of the execution (the step) differ. Neither text says how a
verifier holding one approval and N capsules tells that a capsule is step i of that plan, that no step is missing,
that none ran outside it, and that an argument written in the plan as a reference to an earlier step's output was
executed with the output that step actually recorded. The joins below say it; the manifest is what they need.

Synthetic data, modelled on a client-onboarding plan of a broker's runtime (a document, a CRM record, a message),
with no real client, document or person in it. One test key; never use it for anything real.
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
MANIFEST_PROFILE, MANIFEST_VERSION = "net.isoluce.plan_run", "0.1.0"   # provisional, this repository's


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


def key_from_seed(text):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(text.encode()).digest())


def raw_public(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def at(minute, second=0):
    """A time on the run day, 6 November 2026, from 09:00Z."""
    total = minute * 60 + second
    return f"2026-11-06T{9 + total // 3600:02d}:{total // 60 % 60:02d}:{total % 60:02d}Z"


def json_digest(v):
    return CAP_CANON.json_digest(v) if CAP_CANON else sha256(jcs(v))


owner_key = key_from_seed("dps-scitt-decision-layer plan-run: office manager key (test only)")
OWNER, OWNER_KEY_REF = "office-manager-1", "office-manager-1-key-1"
issuer_key = key_from_seed("dps-scitt-decision-layer plan-run: issuer seal key (test only)")
ISSUER, ISSUER_KEY_REF = "Example Brokerage", "example-brokerage-issuer-key-1"
TENANT = "urn:example:tenant:brokerage-1"
CLIENT = "urn:example:client:C-4471"
USECASE_REF = "urn:example:usecase:onboarding_client@1.0.0"
BRIEF_REF = "urn:example:client-brief:C-4471:v3"
RUN_ID = "urn:example:plan-run:2026-11-06-0471"
AGENT, EXECUTOR = "onboarding-assistant/3", "urn:example:executor:broker-runtime"

# ---- the plan policy, the issuer's document: its digest is the specification's policy_version (the reading of
# issue 93), so the approval signs its words: a plan is approved as a whole, once, on its exact steps
plan_policy = {
    "policy_id": "urn:example:policy:onboarding-plans", "version": "2026-11-01",
    "applies_to": {"tenant": TENANT},
    "approvers": [{"actor_ref": OWNER, "role": "office manager"}],
    "approval": "a compiled plan is approved as a whole, on its exact steps and their hash; one execution per approval",
    "resolved_arguments": "an argument written as {\"$ref\": \"steps[k].outputs.<name>\"} is approved as that reference; "
                          "the executor substitutes the output step k recorded, and nothing else",
    "order": "steps run in plan order; a step runs only after the step it takes an output from has succeeded",
    "no_step_outside_the_plan": True,
    "max_approval_age_seconds": 86400,
    "recheck": "the executor rechecks the approval before the first step, on its own clock",
}
policy_bytes = compact(plan_policy)
POLICY_VERSION = "sha256:" + sha256(policy_bytes)
POLICY_REF = plan_policy["policy_id"] + "#" + plan_policy["version"]
VALID_UNTIL = at(24 * 60 + 25)                   # 7 November, 09:25Z

# ---- the plan as compiled by the assistant from the use case and the brief: three steps; two arguments exist only
# after an earlier step ran, and are written as references to its outputs
STEPS = [
    {"index": 0, "operation": "drive.document.create", "target": "urn:example:drive:folder:clients/C-4471",
     "parameters": {"template_ref": "urn:example:drive:template:onboarding-v7", "client_ref": CLIENT,
                    "title": "Onboarding C-4471"}},
    {"index": 1, "operation": "crm.client.create", "target": "urn:example:crm:brokerage-1",
     "parameters": {"client_ref": CLIENT, "legal_name": "Example Client 4471 SAS", "segment": "small-business",
                    "document_ref": {"$ref": "steps[0].outputs.document_ref"}}},
    {"index": 2, "operation": "chat.message.send", "target": "urn:example:chat:channel:onboarding",
     "parameters": {"text": "New client C-4471 onboarded.", "document_ref": {"$ref": "steps[0].outputs.document_ref"},
                    "crm_record_ref": {"$ref": "steps[1].outputs.crm_record_ref"}}},
]
OUTPUTS = [  # what each step produced, as the executor observed it
    {"document_ref": "urn:example:drive:document:D-88213"},
    {"crm_record_ref": "urn:example:crm:client:R-30417"},
    {"message_ref": "urn:example:chat:message:M-551902"},
]
STEP_AT = [(30, 12), (30, 40), (31, 5)]       # when each step ran
CONTEXT_TYPE = "net.isoluce.plan_run_context"   # provisional, this repository's: a state of the run's context
INITIAL_CONTEXT = {"tenant": TENANT, "client_ref": CLIENT, "usecase_ref": USECASE_REF, "brief_ref": BRIEF_REF,
                   "correlation_id": "urn:example:correlation:onboarding:C-4471"}


def next_context(prev, index, outputs):
    """The state of the context after a step: the state before it, the step, and the outputs it recorded."""
    return sha256(jcs({"prev": prev, "step": index, "outputs": outputs}))


def context_chain(initial, steps_outputs):
    """Every state of a run's context, from the initial one to the state after the last step, in plan order."""
    states = [sha256(jcs({"initial": initial}))]
    for index, outputs in steps_outputs:
        states.append(next_context(states[-1], index, outputs))
    return states
IRREVERSIBILITY = {"drive.document.create": "one_way_recoverable", "crm.client.create": "one_way_recoverable",
                   "chat.message.send": "one_way_recoverable"}


def plan_hash_of(steps):
    """The hash of the executable steps, in order: what the person's approval of the plan rests on."""
    return sha256(jcs([{k: s[k] for k in ("index", "operation", "target", "parameters")} for s in steps]))


def refs_in(parameters):
    """The references to earlier steps' outputs among a step's arguments: name -> (step index, output name)."""
    out = {}
    for name, v in parameters.items():
        if isinstance(v, dict) and set(v) == {"$ref"}:
            k, _, o = v["$ref"].partition("].outputs.")
            out[name] = (int(k[len("steps["):]), o)
    return out


def resolve(step, outputs_by_index):
    """The request the executor sends for a step: the plan's arguments with each reference replaced by the output
    the referenced step recorded. Returns the request, or None if an output it needs is not recorded."""
    p = dict(step["parameters"])
    for name, (k, o) in refs_in(step["parameters"]).items():
        if k not in outputs_by_index or o not in outputs_by_index[k]:
            return None
        p[name] = outputs_by_index[k][o]
    return {"operation": step["operation"], "target": step["target"], "parameters": p}


def view_for_plan(spec):
    lines = [f"Run plan {USECASE_REF} for {CLIENT} in {TENANT}", f"policy {POLICY_REF} ({POLICY_VERSION})",
             f"plan hash {spec['parameters']['plan_hash']}; valid until {spec['valid_until']}; one execution"]
    for s in spec["parameters"]["steps"]:
        lines.append(f"{s['index']}. {s['operation']} on {s['target']}: " + json.dumps(s["parameters"], ensure_ascii=False))
    return ("\n".join(lines) + "\n").encode()


def build():
    """Every part of the run, as dicts; the negative cases change a copy before assembly."""
    steps = copy.deepcopy(STEPS)
    spec = {"operation": "workflow.run", "target": TENANT,
            "parameters": {"usecase_ref": USECASE_REF, "plan_hash": plan_hash_of(steps), "steps": steps},
            "input_version_refs": [USECASE_REF, BRIEF_REF], "policy_version": POLICY_VERSION, "valid_until": VALID_UNTIL}
    return {"spec": spec,
            "recorded_outputs": copy.deepcopy(OUTPUTS),   # what the manifest records, and what later steps resolve from
            "observed_outputs": copy.deepcopy(OUTPUTS),   # what each step's capsule commits to (response_digest)
            "executed": {},                               # index -> a request executed instead of the plan's (negatives)
            "order": [0, 1, 2],                           # the order the steps ran in
            "extra_requests": 0,                          # further executions of the plan under the same approval
            "step_at": list(STEP_AT)}


def assemble(b, extend=None):
    """Bytes and documents from the parts, in dependency order: record, capsules, manifest, attachment, signatures.
    extend, if given, is called with (b, record, capsules, manifest) after the capsules and the manifest exist and
    before the manifest's bytes are fixed and the attachment names them (the checkpoint case builds on it)."""
    spec = b["spec"]
    spec_bytes = compact(spec)
    spec_digest = sha256(spec_bytes)
    view = view_for_plan(spec)
    record = json.loads(TEMPLATE.read_bytes())    # a schema-valid decision record (Core v1.3 rev. 11, reference files 5.2.0); every field below is this run's
    record.update({
        "decision_id": "DR-2026-1106", "created_at": at(12), "charter_id": "CH-EXAMPLE-ONBOARDING-1",
        "record_type": "decision", "record_state": "closed", "dispatch_mode": "mode-1-with-embedded-mode-2-summary",
        "altitude": "individual-professional", "decision_class": "client-onboarding",
        "consent_posture": {"posture_class": "the client's brief, given for onboarding; no other data read"},
        "success_criteria": ["The onboarding document, the CRM record and the team message exist and agree.",
                             "No step runs outside the plan shown."],
        "assumptions_depended_on": ["The client brief C-4471 v3 is the one the client confirmed."],
        "accountable_owner": {"full_name": "Office Manager One", "role": "Office manager", "employer": "Example Brokerage"},
        "re_decision_trigger": "The brief changes, or a step fails, before the plan completes.",
        "supersedes": None,
        "decision_statement": "Onboard client C-4471 by running the compiled plan onboarding_client 1.0.0 as shown: "
                              "create the onboarding document, create the CRM record with it, and tell the onboarding "
                              "channel, under the onboarding plans policy of 1 November 2026.",
        "context_at_decision": "The onboarding assistant compiled the plan from use case onboarding_client 1.0.0 and the "
                               "client brief C-4471 v3; two of its arguments exist only after an earlier step runs.",
        "options_considered": ["Approve the compiled plan as a whole, on its exact steps (chosen).",
                               "Approve each step on its own: the two later steps cannot be shown with their final arguments.",
                               "Onboard by hand: no record of what was decided."],
        "required_inputs_used": ["use case onboarding_client 1.0.0", "client brief C-4471 v3", "onboarding plans policy 2026-11-01"],
        "affirmation_record": {"timestamp": at(25), "actor_identity": OWNER,
                               "method": "Ed25519 signature over the DPS person_approval assertion of this plan"},
        "accountable_owner_signoff": {"signed_by": OWNER, "signed_at": at(40)},
        "closed_at": at(40), "record_location": "urn:example:decision-records:DR-2026-1106",
        "drafting_authority": {"deployer_role_pointer": "urn:example:role:onboarding-drafting",
                               "system_name": "onboarding-assistant", "version": "3"},
        "review_log": [{"reviewer": OWNER, "reviewed_at": at(25), "outcome": "approved"}],
    })
    record["mode_classification_attestation"].update({
        "attestor_full_name": "Office Manager One", "attestor_role_title": "Office manager",
        "attestor_employer": "Example Brokerage", "attestation_timestamp": at(40), "attestor_capacity": "employee",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 "
                                   "summary under charter CH-EXAMPLE-ONBOARDING-1: the onboarding assistant "
                                   "(onboarding-assistant, version 3) compiled the plan from the use case and the brief; "
                                   "I approved the plan as shown, as a whole, and I am the accountable owner of this decision."})
    record["seal_hash"] = "0" * 64
    record["seal_hash"] = sha256(compact(record))
    record_bytes = compact(record)
    did = record["decision_id"]
    # -- the steps as they ran: one capsule each, chained in run order; each step resolves its arguments from the
    # outputs the executor recorded for the steps before it
    steps = {s["index"]: s for s in spec["parameters"]["steps"]}
    recorded = {i: o for i, o in enumerate(b["recorded_outputs"])}
    capsules, manifest_steps, prev = [], [], None
    ctx = context_chain(INITIAL_CONTEXT, [])[0]           # the context before any step ran
    for n, i in enumerate(b["order"]):
        request = b["executed"].get(i) or resolve(steps[i], recorded)
        m, s = b["step_at"][n]
        ctx_before, ctx = ctx, next_context(ctx, i, recorded[i])   # the step reads the state before it, adds its outputs
        cap = {"spec_version": "0.12", "format_version": "4", "canonicalization_id": "jcs",
               "action_id": f"{RUN_ID}:step:{i}", "action_type": "decide", "operator": "example broker runtime",
               "developer": "example", "timestamp": at(m, s), "domain": "client_onboarding",
               # the person approved the plan; only a step whose every argument was literal in it is one a person
               # disposed of: an argument resolved at run time was approved as a reference, not as a value
               "disposition": {"decision": "accept", "approver": "human", "human_disposed": not refs_in(steps[i]["parameters"]),
                               "authority": POLICY_REF + "#o0", "verdict_class": "executed"},
               "effect": {"status": "confirmed", "type": "org.example." + steps[i]["operation"].replace(".", "_"),
                          "request_digest": sha256(jcs(request)), "response_digest": json_digest(b["observed_outputs"][i]),
                          "external_ref": next(iter(b["observed_outputs"][i].values())),
                          "irreversibility_class": IRREVERSIBILITY[steps[i]["operation"]], "effect_attestation": "runtime_claimed"},
               "references": [{"type": f"{NS}.decision_record", "digest_alg": "SHA-256", "digest": record["seal_hash"],
                               "citation_purpose": "ran_under"},
                              {"type": CONTEXT_TYPE, "digest_alg": "SHA-256", "digest": ctx_before, "citation_purpose": "ran_under"}]}
        if prev:
            cap["chain"] = {"parent_capsule_id": prev, "relation": "follows"}
        cap["capsule_id"] = CAP_CANON.compute_capsule_id(cap) if CAP_CANON else sha256(jcs(cap))
        prev = cap["capsule_id"]
        capsules.append(cap)
        manifest_steps.append({"index": i, "operation": steps[i]["operation"], "target": steps[i]["target"],
                               "request_digest": cap["effect"]["request_digest"], "capsule_id": cap["capsule_id"],
                               "outputs": recorded[i], "context_before": ctx_before, "context_after": ctx,
                               "status": "succeeded", "started_at": at(m, s), "ended_at": at(m, s + 9)})
    manifest = {"profile": MANIFEST_PROFILE, "profile_version": MANIFEST_VERSION, "run_id": RUN_ID, "decision_id": did,
                "approval_stage_ref": "o0", "spec_digest": spec_digest, "plan_hash": spec["parameters"]["plan_hash"],
                "usecase_ref": USECASE_REF, "requested_by": "urn:example:service:onboarding-routine",
                "initial_context": INITIAL_CONTEXT, "context_initial_digest": context_chain(INITIAL_CONTEXT, [])[0],
                "steps": manifest_steps, "outcome": {"status": "completed", "ended_at": at(31, 14), "context_final": ctx}}
    if extend:
        extend(b, record, capsules, manifest)
    manifest_bytes = compact(manifest)
    # -- the DPS stages: the plan proposed, shown, approved once; then one request, recheck, attempt and result
    stages = [
        {"stage_id": "p0", "kind": "proposal", "at": at(12), "origin": "ai", "spec_digest": spec_digest,
         "deployer_role_pointer": "urn:example:role:onboarding-drafting", "system_name": "onboarding-assistant", "version": "3"},
        {"stage_id": "v0", "kind": "review", "at": at(20), "reviewer_ref": OWNER, "shown_spec_digest": spec_digest,
         "proposal_ref": "p0", "shown_view_ref": "urn:example:review-console:plan-0471", "shown_view_digest": sha256(view)},
        {"stage_id": "o0", "kind": "outcome", "at": at(25), "review_ref": "v0", "outcome": "approved", "actor_ref": OWNER,
         "method": "Ed25519 signature over the DPS person_approval assertion", "approved_spec_digest": spec_digest,
         "request_limit": 1, "authority": {"authority_ref": POLICY_REF},
         "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": at(25), "text_ref": "urn:example:rationale:plan-0471"},
         "core_ref": {"field": "review_log", "index": 0}},
    ]
    for k in range(1 + b["extra_requests"]):
        t, sfx = 30 * 60 + 120 * k, str(k)
        stages += [
            {"stage_id": f"q{sfx}", "kind": "request", "at": at(0, t), "request_id": RUN_ID if k == 0 else f"{RUN_ID}-again-{k}",
             "authorised_by": "o0", "spec_digest": spec_digest, "requested_by": "urn:example:service:onboarding-routine"},
            {"stage_id": f"c{sfx}", "kind": "recheck", "at": at(0, t + 5), "request_ref": f"q{sfx}", "result": "authorised",
             "authority_source_ref": POLICY_REF},
            {"stage_id": f"x{sfx}", "kind": "attempt", "at": at(0, t + 10), "request_ref": f"q{sfx}", "recheck_ref": f"c{sfx}",
             "spec_digest": spec_digest, "executor_ref": EXECUTOR, "trace_refs": [RUN_ID]},
            {"stage_id": f"r{sfx}", "kind": "result", "at": at(0, t + 80), "attempt_ref": f"x{sfx}", "observed": "succeeded",
             "basis": "executor_observation", "evidence_ref": f"urn:example:plan-run-manifest:sha256:{sha256(manifest_bytes)}"},
        ]
    attachment = {"profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": did,
                  "action_specifications": [{
                      "spec_digest": spec_digest, "representation": {"kind": "original_bytes", "media_type": "application/json"},
                      "content": {"availability": "available", "bytes_b64": b64(spec_bytes)},
                      "summary": {"operation": spec["operation"], "target": spec["target"], "policy_version": spec["policy_version"],
                                  "input_version_refs": spec["input_version_refs"]}}],
                  "stages": stages}
    # the issuer's seal of kind attachment (action binding item 7): it covers the result that names the manifest
    attachment["issuer_signature"] = {"algorithm": "Ed25519", "key_ref": ISSUER_KEY_REF,
                                      "signed_bytes_ref": "dps-signatures 0.2.0 organisation_seal", "sealed_at": at(32),
                                      "value_b64": "A" * 88}
    attachment["issuer_signature"]["value_b64"] = b64(issuer_key.sign(SIG.seal_signed_bytes(AB.seal_assertion(attachment))))
    ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval", "decision_id": did,
          "stage_id": "o0", "outcome": "approved", "shown_spec_digest": spec_digest, "shown_view_digest": sha256(view),
          "approved_spec_digest": spec_digest, "signed_at": at(25),
          "signature": {"algorithm": "Ed25519", "key_ref": OWNER_KEY_REF, "value_b64": ""}}
    ps["signature"]["value_b64"] = b64(owner_key.sign(SIG.person_signed_bytes(ps)))
    sig_attachment = {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps]}
    trust = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0", "policy_ref": "urn:example:trust-policy:verifier-1",
             "tsas": [], "checkpoint_sources": [],
             "keys": [{"key_ref": OWNER_KEY_REF, "holder": OWNER, "role": "person", "algorithm": "Ed25519",
                       "public_key_hex": raw_public(owner_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                       "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:people"},
                      {"key_ref": ISSUER_KEY_REF, "holder": ISSUER, "role": "organisation", "algorithm": "Ed25519",
                       "public_key_hex": raw_public(issuer_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                       "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:organisations"}]}
    return {"record": record, "record_bytes": record_bytes, "attachment": attachment, "attachment_bytes": compact(attachment),
            "sig_attachment": sig_attachment, "trust": trust, "capsules": capsules, "manifest": manifest,
            "manifest_bytes": manifest_bytes}


def reserialize(art):
    """After a change to a document in art, its bytes follow (the negative cases that change assembled documents)."""
    art["attachment_bytes"] = compact(art["attachment"])
    art["manifest_bytes"] = compact(art["manifest"])
    return art


def recap(c):
    """A capsule changed after assembly gets the identifier of its new content."""
    c.pop("capsule_id", None)
    c["capsule_id"] = CAP_CANON.compute_capsule_id(c) if CAP_CANON else sha256(jcs(c))
    return c


DIMENSIONS = ("specification_digests", "specification_statements", "record_statements", "action_binding",
              "stage_order", "authorisation_recheck", "observed_results", "rationale_provenance")


def verify(art, b=None, held_extra=()):
    """Each side on its own, then the joins across them. Returns the results; nothing here trusts another side.
    held_extra: digests of further decision records the verifier holds (the checkpoint case adds one)."""
    r = {}
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
    report = AB.reference_report([art["attachment"]], {art["record"]["decision_id"]: art["record_bytes"]}, art["trust"], art["sig_attachment"])
    res = report["results"][0]
    r["dps_issuer_seal"] = {k: res["issuer_signature"].get(k, {}).get("status") if isinstance(res["issuer_signature"].get(k), dict)
                            else res["issuer_signature"].get(k) for k in ("status", "key_state", "holder", "attests")}
    pol, persons, _seals, _ts = SIG.run_context({"attachment": art["sig_attachment"], "export": None, "policy": art["trust"],
                                                 "action_binding": {art["record"]["decision_id"]: art["attachment"]}})
    r["dps_trust_policy"] = pol["status"]
    r["dps_person_signatures"] = {"verified": sum(p["status"] == "verified" for p in persons), "of": len(persons),
                                  "failed": [{"stage": art["sig_attachment"]["person_signatures"][i]["stage_id"],
                                              **{k: p[k]["status"] for k in ("signature", "subject", "key_state", "identity")}}
                                             for i, p in enumerate(persons) if p["status"] != "verified"]}
    # what a reference may resolve to: the record held, and the context states recomputed from the manifest held
    man = art["manifest"]
    states = context_chain(man["initial_context"], [(m["index"], m["outputs"]) for m in sorted(man["steps"], key=lambda m: m["index"])])
    held = {f"{NS}.decision_record": {sha256(compact({**art["record"], "seal_hash": "0" * 64})), *held_extra}, CONTEXT_TYPE: set(states)}
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
        if all(ref["digest"] in held.get(ref["type"], ()) for ref in c["references"]):
            caps["references_resolved"] += 1
        else:
            caps["problems"].append(f"{c['action_id']}: a reference does not resolve against the bytes held")
    if not CAP_PARSE:
        caps["library"] = "not_checked: agent_action_capsule is not installed"
    r["capsules"] = caps
    r["joins"] = joins(art)
    ok = (not any(r["schema_errors"].values())
          and all(v == "verified" for v in r["dps_action_binding"].values()) and r["dps_per_spec"] == "verified"
          and r["dps_trust_policy"] == "verified" and r["dps_issuer_seal"]["status"] == "verified"
          and r["dps_person_signatures"]["verified"] == r["dps_person_signatures"]["of"]
          and caps["references_resolved"] == caps["of"] and (not CAP_PARSE or caps["parsed"] == caps["verified"] == caps["of"])
          and all(v is True for v in r["joins"].values()))
    r["all_verified"] = ok
    return r


def joins(art):
    """What neither the DPS checks nor the capsule library checks: that N capsules are the steps of the one plan a
    person approved, all of them, only them, in its order, with the arguments the plan resolves from recorded outputs."""
    stages = art["attachment"]["stages"]
    by_id = {s["stage_id"]: s for s in stages}
    outcome = next((s for s in stages if s["kind"] == "outcome" and s.get("outcome") == "approved"), None)
    specs = {s["spec_digest"]: json.loads(base64.b64decode(s["content"]["bytes_b64"])) for s in art["attachment"]["action_specifications"]}
    spec = specs.get(outcome["approved_spec_digest"]) if outcome else None
    man = art["manifest"]
    j = {}
    if not spec:
        return {"an approved plan specification is held": False}
    steps = {s["index"]: s for s in spec["parameters"]["steps"]}
    j["the approved plan's plan_hash is the hash of its executable steps, as the policy defines it"] = \
        spec["parameters"]["plan_hash"] == plan_hash_of(spec["parameters"]["steps"])
    j["the run manifest names the approved specification and carries the same plan hash"] = \
        man["spec_digest"] == outcome["approved_spec_digest"] and man["plan_hash"] == spec["parameters"]["plan_hash"] \
        and man["approval_stage_ref"] == outcome["stage_id"]
    results = [s for s in stages if s["kind"] == "result"]
    j["the DPS result names the run manifest held, by its digest"] = \
        any(s["evidence_ref"].rsplit(":", 1)[-1] == sha256(art["manifest_bytes"]) for s in results)
    record_digest = sha256(compact({**art["record"], "seal_hash": "0" * 64}))
    caps = [c for c in art["capsules"]
            if any(ref["type"] == f"{NS}.decision_record" and ref["digest"] == record_digest for ref in c["references"])]
    by_cid = {c["capsule_id"]: c for c in caps}
    recorded = {m["index"]: m["outputs"] for m in man["steps"]}
    expected = {i: resolve(s, recorded) for i, s in steps.items()}
    expected_digests = {i: sha256(jcs(req)) if req else None for i, req in expected.items()}
    man_by_index = {m["index"]: m for m in man["steps"]}
    matches = {i: [c for c in caps if c["effect"]["request_digest"] == d] for i, d in expected_digests.items()}
    j["every step of the approved plan has exactly one capsule whose request is that step, with the arguments the plan "
      "resolves from the outputs recorded, and the manifest lists that capsule at that index"] = all(
        len(matches[i]) == 1 and i in man_by_index and man_by_index[i]["capsule_id"] == matches[i][0]["capsule_id"]
        and man_by_index[i]["request_digest"] == expected_digests[i] for i in steps)
    j["no capsule run under this decision is a step outside the plan"] = all(
        c["effect"]["request_digest"] in expected_digests.values() for c in caps)
    ordered = sorted(man["steps"], key=lambda m: m["index"])
    def follows(k):
        c = by_cid.get(ordered[k]["capsule_id"])
        p = by_cid.get(ordered[k - 1]["capsule_id"])
        return bool(c and p and c.get("chain", {}).get("parent_capsule_id") == p["capsule_id"]
                    and c["chain"].get("relation") == "follows" and c["timestamp"] >= p["timestamp"])
    j["the steps ran in plan order: the manifest lists them in it, each capsule follows the previous step's capsule, "
      "and the issuer's times do not go backwards"] = (
        [m["index"] for m in man["steps"]] == [m["index"] for m in ordered]
        and all(follows(k) for k in range(1, len(ordered))) and not by_cid.get(ordered[0]["capsule_id"], {}).get("chain")
        if ordered else False)
    def output_committed(i):
        c = by_cid.get(man_by_index.get(i, {}).get("capsule_id"))
        return bool(c and c["effect"]["response_digest"] == json_digest(man_by_index[i]["outputs"]))
    j["an argument resolved from an earlier step's output equals the output that step recorded, which its own "
      "capsule committed to (response_digest)"] = all(
        output_committed(k) for s in steps.values() for (k, _o) in refs_in(s["parameters"]).values())
    j["a capsule says a person disposed of a step only where every argument of that step was literal in the plan "
      "approved"] = all(
        matches[i][0]["disposition"]["human_disposed"] is (not refs_in(steps[i]["parameters"])) for i in steps if len(matches[i]) == 1)
    chain = context_chain(man["initial_context"], [(m["index"], m["outputs"]) for m in ordered])
    def context_ok(k):
        m = ordered[k]
        c = by_cid.get(m["capsule_id"])
        cited = [r["digest"] for r in (c or {}).get("references", [])
                 if r["type"] == CONTEXT_TYPE and r.get("citation_purpose") == "ran_under"]
        return bool(c) and m["context_before"] == chain[k] and m["context_after"] == chain[k + 1] and cited == [chain[k]] \
            and c["effect"]["response_digest"] == json_digest(m["outputs"])
    j["the context grows one step at a time: each state recomputes from the state before it and the outputs that "
      "step's capsule committed to, the manifest carries every state, and each capsule cites the state it ran under, "
      "the one just before it"] = (man["context_initial_digest"] == chain[0] and man["outcome"]["context_final"] == chain[-1]
                                   and all(context_ok(k) for k in range(len(ordered))))
    j["the specification names the plan policy by the digest of the policy held"] = \
        spec["policy_version"] == "sha256:" + sha256(policy_bytes)
    return j


def write(out, art):
    out.mkdir(parents=True, exist_ok=True)
    (out / "decision-record.json").write_bytes(art["record_bytes"])
    (out / "action-binding-attachment.json").write_bytes(art["attachment_bytes"])
    (out / "signatures-attachment.json").write_bytes(compact(art["sig_attachment"]))
    (out / "trust-policy.json").write_bytes(compact(art["trust"]))
    (out / "policy.json").write_bytes(policy_bytes)
    (out / "plan-run-manifest.json").write_bytes(art["manifest_bytes"])
    (out / "capsules.json").write_text(json.dumps(art["capsules"], ensure_ascii=False, indent=1) + "\n")


if __name__ == "__main__":
    parts = build()
    art = assemble(parts)
    write(HERE / "out", art)
    results = verify(art, parts)
    (HERE / "out" / "summary.json").write_text(json.dumps(results, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(results, ensure_ascii=False, indent=1))
    sys.exit(0 if results["all_verified"] else 1)
