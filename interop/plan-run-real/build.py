#!/usr/bin/env python3
"""Case 13b: the plan of ../plan-run (case 13), approved by a real person.

Everything of case 13 is kept: the three-step onboarding plan compiled by the assistant, the one DPS specification (the
plan, its steps and their hash) shown and approved once as a whole, the one request, recheck, attempt and result, the
issuer's seal, the three Agent Action Capsules chained in run order, the run manifest between them, the ten joins. One
thing changes: the person. The office manager's Ed25519 test signature is replaced by a signature Laurent Lemonnier made
with his own passkey (WebAuthn, ES256, iPhone, Face ID) on https://sign.pria.fr, over the exact DPS person_approval bytes
of this plan: decision DR-2026-1106, stage o0, outcome approved, the SHA-256 of the specification in
signed/action-specification.json and of the view in signed/review-view.txt, signed_at as the request fixed it. The
assertion (signature, authenticatorData, clientDataJSON) and the passkey's public key are pinned in signed/; nothing here
can produce another one.

The run is rebuilt around that signature: A1 carries those specification bytes, the review stage that view's digest, the
approval stage that moment; every other moment of case 13 (the proposal, the review, the request, the three steps, the
result, the seal, the record's closing) keeps its distance to the approval and is laid around it, before the
specification's valid_until (2026-11-09T12:00:00Z, fixed before signing so the plan could be approved later than the
day it was compiled on). The Standard's reference check (extensions/signatures) verifies the passkey signature over
authenticatorData || SHA-256(client data): the challenge is the SHA-256 of the signed bytes it rebuilt from A1, the origin
is the policy's, the relying party hash is sign.pria.fr's, UP and UV are set, the key is in its validity, the holder is the
actor o0 names. The capsule library (agent-action-capsule 0.16.0) verifies the three capsules as in case 13.

Still synthetic, and said so in every file: the brokerage, the client, the assistant, the executor and its effects, the
issuer's seal (Ed25519 test key), every moment other than the signature's. Deterministic output once signed/ is fixed.

  build.py prepare     writes the two files to sign (the specification bytes and the view, exactly as this case renders
                       them) and prints the sign.py command that creates the signing request; creates nothing else
  build.py             once signed/ holds person-approval.json and passkey.json: builds, verifies, writes out/

assemble() below is case 13's assemble with the person's fields, the approval's moment and the signature taken from
signed/ instead of the module's test key; every builder it calls (plan hash, references, resolution, view, context chain,
capsule shape, joins, checks, writer) is imported from ../plan-run/build.py. verify() records that, run with case 13's
person and case 13's clock, this assemble yields byte for byte the documents of case 13 (pinned_inputs).
"""
import base64
import copy
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import sys
import unicodedata

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

HERE = pathlib.Path(__file__).resolve().parent
INTEROP = HERE.parent
SIGNED = HERE / "signed"
SIGN_DIR = pathlib.Path(os.environ.get("SIGN_DIR") or HERE / "to-sign")   # prepare only: where sign.py reads the files to sign


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


B = load("plan_run_build", INTEROP / "plan-run" / "build.py")        # case 13, whole: builders, joins, checks, writer
SIG, AB = B.SIG, B.AB
sha256, compact, jcs, b64, json_digest = B.sha256, B.compact, B.jcs, B.b64, B.json_digest

DECISION_ID, STAGE_ID = "DR-2026-1106", "o0"                         # case 13's; fixed before signing, named in the request
VALID_UNTIL = "2026-11-09T12:00:00Z"                                 # case 13 had 7 November 09:25Z: moved so the plan could be signed later
HOLDER, DISPLAY, KEY_REF = "laurent-lemonnier", "Laurent Lemonnier", "laurent-passkey-1"
RP_ID, ORIGINS = "sign.pria.fr", ["https://sign.pria.fr"]
METHOD = "WebAuthn-ES256 passkey assertion (sign.pria.fr) over the DPS person_approval assertion of this plan"
METHOD_STAGE = "WebAuthn-ES256 passkey assertion (sign.pria.fr) over the DPS person_approval assertion"


# ---------------------------------------------------------------- the bytes to sign: the specification and the view as case 13 renders them

def spec_and_view():
    """The exact specification bytes and the review view of this plan: case 13's build() with valid_until moved."""
    parts = B.build()
    parts["spec"]["valid_until"] = VALID_UNTIL
    spec_bytes = compact(parts["spec"])
    return parts, spec_bytes, B.view_for_plan(parts["spec"])


# the view safety rule of sign.py check-view (draft-schrock-ep-presentation-binding-01, section 2): a value that could
# display otherwise than its bytes is refused, never rewritten
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
INVISIBLE = {0x00AD, 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062,
             0x2063, 0x2064, 0x3164, 0xFEFF, 0xFFA0}
SCRIPTS = ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE")


def view_unsafe_reasons(view):
    reasons = []
    if unicodedata.normalize("NFC", view) != view:
        reasons.append("view_not_nfc")
    for n, line in enumerate(view.split("\n"), 1):
        for ch in line:
            cp = ord(ch)
            if cp in BIDI:
                reasons.append(f"line_{n}_bidi_control:U+{cp:04X}")
            elif cp in INVISIBLE or unicodedata.category(ch) == "Cf":
                reasons.append(f"line_{n}_invisible_or_format:U+{cp:04X}")
            elif unicodedata.category(ch) in ("Cc", "Cs", "Co", "Cn") or cp in (0x2028, 0x2029):
                reasons.append(f"line_{n}_control_or_unassigned:U+{cp:04X}")
        for word in re.findall(r"\w+", line):
            scripts = {s for s in (next((s for s in SCRIPTS if unicodedata.name(c, "").startswith(s + " ")), None) for c in word) if s}
            if len(scripts) > 1:
                reasons.append(f"line_{n}_mixed_scripts:{'+'.join(sorted(scripts))}")
    return sorted(set(reasons))


def prepare():
    _parts, spec_bytes, view = spec_and_view()
    reasons = view_unsafe_reasons(view.decode("utf-8"))
    if reasons:
        sys.exit("the view cannot be shown safely, nothing written: " + ", ".join(reasons))
    for d in (SIGN_DIR, SIGNED):
        d.mkdir(parents=True, exist_ok=True)
        (d / "action-specification.json").write_bytes(spec_bytes)
        (d / "review-view.txt").write_bytes(view)
    title = "Approuver : plan onboarding_client 1.0.0 pour C-4471 (cas 13, plan-run-real)"
    lines = view.count(b"\n")
    print(f"specification: {len(spec_bytes)} bytes, sha256 {sha256(spec_bytes)}")
    print(f"view: {len(view)} bytes, {lines} lines, sha256 {sha256(view)}, safe (no bidi, format, control or mixed-script character; NFC)")
    print(f"written to {SIGN_DIR}/ and {SIGNED}/ (action-specification.json, review-view.txt)")
    print(f"decision {DECISION_ID}, stage {STAGE_ID}, valid_until {VALID_UNTIL}; the approval's moment will be the signature's signed_at")
    print("\nto create the signing request (main session, not here):\n")
    print(f'  (in the signing tool\'s directory) python3 sign.py request-from-spec {SIGN_DIR}/action-specification.json '
          f'{SIGN_DIR}/review-view.txt {DECISION_ID} {STAGE_ID} "{title}" --minutes 180')
    print("\nthen, once signed: pin the assertion and the passkey's public part into signed/ (person-approval.json, passkey.json,"
          " SHA256SUMS; pin-signed.py <request id>, kept with the signing tool) and run build.py and negatives.py")


# ---------------------------------------------------------------- the real part (read only when signed/ is complete)

def signed_inputs():
    missing = [n for n in ("action-specification.json", "review-view.txt", "person-approval.json", "passkey.json") if not (SIGNED / n).exists()]
    if missing:
        sys.exit(f"signed/ is not complete ({', '.join(missing)} missing): run `build.py prepare`, sign, pin, then build")
    spec_bytes = (SIGNED / "action-specification.json").read_bytes()
    view = (SIGNED / "review-view.txt").read_bytes()
    approval = json.loads((SIGNED / "person-approval.json").read_text())
    passkey = json.loads((SIGNED / "passkey.json").read_text())
    _p, expected_spec, expected_view = spec_and_view()
    if spec_bytes != expected_spec or view != expected_view:
        sys.exit("signed/ does not hold the bytes this case renders: the plan, the view or valid_until changed since the request")
    for k, v in (("decision_id", DECISION_ID), ("stage_id", STAGE_ID), ("outcome", "approved"), ("shown_spec_digest", sha256(spec_bytes)),
                 ("approved_spec_digest", sha256(spec_bytes)), ("shown_view_digest", sha256(view))):
        if approval.get(k) != v:
            sys.exit(f"signed/person-approval.json: {k} is not this case's ({approval.get(k)!r} for {v!r})")
    return spec_bytes, view, approval, passkey


if len(sys.argv) > 1 and sys.argv[1] == "prepare":
    prepare()
    sys.exit(0)

SPEC_BYTES, VIEW_BYTES, APPROVAL, PASSKEY = signed_inputs()
SIGNED_AT = APPROVAL["signed_at"]
_T0 = datetime.datetime.strptime(SIGNED_AT, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc) - datetime.timedelta(minutes=25)


def at_real(minute, second=0):
    """Case 13's clock laid around the signature: case 13 approved at its minute 25; here minute 25 is signed_at, and
    every other moment keeps its distance to it (proposal -13 min, review -5, request +5, steps +5 to +6, seal +7, close +15)."""
    return (_T0 + datetime.timedelta(minutes=minute, seconds=second)).strftime("%Y-%m-%dT%H:%M:%SZ")


other_passkey = ec.derive_private_key(int.from_bytes(hashlib.sha256(b"dps-scitt-decision-layer plan-run-real: a P-256 key of nobody (test only)").digest(), "big"),
                                      ec.SECP256R1())
OTHER_POINT = other_passkey.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()


def passkey_entry(point_hex=None):
    """The trust policy's entry for the passkey, as sign.py and case 18b write it: role person, the 65-byte uncompressed
    P-256 point, validity from the enrolment, the relying party and the origins the Standard's check reads."""
    return {"key_ref": KEY_REF, "holder": HOLDER, "role": "person", "algorithm": "WebAuthn-ES256",
            "public_key_hex": point_hex or PASSKEY["public_key_hex"], "not_before": PASSKEY["enrolled_at"],
            "not_after": "2027-11-30T23:59:59Z", "identity_source_ref": f"urn:pria:sign:enrolment:{KEY_REF}",
            "webauthn": {"rp_id": RP_ID, "origins": ORIGINS}}


# ---------------------------------------------------------------- the person: case 13's (for the fidelity check) and the real one

def synthetic_sign(ps):
    ps["signature"] = {"algorithm": "Ed25519", "key_ref": B.OWNER_KEY_REF, "value_b64": ""}
    ps["signature"]["value_b64"] = b64(B.owner_key.sign(SIG.person_signed_bytes(ps)))
    return ps


SYNTHETIC = {"owner": B.OWNER, "key_ref": B.OWNER_KEY_REF, "display": "Office Manager One", "role": "Office manager",
             "employer": "Example Brokerage", "method": "Ed25519 signature over the DPS person_approval assertion of this plan",
             "method_stage": "Ed25519 signature over the DPS person_approval assertion",
             "attested": "I approved the plan as shown, as a whole, and I am the accountable owner of this decision.",
             "shown_view_ref": "urn:example:review-console:plan-0471", "at": B.at, "sign": synthetic_sign,
             "trust_key": {"key_ref": B.OWNER_KEY_REF, "holder": B.OWNER, "role": "person", "algorithm": "Ed25519",
                           "public_key_hex": B.raw_public(B.owner_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                           "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:people"}}


def real_sign(ps):
    """The pinned assertion attached to the person_approval the run states. No key is held here: when the run's fields
    are not the ones signed, the Standard's check says so (the challenge is the SHA-256 of the signed bytes)."""
    ps["signature"] = dict(APPROVAL["signature"])
    return ps


REAL = {"owner": HOLDER, "key_ref": KEY_REF, "display": DISPLAY, "role": "Office manager (for this case)",
        "employer": "Example Brokerage (synthetic)", "method": METHOD, "method_stage": METHOD_STAGE,
        "attested": "I read the plan and the view shown on sign.pria.fr, approved the plan as shown, as a whole, with my passkey, and I "
                    "am the accountable owner of this decision. The brokerage, the client, the assistant, the executor and its effects "
                    "are synthetic; the approval is mine.",
        "shown_view_ref": "https://sign.pria.fr/approve.html#" + PASSKEY["assertion_request_id"], "at": at_real, "sign": real_sign,
        "trust_key": passkey_entry()}


def build():
    """Case 13's parts, valid_until moved, and the knobs of the failing cases that touch the real thing."""
    p, _s, _v = spec_and_view()
    p.update({"decision_id": DECISION_ID,       # the record the approval names (R10 moves the assertion to another)
              "run_minute": 30,                 # case 13's clock: the request at minute 30, the approval at 25 (R5: 20)
              "view_shown": None,               # the view the review stage and the approval say was shown (R9: another)
              "trust_point": "enrolled",        # enrolled | other (the policy binds laurent-passkey-1 to another P-256 key)
              "approver_signature": "real",     # real | case13_test_key | absent
              "tamper_ps": None})               # function over the person_approval before it is attached
    return p


def assemble(b, person=None, extend=None):
    """Case 13's assemble (../plan-run/build.py), the person taken from `person`: the same bytes and documents in the
    same order (record, capsules, manifest, attachment, signatures); nothing else differs. Read side by side with it."""
    P = person or REAL
    at = P["at"]
    spec = b["spec"]
    spec_bytes = compact(spec)
    spec_digest = sha256(spec_bytes)
    view = b.get("view_shown") or B.view_for_plan(spec)
    record = json.loads(B.TEMPLATE.read_bytes())
    did = b.get("decision_id", DECISION_ID)
    record.update({
        "decision_id": did, "created_at": at(12), "charter_id": "CH-EXAMPLE-ONBOARDING-1",
        "record_type": "decision", "record_state": "closed", "dispatch_mode": "mode-1-with-embedded-mode-2-summary",
        "altitude": "individual-professional", "decision_class": "client-onboarding",
        "consent_posture": {"posture_class": "the client's brief, given for onboarding; no other data read"},
        "success_criteria": ["The onboarding document, the CRM record and the team message exist and agree.",
                             "No step runs outside the plan shown."],
        "assumptions_depended_on": ["The client brief C-4471 v3 is the one the client confirmed."],
        "accountable_owner": {"full_name": P["display"], "role": P["role"], "employer": P["employer"]},
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
        "affirmation_record": {"timestamp": at(25), "actor_identity": P["owner"], "method": P["method"]},
        "accountable_owner_signoff": {"signed_by": P["owner"], "signed_at": at(40)},
        "closed_at": at(40), "record_location": f"urn:example:decision-records:{did}",
        "drafting_authority": {"deployer_role_pointer": "urn:example:role:onboarding-drafting",
                               "system_name": "onboarding-assistant", "version": "3"},
        "review_log": [{"reviewer": P["owner"], "reviewed_at": at(25), "outcome": "approved"}],
    })
    record["mode_classification_attestation"].update({
        "attestor_full_name": P["display"], "attestor_role_title": P["role"],
        "attestor_employer": P["employer"], "attestation_timestamp": at(40), "attestor_capacity": "employee",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 "
                                   "summary under charter CH-EXAMPLE-ONBOARDING-1: the onboarding assistant "
                                   "(onboarding-assistant, version 3) compiled the plan from the use case and the brief; " + P["attested"]})
    record["seal_hash"] = "0" * 64
    record["seal_hash"] = sha256(compact(record))
    record_bytes = compact(record)
    run_minute = b.get("run_minute", 30)
    steps = {s["index"]: s for s in spec["parameters"]["steps"]}
    recorded = {i: o for i, o in enumerate(b["recorded_outputs"])}
    capsules, manifest_steps, prev = [], [], None
    ctx = B.context_chain(B.INITIAL_CONTEXT, [])[0]
    for n, i in enumerate(b["order"]):
        request = b["executed"].get(i) or B.resolve(steps[i], recorded)
        m, s = b["step_at"][n]
        m += run_minute - 30
        ctx_before, ctx = ctx, B.next_context(ctx, i, recorded[i])
        cap = {"spec_version": "0.12", "format_version": "4", "canonicalization_id": "jcs",
               "action_id": f"{B.RUN_ID}:step:{i}", "action_type": "decide", "operator": "example broker runtime",
               "developer": "example", "timestamp": at(m, s), "domain": "client_onboarding",
               "disposition": {"decision": "accept", "approver": "human", "human_disposed": not B.refs_in(steps[i]["parameters"]),
                               "authority": B.POLICY_REF + "#o0", "verdict_class": "executed"},
               "effect": {"status": "confirmed", "type": "org.example." + steps[i]["operation"].replace(".", "_"),
                          "request_digest": sha256(jcs(request)), "response_digest": json_digest(b["observed_outputs"][i]),
                          "external_ref": next(iter(b["observed_outputs"][i].values())),
                          "irreversibility_class": B.IRREVERSIBILITY[steps[i]["operation"]], "effect_attestation": "runtime_claimed"},
               "references": [{"type": f"{B.NS}.decision_record", "digest_alg": "SHA-256", "digest": record["seal_hash"],
                               "citation_purpose": "ran_under"},
                              {"type": B.CONTEXT_TYPE, "digest_alg": "SHA-256", "digest": ctx_before, "citation_purpose": "ran_under"}]}
        if prev:
            cap["chain"] = {"parent_capsule_id": prev, "relation": "follows"}
        cap["capsule_id"] = B.CAP_CANON.compute_capsule_id(cap) if B.CAP_CANON else sha256(jcs(cap))
        prev = cap["capsule_id"]
        capsules.append(cap)
        manifest_steps.append({"index": i, "operation": steps[i]["operation"], "target": steps[i]["target"],
                               "request_digest": cap["effect"]["request_digest"], "capsule_id": cap["capsule_id"],
                               "outputs": recorded[i], "context_before": ctx_before, "context_after": ctx,
                               "status": "succeeded", "started_at": at(m, s), "ended_at": at(m, s + 9)})
    manifest = {"profile": B.MANIFEST_PROFILE, "profile_version": B.MANIFEST_VERSION, "run_id": B.RUN_ID, "decision_id": did,
                "approval_stage_ref": "o0", "spec_digest": spec_digest, "plan_hash": spec["parameters"]["plan_hash"],
                "usecase_ref": B.USECASE_REF, "requested_by": "urn:example:service:onboarding-routine",
                "initial_context": B.INITIAL_CONTEXT, "context_initial_digest": B.context_chain(B.INITIAL_CONTEXT, [])[0],
                "steps": manifest_steps, "outcome": {"status": "completed", "ended_at": at(run_minute + 1, 14), "context_final": ctx}}
    if extend:
        extend(b, record, capsules, manifest)
    manifest_bytes = compact(manifest)
    stages = [
        {"stage_id": "p0", "kind": "proposal", "at": at(12), "origin": "ai", "spec_digest": spec_digest,
         "deployer_role_pointer": "urn:example:role:onboarding-drafting", "system_name": "onboarding-assistant", "version": "3"},
        {"stage_id": "v0", "kind": "review", "at": at(20), "reviewer_ref": P["owner"], "shown_spec_digest": spec_digest,
         "proposal_ref": "p0", "shown_view_ref": P["shown_view_ref"], "shown_view_digest": sha256(view)},
        {"stage_id": "o0", "kind": "outcome", "at": at(25), "review_ref": "v0", "outcome": "approved", "actor_ref": P["owner"],
         "method": P["method_stage"], "approved_spec_digest": spec_digest,
         "request_limit": 1, "authority": {"authority_ref": B.POLICY_REF},
         "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": at(25), "text_ref": "urn:example:rationale:plan-0471"},
         "core_ref": {"field": "review_log", "index": 0}},
    ]
    for k in range(1 + b["extra_requests"]):
        t, sfx = run_minute * 60 + 120 * k, str(k)
        stages += [
            {"stage_id": f"q{sfx}", "kind": "request", "at": at(0, t), "request_id": B.RUN_ID if k == 0 else f"{B.RUN_ID}-again-{k}",
             "authorised_by": "o0", "spec_digest": spec_digest, "requested_by": "urn:example:service:onboarding-routine"},
            {"stage_id": f"c{sfx}", "kind": "recheck", "at": at(0, t + 5), "request_ref": f"q{sfx}", "result": "authorised",
             "authority_source_ref": B.POLICY_REF},
            {"stage_id": f"x{sfx}", "kind": "attempt", "at": at(0, t + 10), "request_ref": f"q{sfx}", "recheck_ref": f"c{sfx}",
             "spec_digest": spec_digest, "executor_ref": B.EXECUTOR, "trace_refs": [B.RUN_ID]},
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
    attachment["issuer_signature"] = {"algorithm": "Ed25519", "key_ref": B.ISSUER_KEY_REF,
                                      "signed_bytes_ref": "dps-signatures 0.2.0 organisation_seal", "sealed_at": at(32),
                                      "value_b64": "A" * 88}
    attachment["issuer_signature"]["value_b64"] = b64(B.issuer_key.sign(SIG.seal_signed_bytes(AB.seal_assertion(attachment))))
    ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval", "decision_id": did,
          "stage_id": "o0", "outcome": "approved", "shown_spec_digest": spec_digest, "shown_view_digest": sha256(view),
          "approved_spec_digest": spec_digest, "signed_at": at(25)}
    mode = b.get("approver_signature", "real")
    if mode == "case13_test_key":
        ps = synthetic_sign(ps)
    else:
        ps = P["sign"](ps)
    if b.get("tamper_ps"):
        ps = b["tamper_ps"](ps)
    sig_attachment = {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [] if mode == "absent" else [ps]}
    trust_key = dict(P["trust_key"])
    if b.get("trust_point") == "other":
        trust_key["public_key_hex"] = OTHER_POINT
    trust = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0", "policy_ref": "urn:example:trust-policy:verifier-1",
             "tsas": [], "checkpoint_sources": [],
             "keys": [trust_key,
                      {"key_ref": B.ISSUER_KEY_REF, "holder": B.ISSUER, "role": "organisation", "algorithm": "Ed25519",
                       "public_key_hex": B.raw_public(B.issuer_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                       "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:organisations"}]}
    return {"record": record, "record_bytes": record_bytes, "attachment": attachment, "attachment_bytes": compact(attachment),
            "sig_attachment": sig_attachment, "trust": trust, "capsules": capsules, "manifest": manifest,
            "manifest_bytes": manifest_bytes, "spec_bytes": spec_bytes, "view": view}


def assemble_is_case_13s():
    """With case 13's person and case 13's clock, this assemble writes case 13's documents, byte for byte."""
    ours, theirs = assemble(B.build(), SYNTHETIC), B.assemble(B.build())
    return all(compact(ours[k]) == compact(theirs[k]) for k in ("record", "attachment", "sig_attachment", "trust", "capsules", "manifest")) \
        and all(ours[k] == theirs[k] for k in ("record_bytes", "attachment_bytes", "manifest_bytes"))


def real_approval_report(art):
    """The Standard's reference check of the person's signature, read in full (as case 18b reads it): every dimension,
    the authenticator's facts (UP, UV, cross-origin), what the client data says, and that the challenge is the signed
    bytes' digest."""
    _pol, persons, _s, _t = SIG.run_context({"attachment": art["sig_attachment"], "export": None, "policy": art["trust"],
                                             "action_binding": {art["record"]["decision_id"]: art["attachment"]}})
    if not persons:
        return {"status": "absent", "findings": ["no person signature in the attachment"]}
    p = persons[0]
    ps = art["sig_attachment"]["person_signatures"][0]
    out = {"status": p["status"], "key_ref": p["key_ref"], "algorithm": ps["signature"]["algorithm"],
           **{d: p[d]["status"] for d in ("signature", "subject", "key_state", "identity")},
           "authenticator": p.get("authenticator"), "identity_holder": p["identity"].get("holder"), "identity_issuer_named": p["identity"].get("issuer_named"),
           "key_state_time": p["key_state"].get("time"), "key_state_basis": p["key_state"].get("time_basis"),
           "findings": [f for d in ("signature", "subject", "key_state", "identity") for f in p[d].get("findings", [])]}
    try:
        client = json.loads(base64.b64decode(ps["signature"]["client_data_json_b64"], validate=True))
        auth = base64.b64decode(ps["signature"]["authenticator_data_b64"], validate=True)
        out["client_data"] = {k: client.get(k) for k in ("type", "origin", "crossOrigin")}
        out["challenge_is_sha256_of_signed_bytes"] = (base64.urlsafe_b64decode(client["challenge"] + "==") == hashlib.sha256(SIG.person_signed_bytes(ps)).digest())
        out["rp_id_hash_is"] = RP_ID if auth[:32] == hashlib.sha256(RP_ID.encode()).digest() else "not " + RP_ID
        out["flags_byte"] = f"0x{auth[32]:02x}"
        out["signature_counter"] = int.from_bytes(auth[33:37], "big")
    except Exception as e:                                   # noqa: BLE001  (an Ed25519 or tampered signature has no client data)
        out["client_data"] = f"unreadable: {e}"
    out["signed_bytes_sha256"] = sha256(SIG.person_signed_bytes(ps))
    out["signature_value_sha256"] = sha256(base64.b64decode(ps["signature"]["value_b64"]))
    return out


def verify(art, parts=None):
    r = B.verify(art, parts)
    r["real_approval"] = real_approval_report(art)
    o0 = next((s for s in art["attachment"]["stages"] if s["stage_id"] == "o0"), {})
    r["pinned_inputs"] = {"specification_bytes_are_the_signed_ones": art["spec_bytes"] == SPEC_BYTES,
                          "view_bytes_are_the_signed_ones": art["view"] == VIEW_BYTES,
                          "person_approval_is_the_pinned_one": art["sig_attachment"]["person_signatures"][:1] == [APPROVAL],
                          "o0_at_is_signed_at": o0.get("at") == SIGNED_AT,
                          "assemble_reproduces_case_13": assemble_is_case_13s()}
    r["all_verified"] = (r["all_verified"] and r["real_approval"]["status"] == "verified"
                         and r["real_approval"].get("challenge_is_sha256_of_signed_bytes") is True
                         and r["real_approval"]["authenticator"] == {"user_present": True, "user_verified": True, "cross_origin": False}
                         and all(r["pinned_inputs"].values()))
    return r


def write(out, art, r=None):
    B.write(out, art)
    (out / "passkey.json").write_text(json.dumps(PASSKEY, indent=1) + "\n")
    (out / "keys.json").write_text(json.dumps({
        "approver_passkey_key_ref": KEY_REF, "approver_passkey_p256_uncompressed_point_hex": art["trust"]["keys"][0]["public_key_hex"],
        "issuer_ed25519_pub": B.raw_public(B.issuer_key).hex(),
        "note": "the passkey is Laurent Lemonnier's, enrolled on sign.pria.fr on " + PASSKEY["enrolled_at"] + " (public key only); "
                "the issuer's key is a test key from a fixed seed, never for anything real"}, indent=1) + "\n")
    if r is not None:
        (out / "summary.json").write_text(json.dumps(r, ensure_ascii=False, indent=1, default=str) + "\n")


if __name__ == "__main__":
    parts = build()
    art = assemble(parts)
    results = verify(art, parts)
    write(HERE / "out", art, results)
    print(json.dumps(results, ensure_ascii=False, indent=1, default=str))
    sys.exit(0 if results["all_verified"] else 1)
