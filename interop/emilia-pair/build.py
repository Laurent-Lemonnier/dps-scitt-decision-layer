#!/usr/bin/env python3
"""A pair, at Iman Schrock's request (1 November 2026): an EP-AUTHORIZATION-BUNDLE-v1 whose signed Authorization
Contexts carry an authorization_binding that names a DPS decision by its native bytes, and, later, a DPS action-binding
attachment that cites the complete EP Trust Receipt by SHA-256 over its JCS bytes.

The order fixes the bytes so that no digest is circular:
  1. the DPS decision record and the action-binding attachment A1 as issued at the approval (proposal, review, the
     person's approval of one specification), sealed by the issuer, the person's approval signed;
  2. the EP bundle: two approvers' Authorization Contexts, each carrying the same authorization_binding (profile
     DPS-ACTION-BINDING-v1: the record by its seal digest, A1 by SHA-256 over its bytes as issued, the outcome stage, the
     approved specification's digest, the EP action_hash), signed (Ed25519, class B, over the 32 raw bytes of the
     context hash, as the published vector shows);
  3. the EP Trust Receipt of section 7.2, synthetic: its log_proof is a one-leaf log built here, said to be;
  4. the later DPS attachment A2: A1's stages unchanged, then request, recheck, attempt and result, the recheck naming
     the receipt by base_receipt_digest (section 8: SHA-256 over the JCS of the complete, unchanged receipt), with its
     receipt_id and action_hash, sealed by the issuer.

What each side checks is written from its text: the EP bundle from draft-schrock-ep-authorization-receipts-13
sections 3, 4, 5.3, 6, 6.1, 6.2 and 7.2, 8; the DPS side by the Standard's reference checks (action binding 0.3.0,
signatures 0.2.0). The binding profile is this repository's (provisional), defined in README.md: its byte scope, its
mapping from the DPS specification to the EP Action Object, and its verification. Neither reference alone establishes
execution or its ordering.
"""
import base64
import copy
import importlib.util
import json
import pathlib
import sys

from cryptography.hazmat.primitives import serialization

HERE = pathlib.Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PR = load("plan_run_build", HERE.parent / "plan-run" / "build.py")
sha256, compact, jcs, b64, at = PR.sha256, PR.compact, PR.jcs, PR.b64, PR.at
AB, SIG, REPO, key_from_seed, raw_public = PR.AB, PR.SIG, PR.REPO, PR.key_from_seed, PR.raw_public

PROFILE = "DPS-ACTION-BINDING-v1"          # provisional, this repository's binding profile (README.md)
OWNER, OWNER_KEY_REF = "treasury-controller-1", "treasury-controller-1-key-1"
ISSUER, ISSUER_KEY_REF = "Example Payments Ltd", "example-payments-issuer-key-1"
owner_key = key_from_seed("dps-scitt-decision-layer emilia-pair: treasury controller key (test only)")
issuer_key = key_from_seed("dps-scitt-decision-layer emilia-pair: issuer seal key (test only)")
EP_APPROVERS = [("ep:approver:controller", "ep:key:controller#1",
                 key_from_seed("dps-scitt-decision-layer emilia-pair: EP approver controller (test only)")),
                ("ep:approver:treasurer", "ep:key:treasurer#1",
                 key_from_seed("dps-scitt-decision-layer emilia-pair: EP approver treasurer (test only)"))]
OUTSIDER = ("ep:approver:outsider", "ep:key:outsider#1", key_from_seed("dps-scitt-decision-layer emilia-pair: outsider (test only)"))
log_key = key_from_seed("dps-scitt-decision-layer emilia-pair: synthetic log key (test only)")
AUDIENCE = "https://payments.example.com"
AUTH_INSTANCE = "b64u:" + base64.urlsafe_b64encode(PR.hashlib.sha256(b"emilia-pair authorization instance").digest()[:16]).decode().rstrip("=")
NOW = "2026-11-06T09:56:00Z"      # the relying party's clock at the pre-execution check: after the signoffs, before the request
RUN = "urn:example:payment-run:2026-11-06-7"
EXECUTOR = "urn:example:executor:payments-gateway"

POLICY = {"policy_id": "ep:policy:releases-over-100@v3", "rule": "two approvers: controller and treasurer; the DPS approval of the exact specification first"}
POLICY_HASH = "sha256:" + sha256(jcs(POLICY))
DPS_POLICY_REF = "urn:example:policy:payment-releases#v3"
DPS_POLICY_VERSION = "sha256:" + sha256(compact({"policy_id": "urn:example:policy:payment-releases", "version": "v3",
                                                  "approver": OWNER, "single_use": True}))


def spki_b64u(k):
    der = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.urlsafe_b64encode(der).decode().rstrip("=")


def hx(b):
    return "sha256:" + sha256(b)


# ---------------------------------------------------------------- the binding profile: the mapping and the binding object

ACTION_REQUIRED = ("ep_version", "action_type", "target", "parameters", "initiator", "policy_id", "requested_at")   # section 3
CONTEXT_REQUIRED = ("ep_version", "context_type", "action_hash", "policy_id", "policy_hash", "initiator", "authorization_instance",
                    "audience", "approver", "approver_index", "required_approvals", "nonce", "issued_at", "expires_at")    # section 4
SPEC_PROJECTED = ("operation", "target", "parameters")   # what the inverse reconstructs; the rest stays under approved_spec_digest


def action_from_spec(spec, policy_id, requested_at):
    """DPS-ACTION-BINDING-v1 mapping, specification -> EP Action Object (section 3's minimum members, all present):
    action_type = operation; initiator = parameters.initiator; parameters = the specification's other parameters,
    unchanged; target = {system, resource} split from the specification's target at its first '/'; ep_version = 1.0;
    policy_id = the relying party's pinned EP policy identifier (never a value made up to fill the shape);
    requested_at = the time of A1's proposal stage, in the bytes the binding names. The inverse, action_back(),
    reconstructs operation, target and parameters exactly; input_version_refs, policy_version and valid_until stay
    outside that projection, bound by approved_spec_digest: this is not an inverse of the entire specification."""
    p = dict(spec["parameters"])
    initiator = p.pop("initiator")
    system, resource = spec["target"].split("/", 1)
    return {"ep_version": "1.0", "action_type": spec["operation"], "target": {"system": system, "resource": resource},
            "parameters": p, "initiator": initiator, "policy_id": policy_id, "requested_at": requested_at}


def action_back(action):
    return {"operation": action["action_type"], "target": action["target"]["system"] + "/" + action["target"]["resource"],
            "parameters": dict(action["parameters"], initiator=action["initiator"])}


def schema_reasons(b):
    """Presence and form of the members sections 3 and 4 make minimum, checked before anything is read from them: a
    context re-signed validly without one of them is refused here, not accepted (Iman Schrock, 4 November 2026)."""
    r = []
    a = b.get("action")
    if not isinstance(a, dict):
        return ["action_malformed"]
    for m in ACTION_REQUIRED:
        if m not in a:
            r.append(f"action_missing:{m}")
    if "ep_version" in a and a["ep_version"] != "1.0":
        r.append("action_ep_version_unsupported")
    if "target" in a and (not isinstance(a["target"], dict) or set(a["target"]) != {"system", "resource"}):
        r.append("action_target_malformed")
    ctxs = b.get("contexts")
    if not isinstance(ctxs, list) or not ctxs:
        return r + ["contexts_malformed"]
    for i, c in enumerate(ctxs):
        for m in CONTEXT_REQUIRED:
            if m not in c:
                r.append(f"context_{i}_missing:{m}")
        if c.get("ep_version", "1.0") != "1.0" or c.get("context_type", "ep.signoff.v1") != "ep.signoff.v1":
            r.append(f"context_{i}_type_or_version_unsupported")
    if not r:
        if sorted(c["approver_index"] for c in ctxs) != list(range(1, len(ctxs) + 1)):
            r.append("context_approver_index_not_1_to_n")
        if any(c["initiator"] != a["initiator"] for c in ctxs):
            r.append("context_initiator_not_the_actions")
        if any(c["policy_id"] != a["policy_id"] for c in ctxs):
            r.append("context_policy_id_not_the_actions")
    return r


def binding_of(record, a1_bytes, outcome_stage_id, spec_digest, action_hash):
    return {"profile": PROFILE, "decision_record_digest": "sha256:" + record["seal_hash"],
            "attachment_digest": hx(a1_bytes), "outcome_stage_id": outcome_stage_id,
            "approved_spec_digest": "sha256:" + spec_digest, "action_digest": action_hash}


# ---------------------------------------------------------------- the build

def build():
    """Every input as data, so that a failing case can change one thing before the bytes are fixed."""
    spec = {"operation": "payment.release.1", "target": "payments.example/release-queue",
            "parameters": {"initiator": "ep:entity:agent-recon-7", "amount_minor": 12550, "currency": "USD", "payee": "merchant:7"},
            "input_version_refs": ["urn:example:invoice:INV-2026-0912"], "policy_version": DPS_POLICY_VERSION,
            "valid_until": "2026-11-06T12:00:00Z"}
    return {"spec": spec, "ep_action_override": None, "binding_override": None, "binding_on": [True, True],
            "signers": [EP_APPROVERS[0], EP_APPROVERS[1]], "receipt_reference_in": "A2", "a2_spec_override": None,
            "action_policy_id": None, "action_requested_at": None, "context_drop": []}


def dps_record():
    record = json.loads(PR.TEMPLATE.read_bytes())
    record.update({
        "decision_id": "DR-2026-11070", "created_at": at(40), "charter_id": "CH-EXAMPLE-PAYMENTS-1",
        "decision_statement": "Release payment of 125.50 USD to merchant:7 against invoice INV-2026-0912, under the releases policy v3.",
        "context_at_decision": "The reconciliation agent proposed the release; the controller reviewed the call as rendered.",
        "options_considered": ["Release now (chosen): invoice matched, amount under the controller's limit.",
                               "Hold for the month-end run: the merchant waits eleven days.",
                               "Reject: no ground, the invoice is matched."],
        "required_inputs_used": ["invoice INV-2026-0912", "reconciliation report 2026-11-06"],
        "assumptions_depended_on": ["The payee merchant:7 is the invoice's payee."],
        "success_criteria": ["The payment is released once, for the amount approved."],
        "re_decision_trigger": "A second release request for the same invoice.",
        "accountable_owner": {"full_name": "Treasury Controller One", "role": "Treasury controller", "employer": ISSUER},
        "affirmation_record": {"timestamp": at(45), "actor_identity": OWNER,
                               "method": "Ed25519 signature over the DPS person_approval assertion"},
        "accountable_owner_signoff": {"signed_by": OWNER, "signed_at": at(46)},
        "review_log": [{"reviewer": OWNER, "reviewed_at": at(45), "outcome": "approved"}],
        "closed_at": at(46), "record_location": "urn:example:decision-records:DR-2026-11070", "supersedes": None,
        "drafting_authority": {"deployer_role_pointer": "urn:example:role:reconciliation-drafting",
                               "system_name": "reconciliation-agent", "version": "7"},
    })
    record["mode_classification_attestation"].update({
        "attestor_full_name": "Treasury Controller One", "attestor_role_title": "Treasury controller",
        "attestor_employer": ISSUER, "attestation_timestamp": at(46), "attestor_capacity": "employee",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 summary "
                                   "under charter CH-EXAMPLE-PAYMENTS-1: the reconciliation agent proposed the release of "
                                   "invoice INV-2026-0912; I reviewed the call as rendered, approved it as shown, and I am "
                                   "accountable for this decision."})
    record["seal_hash"] = "0" * 64
    record["seal_hash"] = sha256(compact(record))
    return record


def seal(att, sealed_at):
    att["issuer_signature"] = {"algorithm": "Ed25519", "key_ref": ISSUER_KEY_REF,
                               "signed_bytes_ref": "dps-signatures 0.2.0 organisation_seal", "sealed_at": sealed_at, "value_b64": "A" * 88}
    att["issuer_signature"]["value_b64"] = b64(issuer_key.sign(SIG.seal_signed_bytes(AB.seal_assertion(att))))
    return att


def assemble(b):
    record = dps_record()
    did = record["decision_id"]
    spec = b["spec"]
    spec_bytes = compact(spec)
    sd = sha256(spec_bytes)
    view = (f"Release {spec['parameters']['amount_minor']} minor units {spec['parameters']['currency']} to "
            f"{spec['parameters']['payee']} ({spec['target']}), policy {DPS_POLICY_REF}\n").encode()
    spec_entry = {"spec_digest": sd, "representation": {"kind": "original_bytes", "media_type": "application/json"},
                  "content": {"availability": "available", "bytes_b64": b64(spec_bytes)},
                  "summary": {"operation": spec["operation"], "target": spec["target"], "policy_version": spec["policy_version"],
                              "input_version_refs": spec["input_version_refs"]}}
    head = [
        {"stage_id": "p0", "kind": "proposal", "at": at(40), "origin": "ai", "spec_digest": sd,
         "deployer_role_pointer": "urn:example:role:reconciliation-drafting", "system_name": "reconciliation-agent", "version": "7"},
        {"stage_id": "v0", "kind": "review", "at": at(43), "reviewer_ref": OWNER, "shown_spec_digest": sd, "proposal_ref": "p0",
         "shown_view_ref": "urn:example:review-console:release-7", "shown_view_digest": sha256(view)},
        {"stage_id": "o0", "kind": "outcome", "at": at(45), "review_ref": "v0", "outcome": "approved", "actor_ref": OWNER,
         "method": "Ed25519 signature over the DPS person_approval assertion", "approved_spec_digest": sd, "request_limit": 1,
         "authority": {"authority_ref": DPS_POLICY_REF},
         "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": at(45), "text_ref": "urn:example:rationale:release-7"},
         "core_ref": {"field": "review_log", "index": 0}}]
    a1 = seal({"profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": did,
               "action_specifications": [spec_entry], "stages": copy.deepcopy(head)}, at(46))
    a1_bytes = compact(a1)
    ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval", "decision_id": did,
          "stage_id": "o0", "outcome": "approved", "shown_spec_digest": sd, "shown_view_digest": sha256(view),
          "approved_spec_digest": sd, "signed_at": at(45), "signature": {"algorithm": "Ed25519", "key_ref": OWNER_KEY_REF, "value_b64": ""}}
    ps["signature"]["value_b64"] = b64(owner_key.sign(SIG.person_signed_bytes(ps)))
    sig_att = {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps]}
    trust = {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0", "policy_ref": "urn:example:trust-policy:payments-verifier",
             "tsas": [], "checkpoint_sources": [],
             "keys": [{"key_ref": OWNER_KEY_REF, "holder": OWNER, "role": "person", "algorithm": "Ed25519",
                       "public_key_hex": raw_public(owner_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                       "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:people"},
                      {"key_ref": ISSUER_KEY_REF, "holder": ISSUER, "role": "organisation", "algorithm": "Ed25519",
                       "public_key_hex": raw_public(issuer_key).hex(), "not_before": "2026-10-01T00:00:00Z",
                       "not_after": "2027-09-30T23:59:59Z", "identity_source_ref": "urn:example:directory:organisations"}]}
    # -- the EP side: the Action Object by the profile's mapping, the contexts with the binding, the signoffs
    action = b["ep_action_override"] or action_from_spec(spec, b["action_policy_id"] or POLICY["policy_id"],
                                                         b["action_requested_at"] or head[0]["at"])
    action_hash = hx(jcs(action))
    binding = b["binding_override"] or binding_of(record, a1_bytes, "o0", sd, action_hash)
    contexts = []
    for i, (approver, _, _) in enumerate(EP_APPROVERS):
        ctx = {"ep_version": "1.0", "context_type": "ep.signoff.v1", "action_hash": action_hash,
               "policy_id": action.get("policy_id", POLICY["policy_id"]),
               "policy_hash": POLICY_HASH, "initiator": action["initiator"], "authorization_instance": AUTH_INSTANCE,
               "audience": AUDIENCE, "approver": approver, "approver_index": i + 1, "required_approvals": 2,
               "nonce": "b64u:" + base64.urlsafe_b64encode(PR.hashlib.sha256(f"nonce {i}".encode()).digest()[:16]).decode().rstrip("="),
               "issued_at": at(50), "expires_at": at(65)}
        if b["binding_on"][i]:
            ctx["authorization_binding"] = copy.deepcopy(binding)
        for m in b["context_drop"]:          # a failing case: a required member left out, the context then signed validly
            ctx.pop(m, None)
        contexts.append(ctx)
    signoffs = []
    for ctx, (_, key_id, key) in zip(contexts, b["signers"]):
        ch = PR.hashlib.sha256(jcs(ctx)).digest()
        signoffs.append({"context_hash": "sha256:" + ch.hex(), "signature": base64.urlsafe_b64encode(key.sign(ch)).decode().rstrip("="),
                         "key_class": "B", "approver_key_id": key_id, "signed_at": at(55)})
    bundle = {"bundle_version": "EP-AUTHORIZATION-BUNDLE-v1", "bundle_id": "ep:authorization-bundle:release-7",
              "action": action, "action_hash": action_hash, "contexts": contexts, "signoffs": signoffs,
              "approver_key_proofs": [], "presentation_evidence": []}
    # -- the Trust Receipt (section 7.2), synthetic: a one-leaf log built here
    receipt = {"receipt_id": "ep:receipt:release-7", "action": action, "action_hash": action_hash, "contexts": contexts,
               "signoffs": signoffs, "consumption": {"nonce": AUTH_INSTANCE, "state": "committed", "committed_at": at(58)},
               "approver_key_proofs": []}
    leaf = PR.hashlib.sha256(b"\x00" + jcs(receipt)).digest()
    receipt["log_proof"] = {"leaf_index": 0, "inclusion_path": [],
                            "checkpoint": {"tree_size": 1, "root_hash": "sha256:" + leaf.hex(),
                                           "log_signature": base64.urlsafe_b64encode(log_key.sign(leaf)).decode().rstrip("="),
                                           "log_key_id": "ep:log:synthetic-1"}}
    base_receipt_digest = hx(jcs(receipt))
    # -- A2: A1's stages unchanged, then the execution, the recheck naming the receipt
    a2_spec = b["a2_spec_override"] or sd
    tail = [
        {"stage_id": "q0", "kind": "request", "at": at(60), "request_id": RUN, "authorised_by": "o0", "spec_digest": a2_spec,
         "requested_by": "urn:example:service:payment-routine"},
        {"stage_id": "c0", "kind": "recheck", "at": at(61), "request_ref": "q0", "result": "authorised",
         "authority_source_ref": f"ep:trust-receipt:{base_receipt_digest}",
         "detail": f"EP Trust Receipt {receipt['receipt_id']}, base_receipt_digest {base_receipt_digest}, action_hash {action_hash}"},
        {"stage_id": "x0", "kind": "attempt", "at": at(62), "request_ref": "q0", "recheck_ref": "c0", "spec_digest": a2_spec,
         "executor_ref": EXECUTOR, "trace_refs": [RUN, receipt["receipt_id"]]},
        {"stage_id": "r0", "kind": "result", "at": at(63), "attempt_ref": "x0", "observed": "succeeded",
         "basis": "executor_observation", "evidence_ref": "urn:example:payments:release-7:settled"}]
    a2 = seal({"profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": did,
               "action_specifications": [spec_entry], "stages": copy.deepcopy(head) + tail}, at(64))
    art = {"record": record, "record_bytes": compact(record), "a1": a1, "a1_bytes": a1_bytes, "a2": a2,
           "a2_bytes": compact(a2), "sig_attachment": sig_att, "trust": trust, "spec": spec, "bundle": bundle,
           "receipt": receipt, "view": view.decode()}
    if b["receipt_reference_in"] == "A1":
        # the reverse reference moved into the attachment the binding names: the binding then names bytes that
        # depend on a receipt that contains the binding; this build can only re-seal A1 after the fact
        art["a1"] = seal(dict(copy.deepcopy(a1), stages=copy.deepcopy(head) + [copy.deepcopy(tail[1]) | {"request_ref": "o0"}]), at(46))
        art["a1_bytes"] = compact(art["a1"])
    return art


# ---------------------------------------------------------------- verification, each side from its text, then the joins

NOT_YET = ("authorisation_recheck", "observed_results")   # an attachment as issued at the approval has no execution yet


def verify_dps(record_bytes, record, att, sig_att, trust, executed=True):
    """The DPS side natively, by the Standard's reference checks: every binding dimension, the issuer's seal, the
    person's approval under the verifier's trust policy. For the attachment as issued at the approval (executed=False),
    the recheck and the observed results are not checked, because there are none yet; every other dimension must hold."""
    out = {}
    ab = AB.check_attachment(att, record_bytes)
    out["dimensions"] = {d: ab[d][0] for d in PR.DIMENSIONS}
    rep = AB.reference_report([att], {record["decision_id"]: record_bytes}, trust, sig_att)
    out["issuer_seal"] = rep["results"][0]["issuer_signature"].get("status")
    _p, persons, _s, _t = SIG.run_context({"attachment": sig_att, "export": None, "policy": trust,
                                           "action_binding": {record["decision_id"]: att}})
    out["person_approvals_verified"] = sum(p["status"] == "verified" for p in persons)
    dims_ok = all(v == "verified" or (not executed and d in NOT_YET and v == "not_checked") for d, v in out["dimensions"].items())
    out["verified"] = dims_ok and out["issuer_seal"] == "verified" and out["person_approvals_verified"] == len(persons) >= 1
    return out


def b64u_dec(s):
    s = s.split(":", 1)[1] if s.startswith("b64u:") else s
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_bundle(art, pinned):
    """Section 6.2 of draft-schrock-ep-authorization-receipts-13, in its order, for this case's inputs. Returns
    (result, reasons): SATISFIED, REFUSE or INDETERMINATE. Step 9 (directory, revocation, presentation, delegation
    evidence) is not required by the pinned policy here; step 5's directory proofs likewise (empty arrays allowed)."""
    b = art["bundle"]
    reasons = []
    members = {"bundle_version", "bundle_id", "action", "action_hash", "contexts", "signoffs", "approver_key_proofs", "presentation_evidence"}
    if set(b) != members or b["bundle_version"] != "EP-AUTHORIZATION-BUNDLE-v1":                                    # 1
        return "REFUSE", ["bundle_malformed"]
    schema = schema_reasons(b)                                                                                         # 1, schema
    if schema:
        return "REFUSE", schema
    if hx(jcs(b["action"])) != b["action_hash"]:                                                                       # 2
        reasons.append("action_hash_mismatch")
    ctxs = b["contexts"]
    chs = [hx(jcs(c)) for c in ctxs]                                                                                    # 3
    if any(c["action_hash"] != b["action_hash"] for c in ctxs):
        reasons.append("context_action_hash_mismatch")
    for m in ("policy_hash", "audience", "authorization_instance"):
        if len({c[m] for c in ctxs}) != 1:
            reasons.append(f"context_{m}_not_shared")
    bindings = [jcs(c["authorization_binding"]) if "authorization_binding" in c else None for c in ctxs]
    if len(set(bindings)) != 1:
        reasons.append("authorization_binding_mixed_or_unequal")
    if len({c["nonce"] for c in ctxs}) != len(ctxs):
        reasons.append("nonce_reused")
    if any(c["authorization_instance"] != pinned["authorization_instance"] for c in ctxs):                             # 4
        reasons.append("authorization_instance_mismatch")
    covered = set()                                                                                                    # 5
    for so in b["signoffs"]:
        key = pinned["approver_keys"].get(so["approver_key_id"])
        if key is None or so["key_class"] not in pinned["accepted_key_classes"]:
            reasons.append("approver_key_not_trusted")
            continue
        if so["context_hash"] not in chs:
            reasons.append("signoff_covers_no_selected_context")
            continue
        i = chs.index(so["context_hash"])
        if ctxs[i]["approver"] != key["approver_id"] or i in covered:
            reasons.append("signoff_context_or_approver_mismatch")
            continue
        try:
            serialization.load_der_public_key(b64u_dec(key["public_key"])).verify(b64u_dec(so["signature"]), bytes.fromhex(so["context_hash"][7:]))
        except Exception:
            reasons.append("signoff_signature_invalid")
            continue
        covered.add(i)
    if {c["approver"] for c in ctxs} != set(pinned["expected_approvers"]):                                              # 6
        reasons.append("approver_set_not_the_selected_one")
    if len(covered) < min(c["required_approvals"] for c in ctxs):
        reasons.append("threshold_not_met")
    if any(not (c["issued_at"] <= pinned["now"] <= c["expires_at"]) for c in ctxs):                                    # 7
        reasons.append("outside_validity_window")
    if any(c["audience"] != pinned["audience"] for c in ctxs):                                                         # 8
        reasons.append("audience_mismatch")
    indeterminate = []
    if bindings[0] is not None:                                                                                        # 10
        if pinned["dps"] is None:
            indeterminate.append("dps_trust_inputs_unavailable")
        else:
            dps = pinned["dps"]
            native = verify_dps(dps["record_bytes"], dps["record"], dps["a1"], dps["sig_attachment"], dps["trust"], executed=False)
            if not native["verified"]:
                reasons.append("binding_source_does_not_verify")
            else:
                outcome = next(s for s in dps["a1"]["stages"] if s["kind"] == "outcome" and s["outcome"] == "approved")
                spec_e = next(e for e in dps["a1"]["action_specifications"] if e["spec_digest"] == outcome["approved_spec_digest"])
                spec = json.loads(base64.b64decode(spec_e["content"]["bytes_b64"]))
                proposal = next(s for s in dps["a1"]["stages"] if s["kind"] == "proposal" and s["spec_digest"] == outcome["approved_spec_digest"])
                if b["action"]["policy_id"] != pinned["policy_id"]:          # derived from the pinned policy, not made up
                    reasons.append("action_policy_id_not_the_pinned_one")
                if b["action"]["requested_at"] != proposal["at"]:            # derived from A1's proposal stage, not made up
                    reasons.append("action_requested_at_not_the_proposal_time")
                mapped = action_from_spec(spec, pinned["policy_id"], proposal["at"])
                expected = binding_of(dps["record"], dps["a1_bytes"], outcome["stage_id"], outcome["approved_spec_digest"], hx(jcs(mapped)))
                if jcs(expected) != bindings[0]:
                    reasons.append("authorization_binding_unequal")
                if jcs(mapped) != jcs(b["action"]) or action_back(b["action"]) != {k: spec[k] for k in SPEC_PROJECTED}:
                    reasons.append("mapping_not_lossless_to_the_action")
    if any(c["policy_hash"] != pinned["policy_hash"] for c in ctxs):                                                   # 11
        reasons.append("policy_digest_mismatch")
    if reasons:
        return "REFUSE", reasons
    if indeterminate:
        return "INDETERMINATE", indeterminate
    return "SATISFIED", []


def joins(art, bundle_result):
    a1, a2, receipt, b = art["a1"], art["a2"], art["receipt"], art["bundle"]
    j = {}
    rc = next((s for s in a2["stages"] if s["kind"] == "recheck"), {})
    ref = rc.get("authority_source_ref", "")
    j["the later attachment names the complete, unchanged Trust Receipt by SHA-256 over its JCS bytes (section 8), with its "
      "receipt_id and action_hash"] = (ref == f"ep:trust-receipt:{hx(jcs(receipt))}" and receipt["receipt_id"] in rc.get("detail", "")
                                       and receipt["action_hash"] in rc.get("detail", ""))
    j["the receipt is the bundle's: same action, action_hash, contexts and signoffs, its consumption nonce the signed "
      "authorization_instance (section 7.2)"] = (
        receipt["action_hash"] == b["action_hash"] and jcs(receipt["action"]) == jcs(b["action"])
        and receipt["contexts"] == b["contexts"] and receipt["signoffs"] == b["signoffs"]
        and receipt["consumption"]["nonce"] == b["contexts"][0]["authorization_instance"])
    j["the later attachment extends the one the binding names: A1's stages unchanged, and its request and attempt are for "
      "the specification the outcome approved"] = (
        a2["stages"][:len(a1["stages"])] == a1["stages"] and a2["action_specifications"] == a1["action_specifications"]
        and all(s.get("spec_digest") == a1["stages"][2]["approved_spec_digest"] for s in a2["stages"] if s["kind"] in ("request", "attempt")))
    j["the attachment the binding names carries no reverse reference (no circular digest)"] = not any(
        "ep:trust-receipt:" in str(s.get("authority_source_ref", "")) for s in a1["stages"])
    j["the issuer's times order the pair: DPS approval, then EP contexts issued and signed, then the receipt committed, then "
      "the request and the attempt"] = (
        a1["stages"][2]["at"] < b["contexts"][0]["issued_at"] <= min(s["signed_at"] for s in b["signoffs"])
        < receipt["consumption"]["committed_at"] < next(s["at"] for s in a2["stages"] if s["kind"] == "request"))
    return j


def pinned_inputs(art, with_dps=True):
    return {"authorization_instance": AUTH_INSTANCE, "audience": AUDIENCE, "now": NOW, "policy_hash": POLICY_HASH,
            "policy_id": POLICY["policy_id"],
            "expected_approvers": [a for a, _, _ in EP_APPROVERS], "accepted_key_classes": ["B"],
            "approver_keys": {kid: {"approver_id": a, "public_key": spki_b64u(k), "key_class": "B"} for a, kid, k in EP_APPROVERS},
            "dps": {"record": art["record"], "record_bytes": art["record_bytes"], "a1": art["a1"], "a1_bytes": art["a1_bytes"],
                    "sig_attachment": art["sig_attachment"], "trust": art["trust"]} if with_dps else None}


def verify(art, with_dps=True):
    r = {"dps_a1": verify_dps(art["record_bytes"], art["record"], art["a1"], art["sig_attachment"], art["trust"], executed=False),
         "dps_a2": verify_dps(art["record_bytes"], art["record"], art["a2"], art["sig_attachment"], art["trust"])}
    res, why = verify_bundle(art, pinned_inputs(art, with_dps))
    r["ep_bundle"] = {"result": res, "reasons": why}
    r["joins"] = joins(art, res)
    r["all_verified"] = r["dps_a1"]["verified"] and r["dps_a2"]["verified"] and res == "SATISFIED" and all(r["joins"].values())
    return r


def published_example():
    """The bundle verifier above, run on the author's own example at the pin: valid-non-oauth-native-binding, whose
    binding profile is the vector's (EXAMPLE-NATIVE-MANDATE-BINDING-v1): its expected binding is the case's
    expected_authorization_binding, taken as given (the native source is outside the vector)."""
    d = json.loads((HERE / "vectors" / "authorization-bundle.v1.json").read_text())
    c = next(x for x in d["cases"] if x["id"] == "valid-non-oauth-native-binding")
    pinned = {"authorization_instance": c["expected_authorization_instance"], "audience": c["audience"], "now": c["now"],
              "policy_hash": c["current_policy"]["policy_hash"], "policy_id": c["current_policy"].get("policy_id"),
              "expected_approvers": c["expected_approvers"],
              "accepted_key_classes": c["accepted_key_classes"], "approver_keys": c["approver_keys"], "dps": None}
    res, why = verify_bundle({"bundle": c["bundle"]}, pinned)
    bindings = {jcs(x["authorization_binding"]) for x in c["bundle"]["contexts"]}
    eq = bindings == {jcs(c["expected_authorization_binding"])}
    # with no DPS source, step 10 is INDETERMINATE here; the example's profile is compared with its expected object instead
    final = "SATISFIED" if res == "INDETERMINATE" and why == ["dps_trust_inputs_unavailable"] and eq else res
    # with the schema controls of section 3, the vector's action (action_type, initiator, parameters only) is refused;
    # the author wrote on 4 November 2026 that the published vector is incomplete against section 3 and needs correcting
    return {"case": c["id"], "expected": c["expect"]["verdict"], "ours": final, "reasons": why, "agree": final == c["expect"]["verdict"],
            "note": "the pinned vector predates the author's confirmation (4 November 2026) that section 3's minimum applies "
                    "and that this vector needs correcting; the disagreement is expected until the corrected vector is pinned"}


def write(out, art):
    out.mkdir(parents=True, exist_ok=True)
    (out / "decision-record.json").write_bytes(art["record_bytes"])
    (out / "action-binding-attachment-A1.json").write_bytes(art["a1_bytes"])
    (out / "action-binding-attachment-A2.json").write_bytes(art["a2_bytes"])
    (out / "signatures-attachment.json").write_bytes(compact(art["sig_attachment"]))
    (out / "trust-policy.json").write_bytes(compact(art["trust"]))
    (out / "ep-authorization-bundle.json").write_bytes(jcs(art["bundle"]))
    (out / "ep-trust-receipt.json").write_bytes(jcs(art["receipt"]))
    (out / "review-view.txt").write_text(art["view"])
    (out / "ep-pinned-inputs.json").write_text(json.dumps({k: v for k, v in pinned_inputs(art).items() if k != "dps"}, indent=1) + "\n")


if __name__ == "__main__":
    art = assemble(build())
    write(HERE / "out", art)
    r = verify(art)
    r["published_example"] = published_example()
    # all_verified is this pair's own result; the published example's agreement is reported beside it, not folded in
    (HERE / "out" / "summary.json").write_text(json.dumps(r, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(r, ensure_ascii=False, indent=1))
    sys.exit(0 if r["all_verified"] else 1)
