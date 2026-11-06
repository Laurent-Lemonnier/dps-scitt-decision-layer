#!/usr/bin/env python3
"""Case 18b: the one chain of ../one-chain (case 18), with a real approver.

Everything of case 18 is kept: the refund of 120.00 EUR on order 8812 through Thaha's receipts, the Decision Provenance
Standard's record and action-binding attachment (A1 at the approval, A2 after the run), Wright's verdict record, the
Goshi/Farley dispute packet, the twelve joins. One thing changes: the person. The finance controller's Ed25519 test
signature is replaced by a signature Laurent Lemonnier made on 6 November 2026 with his own passkey (WebAuthn, ES256,
iPhone, Face ID) on https://sign.pria.fr, over the exact DPS person_approval bytes of this chain: decision DR-2026-1104,
stage o1, outcome approved, the SHA-256 of the specification in signed/action-specification.json and of the view in
signed/review-view.txt, signed_at 2026-11-06T19:05:00Z. The assertion (signature, authenticatorData, clientDataJSON) and
the passkey's public key are pinned in signed/; nothing here can produce another one.

The chain is rebuilt around that signature: A1 carries those specification bytes, the review stage that view's digest, the
approval stage that moment; the stages after the approval, the receipts' allow outcome, A2, the verdict and the packet are
given times after 19:05:00Z the same evening and before the specification's valid_until (2026-11-07T12:00:00Z). The
Standard's reference check (extensions/signatures) verifies the passkey signature over authenticatorData || SHA-256(client
data): the challenge is the SHA-256 of the signed bytes it rebuilt from A1, the origin is the policy's, the relying party
hash is sign.pria.fr's, UP and UV are set, the key is in its validity, the holder is the actor o1 names.

Still synthetic, and said so in every file: the Harness, the agent, the payment, the issuer's seals (Ed25519 test key), the
auditor, the merchant's desk, the merchant's ledger, every moment other than the signature's. Deterministic output.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric import ec

HERE = pathlib.Path(__file__).resolve().parent
INTEROP = HERE.parent
SIGNED = HERE / "signed"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


C18 = load("one_chain_build", INTEROP / "one-chain" / "build.py")   # case 18, whole: links 1-4, joins, writer
C17, C16, G = C18.C17, C18.C16, C18.G
SIG, AB, AEE = C17.SIG, C17.AB, C17.AEE
sha256, compact, b64 = C17.sha256, C17.compact, C17.b64

# ---- the real part: one person, one passkey, one signature (signed/, pinned)
SPEC_BYTES = (SIGNED / "action-specification.json").read_bytes()
VIEW_BYTES = (SIGNED / "review-view.txt").read_bytes()
APPROVAL = json.loads((SIGNED / "person-approval.json").read_text())      # the person_approval with the assertion
PASSKEY = json.loads((SIGNED / "passkey.json").read_text())               # the enrolled credential's public part
HOLDER, DISPLAY, KEY_REF = PASSKEY["holder"], PASSKEY["display_name"], PASSKEY["key_ref"]
SIGNED_AT = APPROVAL["signed_at"]
RP_ID, ORIGINS = PASSKEY["rp_id"], PASSKEY["origins"]
METHOD = "WebAuthn-ES256 passkey assertion (sign.pria.fr) over the DPS person_approval assertion"

# ---- the timeline: the signature's moment is the one fixed point; the rest of case 18's timeline is laid around it,
# the same evening, every later moment before the specification's valid_until
T17 = {"task_start": "2026-11-06T19:04:00.000Z", "inference": "2026-11-06T19:04:01.200Z", "confirm": "2026-11-06T19:04:02.500Z",
       "proposal": "2026-11-06T19:04:03Z", "review": "2026-11-06T19:04:40Z", "approval": SIGNED_AT,
       "closed": "2026-11-06T19:07:01Z", "a1_sealed": "2026-11-06T19:07:02Z", "request": "2026-11-06T19:07:05Z",
       "recheck": "2026-11-06T19:07:06Z", "outcome": "2026-11-06T19:07:08.000Z", "attempt": "2026-11-06T19:07:08Z",
       "tool_result": "2026-11-06T19:07:09.300Z", "task_end": "2026-11-06T19:07:10.000Z", "result": "2026-11-06T19:07:11Z",
       "a2_sealed": "2026-11-06T19:08:00Z", "binding": "2026-11-06T19:09:00Z", "valid_until": "2026-11-07T12:00:00Z"}
T18 = dict(T17, verdict="2026-11-06T20:00:00.000000Z", intake="2026-11-06T20:05:00.000000Z", settlement="2026-11-06T19:07:30Z",
           ledger_verdict="2026-11-06T20:05:01Z", packet="2026-11-06T21:00:00Z",
           confirm2="2026-11-06T19:07:09.400Z", outcome2="2026-11-06T19:07:09.600Z", tool_result2="2026-11-06T19:07:09.800Z",
           request2="2026-11-06T19:07:09Z", recheck2="2026-11-06T19:07:09Z", attempt2="2026-11-06T19:07:09Z", result2="2026-11-06T19:07:12Z",
           settlement2="2026-11-06T19:07:31Z")
# the failing case "approval after the allow" on this timeline: the signature stays at 19:05:00Z (it cannot move); the
# Harness's allow outcome, the request, the recheck and the attempt are placed before it
T_ALLOW_FIRST = dict(T18, request="2026-11-06T19:04:55Z", recheck="2026-11-06T19:04:56Z", outcome="2026-11-06T19:04:58.000Z",
                     attempt="2026-11-06T19:04:58Z", tool_result="2026-11-06T19:04:59.300Z")

other_passkey = ec.derive_private_key(int.from_bytes(hashlib.sha256(b"dps-scitt-decision-layer one-chain-real: a P-256 key of nobody (test only)").digest(), "big"),
                                      ec.SECP256R1())
OTHER_POINT = other_passkey.public_key().public_bytes(C17.serialization.Encoding.X962, C17.serialization.PublicFormat.UncompressedPoint).hex()


def passkey_entry(point_hex=None):
    """The trust policy's entry for the passkey, as sign.py writes it: role person, the 65-byte uncompressed P-256
    point, validity from the enrolment, the relying party and the origins the Standard's check reads."""
    return {"key_ref": KEY_REF, "holder": HOLDER, "role": "person", "algorithm": "WebAuthn-ES256",
            "public_key_hex": point_hex or PASSKEY["public_key_hex"], "not_before": PASSKEY["enrolled_at"],
            "not_after": "2027-11-30T23:59:59Z", "identity_source_ref": f"urn:pria:sign:enrolment:{KEY_REF}",
            "webauthn": {"rp_id": RP_ID, "origins": ORIGINS}}


def trust_policy(point_hex=None):
    t = copy.deepcopy(C17.TRUST)
    t["keys"] = [passkey_entry(point_hex)] + [k for k in t["keys"] if k["role"] != "person"]
    return t


# ---- state the chain builders read (case 17's module globals, set once; the failing cases change one at a time)
STATE = {"timeline": T18, "trust_point": None, "tamper_ps": None, "approver_signature": "real"}
TRUST0 = C17.TRUST


def configure():
    C17.APPROVER, C17.APPROVER_KEY = HOLDER, KEY_REF
    C17.APPROVER_CANONICAL_ID = f"user:{HOLDER}@example.com"       # the Harness's canonical identifier (synthetic, as the Harness is)
    C17.T = {k: STATE["timeline"][k] for k in C17.T}
    C18.T = dict(STATE["timeline"])
    C17.TRUST = trust_policy(STATE["trust_point"])


def real_signatures(record, sd, *, approved=None, signed_at=None, key=None):
    """In place of case 17's make_signatures: the fields of the person_approval as the chain gives them, and the
    assertion the person made, attached as sign.py's finish attaches it (value_b64, authenticator_data_b64,
    client_data_json_b64). No key is held here: when the chain's fields are not the ones signed, the Standard's check
    says so (the challenge is the SHA-256 of the signed bytes)."""
    if STATE["approver_signature"] == "case18_test_key":   # case 18's approver, under his own key_ref, which this policy does not list
        saved, C17.APPROVER_KEY = C17.APPROVER_KEY, "finance-controller-1-key-1"
        try:
            return C17_make_signatures(record, sd, approved=approved, signed_at=signed_at)
        finally:
            C17.APPROVER_KEY = saved
    ps = {"profile": "dps-signatures", "profile_version": "0.2.0", "assertion": "person_approval",
          "decision_id": record["decision_id"], "stage_id": "o1", "outcome": "approved", "shown_spec_digest": sd,
          "shown_view_digest": sha256(C17.VIEW), "approved_spec_digest": approved or sd, "signed_at": signed_at or SIGNED_AT,
          "signature": dict(APPROVAL["signature"])}
    if STATE["tamper_ps"]:
        ps = STATE["tamper_ps"](ps)
    return {"profile": "dps-signatures", "profile_version": "0.2.0", "person_signatures": [ps]}


C17_make_signatures, C17_head_stages, C18_make_record = C17.make_signatures, C17.head_stages, C18.make_record


def head_stages(sd, approval_at=None):
    stages = C17_head_stages(sd, approval_at)
    for s in stages:
        if s["kind"] == "review":
            s["shown_view_ref"] = "https://sign.pria.fr/approve.html#" + PASSKEY["assertion_request_id"]
        if s["kind"] == "outcome":
            s["method"] = METHOD
            s["rationale"]["text_ref"] = "urn:example:rationale:refund-8812"
    return stages


def make_record():
    r = C18_make_record()
    r.update({"accountable_owner": {"full_name": DISPLAY, "role": "Finance controller (for this case)", "employer": "Example Corp (synthetic)"},
              "affirmation_record": {"timestamp": SIGNED_AT, "actor_identity": HOLDER, "method": METHOD}})
    r["mode_classification_attestation"].update({
        "attestor_full_name": DISPLAY, "attestor_role_title": "Finance controller (for this case)", "attestor_employer": "Example Corp (synthetic)",
        "attestation_text_signed": "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 summary under "
                                   "charter CH-EXAMPLE-INVOICING-1: the invoicing agent (invoicing-assistant, version 2) drafted the refund "
                                   "from ticket 4410; I read the specification and the view shown on sign.pria.fr, approved the specification "
                                   "whose digest the attachment names with my passkey, and I am the accountable owner of this decision. The "
                                   "payment, the agent and the charter are synthetic; the approval is mine."})
    r["seal_hash"] = "0" * 64
    r["seal_hash"] = sha256(compact(r))
    return r


C17.make_signatures, C17.head_stages, C18.make_record = real_signatures, head_stages, make_record


# ---------------------------------------------------------------- the build: case 18's parameters and four more

def build():
    p = C18.build()
    p.update({"timeline": "real",                    # real | allow_first (the approval after the allow, on this timeline)
              "trust_point": "enrolled",             # enrolled | other (the policy binds laurent-passkey-1 to another P-256 key)
              "tamper_ps": None,                     # function over the person_approval before the Standard reads it
              "approver_signature": "real"})         # real | case18_test_key (the finance controller's Ed25519 signature, as in case 18)
    return p


def assemble(p):
    STATE.update(timeline=T_ALLOW_FIRST if p["timeline"] == "allow_first" else T18,
                 trust_point=OTHER_POINT if p["trust_point"] == "other" else None,
                 tamper_ps=p["tamper_ps"], approver_signature=p["approver_signature"])
    configure()
    a = C18.assemble(p)
    a["trust"] = copy.deepcopy(C17.TRUST)
    return a


def real_approval_report(a):
    """The Standard's reference check of the person's signature, read in full: every dimension, the authenticator's
    facts (UP, UV, cross-origin), what the client data says, and that the challenge is the signed bytes' digest."""
    art = a["chain"]
    _pol, persons, _s, _t = SIG.run_context({"attachment": art["sig"], "export": None, "policy": a["trust"],
                                             "action_binding": {art["record"]["decision_id"]: art["a1"]}})
    if not persons:
        return {"status": "absent", "findings": ["no person signature in the attachment"]}
    p = persons[0]
    ps = art["sig"]["person_signatures"][0]
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
    except Exception as e:                                   # noqa: BLE001  (a tampered assertion may not decode)
        out["client_data"] = f"unreadable: {e}"
    out["signed_bytes_sha256"] = sha256(SIG.person_signed_bytes(ps))
    out["signature_value_sha256"] = sha256(base64.b64decode(ps["signature"]["value_b64"]))
    return out


def verify(a):
    r = C18.verify(a)
    r["real_approval"] = real_approval_report(a)
    r["pinned_inputs"] = {"specification_bytes_are_the_signed_ones": a["chain"]["spec_bytes"] == SPEC_BYTES,
                          "view_bytes_are_the_signed_ones": C17.VIEW == VIEW_BYTES,
                          "person_approval_is_the_pinned_one": a["chain"]["sig"]["person_signatures"][:1] == [APPROVAL],
                          "o1_at_is_signed_at": next(s["at"] for s in a["chain"]["a1"]["stages"] if s["stage_id"] == "o1") == SIGNED_AT}
    r["all_verified"] = (r["all_verified"] and r["real_approval"]["status"] == "verified"
                         and r["real_approval"].get("challenge_is_sha256_of_signed_bytes") is True
                         and r["real_approval"]["authenticator"] == {"user_present": True, "user_verified": True, "cross_origin": False}
                         and all(r["pinned_inputs"].values()))
    return r


def write(out, a, r=None):
    C18.write(out, a, r)
    keys = json.loads((out / "keys.json").read_text())
    keys.pop("finance_controller_ed25519_pub", None)
    keys["approver_passkey_p256_uncompressed_point_hex"] = a["trust"]["keys"][0]["public_key_hex"]
    keys["approver_passkey_key_ref"] = KEY_REF
    keys["note"] = ("the passkey is Laurent Lemonnier's, enrolled on sign.pria.fr on " + PASSKEY["enrolled_at"] + " (public key only); "
                    "the Harness, agent, DPS issuer, auditor and merchant keys are test keys from fixed seeds, never for anything real")
    (out / "keys.json").write_text(json.dumps(keys, indent=1) + "\n")
    (out / "trust-policy.json").write_bytes(compact(a["trust"]))
    (out / "passkey.json").write_text(json.dumps(PASSKEY, indent=1) + "\n")


def anchoring_subjects(out, a):
    """The bytes to timestamp for this chain, in the shape of ../../ietf horodatage of case 18 (five subjects): the raw
    signature value of the passkey assertion, A1, A2, the verdict record, the packet. Prepared, not submitted (stamp.sh)."""
    out.mkdir(parents=True, exist_ok=True)
    art = a["chain"]
    sigval = base64.b64decode(art["sig"]["person_signatures"][0]["signature"]["value_b64"])
    files = {"approval-signature.bin": sigval, "action-binding-attachment-a1.json": art["a1_bytes"],
             "action-binding-attachment-a2.json": art["a2_bytes"], "verdict-record.json": a["verdict_raw"],
             "dispute-packet.json": json.dumps(a["packet"], ensure_ascii=False, indent=1).encode() + b"\n"}
    for name, data in files.items():
        (out / name).write_bytes(data)
    (out / "SHA256SUMS").write_text("".join(f"{sha256(d)}  {n}\n" for n, d in files.items()))
    return {n: sha256(d) for n, d in files.items()}


if __name__ == "__main__":
    out = HERE / "out"
    pos = assemble(build())
    res = verify(pos)
    write(out / "positive", pos, res)
    subjects = anchoring_subjects(HERE / "anchoring" / "subjects", pos)
    neg = assemble(dict(build(), executed_amount=15000))
    nres = verify(neg)
    write(out / "stated-negative", neg, nres)
    l12 = nres["link1_2_thaha_dps"]
    j1 = next(k for k in l12["joins"] if k.startswith("J1"))
    neg_as_expected = (l12["joins"][j1] is False and l12["dps_a2"]["dimensions"]["action_binding"] == "failed"
                       and nres["link3_verdict"]["state"] == "released" and neg["verdict_stated"] == "not_as_approved"
                       and nres["link4_packet"]["result"] == "VERIFIED" and nres["link4_packet"]["re_derived"]["scope_conformance"] == "BREACH:amount_minor"
                       and nres["real_approval"]["status"] == "verified" and all(v is True for v in nres["joins"].values()))
    summary = {"positive": {k: res[k] for k in ("all_verified", "joins", "real_approval", "pinned_inputs")},
               "positive_link_results": {"thaha": res["link1_2_thaha_dps"]["aee"]["result"], "dps_a1": res["link1_2_thaha_dps"]["dps_a1"]["dimensions"],
                                         "dps_a2": res["link1_2_thaha_dps"]["dps_a2"]["dimensions"],
                                         "dps_a2_person_approval": res["link1_2_thaha_dps"]["dps_a2"]["person_approval"],
                                         "verdict": res["link3_verdict"]["summary"], "packet": res["link4_packet"]["result"]},
               "stated_negative": {"as_expected": neg_as_expected, "thaha_J1": l12["joins"][j1],
                                   "dps_a2_action_binding": l12["dps_a2"]["dimensions"]["action_binding"], "real_approval": nres["real_approval"]["status"],
                                   "verdict": nres["link3_verdict"]["summary"], "packet": nres["link4_packet"]["result"],
                                   "scope_re_derived": nres["link4_packet"]["re_derived"]["scope_conformance"], "joins": nres["joins"]},
               "anchoring_subjects_sha256": subjects, "all_verified": res["all_verified"] and neg_as_expected}
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1, default=str) + "\n")
    print(json.dumps(summary, ensure_ascii=False, indent=1, default=str))
    sys.exit(0 if summary["all_verified"] else 1)
