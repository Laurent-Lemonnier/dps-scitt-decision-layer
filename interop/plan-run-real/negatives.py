#!/usr/bin/env python3
"""The failing cases of case 13b: the valid run with the real approval, changed in one place.

Two families. N1 to N14 are case 13's own (../plan-run/negatives.py, imported and run unchanged on this run: a step
missing, reordered, outside the plan, arguments changed, the plan hash, the manifest, a substituted output, a step twice,
a false disposition, the plan run twice, a fourth step, a stale record or context, a broken link); the real approval is
attached to each, and verifies in each but N5, where the plan the person is said to have approved is not the plan he
signed. R1 to R10 touch the one real thing (the assertion, the key the policy binds, the bytes it is said to cover, the
view, the moment) or move the run around the signature, which cannot move.

Same reading as case 13: a case is as expected when the place it names is among those that fail; the places are case 13's
(schema, dps_action_binding, dps_person_signatures, dps_issuer_seal, capsules, joins) plus real_approval, the Standard's
full reading of the person's signature (status other than verified). Each case is written under out/negatives/<case>/
with every document, what.txt, result.json and real-approval.json. Exit 0 when every case is as expected. Deterministic."""
import base64
import copy
import json
import pathlib
import sys

import build as R

HERE = pathlib.Path(__file__).resolve().parent
B = R.B

# case 13's failing cases, their failures() and publish(), loaded with their `build` bound to case 13's module
_saved = sys.modules.get("build")
sys.modules["build"] = B
PRN = R.load("plan_run_negatives", R.INTEROP / "plan-run" / "negatives.py")
sys.modules["build"] = _saved

N = {}


def case(name, where, what):
    def deco(fn):
        N[name] = (where, what, fn)
        return fn
    return deco


def b64(b):
    return base64.b64encode(b).decode()


def with_client_data(ps, change):
    sig = dict(ps["signature"])
    client = json.loads(base64.b64decode(sig["client_data_json_b64"], validate=True))
    change(client)
    sig["client_data_json_b64"] = b64(json.dumps(client, separators=(",", ":")).encode())
    return {**ps, "signature": sig}


def with_flags(ps, mask):
    sig = dict(ps["signature"])
    auth = bytearray(base64.b64decode(sig["authenticator_data_b64"], validate=True))
    auth[32] &= mask
    sig["authenticator_data_b64"] = b64(bytes(auth))
    return {**ps, "signature": sig}


@case("R1-assertion-presented-over-another-plan", "real_approval",
      "the person's real assertion is presented as the approval of another plan: step 1 creates the CRM record under another legal "
      "name (the plan hash follows, A1 names that plan, the review was shown it, the run executed it, the capsules and the manifest "
      "agree with it: every join is true), and the passkey assertion is attached to the person_approval whose digests are that plan's. "
      "The Standard's check rebuilds the signed bytes from these fields and finds the challenge in the client data is not their SHA-256: "
      "the person signed the other plan. Only the Standard sees it: the joins read digests, the capsule library reads capsules")
def r1(p):
    p["spec"]["parameters"]["steps"][1]["parameters"]["legal_name"] = "Example Client 4471 Holding SAS"
    p["spec"]["parameters"]["plan_hash"] = B.plan_hash_of(p["spec"]["parameters"]["steps"])


@case("R2-client-data-from-another-origin", "real_approval",
      "the clientDataJSON says origin https://sign.example.org, the rest unchanged: the Standard's check names the origin as one the "
      "policy does not allow for laurent-passkey-1, and the signature no longer verifies, since the client data hash is signed")
def r2(p):
    p["tamper_ps"] = lambda ps: with_client_data(ps, lambda c: c.update(origin="https://sign.example.org"))


@case("R3-user-verification-flag-cleared", "real_approval",
      "the UV bit (0x04) of the authenticatorData flags is cleared, as if the authenticator had stated presence without verifying the "
      "user: the Standard's check reports user_verified false as a fact and the signature fails, since the flags are signed")
def r3(p):
    p["tamper_ps"] = lambda ps: with_flags(ps, 0xFF ^ 0x04)


@case("R4-another-credential-under-the-same-key-ref", "real_approval",
      "the trust policy binds laurent-passkey-1 to another P-256 public key (a key of nobody, derived from a fixed seed): the assertion "
      "is Laurent Lemonnier's and does not verify under that key; the capsules, the manifest and the joins notice nothing")
def r4(p):
    p["trust_point"] = "other"


@case("R5-run-before-the-approval", "dps_action_binding",
      "the signature stays at its moment (the one moment here that cannot be moved); the request, the recheck, the attempt, the three "
      "steps and the result are placed five minutes before it: the Standard's stage_order dimension fails (a request authorised by an "
      "outcome that did not yet exist). The passkey signature itself still verifies: it says when the person signed, not when the run "
      "proceeded; the capsules and the joins, which read no approval time, see nothing")
def r5(p):
    p["run_minute"] = 20


@case("R6-case-13-test-signature-under-this-policy", "real_approval",
      "the office manager's Ed25519 test signature of case 13 (office-manager-1-key-1) is attached in place of the passkey assertion: "
      "the key is not in this run's trust policy, which binds one person's key, laurent-passkey-1; the Standard's check names it as "
      "not a key in the trust policy")
def r6(p):
    p["approver_signature"] = "case13_test_key"


@case("R7-approval-absent", "real_approval",
      "the signatures attachment carries no person signature while o0 is still claimed and the run proceeds: the absence shows only "
      "in the Standard's reading of the person approval; the eight action-binding dimensions, the seal, the capsules and the joins hold")
def r7(p):
    p["approver_signature"] = "absent"


@case("R8-signed-at-moved-by-one-second", "real_approval",
      "the person_approval's signed_at is written one second after the moment the person signed bytes for: the challenge is not the "
      "SHA-256 of the bytes the Standard rebuilds, the signature fails")
def r8(p):
    p["tamper_ps"] = lambda ps: {**ps, "signed_at": R.at_real(25, 1)}


@case("R9-another-view-shown", "real_approval",
      "the review stage and the person_approval carry the digest of another view (one in which the plan hash line is missing), as if "
      "the person had been shown that view: the subject dimension agrees (A1 and the approval name the same view), the signature "
      "fails (the view digest is among the signed bytes); the person was shown the view pinned in signed/")
def r9(p):
    view = B.view_for_plan(p["spec"]).decode()
    p["view_shown"] = "\n".join(l for l in view.split("\n") if not l.startswith("plan hash ")).encode()


@case("R10-assertion-moved-to-another-decision", "real_approval",
      "the whole run is issued under another decision record, DR-2026-1107 (record, A1, manifest, capsules' references agree), and the "
      "person's assertion is attached to its o0: the challenge is not the SHA-256 of bytes naming DR-2026-1107; the person approved "
      "the plan of DR-2026-1106")
def r10(p):
    p["decision_id"] = "DR-2026-1107"


def failures(r):
    f = PRN.failures(r)
    if r["real_approval"]["status"] != "verified":
        f["real_approval"] = {k: r["real_approval"].get(k) for k in ("status", "signature", "subject", "key_state", "identity")} | \
            {"findings": r["real_approval"].get("findings", [])[:3]}
    return f


def run_case13_case(name, where, what, fn):
    """Case 13's case on this run: its parts-level or art-level mutation, with case 13's clock patched to this run's for
    the moments it writes (N8, N11), then restored before the fidelity check in verify."""
    parts = R.build()
    art_level = fn.__code__.co_argcount == 2
    saved_at, B.at = B.at, R.at_real
    try:
        if not art_level:
            fn(parts)
        art = R.assemble(parts)
        if art_level:
            fn(art, parts)
    finally:
        B.at = saved_at
    return art, parts


def run_own_case(name, where, what, fn):
    parts = R.build()
    fn(parts)
    return R.assemble(parts), parts


def main():
    out = HERE / "out" / "negatives"
    out.mkdir(parents=True, exist_ok=True)
    summary, ok = {}, True
    cases = [(n, w, what, fn, run_case13_case) for n, (w, what, fn) in PRN.N.items()] + \
            [(n, w, what, fn, run_own_case) for n, (w, what, fn) in N.items()]
    for name, where, what, fn, runner in cases:
        art, parts = runner(name, where, what, fn)
        r = R.verify(art, parts)
        f = failures(r)
        expected = where in f
        ok = ok and expected
        summary[name] = {"what": what, "caught_by": sorted(f), "expected_place": where, "as_expected": expected,
                         "real_approval": r["real_approval"]["status"], "detail": f}
        d = out / name
        PRN.publish(d, {k: v for k, v in art.items() if k not in ("spec_bytes", "view")}, what, summary[name])
        (d / "real-approval.json").write_text(json.dumps(r["real_approval"], indent=1, default=str) + "\n")
        print(("ok   " if expected else "FAIL ") + f"{name}: caught by {', '.join(sorted(f)) or 'nothing'}; real approval {r['real_approval']['status']}")
        for finding in (r["real_approval"].get("findings") or [])[:2]:
            print(f"      signature finding: {finding}")
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1, default=str) + "\n")
    print(f"{sum(v['as_expected'] for v in summary.values())}/{len(summary)} failing cases caught where expected")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
