#!/usr/bin/env python3
"""The failing cases of case 18b: the valid chain with the real approval, changed in one place. The signature-level cases
touch the one real thing (the assertion, the key the policy binds, the bytes it is said to cover); the timing case moves the
chain around the signature, which cannot move. Same reading as ../one-chain/negatives.py: a case is as expected when every
place it names is among those that fail ("dps": a Standard check of A1, A2, the seal or the person's approval is not
verified; "J1".."J7", "K1".."K12": the joins; "verdict:refused"/"verdict:held"; "goshi:<CODE>"). Each case is written
under out/negatives/<case>/ with every document, what.txt and result.json, plus the Standard's full reading of the
person's signature (real-approval.json). Exit 0 when every case is as expected. Deterministic."""
import base64
import json
import pathlib
import sys

import build as B

HERE = pathlib.Path(__file__).resolve().parent
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


@case("R1-assertion-presented-over-other-bytes", ["dps"],
      "the person's real assertion is presented as the approval of a specification of 150.00 EUR: the chain is rebuilt around that "
      "specification (A1 names it, the review was shown it, the run executes it, so every other check passes), and the passkey "
      "assertion is attached to the person_approval whose digests are its. The Standard's check rebuilds the signed bytes from these "
      "fields and finds the challenge in the client data is not their SHA-256, and the ECDSA signature does not verify over "
      "authenticatorData || SHA-256(clientDataJSON) for them: the person signed other bytes (the 120.00 approval at 19:05:00Z). "
      "Only the Standard sees it: the receipts, the verdict's rule and the packet read the approval event by digest, not the signature")
def r1(p):
    p.update(approved_amount=15000, executed_amount=15000)


@case("R2-client-data-from-another-origin", ["dps"],
      "the clientDataJSON says origin https://sign.example.org, the rest unchanged: the Standard's check names the origin as one the "
      "policy does not allow for laurent-passkey-1 (the policy's entry names https://sign.pria.fr), and the signature no longer verifies, "
      "since the client data hash is signed")
def r2(p):
    p["tamper_ps"] = lambda ps: with_client_data(ps, lambda c: c.update(origin="https://sign.example.org"))


@case("R3-user-verification-flag-cleared", ["dps"],
      "the UV bit (0x04) of the authenticatorData flags is cleared, as if the authenticator had stated presence without verifying the "
      "user: the Standard's check reports user_verified false as a fact and the signature fails, since the flags are signed; the real "
      "assertion has UP and UV set (0x1d: UP, UV, BE, BS)")
def r3(p):
    p["tamper_ps"] = lambda ps: with_flags(ps, 0xFF ^ 0x04)


@case("R4-another-credential-under-the-same-key-ref", ["dps"],
      "the trust policy binds laurent-passkey-1 to another P-256 public key (a key of nobody, derived from a fixed seed): the assertion "
      "is Laurent Lemonnier's and does not verify under that key; nothing downstream notices (the verdict's rule reads the dimensions, "
      "the packet reads digests)")
def r4(p):
    p["trust_point"] = "other"


@case("R5-approval-after-the-allow-on-the-real-timeline", ["J2", "K2", "dps", "verdict:refused"],
      "the signature stays at 19:05:00Z (it is the one moment here that cannot be moved); the Harness's allow outcome, the request, the "
      "recheck and the attempt are placed before it (19:04:55 to 19:04:59): case 17's J2 and the join K2 (approval before allow in every "
      "record of it) are false, the Standard's stage_order dimension fails on A2, the checker refuses the verdict (the "
      "rule reads the dimensions; K5, K7, K12 follow). The passkey signature itself still verifies: it says when the person signed, not when the call "
      "proceeded; Thaha's receipts alone cannot see it")
def r5(p):
    p["timeline"] = "allow_first"


@case("R6-case-18-test-signature-under-this-policy", ["dps"],
      "the finance controller's Ed25519 test signature of case 18 (finance-controller-1-key-1) is attached in place of the passkey "
      "assertion: the key is not in this chain's trust policy, which binds one person's key, laurent-passkey-1; the Standard's check "
      "names it as not a key in the trust policy, and the identity dimension is not checked")
def r6(p):
    p["approver_signature"] = "case18_test_key"


@case("R7-confirm-without-approval", ["dps", "J2", "K2"],
      "case 18's N4 on this chain: the signatures attachment carries no person signature while o1 is still claimed: the Standard's "
      "person_approval check is where the absence shows; the receipts and the packet say nothing")
def r7(p):
    p["approval"] = "absent"


@case("R8-signed-at-moved-by-one-second", ["dps", "J2", "K2"],
      "the person_approval's signed_at is written 19:05:01Z where the person signed bytes saying 19:05:00Z: the challenge is not the "
      "SHA-256 of the bytes the Standard rebuilds, the signature fails; and o1 (19:05:00Z) is no longer the signature's moment (J2, K2)")
def r8(p):
    p["tamper_ps"] = lambda ps: {**ps, "signed_at": "2026-11-06T19:05:01Z"}


def failed_places(a, r):
    l12, failed = r["link1_2_thaha_dps"], set()
    if l12["aee"]["result"] != "CHECKS_PERFORMED":
        failed.add("aee")
    for k in ("dps_a1", "dps_a2"):
        dims = l12[k]["dimensions"]
        if [d for d, v in dims.items() if v not in ("verified", "not_checked")] or l12[k]["issuer_seal"] != "verified" \
                or l12[k]["person_approval"]["status"] != "verified":
            failed.add("dps")
    if r["real_approval"]["status"] != "verified":
        failed.add("dps")
    for k, v in l12["joins"].items():
        if v is not True:
            failed.add(k.split(" ")[0])
    if r["link3_verdict"]["state"] != "released":
        failed.add("verdict:" + r["link3_verdict"]["state"])
    for f in r["link4_packet"]["failures"]:
        failed.add("goshi:" + f["code"])
    for k, v in r["joins"].items():
        if v is not True:
            failed.add(k.split(" ")[0])
    return failed


def run_case(name):
    where, what, fn = N[name]
    p = B.build()
    fn(p)
    a = B.assemble(p)
    r = B.verify(a)
    failed = failed_places(a, r)
    out = HERE / "out" / "negatives" / name
    B.write(out, a, r)
    (out / "what.txt").write_text(what + "\n")
    (out / "real-approval.json").write_text(json.dumps(r["real_approval"], indent=1, default=str) + "\n")
    verdict = {"case": name, "expected_to_fail_at": where, "failed_at": sorted(failed), "as_expected": set(where) <= failed,
               "person_signature": {k: r["real_approval"].get(k) for k in ("status", "signature", "subject", "key_state", "identity", "authenticator")},
               "person_signature_findings": r["real_approval"].get("findings"),
               "verdict_state": r["link3_verdict"]["state"], "packet": r["link4_packet"]["result"],
               "packet_failures": [f["code"] for f in r["link4_packet"]["failures"]],
               "joins_false": [k.split(" ")[0] for k, v in r["joins"].items() if v is not True]}
    (out / "result.json").write_text(json.dumps(verdict, indent=1, default=str) + "\n")
    return verdict


if __name__ == "__main__":
    verdicts = [run_case(n) for n in N]
    (HERE / "out" / "negatives" / "summary.json").write_text(json.dumps(verdicts, indent=1, default=str) + "\n")
    for v in verdicts:
        print(f"{'ok ' if v['as_expected'] else 'NOT'} {v['case']}: expected {v['expected_to_fail_at']}, failed at {v['failed_at']}")
        for f in v["person_signature_findings"] or []:
            print(f"      signature finding: {f}")
    print(f"{sum(v['as_expected'] for v in verdicts)}/{len(verdicts)} failing cases caught where expected")
    sys.exit(0 if all(v["as_expected"] for v in verdicts) else 1)
