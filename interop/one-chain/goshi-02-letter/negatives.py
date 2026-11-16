#!/usr/bin/env python3
"""The failing cases of the packet built to the letter of -02: each is the valid packet and its Signed Statement changed
in one place, run through the same three checks as build.py. A place is "reader:<CODE>" (the packet verifier of
../goshi_from_text.py as published names that failure), "letter:<CODE>" or "statement:<CODE>" (the two checks of
letter.py). A case is as expected when the places that fail are exactly the places it names: nothing less, nothing more.
Writes out/negatives.json. Exit 0 when every case is as expected. Deterministic."""
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


@case("M1-a-twelfth-member-signed", ["letter:RECEIPT_MEMBER_NOT_IN_SECTION_4"],
      "the receipt payload carries issued_at beside the eleven members, and the signature covers it: the packet verifier names the "
      "member and verifies (the text does not say a receipt carries nothing else); the letter check fails")
def m1(p):
    p["extra_member"] = ("issued_at", B.PACKET_TIME)


@case("M2-a-member-missing-signed", ["reader:RECEIPT_MEMBER_MISSING", "letter:RECEIPT_MEMBER_MISSING"],
      "the receipt payload has ten members: rail_anchors_hash is absent, and the signature covers the ten")
def m2(p):
    p["drop_member"] = "rail_anchors_hash"


@case("M3-manifest-names-01", ["letter:MANIFEST_NAMES_ANOTHER_REVISION"],
      "the same packet under a manifest whose profile member names draft-xg-payment-dispute-profile-01: nothing the packet verifier "
      "re-derives depends on that member")
def m3(p):
    p["profile"] = "draft-xg-payment-dispute-profile-01"


@case("M4-statement-signed-with-another-key", ["statement:STATEMENT_NOT_SIGNED_BY_THE_RECEIPT_KEY"],
      "the Signed Statement carries the receipt's canonical bytes and the receipt's key_id as kid, and is signed with another key")
def m4(p):
    p["statement_key"] = "other"


@case("M5-subject-is-not-the-action-identifier", ["statement:STATEMENT_SUBJECT_NOT_THE_ACTION_IDENTIFIER"],
      "the Signed Statement's subject names another action than the packet manifest's action_id")
def m5(p):
    p["statement_subject"] = "urn:example:action:refund-8813"


@case("M6-statement-carries-the-whole-packet", ["statement:STATEMENT_PAYLOAD_NOT_THE_RECEIPT"],
      "the Signed Statement's payload is the file of the whole dispute packet, the form of the parent case's registration, not the "
      "receipt's canonical bytes")
def m6(p):
    p["statement_payload"] = "packet"


@case("M7-statement-carries-the-receipt-not-canonical", ["statement:STATEMENT_PAYLOAD_NOT_THE_RECEIPT"],
      "the Signed Statement's payload is the receipt as indented JSON: the same receipt, not its canonical bytes")
def m7(p):
    p["statement_payload"] = "indented"


@case("M8-statement-carries-another-receipt", ["statement:STATEMENT_PAYLOAD_NOT_THE_RECEIPT"],
      "the Signed Statement's payload is the canonical bytes of the parent packet's receipt (the same action, another receipt), "
      "signed with this packet's receipt key")
def m8(p):
    p["statement_payload"] = "parent_receipt"


@case("M9-statement-carries-the-payload-member-alone", ["statement:STATEMENT_PAYLOAD_IS_THE_PAYLOAD_MEMBER_ALONE"],
      "the Signed Statement's payload is the canonical bytes of the receipt's payload member, without the signature object: the other "
      "reading of \"the receipt's canonical bytes\" (letter.READINGS, R1). It fails here because one reading was chosen, not because "
      "the text excludes it")
def m9(p):
    p["statement_payload"] = "payload_member"


@case("M10-statement-without-issuer", ["statement:STATEMENT_ISSUER_MISSING"],
      "the CWT claims of the Signed Statement carry a subject and no issuer")
def m10(p):
    p["statement_issuer"] = None


@case("M11-approval-held-outside-the-ledger", ["letter:APPROVAL_HELD_OUTSIDE_THE_LEDGER"],
      "the ApprovalGranted event keeps the parent case's dps_approval, the typed digests of an approval held outside the ledger "
      "(Section 5: out of scope for this revision); the ledger is chained over it and the packet verifier, which reads that member as "
      "an extension, names no failure")
def m11(p):
    p["approval_held_outside"] = True


@case("M12-a-number-in-the-receipt", ["letter:RECEIPT_VALUE_OUTSIDE_THE_STATED_DOMAIN"],
      "mandate_hash is the number 0 in the receipt and in the agent anchors, signed: outside the value domain Section 4 states for the "
      "receipt (strings, booleans, null). The packet verifier canonicalises integers below 2^53 (its own allowance, for the recorded "
      "intent scope) and names no failure")
def m12(p):
    p["mandate_hash"] = 0


@case("M13-receipt-and-statement-signed-end-to-end-with-another-key",
      ["reader:RECEIPT_SIGNATURE_INVALID", "reader:RECEIPT_SIGNER_PUBKEY_HASH", "statement:STATEMENT_NOT_SIGNED_BY_THE_RECEIPT_KEY"],
      "the receipt and the Signed Statement are signed with another key, and the manifest and signer_pubkey_hash declare that key: the "
      "packet is consistent with itself (the letter check, which reads only the packet, passes) and fails against the key resolved "
      "out of band (Section 11: \"without a key resolved out of band, a packet re-signed end to end with another key verifies\")")
def m13(p):
    p.update(sign_with="other", declared_key="other", statement_key="other")


@case("M14-statement-under-an-algorithm-that-is-not-ed25519", ["statement:STATEMENT_ALG"],
      "the Signed Statement's protected header names alg -7 (ES256) over an Ed25519 signature")
def m14(p):
    p["statement_alg"] = -7


def places(reports):
    return sorted(f"{name}:{f['code']}" for name, r in reports.items() for f in r["failures"])


def main():
    lines, summary, ok_all = [], {}, True
    for name, (where, what, fn) in N.items():
        p = B.options()
        fn(p)
        packet = B.build_packet(p)
        statement = B.build_statement(packet, p)
        failed = places(B.verify(packet, statement))
        ok = failed == sorted(where)
        ok_all &= ok
        summary[name] = {"what": what, "expected": sorted(where), "failed_at": failed, "as_expected": ok}
        lines.append(f"{'ok ' if ok else 'NOT'} {name}: expected {sorted(where)}, failed at {failed}")
    lines.append(f"{sum(v['as_expected'] for v in summary.values())}/{len(summary)} failing cases caught where expected, and nowhere else")
    (HERE / "out" / "negatives.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
