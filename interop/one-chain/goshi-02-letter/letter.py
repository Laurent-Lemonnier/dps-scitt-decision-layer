#!/usr/bin/env python3
"""Two checks beside the packet verifier of ../goshi_from_text.py, for a packet built to the letter of
draft-xg-payment-dispute-profile-02 as we read it. The verifier of the parent directory is not changed and is not
repeated here: it re-derives what Sections 5, 8 and 9 let a verifier re-derive. These two checks are stricter on shape:

  check_letter(packet): the receipt payload has the eleven members of Section 4 and no other; its values are in the
  value domain Section 4 states (strings, booleans, null); the manifest names revision -02 and carries
  receipt_public_key_hex (Section 4); the approval event the packet cites carries the receipt's action_hash (Section 5)
  and no approval held outside the ledger (Section 5: "out of scope for this revision").

  check_statement(statement, packet, public_key_hex): the Signed Statement of Section 6: a COSE_Sign1 whose payload is
  the receipt's canonical bytes, signed with the receipt's own signing key, with the CWT claims issuer present and the
  subject equal to the manifest's action identifier.

Where Section 6 leaves a choice open, READINGS says which one this module takes. Every failure is named; the names are
this module's.
"""
import importlib.util
import pathlib
from collections.abc import Mapping

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("goshi_from_text", HERE.parent / "goshi_from_text.py")
G = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(G)

PROFILE_02 = "draft-xg-payment-dispute-profile-02"
ALG_ED25519, ALG_EDDSA = -19, -8                                 # RFC 9864; RFC 9053
CONTENT_TYPE = "application/json"

# What the text of -02 leaves open for this packet and its Signed Statement, the sentence that leaves it open, and the
# one choice made here. Where ts.isoluce.net already had a practice (algorithm, content type, kid), the choice is that one.
READINGS = {
    "R1 the payload of the Signed Statement": {
        "text": "6: \"The Signed Statement is a COSE_Sign1 [RFC9052] whose payload is the receipt's canonical bytes\"; "
                "3: a dispute receipt is \"an Ed25519 ([RFC8032]) signature over an [RFC8785] (JCS) canonicalized payload, in an "
                "envelope of the form {payload, signature{alg, kid, sig}}\"",
        "open": "the receipt's canonical bytes can be the canonical bytes of the whole envelope, or of its payload member alone",
        "choice": "the JCS bytes of the whole envelope {payload, signature}: the receipt is the envelope (Section 3), and "
                  "Appendix A gives SHA-256(R) and a leaf hash for the envelope R, which is printed in that form. The receipt's "
                  "own signature is then inside the registered bytes"},
    "R2 the COSE algorithm identifier": {
        "text": "6: \"signed with the receipt's own signing key\"; 4: \"Signature: Ed25519, lowercase hex (alg = EdDSA)\"",
        "open": "the COSE_Sign1 needs an integer alg; Ed25519 has two, -8 (EdDSA, RFC 9053) and -19 (Ed25519, RFC 9864); "
                "the text names neither",
        "choice": "-19, the identifier ts.isoluce.net signs its receipts with and the one the statements of ../registration "
                  "carry; check_statement accepts -8 as well"},
    "R3 the content type": {
        "text": "6: the bullet that describes the Signed Statement names its payload, its key, the CWT claims issuer and subject",
        "open": "no content type (COSE header 3) is named",
        "choice": "application/json, as the statements of ../registration carry for a JSON payload"},
    "R4 the kid of the Signed Statement": {
        "text": "6: \"A party that already trusts the receipt key needs no other key to check the statement\"; "
                "5: \"key_id names that key in the operator's published keyring\"",
        "open": "the text does not say how the COSE_Sign1 names the key; RFC 9943 Section 6 requires a kid when there is no "
                "x5t or x5chain",
        "choice": "the receipt's key_id, as a byte string (ts.isoluce.net refuses a kid that is not a byte string)"},
    "R5 the issuer": {
        "text": "6: \"with the CWT claims issuer set to an identifier the registering party supplies (the receipt payload "
                "carries none)\"",
        "open": "which identifier",
        "choice": "urn:example:merchant:dispute-desk, the fictional desk the packet's acquisition record names: the key is a "
                  "test key whose seed is public, so the statement is put under no real identifier"},
    "R6 the eleven members and approval_event_hash": {
        "text": "4: \"Payload: the implementation's PolicyDecisionReceipt canonical dict -- decision, reason_code, action_hash, "
                "evidence_set_hash, ledger_entry_hash, timestamp, mandate_hash, rail_anchors_hash, scope_conformance, key_id, "
                "signer_pubkey_hash\"; 5: \"the receipt fields that bind to other parts of the packet are built as follows\", "
                "a list that includes approval_event_hash and anchor_hash; 8.2: the agent_anchors block carries the \"approval "
                "event hash\"",
        "open": "whether approval_event_hash and anchor_hash are members of the receipt payload",
        "choice": "no: the payload has the eleven members of Section 4 and no other, as the vector of Appendix A does; "
                  "approval_event_hash is in the manifest's agent_anchors block (8.2), anchor_hash in its settlement block (8.3)"},
    "R7 mandate_hash without an AP2 mandate": {
        "text": "8.2: \"AP2 mandate_hash\"; \"Network token id and 3DS/ACS result are part of the block's shape but null when "
                "the implementation has no source for them\"; 4: \"the receipt dict is strings, booleans, null\"",
        "open": "whether mandate_hash may be null when the approval is a person's and not an AP2 mandate",
        "choice": "null, in the receipt and in the agent_anchors block"},
    "R8 evidence_set_hash and rail_anchors_hash": {
        "text": "5: \"evidence_set_hash and rail_anchors_hash are signed but not re-derived by the reference verifier in this "
                "revision; a verifier MUST NOT report them as checked\"",
        "open": "what the two values are built from",
        "choice": "the constructions of the parent case (the SHA-256 of the canonical JSON of the sorted digests the packet "
                  "cites; the settlement anchor_hash). They are signed and not reported as checked"},
    "R9 the manifest, the ledger slice and the event hash": {
        "text": "Appendix B: \"The packet manifest, the ledger slice and the ledger event hash are named but not yet defined in "
                "this document\"",
        "open": "their shapes",
        "choice": "the shapes of the parent case, which ../goshi_from_text.py reads; a member profile in the manifest names the "
                  "revision the packet was built to (the text asks for no such member)"},
    "R10 a number in the recorded action": {
        "text": "5: \"action_hash: the canonical hash of the executed-action object recorded in the action's ScopeEvaluated ledger "
                "event\"; \"'Canonical hash' means lowercase hex SHA-256 over the canonical bytes of Section 4\"; 4: \"the receipt "
                "dict is strings, booleans, null, and nested objects/arrays of the same, with amounts pre-converted to decimal "
                "strings before canonicalization\"",
        "open": "whether the value domain stated for the receipt dict also binds the recorded executed-action and intent-scope objects",
        "choice": "no: the two recorded objects keep amount_minor as the integer the tool door saw (12000), which JCS writes as a "
                  "plain integer, so that action_hash is the digest the other three links of the chain carry. The receipt itself "
                  "holds strings and null only"},
}


def _fail(F, code, why):
    F.append({"code": code, "why": why})


def check_letter(packet):
    """Returns {result, failures, checks}. Shape checks of the receipt and the manifest against the letter of -02."""
    F, C = [], []
    receipt = packet.get("receipt") if isinstance(packet, dict) else None
    manifest = packet.get("manifest") if isinstance(packet, dict) else None
    payload = receipt.get("payload") if isinstance(receipt, dict) else None
    if not isinstance(payload, dict) or not isinstance(manifest, dict):
        _fail(F, "PACKET_SHAPE", "no receipt payload or no manifest to read")
        return {"result": "FAILED", "failures": F, "checks": C}
    # ---- Section 4: the eleven members and no other
    extra = sorted(set(payload) - set(G.PROFILE_MEMBERS))
    missing = [m for m in G.PROFILE_MEMBERS if m not in payload]
    if extra:
        _fail(F, "RECEIPT_MEMBER_NOT_IN_SECTION_4", f"4: the payload carries {extra}, which Section 4 does not list")
    if missing:
        _fail(F, "RECEIPT_MEMBER_MISSING", f"4: the payload lacks {missing}")
    if not extra and not missing:
        C.append("the receipt payload has the eleven members of Section 4 and no other")
    # ---- Section 4: the stated value domain of the receipt (strings, booleans, null)
    outside = sorted(k for k, v in payload.items() if not (v is None or isinstance(v, (str, bool))))
    if outside:
        _fail(F, "RECEIPT_VALUE_OUTSIDE_THE_STATED_DOMAIN", f"4: \"the receipt dict is strings, booleans, null\"; {outside} "
                                                            "are of another type")
    else:
        C.append("every value of the receipt payload is a string, a boolean or null (4)")
    # ---- the manifest names the revision, and carries the receipt public key (4)
    if manifest.get("profile") != PROFILE_02:
        _fail(F, "MANIFEST_NAMES_ANOTHER_REVISION", f"the manifest's profile is {manifest.get('profile')!r}, not {PROFILE_02!r}")
    else:
        C.append(f"the manifest names {PROFILE_02}")
    pk = manifest.get("receipt_public_key_hex")
    try:
        ok_pk = isinstance(pk, str) and len(bytes.fromhex(pk)) == 32 and G.sha256_hex(bytes.fromhex(pk)) == payload.get("signer_pubkey_hash")
    except ValueError:
        ok_pk = False
    if not ok_pk:
        _fail(F, "MANIFEST_RECEIPT_PUBLIC_KEY", "4: \"the packet manifest carries receipt_public_key_hex\"; absent, not a raw "
                                                "Ed25519 key, or not the key signer_pubkey_hash names (5)")
    else:
        C.append("the manifest carries receipt_public_key_hex, whose SHA-256 is the receipt's signer_pubkey_hash (4, 5); "
                 "a hint, not a key resolved out of band")
    # ---- Section 5: the approval event, to the letter
    events = packet.get("ledger_slice") if isinstance(packet.get("ledger_slice"), list) else []
    by_hash = {e.get("event_hash"): e for e in events if isinstance(e, dict)}
    aeh = (manifest.get("agent_anchors") or {}).get("approval_event_hash") if isinstance(manifest.get("agent_anchors"), dict) else None
    if aeh is not None:
        ev = by_hash.get(aeh)
        data = ev.get("data") if isinstance(ev, dict) and isinstance(ev.get("data"), dict) else {}
        if ev is None or ev.get("type") not in ("ApprovalGranted", "ApprovalDenied") or data.get("action_hash") != payload.get("action_hash"):
            _fail(F, "APPROVAL_EVENT_NOT_AS_SECTION_5", "5: \"the event hash of an ApprovalGranted or ApprovalDenied event in the "
                                                        "ledger slice, whose payload carries an action_hash equal to the receipt's\"")
        else:
            C.append("approval_event_hash is an ApprovalGranted or ApprovalDenied event of the slice whose payload carries the "
                     "receipt's action_hash (5)")
        held_outside = sorted(k for k in data if k.startswith("dps_"))
        if held_outside:
            _fail(F, "APPROVAL_HELD_OUTSIDE_THE_LEDGER", f"5: \"An approval held outside the ledger is out of scope for this "
                                                         f"revision\"; the approval event carries {held_outside}")
        elif ev is not None:
            C.append("the approval event points to no approval held outside the ledger (5)")
    return {"result": "VERIFIED" if not F else "FAILED", "failures": F, "checks": C}


def parse_sign1(raw):
    """A tagged COSE_Sign1 (RFC 9052 Section 4.2): (protected bytes, protected map, unprotected, payload, signature)."""
    obj = cbor2.loads(raw)
    # cbor2 >= 6 hands back tuples and frozen maps for the items inside a tag: read sequences and mappings, not list and dict
    if not isinstance(obj, cbor2.CBORTag) or obj.tag != 18 or not isinstance(obj.value, (list, tuple)) or len(obj.value) != 4:
        raise ValueError("not a tagged COSE_Sign1")
    protected, unprotected, payload, signature = obj.value
    if not isinstance(protected, bytes) or not isinstance(unprotected, Mapping) or not isinstance(signature, bytes):
        raise ValueError("not a COSE_Sign1")
    pmap = cbor2.loads(protected) if protected else {}
    if not isinstance(pmap, Mapping):
        raise ValueError("the protected header is not a map")
    return protected, pmap, unprotected, payload, signature


def check_statement(statement, packet, *, public_key_hex, manifest_at_hand=True):
    """The Signed Statement of Section 6 against the packet it is said to register. public_key_hex: the receipt key
    resolved out of band, the same the packet verifier is given. Returns {result, failures, checks, read}."""
    F, C, R = [], [], {}
    try:
        protected, pmap, unprotected, payload, signature = parse_sign1(statement)
    except Exception as e:                                       # cbor2 raises several types on malformed input
        _fail(F, "STATEMENT_NOT_A_COSE_SIGN1", f"6: \"a COSE_Sign1 object as specified by [RFC9943]\": {e}")
        return {"result": "FAILED", "failures": F, "checks": C, "read": R}
    receipt = packet.get("receipt") if isinstance(packet, dict) else None
    manifest = packet.get("manifest") if isinstance(packet, dict) else None
    R.update(alg=pmap.get(1), content_type=pmap.get(3), kid=pmap.get(4).decode("utf-8", "replace") if isinstance(pmap.get(4), bytes) else pmap.get(4))
    # ---- the payload is the receipt's canonical bytes (reading R1: of the whole envelope)
    if not isinstance(payload, bytes):
        _fail(F, "STATEMENT_PAYLOAD_DETACHED", "6: \"whose payload is the receipt's canonical bytes\": no payload is attached")
    else:
        try:
            envelope_bytes = G.canonical(receipt)
            payload_bytes = G.canonical(receipt["payload"])
        except (G.Refuse, TypeError, KeyError) as e:
            envelope_bytes = payload_bytes = None
            _fail(F, "RECEIPT_NOT_CANONICALISABLE", f"4: {e}")
        if envelope_bytes is not None:
            if payload == envelope_bytes:
                C.append("the statement's payload is, byte for byte, the canonical bytes of the packet's receipt envelope (6, reading R1)")
            elif payload == payload_bytes:
                _fail(F, "STATEMENT_PAYLOAD_IS_THE_PAYLOAD_MEMBER_ALONE", "6, reading R1: the statement carries the canonical bytes of "
                                                                         "the receipt's payload member, without its signature; the "
                                                                         "other reading of \"the receipt's canonical bytes\"")
            else:
                _fail(F, "STATEMENT_PAYLOAD_NOT_THE_RECEIPT", "6: the statement's payload is not the canonical bytes of this packet's receipt")
    # ---- signed with the receipt's own signing key
    alg = pmap.get(1)
    if alg not in (ALG_ED25519, ALG_EDDSA):
        _fail(F, "STATEMENT_ALG", f"6, reading R2: alg is {alg!r}; an Ed25519 key signs under -19 or -8")
    elif isinstance(payload, bytes):
        tbs = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)      # RFC 9052 Section 4.4
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(signature, tbs)
            C.append(f"the statement's signature verifies, under alg {alg}, with the receipt key resolved out of band (6: "
                     "\"signed with the receipt's own signing key\")")
        except (InvalidSignature, ValueError):
            _fail(F, "STATEMENT_NOT_SIGNED_BY_THE_RECEIPT_KEY", "6: the statement's signature does not verify under the receipt's key")
    key_id = receipt.get("payload", {}).get("key_id") if isinstance(receipt, dict) and isinstance(receipt.get("payload"), dict) else None
    if not isinstance(pmap.get(4), bytes) or pmap.get(4) != (key_id or "").encode("utf-8"):
        _fail(F, "STATEMENT_KID_NOT_THE_RECEIPT_KEY_ID", "reading R4: the statement's kid is not the receipt's key_id as a byte string")
    else:
        C.append("the statement's kid is the receipt's key_id, as a byte string (reading R4)")
    # ---- the CWT claims: issuer supplied, subject the action identifier
    claims = pmap.get(15)
    claims = claims if isinstance(claims, Mapping) else {}
    R.update(iss=claims.get(1), sub=claims.get(2))
    if not isinstance(claims.get(1), str) or not claims.get(1):
        _fail(F, "STATEMENT_ISSUER_MISSING", "6: \"the CWT claims issuer set to an identifier the registering party supplies\"")
    else:
        C.append("the CWT claims carry an issuer (6)")
    expected_sub = manifest.get("action_id") if manifest_at_hand and isinstance(manifest, dict) else \
        (receipt["payload"].get("action_hash") if isinstance(receipt, dict) else None)
    if claims.get(2) != expected_sub or expected_sub is None:
        _fail(F, "STATEMENT_SUBJECT_NOT_THE_ACTION_IDENTIFIER", "6: \"subject set to the action identifier from the packet manifest, or "
                                                                "to the receipt's action_hash when no manifest is at hand\"; the "
                                                                f"subject is {claims.get(2)!r}")
    else:
        C.append("the subject is the action identifier of the packet manifest (6)" if manifest_at_hand else
                 "the subject is the receipt's action_hash, no manifest being at hand (6)")
    if unprotected:
        R["unprotected_header_not_empty"] = sorted(map(str, unprotected))
    return {"result": "VERIFIED" if not F else "FAILED", "failures": F, "checks": C, "read": R}
