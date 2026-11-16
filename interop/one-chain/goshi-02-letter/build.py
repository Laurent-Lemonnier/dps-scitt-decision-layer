#!/usr/bin/env python3
"""A second dispute packet for the action of the one chain (the refund of 120.00 EUR on order 8812), built to the letter
of draft-xg-payment-dispute-profile-02 (16 November 2026) as we read it, and its Signed Statement of Section 6.

It starts from the published packet of the parent case, ../out/positive/dispute-packet.json, which is not changed, and
keeps what that packet records of the action (the intent scope, the executed action, the settlement anchor, the ledger's
events, the digests of the verdict record and of the other records of the chain). What differs:

  - the receipt payload has the eleven members of Section 4 and no other (the parent's also carries type, issued_at and
    issuer_id, the members of the base draft that -01 required);
  - the manifest names draft-xg-payment-dispute-profile-02 and no base draft;
  - the ApprovalGranted event no longer carries dps_approval, the pointer to the approval held outside the ledger
    (Section 5: "out of scope for this revision"); the ledger is chained again from that event on;
  - the receipt is signed with a key made for this case, whose seed is public (TEST ONLY);
  - the Signed Statement of Section 6: a COSE_Sign1 whose payload is the receipt's canonical bytes, signed with that
    same key, subject the manifest's action identifier.

The packet is verified by ../goshi_from_text.py as published (unchanged), then by the two checks of letter.py. What the
text leaves open and the choice made each time: letter.READINGS. Synthetic data, fixed times, deterministic output.
Never use the key for anything real. Exit 0 when the three reports say VERIFIED and the comparisons with the parent
packet hold.
"""
import copy
import hashlib
import json
import pathlib
import sys

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import letter as L

HERE = pathlib.Path(__file__).resolve().parent
ONE = HERE.parent
G = L.G

# ---- the key of this case. TEST ONLY: the seed is the SHA-256 of the label below, so anyone can sign with it.
SEED_LABEL = "dps-scitt-decision-layer one-chain/goshi-02-letter: dispute receipt key (TEST ONLY, public seed) v1"
OTHER_SEED_LABEL = "dps-scitt-decision-layer one-chain/goshi-02-letter: a key of nobody (TEST ONLY, public seed) v1"
KEY_ID = "one-chain-goshi-02-letter-test-key-1"
ISSUER = "urn:example:merchant:dispute-desk"                    # reading R5
PACKET_TIME = "2026-11-16T21:30:00Z"                            # when the fictional desk assembled this packet (its claim)


def key_from_label(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


receipt_key, other_key = key_from_label(SEED_LABEL), key_from_label(OTHER_SEED_LABEL)
PUBLIC_KEY_HEX = raw_public(receipt_key).hex()


def parent_packet():
    return json.loads((ONE / "out" / "positive" / "dispute-packet.json").read_text(encoding="utf-8"))


def options():
    """Every part as data; negatives.py changes one at a time."""
    return {"profile": L.PROFILE_02,
            "extra_member": None,                # (name, value) added to the payload before signing
            "drop_member": None,                 # a member removed from the payload before signing
            "mandate_hash": None,                # the value of mandate_hash in the receipt and in the agent anchors
            "approval_held_outside": False,      # True: the ApprovalGranted event keeps the parent's dps_approval
            "sign_with": "receipt",              # receipt | other: the key that signs the receipt
            "declared_key": "receipt",           # receipt | other: the key the manifest and signer_pubkey_hash name
            "statement_key": "receipt",          # receipt | other: the key that signs the Signed Statement
            "statement_subject": None,           # None: the manifest's action_id
            "statement_issuer": ISSUER,          # None: no iss in the CWT claims
            "statement_payload": "envelope",     # envelope | payload_member | packet | indented | parent_receipt
            "statement_alg": L.ALG_ED25519}


def build_packet(p):
    old = parent_packet()
    om, of = old["manifest"], old["fre901"]
    action_id = om["action_id"]
    # ---- the ledger slice: the parent's events, the approval event without the approval held outside, chained again
    events, new_hash = [], {}
    for ev in old["ledger_slice"]:
        data = copy.deepcopy(ev["data"])
        if ev["type"] == "ApprovalGranted" and not p["approval_held_outside"]:
            data.pop("dps_approval")
        new = {"seq": str(len(events)), "action_id": ev["action_id"], "type": ev["type"], "at": ev["at"], "data": data,
               "prev_hash": events[-1]["event_hash"] if events else "0" * 64}
        new["event_hash"] = G.event_hash(new)
        new_hash[ev["event_hash"]] = new["event_hash"]
        events.append(new)
    approval_ev = next(e for e in events if e["type"] == "ApprovalGranted")
    exec_ev = next(e for e in events if e["type"] == "ActionExecuted")
    scope_ev = next(e for e in events if e["type"] == "ScopeEvaluated")
    block = copy.deepcopy(om["settlement_anchor"])               # {status: "anchored", anchor, anchor_hash}: unchanged
    further = copy.deepcopy(om["further_anchors"])
    cited = [approval_ev["event_hash"]] + [r["digest"] for r in further.values()] + [block["anchor_hash"], exec_ev["event_hash"]]
    declared = receipt_key if p["declared_key"] == "receipt" else other_key
    # ---- Section 4: the eleven members, and no other
    payload = {"decision": "allow", "reason_code": "approved_by_accountable_person",
               "action_hash": scope_ev["data"]["action_hash"],
               "evidence_set_hash": G.evidence_set_hash(cited),                  # reading R8: ours, signed, not reported as checked
               "ledger_entry_hash": exec_ev["event_hash"],
               "timestamp": old["receipt"]["payload"]["timestamp"],              # the moment of the decision, as the producer claims it
               "mandate_hash": p["mandate_hash"],                                # reading R7
               "rail_anchors_hash": block["anchor_hash"],                        # reading R8
               "scope_conformance": om["headline"]["scope_conformance"],
               "key_id": KEY_ID,
               "signer_pubkey_hash": G.sha256_hex(raw_public(declared))}
    if p["extra_member"]:
        payload[p["extra_member"][0]] = p["extra_member"][1]
    if p["drop_member"]:
        del payload[p["drop_member"]]
    signer = receipt_key if p["sign_with"] == "receipt" else other_key
    sig_hex = signer.sign(G.canonical(payload)).hex()
    receipt = {"payload": payload, "signature": {"alg": "EdDSA", "kid": KEY_ID, "sig": sig_hex}}
    manifest = {"profile": p["profile"],
                "constructions": "draft-xg-payment-dispute-profile-02 Section 5 for action_hash, scope_hash, ledger_entry_hash, the "
                                 "approval event hash, signer_pubkey_hash and anchor_hash; evidence_set_hash and rail_anchors_hash are "
                                 "this builder's (Section 5 does not construct them); the manifest, the ledger slice and the event "
                                 "hash are the shapes of the parent case (Appendix B: named but not yet defined)",
                "action_id": action_id,
                "dispute_reason_code": om["dispute_reason_code"],
                "receipt_public_key_hex": raw_public(declared).hex(),
                "headline": copy.deepcopy(om["headline"]),
                "agent_anchors": {"mandate_hash": p["mandate_hash"], "agent_id": om["agent_anchors"]["agent_id"],
                                  "approval_event_hash": approval_ev["event_hash"], "receipt_signature": sig_hex,
                                  "network_token_id": None, "threeds_acs_result": None},
                "further_anchors": further,
                "intent_scope": copy.deepcopy(om["intent_scope"]), "intent_scope_sha256": om["intent_scope_sha256"],
                "intent_scope_source": copy.deepcopy(om["intent_scope_source"]),
                "executed_action": copy.deepcopy(om["executed_action"]), "executed_action_sha256": om["executed_action_sha256"],
                "executed_action_source": copy.deepcopy(om["executed_action_source"]),
                "settlement_anchor": block,
                "ce3_fpt_categories": copy.deepcopy(om["ce3_fpt_categories"])}
    fre = {"acquisition": {"captured_by": ISSUER, "captured_at": PACKET_TIME, "tool": "one-chain/goshi-02-letter/build.py (synthetic)",
                           "clock_source": "host clock, declared untrusted (no external time anchor inside the packet)",
                           "gaps": ["no RFC 3161 or SCITT time anchor inside the packet; the receipt's registration is outside it"]},
           "custody": [dict(c, ledger_event_hash=new_hash[c["ledger_event_hash"]]) for c in of["custody"]],
           "authentication_statement": copy.deepcopy(of["authentication_statement"])}
    return {"receipt": receipt, "manifest": manifest, "ledger_slice": events, "fre901": fre}


def sign1(key, protected_map, payload):
    protected = cbor2.dumps(protected_map, canonical=True)
    tbs = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)          # RFC 9052 Section 4.4
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, key.sign(tbs)]), canonical=True)


def build_statement(packet, p):
    """Section 6: a COSE_Sign1 whose payload is the receipt's canonical bytes, signed with the receipt's own signing
    key, CWT claims issuer supplied by the registering party, subject the manifest's action identifier."""
    receipt = packet["receipt"]
    payload = {"envelope": lambda: G.canonical(receipt),                                  # reading R1
               "payload_member": lambda: G.canonical(receipt["payload"]),
               "packet": lambda: (json.dumps(packet, ensure_ascii=False, indent=1) + "\n").encode("utf-8"),
               "indented": lambda: (json.dumps(receipt, ensure_ascii=False, indent=1) + "\n").encode("utf-8"),
               "parent_receipt": lambda: G.canonical(parent_packet()["receipt"])}[p["statement_payload"]]()
    claims = {2: p["statement_subject"] or packet["manifest"]["action_id"]}
    if p["statement_issuer"]:
        claims[1] = p["statement_issuer"]
    protected = {1: p["statement_alg"], 3: L.CONTENT_TYPE, 4: KEY_ID.encode("utf-8"), 15: claims}
    return sign1(receipt_key if p["statement_key"] == "receipt" else other_key, protected, payload)


def held_from_parent(packet):
    """The records of the chain a verifier of this packet can hold from ../out/positive, by the SHA-256 of their bytes."""
    fa = packet["manifest"]["further_anchors"]
    pos = ONE / "out" / "positive"
    return {fa["verdict_record"]["type"]: {G.sha256_hex((pos / "verdict-record.json").read_bytes())},
            fa["signatures_attachment"]["type"]: {G.sha256_hex((pos / "signatures-attachment.json").read_bytes())}}


def verify(packet, statement):
    """The three reports: the packet verifier of the parent directory as published, the letter, the statement."""
    return {"reader": G.verify_packet(packet, public_key_hex=PUBLIC_KEY_HEX, held=held_from_parent(packet)),
            "letter": L.check_letter(packet),
            "statement": L.check_statement(statement, packet, public_key_hex=PUBLIC_KEY_HEX)}


def same_action(packet):
    """This packet and the parent's are about the same action: what is equal, what differs."""
    old = parent_packet()
    op, np_, om, nm = old["receipt"]["payload"], packet["receipt"]["payload"], old["manifest"], packet["manifest"]
    return {"action_id equal": om["action_id"] == nm["action_id"],
            "action_hash equal": op["action_hash"] == np_["action_hash"],
            "intent scope and executed action equal": (om["intent_scope"], om["executed_action"]) == (nm["intent_scope"], nm["executed_action"]),
            "settlement anchor block equal": om["settlement_anchor"] == nm["settlement_anchor"],
            "verdict record digest equal": om["further_anchors"]["verdict_record"] == nm["further_anchors"]["verdict_record"],
            "scope_conformance equal": op["scope_conformance"] == np_["scope_conformance"] == "in_scope",
            "producer-claimed timestamp equal": op["timestamp"] == np_["timestamp"],
            "receipt keys differ": om["receipt_public_key_hex"] != nm["receipt_public_key_hex"],
            "ledger_entry_hash differs (the ledger was chained again)": op["ledger_entry_hash"] != np_["ledger_entry_hash"]}


def main():
    out = HERE / "out"
    out.mkdir(exist_ok=True)
    p = options()
    packet = build_packet(p)
    statement = build_statement(packet, p)
    reports = verify(packet, statement)
    R = G.canonical(packet["receipt"])                            # the envelope's canonical bytes, the statement's payload
    cb = G.canonical(packet["receipt"]["payload"])
    (out / "dispute-packet.json").write_text(json.dumps(packet, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    (out / "dispute-receipt.json").write_bytes(R)
    (out / "dispute-receipt.canonical-payload.json").write_bytes(cb)
    (out / "section-6.signed-statement.cose").write_bytes(statement)
    (out / "keys.json").write_text(json.dumps({
        "note": "TEST ONLY. The seed is public: it MUST NOT be used to sign anything other than test material.",
        "seed_label": SEED_LABEL, "seed_hex_sha256_of_the_label": hashlib.sha256(SEED_LABEL.encode()).hexdigest(),
        "ed25519_public_key_raw_hex": PUBLIC_KEY_HEX, "key_id": KEY_ID,
        "ed25519_public_key_pem": receipt_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}, indent=1) + "\n")
    protected = cbor2.loads(cbor2.loads(statement).value[0])
    same = same_action(packet)
    summary = {
        "built_to": "the letter of draft-xg-payment-dispute-profile-02 as we read it (letter.READINGS); not a claim of conformance",
        "receipt": {"members": sorted(packet["receipt"]["payload"]), "member_count": len(packet["receipt"]["payload"]),
                    "envelope_octets": len(R), "canonical_payload_octets": len(cb),
                    "sha256_envelope": G.sha256_hex(R), "sha256_canonical_payload": G.sha256_hex(cb),
                    "appendix_a_form_leaf_hash_sha256_00_envelope": G.sha256_hex(b"\x00" + R)},
        "statement": {"octets": len(statement), "sha256": G.sha256_hex(statement),
                      "protected_header": {"1 alg": protected[1], "3 content type": protected[3], "4 kid": protected[4].decode(),
                                           "15 CWT claims": {"1 iss": protected[15][1], "2 sub": protected[15][2]}},
                      "entry_id_on_a_log_whose_leaf_is_the_statement_sha256_00_statement": G.sha256_hex(b"\x00" + statement)},
        "reports": reports,
        "same_action_as_the_parent_packet": same,
        "readings": L.READINGS,
        "all_verified": all(r["result"] == "VERIFIED" for r in reports.values()) and all(same.values())}
    (out / "result.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("built_to", "receipt", "statement", "same_action_as_the_parent_packet", "all_verified")}
                     | {"results": {k: v["result"] for k, v in reports.items()},
                        "failures": {k: [f["code"] for f in v["failures"]] for k, v in reports.items()}}, indent=1))
    return 0 if summary["all_verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
