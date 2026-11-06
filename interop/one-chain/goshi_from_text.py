#!/usr/bin/env python3
"""A verifier for a dispute evidence packet in the shape of draft-xg-payment-dispute-profile-01 (Goshi, 16 October
2026), a vendor profile of draft-farley-acta-signed-receipts-03 (Farley, 29 August 2026), written from the two texts
alone: no code of either author was read. Goshi's text describes an implementation (ActaSeal's DisputeEvidencePacket)
in prose and names its parts; where the prose names a field without defining its construction, this module fixes one
construction and says so in AMBIGUITIES. Section numbers refer to Goshi unless prefixed F- (Farley).

What the text lets a verifier re-derive (Section 5: "re-derivation, not trust"):
  - the receipt signature over canonical bytes (F-5.2: JCS of the payload member, Ed25519, key resolved out of band);
  - the receipt's payload shape of Section 3 (eleven members plus the base draft's type, issued_at, issuer_id);
  - event hashes and chain links of the ledger slice (Section 5, Section 4.4 "each custody event bound to a ledger
    event hash");
  - the scope verdict from the recorded intent scope and executed action (Section 4.2: in_scope, BREACH:<field>,
    not_evaluated; "MUST be re-derived by the verifier from recorded inputs, never asserted without re-derivation");
  - the settlement anchor hash (Section 4.3: "bound by an anchor_hash (a canonical hash of the anchor content)";
    absence MUST be stated as SETTLEMENT_UNANCHORED; a manifest without the block MUST fail);
  - headline consistency across manifest, receipt and ledger slice (Section 5).
Every failure is named (Section 5). The two names the text gives are SCOPE_HEADLINE_MISMATCH and
SETTLEMENT_ANCHOR_HASH_MISMATCH (Section 5) and SETTLEMENT_UNANCHORED (Section 4.3); every other name is this module's.
"""
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RECEIPT_TYPE = "actaseal:policy_decision"                       # Section 3
PROFILE_MEMBERS = ("decision", "reason_code", "action_hash", "evidence_set_hash", "ledger_entry_hash", "timestamp",
                   "mandate_hash", "rail_anchors_hash", "scope_conformance", "key_id", "signer_pubkey_hash")   # Section 3
BASE_MEMBERS = ("type", "issued_at", "issuer_id")               # F-2.2 REQUIRED members of every payload
DECISIONS = ("allow", "deny", "rate_limit", "require_approval")  # F-3.1.1
SETTLEMENT_MEMBERS = ("rail", "txn_ref", "finality_status", "amount_minor", "currency", "captured_at", "network", "payer")  # 4.3
AGENT_ANCHOR_MEMBERS = ("mandate_hash", "agent_id", "approval_event_hash", "receipt_signature", "network_token_id", "threeds_acs_result")  # 4.2
CE3_CATEGORIES = ("device_identity", "delivery_information", "additional_identity_factor")   # 4.1
TEXT_NAMED_FAILURES = ("SCOPE_HEADLINE_MISMATCH", "SETTLEMENT_ANCHOR_HASH_MISMATCH", "SETTLEMENT_UNANCHORED")

AMBIGUITIES = {
    "3 canonical form": "Section 3 says the payload is strings, null and nested objects/arrays of the same, amounts as decimal "
                        "strings, so JCS (RFC 8785) and codepoint-sorted compact JSON coincide. This module uses sorted-key compact "
                        "JSON, which is JCS over that value domain extended to integers below 2^53 (JCS formats those as plain "
                        "integers too; the intent scope carried in the manifest keeps the decision chain's integer amounts so that "
                        "its digest is the digest of the same bytes); it refuses a float, a boolean or a non-BMP key rather than "
                        "claim JCS for it.",
    "3 action_hash": "the text names action_hash without saying what is hashed. Farley's action_ref (F-2.2) hashes {agentId, "
                     "actionType, scopeRequired, timestamp}, which is a different thing (a correlation anchor). Here action_hash is "
                     "the SHA-256 of the executed action's argument bytes as the tool door hashed them, the same bytes the other "
                     "three links hash; a verifier cannot check this without the manifest saying so (manifest.executed_action).",
    "3 evidence_set_hash": "not defined in the text. Here: SHA-256 over the canonical JSON of the sorted list of every evidence "
                           "digest the packet cites (agent anchors, settlement anchor_hash, ledger entry). Re-derivable from the "
                           "manifest; the construction is this module's.",
    "3 ledger_entry_hash": "the text speaks of a ledger slice, ledger events and ledger event hashes (4.1, 4.4, 5) without a "
                           "format. Here a ledger event is {seq, type, at, data, prev_hash, event_hash}, event_hash = SHA-256 of the "
                           "canonical JSON of the event without event_hash, prev_hash the previous event_hash (genesis: 64 zeros); "
                           "ledger_entry_hash is the event_hash of the event that recorded the decision the receipt states.",
    "3 mandate_hash": "named as the AP2 mandate_hash (4.2). A chain whose mandate is a person's signed approval, not an AP2 "
                      "mandate, has no source for it: set to null, as 4.2 does for the network token id and the 3DS result when "
                      "the implementation has no source. Whether null is allowed for mandate_hash is not said.",
    "3 rail_anchors_hash": "a receipt member; the settlement block of 4.3 has its own anchor_hash. The text does not say they are "
                           "equal. Here rail_anchors_hash = the settlement anchor_hash, which is what lets Section 5's 'headline "
                           "consistency across manifest, receipt' be checked at all.",
    "3 key_id and signer_pubkey_hash": "key_id is taken as equal to the envelope's kid and the payload's issuer_id (F-2.2: issuer_id "
                                       "MUST match kid); signer_pubkey_hash as SHA-256 of the raw 32-byte Ed25519 public key, hex. "
                                       "Neither construction is in the text.",
    "3 timestamp and issued_at": "the profile lists timestamp and the base draft requires issued_at; both are carried, timestamp "
                                 "read as the time of the decision stated, issued_at as the time the receipt was signed.",
    "4.1 categories": "the CE 3.0 / FPT view is a mapping of what the packet holds into three named categories with gap notes; "
                      "the text defines no field names. Here: {category: {populated, value_or_null, gap_note}}. The verifier only "
                      "checks that a category marked populated has a value, that the dispute reason code is present (4.1: a missing "
                      "one MUST cause the mapper to raise), and that no category is populated from a source the manifest does not hold.",
    "4.2 approval event hash": "the text names an 'approval event hash' with no construction and no type. Here it is a typed "
                               "digest {type, alg, digest} so a verifier can know which bytes to look for; the type is this "
                               "repository's namespace. 4.2 says what the headline values are; it does not say which field of the "
                               "executed action a BREACH names when several differ (here: the first differing key in sorted order), "
                               "nor what intent scope and executed action look like (here: JSON objects carried in the manifest, "
                               "each bound by digest to an item the packet also cites).",
    "4.2 receipt_signature in agent_anchors": "the block lists 'receipt signature' among agent-native facts: read as the hex "
                                              "signature of the dispute receipt itself, which the block then repeats. A block that "
                                              "carries it must carry the same value as the envelope.",
    "4.3 anchor_hash": "'a canonical hash of the anchor content': here SHA-256 of the canonical JSON of the block without "
                       "anchor_hash (unanchored_fields included, since they are a statement about the content).",
    "4.3 settlement versus headline": "Section 5 asks for headline consistency; which headline the settlement amount is compared "
                                      "with is not said. Here: manifest.headline.amount_minor, which the manifest states as the "
                                      "amount in dispute; a mismatch is named SETTLEMENT_HEADLINE_MISMATCH (this module's name).",
    "4.4 wrapper": "acquisition record, custody record and authentication statement are described, not specified. Here: "
                   "acquisition {captured_by, captured_at, tool, clock_source, gaps[]} (gaps declared, custodian never "
                   "invented: captured_by MUST be present; 7: a host clock MUST be declared untrusted absent an external anchor), "
                   "custody [{event, at, actor, ledger_event_hash}], authentication_statement {re_derivable: [names of checks]}.",
    "5 failure names": "the text names failures by example. SCOPE_HEADLINE_MISMATCH, SETTLEMENT_ANCHOR_HASH_MISMATCH and "
                       "SETTLEMENT_UNANCHORED are the text's; every other code this verifier emits is its own.",
    "F-2.1 envelope": "the envelope shape only (payload + signature{alg, kid, sig}); the flat shape of F-2.1 and F-6.6 is refused, "
                      "not verified, since the profile's receipt is a 'canonical dict' under an envelope.",
}


class Refuse(Exception):
    pass


def canonical(value):
    """JCS over the value domain Section 3 states (strings, null, objects, arrays). Anything else is refused."""
    def walk(v, path):
        if isinstance(v, dict):
            for k in v:
                if not isinstance(k, str) or any(ord(c) > 0xFFFF for c in k):
                    raise Refuse(f"{path}: key outside the profile's value domain")
                walk(v[k], f"{path}/{k}")
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, f"{path}/{i}")
        elif isinstance(v, bool) or isinstance(v, float):
            raise Refuse(f"{path}: a float or boolean, outside the profile's value domain (amounts are decimal strings)")
        elif isinstance(v, int) and abs(v) >= 2 ** 53:
            raise Refuse(f"{path}: an integer beyond 2^53, where JCS number formatting and the host serializer part")
        elif v is not None and not isinstance(v, (str, int)):
            raise Refuse(f"{path}: unsupported value type {type(v).__name__}")
    walk(value, "")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def event_hash(event):
    return sha256_hex(canonical({k: v for k, v in event.items() if k != "event_hash"}))


def anchor_hash(block):
    return sha256_hex(canonical({k: v for k, v in block.items() if k != "anchor_hash"}))


def evidence_set_hash(digests):
    return sha256_hex(canonical(sorted(digests)))


def scope_verdict(intent_scope, executed_action):
    """Section 4.2: the intent-scope vs executed-action diff. in_scope when every key of the intent scope has the same
    value in the executed action and the executed action has no key the intent scope lacks; BREACH:<field> naming the
    first differing key in sorted order; not_evaluated when either side is missing."""
    if not isinstance(intent_scope, dict) or not isinstance(executed_action, dict):
        return "not_evaluated"
    for k in sorted(set(intent_scope) | set(executed_action)):
        if intent_scope.get(k) != executed_action.get(k):
            return f"BREACH:{k}"
    return "in_scope"


def verify_packet(packet, *, public_key_hex, held=None, dispute_reason_code_required=True):
    """packet: {receipt, manifest, ledger_slice, fre901}. public_key_hex: the receipt key resolved out of band (F-5.2
    step 4: never from the receipt itself; manifest.receipt_public_key_hex is a hint the verifier decides to trust or
    not). held: dict type -> set of hex digests of the items the verifier holds, to resolve the agent anchors against
    (an anchor whose digest is not held is named, not failed: the text says what the anchors are, not that a verifier
    holds them). Returns {result, failures, checks, re_derived}."""
    F, C, R = [], [], {}

    def fail(code, why):
        F.append({"code": code, "why": why, "named_in_text": code in TEXT_NAMED_FAILURES})

    def ok(what):
        C.append(what)

    receipt, manifest, ledger, fre = packet.get("receipt"), packet.get("manifest"), packet.get("ledger_slice"), packet.get("fre901")
    # ---- F-2.1, F-5.2: the envelope and the signature over the canonical payload
    if not isinstance(receipt, dict) or set(receipt) != {"payload", "signature"}:
        fail("RECEIPT_SHAPE", "F-2.1: the envelope is {payload, signature}; the flat shape is not this profile's")
        return {"result": "FAILED", "failures": F, "checks": C, "re_derived": R}
    sig, payload = receipt["signature"], receipt["payload"]
    if not isinstance(sig, dict) or set(sig) != {"alg", "kid", "sig"}:
        fail("RECEIPT_SIGNATURE_OBJECT", "F-2.1.1: alg, kid, sig REQUIRED")
    elif sig["alg"] != "EdDSA":
        fail("RECEIPT_ALG", f"F-2.1.1 / 3: alg is {sig['alg']!r}, this profile's is EdDSA")
    else:
        try:
            cb = canonical(payload)
            if sig["sig"] != sig["sig"].lower() or len(sig["sig"]) != 128:
                fail("RECEIPT_SIGNATURE_ENCODING", "3: Ed25519, lowercase hex (F-2.1.1: not rejected on length alone, here on both)")
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(bytes.fromhex(sig["sig"]), cb)
            ok("receipt signature verified over the canonical payload bytes with the key resolved out of band (F-5.2 steps 2-5)")
            R["canonical_payload_sha256"] = sha256_hex(cb)
        except Refuse as e:
            fail("RECEIPT_PAYLOAD_VALUE_DOMAIN", f"3: {e}")
        except (InvalidSignature, ValueError):
            fail("RECEIPT_SIGNATURE_INVALID", "F-5.2 step 6: the signature does not verify over the canonical payload; the receipt MUST be rejected")
    # ---- 3: the payload members
    if isinstance(payload, dict):
        missing = [m for m in BASE_MEMBERS + PROFILE_MEMBERS if m not in payload]
        if missing:
            fail("RECEIPT_MEMBER_MISSING", f"3 / F-2.2: {missing}")
        else:
            ok("the receipt carries the three base members and the eleven profile members of Section 3")
        if payload.get("type") != RECEIPT_TYPE:
            fail("RECEIPT_TYPE", f"3: type is {payload.get('type')!r}, this profile's is {RECEIPT_TYPE}")
        if payload.get("decision") not in DECISIONS:
            fail("RECEIPT_DECISION_VALUE", f"F-3.1.1: decision is {payload.get('decision')!r}")
        if isinstance(sig, dict) and not (payload.get("issuer_id") == sig.get("kid") == payload.get("key_id")):
            fail("RECEIPT_ISSUER_KID_MISMATCH", "F-2.2: issuer_id MUST match the signature's kid (and 3: key_id, read as the same)")
        if payload.get("signer_pubkey_hash") != sha256_hex(bytes.fromhex(public_key_hex)):
            fail("RECEIPT_SIGNER_PUBKEY_HASH", "3: signer_pubkey_hash is not the SHA-256 of the key resolved (this module's construction)")
        if payload.get("reason_code") in (None, ""):
            fail("RECEIPT_REASON_CODE_MISSING", "3: reason_code is a member of the canonical dict; empty here")
    if not isinstance(manifest, dict):
        fail("MANIFEST_MISSING", "4.3: a manifest without the settlement block MUST fail; there is no manifest at all")
        return {"result": "FAILED", "failures": F, "checks": C, "re_derived": R}
    # ---- 4.3: the settlement anchor
    sa = manifest.get("settlement_anchor")
    if not isinstance(sa, dict):
        fail("SETTLEMENT_UNANCHORED", "4.3: the manifest has no settlement_anchor block")
    else:
        miss = [m for m in SETTLEMENT_MEMBERS + ("unanchored_fields", "anchor_hash") if m not in sa]
        if miss:
            fail("SETTLEMENT_ANCHOR_MEMBER_MISSING", f"4.3: {miss}")
        else:
            try:
                if anchor_hash(sa) != sa["anchor_hash"]:
                    fail("SETTLEMENT_ANCHOR_HASH_MISMATCH", "4.3 / 5: the anchor_hash does not recompute over the block's content")
                else:
                    ok("settlement anchor_hash recomputed over the block's content (4.3)")
            except Refuse as e:
                fail("SETTLEMENT_ANCHOR_VALUE_DOMAIN", str(e))
            for f in sa["unanchored_fields"]:
                if f in SETTLEMENT_MEMBERS and sa.get(f) is not None:
                    fail("SETTLEMENT_UNANCHORED_FIELD_HAS_VALUE", f"4.3: {f} is named unanchored and carries a value")
            if isinstance(payload, dict) and payload.get("rail_anchors_hash") != sa.get("anchor_hash"):
                fail("RAIL_ANCHORS_HASH_MISMATCH", "3 / 4.3: the receipt's rail_anchors_hash is not the settlement anchor_hash (this module's reading)")
            head = manifest.get("headline", {})
            if sa.get("amount_minor") != head.get("amount_minor") or sa.get("currency") != head.get("currency"):
                fail("SETTLEMENT_HEADLINE_MISMATCH", f"5: what moved ({sa.get('amount_minor')} {sa.get('currency')}) is not the manifest's "
                                                     f"headline amount ({head.get('amount_minor')} {head.get('currency')})")
            else:
                ok("settlement amount and currency equal the manifest's headline amount (5: headline consistency)")
    # ---- ledger slice: event hashes and chain links (5, 4.4)
    events = ledger if isinstance(ledger, list) else []
    hashes = set()
    prev = "0" * 64
    chain_ok = bool(events)
    for i, ev in enumerate(events):
        try:
            if ev.get("event_hash") != event_hash(ev):
                fail("LEDGER_EVENT_HASH_MISMATCH", f"5: event {i} ({ev.get('type')}) does not recompute")
                chain_ok = False
            if ev.get("prev_hash") != prev:
                fail("LEDGER_CHAIN_BROKEN", f"5: event {i} does not link to event {i - 1}")
                chain_ok = False
        except Refuse as e:
            fail("LEDGER_EVENT_VALUE_DOMAIN", f"event {i}: {e}")
            chain_ok = False
        prev = ev.get("event_hash", "")
        hashes.add(prev)
    if chain_ok:
        ok(f"{len(events)} ledger events recompute and link (5)")
    if isinstance(payload, dict) and payload.get("ledger_entry_hash") not in hashes:
        fail("LEDGER_ENTRY_HASH_UNKNOWN", "3: the receipt's ledger_entry_hash is not an event of the ledger slice")
    # ---- 4.2: agent anchors and the scope verdict re-derived
    aa = manifest.get("agent_anchors")
    if not isinstance(aa, dict) or set(aa) != set(AGENT_ANCHOR_MEMBERS):
        fail("AGENT_ANCHORS_SHAPE", f"4.2: the block's shape is {list(AGENT_ANCHOR_MEMBERS)}")
    else:
        if isinstance(sig, dict) and aa.get("receipt_signature") != sig.get("sig"):
            fail("AGENT_ANCHORS_RECEIPT_SIGNATURE", "4.2: the block's receipt signature is not the envelope's")
        if isinstance(payload, dict) and aa.get("mandate_hash") != payload.get("mandate_hash"):
            fail("MANDATE_HASH_INCONSISTENT", "3 / 4.2: mandate_hash differs between receipt and block")
        R["anchors"] = []
        for name in ("approval_event_hash",) + tuple(k for k in manifest.get("further_anchors", {})):
            ref = aa.get(name) if name == "approval_event_hash" else manifest["further_anchors"][name]
            if not isinstance(ref, dict) or set(ref) != {"type", "alg", "digest"}:
                fail("ANCHOR_SHAPE", f"4.2: {name} is not a typed digest {{type, alg, digest}} (this module's reading)")
                continue
            state = "not resolved: verifier holds nothing of that type" if held is None or ref["type"] not in held else \
                ("resolved" if ref["digest"] in held[ref["type"]] else "not held")
            if state == "not held":
                fail("ANCHOR_UNRESOLVED", f"{name}: no item of type {ref['type']} held has digest {ref['digest'][:16]}...")
            R["anchors"].append({"name": name, **ref, "state": state})
    intent, executed = manifest.get("intent_scope"), manifest.get("executed_action")
    derived = scope_verdict(intent, executed)
    R["scope_conformance"] = derived
    head_scope = manifest.get("headline", {}).get("scope_conformance")
    if isinstance(payload, dict):
        if payload.get("scope_conformance") != derived or head_scope != derived:
            fail("SCOPE_HEADLINE_MISMATCH", f"4.2 / 5: re-derived {derived!r}; receipt says {payload.get('scope_conformance')!r}, "
                                            f"manifest headline {head_scope!r}")
        else:
            ok(f"scope verdict re-derived from intent scope and executed action: {derived}; receipt and manifest headline agree (4.2, 5)")
        # the executed action and the intent scope are bound to the items the packet cites
        for which, obj, dkey in (("intent_scope", intent, "intent_scope_sha256"), ("executed_action", executed, "executed_action_sha256")):
            try:
                if manifest.get(dkey) != sha256_hex(canonical(obj)):
                    fail("SCOPE_INPUT_DIGEST_MISMATCH", f"4.2: {which} does not hash to manifest.{dkey}")
            except Refuse as e:
                fail("SCOPE_INPUT_VALUE_DOMAIN", f"{which}: {e}")
        if payload.get("action_hash") != manifest.get("executed_action_sha256"):
            fail("ACTION_HASH_MISMATCH", "3: action_hash is not the digest of the executed action the manifest records (this module's construction)")
        # evidence_set_hash over what the packet cites
        cited = []
        if isinstance(aa, dict) and isinstance(aa.get("approval_event_hash"), dict):
            cited.append(aa["approval_event_hash"].get("digest"))
        cited += [r.get("digest") for r in manifest.get("further_anchors", {}).values() if isinstance(r, dict)]
        if isinstance(sa, dict):
            cited.append(sa.get("anchor_hash"))
        cited.append(payload.get("ledger_entry_hash"))
        if payload.get("evidence_set_hash") != evidence_set_hash([c for c in cited if c]):
            fail("EVIDENCE_SET_HASH_MISMATCH", "3: evidence_set_hash does not recompute over the digests the packet cites (this module's construction)")
        else:
            ok("evidence_set_hash recomputed over the digests the packet cites")
    # ---- 4.1: the categories
    cats = manifest.get("ce3_fpt_categories")
    if not isinstance(cats, dict) or set(cats) != set(CE3_CATEGORIES):
        fail("CATEGORIES_SHAPE", f"4.1: three categories {list(CE3_CATEGORIES)}")
    else:
        for c, v in cats.items():
            if v.get("populated") and v.get("value") in (None, ""):
                fail("CATEGORY_POPULATED_WITHOUT_VALUE", f"4.1: {c} marked populated with no value (the mapper MUST NOT invent evidence)")
            if not v.get("populated") and not v.get("gap_note"):
                fail("CATEGORY_GAP_UNDECLARED", f"4.1: {c} unpopulated without a gap note")
    if dispute_reason_code_required and not manifest.get("dispute_reason_code"):
        fail("DISPUTE_REASON_CODE_MISSING", "4.1: a missing dispute reason code MUST cause the mapper to raise rather than pass silently")
    # ---- 4.4: the FRE 901 wrapper
    if not isinstance(fre, dict) or set(fre) != {"acquisition", "custody", "authentication_statement"}:
        fail("FRE901_SHAPE", "4.4: acquisition record, custody record, authentication statement")
    else:
        acq = fre["acquisition"]
        if not all(acq.get(k) for k in ("captured_by", "captured_at", "tool", "clock_source")) or "gaps" not in acq:
            fail("ACQUISITION_INCOMPLETE", "4.4: who, when, with what tool and clock source; gaps declared")
        if "untrusted" not in str(acq.get("clock_source", "")) and not acq.get("external_time_anchor"):
            fail("CLOCK_NOT_DECLARED_UNTRUSTED", "7: absent an external anchor proof, the host clock MUST be declared untrusted")
        unbound = [c for c in fre["custody"] if c.get("ledger_event_hash") not in hashes]
        if unbound:
            fail("CUSTODY_EVENT_UNBOUND", f"4.4: {len(unbound)} custody event(s) not bound to a ledger event hash of the slice")
        elif fre["custody"]:
            ok(f"{len(fre['custody'])} custody events each bound to a ledger event hash (4.4)")
        if not isinstance(fre["authentication_statement"].get("re_derivable"), list) or not fre["authentication_statement"]["re_derivable"]:
            fail("AUTHENTICATION_STATEMENT_EMPTY", "4.4: it names exactly what a challenger can independently re-derive")
    return {"result": "FAILED" if F else "VERIFIED", "failures": F, "checks": C, "re_derived": R}
