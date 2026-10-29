#!/usr/bin/env python3
"""Case 08: a decision of the Decision Provenance Standard bound to an AI-Agent Action Receipt of the NOA Mandate
profile (draft-noa-scitt-ai-agent-receipt-01), the way its author described on 2026-10-29: the receipt is a closed
object, so the reference cannot go inside it; a separate SCITT Signed Statement carries typed digest references to the
receipt and to the decision record (and to the action-binding attachment), the receipt and its envelope bytes unchanged.

The receipt side: the published conformance vectors of noa-mandate-core at commit 6642fb2 (valid-chain.json, three
noa.receipt/0.1 receipts; keyring.json, test key noa-test-key-2026). The reference's digest for a receipt is the value
the profile defines: "sha256:" followed by the lowercase hex of SHA-256 over UTF8(JCS(receipt with only chain.hash and
sig.value removed)), which for a valid receipt equals its chain.hash; the declaration keeps that prefixed form as the
representation for this type, and the reference binds the receipt object, not the signed file nor any COSE wrapper.

The decision side: the record and attachment of case 01 (a signed approval), cited by the Standard's two names.

Built: a Signed Statement (RFC 9943 form, scitt-cose) over a small JSON binding payload, with the three references in
the protected cpb-refs header (CPB -06 Section 9.3; label TBD1, private-use -65537 in this fixture), marked critical.
Verified: the statement's signature; each reference resolved under its declared context (the receipt by recomputing the
profile's digest from the receipt bytes held; the record by its seal; the attachment by the SHA-256 of its bytes).
Negatives: the receipt's digest altered in the reference (Failed); a receipt whose bytes were changed after the
reference was made (Failed, and the receipt's chain.hash no longer recomputes either); a reference naming the
receipt by the digest of its signed file instead of the profile's value (Failed: a different object).
Writes everything under cases/08-noa-receipt/.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scitt_cose.cose_sign1 import CoseError, sign_sign1, strict_decode, verify_sign1

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "cases" / "01-valid"
NOA = HERE / "noa"
OUT = HERE / "cases" / "08-noa-receipt"
OUT.mkdir(parents=True, exist_ok=True)
spec = importlib.util.spec_from_file_location("aq", "/root/claude-ops/ietf/demo/interop/aqta/aqta_verify_independent.py")
AQ = importlib.util.module_from_spec(spec); spec.loader.exec_module(AQ)   # its canonical() is RFC 8785

CPB_REFS_LABEL, HDR_CRIT = -65537, 2
NOA_COMMIT = "6642fb238bb33a0bcda53c175c0d4a7683d95dcd"
NOA_TYPE = "noa.receipt/0.1"     # the "spec" identifier the receipts carry; confirmed as the type token by the profile author (29/10/2026)
NOA_SIG_TAG = "NOA-Receipt-v0.1-sig:".encode("utf-8")   # 21-byte domain tag, docs/receipt-spec.md "Hashing rule (frozen)" at NOA_COMMIT


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def noa_digest(receipt):
    """The profile's value: 'sha256:' + hex SHA-256 over UTF8(JCS(receipt with only chain.hash and sig.value removed))."""
    body = copy.deepcopy(receipt)
    del body["chain"]["hash"]
    del body["sig"]["value"]
    return "sha256:" + sha256(AQ.canonical(body).encode("utf-8"))


def noa_signature_verifies(receipt, keyring, message="tag||raw"):
    """The receipt's own signature: Ed25519 (RFC 8032, pure) over UTF8("NOA-Receipt-v0.1-sig:") || the raw 32-byte
    SHA-256 of UTF8(JCS(receipt without chain.hash and sig.value)), as the profile author stated it on 29/10/2026.
    The two other messages are kept as negatives: the tag followed by the hex digest, and the bare digest."""
    import base64
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    body = copy.deepcopy(receipt)
    del body["chain"]["hash"]
    del body["sig"]["value"]
    digest = hashlib.sha256(AQ.canonical(body).encode("utf-8")).digest()
    msg = {"tag||raw": NOA_SIG_TAG + digest, "tag||hex": NOA_SIG_TAG + digest.hex().encode("ascii"), "raw": digest}[message]
    try:
        load_der_public_key(base64.b64decode(keyring[receipt["sig"]["kid"]])).verify(base64.b64decode(receipt["sig"]["value"]), msg)
        return True
    except Exception:
        return False


# ---- the receipt (seq 2, the chain's head) and the decision documents; the vectors are fetched at the pinned commit
import urllib.request
NOA.mkdir(exist_ok=True)
for name in ("valid-chain.json", "keyring.json"):
    if not (NOA / name).exists():
        urllib.request.urlretrieve(f"https://raw.githubusercontent.com/NordenSoft/noa-mandate-core/{NOA_COMMIT}/conformance/vectors/{name}", NOA / name)
chain = json.loads((NOA / "valid-chain.json").read_text())
receipt = chain[2]
receipt_bytes = json.dumps(receipt, separators=(",", ":"), ensure_ascii=False).encode("utf-8")   # the bytes we hold
record_bytes = (SRC / "decision-record.json").read_bytes()
attachment_bytes = (SRC / "action-binding-attachment.json").read_bytes()
record = json.loads(record_bytes)
held = {NOA_TYPE: lambda: noa_digest(json.loads(receipt_bytes)),
        "org.decisionprovenancestandard.decision_record": lambda: record["seal_hash"],
        "org.decisionprovenancestandard.action_binding_attachment": lambda: sha256(attachment_bytes)}
representation = {NOA_TYPE: "sha256-prefixed", "org.decisionprovenancestandard.decision_record": "hex",
                  "org.decisionprovenancestandard.action_binding_attachment": "hex"}
chain_ok = all(noa_digest(r) == r["chain"]["hash"] for r in chain) and all(
    chain[i]["chain"]["prevHash"] == chain[i - 1]["chain"]["hash"] for i in range(1, len(chain)))

# ---- the binding statement
key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"dps-noa interop case 08 issuer key (test only)").digest())
pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
refs = [{1: NOA_TYPE, 2: "acted_as", 3: "SHA-256", 4: noa_digest(receipt)},
        {1: "org.decisionprovenancestandard.decision_record", 2: "ran_under", 3: "SHA-256", 4: record["seal_hash"]},
        {1: "org.decisionprovenancestandard.action_binding_attachment", 2: "acted_on", 3: "SHA-256", 4: sha256(attachment_bytes)}]
payload = json.dumps({"binding": "a NOA Mandate receipt to the decision it executed", "receipt_id": receipt["id"],
                      "decision_id": record["decision_id"]}, separators=(",", ":")).encode()


def statement(entries):
    protected = {3: "application/json", 4: pub, 15: {1: "urn:isoluce:noa-interop:binder", 2: receipt["id"]},
                 CPB_REFS_LABEL: entries, HDR_CRIT: [CPB_REFS_LABEL]}
    return sign_sign1(payload, alg="EdDSA", private_key_pem=pem, protected=protected, unprotected={})


def read_refs(protected):
    value = protected.get(CPB_REFS_LABEL)
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        return "Malformed", []
    out = []
    for m in value:
        if not isinstance(m, dict) or set(m) - {1, 2, 3, 4} or not {1, 3, 4} <= set(m):
            return "Malformed", []
        out.append({"type": m[1], "purpose": m.get(2), "digest_alg": m[3], "digest": m[4]})
    return "ok", out


def resolve(entries, held_values):
    res = []
    for e in entries:
        if e["type"] not in held_values:
            res.append((e["type"], "Unresolved", "context: type not accepted by this profile")); continue
        if e["digest_alg"] != "SHA-256":
            res.append((e["type"], "Failed", "digest_alg")); continue
        d = e["digest"]
        rep = representation[e["type"]]
        if rep == "sha256-prefixed" and not (isinstance(d, str) and d.startswith("sha256:") and len(d) == 71):
            res.append((e["type"], "Failed", "representation: the receipt profile's value carries the sha256: prefix")); continue
        if rep == "hex" and not (isinstance(d, str) and len(d) == 64):
            res.append((e["type"], "Failed", "representation: lowercase hex")); continue
        res.append((e["type"], "Verified" if held_values[e["type"]]() == d else "Failed", None))
    return res


def verify(data, held_values=held):
    rep = {}
    try:
        verify_sign1(data, public_key_pem=pub_pem, understood_labels={CPB_REFS_LABEL})
        rep["signature"] = "Signature-Valid"
    except TypeError:
        verify_sign1(data, pub_pem); rep["signature"] = "Signature-Valid"
    except CoseError as e:
        rep["signature"] = f"failed: {e}"
    protected = cbor2.loads(strict_decode(data).value[0])
    state, entries = read_refs(protected)
    rep["cpb_refs"] = state
    rep["references"] = [{"type": t, "state": s, **({"reason": r} if r else {})} for t, s, r in resolve(entries, held_values)]
    return rep


valid = statement(refs)
(OUT / "signed-statement-cpb-refs.cose").write_bytes(valid)
(OUT / "receipt.json").write_bytes(receipt_bytes)
(OUT / "binding-payload.json").write_bytes(payload)
# negatives
altered = copy.deepcopy(refs); altered[0][4] = altered[0][4][:-1] + ("0" if altered[0][4][-1] != "0" else "1")
n1 = statement(altered)
tampered = json.loads(receipt_bytes); tampered["action"]["paramsHash"] = "sha256:" + "0" * 64   # the parameters changed after the reference was made
held_tampered = dict(held); held_tampered[NOA_TYPE] = (lambda: noa_digest(tampered))
wrong_object = copy.deepcopy(refs); wrong_object[0][4] = "sha256:" + sha256(receipt_bytes)   # the signed file, not the receipt object
n3 = statement(wrong_object)

keyring = json.loads((NOA / "keyring.json").read_text())
receipt_signature = {
    "construction": "Ed25519 over UTF8('NOA-Receipt-v0.1-sig:') || raw SHA-256 of UTF8(JCS(receipt without chain.hash and sig.value)); 53 bytes",
    "source": f"NordenSoft/noa-mandate-core {NOA_COMMIT[:7]} docs/receipt-spec.md 'Hashing rule (frozen)', src/signing.ts signingMessage; raw-vs-hex stated in NordenSoft/noa-mandate-core#75",
    "all_three_receipts_verify": all(noa_signature_verifies(r, keyring) for r in chain),
    "negative_tag_then_hex_digest_verifies": any(noa_signature_verifies(r, keyring, "tag||hex") for r in chain),
    "negative_bare_digest_verifies": any(noa_signature_verifies(r, keyring, "raw") for r in chain),
    "tampered_receipt_signature_verifies": noa_signature_verifies(tampered, keyring)}

result = {"case": "08-noa-receipt", "noa_vectors_commit": NOA_COMMIT, "receipt": receipt["id"], "receipt_spec": receipt["spec"],
          "noa_chain_recomputes": chain_ok, "receipt_signature": receipt_signature,"declaration": {NOA_TYPE: "context: the profile's digest over UTF8(JCS(receipt without chain.hash and sig.value)); representation: 'sha256:' + lowercase hex; equals chain.hash for a valid receipt; binds the receipt object"},
          "cpb_refs_label": CPB_REFS_LABEL,
          "valid": verify(valid),
          "altered_receipt_digest_in_reference": verify(n1),
          "receipt_bytes_changed_after_reference": {**verify(valid, held_tampered), "tampered_receipt_chain_hash_recomputes": noa_digest(tampered) == tampered["chain"]["hash"]},
          "reference_to_the_signed_file_instead_of_the_object": verify(n3)}
(OUT / "result.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
print(json.dumps(result, indent=1, ensure_ascii=False))
