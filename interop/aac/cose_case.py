#!/usr/bin/env python3
"""Case 07: the capsule of case 01 in its two COSE forms, produced by us and verified by the capsule library's own
verifier on one side and by a CPB reader written from CPB -06 Section 9.3 on the other.

  07a  Producer Envelope (AAC -05 Section 3.1): COSE_Sign1, tag 18, payload = the raw 32 bytes of capsule_id, protected
       header exactly {alg -8, content type application/agent-action-capsule-id, kid = raw Ed25519 public key}, empty
       unprotected map. Verified with agent_action_capsule.producer_envelope.verify_producer_envelope (the library only
       verifies envelopes; it does not produce them). A second envelope over another capsule_id must fail.
  07b  CPB-bound Signed Statement (CPB -06 Section 9.3, envelope carriage): an RFC 9943 Signed Statement over the same
       raw capsule_id (iss/sub in CWT claims, as AAC -05 Section 3.3 requires of a registration statement) whose
       protected header carries cpb-refs: the two typed digest references of case 01 (decision record, action-binding
       attachment) as a closed CBOR array of maps {1 type, 2 purpose, 3 digest_alg, 4 digest}, with the label in crit.
       The label is TBD1 in CPB -06 Section 15.2; this fixture uses the private-use value -65537 and says so. Verified
       with scitt_cose.verify_sign1 (signature, crit understood), then each reference resolved against the DPS bytes
       held in case 01 under the as-transmitted context (SHA-256 of the bytes as issued). Negative forms: an altered
       digest (Failed), an extra key in a reference map (Malformed, no entry reported Verified), cpb-refs in the
       unprotected header (nonconforming).

Writes everything under cases/07-cose/. Keys are test keys derived from a fixed seed; never use them for anything real.
"""
import hashlib
import importlib
import json
import pathlib

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scitt_cose.cose_sign1 import CoseError, sign_sign1, strict_decode, verify_sign1
from scitt_cose.statement import build_signed_statement

pe = importlib.import_module("agent_action_capsule.producer_envelope")
media = importlib.import_module("agent_action_capsule.media_types")

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "cases" / "01-valid"
OUT = HERE / "cases" / "07-cose"
OUT.mkdir(parents=True, exist_ok=True)

CPB_REFS_LABEL = -65537          # TBD1 in CPB -06 Section 15.2; private-use value for this fixture only
HDR_CRIT = 2
CAPSULE_ID_MT = media.CAPSULE_ID_MEDIA_TYPE


def sha256(b):
    return hashlib.sha256(b).hexdigest()


# ---- the capsule of case 01 and the DPS bytes it cites
capsule_bytes = (SRC / "capsule.json").read_bytes()
capsule = json.loads(capsule_bytes)
record_bytes = (SRC / "decision-record.json").read_bytes()
attachment_bytes = (SRC / "action-binding-attachment.json").read_bytes()
result01 = json.loads((SRC / "result.json").read_bytes())
capsule_id = result01["capsule"].get("capsule_id") or result01.get("capsule_id")
if capsule_id is None:
    canonical = importlib.import_module("agent_action_capsule.canonical")
    capsule_id = canonical.compute_capsule_id(capsule)
cid = bytes.fromhex(capsule_id)
refs = capsule["references"]
# the digest contexts the Standard declares for the two names (extensions/README.md after PR #73/#87): the record is
# cited by its seal (the SHA-256 the Standard seals over the covered bytes), the attachment by the SHA-256 of its bytes
# as issued; both lowercase hex text
record = json.loads(record_bytes)
held = {"org.decisionprovenancestandard.decision_record": record["seal_hash"],
        "org.decisionprovenancestandard.action_binding_attachment": sha256(attachment_bytes)}

# ---- a test producer key
key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"dps-aac interop case 07 producer key (test only)").digest())
pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

# ================================================================ 07a Producer Envelope
envelope = sign_sign1(cid, alg="EdDSA", private_key_pem=pem, protected={3: CAPSULE_ID_MT, 4: pub}, unprotected={})
(OUT / "producer-envelope.cose").write_bytes(envelope)
v = pe.verify_producer_envelope(capsule_id, envelope)
other = "0" * 63 + "1"
v_other = pe.verify_producer_envelope(other, envelope)
env_report = {
    "bytes": len(envelope),
    "library_verify_ok": bool(v.ok),
    "library_authenticated_key_hex": (v.public_key.hex() if getattr(v, "public_key", None) else None),
    "library_findings": [f"{f.code}: {f.detail}" for f in (v.findings or [])],
    "key_matches_ours": (getattr(v, "public_key", None) == pub),
    "against_another_capsule_id": {"ok": bool(v_other.ok), "findings": [f"{f.code}: {f.detail}" for f in (v_other.findings or [])]},
}

# ================================================================ 07b CPB-bound Signed Statement with cpb-refs
def cpb_refs_value(entries):
    out = []
    for r in entries:
        m = {1: r["type"], 3: r["digest_alg"], 4: r["digest"]}
        if r.get("citation_purpose"):
            m[2] = r["citation_purpose"]
        out.append(m)
    return out


def statement_with_refs(entries, in_unprotected=False):
    protected = {3: CAPSULE_ID_MT, 4: pub, 15: {1: "urn:isoluce:aac-interop:producer", 2: capsule_id}}
    unprotected = {}
    if in_unprotected:
        unprotected[CPB_REFS_LABEL] = cpb_refs_value(entries)
    else:
        protected[CPB_REFS_LABEL] = cpb_refs_value(entries)
        protected[HDR_CRIT] = [CPB_REFS_LABEL]
    return sign_sign1(cid, alg="EdDSA", private_key_pem=pem, protected=protected, unprotected=unprotected)


# a CPB reader written from Section 9.3: closed maps, sizes, uniqueness, then resolution under as-transmitted
def read_cpb_refs(protected, unprotected):
    if CPB_REFS_LABEL in unprotected:
        return "nonconforming", "cpb-refs MUST NOT occur in the unprotected header", []
    value = protected.get(CPB_REFS_LABEL)
    if value is None:
        return "absent", None, []
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        return "Malformed", "cpb-refs is not an array of 1..64 entries", []
    seen, entries = set(), []
    for item in value:
        if not isinstance(item, dict) or set(item) - {1, 2, 3, 4} or not {1, 3, 4} <= set(item):
            return "Malformed", "a reference map is not closed on keys 1..4 with 1, 3, 4 present", []
        t, p, a, d = item[1], item.get(2), item[3], item[4]
        if not (isinstance(t, str) and 1 <= len(t.encode()) <= 255) or not (isinstance(a, str) and 1 <= len(a.encode()) <= 32) \
                or (p is not None and not (isinstance(p, str) and 1 <= len(p.encode()) <= 64)) \
                or not (isinstance(d, (str, bytes)) and 1 <= len(d if isinstance(d, bytes) else d.encode()) <= 128):
            return "Malformed", "a member is of the wrong type or size", []
        tup = (t, p, a, d)
        if tup in seen:
            return "Malformed", "repeated entry", []
        seen.add(tup)
        entries.append({"type": t, "purpose": p, "digest_alg": a, "digest": d})
    return "ok", None, entries


def resolve(entries):
    # the consuming profile (our draft) accepts the two names, each with one context: as-transmitted, SHA-256 of the
    # bytes as issued, lowercase hex (the declarations of the Standard's extensions/README.md after PR #87)
    results = []
    for e in entries:
        if e["type"] not in held:
            results.append((e["type"], "Unresolved", "context: type not accepted by this profile")); continue
        if e["digest_alg"] != "SHA-256":
            results.append((e["type"], "Failed", "digest_alg is not the context's token")); continue
        if not isinstance(e["digest"], str):
            results.append((e["type"], "Failed", "representation: the context declares lowercase hex text")); continue
        results.append((e["type"], "Verified" if held[e["type"]] == e["digest"] else "Failed", None))
    return results


def verify_statement(data, understood=(CPB_REFS_LABEL,)):
    rep = {}
    try:
        res = verify_sign1(data, public_key_pem=key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
                           understood_labels=set(understood))
        rep["signature"] = "Signature-Valid"
    except TypeError:
        res = verify_sign1(data, key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        rep["signature"] = "Signature-Valid"
    except CoseError as e:
        rep["signature"] = f"failed: {e}"
    tag = strict_decode(data)
    protected_bstr, unprotected, payload, _sig = tag.value
    protected = cbor2.loads(protected_bstr)
    rep["payload_is_capsule_id"] = payload == cid
    rep["cwt"] = {"iss": protected.get(15, {}).get(1), "sub": protected.get(15, {}).get(2)}
    rep["crit"] = protected.get(HDR_CRIT)
    state, why, entries = read_cpb_refs(protected, unprotected or {})
    rep["cpb_refs"] = state
    if why:
        rep["cpb_refs_reason"] = why
    rep["references"] = [] if state != "ok" else [{"type": t, "state": s, **({"reason": r} if r else {})} for t, s, r in resolve(entries)]
    return rep


stmt = statement_with_refs(refs)
(OUT / "signed-statement-cpb-refs.cose").write_bytes(stmt)
altered = [dict(refs[0], digest=refs[0]["digest"][:-1] + ("0" if refs[0]["digest"][-1] != "0" else "1")), refs[1]]
stmt_altered = statement_with_refs(altered)
bad_map = statement_with_refs(refs)
# an extra key in the first reference map: rebuild with key 5 added
protected = {3: CAPSULE_ID_MT, 4: pub, 15: {1: "urn:isoluce:aac-interop:producer", 2: capsule_id},
             CPB_REFS_LABEL: [{**cpb_refs_value(refs)[0], 5: "extension"}, cpb_refs_value(refs)[1]], HDR_CRIT: [CPB_REFS_LABEL]}
stmt_malformed = sign_sign1(cid, alg="EdDSA", private_key_pem=pem, protected=protected, unprotected={})
stmt_unprotected = statement_with_refs(refs, in_unprotected=True)
for name, data in (("signed-statement-altered-digest.cose", stmt_altered), ("signed-statement-malformed-map.cose", stmt_malformed),
                   ("signed-statement-refs-unprotected.cose", stmt_unprotected)):
    (OUT / name).write_bytes(data)

stmt_report = {
    "valid": verify_statement(stmt),
    "altered_digest": verify_statement(stmt_altered),
    "malformed_map": verify_statement(stmt_malformed),
    "refs_in_unprotected": verify_statement(stmt_unprotected),
    "without_understanding_cpb_refs": verify_statement(stmt, understood=()),
}

result = {"case": "07-cose", "capsule_id": capsule_id, "producer_public_key_hex": pub.hex(),
          "cpb_refs_label": CPB_REFS_LABEL, "cpb_refs_label_note": "TBD1 in CPB -06 Section 15.2; private-use value, fixture only",
          "07a_producer_envelope": env_report, "07b_cpb_refs_statement": stmt_report}
(OUT / "result.json").write_text(json.dumps(result, indent=1, ensure_ascii=False))
print(json.dumps(result, indent=1, ensure_ascii=False))
