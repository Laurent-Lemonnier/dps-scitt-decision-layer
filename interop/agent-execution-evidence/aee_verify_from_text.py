#!/usr/bin/env python3
"""A verifier written from the text of draft-thaha-scitt-agent-execution-evidence-02 (November 2026), for the parts of
the profile this case uses. It imports nothing from the author's code and has seen none of it. Each check names the
section it comes from. What it covers:

  Section 5      canonical CBOR (RFC 8949 4.2.1) of every payload, no floats, UTF-8 text, the integer-key map; the
                 Signed Statement's protected header (alg, content type, kid/x5t/x5chain, CWT Claims with iss, sub and
                 aee_type equal to key 1 of the payload);
  Section 6.7    the Execution Receipt map: closed key set 1..29, the required keys, types, the record-type and decision
                 enumerations, confirm only on tool_call, confirm_seq only on an outcome, the confirm/outcome pairing
                 (same parent_seq, target, request_digest and Task; exactly one outcome), tool_result not before the
                 allow outcome, parent_seq rules, request_digest/response_digest as [alg, bstr] digests, egress_host
                 required beside call_digest;
  Section 6.7.1  record-hash = SHA-256 over the canonical encoding including key 15; seq from 0 by exactly one;
                 prev_hash chaining from 32 zero octets; task_seq naming an earlier allow task_start that has not ended;
                 one task_end per Task; every receipt of a Task carrying its task_start's principal;
  Section 6.7    agent_sig (key 15): COSE_Sign1 with detached payload over the canonical receipt without key 15, with
                 CWT iss and sub equal to the agent identifier (verified with the agent key given; step 10 of Section 9);
  Section 7      the Registration Policy checks of "All types" and of Execution Receipt (5) that need no other
                 statement: aee_type equals key 1, content type among Section 12.1's, sub equals agent_id (Section 3),
                 a tool_call carrying call_digest carries egress_host;
  Section 8      the Bundle map shape (keys 1 and 2 required, 3 and 4 optional; receipts in ascending seq);
  Section 9      steps 3, 6, 8, 9 and 10 as listed above, and step 2 against the Issuer key given.

Not performed, so the result is never PASS (Section 9: "A verifier that does not perform a step MUST NOT report PASS"):
step 1 (Transparency Service Receipts, label 394: no TS here), steps 4, 5, 11 to 17 (Agent Credential, Registration,
Policy Pack, Configuration Integrity, Assurance, Status List and admission statements are not built by this case), step
7 (no Execution Epoch here: the receipts are registered individually, which Section 6.7.4 permits). The result is
CHECKS_PERFORMED with the list of checks and their verdicts, or FAIL with the first failing error name.

Also here: the reproduction of the Appendix A record-hashes from the diagnostic notation of the text alone.

Ambiguities met while writing this (the README's ambiguity log repeats them with its own numbering):
 (a) duplicate map keys (Section 5) cannot be detected after a generic CBOR decode; this verifier checks that the
     canonical re-encoding equals the bytes, which catches ordering and non-shortest forms, not duplicates;
 (b) the Sig_structure for agent_sig: "detached payload" and "whose Sig_structure payload is the canonical encoding of
     the receipt without key 15"; external_aad is not mentioned and is taken as empty;
 (c) who confirmed, and on what evidence, is not a member of the confirm or outcome receipt (Section 6.7: "confirmation
     from a Principal or operator"); the pairing is checked, the confirmation itself cannot be;
 (d) the deadline for a confirm's outcome is the Policy Pack's; no bound in Section 6.7 is checkable here;
 (e) the kid value (Appendix A: 8 octets) is not defined; taken as opaque;
 (f) principal id for a natural person: "the canonical identifier of the person (Section 10)"; Section 10 does not
     define the canonical form; Appendix A uses the literal "user:alice@example.com" and it reproduces.
"""
import hashlib
from collections.abc import Mapping

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SHA256_COSE = -16                                      # IANA COSE Algorithms, Section 5
EDDSA = -8                                             # RFC 9053, Appendix A.1
MEDIA_CBOR = "application/aee-statement+cbor"          # Section 12.1
MEDIA_JSON = "application/aee-statement+json"
ZERO32 = bytes(32)
RECORD_TYPE = {1: "task_start", 2: "task_end", 3: "inference", 4: "tool_call", 5: "tool_result", 6: "egress", 7: "admission"}
DECISION = {1: "allow", 2: "block", 3: "confirm", 4: "record"}
DECISION_POINT = {1: "model", 2: "tool", 3: "network", 4: "ingress"}
RECEIPT_KEYS = set(range(1, 30))
REQUIRED = {1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 14}
# Keys outside the author's CDDL that a run of this verifier accepts on purpose. Empty by default: the text's map is
# closed. The case's route 2 sets {30} for its clearly labelled proposal and for nothing else.
ACCEPT_PROPOSED_KEYS = set()


class Fail(Exception):
    def __init__(self, error, detail):
        super().__init__(f"{error}: {detail}")
        self.error, self.detail = error, detail


def canonical(obj):
    return cbor2.dumps(obj, canonical=True)


def record_hash(receipt_map):
    """Section 6.7.1: SHA-256 over the canonical encoding, including key 15 when present."""
    return hashlib.sha256(canonical(receipt_map)).digest()


def _no_float(v, where):
    if isinstance(v, float):
        raise Fail("E_MALFORMED", f"floating-point value at {where} (Section 5)")
    if isinstance(v, Mapping):
        for k, x in v.items():
            _no_float(k, where)
            _no_float(x, where)
    elif isinstance(v, (list, tuple)):
        for x in v:
            _no_float(x, where)
    elif isinstance(v, str):
        try:
            v.encode("utf-8")
        except UnicodeEncodeError:
            raise Fail("E_MALFORMED", f"text string not valid UTF-8 at {where} (Section 5)")


def decode_canonical(data, where):
    """Section 5: deterministic encoding of RFC 8949 4.2.1; a payload that is not in that form is malformed (reading:
    the canonical re-encoding must equal the bytes; ambiguity (a) on duplicate keys)."""
    try:
        obj = cbor2.loads(data)
    except Exception as e:                                 # noqa: BLE001
        raise Fail("E_MALFORMED", f"{where}: not CBOR ({e})")
    if canonical(obj) != data:
        raise Fail("E_MALFORMED", f"{where}: not in canonical CBOR form (Section 5)")
    _no_float(obj, where)
    return thaw(obj)


def thaw(v):
    """cbor2 decodes maps used as keys or inside tags as immutable mappings; plain dicts and lists everywhere."""
    if isinstance(v, Mapping):
        return {k: thaw(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):          # cbor2 decodes arrays inside tags as tuples
        return [thaw(x) for x in v]
    return v


def _is_digest(v):
    return isinstance(v, list) and len(v) == 2 and isinstance(v[0], int) and not isinstance(v[0], bool) \
        and isinstance(v[1], bytes) and (v[0] != SHA256_COSE or len(v[1]) == 32)


def _uint(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def check_receipt_shape(r, where):
    """Section 6.7, the CDDL of execution-receipt and the member semantics that hold for one receipt alone."""
    if not isinstance(r, Mapping):
        raise Fail("E_MALFORMED", f"{where}: receipt is not a map")
    keys = set(r)
    if not all(isinstance(k, int) for k in keys) or not keys <= RECEIPT_KEYS | ACCEPT_PROPOSED_KEYS:
        raise Fail("E_MALFORMED", f"{where}: keys outside 1..29 (Section 6.7 CDDL, closed map)")
    if 30 in keys and 30 in ACCEPT_PROPOSED_KEYS:
        # the proposal of this case (README, route 2), not the author's text: an optional array of external typed
        # references {1 type tstr, 2 digest}, on a tool_call receipt
        v = r[30]
        if not (isinstance(v, list) and v and all(isinstance(e, dict) and set(e) == {1, 2} and isinstance(e[1], str)
                                                     and _is_digest(e[2]) for e in v)) or r.get(4) != 4:
            raise Fail("E_MALFORMED", f"{where}: proposed key 30 is not an array of {{1 tstr, 2 digest}} on a tool_call")
    if not REQUIRED <= keys:
        raise Fail("E_MALFORMED", f"{where}: required keys missing: {sorted(REQUIRED - keys)} (Section 6.7)")
    if r[1] != 5:
        raise Fail("E_TYPE_MISMATCH", f"{where}: key 1 is not 5 (execution-receipt)")
    if not _uint(r[2]):
        raise Fail("E_MALFORMED", f"{where}: seq not a uint")
    if not (isinstance(r[3], bytes) and len(r[3]) == 32):
        raise Fail("E_MALFORMED", f"{where}: prev_hash not 32 octets")
    if r[4] not in RECORD_TYPE:
        raise Fail("E_MALFORMED", f"{where}: record_type {r[4]} not in the enumeration")
    if r[6] not in DECISION:
        raise Fail("E_MALFORMED", f"{where}: decision {r[6]} not in the enumeration")
    if not (_is_digest(r[7]) and _is_digest(r[8])):
        raise Fail("E_MALFORMED", f"{where}: policy_pack_digest or config_integrity_digest not a digest")
    if not isinstance(r[9], str):
        raise Fail("E_MALFORMED", f"{where}: agent_id not a text string")
    p = r[10]
    if not (isinstance(p, Mapping) and set(p) <= {1, 2, 3, 4} and {1, 2} <= set(p) and p[1] in (1, 2, 3)):
        raise Fail("E_MALFORMED", f"{where}: principal not a principal map")
    if p[1] == 1 and not (isinstance(p[2], bytes) and len(p[2]) == 32):
        raise Fail("E_MALFORMED", f"{where}: natural-person principal id not a 32-octet digest (Section 3)")
    if not _uint(r[11]) or not _uint(r[14]):
        raise Fail("E_MALFORMED", f"{where}: task_seq or ts not a uint")
    for k in (12, 13, 29):
        if k in r and not _is_digest(r[k]):
            raise Fail("E_MALFORMED", f"{where}: key {k} not a digest")
    for k in (16, 17, 20, 25):
        if k in r and not isinstance(r[k], str):
            raise Fail("E_MALFORMED", f"{where}: key {k} not a text string")
    for k in (5, 19, 28):
        if k in r and not _uint(r[k]):
            raise Fail("E_MALFORMED", f"{where}: key {k} not a uint")
    if 18 in r and r[18] not in DECISION_POINT:
        raise Fail("E_MALFORMED", f"{where}: decision_point not in the enumeration")
    if 15 in r and not isinstance(r[15], bytes):
        raise Fail("E_MALFORMED", f"{where}: agent_sig not a byte string")
    if r[6] == 3 and r[4] != 4:
        raise Fail("E_MALFORMED", f"{where}: confirm appears only on tool_call receipts (Section 6.7)")
    if 19 in r and not (r[4] == 4 and r[6] in (1, 2)):
        raise Fail("E_MALFORMED", f"{where}: confirm_seq on a receipt that is not a tool_call outcome (Section 6.7)")
    if 29 in r and r[4] in (4, 6) and 17 not in r:
        raise Fail("E_MALFORMED", f"{where}: call_digest without egress_host (Sections 6.7 and 7)")


PARENT_TYPE = {4: {3}, 5: {4}, 6: {4, 3}, 1: {7}}       # Section 6.7, parent_seq


def verify_chain(receipt_maps, agent_public_key=None):
    """Sections 6.7, 6.7.1 and 9 steps 6, 8, 9, 10 over a chain segment starting at seq 0, as a list of decoded maps in
    ascending order. Returns the per-check report; raises Fail at the first failure, as Section 9 orders."""
    checks = []

    def ok(name, section):
        checks.append({"check": name, "section": section, "ok": True})

    by_seq = {}
    prev, prev_hash, prev_ts = None, ZERO32, 0
    for i, r in enumerate(receipt_maps):
        check_receipt_shape(r, f"seq {r.get(2, i)}")
        if r[2] != i:
            raise Fail("E_CHAIN_GAP", f"seq {r[2]} where {i} expected (6.7.1: seq increases by exactly one)")
        if r[3] != prev_hash:
            raise Fail("E_CHAIN_HASH", f"seq {i}: prev_hash is not the record-hash of seq {i - 1}" if i else
                       "seq 0: prev_hash is not 32 zero octets")
        if r[14] < prev_ts:
            raise Fail("E_KEY_CURRENCY", f"seq {i}: ts decreases (6.7, step 9)")
        prev_hash, prev_ts, prev = record_hash(r), r[14], r
        by_seq[i] = r
    ok("shape of every receipt: closed integer-key map, required keys, enumerations, digests", "6.7 CDDL; 5")
    ok("seq from 0 by exactly one; prev_hash chains from 32 zero octets by record-hash", "6.7.1; 9 step 6")
    ok("ts non-decreasing along the chain", "6.7; 9 step 9")
    # Tasks (6.7.1)
    ended = set()
    for s, r in by_seq.items():
        if r[4] == 7:
            if r[11] != s:
                raise Fail("E_TASK", f"seq {s}: admission task_seq is not its own seq")
            continue
        if r[4] == 1:
            if r[11] != s:
                raise Fail("E_TASK", f"seq {s}: task_start does not carry its own seq as task_seq")
            continue
        ts_ = by_seq.get(r[11])
        if ts_ is None or ts_[4] != 1 or ts_[6] != 1 or r[11] >= s:
            raise Fail("E_TASK", f"seq {s}: task_seq does not name an earlier task_start with decision allow")
        if r[11] in ended:
            raise Fail("E_TASK", f"seq {s}: names a Task after its task_end")
        if r[10] != ts_[10]:
            raise Fail("E_TASK", f"seq {s}: principal differs from the Task's task_start")
        if r[4] == 2:
            ended.add(r[11])
    ok("every receipt names an earlier allow task_start of its Task, not ended, with the same principal", "6.7.1")
    # parent_seq (6.7; step 8)
    result_parents = {}
    for s, r in by_seq.items():
        if 5 in r:
            p = by_seq.get(r[5])
            if p is None or r[5] >= s:
                raise Fail("E_PARENT_SEQ", f"seq {s}: parent_seq not an earlier receipt present")
            if p[4] not in PARENT_TYPE.get(r[4], set()):
                raise Fail("E_PARENT_TYPE", f"seq {s}: parent is a {RECORD_TYPE[p[4]]}, not the type Section 6.7 requires")
            if r[4] != 1 and p[11] != r[11]:
                raise Fail("E_TASK", f"seq {s}: parent in another Task")
            if r[4] == 5:
                if p[6] not in (1, 4):
                    raise Fail("E_TASK", f"seq {s}: tool_result's parent is not an allow (or record) tool_call: a tool_result "
                                         "MUST NOT precede an allow outcome (6.7)")
                if r[5] in result_parents:
                    raise Fail("E_PARENT_SEQ", f"seq {s}: a second tool_result for tool_call {r[5]} (step 8)")
                result_parents[r[5]] = s
        elif r[4] in (4, 5):
            raise Fail("E_PARENT_SEQ", f"seq {s}: a {RECORD_TYPE[r[4]]} without parent_seq (6.7: the causal link)")
    ok("parent_seq earlier, present, of the required type and Task; one tool_result per tool_call, after an allow", "6.7; 9 step 8")
    # confirm / outcome pairing (6.7; step 8)
    outcomes = {}
    for s, r in by_seq.items():
        if 19 in r:
            c = by_seq.get(r[19])
            if c is None or r[19] >= s or c[6] != 3 or c[4] != 4:
                raise Fail("E_TASK", f"seq {s}: confirm_seq does not name an earlier confirm receipt")
            if (c.get(5), c.get(16), c.get(12), c[11]) != (r.get(5), r.get(16), r.get(12), r[11]):
                raise Fail("E_TASK", f"seq {s}: outcome differs from its confirm in parent_seq, target, request_digest or Task")
            if r[19] in outcomes:
                raise Fail("E_TASK", f"seq {s}: a second outcome for confirm {r[19]}")
            outcomes[r[19]] = s
    pending = []
    for s, r in by_seq.items():
        if r[6] == 3 and s not in outcomes:
            if r[11] in ended or any(x.get(5) == s for x in by_seq.values()):
                raise Fail("E_TASK", f"seq {s}: confirm without outcome although its Task ended or a receipt names it as parent")
            pending.append(s)
        if r[4] == 5 and by_seq[r[5]][6] == 3:
            raise Fail("E_TASK", f"seq {s}: tool_result whose parent is the confirm receipt, not the allow outcome (6.7)")
    ok("every confirm_seq names an earlier confirm with the same parent_seq, target, request_digest and Task; one outcome each; "
       "no tool_result before an allow outcome; no Task ends with a confirm pending", "6.7; 9 step 8")
    # agent_sig (6.7; step 10)
    signed = 0
    for s, r in by_seq.items():
        if 15 in r:
            if agent_public_key is None:
                raise Fail("E_AGENT_SIG", f"seq {s}: agent_sig present and no agent key to verify it (6.7: MUST be verified when present)")
            verify_agent_sig(r, agent_public_key)
            signed += 1
    ok(f"agent_sig verified on {signed} receipt(s): COSE_Sign1, detached payload = canonical receipt without key 15, "
       "CWT iss and sub = agent_id", "6.7; 9 step 10")
    return {"checks": checks, "record_hashes": {s: record_hash(r).hex() for s, r in by_seq.items()},
            "confirm_outcomes": outcomes, "confirms_pending": pending}


def sig_structure(protected_bytes, payload, external_aad=b""):
    """RFC 9052 4.4, Signature1."""
    return canonical(["Signature1", protected_bytes, external_aad, payload])


def parse_cose_sign1(data, where):
    try:
        obj = cbor2.loads(data)
    except Exception as e:                                 # noqa: BLE001
        raise Fail("E_MALFORMED", f"{where}: not CBOR ({e})")
    if isinstance(obj, cbor2.CBORTag):
        if obj.tag != 18:
            raise Fail("E_MALFORMED", f"{where}: tag {obj.tag} is not COSE_Sign1 (18)")
        obj = obj.value
    if not (isinstance(obj, (list, tuple)) and len(obj) == 4 and isinstance(obj[0], bytes) and isinstance(obj[1], Mapping)
            and (obj[2] is None or isinstance(obj[2], bytes)) and isinstance(obj[3], bytes)):
        raise Fail("E_MALFORMED", f"{where}: not a COSE_Sign1 array of four")
    protected = cbor2.loads(obj[0]) if obj[0] else {}
    if not isinstance(protected, Mapping):
        raise Fail("E_MALFORMED", f"{where}: protected header is not a map")
    return obj[0], dict(protected), dict(obj[1]), obj[2], obj[3]


def verify_agent_sig(receipt, agent_public_key):
    """Section 6.7, agent_sig: detached payload, Sig_structure payload = canonical receipt without key 15; CWT iss and
    sub carry the agent identifier (read: equal to agent_id, key 9)."""
    s = receipt[2]
    pb, protected, _unp, payload, sig = parse_cose_sign1(receipt[15], f"seq {s} agent_sig")
    if payload is not None:
        raise Fail("E_AGENT_SIG", f"seq {s}: agent_sig payload is not detached")
    if protected.get(1) != EDDSA:
        raise Fail("E_AGENT_SIG", f"seq {s}: agent_sig alg is not EdDSA (the Appendix A keys are Ed25519; this case's too)")
    cwt = protected.get(15)
    if not (isinstance(cwt, Mapping) and cwt.get(1) == receipt[9] and cwt.get(2) == receipt[9]):
        raise Fail("E_AGENT_SIG", f"seq {s}: agent_sig CWT Claims iss/sub are not the agent identifier")
    body = canonical({k: v for k, v in receipt.items() if k != 15})
    try:
        agent_public_key.verify(sig, sig_structure(pb, body))
    except InvalidSignature:
        raise Fail("E_AGENT_SIG", f"seq {s}: agent_sig does not verify over the canonical receipt without key 15")


def verify_signed_statement(data, issuer_public_key, where="statement"):
    """Section 5 (the Signed Statement's protected header), Section 7 'All types' and Execution Receipt (5) checks that
    need no other statement, Section 9 steps 2 and 3. Returns (payload map, protected header)."""
    pb, protected, _unp, payload, sig = parse_cose_sign1(data, where)
    if payload is None:
        raise Fail("E_MALFORMED", f"{where}: a Signed Statement carries its payload (Section 5)")
    if protected.get(1) is None:
        raise Fail("E_TYPE_MISMATCH", f"{where}: alg (label 1) missing (Section 5)")
    ct = protected.get(3)
    if ct not in (MEDIA_CBOR, MEDIA_JSON):
        raise Fail("E_TYPE_MISMATCH", f"{where}: content type {ct!r} is not a statement media type of Section 12.1")
    if not any(k in protected for k in (4, 34, 33)):
        raise Fail("E_TYPE_MISMATCH", f"{where}: none of kid, x5t, x5chain (Section 5; RFC 9943 6)")
    cwt = protected.get(15)
    if not (isinstance(cwt, Mapping) and isinstance(cwt.get(1), str) and isinstance(cwt.get(2), str)):
        raise Fail("E_TYPE_MISMATCH", f"{where}: CWT Claims (label 15) with iss and sub missing (Section 5)")
    aee_type = cwt.get("aee_type")                          # the text-string key pending TBD1 (Section 12.2)
    if ct != MEDIA_CBOR:
        raise Fail("E_TYPE_MISMATCH", f"{where}: this verifier reads the CBOR form only (Section 5.1 not implemented)")
    pay = decode_canonical(payload, f"{where} payload")
    if not isinstance(pay, Mapping) or pay.get(1) != aee_type:
        raise Fail("E_TYPE_MISMATCH", f"{where}: aee_type claim {aee_type!r} does not equal key 1 of the payload (Sections 5, 7)")
    if protected.get(1) != EDDSA:
        raise Fail("E_ISSUER_SIG", f"{where}: alg {protected.get(1)} not EdDSA; this verifier knows Ed25519 only")
    try:
        issuer_public_key.verify(sig, sig_structure(pb, payload))
    except InvalidSignature:
        raise Fail("E_ISSUER_SIG", f"{where}: the Issuer's signature does not verify (step 2)")
    if aee_type == 5:
        check_receipt_shape(pay, where)
        if cwt.get(2) != pay[9]:
            raise Fail("E_TYPE_MISMATCH", f"{where}: sub does not equal the receipt's agent_id (Sections 3, 7)")
    return pay, protected


def verify_bundle(bundle_bytes, *, issuer_public_key, agent_public_key=None):
    """Section 8 shape, then Section 9 for the steps this verifier performs. Never PASS (see the module docstring)."""
    report = {"result": None, "checks": [], "not_performed": [
        "step 1: Transparency Service Receipts (label 394) - no TS in this case",
        "step 4, 5: Agent Credential and Agent Registration Statements - not built",
        "step 7: Execution Epoch - receipts registered individually (6.7.4 permits it), no epoch to check",
        "steps 11-17: Policy Pack, Configuration Integrity, Assurance, Status Lists, Sub-agents, admission, delegation - not built"]}
    try:
        b = decode_canonical(bundle_bytes, "bundle")
        if not (isinstance(b, Mapping) and {1, 2} <= set(b) <= {1, 2, 3, 4} and isinstance(b[1], list) and b[1]
                and isinstance(b[2], list)):
            raise Fail("E_MALFORMED", "bundle: not a map with keys 1 and 2 (3, 4 optional) (Section 8)")
        report["checks"].append({"check": "Bundle is a CBOR map with statements (1) and receipts (2)", "section": "8", "ok": True})
        statements = []
        for i, st in enumerate(b[1]):
            pay, prot = verify_signed_statement(st, issuer_public_key, f"statement {i}")
            statements.append((pay, prot))
        report["checks"].append({"check": f"{len(statements)} Signed Statement(s): header per Section 5, Issuer signature, "
                                 "aee_type = payload key 1, sub = agent_id, Registration Policy checks needing no other statement",
                                 "section": "5; 7; 9 steps 2, 3", "ok": True})
        receipts = [decode_canonical(r, f"receipt {i}") if isinstance(r, bytes) else r for i, r in enumerate(b[2])]
        # Section 8: key 2 holds the receipts themselves (the CDDL says execution-receipt, not bstr); this verifier
        # accepts both the maps and their canonical bytes, and re-encodes to check canonical form
        for i, r in enumerate(receipts):
            if canonical(r) != canonical(cbor2.loads(canonical(r))):
                raise Fail("E_MALFORMED", f"receipt {i}: not canonical")
        chain = verify_chain(receipts, agent_public_key)
        report["checks"] += chain["checks"]
        # the receipts registered individually must be the ones in key 2 (8: "or the receipt's own Transparent Statement")
        registered = {record_hash(p).hex() for p, _ in statements if p.get(1) == 5}
        missing = [s for s, h in chain["record_hashes"].items() if h not in registered]
        if missing:
            raise Fail("E_EPOCH_ROOT", f"receipts {missing} have neither an Execution Epoch nor their own Signed Statement in key 1 (Section 8)")
        report["checks"].append({"check": "every receipt of key 2 has its own Signed Statement in key 1 (no epoch here)",
                                 "section": "8; 6.7.4", "ok": True})
        report.update(record_hashes=chain["record_hashes"], confirm_outcomes=chain["confirm_outcomes"],
                      confirms_pending=chain["confirms_pending"], result="CHECKS_PERFORMED")
    except Fail as e:
        report.update(result="FAIL", error=e.error, detail=e.detail)
    return report


# ---- Appendix A, reproduced from the diagnostic notation of the text
def appendix_a_reproduction():
    """The record-hashes and digests Appendix A prints, recomputed from the text alone. Not reproducible from the text:
    record-hash(2) (needs the 226 octets of agent_sig, which the text elides) and request_digest 989a65... (over
    octets the text does not give)."""
    h = lambda b: hashlib.sha256(b).digest()               # noqa: E731
    agent = "wimse://agents.example.com/agent/billing-assistant"
    principal = {1: 1, 2: h(b"operator-pepper-0001" + b"user:alice@example.com")}
    pack = h(b'{"pack":"example-deployment-pack","v":"1.0.0"}')
    cfg = bytes.fromhex("654e7b4e605a07c8657d5f2c01360d2367022d18a2ee2dfce1a6489e1c6b6781")
    r0 = {1: 5, 2: 0, 3: ZERO32, 4: 1, 6: 1, 7: [-16, pack], 8: [-16, cfg], 9: agent, 10: principal, 11: 0, 14: 1790001000000}
    rh0 = record_hash(r0)
    r1 = {1: 5, 2: 1, 3: rh0, 4: 3, 6: 1, 7: [-16, pack], 8: [-16, cfg], 9: agent, 10: principal, 11: 0,
          12: [-16, h(b"<prompt bytes>")], 13: [-16, h(b"<completion bytes>")], 14: 1790001000120, 16: "example-model-2026-06", 18: 1}
    rh1 = record_hash(r1)
    rh2 = bytes.fromhex("7df8cc808530b8a02e78f723ddcda32645e14c66dd61b8525279fa94118f9ec9")   # given, not reproducible
    req = bytes.fromhex("989a658a232f0329b3372261bdd4d3bec9e31d57094015433bf54fbd2aeca8f5")
    plink = h(b"<delegation token octets>")
    cd = h(canonical(["POST", "/invoices", h(b"<invoice request bytes>")]))
    r3 = {1: 5, 2: 3, 3: rh2, 4: 4, 5: 1, 6: 1, 7: [-16, pack], 8: [-16, cfg], 9: agent, 10: principal, 11: 0, 12: [-16, req],
          14: 1790001009000, 16: "send_invoice", 17: "api.customer.example", 18: 2, 19: 2, 23: [agent], 24: plink, 25: "txn-0001",
          29: [-16, cd]}
    rh3 = record_hash(r3)
    sp_principal = h(b"serving-pepper-0001" + b"user:alice@example.com")
    adm = {1: 5, 2: 0, 3: ZERO32, 4: 7, 6: 1, 7: [-16, bytes.fromhex("5b582ac36c7eb1ee98d6be83fe7594a80ae9c11d65a4da796810897772123dce")],
           8: [-16, bytes.fromhex("db4faed7cf5ef7b1127006d60afda3d47e4970f7f89baf37eb233ec665dc6c68")], 9: "https://api.customer.example",
           10: {1: 1, 2: sp_principal}, 11: 0, 12: [-16, req], 14: 1790001009050, 16: "POST /invoices", 18: 4, 20: agent,
           21: {1: "https://harness.example/issuer", 2: 3, 3: rh3},
           22: {3: 1790001009, 4: 0, 5: [-16, bytes.fromhex("f994b20f8c780fcd2b2981784c79e1afa1591a1a33d2a9ce90739b0d622716ec")], 6: [-16, plink]},
           23: [agent], 24: plink, 25: "txn-0001", 29: [-16, cd]}
    expected = {
        "A.3 principal digest (pepper || user:alice@example.com)": (principal[2].hex(), "355acb442721073848a4b78577b31cd2958587696cf8378ab050011c8a042638"),
        "A.5 policy pack digest": (pack.hex(), "563a0a3a0c09b773b7f07dd66931dc56605cb0e56d53d1da9cdefe6ae4c56f4d"),
        "A.5 record-hash(0)": (rh0.hex(), "1942de9ac9bd019506aa5e551ede9ae92676942d4278816ab458a9deb16548c0"),
        "A.5 record-hash(1)": (rh1.hex(), "3d3b1f63cb07c710049eed093e439600464a47a36b37175372e1fc734f6d39a9"),
        "A.5 record-hash(3), the allow outcome": (rh3.hex(), "6724c98d2b78fe984db24ce2d8cb63cc214171928ec4f9ebb09770e3d9196fa7"),
        "A.5 principal_link": (plink.hex(), "1c8ec66d31e2260b8ebe9e7c602773d0b7b8803689e8a935c3d7d22002cd813d"),
        "A.5 call_digest (HTTP binding of 6.7)": (cd.hex(), "544d017602d3f2c25b263dc8b8a7c124a27f447f9820363ba99793d5baeda60f"),
        "A.7 Serving Party principal digest": (sp_principal.hex(), "461e46747b2b36f5a21c8ef5d0526c9d4c8b8d4d561b92ed4cef35f80b14f3f0"),
        "A.7 record-hash(admission 0)": (record_hash(adm).hex(), "712bba68319f1aa5f048292b99107131d513b3ba96f3d23b2a318585bf98a425"),
    }
    out = {k: {"computed": c, "published": p, "agree": c == p} for k, (c, p) in expected.items()}
    out["A.5 record-hash(2), the confirm receipt"] = {"computed": None, "published": rh2.hex(), "agree": None,
                                                      "note": "not reproducible: agent_sig's 226 octets are elided in the text"}
    # the pairing rules of 6.7 hold on the Appendix A receipts 0..3 (with record-hash(2) taken from the text)
    try:
        r2_approx = {k: v for k, v in r3.items() if k not in (19, 23, 24, 25, 29)} | {2: 2, 3: rh1, 6: 3, 14: 1790001000350}
        verify_chain([r0, r1, r2_approx, {**r3, 3: record_hash(r2_approx)}], None)   # seq 2 without key 15, rules only
        pairing = "the 6.7 rules hold on receipts 0..3 as written (seq 2 taken without its agent_sig)"
    except Fail as e:
        pairing = f"FAIL {e}"
    out["_rules_on_appendix_a"] = pairing
    return out


if __name__ == "__main__":
    import json
    print(json.dumps(appendix_a_reproduction(), indent=1))
