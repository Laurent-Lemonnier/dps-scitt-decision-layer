#!/usr/bin/env python3
"""Independent verifier for the agent audit record of
draft-gilda-audit-agent-audit-record-02, written from the draft text (Sections
4 and 5) and from the corpus MANIFEST's published test keys only. It imports
nothing from the agent-evidence-vectors package and shares no code with its
reference rail. The refusal codes are the names the corpus publishes, so that
two implementations can compare where they stopped.

Scope (29/10/2026): single records (statements/), sets (sets/) and the verdict
of retained records (retained/), with the parts of the dating check of Section
4.7.1 that need no anchor. Extended on 31/10/2026, read from -03: every anchor
of a retention entry is validated offline under Section 4.7.2 against what the
corpus MANIFEST pins as held independently (anchorTrust: the tree heads of the
test log, the 80-byte headers of the test chain). A transparency-log anchor is
an RFC 9162 TransItem of type inclusion_proof_v2 (0x0106), recomputed from the
leaf SHA-256(0x00 || envelopeDigest) by the algorithm of RFC 9162 Section
2.1.3.2 to a head held for its log and tree size; its time is that head's. An
opentimestamps anchor is read in the OpenTimestamps serialisation (magic,
version, sha256 and the digest, then append, prepend, sha256, fork and
attestation operations), replayed from envelopeDigest along each Bitcoin
attestation to the Merkle root of the held header at the named height; its time
is that header's time field. A pending attestation validates nothing. The
established time (datedAt), the retention time, the bracket codes
entry-received-after-anchor and entry-anchor-late (with the 7200-second
allowance in place of the skew tolerance where the time is an opentimestamps
anchor's, and block heights in place of times where both are), the receipt
reading and the delegation root are then reported in full. An rfc3161 anchor
is not validated (none in the corpus; no certification path is held) and is
reported as not attempted. Rules new in -03 are applied: a record whose
issuedAt is earlier than effect.interval.sealedAt (issued-before-sealed), the
v2 predicate type with the input principal-standing-source (Section 8), the
empty-tree constant as -03 states it, and an unreadable delegation-root
element (entry-delegation-root-unreadable).

Usage: gilda_verify_independent.py --corpus DIR [--report out.json]
"""
import struct
import argparse
import base64
import datetime
import hashlib
import json
import math
import os
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/agent-audit-record"
PREDICATE_TYPE_V2 = "https://probityai.github.io/agent-evidence-vectors/predicate/v2/agent-audit-record"  # -03 Section 8
# Section 5.3 / vector E3: the empty-tree constant under sha256. -03 states it:
# the digest of the empty byte string.
EMPTY_TREE_SHA256 = hashlib.sha256(b"").hexdigest()
SAFE_INT = 2 ** 53  # RFC 7493 I-JSON, Section 4.1.1
MAX_DEPTH = 128     # Section 4.1.2
SKEW = 300          # skew tolerance, seconds (MANIFEST skewTolerance)
OTS_ALLOWANCE = 7200  # Section 4.7.2: in place of the skew tolerance where a time is an opentimestamps anchor's
# the OpenTimestamps serialisation, as draft-fassbender-scitt-time-anchor Appendix D.4 and the Standard's anchoring
# extension describe it; nothing of the OpenTimestamps software is used
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_BITCOIN = bytes.fromhex("0588960d73d71901")
OTS_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
INCLUSION_PROOF_V2 = 0x0106  # RFC 9162, VersionedTransType

VOCAB = {
    "tier": {"voluntary", "authoritative"},
    "hashAlgorithm": {"sha256"},
    "agent.authentication": {"wimse-wpt", "http-message-signature", "mtls", "oauth-access-token", "api-key", "none"},
    "delegation.subjectKind": {"user", "system", "none"},
    "resource.kind": {"path", "uri", "tool"},
    "resource.binding": {"digest-bound", "not-bindable"},
    "decision.reported": {"permit", "deny", "permit-with-conditions"},
    "effect.observed": {"occurred", "none", "unknown"},
    "effect.interval.baseResolution": {"supplied", "empty-tree"},
    "agreement": {"agree", "disagree", "not-exercised", "indeterminate", "one-sided"},
    "evaluation.status": {"evaluated", "not-evaluated"},
    "evaluation.input": {"standing-source", "key-source", "consumption-state", "policy-source"},
    "oversight.act": {"observation", "check", "decision", "release"},
    "correlation.scope": {"producer", "cross-party"},
    "correlation.timeBasis": {"beacon-anchored", "asserted"},
    "correlation.externalAnchor.kind": {"rfc3161", "transparency-log", "opentimestamps"},
    "posture": {"no_network", "allowlist", "sinkhole", "unsafe_bypass_egress"},
    "posture.agreement": {"agree", "disagree"},
    "remediation.cause": {"session-revoked", "risk-elevated", "subject-disabled", "token-replay-suspected", "policy-changed", "operator-action"},
    "remediation.enforcement": {"access-attenuated", "session-terminated", "tokens-discarded", "privileges-reduced", "reevaluated", "not-enforced"},
    "observation.vantage": {"below-observed", "peer", "self"},
    "fieldEvidence": {"substrate-covered", "producer-asserted"},
}
FIELD_EVIDENCE_KEYS = {"agent", "correlation", "decision", "delegation", "posture", "remediation", "resource"}
REQUIRED = ["recordId", "tier", "hashAlgorithm", "agent", "delegation", "resource", "decision",
            "evaluation", "effect", "agreement", "correlation", "posture", "remediation",
            "observation", "fieldEvidence", "doesNotAssert", "issuedAt"]
SUBMEMBERS = {
    "agent": ["id", "credentialDigest", "authentication", "signers"],
    "delegation": ["subject", "subjectKind", "authorityDigest"],
    "resource": ["kind", "id", "binding"],
    "decision": ["action", "requestDigest", "reported", "decisionPointId", "policyDigest", "reportedAt"],
    "evaluation": ["status", "inputs"],
    "effect": ["observed", "interval", "pathScope", "writes"],
    "effect.interval": ["beforeRoot", "afterRoot", "baseResolution", "openedAt", "sealedAt"],
    "correlation": ["id", "scope", "timeBasis"],
    "posture": ["reported", "reportedDigest", "observed", "observedDigest", "assessedAt", "agreement"],
    "observation": ["vantage", "coverage"],
    "observation.coverage": ["scopeComplete", "gaps"],
}
COMMITMENT_MEMBERS = ["committedAt", "witnessNonce", "commitmentDigest", "keyid", "sig"]
WRITE_MEMBERS = ["path", "preStateDigest", "postStateDigest", "requestDigest", "inScope"]
REMEDIATION_MEMBERS = ["cause", "signalReceivedAt", "enforcedAt", "enforcement"]
CONSUMPTION_MEMBERS = ["limitDigest", "unit", "limit", "consumed", "reserved", "requested", "held", "stateRevision"]


class Malformed(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# ---------------------------------------------------------------- JSON profile

def utf16_key(s):
    return s.encode("utf-16-be")


def ecma_number(x):
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)
    sign = "-" if r.startswith("-") else ""
    r = r.lstrip("-")
    mant, exp = (r.lower().split("e") + ["0"])[:2]
    exp = int(exp)
    ip, fp = (mant.split(".") + [""])[:2]
    digits = (ip + fp).lstrip("0")
    n = len(ip.lstrip("0")) + exp if ip.strip("0") else exp - (len(fp) - len(fp.lstrip("0")))
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + s


def jcs(value):
    """RFC 8785 canonical JSON, as text."""
    if isinstance(value, dict):
        return "{" + ",".join(jcs(k) + ":" + jcs(v) for k, v in sorted(value.items(), key=lambda kv: utf16_key(kv[0]))) + "}"
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise Malformed("statement-malformed")
        return ecma_number(value)
    raise Malformed("statement-malformed")


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def parse_strict(raw_bytes):
    """Section 4.1: no repeated member at any depth, safe integers, depth <= 128."""
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise Malformed("duplicate-member")
            d[k] = v
        return d

    def parse_int(s):
        n = int(s)
        if abs(n) >= SAFE_INT:
            raise Malformed("unsafe-integer")
        return n

    def parse_float(s):
        raise Malformed("value-not-representable")   # a number with a fraction (vector X1): not representable under the profile

    try:
        text = raw_bytes.decode("utf-8")
        value = json.loads(text, object_pairs_hook=pairs, parse_int=parse_int, parse_float=parse_float)
    except Malformed:
        raise
    except RecursionError:
        raise Malformed("nesting-too-deep")
    except Exception:
        raise Malformed("not-parseable")

    def depth(o, d=1):
        if d > MAX_DEPTH:
            raise Malformed("nesting-too-deep")
        if isinstance(o, dict):
            for v in o.values():
                depth(v, d + 1)
        elif isinstance(o, list):
            for v in o:
                depth(v, d + 1)
    depth(value)
    return value


# ---------------------------------------------------------------- helpers

def t(s):
    """RFC 3339 date-time to aware datetime; Malformed otherwise."""
    if not isinstance(s, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})", s):
        raise Malformed("timestamp-malformed")
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise Malformed("timestamp-malformed")


def is_hex64(s):
    return isinstance(s, str) and re.fullmatch(r"[0-9a-f]{64}", s) is not None


def under(path, scope):
    """A path lies under a scope member (Section 5.3: as inScope is derived)."""
    if scope == "/":
        return True
    return path == scope or path.startswith(scope if scope.endswith("/") else scope + "/")


def nonneg_int(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


# ---------------------------------------------------------------- the verifier

class Report:
    def __init__(self):
        self.codes = []
        self.derived_tier = None
        self.within_limit = None
        self.identity = None      # sha256 of decoded payload bytes (Section 5.10)
        self.keyid = None
        self.statement = None

    def add(self, code):
        if code not in self.codes:
            self.codes.append(code)

    @property
    def verdict(self):
        return "malformed" if self.codes else "valid"


def verify_envelope(env, keys):
    """Judge one DSSE envelope. keys: {keyid: 32-byte public key}."""
    rep = Report()
    try:
        _verify(env, keys, rep)
    except Malformed as e:
        rep.add(e.code)
    return rep


def _verify(env, keys, rep):
    if not isinstance(env, dict) or env.get("payloadType") != PAYLOAD_TYPE or not isinstance(env.get("signatures"), list):
        raise Malformed("envelope-unreadable")
    try:
        payload = base64.b64decode(env["payload"], validate=True)
    except Exception:
        raise Malformed("envelope-unreadable")
    rep.identity = sha256_hex(payload)
    stmt = parse_strict(payload)                       # 4.6 first: the JSON profile
    rep.statement = stmt
    canon = jcs(stmt).encode("utf-8")                  # 4.6 second: the signature over JCS bytes
    pae = b"DSSEv1 " + str(len(PAYLOAD_TYPE)).encode() + b" " + PAYLOAD_TYPE.encode() + b" " + str(len(canon)).encode() + b" " + canon
    ok = False
    for s in env["signatures"]:
        kid = s.get("keyid") if isinstance(s, dict) else None
        pk = keys.get(kid)
        if pk is None:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(base64.b64decode(s["sig"]), pae)
            ok, rep.keyid = True, kid
            break
        except (InvalidSignature, Exception):
            continue
    if not ok:
        raise Malformed("signature-invalid")

    if not isinstance(stmt, dict):
        raise Malformed("statement-shape")
    if stmt.get("_type") != STATEMENT_TYPE:
        raise Malformed("statement-type-unexpected")
    if stmt.get("predicateType") not in (PREDICATE_TYPE, PREDICATE_TYPE_V2):
        raise Malformed("predicate-type-mismatch")
    if not isinstance(stmt.get("subject"), list) or not isinstance(stmt.get("predicate"), dict):
        raise Malformed("statement-shape")
    p = stmt["predicate"]
    subj = stmt["subject"]
    # -03 Section 8: the v2 URI publishes the set of Section 5.4 extended by principal-standing-source; under the v1
    # URI that value is one a verifier is required to refuse
    inputs_vocab = VOCAB["evaluation.input"] | ({"principal-standing-source"} if stmt["predicateType"] == PREDICATE_TYPE_V2 else set())

    # 4.2 subject convention, checked before membership as the reference order has it
    interval = p.get("effect", {}).get("interval") if isinstance(p.get("effect"), dict) else None
    if (len(subj) == 2) != (interval is not None) or len(subj) not in (1, 2):
        raise Malformed("subject-interval-mismatch")

    # membership (Section 4, Section 5)
    for m in REQUIRED:
        if m not in p:
            raise Malformed("member-missing")
    for parent, subs in SUBMEMBERS.items():
        o = p
        for k in parent.split("."):
            o = o.get(k) if isinstance(o, dict) else None
        if not isinstance(o, dict):
            raise Malformed("member-missing")
        for s in subs:
            if s not in o:
                raise Malformed("member-missing")
    if not isinstance(p["evaluation"]["inputs"], list):
        raise Malformed("member-missing")
    for e in p["evaluation"]["inputs"]:
        if not isinstance(e, dict):
            raise Malformed("evaluation-entry-malformed")
        for s in ("input", "lastResult", "maxAge"):
            if s not in e:
                raise Malformed("member-missing")
    if "oversight" in p:
        if not isinstance(p["oversight"], dict) or "act" not in p["oversight"]:
            raise Malformed("member-missing")
    for w in p["effect"]["writes"] if isinstance(p["effect"]["writes"], list) else []:
        if not isinstance(w, dict) or any(k not in w for k in WRITE_MEMBERS):
            raise Malformed("member-missing")
    for r in p["remediation"] if isinstance(p["remediation"], list) else []:
        if not isinstance(r, dict) or any(k not in r for k in REMEDIATION_MEMBERS):
            raise Malformed("member-missing")
    if not isinstance(p["fieldEvidence"], dict) or set(p["fieldEvidence"]) != FIELD_EVIDENCE_KEYS:
        raise Malformed("field-evidence-keys")
    for e in p["evaluation"]["inputs"]:
        if "consumption" in e:
            c = e["consumption"]
            if not isinstance(c, dict) or any(k not in c for k in CONSUMPTION_MEMBERS if k != "unit") \
                    or ("unit" not in c and "asset" not in c):
                raise Malformed("member-missing")
            if "operationKey" not in p["decision"]:
                raise Malformed("member-missing")

    # closed vocabularies
    def vocab(path, value):
        if value not in VOCAB[path]:
            raise Malformed("value-outside-vocabulary")
    vocab("tier", p["tier"])
    vocab("hashAlgorithm", p["hashAlgorithm"])
    vocab("agent.authentication", p["agent"]["authentication"])
    vocab("delegation.subjectKind", p["delegation"]["subjectKind"])
    vocab("resource.kind", p["resource"]["kind"])
    vocab("resource.binding", p["resource"]["binding"])
    vocab("decision.reported", p["decision"]["reported"])
    vocab("effect.observed", p["effect"]["observed"])
    vocab("effect.interval.baseResolution", p["effect"]["interval"]["baseResolution"])
    vocab("agreement", p["agreement"])
    if p["agreement"] == "one-sided":
        raise Malformed("agreement-reserved-value")
    vocab("evaluation.status", p["evaluation"]["status"])
    for e in p["evaluation"]["inputs"]:
        if e["input"] not in inputs_vocab:
            raise Malformed("value-outside-vocabulary")
    if "unavailableInput" in p["evaluation"] and isinstance(p["evaluation"]["unavailableInput"], list):
        for u in p["evaluation"]["unavailableInput"]:
            if u not in inputs_vocab:
                raise Malformed("value-outside-vocabulary")
    if "oversight" in p:
        vocab("oversight.act", p["oversight"]["act"])
    vocab("correlation.scope", p["correlation"]["scope"])
    vocab("correlation.timeBasis", p["correlation"]["timeBasis"])
    if isinstance(p["correlation"].get("externalAnchor"), dict):
        vocab("correlation.externalAnchor.kind", p["correlation"]["externalAnchor"].get("kind"))
    vocab("posture", p["posture"]["reported"])
    vocab("posture", p["posture"]["observed"])
    vocab("posture.agreement", p["posture"]["agreement"])
    for r in p["remediation"]:
        vocab("remediation.cause", r["cause"])
        vocab("remediation.enforcement", r["enforcement"])
    vocab("observation.vantage", p["observation"]["vantage"])
    for v in p["fieldEvidence"].values():
        vocab("fieldEvidence", v)

    # 5.4 evaluation
    ev = p["evaluation"]
    if set(ev) - {"status", "inputs", "unavailableInput"}:
        raise Malformed("evaluation-malformed")
    seen = set()
    reported_at = t(p["decision"]["reportedAt"])
    unavailable = []
    for e in ev["inputs"]:
        if set(e) - {"input", "lastResult", "maxAge", "consumption"}:
            raise Malformed("evaluation-entry-malformed")
        if not nonneg_int(e["maxAge"]):
            raise Malformed("evaluation-entry-malformed")
        if e["input"] in seen:
            raise Malformed("evaluation-input-repeated")
        seen.add(e["input"])
        if e["lastResult"] == "none":
            unavailable.append(e["input"])
        else:
            lr = t(e["lastResult"])
            if (lr - reported_at).total_seconds() > SKEW:
                raise Malformed("evaluation-result-after-decision")
            if (reported_at - lr).total_seconds() > e["maxAge"]:
                unavailable.append(e["input"])
        if "consumption" in e and e["input"] != "consumption-state":
            raise Malformed("consumption-misplaced")
    if ev["status"] == "evaluated":
        if "unavailableInput" in ev or unavailable:
            raise Malformed("evaluation-inconsistent")
    else:
        ui = ev.get("unavailableInput")
        if not isinstance(ui, list) or not ui or len(set(ui)) != len(ui) or set(ui) != set(unavailable):
            raise Malformed("evaluation-inconsistent")

    # 5.5 oversight, 5.10 sequence
    if "oversight" in p and set(p["oversight"]) - {"act", "recordDigest"}:
        raise Malformed("oversight-malformed")
    if "sequence" in p:
        sq = p["sequence"]
        if not isinstance(sq, dict) or set(sq) != {"boundary", "seq"} or not isinstance(sq["boundary"], str) \
                or not isinstance(sq["seq"], int) or isinstance(sq["seq"], bool) or sq["seq"] < 1:
            raise Malformed("sequence-malformed")

    # 5.9 consumption
    for e in ev["inputs"]:
        if "consumption" in e:
            c = e["consumption"]
            if set(c) - set(CONSUMPTION_MEMBERS) - {"supersedes", "asset"}:
                raise Malformed("consumption-malformed")
            ok_ = p["decision"].get("operationKey")
            if not isinstance(ok_, str) or ok_ == "":
                raise Malformed("operation-key-invalid")   # vector X7
            for k in ("limit", "consumed", "reserved", "requested", "stateRevision"):
                if not nonneg_int(c[k]):
                    raise Malformed("consumption-value-invalid")
            # the denomination: an ISO 4217 unit or an exact asset (corpus README, CS34 to CS37), never both
            if "unit" in c and "asset" in c:
                raise Malformed("consumption-unit-ambiguous")
            if "asset" in c:
                a = c["asset"]
                if not isinstance(a, dict) or set(a) != {"id", "decimals"} or not isinstance(a["id"], str) \
                        or not re.fullmatch(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}", a["id"]) \
                        or not nonneg_int(a["decimals"]) or a["decimals"] > 255:
                    raise Malformed("consumption-value-invalid")
            # a replaced limit document (corpus README, CS23, CS24): a digest, and not this record's own limitDigest
            if "supersedes" in c:
                if not is_hex64(c["supersedes"]):
                    raise Malformed("consumption-value-invalid")
                if c["supersedes"] == c["limitDigest"]:
                    raise Malformed("consumption-supersedes-self")
            if not isinstance(c["held"], list):
                raise Malformed("consumption-value-invalid")
            keys_seen = set()
            for h in c["held"]:
                if not isinstance(h, dict) or any(k not in h for k in ("operationKey", "requestDigest", "amount")) or not nonneg_int(h["amount"]):
                    raise Malformed("consumption-value-invalid")
                if set(h) - {"operationKey", "requestDigest", "amount"}:
                    raise Malformed("consumption-malformed")   # vector X6
                if h["operationKey"] in keys_seen:
                    raise Malformed("consumption-held-key-repeated")
                keys_seen.add(h["operationKey"])
            if sum(h["amount"] for h in c["held"]) != c["reserved"]:
                raise Malformed("consumption-reserved-mismatch")
            held = [h for h in c["held"] if h["operationKey"] == p["decision"]["operationKey"]]
            if held:
                if held[0]["requestDigest"] != p["decision"]["requestDigest"] or held[0]["amount"] != c["requested"]:
                    raise Malformed("consumption-key-reused")
                rep.within_limit = c["consumed"] + c["reserved"] <= c["limit"]
            else:
                rep.within_limit = c["consumed"] + c["reserved"] + c["requested"] <= c["limit"]

    # 5.2 delegation and binding
    d = p["delegation"]
    if (d["subjectKind"] == "none") != (d["subject"] == "none"):
        raise Malformed("delegation-subject-inconsistent")
    r = p["resource"]
    if r["binding"] == "digest-bound" and not is_hex64(r.get("argumentsDigest")):
        raise Malformed("arguments-digest-missing")
    if r["binding"] == "not-bindable" and "argumentsDigest" in r:
        raise Malformed("arguments-digest-forbidden")

    # 5.3 request digest and subject binding
    req = {"action": p["decision"]["action"], "resourceId": r["id"], "resourceKind": r["kind"]}
    if r["binding"] == "digest-bound":
        req["argumentsDigest"] = r["argumentsDigest"]
    rd = sha256_hex(jcs(req).encode("utf-8"))
    s0 = subj[0].get("digest", {}).get("sha256") if isinstance(subj[0], dict) else None
    if p["decision"]["requestDigest"] != rd:
        raise Malformed("request-digest-mismatch")
    if s0 != rd:
        raise Malformed("subject-request-mismatch")
    iv = p["effect"]["interval"]
    s1 = subj[1].get("digest", {}).get("sha256") if isinstance(subj[1], dict) else None
    if s1 != iv["afterRoot"]:
        raise Malformed("subject-after-root-mismatch")
    # -03 Section 5.1 (vectors IS1, IS2): issuedAt MUST be at or after the interval's sealedAt, however far earlier;
    # a check on the two stated times, not on any clock
    if t(p["issuedAt"]) < t(iv["sealedAt"]):
        raise Malformed("issued-before-sealed")

    # 5.6 external anchor, remediation order
    if (p["correlation"]["timeBasis"] == "beacon-anchored") != ("externalAnchor" in p["correlation"]):
        raise Malformed("external-anchor-inconsistent")
    for rm in p["remediation"]:
        if t(rm["enforcedAt"]) < t(rm["signalReceivedAt"]):
            raise Malformed("remediation-order")

    # 5.3 empty tree; 5.7 commitment
    if iv["baseResolution"] == "empty-tree" and iv["beforeRoot"] != EMPTY_TREE_SHA256:
        raise Malformed("empty-tree-constant-mismatch")
    pc = p["observation"].get("priorCommitment")
    if isinstance(pc, dict) and all(k in pc for k in COMMITMENT_MEMBERS):
        if pc["keyid"] in p["agent"]["signers"]:
            raise Malformed("commitment-key-is-agent-signer")
        if not t(pc["committedAt"]) < t(iv["openedAt"]):
            raise Malformed("commitment-order")
        cd = sha256_hex(jcs({"authorityDigest": d["authorityDigest"], "beforeRoot": iv["beforeRoot"],
                             "recordId": p["recordId"], "witnessNonce": pc["witnessNonce"]}).encode("utf-8"))
        if pc["commitmentDigest"] != cd:
            raise Malformed("commitment-digest-mismatch")

    # 5.3 write chain
    running = iv["beforeRoot"]
    for w in p["effect"]["writes"]:
        if w["preStateDigest"] != running:
            raise Malformed("write-chain-broken")
        running = w["postStateDigest"]
    if running != iv["afterRoot"]:
        raise Malformed("write-chain-broken")

    # 5.3 path scope, 5.7 coverage, tier, write scope
    scope = p["effect"]["pathScope"]
    if not isinstance(scope, list) or any(not isinstance(m, str) or re.search(r"[*?\[]", m) for m in scope):
        raise Malformed("path-scope-glob")
    cov = p["observation"]["coverage"]
    gaps_inside = [g for g in cov["gaps"] if any(under(g, m) for m in scope)]
    if cov["scopeComplete"] is True and gaps_inside:
        raise Malformed("coverage-inconsistent")
    clauses = [
        ("tier-overclaim-vantage", p["observation"]["vantage"] == "below-observed"),
        ("tier-overclaim-commitment", isinstance(pc, dict) and all(k in pc for k in COMMITMENT_MEMBERS)),
        ("tier-overclaim-scope", bool(scope)),
        ("tier-overclaim-coverage", cov["scopeComplete"] is True and not gaps_inside),
        ("tier-overclaim-binding", r["binding"] == "digest-bound"),
    ]
    derived = "authoritative" if all(ok for _, ok in clauses) else "voluntary"
    if p["tier"] == "authoritative" and derived != "authoritative":
        raise Malformed(next(code for code, ok in clauses if not ok))
    rep.derived_tier = derived
    for w in p["effect"]["writes"]:
        if w["inScope"] != any(under(w["path"], m) for m in scope):
            raise Malformed("write-scope-mismatch")

    # 5.3 observed effect and agreement; posture agreement; field evidence
    mine = [w for w in p["effect"]["writes"] if w["requestDigest"] == rd]
    unattributed_inside = [w for w in p["effect"]["writes"] if w["requestDigest"] == "unattributed" and w["inScope"]]
    observed = "occurred" if mine else ("none" if not unattributed_inside else "unknown")
    if p["effect"]["observed"] != observed:
        raise Malformed("effect-observed-underivable")
    dec = p["decision"]["reported"]
    table = {("permit", "occurred"): "agree", ("permit-with-conditions", "occurred"): "agree",
             ("deny", "none"): "agree", ("deny", "occurred"): "disagree",
             ("permit", "none"): "not-exercised", ("permit-with-conditions", "none"): "not-exercised"}
    expected_agreement = "indeterminate" if observed == "unknown" else table[(dec, observed)]
    if p["agreement"] != expected_agreement:
        raise Malformed("agreement-underivable")
    po = p["posture"]
    if po["agreement"] != ("agree" if po["reported"] == po["observed"] else "disagree"):
        raise Malformed("posture-agreement-underivable")
    if p["observation"]["vantage"] == "self" and "substrate-covered" in p["fieldEvidence"].values():
        raise Malformed("field-evidence-self-substrate")


# ---------------------------------------------------------------- sets (5.9, 5.10)

def verify_set(records, keys):
    reps = [verify_envelope(r, keys) for r in records]
    codes, missing = [], []
    good = [r for r in reps if r.verdict == "valid"]
    if len(good) < len(reps):
        codes.append("set-record-malformed")   # vector X18: a set holding a malformed record
    # consumption across records under one limitDigest, ordered by stateRevision
    cons = []
    for r in good:
        p = r.statement["predicate"]
        for e in p["evaluation"]["inputs"]:
            if "consumption" in e:
                cons.append((e["consumption"]["stateRevision"], p, e["consumption"]))
    cons.sort(key=lambda x: x[0])
    # the ledgers (corpus README, CS18 to CS25): two limitDigest values are one ledger when any record names one as the
    # other's supersedes, transitively; stateRevision orders the whole ledger. Unlinked values are separate ledgers.
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for _, _, c in cons:
        find(c["limitDigest"])
        if "supersedes" in c:
            parent[find(c["supersedes"])] = find(c["limitDigest"])
    by_ledger = {}
    for rev, p, c in cons:
        by_ledger.setdefault(find(c["limitDigest"]), []).append((rev, p, c))

    def denomination(c):
        return ("unit", c["unit"]) if "unit" in c else ("asset", c["asset"]["id"], c["asset"]["decimals"])
    for lim, items in by_ledger.items():
        # Section 5.9, across the records of one ledger, followed by operationKey.
        # A permit stays held until a record of the same operation shows none or occurred.
        settled = {p["decision"]["operationKey"] for _, p, _ in items if p["effect"]["observed"] in ("none", "occurred")}
        if len({denomination(c) for _, _, c in items}) > 1 and "consumption-set-asset-mismatch" not in codes:
            codes.append("consumption-set-asset-mismatch")   # one ledger counts one denomination (CS38, CS39)
        for rev, p, c in items:
            own = p["decision"]["operationKey"]
            held_keys = {h["operationKey"] for h in c["held"]}
            is_permit = p["decision"]["reported"] in ("permit", "permit-with-conditions")
            for rev2, p2, c2 in items:
                for k in {h["operationKey"] for h in c2["held"]}:
                    if k == own or k in held_keys:
                        continue
                    if rev2 > rev and is_permit:
                        # vector CS7 / CS17: this permit read a state older than a record that
                        # already held an unsettled permit, and omits that permit from its own held
                        if "consumption-set-stale-revision" not in codes:
                            codes.append("consumption-set-stale-revision")
                    if rev2 < rev and k not in settled:
                        # vector CS8: released from held with no record of that operation
                        # showing none or occurred
                        if "consumption-set-release-unshown" not in codes:
                            codes.append("consumption-set-release-unshown")
    # a held claim is keyed by the principal, the agent key and the operation key, never by the limit document
    # (corpus README, CS26 to CS33): a permit whose own key an earlier record of the same scope holds, and which
    # does not hold that key itself, presents a retry as a new operation; a call whose tool sent nothing leaves no claim
    def scope(p):
        return (p["delegation"]["subject"], tuple(sorted(p["agent"]["signers"])) if isinstance(p["agent"]["signers"], list) else None)
    for rev, p, c in cons:
        own = p["decision"]["operationKey"]
        if p["decision"]["reported"] not in ("permit", "permit-with-conditions") or p["effect"]["observed"] == "none":
            continue
        if any(h["operationKey"] == own for h in c["held"]):
            continue
        holds = [rev2 for rev2, p2, c2 in cons if rev2 < rev and scope(p2) == scope(p) and any(h["operationKey"] == own for h in c2["held"])]
        if not holds:
            continue
        # the claim ended if, after it was last held and before this permit, a record of the operation in the same
        # scope showed none or occurred (CS28); otherwise this permit presents a retry as a new operation
        ended = any(max(holds) <= rev3 < rev and scope(p3) == scope(p) and p3["decision"]["operationKey"] == own
                    and p3["effect"]["observed"] in ("none", "occurred") for rev3, p3, _ in cons)
        if not ended and "consumption-set-retry-as-new" not in codes:
            codes.append("consumption-set-retry-as-new")
    # sequence: same boundary and same signing key
    series = {}
    for r in good:
        sq = r.statement["predicate"].get("sequence")
        if isinstance(sq, dict):
            series.setdefault((sq["boundary"], r.keyid), {}).setdefault(sq["seq"], set()).add(r.identity)
    for (boundary, _), seqs in series.items():
        if any(len(ids) > 1 for ids in seqs.values()):
            codes.append("sequence-duplicate")
        for n in range(1, max(seqs)):
            if n not in seqs:
                missing.append({"boundary": boundary, "seq": n})
    return reps, {"codes": codes, "verdict": "malformed" if codes else "valid", "missing": missing,
                  "withinLimit": [r.within_limit for r in reps]}


# ---------------------------------------------------------------- anchors (4.7.2)

def inclusion_root(leaf, index, size, path):
    """RFC 9162 Section 2.1.3.2: the root an inclusion path leads to from a leaf hash, or None if the path does not
    fit the tree size."""
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return None
        if fn % 2 == 1 or fn == sn:
            r = hashlib.sha256(b"\x01" + p + r).digest()
            while not (fn % 2 == 1 or fn == 0):
                fn >>= 1
                sn >>= 1
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def read_transitem(raw):
    """An RFC 9162 TransItem of type inclusion_proof_v2: (log_id hex, tree_size, leaf_index, [node hashes]);
    None if the bytes do not read as one."""
    try:
        if struct.unpack(">H", raw[:2])[0] != INCLUSION_PROOF_V2:
            return None
        n = raw[2]
        log_id = raw[3:3 + n].hex()
        p = 3 + n
        size, index = struct.unpack(">QQ", raw[p:p + 16])
        p += 16
        plen = struct.unpack(">H", raw[p:p + 2])[0]
        p += 2
        end = p + plen
        if end != len(raw) or n < 2:
            return None
        path = []
        while p < end:
            k = raw[p]
            if k != 32 or p + 1 + k > end:
                return None
            path.append(raw[p + 1:p + 1 + k])
            p += 1 + k
        return log_id, size, index, path
    except Exception:
        return None


def read_ots(raw):
    """The OpenTimestamps serialisation: (digest the proof commits to, [(ops, attestation tag, payload)]) with ops
    among append, prepend and sha256; None if the bytes do not read as a proof over a SHA-256 digest."""
    try:
        pos = 0

        def take(n):
            nonlocal pos
            if pos + n > len(raw):
                raise ValueError
            pos += n
            return raw[pos - n:pos]

        def varint():
            v, shift = 0, 0
            while True:
                b = take(1)[0]
                v |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    return v

        def varbytes():
            return take(varint())
        if take(len(OTS_MAGIC)) != OTS_MAGIC:
            return None
        varint()                      # version
        if take(1) != b"\x08":        # sha256
            return None
        msg = take(32)
        branches = []

        def walk(ops):
            while True:
                tag = take(1)[0]
                if tag == 0x00:
                    branches.append((ops, take(8), varbytes()))
                    return
                if tag == 0xFF:
                    walk(list(ops))
                    continue
                if tag == 0xF0:
                    ops.append(("append", varbytes()))
                elif tag == 0xF1:
                    ops.append(("prepend", varbytes()))
                elif tag == 0x08:
                    ops.append(("sha256", None))
                else:
                    ops.append(("unsupported", tag))
        walk([])
        if pos != len(raw):
            return None
        return msg, branches
    except Exception:
        return None


def validate_anchor(anchor, envelope_digest, trust):
    """One anchor under Section 4.7.2 against what the verifier holds (trust: the MANIFEST's anchorTrust). Returns a
    dict: validated (bool), and for a validated anchor its time (aware datetime), kind, origin, and height for an
    opentimestamps anchor; otherwise why it did not validate."""
    out = {"kind": anchor.get("kind"), "origin": anchor.get("origin"), "validated": False}
    try:
        raw = base64.b64decode(anchor["proof"], validate=True)
    except Exception:
        out["why"] = "proof not base64"
        return out
    digest = bytes.fromhex(envelope_digest)
    if anchor.get("kind") == "transparency-log":
        item = read_transitem(raw)
        if item is None:
            out["why"] = "not an inclusion_proof_v2 TransItem"
            return out
        log_id, size, index, path = item
        root = inclusion_root(hashlib.sha256(b"\x00" + digest).digest(), index, size, path)
        heads = [h for h in trust.get("treeHeads", []) if h.get("logId") == log_id and h.get("treeSize") == size]
        if root is None or not heads:
            out["why"] = "path does not fit the tree size" if root is None else "no head held for this log and tree size"
            return out
        for h in heads:
            if root.hex() == h.get("rootHash"):
                out.update(validated=True, time=t(h["timestamp"]), basis="hash commitment: a head the verifier holds")
                return out
        out["why"] = "recomputed root is not a head held for this log and tree size"
        return out
    if anchor.get("kind") == "opentimestamps":
        proof = read_ots(raw)
        if proof is None:
            out["why"] = "not an OpenTimestamps proof over a SHA-256 digest"
            return out
        msg, branches = proof
        if msg != digest:
            out["why"] = "the proof commits to another digest"
            return out
        headers = {h["height"]: bytes.fromhex(h["header"]) for h in trust.get("blockHeaders", [])}
        found = []
        for ops, tag, payload in branches:
            if tag != OTS_BITCOIN:
                continue
            d = msg
            for op, arg in ops:
                d = d + arg if op == "append" else arg + d if op == "prepend" else hashlib.sha256(d).digest() if op == "sha256" else None
                if d is None:
                    break
            height, shift = 0, 0
            for b in payload:
                height |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            hdr = headers.get(height)
            if d is not None and hdr is not None and len(hdr) == 80 and d == hdr[36:68]:
                found.append((height, datetime.datetime.fromtimestamp(struct.unpack("<I", hdr[68:72])[0], datetime.timezone.utc)))
        if found:
            height, when = min(found)
            out.update(validated=True, time=when, height=height, basis="hash commitment: a block header the verifier holds")
            return out
        out["why"] = "pending attestation only" if not any(tag == OTS_BITCOIN for _, tag, _ in branches) else \
            "no Bitcoin attestation recomputes to a held header's Merkle root"
        return out
    out["why"] = "not attempted: no certification path held for an rfc3161 token" if anchor.get("kind") == "rfc3161" else "unknown kind"
    return out


def earlier(a, b):
    """Section 4.7.2: where both times compared are opentimestamps anchors', compare block heights, not times."""
    if a is None:
        return b
    if b is None:
        return a
    if "height" in a and "height" in b:
        return a if a["height"] <= b["height"] else b
    return a if a["time"] <= b["time"] else b


def tolerance(anchor):
    return OTS_ALLOWANCE if anchor.get("kind") == "opentimestamps" else SKEW


def iso(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- retained (4.7)

def verify_retained(env, entry, keys, trust):
    rep = verify_envelope(env, keys)
    dating = {"codes": [], "anchors": [], "notAttempted": []}
    if rep.statement is None:   # the record cannot be read (vector X15): nothing of the entry is dated
        dating.update(codes=["entry-record-unreadable"], entry="malformed", delegationRoot={"result": "not-established"})
        return rep, dating
    codes = []   # the entry's codes accumulate: a mismatch or an inconsistency does not stop the dating (vectors R9, X12, X13)
    try:
        # the entry's shape first: an entry that is not an object, a received that is not a boolean, anchors that are
        # not an array, or an anchor that is not an object, is unreadable as an entry and nothing in it is dated
        if not isinstance(entry, dict) or not isinstance(entry.get("anchors", []), list) \
                or entry.get("received") not in (True, False) or not is_hex64(entry.get("envelopeDigest")) \
                or not all(isinstance(a, dict) for a in entry.get("anchors", [])) \
                or ("receivedAt" in entry and not isinstance(entry["receivedAt"], str)):
            raise Malformed("entry-shape-malformed")
        # every anchor is over the digest of the envelope's canonical bytes (Section 4.7): the verifier recomputes it,
        # and an entry that states another value is noted (vector X12) while the anchors are still read over the envelope
        envelope_digest = sha256_hex(jcs(env).encode("utf-8"))
        if entry["envelopeDigest"] != envelope_digest:
            codes.append("entry-envelope-digest-mismatch")
        rec = entry["received"]
        if (rec is True) != ("receivedAt" in entry):
            codes.append("entry-received-at-inconsistent")
            rec = rec is True and "receivedAt" in entry
        anchors = entry.get("anchors", [])
        results = [validate_anchor(a, envelope_digest, trust) for a in anchors]
        dating["anchors"] = [{k: (iso(v) if k == "time" else v) for k, v in r.items()} for r in results]
        dating["notAttempted"] = [r["why"] for r in results if str(r.get("why", "")).startswith("not attempted")]
        valid = [r for r in results if r["validated"]]
        dated = None
        for r in valid:
            dated = earlier(dated, r)
        if dated:
            dating["datedAt"] = iso(dated["time"])
        retention = None
        for r in valid:
            if r.get("origin") == "retainer":
                retention = earlier(retention, r)
        if rec is True and not any(a.get("origin") == "retainer" for a in anchors):
            codes.append("entry-retainer-anchor-missing")
        issued = t(rep.statement["predicate"]["issuedAt"]) if rep.statement is not None else None
        received_at = t(entry["receivedAt"]) if rec is True else None
        if rec is True and issued is not None and (issued - received_at).total_seconds() > SKEW:
            codes.append("entry-received-before-issued")
        if retention is not None:
            tol = tolerance(retention)
            if rec is True and (received_at - retention["time"]).total_seconds() > tol:
                codes.append("entry-received-after-anchor")
            lower = received_at if rec is True else issued
            within = entry.get("anchorWithin")
            if lower is not None and nonneg_int(within) and (retention["time"] - lower).total_seconds() > within + tol:
                codes.append("entry-anchor-late")
        roots = [x for x in entry.get("validationData", []) if isinstance(x, dict) and x.get("for") == "delegation-root"]
        root_digest = rep.statement["predicate"]["delegation"].get("rootDigest") if rep.statement else None
        dating["delegationRoot"] = {"result": "not-established"}
        if len(roots) > 1:
            codes.append("entry-shape-malformed")
        elif roots and root_digest is None:
            codes.append("entry-delegation-root-unexpected")
        elif roots:
            try:
                material = base64.b64decode(roots[0]["value"], validate=True)
            except Exception:
                material = None
                codes.append("entry-delegation-root-unreadable")
            if material is not None and sha256_hex(material) != root_digest:
                codes.append("entry-delegation-root-mismatch")
            elif material is not None:
                alg = None
                try:
                    jwks = json.loads(material)
                    k = jwks["keys"][0]
                    alg = "Ed25519" if k.get("kty") == "OKP" and k.get("crv") == "Ed25519" else k.get("alg")
                except Exception:
                    pass
                dating["delegationRoot"] = {"result": "established", "algorithm": alg}
    except Malformed as e:
        codes.append(e.code)
        dating.pop("datedAt", None)
        dating.setdefault("delegationRoot", {"result": "not-established"})
    dating["codes"] = codes
    dating["entry"] = "malformed" if codes else "well-formed"
    # Section 4.7.1: a receivedAt that passes the check is asserted and consistent with the anchors, never established
    if isinstance(entry, dict) and entry.get("received") is True and not codes:
        dating["receipt"] = "asserted-consistent"
    return rep, dating


# ---------------------------------------------------------------- judge

def judge(corpus, report_path=None):
    m = json.load(open(os.path.join(corpus, "MANIFEST.json")))
    keys = {v["keyid"]: bytes.fromhex(v["publicKey"]) for v in m["keys"].values()}
    rows, agree, first_agree = [], 0, 0
    partial = 0
    for v in m["vectors"]:
        exp = v["expected"]
        doc = json.load(open(os.path.join(corpus, v["file"])))
        notes = []
        if "records" in doc:
            reps, setres = verify_set(doc["records"], keys)
            rep = reps[0]
            verdict = "malformed" if any(r.verdict == "malformed" for r in reps) else "valid"
            codes = [c for r in reps for c in r.codes]
            ok = verdict == exp.get("verdict", "valid")
            es = exp.get("set", {})
            if es:
                ok = ok and set(es.get("codes", [])) == set(setres["codes"]) and es.get("verdict") == setres["verdict"]
                if "missing" in es:
                    ok = ok and es["missing"] == setres["missing"]
                if "withinLimit" in es:
                    ok = ok and es["withinLimit"] == setres["withinLimit"]
                notes.append(f"set={setres['codes'] or setres['verdict']}")
            tier = reps[0].derived_tier
        elif "envelope" in doc:
            if "retention" in doc:
                rep, dating = verify_retained(doc["envelope"], doc["retention"], keys, m.get("anchorTrust", {}))
                verdict, codes, tier = rep.verdict, rep.codes, rep.derived_tier
            else:  # a retained member with no retention entry (vector X16): unreadable as a retained member
                rep = verify_envelope(doc["envelope"], keys)
                verdict, codes, tier = "malformed", ["retained-unreadable"], rep.derived_tier
                dating = {"codes": ["retained-unreadable"], "entry": "malformed", "delegationRoot": {"result": "not-established"}, "notAttempted": []}
            ok = verdict == exp.get("verdict", "valid")
            ed = exp.get("dating", {})
            ok = ok and set(ed.get("codes", [])) == set(dating["codes"])
            ok = ok and ed.get("datedAt") == dating.get("datedAt")
            ok = ok and ed.get("entry") == dating.get("entry")
            ok = ok and ed.get("receipt") == dating.get("receipt")
            if "delegationRoot" in ed:
                ok = ok and ed["delegationRoot"].get("result") == dating.get("delegationRoot", {}).get("result")
                if "algorithm" in ed["delegationRoot"]:
                    ok = ok and ed["delegationRoot"]["algorithm"] == dating["delegationRoot"].get("algorithm")
            if dating["notAttempted"]:
                partial += 1
            notes.append("dating=" + (",".join(dating["codes"]) or "well-formed") + (" datedAt=" + dating["datedAt"] if "datedAt" in dating else " not dated"))
        else:
            rep = verify_envelope(doc, keys)
            verdict, codes, tier = rep.verdict, rep.codes, rep.derived_tier
            if v["kind"] == "indeterminate":
                ok = verdict == "valid" if not exp.get("codes") else True
            else:
                ok = verdict == exp.get("verdict", "valid" if v["kind"] == "accept" else "malformed")
        exp_codes = set(exp.get("codes", []))
        if exp_codes:
            ok = ok and bool(exp_codes & set(codes))
            if codes and codes[0] in exp_codes:
                first_agree += 1
        if "derivedTier" in exp and verdict == "valid":
            ok = ok and exp["derivedTier"] == tier
        if "withinLimit" in exp and "records" not in doc:
            ok = ok and exp["withinLimit"] == rep.within_limit
        agree += ok
        rows.append({"draftId": v["draftId"], "kind": v["kind"], "expected": exp.get("verdict", v["kind"]), "expectedCodes": sorted(exp_codes),
                     "got": verdict, "codes": codes, "derivedTier": tier, "agree": ok, "notes": notes, "row": v["row"]})
    n = len(rows)
    out = {"corpus": m["suite"], "draft": m["draft"], "members": n, "agree": agree,
           "firstCodeAgree": first_agree, "rejectMembers": sum(1 for r in rows if r["expectedCodes"]),
           "datingNotAttempted": partial, "rows": rows}
    for r in rows:
        if not r["agree"]:
            print(f"DISAGREE {r['draftId']:6} expected {r['expected']:9} {r['expectedCodes']} | got {r['got']:9} {r['codes']} {' '.join(r['notes'])} | {r['row'][:70]}")
    print(f"# {m['suite']}: {agree}/{n} members agree with MANIFEST (verdict, codes, derivedTier, withinLimit, set, dating: "
          f"codes, datedAt, entry, receipt, delegation root); first refusal code agrees on {first_agree}/{out['rejectMembers']} "
          f"reject members; {partial} retained members with an anchor not attempted (rfc3161 only)")
    if report_path:
        json.dump(out, open(report_path, "w"), indent=1)
    return 0 if agree == n else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--report")
    a = ap.parse_args()
    sys.exit(judge(a.corpus, a.report))
