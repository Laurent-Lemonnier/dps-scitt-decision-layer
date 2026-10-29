#!/usr/bin/env python3
"""Independent verifier for the agent audit record of
draft-gilda-audit-agent-audit-record-02, written from the draft text (Sections
4 and 5) and from the corpus MANIFEST's published test keys only. It imports
nothing from the agent-evidence-vectors package and shares no code with its
reference rail. The refusal codes are the names the corpus publishes, so that
two implementations can compare where they stopped.

Scope (29/10/2026): single records (statements/), sets (sets/) and the verdict
of retained records (retained/). Of the dating check of Section 4.7.1 it does
the parts that need no anchor validation (received/receivedAt consistency,
retainer-anchor presence, receivedAt before issuedAt, delegation-root element
rules). Anchor proofs (transparency-log, opentimestamps) are not validated, so
datedAt and the bracket checks that need an anchor time are reported as not
attempted, never as passed.

Usage: gilda_verify_independent.py --corpus DIR [--report out.json]
"""
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
# Section 5.3 / vector E3: the empty-tree constant under sha256. This is the
# SHA-256 of a git tree object with no entries ("tree 0\0").
EMPTY_TREE_SHA256 = hashlib.sha256(b"tree 0\0").hexdigest()
SAFE_INT = 2 ** 53  # RFC 7493 I-JSON, Section 4.1.1
MAX_DEPTH = 128     # Section 4.1.2
SKEW = 300          # skew tolerance, seconds (MANIFEST skewTolerance)

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

    try:
        text = raw_bytes.decode("utf-8")
        value = json.loads(text, object_pairs_hook=pairs, parse_int=parse_int)
    except Malformed:
        raise
    except RecursionError:
        raise Malformed("nesting-too-deep")
    except Exception:
        raise Malformed("statement-malformed")

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
        raise Malformed("statement-malformed")
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


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
        raise Malformed("statement-malformed")
    try:
        payload = base64.b64decode(env["payload"], validate=True)
    except Exception:
        raise Malformed("statement-malformed")
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

    if not isinstance(stmt, dict) or stmt.get("_type") != STATEMENT_TYPE or stmt.get("predicateType") != PREDICATE_TYPE \
            or not isinstance(stmt.get("subject"), list) or not isinstance(stmt.get("predicate"), dict):
        raise Malformed("statement-malformed")
    p = stmt["predicate"]
    subj = stmt["subject"]

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
            if not isinstance(c, dict) or any(k not in c for k in CONSUMPTION_MEMBERS):
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
        vocab("evaluation.input", e["input"])
    if "unavailableInput" in p["evaluation"] and isinstance(p["evaluation"]["unavailableInput"], list):
        for u in p["evaluation"]["unavailableInput"]:
            vocab("evaluation.input", u)
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
            if set(c) - set(CONSUMPTION_MEMBERS):
                raise Malformed("consumption-malformed")
            for k in ("limit", "consumed", "reserved", "requested", "stateRevision"):
                if not nonneg_int(c[k]):
                    raise Malformed("consumption-value-invalid")
            if not isinstance(c["held"], list):
                raise Malformed("consumption-value-invalid")
            keys_seen = set()
            for h in c["held"]:
                if not isinstance(h, dict) or any(k not in h for k in ("operationKey", "requestDigest", "amount")) or not nonneg_int(h["amount"]):
                    raise Malformed("consumption-value-invalid")
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
    if p["decision"]["requestDigest"] != rd or s0 != rd:
        raise Malformed("request-digest-mismatch")
    iv = p["effect"]["interval"]
    s1 = subj[1].get("digest", {}).get("sha256") if isinstance(subj[1], dict) else None
    if s1 != iv["afterRoot"]:
        raise Malformed("subject-after-root-mismatch")

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
    # consumption across records under one limitDigest, ordered by stateRevision
    cons = []
    for r in good:
        p = r.statement["predicate"]
        for e in p["evaluation"]["inputs"]:
            if "consumption" in e:
                cons.append((e["consumption"]["stateRevision"], p, e["consumption"]))
    cons.sort(key=lambda x: x[0])
    by_limit = {}
    for rev, p, c in cons:
        by_limit.setdefault(c["limitDigest"], []).append((rev, p, c))
    for lim, items in by_limit.items():
        # Section 5.9, across records under one limitDigest, followed by operationKey.
        # A permit stays held until a record of the same operation shows none or occurred.
        settled = {p["decision"]["operationKey"] for _, p, _ in items if p["effect"]["observed"] in ("none", "occurred")}
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


# ---------------------------------------------------------------- retained (4.7), partial

def verify_retained(env, entry, keys):
    rep = verify_envelope(env, keys)
    dating = {"codes": [], "attempted": [], "notAttempted": ["anchor validation", "datedAt", "entry-anchor-late", "entry-received-after-anchor"]}
    try:
        if not isinstance(entry, dict):
            raise Malformed("entry-malformed")
        if entry.get("envelopeDigest") != sha256_hex(jcs(env).encode("utf-8")):
            raise Malformed("entry-envelope-digest-mismatch")
        dating["attempted"].append("envelopeDigest")
        rec = entry.get("received")
        if rec not in (True, False) or (rec is True) != ("receivedAt" in entry):
            raise Malformed("entry-received-at-inconsistent")
        dating["attempted"].append("received/receivedAt")
        if rec is True and not any(a.get("origin") == "retainer" for a in entry.get("anchors", [])):
            raise Malformed("entry-retainer-anchor-missing")
        dating["attempted"].append("retainer anchor present")
        if rec is True and rep.statement is not None:
            issued = t(rep.statement["predicate"]["issuedAt"])
            if (issued - t(entry["receivedAt"])).total_seconds() > SKEW:
                raise Malformed("entry-received-before-issued")
            dating["attempted"].append("receivedAt vs issuedAt")
        roots = [x for x in entry.get("validationData", []) if x.get("for") == "delegation-root"]
        root_digest = rep.statement["predicate"]["delegation"].get("rootDigest") if rep.statement else None
        if len(roots) > 1 or (roots and root_digest is None):
            raise Malformed("entry-malformed")
        if roots and root_digest is not None:
            material = base64.b64decode(roots[0]["value"])
            if sha256_hex(material) != root_digest:
                raise Malformed("entry-delegation-root-mismatch")
            alg = None
            try:
                jwks = json.loads(material)
                k = jwks["keys"][0]
                alg = "Ed25519" if k.get("kty") == "OKP" and k.get("crv") == "Ed25519" else k.get("alg")
            except Exception:
                pass
            dating["delegationRoot"] = {"result": "established", "algorithm": alg}
        else:
            dating["delegationRoot"] = {"result": "not-established"}
        dating["attempted"].append("delegation root")
    except Malformed as e:
        dating["codes"].append(e.code)
    dating["entry"] = "malformed" if dating["codes"] else "well-formed (as far as attempted)"
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
            rep, dating = verify_retained(doc["envelope"], doc["retention"], keys)
            verdict, codes, tier = rep.verdict, rep.codes, rep.derived_tier
            ok = verdict == exp.get("verdict", "valid")
            ed = exp.get("dating", {})
            exp_codes = set(ed.get("codes", []))
            if exp_codes <= {"entry-received-at-inconsistent", "entry-retainer-anchor-missing", "entry-received-before-issued", "entry-delegation-root-mismatch"}:
                ok = ok and exp_codes == set(dating["codes"])
                if "delegationRoot" in ed and "delegationRoot" in dating:
                    ok = ok and ed["delegationRoot"].get("result") == dating["delegationRoot"].get("result")
                notes.append("dating(partial)=" + (",".join(dating["codes"]) or "well-formed"))
            else:
                partial += 1
                notes.append("dating NOT ATTEMPTED (needs anchor validation): expected " + ",".join(exp_codes))
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
    print(f"# {m['suite']}: {agree}/{n} members agree with MANIFEST (verdict, codes, derivedTier, withinLimit, set); "
          f"first refusal code agrees on {first_agree}/{out['rejectMembers']} reject members; "
          f"{partial} retained members' dating not attempted (anchor validation out of scope today)")
    if report_path:
        json.dump(out, open(report_path, "w"), indent=1)
    return 0 if agree == n else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--report")
    a = ap.parse_args()
    sys.exit(judge(a.corpus, a.report))
