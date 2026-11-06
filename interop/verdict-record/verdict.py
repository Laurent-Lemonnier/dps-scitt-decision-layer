#!/usr/bin/env python3
"""A checker of verdict records, written from the text of draft-wright-verdict-record-02 and from nothing else:
no code of its author was read. Section numbers in the comments are that draft's.

What the checker takes as its own inputs (Section 4.2, Section 4.5): its policy; its trust anchors (the keys it
accepts for writers, and whatever the format rules it holds need); the rule specifications it holds (a registry
of rule name -> function and input types); the format rules it holds (a registry of format name -> function over
the item's bytes and the other items held). What it takes from the presenter: the record's exact bytes, the
container that carries them (Section 3), and the evidence items by their digests. It reads no clock (Section 4.1).

The report names a state (released, held, refused, or no verdict) and every step's result; it never says of the
whole record that it is verified, valid, true, trusted, correct, proven, confirmed or OK (Section 4.4).
"""
import base64
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERSION = "verdict-record/1"
MEMBERS = ("v", "kind", "key", "version", "supersedes", "writer", "actor", "act_time", "evidence", "check", "body")
REQUIRED = ("v", "kind", "key", "version", "writer", "body")
KINDS = ("check-run", "model-decision")
TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")      # Section 2.1: exactly six fraction digits
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")                                        # Section 2.1: lowercase, no prefix
INT_MAX = 2 ** 53 - 1
MAX_DEPTH = 32
FORBIDDEN_WORDS = ("verified", "valid", "true", "trusted", "correct", "proven", "confirmed", "ok")


class Refused(Exception):
    """Bytes or members that break Section 2.1, or Section 2.2 outside evidence and check: refused before any step."""


# ---------------------------------------------------------------- Section 2.1: canonical form and strict JSON

def _escape(s):
    out = []
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ord(ch) < 0x20:
            # a control character is escaped; the draft does not say in which of RFC 8259's forms (ambiguity log A1):
            # this checker writes the short forms RFC 8259 names and \u00XX for the others
            out.append({"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(ch, "\\u%04x" % ord(ch)))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def canonical(value):
    """Section 2.1: members sorted by name as sequences of code points, no whitespace, minimal escapes, literal
    UTF-8, integers only, arrays in order."""
    if isinstance(value, dict):
        return "{" + ",".join(_escape(k) + ":" + canonical(value[k]) for k in sorted(value)) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, str):
        return _escape(value)
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        if abs(value) > INT_MAX:
            raise Refused("Section 2.1: an integer lies between -(2^53 - 1) and 2^53 - 1")
        return str(value)
    raise Refused(f"Section 2.1: numbers are integers; a {type(value).__name__} is not written")


def canonical_bytes(value):
    return canonical(value).encode("utf-8")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Refused(f"Section 2.1: member name {k!r} appears twice in one object")
        d[k] = v
    return d


def _no_float(s):
    raise Refused(f"Section 2.1: numbers are integers; {s!r} is not one")


def _no_constant(s):
    raise Refused(f"Section 2.1: {s!r} is not a JSON value")


def _depth(v, level):
    if level > MAX_DEPTH:
        raise Refused(f"Section 2.1: JSON nested deeper than {MAX_DEPTH} levels")
    if isinstance(v, dict):
        for k, x in v.items():
            _surrogates(k)
            _depth(x, level + 1)
    elif isinstance(v, list):
        for x in v:
            _depth(x, level + 1)
    elif isinstance(v, str):
        _surrogates(v)
    elif isinstance(v, int) and not isinstance(v, bool) and abs(v) > INT_MAX:
        raise Refused("Section 2.1: an integer lies between -(2^53 - 1) and 2^53 - 1")


def _surrogates(s):
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise Refused("Section 2.1: an escape forms a lone surrogate")


def strict_json(raw):
    """Section 2.1's strict JSON: UTF-8 without a byte-order mark, no duplicate member, no lone surrogate, integers
    only, at most 32 levels. Raises Refused. Used for the record and, at step 3, for an item read by pointer."""
    if raw[:3] == b"\xef\xbb\xbf":
        raise Refused("Section 2.1: the bytes start with a byte-order mark")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Refused(f"Section 2.1: not valid UTF-8 ({e.reason})")
    try:
        value = json.loads(text, object_pairs_hook=_no_dupes, parse_float=_no_float, parse_constant=_no_constant)
    except json.JSONDecodeError as e:
        raise Refused(f"Section 2.1: not JSON ({e.msg})")
    _depth(value, 1)
    return value


def parse_record(raw):
    """The record's bytes to its value, refusing what Section 2.1 refuses, and requiring that re-serializing the
    parsed record gives the same bytes."""
    value = strict_json(raw)
    if not isinstance(value, dict):
        raise Refused("Section 2.1: a verdict record is a JSON object")
    if canonical_bytes(value) != raw:
        raise Refused("Section 2.1: re-serializing the parsed record does not give the same bytes (not canonical form)")
    return value


# ---------------------------------------------------------------- Section 2.2, 2.3: members outside evidence and check

def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def check_members(r):
    """Section 2.2 outside evidence and check, and Section 2.3: what is refused before any step runs."""
    extra = [k for k in r if k not in MEMBERS]
    if extra:
        raise Refused(f"Section 2.2: no other member is allowed ({', '.join(sorted(extra))})")
    missing = [k for k in REQUIRED if k not in r]
    if missing:
        raise Refused(f"Section 2.2: members that MUST be present are missing ({', '.join(missing)})")
    if r["v"] != VERSION:
        raise Refused(f"Section 2.2: v is {r['v']!r}; this document defines {VERSION!r}")
    kind = r["kind"]
    if not isinstance(kind, str) or not (kind in KINDS or kind.startswith("x-")):
        # a kind this document does not define and that is not private: refused here (ambiguity log A5)
        raise Refused("Section 2.2: kind is not one this document defines nor a private kind")
    if not isinstance(r["key"], str) or not r["key"]:
        raise Refused("Section 2.2: key is a non-empty string")
    if not _is_int(r["version"]) or r["version"] < 1:
        raise Refused("Section 2.2: version is an integer of 1 or more")
    sup = r.get("supersedes")
    if r["version"] == 1 and sup is not None:
        raise Refused("Section 2.2: supersedes is null for version 1")
    if r["version"] > 1 and not (isinstance(sup, str) and HEX64_RE.match(sup)):
        raise Refused("Section 2.2: for a later version, supersedes is the digest of the previous version")
    if not isinstance(r["writer"], str) or not r["writer"]:
        raise Refused("Section 2.2: writer is a non-empty string")
    if "actor" in r:
        a = r["actor"]
        if not isinstance(a, dict) or a.get("type") not in ("person", "system") or not isinstance(a.get("id"), str):
            raise Refused("Section 2.2: actor has members type (person or system) and id")
        want = {"type", "id"} | ({"model", "model_version"} if a["type"] == "system" else set())
        if set(a) != want or not all(isinstance(a[k], str) for k in want):
            raise Refused("Section 2.2: actor's members are type and id, and for a system also model and model_version")
    if "act_time" in r and not (isinstance(r["act_time"], str) and TIME_RE.match(r["act_time"])):
        raise Refused("Section 2.1: a time is written YYYY-MM-DDTHH:MM:SS.ffffffZ")
    body = r["body"]
    if not isinstance(body, dict):
        raise Refused("Section 2.2: body is an object")
    claim = body.get("claim")
    if not isinstance(claim, dict) or set(claim) not in ({"text"}, {"ref"}):
        raise Refused("Section 2.3: body.claim is an object with exactly one of text or ref")
    if "text" in claim and not isinstance(claim["text"], str):
        raise Refused("Section 2.3: claim.text is a string")
    if "ref" in claim:
        if not entry_ok(claim["ref"]):
            raise Refused("Section 2.3: claim.ref is an evidence entry")
        if claim["ref"] not in (r.get("evidence") if isinstance(r.get("evidence"), list) else []):
            raise Refused("Section 2.3: the entry claim.ref names MUST also appear in evidence")


def entry_ok(e):
    return (isinstance(e, dict) and set(e) == {"sha256", "format"} and isinstance(e["sha256"], str)
            and HEX64_RE.match(e["sha256"]) is not None and isinstance(e["format"], str) and bool(e["format"]))


# ---------------------------------------------------------------- Section 4.5: the checker's policy

def policy_valid(p):
    """A policy lists the kinds for which judgement is allowed, the formats it can verify, and the citation depth
    (an integer of 0 or more); optionally that inputs are read from evidence only. Anything else: invalid."""
    if not isinstance(p, dict):
        return False
    for k in ("judgement_kinds", "formats"):
        if not isinstance(p.get(k), list) or not all(isinstance(x, str) for x in p[k]):
            return False
    if not _is_int(p.get("citation_depth")) or p["citation_depth"] < 0:
        return False
    if "inputs_from_evidence_only" in p and not isinstance(p["inputs_from_evidence_only"], bool):
        return False
    return set(p) <= {"judgement_kinds", "formats", "citation_depth", "inputs_from_evidence_only"}


# ---------------------------------------------------------------- Section 3: the container

def container_shows(raw, container, anchors):
    """Section 3: from the container a checker needs the exact bytes, a key that bound them shown to belong to the
    party named in writer, and an upper time bound it establishes itself. This case's container is a detached
    Ed25519 signature over the exact bytes (a stand-in for a SCITT Signed Statement and its Receipt); the key is
    shown to belong to the writer by the checker's trust anchors (writer -> key_ref -> public key). The upper time
    bound is the checker's own intake time for those bytes (anchors['intake'][digest]), not a statement of the
    issuer or of the container. Returns (shown, reason, upper_time_bound)."""
    d = sha256(raw)
    bound = (anchors.get("intake") or {}).get(d)
    if container is None:
        return False, "no container carries the record", bound
    if container.get("record_sha256") != d:
        return False, "the container names other bytes than those held", bound
    writer = container.get("writer")
    keys = (anchors.get("writers") or {}).get(writer) or {}
    pub_hex = keys.get(container.get("key_ref"))
    if pub_hex is None:
        return False, f"the key {container.get('key_ref')!r} is not shown to belong to {writer!r}", bound
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(base64.b64decode(container.get("signature_b64", "")), raw)
    except (InvalidSignature, ValueError):
        return False, "the signature over the record's bytes does not verify under the writer's key", bound
    if bound is None:
        return False, "the checker has no upper time bound of its own for these bytes", None
    return True, None, bound


# ---------------------------------------------------------------- Section 4: the check

def resolve_pointer(doc, pointer):
    """RFC 6901. Returns (found, value)."""
    if pointer == "":
        return True, doc
    if not pointer.startswith("/"):
        return False, None
    cur = doc
    for tok in pointer[1:].split("/"):
        tok = tok.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict):
            if tok not in cur:
                return False, None
            cur = cur[tok]
        elif isinstance(cur, list):
            if not re.match(r"^(0|[1-9][0-9]*)$", tok) or int(tok) >= len(cur):
                return False, None
            cur = cur[int(tok)]
        else:
            return False, None
    return True, cur


JSON_TYPES = {"string": str, "integer": int, "object": dict, "array": list, "boolean": bool, "null": type(None)}


def _of_type(v, name):
    if name == "any":
        return True
    if name == "integer":
        return _is_int(v)
    if name == "boolean":
        return isinstance(v, bool)
    return isinstance(v, JSON_TYPES[name])


class Checker:
    """One checker: its policy, trust anchors, rule specifications and format rules are its own inputs."""

    def __init__(self, policy, anchors, rules, formats):
        self.policy, self.anchors, self.rules, self.formats = policy, anchors, rules, formats

    def own_inputs(self):
        return {"policy_sha256": sha256(canonical_bytes(self.policy)) if policy_valid(self.policy) else None,
                "trust_anchors_sha256": sha256(canonical_bytes(self.anchors)),
                "rule_specifications_held": sorted(self.rules), "format_rules_held": sorted(self.formats)}

    def check(self, raw, items, container=None, depth=0):
        """raw: the record's exact bytes; items: dict digest -> (bytes, container or None) of every evidence item
        the presenter hands over (a cited verdict record comes with its own container). Returns the report."""
        report = {"record_sha256": sha256(raw), "depth": depth, **self.own_inputs()}
        if not policy_valid(self.policy):
            report.update({"state": "no verdict", "reason": "Section 4.5: the checker's policy is invalid"})
            return report
        shown, reason, bound = container_shows(raw, container, self.anchors)
        report["upper_time_bound"] = bound
        try:
            r = parse_record(raw)
            check_members(r)
        except Refused as e:
            report.update({"state": "refused", "before_steps": str(e), "steps": {}})
            return report
        report["key"], report["version"], report["supersedes"], report["writer"] = r["key"], r["version"], r.get("supersedes"), r["writer"]
        steps, relied, body_inputs = {}, {}, []
        # Step 1
        chk = r.get("check")
        if not isinstance(chk, dict) or set(chk) - {"rule", "inputs", "result"} or not {"rule", "result"} <= set(chk) \
                or not isinstance(chk["rule"], str) or not chk["rule"]:
            steps["1"] = {"result": "FAIL", "why": "Section 4.3 step 1: check MUST be present, name a rule and give a result"}
        elif chk["rule"] == "judgement" and r["kind"] not in self.policy["judgement_kinds"]:
            steps["1"] = {"result": "FAIL", "why": f"Section 4.3 step 1: judgement is not allowed for kind {r['kind']!r} by the policy"}
        else:
            steps["1"] = {"result": "PASS"}
        # Step 2
        ev = r.get("evidence")
        s2 = {"result": "PASS", "items": []}
        if not isinstance(ev, list) or not all(entry_ok(e) for e in ev):
            s2 = {"result": "FAIL", "why": "Section 4.3 step 2: evidence MUST be an array of entries as in Section 2.2", "items": []}
            ev = []
        for i, e in enumerate(ev):
            it = {"index": i, "sha256": e["sha256"], "format": e["format"]}
            held = items.get(e["sha256"])
            if held is None:
                it["held"] = False
                s2["result"], s2["why"], s2["needs"] = "NOT RUN", f"Section 4.3 step 2: no item held with the digest of entry {i}", f"evidence[{i}]"
            elif e["format"] not in self.policy["formats"]:
                it["held"], it["format_rules"] = True, "not in the checker's policy"
                s2["result"], s2["why"], s2["needs"] = "NOT RUN", f"Section 4.3 step 2: the policy does not list format {e['format']!r} (entry {i})", f"evidence[{i}]"
            elif e["format"] == VERSION:
                if depth + 1 > self.policy["citation_depth"]:
                    it["held"], it["format_rules"] = True, f"beyond the citation depth {self.policy['citation_depth']}"
                    s2["result"], s2["why"], s2["needs"] = "NOT RUN", f"Section 4.3 step 2: entry {i} is a verdict record beyond the citation depth", f"evidence[{i}]"
                else:
                    sub = self.check(held[0], items, held[1], depth + 1)
                    it["held"], it["cited_record"] = True, {k: sub.get(k) for k in ("state", "key", "version", "upper_time_bound")}
                    if sub["state"] != "released":
                        it["format_rules"] = f"the cited verdict record's state is {sub['state']}"
                        s2["result"], s2["why"], s2["needs"] = "NOT RUN", f"Section 4.3 step 2, Section 6: the verdict record cited at entry {i} is not released", f"evidence[{i}]"
                    elif bound is not None and sub.get("upper_time_bound") is not None and sub["upper_time_bound"] > bound:
                        it["format_rules"] = "its upper time bound is later than the citing record's"
                        s2["result"], s2["why"], s2["needs"] = "NOT RUN", f"Section 4.3 step 2: the item at entry {i} has a later upper time bound than the record citing it", f"evidence[{i}]"
                    else:
                        it["format_rules"] = "met"
                        relied[i] = held[0]
            else:
                ok, why, item_bound = self.formats[e["format"]](held[0], items, self.anchors)
                it["held"], it["format_rules"] = True, "met" if ok else f"not met: {why}"
                if item_bound is not None and bound is not None and item_bound > bound:
                    ok, it["format_rules"] = False, "its upper time bound is later than the citing record's"
                if ok:
                    relied[i] = held[0]
                else:
                    s2["result"], s2["why"], s2["needs"] = "NOT RUN", f"Section 4.3 step 2: the item at entry {i} is not relied on ({it['format_rules']})", f"evidence[{i}]"
            s2["items"].append(it)
        steps["2"] = s2
        # Step 3
        s3 = {"result": "PASS"}
        if steps["1"]["result"] == "FAIL":
            s3 = {"result": "NOT RUN", "why": "Section 4.3 step 3: no rule to re-run (step 1 failed)", "needs": "check.rule"}
        elif chk["rule"] == "judgement":
            s3 = {"result": "PASS", "note": "Section 5: judgement, no rule re-run; the check shows what the result was based on, and when"}
        elif chk["rule"] not in self.rules:
            s3 = {"result": "NOT RUN", "why": f"Section 4.3 step 3: the checker does not hold the specification of rule {chk['rule']!r}", "needs": "the rule's specification"}
        else:
            spec = self.rules[chk["rule"]]
            inputs_decl = chk.get("inputs", {})
            resolved, fails, not_run = {}, [], []
            if not isinstance(inputs_decl, dict):
                fails.append("check.inputs is not an object")
                inputs_decl = {}
            for name, where in inputs_decl.items():
                if isinstance(where, str):
                    if self.policy.get("inputs_from_evidence_only"):
                        not_run.append(f"{name}: read from body, which the policy excludes")
                        continue
                    if where not in r["body"]:
                        fails.append(f"{name}: no such member of body ({where!r})")
                        continue
                    resolved[name] = r["body"][where]
                    body_inputs.append(name)
                elif isinstance(where, dict) and "evidence" in where and set(where) <= {"evidence", "pointer"} and _is_int(where["evidence"]):
                    idx = where["evidence"]
                    if not 0 <= idx < len(ev):
                        fails.append(f"{name}: no such evidence entry ({idx})")
                        continue
                    if idx not in relied:
                        not_run.append(f"{name}: bound to evidence[{idx}], which step 2 does not rely on")
                        continue
                    if "pointer" not in where:
                        resolved[name] = sha256(relied[idx])
                        continue
                    if not isinstance(where["pointer"], str):
                        fails.append(f"{name}: pointer is not a string")
                        continue
                    try:
                        doc = strict_json(relied[idx])
                    except Refused as e:
                        fails.append(f"{name}: the item at evidence[{idx}] is not JSON by the rules of Section 2.1 ({e})")
                        continue
                    found, v = resolve_pointer(doc, where["pointer"])
                    if not found:
                        fails.append(f"{name}: pointer {where['pointer']!r} does not resolve in evidence[{idx}]")
                        continue
                    resolved[name] = v
                else:
                    fails.append(f"{name}: a binding object with another member, or neither a string nor a binding")
            for name, tname in spec["inputs"].items():
                if name not in inputs_decl:
                    fails.append(f"{name}: the rule needs this input and check.inputs does not name it")
                elif name in resolved and not _of_type(resolved[name], tname):
                    fails.append(f"{name}: of the wrong JSON type (the rule reads a {tname})")
            for name in inputs_decl:
                if name not in spec["inputs"]:
                    fails.append(f"{name}: the rule takes no such input")
            if fails:
                s3 = {"result": "FAIL", "why": "Section 4.3 step 3: " + "; ".join(fails)}
            elif not_run:
                s3 = {"result": "NOT RUN", "why": "Section 4.3 step 3: " + "; ".join(not_run), "needs": not_run}
            else:
                got = spec["run"](resolved)
                s3["re_run_result"] = got
                if got != chk["result"]:
                    s3 = {"result": "FAIL", "why": "Section 4.3 step 3: the re-run result does not equal check.result", "re_run_result": got, "check_result": chk["result"]}
        steps["3"] = s3
        results = [steps[k]["result"] for k in ("1", "2", "3")]
        if not shown:
            state = "held"
            report["container"] = {"shows_the_record": False, "reason": reason}
        elif "FAIL" in results:
            state = "refused"
        elif "NOT RUN" in results:
            state = "held"
        else:
            state = "released"
        if shown:
            report["container"] = {"shows_the_record": True}
        report.update({"state": state, "steps": steps, "body_inputs_read": body_inputs,
                       "first_failed_step": next((k for k in ("1", "2", "3") if steps[k]["result"] == "FAIL"), None),
                       "first_not_run_step": next((k for k in ("1", "2", "3") if steps[k]["result"] == "NOT RUN"), None),
                       "summary": f"state {state}; step 1 {results[0]}; step 2 {results[1]}; step 3 {results[2]}"
                                  + ("" if shown else f"; container: {reason}")})
        return report


def report_wording_ok(report):
    """Section 4.4: no word that speaks for the whole record as 'this is true'. Checked over the report's own
    member names and the state word; values quoted from the items (such as a DPS dimension's status) are not the
    checker's statement about the whole record, and are not scanned."""
    def names(v):
        if isinstance(v, dict):
            for k, x in v.items():
                yield k
                yield from names(x)
        elif isinstance(v, list):
            for x in v:
                yield from names(x)
    words = set(names(report)) | {report.get("state", "")}
    return not any(w.lower() in FORBIDDEN_WORDS for w in words)
