#!/usr/bin/env python3
"""Format rules for the two IronTrellis formats p08 lists, and the "Checking a cited entry" procedure, written from text only.

Source text (nothing else was read; no IronTrellis source code, no SPEC chapter):
- Ramesh Rampertab's proposed -01 section "Checking a cited entry", issue 13 comment 6701158070 of 7 November 2026
  (saved beside this file: irontrellis-checking-a-cited-entry-20261107.md), with its preamble naming the v2-g3 suite
  index conformance/v2-g3/INDEX.sha256 at 983a508c, SHA-256 4c745f10...a68b, and challengeProfile g3;
- conformance/README.md and conformance/v2-g3/README.md (983a508c; the v2-g3 README is byte-identical at a2c487f6);
- the files of the suite p08 cites: vectors.json and histories/budget-v2.json (a2c487f6, digests in SHA256SUMS),
  MANIFEST.json (same bytes at a2c487f6 and 983a508c) and INDEX.sha256 (983a508c only: at a2c487f6 there is none).

What a "format rule" is here (-02 Section 4.3 step 2, Section 7): a function (item bytes, items held, anchors) ->
(verifies, why, upper time bound of the item). The checker relies on an item whose rule says it verifies.

What his section lets a checker decide about one *item* without the citation (the record) in hand:
  "A replay identifier MUST name ... a behavior pin: the SHA-256 digest of a published conformance suite's index."
  "The suite index is a UTF-8 text file, one line per file of the suite, each line the file's lowercase hexadecimal
   SHA-256 digest, two spaces and its path, ending in a line feed. [...] The index lists every file in the suite's
   directory, excludes itself, and lists no symbolic links; that directory MUST hold everything needed to interpret
   the suite: the cases, their expected outputs, the histories they use ..."
So the rule for format <suite>#vectors (resp. #histories) is: the item's SHA-256 is listed in the suite index the
checker holds, under the path vectors.json (resp. a path under histories/), and that index's own SHA-256 is the
behavior pin the checker's policy accepts; the index itself is well formed by the paragraph quoted. A #histories
item is in addition read as the history encoding the files show (a JSON array of events {id, type, timestamp, data},
event 0 of type DEPLOYMENT_INITIALIZED carrying data.domain and data.policyVersion: the "presented genesis" his
step 2 reads). That is all "verifies" means for these two formats: the item is a file of the pinned suite, in the
shape the procedure needs. It does not mean the replay was run (see cited_entry: that is his Procedure, and it stops).

What his section makes a checker do with the *citation* (cited_entry below): steps 1 to 3 of his Procedure can be
done from the text and the files; step 4 ("Rebuild state from the genesis under the replay identifier, and re-derive
the decision ... ('The decision procedure')") needs the decision procedure and the record-chain hashing, which the
text handed to us does not contain, so the function stops there with his outcome NOT RUN, naming the identifier,
or earlier with INVALID CITATION / INDETERMINATE where the text says so.

Ambiguity log (numbered readings; R = the reading implemented, A = the alternative another reader could take):
 1. Format names. p08's formats are "<tree URL at a2c487f6>/conformance/v2-g3#vectors" and "...#histories". No text
    of his defines these names or their fragments. R: the fragment names the suite file (vectors -> vectors.json,
    histories -> any path under histories/) and the URL names the suite directory. A: the names are Darren's and
    bind nothing of the suite's; a checker holds no rule for them (what our run of 6 November did).
 2. The index to hold. The suite p08 cites is at a2c487f6 (6 Nov 14:40Z), where no INDEX.sha256 exists; the index
    he names is at 983a508c (7 Nov 02:34Z) and lists vectors.json, histories/budget-v2.json and MANIFEST.json with
    the digests of the a2c487f6 files (checked). R: the index pins file bytes, not a commit ("A second implementation
    can claim a suite digest; it cannot claim another implementation's source commit"), so an index published later
    may pin files cited earlier, and the pin the checker accepts is 4c745f10...a68b. A: an item cited before any
    index existed is outside any pinned suite ("An index MUST be published before any citation names its digest"),
    so nothing verifies.
 3. The item's upper time bound (-02 step 2 compares it with the record's). His text gives no time for a file; the
    head's "as-of time" is canonicalTime 1100, a scripted clock. R: None (no bound stated). A: the index's publication
    time (7 Nov 02:34Z), which is later than p08's record bound (1 Nov 12:00Z) and would make step 2 NOT RUN.
 4. "Position". The history file is a JSON array of 40 events with no position member; MANIFEST.json says eventCount
    40, head position 39, recordCount 75. R: position p = index in the events array (39 = the last event). A: p
    counts "records" (75), of which an event may make several; then the file does not show positions at all.
 5. "Timestamp" of the cited head. The cited head carries canonicalTime (1100); the event at 39 carries timestamp
    (1100). R: the two are compared. A: canonicalTime is not the event's timestamp (different member names, and the
    section says "timestamp"); nothing to compare, step 3 cannot be completed.
 6. "The domain and policy identifiers". The vector's input has domain {protocol, version, deploymentId},
    policyVersion and rootRecognitionPolicy; the genesis has the same three plus globalPolicySourceId and
    adapterPolicyHash. R: domain and policyVersion (the two he names: "domain", "policy"), rootRecognitionPolicy
    too. A: policyVersion only, or all five.
 7. Where the citation's bindings are read from, for a verdict record. R: a verdict record binds the case entry
    (evidence[0] by digest, pointer /57) and the history (evidence[1] by digest); the head, domain, policy ids,
    evaluation time, operation version and request are the members of that vector entry (bound "by value" inside a
    digest-bound file); the cited result is check.result. A: a binding nested in a digest-bound file is neither "by
    value" in the citation nor "by digest of canonical bytes" of the thing itself; the citation is then missing
    every binding but the result, INVALID CITATION at step 1 whatever else holds.
 8. The replay identifier in p08. The record names operationVersion (in the vector), a source commit (in the rule
    and format URLs), no challenge profile and no suite digest. R: the identifier is incomplete, INVALID CITATION
    ("A checker MUST NOT fill a gap from defaults"); the function also reports what the remaining steps give when the
    checker's own suite (profile g3, pin 4c745f10...) is taken as the identifier, labelled as such. A: the source
    commit at which MANIFEST.json says g3 stands for both; but his text says a commit is for retrieval only.
 9. "every field of the decision ... in versioned canonical bytes". check.result in p08 is a JSON object in the
    verdict record's canonical form; no IronTrellis versioned encoding of a decision is in the text. R: the fields
    are compared as JSON values (what -02 step 3 would do). A: the result must be the IronTrellis canonical bytes
    of a versioned decision, which the record does not carry: INVALID CITATION (malformed binding).
10. Anchoring. The head is read from the vector (and MANIFEST.json), published by the implementer in the suite the
    index pins. R: UNANCHORED (none of the three sources his text accepts: an owner head attestation under a key
    trusted independently of the history, a witness, a public chain anchor). A: a published suite index is a
    "source its own policy accepts" and the head is ANCHORED to it.
11. The record hash at p. "The chain hashes canonical record encodings, not the bytes of a file"; the hash function
    and the canonical record encoding are not in the text held. R: the hash check of step 3 cannot be done; the
    position and timestamp checks can; the function stops before step 4 and says so. A: the event at 39 is a
    STATE_CHECKPOINT whose data.head {hash, position 38} is the head before it, and a reader might take it for the
    cited head (it is not: position 38 != 39, hash differs).
"""
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import verdict  # noqa: E402

SUITE_TREE = "https://github.com/zerohourzulu/irontrellis/tree/a2c487f6cd3afee2e35c7f7f1b64c9d966bf8387/conformance/v2-g3"
FORMAT_VECTORS = SUITE_TREE + "#vectors"
FORMAT_HISTORIES = SUITE_TREE + "#histories"
# The behavior pin his comment states for v2-g3 (INDEX.sha256 at 983a508c), and the profile MANIFEST.json names.
INDEX_PIN = "4c745f10e00564eb7e48af35e4e592ae6ebed003c6b16affa5556b42f338a68b"
INDEX_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")


def parse_suite_index(index_bytes):
    """The suite index as his paragraph defines it. Returns {path: digest}; raises ValueError naming the first breach."""
    try:
        text = index_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("the index is not UTF-8")
    if not text.endswith("\n"):
        raise ValueError("the index does not end in a line feed")
    entries, seen = {}, []
    for n, line in enumerate(text[:-1].split("\n"), 1):
        m = INDEX_LINE.match(line)
        if not m:
            raise ValueError(f"line {n} is not '<lowercase hex sha256><two spaces><path>'")
        digest, path = m.groups()
        segs = path.split("/")
        if any(s in ("", ".", "..") for s in segs):
            raise ValueError(f"line {n}: path {path!r} has an empty, '.' or '..' segment")
        if path in entries:
            raise ValueError(f"line {n}: path {path!r} listed twice")
        if os.path.basename(path) == "INDEX.sha256":
            raise ValueError(f"line {n}: the index lists itself")
        entries[path] = digest
        seen.append(path.encode("utf-8"))
    if seen != sorted(seen):
        raise ValueError("entries are not sorted by the bytes of the path")
    return entries


def read_history(raw):
    """The history encoding the suite's files show. Returns (events, genesis) or raises ValueError."""
    try:
        doc = verdict.strict_json(raw)
    except verdict.Refused as e:
        raise ValueError(f"not JSON by -02 Section 2.1 ({e})")
    if not isinstance(doc, list) or not doc:
        raise ValueError("not a non-empty JSON array of events")
    for i, e in enumerate(doc):
        if not isinstance(e, dict) or not {"id", "type", "timestamp", "data"} <= set(e) or not isinstance(e["data"], dict):
            raise ValueError(f"event {i} is not an object with id, type, timestamp and data")
    g = doc[0]
    if g["type"] != "DEPLOYMENT_INITIALIZED" or not isinstance(g["data"].get("domain"), dict) or "policyVersion" not in g["data"]:
        raise ValueError("event 0 is not a DEPLOYMENT_INITIALIZED genesis carrying data.domain and data.policyVersion")
    return doc, g["data"]


def format_rules(index_bytes, accepted_pin=INDEX_PIN):
    """The two format rules. index_bytes: the suite index the checker holds. Each rule: (raw, items, anchors) ->
    (verifies, why, item upper time bound = None, reading 3)."""
    index_sha = hashlib.sha256(index_bytes).hexdigest()
    try:
        entries = parse_suite_index(index_bytes)
        index_err = None
    except ValueError as e:
        entries, index_err = {}, str(e)
    by_digest = {}
    for p, d in entries.items():
        by_digest.setdefault(d, []).append(p)

    def listed(raw, accept_path):
        if index_sha != accepted_pin:
            return None, f"the suite index held (sha256 {index_sha[:12]}...) is not the behavior pin this checker accepts ({accepted_pin[:12]}...)"
        if index_err:
            return None, f"the suite index held is not well formed: {index_err}"
        d = verdict.sha256(raw)
        paths = [p for p in by_digest.get(d, []) if accept_path(p)]
        if not paths:
            where = by_digest.get(d)
            return None, (f"the item's digest is listed in the pinned suite index only at {where}, not where the format's fragment points"
                          if where else "the item's digest is not listed in the pinned suite index (not a file of the suite)")
        return paths, None

    def vectors_rule(raw, items, anchors):
        paths, why = listed(raw, lambda p: p == "vectors.json")
        if why:
            return False, why, None
        try:
            doc = verdict.strict_json(raw)
        except verdict.Refused as e:
            return False, f"vectors.json of the pinned suite, but not JSON by -02 Section 2.1 ({e})", None
        if not isinstance(doc, list):
            return False, "vectors.json of the pinned suite, but not a JSON array of vectors", None
        return True, None, None

    def histories_rule(raw, items, anchors):
        paths, why = listed(raw, lambda p: p.startswith("histories/"))
        if why:
            return False, why, None
        try:
            read_history(raw)
        except ValueError as e:
            return False, f"{paths[0]} of the pinned suite, but {e}", None
        return True, None, None

    return {FORMAT_VECTORS: vectors_rule, FORMAT_HISTORIES: histories_rule}


# ---------------------------------------------------------------- his Procedure, steps 1 to 3, on the citation a verdict record carries
def _bind(record, items, name):
    """Reading 7: the value a check.inputs binding points at, from the items held. Returns (found, value, why)."""
    where = (record.get("check") or {}).get("inputs", {}).get(name)
    if not isinstance(where, dict) or "evidence" not in where:
        return False, None, f"check.inputs.{name} is not bound to evidence"
    ev = record.get("evidence") or []
    idx = where["evidence"]
    if not isinstance(idx, int) or not 0 <= idx < len(ev):
        return False, None, f"check.inputs.{name}: no such evidence entry"
    held = items.get(ev[idx]["sha256"])
    if held is None:
        return False, None, f"check.inputs.{name}: the item at evidence[{idx}] is not held"
    try:
        doc = verdict.strict_json(held[0] if isinstance(held, tuple) else held)
    except verdict.Refused as e:
        return False, None, f"check.inputs.{name}: the item is not JSON ({e})"
    found, v = verdict.resolve_pointer(doc, where.get("pointer", ""))
    if not found:
        return False, None, f"check.inputs.{name}: pointer {where.get('pointer')!r} does not resolve"
    return True, v, None


def cited_entry(record, items, index_bytes, challenge_profile, accepted_pin=INDEX_PIN):
    """His Procedure on the citation p08's record carries. Returns one outcome with its anchoring, head, source and
    as-of time (his step 6), and a 'with_checker_suite_as_identifier' view (reading 8). Stops before his step 4."""
    out = {"anchoring": "UNANCHORED", "head": None, "head_source": None, "as_of": None, "steps": []}
    # Step 1: validate the citation.
    missing = []
    ok_case, case, why = _bind(record, items, "case")
    if not ok_case:
        return {**out, "outcome": "INVALID CITATION", "why": why}
    inp = case.get("input") if isinstance(case, dict) else None
    if not isinstance(inp, dict):
        return {**out, "outcome": "INVALID CITATION", "why": "the bound case has no input object"}
    head = inp.get("expectedHistoryHead")
    if not (isinstance(head, dict) and {"hash", "position", "canonicalTime"} <= set(head)):
        missing.append("the cited head (hash, position, timestamp)")
    if not isinstance(inp.get("domain"), dict) or "policyVersion" not in inp:
        missing.append("the domain and policy identifiers")
    if "evaluationTime" not in inp:
        missing.append("the evaluation time")
    if not isinstance(inp.get("request"), dict):
        missing.append("the request")
    result = (record.get("check") or {}).get("result")
    if not isinstance(result, dict) or not {"decision", "code", "failureCodes", "scopeAssurance", "controllingAuthorityIds", "budgetId"} <= set(result):
        missing.append("the cited result with at least decision, code, ordered failure list, scope assurance, controlling authorities and budget fields")
    out["head"] = head
    out["head_source"] = f"the vector entry bound at check.inputs.case (evidence[{record['check']['inputs']['case']['evidence']}]{record['check']['inputs']['case'].get('pointer', '')}), published by the implementer in the suite; not an owner head attestation, witness or chain anchor"
    out["as_of"] = (head or {}).get("canonicalTime")
    # the replay identifier: operation version, every verdict-changing encoding setting, the behavior pin
    ident = {"operation_version": inp.get("operationVersion"), "challenge_profile": None, "suite_index_sha256": None,
             "source_commit_in_urls": re.search(r"/tree/([0-9a-f]{40})/", record["check"]["rule"]).group(1) if re.search(r"/tree/([0-9a-f]{40})/", record["check"].get("rule", "")) else None}
    ident_missing = [k for k in ("operation_version", "challenge_profile", "suite_index_sha256") if ident[k] is None]
    if ident_missing:
        missing.append("the replay identifier (" + ", ".join(ident_missing) + " not named by the record; a source commit is for retrieval only)")
    out["replay_identifier_in_citation"] = ident
    out["steps"].append({"1": "INVALID CITATION" if missing else "done", "missing": missing})
    if missing:
        out.update({"outcome": "INVALID CITATION", "why": "step 1: the citation does not bind: " + "; ".join(missing)})
    # Reading 8: what the remaining steps give if the checker's own suite were the identifier (labelled, not his outcome).
    alt = {"identifier_taken": {"operation_version": ident["operation_version"], "challenge_profile": challenge_profile,
                                "suite_index_sha256": hashlib.sha256(index_bytes).hexdigest()}, "steps": []}
    accepted = alt["identifier_taken"]["suite_index_sha256"] == accepted_pin and challenge_profile == "g3"
    alt["steps"].append({"1": "done" if accepted else "INVALID CITATION (identifier not accepted)"})
    # Step 2: check the context against the presented genesis.
    ok_h, hist, why = _bind(record, items, "history")
    if not ok_h:
        alt["steps"].append({"2": "INDETERMINATE", "why": why})
        alt["outcome"] = "INDETERMINATE"
    else:
        try:
            events, genesis = read_history(verdict.canonical_bytes(hist))
        except ValueError as e:
            events, genesis = None, None
            alt["steps"].append({"2": "INDETERMINATE", "why": f"the presented history: {e}"})
            alt["outcome"] = "INDETERMINATE"
    if ok_h and genesis is not None:
        mism = [k for k in ("domain", "policyVersion", "rootRecognitionPolicy") if inp.get(k) != genesis.get(k)]
        if mism:
            alt["steps"].append({"2": "INVALID CITATION", "why": f"the citation's {mism} differ from the presented genesis"})
            alt["outcome"] = "INVALID CITATION"
        else:
            alt["steps"].append({"2": "done", "compared": ["domain", "policyVersion", "rootRecognitionPolicy"]})
            # Step 3: fix the prefix (reading 4: position = index in the events array; reading 5: timestamp = canonicalTime).
            p = head["position"] if isinstance(head, dict) else None
            if not isinstance(p, int) or p >= len(events):
                alt["steps"].append({"3": "INDETERMINATE", "code": "PRESENTED_RECORDS_DO_NOT_REACH_POSITION", "events_presented": len(events)})
                alt["outcome"] = "INDETERMINATE"
            elif events[p]["timestamp"] != head["canonicalTime"]:
                alt["steps"].append({"3": "INDETERMINATE", "code": "TIMESTAMP_AT_POSITION_DIFFERS", "presented": events[p]["timestamp"]})
                alt["outcome"] = "INDETERMINATE"
            else:
                alt["steps"].append({"3": "stopped", "position_reached": p, "timestamp_at_p": events[p]["timestamp"],
                                     "records_after_p_dropped": len(events) - p - 1,
                                     "hash_at_p": "not recomputed: the record-chain hashing and canonical record encoding are not in the text held (reading 11)"})
                alt["steps"].append({"4": "NOT RUN", "why": "this checker does not implement the replay identifier named", "identifier": alt["identifier_taken"]})
                alt["outcome"] = "NOT RUN"
    out["with_checker_suite_as_identifier"] = alt
    if "outcome" not in out:
        out["outcome"] = alt["outcome"]
    return out


if __name__ == "__main__":
    print(json.dumps(sorted(format_rules(open(os.path.join(HERE, "p08-evidence", "INDEX.sha256"), "rb").read())), indent=1))
