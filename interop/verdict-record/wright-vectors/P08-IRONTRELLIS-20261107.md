# p08 under IronTrellis's proposed "Checking a cited entry" (7 November 2026)

Ramesh Rampertab posted a proposed -01 section, "Checking a cited entry", on 7 November 2026
(https://github.com/zerohourzulu/irontrellis/issues/13#issuecomment-6701158070, saved here as
`irontrellis-checking-a-cited-entry-20261107.md`) and asked that it be run against our checkers. This note says what
the section specifies, what was implemented from it, what Darren Wright's case p08 gives now, the readings taken,
and the points two readers could take differently. Nothing of IronTrellis's implementation was read: the section,
`conformance/README.md`, `conformance/v2-g3/README.md`, `MANIFEST.json`, `INDEX.sha256` and the two cited files only.

## What the section specifies

A *citation* (one cited decision) must bind, by value or by SHA-256 of canonical bytes: the cited head (hash,
position, timestamp), the domain and policy identifiers, the evaluation time, the replay identifier, the request (by
digest of its canonical encoding) and the cited result (every field, in versioned canonical bytes). A gap is never
filled from defaults or from the presented history. The *replay identifier* names the operation version, every
encoding setting that changes verdicts (for v2-g3: `challengeProfile` `g3`, from `MANIFEST.json`) and a behavior pin:
the SHA-256 of the suite index (`conformance/v2-g3/INDEX.sha256` at 983a508c, `4c745f10...a68b`). The procedure is:
1 validate the citation, 2 check domain and policy identifiers against the presented genesis, 3 replay exactly
positions 0..p and check the record at p against the cited head, 4 rebuild state under the replay identifier and
re-derive the decision, 5 compare every field as canonical bytes, 6 report one outcome (REPRODUCED, NOT REPRODUCED,
INDETERMINATE, NOT RUN, INVALID CITATION) with its anchoring (ANCHORED/UNANCHORED), head, source and as-of time.

## What was implemented (`irontrellis_formats.py`)

- Two format rules (-02 Section 4.3 step 2) for the formats p08's policy lists, `<v2-g3 tree at a2c487f6>#vectors`
  and `#histories`. An item verifies when the suite index the checker holds is the pin stated (SHA-256
  `4c745f10...a68b`), is well formed by his paragraph on the index (one `<hex>  <path>` line per file, line feed at
  the end, sorted by path bytes, unique, no `.`/`..` segments, itself excluded), and lists the item's digest where the
  fragment points (`vectors.json`; a path under `histories/`); a history is also read as the files show it (a JSON
  array of events `{id, type, timestamp, data}`, event 0 a `DEPLOYMENT_INITIALIZED` genesis with `data.domain` and
  `data.policyVersion`). This is "the item is a file of the pinned suite, in the shape the procedure needs"; it is not
  the replay. Checked: the two cited files verify; swapped, tampered or non-suite bytes do not; a wrong pin or a
  malformed index makes nothing verify.
- His Procedure on the citation a verdict record carries (`cited_entry`): steps 1 to 3 from the text and the files;
  it stops before step 4, whose decision procedure and record-chain hashing are not in the text held.
- The adapter gained a run `adapter+irontrellis` for p08 (`run_wright_cases.py`); `verdict.py` is unchanged
  (same checker digest in `results.json`). `p08-evidence/` gained `INDEX.sha256` (983a508c) and `MANIFEST.json`
  (same bytes at a2c487f6 and 983a508c), both listed in `SHA256SUMS`; `MANIFEST.json` is listed in the index.

## What p08 gives now

| Run | State | Step 1 | Step 2 | Step 3 |
|---|---|---|---|---|
| adapter (6 Nov, items not fetched) | held | PASS | NOT RUN (no item held for entry 1) | NOT RUN (rule not held) |
| adapter+fetched-items (6 Nov) | held | PASS | NOT RUN (no rule for the `#histories` format) | NOT RUN (rule not held) |
| **adapter+irontrellis (7 Nov)** | **held** | **PASS** | **PASS** (both items: `format_rules: met`) | **NOT RUN**: the checker does not hold the specification of rule `.../conformance#authorization` |
| Darren's `expected_under_02` | held | PASS | PASS | NOT RUN |

State and steps now agree with `expected_under_02` (`agrees_with_expected_under_02: {state: true, steps: true}`). The
other seven proposal cases and the 37 main vectors are unchanged. Step 3 stays NOT RUN: re-running p08's rule is the
IronTrellis replay itself, which this checker does not implement.

His Procedure on p08's citation (`results.json` → `irontrellis.cited_entry`):
- Outcome **INVALID CITATION** at step 1, anchoring **UNANCHORED** (head `0x7cbde34e...7108`, position 39, as-of
  canonicalTime 1100; source: the vector entry at `evidence[0]/57`, published by the implementer in the suite). The
  record binds the operation version (`continuity-authorization/0.2`, inside the vector) and a source commit
  (a2c487f6, in the rule and format URLs), but neither the challenge profile nor the suite index digest. At a2c487f6
  (6 Nov 14:40Z) no `INDEX.sha256` existed; the index he names is at 983a508c (7 Nov 02:34Z). His text: "A checker
  MUST NOT fill a gap from defaults", "A citation MAY add a source commit for retrieval".
- Labelled "what the remaining steps give if the checker's own suite (g3, `4c745f10...`) were taken as the
  identifier": step 2 done (domain, policyVersion, rootRecognitionPolicy of vector 57 equal the genesis's); step 3
  reaches position 39 of 40 events, timestamp 1100 equals canonicalTime 1100, no record after 39 is dropped, the hash
  at 39 is **not recomputed** (hashing and canonical record encoding not in the text held); step 4 **NOT RUN**, naming
  the identifier.

## Readings taken

The eleven numbered readings are in the module docstring. The ones that decide the result: (1) the fragment of
Darren's format name points at a suite file; (2) the index pins file bytes, so an index published after the cited
commit may pin files cited earlier; (3) no upper time bound for a suite file (taking the index's publication time
instead would make step 2 NOT RUN: 7 Nov is after the record's 1 Nov bound); (4) position = index in the events array;
(5) the event's `timestamp` is compared with the head's `canonicalTime`; (7) members of a vector entry bound by file
digest + JSON pointer count as bound "by value"; (8) the replay identifier is incomplete in p08; (10) UNANCHORED.

## Points unclear in the text (for the author)

1. **"The citation" / "The replay identifier" — citations that predate the index.** p08 cites files at a2c487f6,
   where no `INDEX.sha256` exists, and names a source commit, not a profile or a suite digest. Sentences: "A checker
   MUST NOT fill a gap from defaults or from the presented history" and "A citation MAY add a source commit for
   retrieval." One reader gives INVALID CITATION (what we did); another completes the identifier from the commit's
   `MANIFEST.json` (`challengeProfile`) and the later index, since the files are byte-identical. The text could say
   whether a source commit at which the suite files exist may stand in for the pin, or that it may not.
2. **"Procedure" step 3 — "positions 0 through p" and "the record at p ... in hash, position and timestamp".**
   `histories/budget-v2.json` is an array of 40 events with no `position` or hash member; `MANIFEST.json` says
   `eventCount` 40, head `position` 39, `recordCount` 75; the head carries `canonicalTime`, events carry `timestamp`.
   Two readers could count positions over events or over records, and compare `canonicalTime` with `timestamp` or
   not. One sentence naming the array, the index and the member would settle both.
3. **"The citation" — "by value or by SHA-256 digest of canonical bytes".** A verdict record binds a 1.4 MB file by
   digest of its bytes and a member in it by JSON Pointer. One reader takes the member as bound by value; another
   says a file digest is "a digest of a history file [that] pins one serialization" and binds none of the fields. The
   request "by the digest of its canonical encoding" also needs the canonical encoding named.
4. **Step 5 / "the cited result ... in versioned canonical bytes".** p08's result is a JSON object in the verdict
   record's canonical form (`budgetId: null`, `controllingAuthorityIds: null`). Comparing "as canonical bytes" and
   comparing as JSON values can differ (null vs absent, member order, number forms); the versioned encoding of a
   decision is not in the section.
5. **Step 2 — "the domain and policy identifiers"; "Where the head comes from" — a published suite.** The genesis
   carries `domain`, `policyVersion`, `rootRecognitionPolicy`, `globalPolicySourceId`, `adapterPolicyHash`; the
   vector input the first three. Which are "the policy identifiers"? And is a head read from a suite the implementer
   publishes and pins by index "a source its own policy accepts" (ANCHORED) or UNANCHORED, as we reported?

## Files

`irontrellis_formats.py` (rules, procedure, ambiguity log), `run_wright_cases.py` (run `adapter+irontrellis`),
`results.json` and `reports-full.json` (re-run of 7 November), `p08-evidence/INDEX.sha256`, `p08-evidence/MANIFEST.json`,
`p08-evidence/SHA256SUMS`, `irontrellis-checking-a-cited-entry-20261107.md` (his text as fetched). `vectors.json` is
fetched before a run and not committed.
