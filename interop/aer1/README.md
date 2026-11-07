# Independent verifier for AER-1 receipts (draft-zambo-aer1-26, kit v1.5.7, re-run at `5d1504b` and `3287eb3`) — 2026-10-29, 2026-10-31, 2026-11-07

`aer1_verify_independent.py` is written from the draft text (Sections 3 to 6, 10) and shares no code with the kit's
runners. First run against the conformance kit `gitlab.com/rambozambodotdev/zambo` at commit 7d5947d (kit v1.5.7, which the
draft's Implementation Status names as the frozen reference for -26); the table is the run of 7 November 2026 at `3287eb3`
(the kit's reinforced set, 143 vectors), after the two readings of point 5 below. The 126 vectors of `5d1504b` give the
same verdicts as on 31 October.

| Suite | Vectors | Agreement |
|---|---|---|
| `test-vectors/valid` | 21 | 21/21 pass |
| `test-vectors/invalid` | 36 | 36/36 fail (reason printed beside the rule, as Section 6 requires) |
| `test-vectors/invalid-profile` | 1 | 1/1: core pass, reference-producer profile fail |
| `test-vectors/anchored` | 6 | 6/6: core pass; disinterested-tier anchor verified only for `anchored-valid` |
| `unicode-vectors.json` (Section 4) | 5 | 5/5 |
| `id-binding-vectors.json` (Section 6, `id_verdict`) | 6 | 6/6, all five id states |
| `anchor-vectors.json` (Section 6, per-anchor report) | 8 | 8/8, all five anchor outcomes, `present`/`evaluated` kept distinct; the partial profile anchor present and failed |
| `chain-vectors.json` (the historical -06 construction, Section 7.4) | 7 | 7/7, reported as historical |
| `chain-vectors-v07.json` (Sections 7.1, 7.2) | 28 | 28/28 |
| `commitment-vectors.json` (Section 7.3) | 8 | 8/8 |
| `merkle-vectors.json` (Section 8.1, receipt-id-v0; 8.2 duplicate id rule) | 9 | 9/9 |
| `workflow-merkle-seq-output-v1.json` at the kit's root (Section 8.1, seq-output-v1 and the selector; added on 5 November 2026 for case 13) | 8 | 8/8, the two cross-version must-fail cases included (a v0 close has no `output_hash`: the v1 leaf cannot be formed, fail closed) |
| **Total** | **143** | **143/143** |

The kit's `index.json` at `3287eb3` counts 143 vectors and 146 checks (set digest `60bf73f3`): the 143 vectors are the
ones replayed here; the three checks beyond them are its frozen-corpus manifests and cross-runner checks, which this
file does not replay. At 7d5947d the count was 124 vectors and 127 checks.

Reports: `judge-20261029.json` (7d5947d, 119 rows), `judge-20261031-5d1504b.json` (126 rows), `judge-20261107-3287eb3.json`
(143 rows; one row per vector: expected, verdict, reason, the fixture's own `rejected_by`, legacy members read, profile
result).

## What the reading found: four places where the kit and the draft text differ

1. **Section 6 step 4 says "A '0.4' receipt without metadata_hash MUST fail."** The kit lists three 0.4 fixtures
   without `metadata_hash` as valid (`bound-04`, `optional-members-18`, `input-hash-multikey-20`); they are bound by
   the schema version and `issuer_claims.provenance_class` carried inside the canonical bytes instead. A verifier
   written from the draft alone fails them. This file applies the kit's reading and flags the absence
   (`metadata_hash_absent_on_04`). Either the sentence in step 4 should say "without metadata_hash and without a
   version committed in the canonical bytes", or the fixtures should carry `metadata_hash`.
2. **Section 6 step 4 admits the legacy forms member by member** ("the creation time MAY be carried by a 'timestamp'
   member when 'created_at' is absent, and the tool member MAY be a bare string when the object form is absent"). The
   kit rejects `tool-not-object` (0.3, `created_at` present, tool a bare string) and accepts `legacy-real-2` (0.3,
   `timestamp` present, tool a bare string, `verification_status` "not_verified"). The kit's effective rule is: a
   receipt is legacy as a whole when it carries `timestamp` instead of `created_at`, and only then are the bare-string
   tool and a non-"verified" status read in legacy form. The draft text would admit a bare-string tool beside
   `created_at`. One sentence in step 4 would settle it.

3. **Section 7.3 says `entry_count` is "a JSON number with an integer value"**, the same wording Section 7.1 uses for
   `seq`, where it explicitly accepts `1.0`. The kit's `x-entry-count-float` vector rejects an `entry_count` of `5.0`.
   Either 7.3 should say "a JSON integer", or the vector should be valid; this file follows the kit.

4. **Section 6 step 4: "When the receipt carries metadata_hash, or when receipt_schema_version is "0.4" or later,
   recompute the metadata block from the receipt's stored member values per Section 3.1 and compare; a mismatch MUST
   cause verification to fail."** At `7d5947d`, no code in the kit recomputed the metadata block: not
   `aer-1/conformance.py`, not `aer-1/conformance.js`, not `aer1-verifier/aer1_verify.py` (the reference verifier
   reports the id as "a label outside the commitment"); and one vector in the corpus carries `metadata_hash` (`valid/real-04`), no invalid one.
   A 0.4 receipt whose `created_at`, `id` or tool version is changed after issuance, or whose `metadata_hash` is
   zeroed, passes them; this file fails it, as the step requires. Found on 29 October 2026 while building `../aer1-decision/`;
   the probes and their results are in `../aer1-decision/out/negatives/metadata-probes.json`. Here this file follows the text, not the kit.
   The author confirmed it on 30 October 2026 and added the recomputation to both runners (kit -24, commit `5d1504b`,
   crediting this report), with the four probes and this report's composition receipt pinned as fixtures under
   `tests/metadata-probes/`; for a missing `metadata_hash` the runners follow the corpus (point 1). Verified here on
   31 October 2026: at `5d1504b` the kit's Python runner fails all eight probes and passes the two controls, and this
   verifier still agrees on 119 of 119. The pin was `5d1504b` from then on; the kit's tree was rebuilt (`base/` holds
   the corpus and runners), and the kit lists this verifier in its `IMPLEMENTERS.md` and, since `3287eb3`, in
   `aer-1/implementations.json`.

5. **Two rules the kit pinned on 2 November 2026 (`3dc1764`, the reinforced set), read here on 7 November from the
   texts.** Unchanged, this file agreed on 140 of the 143 vectors at `3287eb3`. (a) `invalid/payload-is-array` and
   `invalid/payload-omits-issuer-claims`: a 0.4 receipt without `metadata_hash` whose canonical bytes commit no schema
   version, or no `issuer_claims.provenance_class`. Section 6 step 4 says such a receipt MUST fail (point 1); this file
   had taken the kit's reading of `bound-04` and its two siblings (bound by the version and provenance class committed
   inside the canonical bytes) and compared only when both sides were present. It now fails a 0.4 receipt without
   `metadata_hash` when the payload is not an object or omits either committed member, which is the sentence point 1
   suggested for step 4. (b) `anchor-partial-profile`: an anchor member carrying only `leaf_hash`. The report paragraph
   of Section 6 makes an anchor present when it is "in a shape the verifier can attempt to evaluate", and the `spec`
   sentence of `anchor-vectors.json` says a partial profile anchor is present and fails evaluation; this file had
   reported it absent. It is now present, evaluated and "verification failed", naming the missing members; a member
   carrying none of the tier's members stays absent (`anchor-other-profile`). With these two readings: 143 of 143 at
   `3287eb3`, 126 of 126 at `5d1504b` unchanged, `../aer1-decision/` and `../plan-workflow/` rebuilt unchanged. The pin
   is `3287eb3` since 7 November 2026. The kit's runners were not read for either rule.

Rules applied that the draft does not state, taken from the kit's own documents and marked `KIT` in the code:
the payload binding of the outer `receipt_schema_version` and `provenance_class` to the values inside the canonical
bytes (kit verifier README, rule 11; vectors `version-downgrade`, `tampered-provenance`); the reference-producer
profile (`inputs`, `tool`, `outputs` in the payload); the disinterested-tier anchor shape `{log, leaf_hash,
anchored_at, proof}` with the strict v4 id; the input_hash layout (canonical JSON of the payload's `inputs`); and the
convention that a log under the `.invalid` domain is the "rejected: unresolvable record" case.

## Relation to the DPS

An AER-1 receipt is the execution layer: what ran, its exact output bytes, under which provenance class. The DPS action
binding records the decision above it: what a named person was shown and approved, by digest, before the call. The
natural composition is a DPS execution attempt stage carrying the AER-1 receipt `id` and `output_hash`, and the AER-1
`execution_context` (or `field_provenance`) naming the DPS decision record by `decision_id` and seal digest.
Built and checked in `../aer1-decision/`, at the author's request: what binds there is the receipt's id and
output_hash cited by the DPS attempt, and the DPS request_id and the approved values in the receipt's recorded input
(under output_hash); `execution_context` is outside metadata_hash (Section 3.2) and is reported as a pointer only.
