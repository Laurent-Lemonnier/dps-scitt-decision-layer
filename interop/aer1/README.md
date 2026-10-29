# Independent verifier for AER-1 receipts (draft-zambo-aer1-26, kit v1.5.7) — 2026-10-29

`aer1_verify_independent.py` is written from the draft text (Sections 3 to 6, 10) and shares no code with the kit's
runners. Run against the conformance kit `gitlab.com/rambozambodotdev/zambo` at commit 7d5947d (kit v1.5.7, which the
draft's Implementation Status names as the frozen reference for -26).

| Suite | Vectors | Agreement |
|---|---|---|
| `test-vectors/valid` | 13 | 13/13 pass |
| `test-vectors/invalid` | 32 | 32/32 fail (reason printed beside the rule, as Section 6 requires) |
| `test-vectors/invalid-profile` | 1 | 1/1: core pass, reference-producer profile fail |
| `test-vectors/anchored` | 6 | 6/6: core pass; disinterested-tier anchor verified only for `anchored-valid` |
| `unicode-vectors.json` (Section 4) | 3 | 3/3 |
| `id-binding-vectors.json` (Section 6, `id_verdict`) | 6 | 6/6, all five id states |
| `anchor-vectors.json` (Section 6, per-anchor report) | 6 | 6/6, all five anchor outcomes, `present`/`evaluated` kept distinct |
| **Total covered** | **67** | **67/67** |

Not covered by this file: the chain (`chain-vectors.json`, `chain-vectors-v07.json`), chain-commitment and Merkle suites
(52 vectors of the kit's 124). Their rules are in Sections 7.1 to 7.3 and 8.1; a second pass can add them.

Report: `judge-20261029.json` (one row per vector: expected, verdict, reason, the fixture's own `rejected_by`, legacy
members read, profile result).

## What the reading found: two places where the kit and the draft text differ

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
