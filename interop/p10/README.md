# P10 S2b, the replay verifier, read from the text — first pass 4 November, second pass 5 November 2026

An outside reading of S2b, the replay verifier of the P10 underdetermination profile
(draft-nestorov-scitt-p10-underdetermination-02, Section 10), at `VolMax-Studio/p10-replay-verifier` tag
`v0.1.0-s2b-complete`, commit `8eaa91cad1ffa963158b365c6d0d7316f4965e89` (`PINNED_COMMIT.txt`). The files read are
listed with their SHA-256 in `SHA256SUMS` (979 files: `README.md`, `docs/`, `frozen/`, `rules/`, `profile/`,
`manifest/` and `vectors/`); the run fetches them at that commit and checks every digest before reading. Nothing under
`src/`, `tests/`, `scripts/`, `harness/`, `orchestration/` or `evidence/` was opened, nor any generator, issue or
history: the boundary agreed with the author on 1 November 2026. One document outside that list was opened after the
first run, because a case's own note pointed to it: `authorization/S2B_PHASE_B5_AUTHORIZATION_v1_ADDENDUM_1.txt` (see
the ambiguity log); the second pass opened nothing outside the list. This is a reading of what the public text lets an
external reader reconstruct, with the places the text alone did not settle; it is not a conformance result, and the
author's own runs are the reference.

`replay_from_text.py` implements, from `frozen/S2B_PREREG_v0.1_r7.md`, `frozen/IMPLEMENTATION_SELECTION_v0.md`
(section 4, the physical request) and `frozen/LeafEncodeV0_SPEC.md`: the request envelope and its transport rules;
P0 to P7 of the prereg's section 9.1 with the dominance rule (frozen configuration, RFC 9679 thumbprints, the RFC 9942
Receipt and its target-proof authentication of section 11, index discipline, LeafEncodeV0, the RFC 9162 full-prefix
root, the authenticated binding checks with `LogIdentityV0` of section 12 in RFC 8785 bytes); and of P8 what needs no
payload schema: the SCITT structural reading of each row (section 13.2), the subject comparison, and the signature
observations of section 14 (ES256 over the exact `Sig_structure`, detached payloads, key resolution by fingerprint).
`cbor_read.py` is a CBOR reader written from RFC 8949 that accepts what section 13.2 says S2b accepts (no
deterministic-encoding requirement, indefinite lengths) and records duplicate labels. Only `cryptography` (P-256) is
imported; no CBOR or COSE library. The second pass adds `schema_from_text.py` and `transcript_from_text.py` (below).

## First pass, 4 November 2026 (`out/report-pass1.json`)

- **Pins**: the 956 vector files listed in `manifest/VectorManifestS2bV0.json` all hash to the manifest's values; the
  six binding files too. `LeafEncodeSpecArtifactDigestV0` recomputed from `frozen/LeafEncodeV0_SPEC.md` equals the
  pinned `571765530870e4a6…`.
- **LeafEncodeV0, L1 to L8** (the spec's section 5): 9 of 9, the full `leaf_input` of L1 included.
- **The 338 cases** of the vector manifest, each request decoded and replayed, the result compared with the case's
  expected status, class and reason; for a `Verified` case, also with the evidence the case records: the checkpoint
  size, the root, `log_identity_digest`, `leaf_encoding_profile_digest`, the per-index statement digests, the
  unreadable rows and the signature observations.

| | Cases, first pass | Cases, second pass |
|---|---|---|
| agree on the result and on every evidence member compared; in the second pass also on the transcript bytes of every `Verified` case | 307 (188 `Verified`, 107 `Invalid`, 12 `Unavailable`) | 337 (216 `Verified`, 109 `Invalid`, 12 `Unavailable`) |
| agree on the result and the replay evidence; the subject rows' readability and observations differ, and rest on schema stage 1 | 28 | 0 |
| not reached, and why (below) | 3 | 1 (`SPS-12-ok-u64max`) |
| disagree | 0 | 0 |

First-pass agreement by family: C (Receipt authentication) 38 of 38, M (S2b's adversarial mutations of section 17.6)
33 of 33, X 56 of 56, s2a-t11 67 of 67, I (`LogIdentityV0`) 12 of 12, R (RFC 9162 and full prefix) 9 of 9, S 19 of 19,
s2a-post 23 of 24, E 19 of 20, SPS (the payload schema's cases) 31 of 60. The rest of E and SPS agreed on the replay
layer (28); the three not reached were `SPS-12-ok-u64max`, `SPS-17-nfc-subject` and `T12-T2-wrong-kind`. The first
pass did not encode the transcript `tB` of section 15: a `Verified` agreement there is on the result and the evidence
above, not on the transcript bytes.

### Not reached in the first pass, and said

- **The payload schema** (`StatementPayloadSchemaV0` r9, prereg section 13.3): kind derivation, the five predicates,
  projection. Two cases expect `TargetKindMismatch`, which rests on it; 28 `Verified` cases (SPS and E families) mark
  a subject row unreadable under schema stage 1 (section 13.4, third row: no known kind derivable), where the first
  pass, without the schema, read the row and observed its signature. Reached in the second pass.
- **The transcript** (prereg section 15): its grammar is transcribed from ratified S2a; the expected `tB` bytes of
  every `Verified` case are in the vectors. Compared in the second pass.
- **`SPS-12-ok-u64max`** expects `Unavailable(capability, VerifierCapabilityUnsupported)`. Its own note says: "the
  frozen text sets no limit"; the limit is the 64 MiB cap on the encoded transcript at P9, set by the B5 authorization
  addendum 1 as a build capability. A reader of the frozen text alone has no cap and would produce a transcript.
  Still not reached (second pass, below).
- **Appendix A of the draft** (M1 to M35, AP1) is a different series from S2b's M vectors: it mutates the profile, S1
  and S2a. The prereg cross-references the profile's M27 alone, as the class of its binding codes (C10b, M27-attached,
  M27-detached here, all agreeing); which other tests of Appendix A have an S2b counterpart is not established here. A
  reading of Appendix A needs the S2a text and vectors (`p10-coverage-lean-s2`, MIT since 1 November) and the S1
  certificate: not attempted in either pass.

## Second pass, 5 November 2026 (`out/report-pass2.json`)

Same pinned files, same boundary; `sha256sum -c` passes before the run. `--pass 1` still reproduces
`out/report-pass1.json` byte for byte; that file is unchanged.

`schema_from_text.py` implements, from `frozen/StatementPayloadSchemaV0_r9.md` (SHA-256 `7fc847ea…`, as prereg
section 13.3 pins it), the decode pipeline of its section 9: stage 0 (protected `crit`, labels 258/259/260 absent, on
top of the structural reading of prereg section 13.2), stage 1 (payload bytes attached or from
`detached_statement_payloads`, the exact protected `content_type`, strict JSON, the RFC 8785 round trip, the Statement
skeleton of sections 4 and 7, the subject binding of section 3, `predicateType` among the five URIs of section 2: the
kind), stage 2 (the five predicates of section 8 with the local checks of 8.7, the `limitations` constant and its
digest of 8.6, taken from the frozen text and checked against the 5718 bytes and `7c925266…` it states) and stage 3
(projection into the S2a `Payload`). A subject row whose kind cannot be derived is `unavailable`; a known kind with an
invalid predicate keeps its kind with `payload = none`. P8 then applies prereg section 11.2 step 6: the target's wire
kind must be `adjudication`, else `Invalid(request, TargetKindMismatch)`. Nothing after S2a ACCEPT (schema sections 8.8
to 8.11) is implemented; S2b does not run it. JSON is parsed by the standard library with hooks that refuse duplicate
names, numbers and non-JSON constants; RFC 8785 serialization is written from the RFC.

`transcript_from_text.py` encodes `tB` from the grammar transcribed in prereg section 15.2 and the field sources of
section 15.4 (`keyResolutionDigest` = SHA-256 of the JCS bytes of `{"key_resolution": K}`); the S2a codec itself was
not read. Since `nat` is unary in base 255, the length is computed before any bytes are written.

Results:

- **The 338 cases**: 337 agree fully, 1 is not reached, none disagrees; no case that agreed in the first pass changed
  state (the report's `vs_pass1`). The 28 cases agree now on their rows and observations, and both cases expecting
  `TargetKindMismatch` are reached and agree: `T12-T2-wrong-kind` (the target is the closure entry, index 3) and
  `SPS-17-nfc-subject` (the target's `sub` is not the Unicode instance subject, so it is not a subject entry and has
  no derived kind; index 1, as the case's `oref_result` records). By family: C 38 of 38, E 20 of 20, I 12 of 12, M 33
  of 33, R 9 of 9, S 19 of 19, SPS 59 of 60, X 56 of 56, s2a-post 24 of 24, s2a-t11 67 of 67.
- **The transcript**: for all 216 `Verified` cases this reading's `tB` equals the expected bytes byte for byte, 216
  of 216: 127 against `expected_tb_hex` (their SHA-256 also equals the manifest's `tb_sha256` and the case's evidence
  `transcript_sha256`), 89 against the `tB.expected` files of the s2a-t11 (66, whose SHA-256 also equals the case's
  `tb_expected_sha256`) and s2a-post (23) families. There is no first differing byte to report. The 216 transcripts
  carry 660 detailed entries (235 adjudication, 128 closure, 111 admission, 95 instance commitment, 91 profile
  commitment), 26 of them with `payload = none`, and 2089 unavailable rows (2047 of them in `R/R9-full` and `R/R14`,
  prefixes of 1025 and 1024 leaves); `s2a-t11/T3-idx255-FFdigest` (indices from 255 and `0xFF` digest bytes) is among the 216.
- **`SPS-12-ok-u64max`, not reached, and why.** The closure's reference `"18446744073709551615"` is valid (schema
  section 5), so this reading replays the case to `Verified` with an entry whose payload projects that reference;
  `nat` being unary in base 255, the transcript would be 72,340,172,838,077,169 bytes (computed, not allocated). The
  expected `Unavailable(capability, VerifierCapabilityUnsupported)` comes from the 64 MiB cap of the B5 authorization
  addendum 1; the frozen prereg lists no failure at P9, its only capability code is the P0 algorithm check, and no
  file in the pinned set states a size limit. The text alone does not let an outside reader produce the expected
  result, nor the 72 PB transcript.

Several readings below are not separated by the vectors: switching each to its alternative (stage 0 on subject rows
only; `crit` understanding alg alone; the predicate's `instance_subject` compared locally for every kind, or for none)
leaves all 338 results and all 216 transcripts unchanged. They are recorded as readings, not as confirmed.

Appendix A of the draft (M1 to M35, AP1, against the S2a text and vectors) is still not attempted and remains for a
later pass, before the IETF 127 hackathon (14 November 2026), in this directory, with the same boundary.

## Ambiguity log

Readings taken where the text leaves room, each recorded in the reports (`ambiguity_log`); none changed a verdict
against the vectors. The first nine are from the first pass; the next ten were added on 5 November.

| Where | Reading taken |
|---|---|
| section 11.2 step 2 | an inclusion path that does not fit its `tree_size` and `leaf_index` gives no candidate root, so it does not authenticate; it is not `ReceiptMalformed`, which P2 reserves for unreadable proofs and `leaf_index >= tree_size` |
| section 7.3 (b) | the leaf-domain check reads a leaf's COSE_Sign1 array tagged or untagged; an unreadable leaf makes no domain claim |
| section 9.1 P4 | a duplicate index and an index beyond `n` together: `DuplicateIndex` first, as the phase table lists it first |
| section 12.4 rule 2 | `LogIdentityInconsistent` is never emitted: each of its four components is compared by a more specific code, and the physical request has no `expected_log_identity_digest` (no case expects the code) |
| section 13.2 | the CWT `sub` (tstr) is compared with `instance_subject` (bstr) by the tstr's UTF-8 bytes |
| section 9.1 P5 | `TargetStatementMismatch` is evaluated when exactly one record holds `leaf_index` |
| section 7.7 with P3 | an empty target is not encodable: `RequestMalformed` at P5, and P3 is not evaluated |
| section 8.4 | `LeafEncodeSpecArtifactDigestV0` is defined by reference to S2a section 6b; the rule quoted in schema r9 section 8.11.1 reproduces the pinned value |
| P9, transcript size | `SPS-12-ok-u64max` rests on a cap outside the frozen text (above); second pass: the transcript would be 72,340,172,838,077,169 bytes |
| schema r9 section 9 stage 0 and section 6 item 5, `crit` | the text names no list of understood parameters; this reading understands alg (1), content_type (3) and CWT Claims (15), the protected labels S2b processes, and a `crit` that is not a non-empty array of labels fails stage 0 (`SPS-19-crit-ok` lists 1, `SPS-19-crit-unknown` lists 99) |
| schema r9 section 9, stage 0 | applied to every row, subject or not, since the table limits only stages 1 to 3 to subject entries; not separated by the vectors |
| schema r9 sections 4 and 5, null and numbers | "anywhere in a P10 Statement" is read as a stage-1 rule (row `unavailable`), also inside the predicate; `SPS-6-number`, a number inside `ordered_admission_refs`, expects the row unavailable |
| schema r9 section 8.7 with prereg section 6.2.7, order inside a subject entry | stage 1, then the signature observation, then stages 2 and 3 (section 8.7's order); a row that fails stage 1 has no observation and its key is not used. Prereg 6.2.7 says the bytes feed schema decoding "after signature processing"; not separated by the vectors |
| schema r9 sections 8.2, 8.4, 8.5, the predicate's `instance_subject` | compared with the CWT `sub` before S2a only for instance-commitment (section 8.2 says so); for closure S2a's `closureAt` compares it, for adjudication it is A1, after ACCEPT (section 10, SPS-18); not separated by the vectors |
| schema r9 section 5, the reference bound | a reference above 2^64 − 1 fails stage 2 (`payload = none`), like one outside the grammar; the transcript is the same either way |
| prereg section 15.2, `item (fixture)` | in `first b -> 00 ++ nat(b)` the boolean is `nat(0)` or `nat(1)`, as `bool(b)` is defined above it |
| prereg section 15.4, `keyResolutionDigest` | `K` maps each `iss` of `frozen.key_resolution` to the lowercase hex of its fingerprint (the `pB` form the JCS amendment section 9.10 quotes); reproduces the expected bytes |
| prereg sections 13.1 and 15.2, rows | a non-subject row is `available(sub)` with its `sub`'s UTF-8 bytes; a subject row failing stage 0 or 1 is `unavailable` and has no entry |
| prereg section 11.2 step 6, the target's wire kind | the kind derived at stage 1, which runs only for subject entries: a target that is not a subject entry, or whose row is unavailable, gives `TargetKindMismatch` (`SPS-17-nfc-subject`); a target whose payload bytes were not obtained has no known kind and gives no `TargetKindMismatch` (`StatementPayloadUnavailable` stands; no vector has this) |

An assistant wrote the code and the first draft of this report; Laurent Lemonnier read both. Nothing here is a
conformance claim by the profile's author, who is not asked for any interpretation before the report is written.

## Reproduce

```
git clone https://github.com/VolMax-Studio/p10-replay-verifier.git interop/p10/s2b
git -C interop/p10/s2b checkout 8eaa91cad1ffa963158b365c6d0d7316f4965e89
(cd interop/p10/s2b && sha256sum -c --quiet ../SHA256SUMS)
python3 interop/p10/replay_from_text.py --vectors interop/p10/s2b --pass 1 --report interop/p10/out/report-pass1.json
python3 interop/p10/replay_from_text.py --vectors interop/p10/s2b --pass 2 --report interop/p10/out/report-pass2.json \
    --pass1-report interop/p10/out/report-pass1.json
```
