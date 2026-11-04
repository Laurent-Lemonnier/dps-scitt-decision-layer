# P10 S2b, the replay verifier, read from the text — first pass, 4 November 2026

An outside reading of S2b, the replay verifier of the P10 underdetermination profile
(draft-nestorov-scitt-p10-underdetermination-02, Section 10), at `VolMax-Studio/p10-replay-verifier` tag
`v0.1.0-s2b-complete`, commit `8eaa91cad1ffa963158b365c6d0d7316f4965e89` (`PINNED_COMMIT.txt`). The files read are
listed with their SHA-256 in `SHA256SUMS` (979 files: `README.md`, `docs/`, `frozen/`, `rules/`, `profile/`,
`manifest/` and `vectors/`); the run fetches them at that commit and checks every digest before reading. Nothing under
`src/`, `tests/`, `scripts/`, `harness/`, `orchestration/` or `evidence/` was opened, nor any generator, issue or
history: the boundary agreed with the author on 1 November 2026. One document outside that list was opened after the
first run, because a case's own note pointed to it: `authorization/S2B_PHASE_B5_AUTHORIZATION_v1_ADDENDUM_1.txt` (see
the ambiguity log). This is a reading of what the public text lets an external reader reconstruct, with the places
the text alone did not settle; it is not a conformance result, and the author's own runs are the reference.

`replay_from_text.py` implements, from `frozen/S2B_PREREG_v0.1_r7.md`, `frozen/IMPLEMENTATION_SELECTION_v0.md`
(section 4, the physical request) and `frozen/LeafEncodeV0_SPEC.md`: the request envelope and its transport rules;
P0 to P7 of the prereg's section 9.1 with the dominance rule (frozen configuration, RFC 9679 thumbprints, the RFC 9942
Receipt and its target-proof authentication of section 11, index discipline, LeafEncodeV0, the RFC 9162 full-prefix
root, the authenticated binding checks with `LogIdentityV0` of section 12 in RFC 8785 bytes); and of P8 what needs no
payload schema: the SCITT structural reading of each row (section 13.2), the subject comparison, and the signature
observations of section 14 (ES256 over the exact `Sig_structure`, detached payloads, key resolution by fingerprint).
`cbor_read.py` is a CBOR reader written from RFC 8949 that accepts what section 13.2 says S2b accepts (no
deterministic-encoding requirement, indefinite lengths) and records duplicate labels. Only `cryptography` (P-256) is
imported; no CBOR or COSE library.

## Run report (`out/report-pass1.json`)

- **Pins**: the 956 vector files listed in `manifest/VectorManifestS2bV0.json` all hash to the manifest's values; the
  six binding files too. `LeafEncodeSpecArtifactDigestV0` recomputed from `frozen/LeafEncodeV0_SPEC.md` equals the
  pinned `571765530870e4a6…`.
- **LeafEncodeV0, L1 to L8** (the spec's section 5): 9 of 9, the full `leaf_input` of L1 included.
- **The 338 cases** of the vector manifest, each request decoded and replayed, the result compared with the case's
  expected status, class and reason; for a `Verified` case, also with the evidence the case records: the checkpoint
  size, the root, `log_identity_digest`, `leaf_encoding_profile_digest`, the per-index statement digests, the
  unreadable rows and the signature observations.

| | Cases |
|---|---|
| agree on the result and on every evidence member compared (188 `Verified`, 107 `Invalid`, 12 `Unavailable`) | 307 |
| agree on the result and the replay evidence; the subject rows' readability and observations differ, and rest on schema stage 1 (second pass) | 28 |
| not reached in this pass, and why (below) | 3 |
| disagree | 0 |

Full agreement by family: C (Receipt authentication) 38 of 38, M (S2b's adversarial mutations of section 17.6) 33 of
33, X 56 of 56, s2a-t11 67 of 67, I (`LogIdentityV0`) 12 of 12, R (RFC 9162 and full prefix) 9 of 9, S 19 of 19,
s2a-post 23 of 24, E 19 of 20, SPS (the payload schema's cases) 31 of 60. The rest of E and SPS agree on the replay
layer (28); the three not reached are `SPS-12-ok-u64max`, `SPS-17-nfc-subject` and `T12-T2-wrong-kind`.

The transcript `tB` of section 15 is not encoded in this pass: a `Verified` agreement is on the result and the
evidence above, not on the transcript bytes.

## Not reached in this pass, and said

- **The payload schema** (`StatementPayloadSchemaV0` r9, prereg section 13.3): kind derivation, the five predicates,
  projection. Two cases expect `TargetKindMismatch`, which rests on it; 28 `Verified` cases (SPS and E families) mark
  a subject row unreadable under schema stage 1 (section 13.4, third row: no known kind derivable), where this pass,
  without the schema, reads the row and observes its signature. Second pass.
- **The transcript** (prereg section 15): its grammar is transcribed from ratified S2a; the expected `tB` bytes of
  every `Verified` case are in the vectors and will be compared byte for byte in the second pass.
- **`SPS-12-ok-u64max`** expects `Unavailable(capability, VerifierCapabilityUnsupported)`. Its own note says: "the
  frozen text sets no limit"; the limit is the 64 MiB cap on the encoded transcript at P9, set by the B5 authorization
  addendum 1 as a build capability. A reader of the frozen text alone has no cap and would produce a transcript.
- **Appendix A of the draft** (M1 to M35, AP1) is a different series from S2b's M vectors: it mutates the profile, S1
  and S2a. The prereg cross-references the profile's M27 alone, as the class of its binding codes (C10b, M27-attached,
  M27-detached here, all agreeing); which other tests of Appendix A have an S2b counterpart is not established here. A
  reading of Appendix A needs the S2a text and vectors (`p10-coverage-lean-s2`, MIT since 1 November) and the S1
  certificate: not attempted.

## Ambiguity log

Readings this pass takes where the text leaves room, each recorded in the report (`ambiguity_log`); none changed a
verdict against the vectors.

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
| P9, transcript size | `SPS-12-ok-u64max` rests on a cap outside the frozen text (above) |

## Second pass, and the date

The payload schema (stages 0 to 3), the transcript encoding of section 15 compared byte for byte with `expected_tb_hex`
for every `Verified` case, and then the draft's Appendix A against the S2a text: before the IETF 127 hackathon
(14 November 2026), in this directory, with the same boundary.

An assistant wrote the code and the first draft of this report; Laurent Lemonnier read both. Nothing here is a
conformance claim by the profile's author, who is not asked for any interpretation before the report is written.

## Reproduce

```
git clone https://github.com/VolMax-Studio/p10-replay-verifier.git interop/p10/s2b
git -C interop/p10/s2b checkout 8eaa91cad1ffa963158b365c6d0d7316f4965e89
(cd interop/p10/s2b && sha256sum -c --quiet ../SHA256SUMS)
python3 interop/p10/replay_from_text.py --vectors interop/p10/s2b --report interop/p10/out/report-pass1.json
```
