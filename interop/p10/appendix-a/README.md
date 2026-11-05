# Appendix A of draft-nestorov-scitt-p10-underdetermination-02, read from the text — 5 November 2026

An outside reading of Appendix A ("Conformance Tests": M1 to M35 and the adversarial-profile test AP1) of
draft-nestorov-scitt-p10-underdetermination-02, against the three public repositories it rests on, each pinned to the
commit and tag object that the draft's Appendix C.1 names (`PINS.txt`):

| Repository | Tag | Commit |
|---|---|---|
| `VolMax-Studio/p10-underdetermination-profile` | `v0.1.1` | `e2a02a73df9e50f624512043dcb007fc337ba587` (A01) |
| `VolMax-Studio/p10-underdetermination-lean-s1` | `v0.1.0-s1-ratified` | `e4db3747eaeeb1a07227bb9029f9a9c3b566cdb1` (A04) |
| `VolMax-Studio/p10-coverage-lean-s2` | `v0.1.0-s2a-ratified` | `741d56d36d7b2bfe2e9e0080a1cba4393e4a47da` (A07) |

The file digests the appendix names (A03 profile, A06 S1 manifest, A09 S2a verifier manifest, A10 S2a vector
manifest, A11 `LeafEncodeV0` specification) recompute equal, and the 315 files under `vectors/` that
`VectorManifestS2aV0.json` lists hash to their listed values, with no unlisted file. S2b (A13) is the replay verifier
read in `../`; it is not re-read here.

**Boundary.** This is a reading of what the public text lets an outside reader reconstruct, not a conformance claim.
In the three repositories only README files, the profile and specification text, the S1 and S2a documentation under
`profile/` and the top level (`TEST_VECTORS.md`, `IMPLEMENTATION_BINDING.md`, the S2a preregistration v0.2.6),
manifests, published vectors and pin files were read; they are listed with their SHA-256 in `SHA256SUMS`. No `.lean`
module, nothing under `src/`, `tests/`, `scripts/` or `harness/`, no generator, issue or git history was opened (a
directory listing showed file names under `tests/`; none was opened). From `../s2b`, already pinned and listed in
`../SHA256SUMS`, this pass used the transcript grammar of `frozen/S2B_PREREG_v0.1_r7.md` section 15.2 and the
pass-2 report `../out/report-pass2.json`. Python 3 standard library only.

## What was run

- `appendix_a_checks.py` (`out/checks-b.json`):
  - S1: a strict decoder for the instance wire format of `TEST_VECTORS.md` and `CertificateTargetV0` (profile
    section 2.2) over the toy profile as reconstructed below: **15 of 15** vectors agree (P1 accepted; the 14
    negatives rejected for the reason `TEST_VECTORS.md` gives).
  - S1 statement `vectors/out/p1.statement.json`: claim, evidence and witness digests (SHA-256 of JCS) equal the
    values in `TEST_VECTORS.md` and in the statement; `limitations_digest` is reproduced as SHA-256 of the JCS of
    the `limitations` array; a one-word change of a limitation text changes it; the AP1 and COVERAGE_INSTANCE
    texts are verbatim substrings of the profile; the predicate without `limitations` fails the must-understand
    rule; the statement records SHA-256 of `VerifierManifestS1.json` (A06).
  - M2 on the toy profile, by brute force: with `Compatible := true`, FormallyUnderdeterminationCapable is false
    for both toy claims; on the reconstructed profile it is true for `secondBit`.
  - S2a `pB` (`ProfileArtifactS2V0`, prereg section 6a): strict decode, field set, canonical JCS, fixed fields,
    verifier-manifest digest: **72 of 72** vectors agree at this level.
  - S2a `PreclosureDigestV0` (section 6b), vectors S2-K1 to K7: **7 of 7**.
- `s2a_from_text.py` (`out/s2a-coverage.json`, `out/s2a-subset.json`): a strict decoder for the S2a transcript `tB`
  from the grammar transcribed in S2b prereg section 15.2, then the coverage conditions C1, C1a to C1c and C2 to
  C13 of S2a prereg v0.2.6 section 7, with sections 6, 6a, 6b and 13 and the interpretations I-3, I-5 to I-8 and
  I-15 of S2a `profile/IMPLEMENTATION_BINDING.md`; plus the TB7 harness rule and the section 9 claim-digest binding.
  The 71 transcripts decode strictly; **72 of 72** vectors give the expected outcome and the exact reason code
  (N7b, which has no transcript, gives the expected `tb5` HALT); TB7 72 of 72 (N20 REJECT, N21 HALT); the claim
  digest does not bind for N33 only, as that vector expects. A first step, C7 to C10 alone, agreed on the 20 vectors
  in its scope.

## Per test

Classes: **(a)** covered by the S2b reading of `../` (pass 2), cases named, all agree, nothing re-run; **(b)**
reconstructible from the public text and vectors, and run here; **(c)** reconstructible, not run; **(d)** not
reconstructible from the text alone, or needs the implementation or a Lean run. One class per test: a test with a
check run here is (b) even when S2b also covers part of it. "Partial" means the check covers only part of the
mutation as worded.

| Test | Mutation (short) | Expected | Layer | Class | Basis and result |
|---|---|---|---|---|---|
| M1 | W, Compatible, Eval, rules, codec changed after commitment | REJECT | profile + S2a C1, C1c, TB7 | b, partial | N19, N22a-c, N23a-c, N28a-e, N20: 13 of 13 agree. The Lean semantics are bound through the manifest digest, not changed by any vector |
| M2 | `Compatible := true` | fails FUC | S1 formal | b, partial | toy profile brute force agrees; the general statement is a Lean proof, not run |
| M3 | witness outside W | REJECT | S1 | b | `m3_outside_world.json` agrees |
| M4 | same claim value | REJECT | S1 | b | `n3_same_value.json` agrees |
| M5 | no earlier profile registration | REJECT | S2a C3 | b | N13a, N13b, N36a-c: 5 of 5 agree; N13a is HALT (ambiguity log) |
| M6 | limitations or witness bytes changed, digest unchanged | REJECT | S1 statement | b | digests recompute; a changed token or text changes them |
| M7 | different logs, or admission before commitment | REJECT | S2a C1, C4 | b | N8, X3: 2 of 2 agree |
| M8 | two serializations; noncanonical witness | REJECT | S1 + S2a codec | b | five S1 `m8_*` vectors, N23c: 6 of 6 agree; S2b SPS-2-member-order, SPS-2-whitespace, SPS-3-duplicate agree in pass 2 |
| M9 | no determinability witness | preflight HALT | S1 / preflight | c | a finite check like M2, minutes; no vector, and the preflight HALT is not exercised by any artifact read |
| M10 | e^d or e^u added or replaced after admission | REJECT | profile + S2a C3 | b, partial | N13b, N36b, N36c: 3 of 3 agree; mapping by this reading, no vector changes the capability evidence itself |
| M11 | no SCITT Receipt, bare predicate or envelope | REJECT | S2b / form | c | S2b C/C11, C/C22, s2a-t11/N7b agree but give `Unavailable(ReceiptAbsent)`, HALT (ambiguity log); a form check over constructed artifacts is about an hour |
| M12 | timestamps instead of Section 5 | REJECT | S2b | d | missing: an artifact whose timestamp order differs from its leaf order, with an expected outcome |
| M13 | claim not bound before first admission, or replaced | REJECT | S2a C4, section 9 | b | X2, X3, N33: 3 of 3 agree |
| M14 | no pre-evidence InstanceCommitment | preflight HALT | S2a C4 | b | N6a agrees |
| M15 | another profile or claim digest under the tuple | REJECT | S2a C4 | b | N6b, N6c: 2 of 2 agree |
| M16 | closure missing, order or set wrong, admission after closure | HALT / REJECT | S2a C6, C9-C11, C13 | b | N12, X6, X4, P2x, X8, N32a-d, N0, N1, P3b, X7, N5, N24, N25: 16 of 16 agree |
| M17 | predicate lacks limitations | REJECT | S1 statement | b | must-understand rule as read; not a verifier's behaviour |
| M18 | proofs without the complete VDS prefix | HALT | S2b | a | R/R12a, M/M8, M/M8b, M/M22, C/C2: 5 of 5 agree; mapping by this reading |
| M19 | another commitment or conflicting profile/claim | REJECT | S2a C3, C4 | b | N6b, N6c, N36a, N36b: 4 of 4 agree |
| M20 | iss outside authorized admitters | not an admission; REJECT if cited | S2a C8 | b | N4, N4b, N15, N17, N18, N30: 6 of 6 agree |
| M21 | relevant admission omitted from refs | REJECT | S2a C9 | b | N0, N1, P3b: 3 of 3 agree |
| M22 | relevant admission after closure, before S_R | REJECT | S2a C10 | b | N5 agrees |
| M23 | refs duplicated or not increasing | REJECT | S2a C7 | b | N2, N3: 2 of 2 agree |
| M24 | required detached payload unavailable | HALT | S2a C2 + S2b | b | N7a agrees; S2b S/S11 agrees in pass 2 |
| M25 | entry registered after S_R | scoped to S_R | statement wording | c | the COVERAGE_INSTANCE text says so and is present; no vector registers after S_R |
| M26 | same tuple in L1 and L2 | completeness only within L | statement wording | c | as M25; no two-log vector |
| M27 | TS iss, key, VDS or leaf encoding differs from LogIdentityV0 | REJECT | S2b | a | C/C10b, M/M27-attached, M/M27-detached, C/C9, I/I2-ts-iss, I/I5-spec, E/E10-unprotected, M/M4-in-log: 8 of 8 agree; detached gives HALT (S2b G-11) |
| M28 | lifecycle entry signed by another iss | not valid; REJECT if cited | S2a C5 | b | N14 agrees |
| M29 | admission between pre-closure transcript and closure | closure invalid, no verdict | S2a C6 | b | N12, N34, K1-K7: 9 of 9 agree |
| M30 | payload carries S_R, Receipt ref or final result | REJECT | payload schema r9 | a | SPS-15-s_r, SPS-15-receipt_ref, SPS-15-coverage_verification_result: 3 of 3 agree (row `payload = none`); mapping by this reading |
| M31 | limitation bytes absent, altered, digest mismatch | REJECT | S1 statement + schema | b | `limitations_digest` recomputes, an altered text changes it; S2b SPS-14-lim-altered, -lim-extra, -lim-reorder, -digest-wrapped agree in pass 2 |
| M32 | profile digest differs from the commitment's | REJECT | S1 + S2a C1, C3 | b | S1 `m32_wrong_spec.json`, N19, N36c: 3 of 3 agree |
| M33 | checker, .olean, lock, toolchain, policy, command or manifest differs | REJECT; unavailable HALT | build identity | d | needs a build and Lean; run here only the manifest file digests and the TB7 rule (N20 REJECT, N21 HALT) |
| M34 | certificate proves another proposition | REJECT | S1 Lean | d | a Lean type-check |
| M35 | `verifier_digest` differs from the manifest digest | REJECT | S1 statement + S2a TB7 | b, partial | the S1 statement records the A06 digest; N20 REJECT, P1 and P2 PASS; the adjudication-payload side (schema r9 A10) not run |
| AP1 | Compatible strict only for frozen e^d | passes FUC; caught by adequacy review; AP1 limitation | profile adequacy | d | the review is a human gate outside the document; run here only the presence of the verbatim AP1 text |

## Tally

| Class | Tests | Count |
|---|---|---|
| (a) covered by the S2b reading | M18, M27, M30 | 3 |
| (b) reconstructed and run here | M1, M2, M3, M4, M5, M6, M7, M8, M10, M13, M14, M15, M16, M17, M19, M20, M21, M22, M23, M24, M28, M29, M31, M32, M35 | 25 (4 partial: M1, M2, M10, M35) |
| (c) reconstructible, not run | M9, M11, M25, M26 | 4 |
| (d) not reconstructible from the text alone, or needs Lean | M12, M33, M34, AP1 | 4 |
| Total | | 36 |

No check run here disagrees with a published vector.

## Ambiguity log

| Where | Reading taken |
|---|---|
| Appendix A and profile v0.1.1 section 7.1 | same numbering and outcomes; the draft renames "receipt" to "P10 Adjudication Statement", but M35 keeps `receipt.verifier_digest`, read as the `R.verifier_digest` of `ActiveProfileBindingV0` (Section 4) |
| M5 and S2a section 7 C3 | Appendix A says REJECT; C3, which cites M5, gives HALT when no profile commitment exists (N13a) and REJECT when it follows the first admission (N13b). This reading follows the vectors |
| M11 and S2b prereg section 16 | Appendix A says REJECT; a Statement without its Receipt is `Unavailable(material, ReceiptAbsent)` in S2b, HALT. Not resolved; M11 stays (c) |
| M27 and S2b prereg G-11 | REJECT only when the mismatch is authenticated (attached payload); detached gives HALT |
| M2, last sentence | "Empty Wπ makes Determinateπ false" is not exercised: the toy W is not empty |
| S1 README, "five-world toy fixture" | five world tokens, a W of four: `TEST_VECTORS.md` says `wOut` is not in Wπ |
| S1 toy semantics | world `wXY` has firstBit X and secondBit Y; evidence `fAsB` is compatible with `wXY` iff X = A and (B = `_` or Y = B); `inconsistent` has no compatible world. From the token names and the N1-N4 reasons of `TEST_VECTORS.md`; S2a section 13 `itemCompat` states the same per-bit relation |
| S1 `limitations_digest` | no file read states its rule; SHA-256 of the JCS of the `limitations` array reproduces the recorded value |
| S2a section 6a, `fixture_id` | "the compiled fixture constant" has no value in the text; taken from P1's `pB` (`p10-s2-fx-v0`) |
| S2a `inst.bin` | read as the `ic` production of S2b prereg section 15.2 without payload tags; S2a gives no layout for it |
| S2a C1, internal order | I-8 order, then C1a, C1b, C1c; each vector carries one fault, so the order is not separated by the vectors; the row/detail mismatch code is this reading's name and no vector exercises it |
| S2a C3, validity | a profile commitment is valid when owner-signed and verified, whatever its digest; a wrong digest is then `c3_profileDigestMismatch` (G6-B1, N36c), superseding I-6 |
| S2a section 6b, pre-closure view | I-5: entries before the closure leaf that are owner-signed verified lifecycle entries (earlier closure attempts included) or relevant admissions, in leaf order |
| S2a C5 | I-3: a valid owner adjudication whose reference names a non-admission entry with another `iss` |
| M18, M24, M30 (S2b) and M23 (S2a C7) | the texts do not cite these test numbers; the mapping is this reading's |
| README status lines at the ratified tags | the S2a README at `v0.1.0-s2a-ratified` says nothing has been merged or tagged; the S1 README at `v0.1.0-s1-ratified` says "no release, no tag" and names profile commit `3c20df23`, while Appendix C pins `e2a02a73` with the same file digest (A03). Recorded only |

## What this does not show

- Nothing about the Lean proofs: no Lean was run and no `.lean` file was opened (the general case of M2, M33, M34).
- Agreement with the published vectors, not with any implementation's behaviour on other inputs; several readings
  above are not separated by the vectors.
- No new adversarial vector was built; the (b) results are on the author's vectors, or on single-field changes of
  the S1 statement.
- No check on a P10 Adjudication Statement payload after S2a ACCEPT (schema r9 sections 8.8 to 8.11).
- No profile-adequacy review (AP1).

An assistant wrote the code and the first draft of this report; Laurent Lemonnier read both. Nothing here is a
conformance claim by the profile's author, who is not asked for any interpretation before the report is written.

## Reproduce

```
cd interop/p10/appendix-a
git clone https://github.com/VolMax-Studio/p10-underdetermination-profile.git repos/p10-underdetermination-profile
git clone https://github.com/VolMax-Studio/p10-underdetermination-lean-s1.git repos/p10-underdetermination-lean-s1
git clone https://github.com/VolMax-Studio/p10-coverage-lean-s2.git repos/p10-coverage-lean-s2
git -C repos/p10-underdetermination-profile checkout e2a02a73df9e50f624512043dcb007fc337ba587
git -C repos/p10-underdetermination-lean-s1 checkout e4db3747eaeeb1a07227bb9029f9a9c3b566cdb1
git -C repos/p10-coverage-lean-s2 checkout 741d56d36d7b2bfe2e9e0080a1cba4393e4a47da
(cd repos && sha256sum -c --quiet ../SHA256SUMS)
python3 appendix_a_checks.py      # out/checks-b.json
python3 s2a_from_text.py          # out/s2a-subset.json, out/s2a-coverage.json
```

`out/report-appendix-a.json` holds the classification, the tally and the ambiguity log; it is written by hand from
the outputs above and was re-checked against them.
