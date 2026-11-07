# A human checkpoint in the middle of a plan, under an undecided claim — 2026-11-01

The plan of `../plan-run/` again: three steps approved as a whole, three chained capsules, a manifest between them,
the run's context growing one step at a time. This time the run stops after step 0. Before the CRM record is created,
the runtime screens the client against a restricted-parties list; one source says "possible match" at 61 percent,
one has no data. The claim "the client has no match" is left undecided by that evidence, and an adjudication of
that fact is held beside the run. The office manager decides to resume, knowing it; the run resumes; the two steps
after the checkpoint carry her decision.

| Layer | Text | What it records here |
|---|---|---|
| WHO, the plan | Decision Provenance Standard, action binding 0.3.0 and signatures 0.2.0, main at `007f8c9` | as in `../plan-run/`: one specification, the plan, approved once and signed |
| WHO, the checkpoint | the same | **a second decision record** (options, reasons, inputs) with its own attachment: one specification, `workflow.resume` at step 1, whose parameters name by digest **the state of the run's context after step 0** and **the adjudication** decided under; shown, approved once, signed with `person_approval`; the issuer's seal over the attachment |
| the epistemic input | draft-nestorov-scitt-p10-underdetermination-02, Section 9 (shape only) | `out/adjudication.json`: an adjudication in the shape P10 lists, over a two-source screening fixture (`out/screening-fixture.json`): claim, closed evidence, two witness worlds, every structured digest recomputable; outcome `NotDemonstrated(reason=underdetermined)` |
| WHAT | Agent Action Capsule format 4, library 0.15.0 (0.12.0 until 7 November 2026) | one capsule per step; the capsules of steps 1 and 2 cite the checkpoint decision as well as the plan's (`ran_under`), step 0's does not |
| the mother | `out/plan-run-manifest.json` (`net.isoluce.plan_run` 0.1.0, provisional) | the steps, the context states, and a `checkpoints` entry between steps 0 and 1: the state decided on, the decision record by its seal digest, the adjudication by its digest, when it was decided and resumed |

Synthetic data, test keys, as in the plan case.

## What is synthetic, and said to be

The adjudication is built in this directory in the shape of P10 Section 9, with its limitations stating so. It is
not issued, registered or verified by the P10 chain (a Lean certificate, a replay verifier, a transparency service),
and nothing here claims conformance to that profile; the fixture's compatibility relation and evaluation are the
fixture's. The profile's own executed instance is named beside it, for the shape a real one takes: its adjudication
statement, leaf 7 of the instance's log (log identity `6a510bcf…`, checkpoint size 8, Appendix B), is cited by its
bytes as the author published them: `VolMax-Studio/p10-scitt-transparency-s3`, tag `v0.1.0-s3-accepted` (commit
`5acc277a`), `ts-prototype/evidence/s3b-capture/capture/prefix/000007.cose`, 7,516 bytes, SHA-256 `73273d96…a16e`
(the locator as the author corrected it on 1 November 2026; the draft's Appendix C.3 pins the same digest as C09). A
copy is pinned in `vectors/` (`PINNED_COMMIT.txt`, `SHA256SUMS`), and the run checks it against the citation
(`checkpoint.executed_instance_held` in `out/summary.json`); that is a check of the pin, not one of the joins, and
nothing here reads the statement's content or verifies it under the P10 chain. What this case adds is the decision
layer over the synthetic adjudication: what the person knew was undecided, decided anyway, and recorded why.

## The point

A plan approved as a whole does not foresee everything. When a check in the middle of it leaves a claim undecided,
the honest record is not "the check passed" nor "the plan stopped": it is a decision, by a named person, on an
exact state of the run and an exact statement of what was undecided, with the options she had. The Standard
records that decision as it records any other; the plan case's manifest says where in the run it happened; the
capsules after it say they ran under it. The P10 shape gives the undecided claim a verifiable form: the claim, the
evidence closed at that point, two worlds compatible with it that disagree, all by digest.

## What verifies (`out/summary.json`)

- Everything of `../plan-run/`: schemas, the plan's eight dimensions, seal and approval, 3 capsules, the ten joins
  (with the steps' times moved after the checkpoint).
- The checkpoint: the record, attachment and signatures attachment schema-valid; the eight action-binding dimensions
  verified; the issuer's seal and the manager's `person_approval` verified.
- Five joins more:
  11. the checkpoint decision's specification names, by digest, the context state after step 0 as the manifest
      records it, the adjudication held and its claim; the manifest's checkpoint entry names the same;
  12. the adjudication is undecided on its own terms: claim, evidence, witness and limitations digests recompute from
      the objects beside it, both witnesses are compatible with the evidence under the fixture's relation, and they
      give the claim different values;
  13. every step after the checkpoint cites the checkpoint decision as `ran_under`, and no step before it does;
  14. the decision was approved after step 0's capsule and before step 1's, and the resumption requested after the
      approval (the issuer's times);
  15. the manifest's checkpoint entry names the record held by its seal digest, and the record names the run, the
      state and the adjudication among its inputs.

## The failing cases (`negatives.py`, `out/negatives/summary.json`)

Each case is published as a directory `out/negatives/<case>/` holding the documents the verification ran on, as they were at that moment (`<name>.json`; where the bytes as issued are also an input, `<name>.as-issued.json` beside it), the description (`what.txt`) and, apart from them, the verdicts (`result.json`); `summary.json` gathers the verdicts. Layout adopted on 3 November 2026 after an outside reading found the cases could not be rerun from the published verdicts alone.


| Case | Change | Caught by |
|---|---|---|
| N15 | the steps after the checkpoint cite the plan's approval only | join 13 |
| N16 | the decision names the state before step 0, not after it | join 11 |
| N17 | the specification names another claim than the adjudication's | join 11 |
| N18 | the decision is approved after the CRM record was created | join 14 |
| N19 | the two witness worlds give the claim the same value | join 12 |
| N20 | the adjudication's evidence digest is not that of the evidence beside it | join 12 |
| N21 | the manager's signature names another specification | the checkpoint's DPS signatures |
| N22 | step 0's capsule cites a decision that did not exist when it ran | joins 13 and 14 |

The plan case's own fourteen failing cases are not repeated.

## What it shows, and what it does not

It shows that a decision taken in the middle of an approved plan can be recorded with the exact state it was taken
on and the exact statement of what was undecided, and that the steps after it can be told from the steps before it.
It does not show that the screening was right, that the adjudication was issued by anyone, or that the person read
what was shown. The adjudication's form is borrowed from a text whose verifier did not run here; the author of that
text is told so.

## Reproduce

```sh
# as ../plan-run/, which this case imports
DPS_STANDARD=/path/to/standard python3 build.py
DPS_STANDARD=/path/to/standard python3 negatives.py
```
