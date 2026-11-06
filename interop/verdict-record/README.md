# A verdict record over a signed decision chain, and a decision over a verdict — 2026-11-06

draft-wright-verdict-record-02 (Darren Wright, 2 November 2026) defines a verdict record: a result reached on a
claim, the evidence it relies on cited by the SHA-256 of its exact bytes, and the rule by which a checker re-derives
the result. The Decision Provenance Standard (action binding 0.3.0, signatures 0.2.0; draft-lemonnier-scitt-
decision-provenance-01) records what a person was shown, approved and signed, and what was then requested and
executed. This case puts one over the other, both ways, without a change to either text, and checks the verdict
records with a checker written from Wright's text alone (`verdict.py`; no code of his was read).

| Layer | Text | What it records here |
|---|---|---|
| WHO | Decision Provenance Standard, main at `007f8c9` | the refund of `../aer1-decision` again, without the AER-1 receipt: a decision record (120.00 EUR on order 8812), the attachment as issued at the approval (A1: proposal, review, outcome), the attachment after execution (A2: A1's stages then request, recheck, attempt, result), the support lead's `person_approval`, the issuer's seals |
| the result on a claim | draft-wright-verdict-record-02, Sections 2, 2.1, 2.2, 2.3, 3, 4, 6, 7 | **A.** an auditor's verdict record, kind `check-run`, on the claim "the specification executed equals the one the accountable person approved": evidence A1, A2 and the decision record's *file*, each by the digest of its exact bytes, each with the `format` that verifies it; a rule whose five inputs are all bound to the evidence; result `executed_as_approved` |
| WHO over it | the Standard again | **B.** the support lead closes the case on the verdict: a second decision record whose approved specification names the verdict record by the digest of its bytes (`input_version_refs`, the shape of `../plan-checkpoint`), approved, executed, sealed |
| reassessment | Wright Section 6; DPS Core `supersedes` | **C.** the decision record corrected (a new record, `supersedes` = the old `decision_id`; the attachments re-sealed; the specification and the view unchanged; the approver signs again); version 2 of the verdict, `supersedes` = the digest of version 1 |

Synthetic data, three test keys (approver, issuer, auditor), fixed times; two runs give identical bytes.

## The point

Wright's record is a posteriori: a result on a claim, re-derivable. The Standard's record is a priori and chained:
what was shown, approved, requested, executed. Neither contains the other, and neither needs to. A verdict record
cites the attachment's bytes as they are (the attachment's identity in the Standard is already the SHA-256 of its
file), cites the decision record's file as an item of its own (its identity in the Standard is its `seal_hash`,
not the file's digest; Wright's Section 7 anticipates exactly this), and names as its rule the thing a third party
can run: the Standard's reference check over A2 and the record, and the comparison of the approved and attempted
digests. In the other direction, a decision record names a verdict record among its inputs as it names any input,
by digest. What is added is the join: that the verdict re-derives over the bytes the person's approval covers, and
that the person decided on a verdict a third party re-derives.

## The rule (`executed-as-approved:v1`)

Named by URI (Wright Section 1.2 asks that a rule name identify its version). Inputs, every one bound to an evidence
item (Section 2.2: "an issuer SHOULD bind an input to evidence rather than copy a value"): `approval` (A1, whole,
JSON Pointer `""`), `attachment` (A2, whole), `record` (the decision record, whole), `approved_spec_digest`
(A1, `/stages/2/approved_spec_digest`), `attempted_spec_digest` (A2, `/stages/5/spec_digest`). Result
`executed_as_approved` when: the Standard's action binding reference check over `attachment` and `record` reports
all eight dimensions verified; A1's stages are the first stages of A2, unchanged, for the same `decision_id`; A2 has
exactly one attempt, whose digest equals the approved one and equals both digest inputs; the result stage observes
`succeeded`. Otherwise `not_as_approved`. The body holds only the claim, so a checker that reads inputs from
evidence only (Section 4.5) re-runs it.

## The format rules (Section 4.3 step 2, Section 7)

`format` is a URI naming the specification at the pinned commit of the Standard: `…/tree/007f8c9…/extensions/action-binding`
for the attachments, `…/tree/007f8c9…/standard/v5.0` for the record's file. What this checker holds as the rules of
those formats: strict JSON; schema-valid; every specification digest recomputes from the bytes carried; the issuer's
seal verifies under the DPS trust policy the checker holds (attachment); `seal_hash` recomputes (record). The binding
dimensions (requested against approved, recheck, observed result) are not format rules here: they are what the rule
of step 3 re-derives. See the ambiguity log, entry 5.

## What verifies (`out/summary.json`)

- The DPS side, natively, by the Standard's reference checks: A1 (six dimensions, the two execution dimensions not
  yet checkable), A2 (eight), the closing decision (eight), the corrected record's A1 and A2; every issuer seal and
  every `person_approval` verified; schemas valid.
- The verdict records, by the checker written from Wright's text, under an evidence-only policy with citation depth
  1: version 1 **released** (step 1 PASS, step 2 PASS, step 3 PASS, the re-run giving `executed_as_approved`);
  the verdict stating `not_as_approved` over the chain where 150.00 EUR was executed for 120.00 approved
  **released** (a true negative result, re-derivable); version 2 **released**. Each report names the policy's
  digest, the trust anchors' digest, the upper time bound and no word that speaks for the whole record (Section
  4.4; checked over the report's member names).
- Wright's Appendix A, the only vectors his text gives: the canonical form of Section 2.1 as this checker writes it
  reproduces his A.1 record digest (`2a85c94e…`), his A.2 record digest (`62017940…`), the claim and both hop
  digests; his A.2 record run through this checker gives what his text predicts: released under a hop format rule
  that only parses, held under one requiring the signature the hop format requires, refused when the child widens
  its scopes, held when the child hop is not held.
- Eleven joins:
  - A1 the evidence entries are the digests of the exact bytes held, and the record's file digest is not its
    `seal_hash` (Section 7);
  - A2 the re-run gives the result the auditor stated, and that result is what the Standard's checks say natively;
  - A3 every rule input is bound to evidence, none read from body, and the evidence-only policy ran step 3;
  - A4 over the 150/120 chain, the verdict stating `not_as_approved` is released and the Standard's
    `action_binding` dimension fails on that A2;
  - B1 the closing decision's approved specification names the verdict held by its digest, in
    `input_version_refs` and in its parameters, and that record is released;
  - B2 the verdict cited is about the chain the closing decision names (the refund record's file among its
    evidence, its `decision_id` in the closing specification);
  - B3 the result the support lead decided on equals the result the checker re-derived;
  - B4 the verdict was reached (issuer's `act_time`) and taken in by the checker (its upper time bound) before the
    closing decision was shown and approved;
  - C1 version 2 supersedes version 1 by the digest of its exact bytes, same key, one version later; both released;
  - C2 version 2 cites the corrected record, which supersedes (Core) the record version 1 cites: the current pair
    is (version 2, corrected record), the earlier (version 1, original record);
  - C3 the correction changed the record, not the action: the same specification and view digests in both pairs;
    the approver signed again (the `person_approval` names the `decision_id`), same key, same digests.
- Reported, not joined: the closing decision cites version 1, which version 2 supersedes (Wright's Appendix B leaves
  open how a checker holding a later version treats a citation of the earlier; Section 6 says the later version does
  not by itself change the state of the earlier, and this checker reports version 1 released with version 2 held);
  `supersedes` is read by no step of Section 4.3 (join C1 is this case's); nothing in the verdict re-derives the
  person's approval, which is the Standard's check beside.

## The failing cases (`out/negatives/`, 19, each as expected)

| Case | Changed | Wright's text says | Observed |
|---|---|---|---|
| N1 | A2 requests and attempts 150.00 EUR; the verdict states `executed_as_approved` | step 3: the re-run must equal `check.result` | **refused** at step 3, re-run `not_as_approved`; the Standard's `action_binding` failed |
| N2 | one member of A2 changed after citation | step 2: no item held with the entry's digest, NOT RUN naming it | **held**, `evidence[1]` not held |
| N3 | no container (the writer's signature absent) | Section 3: the container does not show the record, held with the reason | **held**; steps 1 to 3 PASS, reported |
| N4 | the container's signature is another key's | Section 3 | **held**, "does not verify under the writer's key" |
| N5 | a space after the first comma | Section 2.1: re-serializing must give the same bytes; refused before any step | **refused** before steps |
| N6 | a member `note` added | Section 2.2: no other member | **refused** before steps |
| N7 | rule `judgement` on a `check-run` | step 1: judgement only for kinds the policy lists | **refused** at step 1 |
| N8 | the attachment format not in the checker's policy | step 2: not relied on, NOT RUN | **held** (all three verdicts) |
| N9 | `attempted_spec_digest` bound to `/stages/9/…` | step 3: a pointer that does not resolve is a FAIL of the step, not a result of the rule | **refused** at step 3 |
| N10 | the attempted digest copied into body; evidence-only policy | Section 4.5: an input bound to body makes step 3 NOT RUN | **held** at step 3 |
| N10b | the same under the default policy | Section 4.2: the report names each input read from body | **released**, `body_inputs_read: [attempted_spec_digest]` (by design: what the -02 policy adds) |
| N11 | the closing decision names an altered copy of the verdict | (the Standard's checks do not read the citation) | DPS verified; join B1 false |
| N12 | version 2 `supersedes` a digest of nothing held | no step reads `supersedes` | **released**; join C1 false |
| N13 | version 2 with `supersedes` null | Section 2.2 | **refused** before steps |
| N14 | a reassessment record cites N1's refused verdict under `verdict-record/1` | Section 4.3, Section 6: relied on only while released | **held** at step 2, cited record refused |
| N15 | the same, citing the released version 1, policy depth 0 | step 2: beyond the depth, NOT RUN | **held**, "beyond the citation depth 0" |
| N16 | the container is signed by a key the anchors bind to `other-audit.example` and names that party; the record's writer is `audit.example` | Section 3: a key shown to belong to the party the record names in writer | **held**, "not to the party the record names in writer"; steps 1 to 3 PASS |
| N17 | body carries an object chain making the record exactly 32 levels deep (his vector a11) | Section 2.1: refuse deeper than 32; each object or array inside adds one level | **released** (refused before 6 November 2026: off by one) |
| N18 | the same chain one object longer, 33 levels (his vector a12) | Section 2.1 | **refused** before steps |

N16 to N18 were added on 6 November 2026 after running the author's test vectors (below): a11 found the depth count off
by one (a scalar inside the 32nd level counted as a 33rd); the writer comparison of N16 was seen while adapting, exercised
by none of his cases (one writer throughout). Both fixed in `verdict.py` the same day; cases 01 to 15 and cases 18 and 18b
(`../one-chain`, `../one-chain-real`), which use this checker, keep their outputs.

Each case directory holds the verdict records as bytes, their containers, every evidence item by its digest, the
checker's policy and anchors, `result.json` and the full `summary.json`: enough to re-run the checker on them.

## What is not shown, and what is synthetic

- The container of Section 3 is a stand-in: a detached Ed25519 signature over the record's exact bytes, the key
  shown to belong to the writer by the checker's trust anchors. A SCITT Signed Statement with its Receipt is the
  container his text names; none is built here, and nothing about a Transparency Service is shown.
- The upper time bound is the checker's own intake time of the bytes, a checker input written as data. No clock is
  read; nothing establishes that time against a third party.
- The checker is read against his text and his Appendix A, not against his vectors: none was read while writing it.
  On 6 November 2026, at his request, his vectors were run through it unchanged (`wright-vectors/`, below): a
  presenter's adapter, not a change to the checker. A checker written by a party other than the author is what his
  Appendix B asks for; this is one, offered for his review, not a conformance claim.
- The rule, its name and its result set are this repository's (provisional); Wright's Appendix B asks where rule
  names and results are registered.
- Nothing here shows that the claim is true (his Section 5), nor that the approver is who the trust policy says.

## Ambiguity log (section numbers are draft-wright-verdict-record-02's)

1. Section 2.1 says strings escape control characters, not in which of RFC 8259's forms (`\n` or `\u000a`). This
   checker writes the short forms RFC 8259 names and `\u00XX` for the rest; a record with the other choice would be
   refused as not canonical. Appendix B's JCS profile would settle it (JCS writes the short forms).
2. Section 2.1 "numbers are integers": what a checker does with `1.0` or `1e2` in the record's bytes is implied
   (refused before steps, as bytes breaking the section); taken so here.
3. Section 2.2: a `v` other than `verdict-record/1`, or a `kind` neither defined nor starting with `x-`, is not
   said to be refused; refused before steps here.
4. Section 2.2: `result` has no stated JSON type ("the result the rule gave"); any value is accepted and compared by
   equality. The rule's own specification fixes its result set.
5. Section 4.3 step 2, "verified by the rules of the format its entry names", and Section 7, "a checker verifies an
   item only by the specification so named": for a format whose verification is a report of several dimensions
   that must not be merged into one pass or fail (the Standard's action binding; our -01 Section 6 step 6), which
   dimensions are the "format rules" of step 2 and which belong to the rule of step 3 is a reading. Here:
   structure, specification digests and the issuer's seal are format rules; the binding dimensions are the rule's.
   With the other reading (every dimension a format rule) the 150/120 chain makes step 2 NOT RUN and the record
   held, never refused, and a verdict stating the negative result could not be released. Also, the attachment's
   rules read a second document (the record it names): this checker hands every format rule all the items held.
6. Section 3, "an upper time bound … which the checker establishes itself": how is not said. Here it is the
   checker's intake time, its own input. Section 4.3's "where an item's verification gives it an upper time bound"
   is read as applying to cited verdict records (their containers) and to no DPS item (the seal's `sealed_at` is
   the issuer's statement).
7. Section 3, "if the container does not show the record, the state is held, with the reason": whether the steps
   still run and are reported, and whether a FAIL on bytes not shown to be the writer's becomes refused, is not
   said. Here the steps run and are reported, and the state is held either way (N3).
8. Section 4.3 step 3, "the checker MUST hold the rule's specification": the state when it does not is not said;
   NOT RUN naming the rule's specification as the input needed, here.
9. Section 4.3 step 3, "if one input cannot be read for the first reason and another for the second, the step
   FAILs": the two "reasons" are the NOT RUN class and the FAIL class of the sentences before; the outcome (FAIL)
   is clear, the pronoun order is not.
10. `supersedes` is read by no step of Section 4.3: a version 2 naming a digest of nothing held is released (N12).
    Appendix B asks about citations of earlier versions, not about this. Whether a checker should check that a
    `supersedes` digest it holds is a record of the same `key` and `version - 1` is open.
11. Section 2.2 and Section 7: a JSON Pointer of `""` (RFC 6901: the whole document) makes a whole item an input,
    which is how a rule re-runs a format's own check over the item. His text neither allows nor excludes it; his
    A.2 example uses only member pointers. Worth a sentence.
12. Section 7: `format` is a URI naming the specification; Section 1.2 asks rule names to identify a version, but
    nothing is said of format names. Here the URI pins the Standard's commit.
13. Section 4.4 forbids the words `verified`, `valid`, `true` and the like in the report. The Standard's reference
    check reports `verified` per dimension. A checker that embedded a format's report in its own would quote them;
    this checker keeps the format's report out of the verdict report, beside it (`dps.*` in `summary.json`).

## Who did what

An assistant wrote the code and the first draft of this README; Laurent Lemonnier read both.

## The author's vectors run through this checker (`wright-vectors/`, 6 November 2026)

At Darren Wright's request of 6 November 2026, his repository `diggertydog/verdict-record-test-vectors` at `97b63b2`
(37 vectors of -01 under `main/`, 8 proposal cases p01 to p08 for his -03 under `proposals/`) was run through
`verdict.py`. `wright-vectors/run_wright_cases.py` is the presenter: it hands the checker the record bytes, every
evidence item by its digest, a stand-in container (a test key bound in the anchors to the party the record names
in writer), the case's upper time bound as the intake time, the test-only formats his READMEs define, and the policy
with his `max_depth` renamed to this checker's `citation_depth` (Section 4.5 names no member). Three runs per case:
raw (his files as they are: every case **no verdict**, the policy member name), policy-only (no container: every
case **held**), adapter. `wright-vectors/results.json` holds the three per case beside his `expected_under_02`;
`main-vectors-run.json` the 37, states only.

- Proposals: p01 to p07 agree on state and steps; p08 agrees on state (held), not on step 2: his PASS, this checker
  NOT RUN, holding no rule for the two IronTrellis formats his policy lists (Section 4.5 does not say what a checker
  does with a listed format it cannot verify). Two more readings differ in the text, not the run: an extra policy
  member (p05) does not make a policy invalid under Section 4.5 as written; a cited verdict record given with a bound
  and no container (p04, p05) is held under Section 3 as written, so the adapter adds a stand-in container per cited
  record.
- Main vectors: 37/37 same state after the fixes above (36/37 before: a11); step results differ on b03 only (step 3
  after a step 1 FAIL: his PASS, this checker NOT RUN; same state).

The vectors themselves are not copied here; the run names the commit. p08 cites two IronTrellis files his repository
links rather than carries: `wright-vectors/p08-evidence/` holds `budget-v2.json` as fetched and the digests of both
(`SHA256SUMS`); `vectors.json` (1.4 MB) is fetched before a run (below), its digest checked by the adapter before the
item is handed over. `run.log` is the run of 6 November 2026.

## How to run

```
DPS_STANDARD=/path/to/decision-provenance-standard/standard python3 build.py       # out/, exit 0 when all verified
DPS_STANDARD=/path/to/decision-provenance-standard/standard python3 negatives.py   # out/negatives/, exit 0 when each case is as expected
```

Dependencies: Python 3.12, `cryptography`, `jsonschema` (with `referencing`) for the Standard's schemas; the
checker itself (`verdict.py`) uses the standard library and `cryptography` only. `../run.sh` runs both.

The author's vectors (not in CI; his repository is not pinned here):

```
git clone https://github.com/diggertydog/verdict-record-test-vectors /tmp/wright-vectors && git -C /tmp/wright-vectors checkout 97b63b2
curl -sSL -o wright-vectors/p08-evidence/vectors.json https://raw.githubusercontent.com/zerohourzulu/irontrellis/a2c487f6cd3afee2e35c7f7f1b64c9d966bf8387/conformance/v2-g3/vectors.json
(cd wright-vectors/p08-evidence && sha256sum -c SHA256SUMS)
WRIGHT_VECTORS=/tmp/wright-vectors python3 wright-vectors/run_wright_cases.py   # results.json, main-vectors-run.json, reports-full.json
```
