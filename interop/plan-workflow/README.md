# Case 13: the approved plan and an AER-1 workflow receipt, composed (`plan-workflow/`)

The plan approved as a whole (`../plan-run`: one exact DPS approval of a three-step plan, three capsules, a run
manifest) and an AER-1 workflow receipt over the same run (draft-zambo-aer1-26, Section 8). The two record the run
from opposite ends: the plan side what was approved before execution, the AER-1 side what ran. Section 8.4 says that a
workflow manifest "published before execution that binds the expected step list or step count" should bind the
`merkle_root` itself; the approved specification is that binding here, and the joins check it. Run: `python3 build.py`,
then `python3 negatives.py`.

## What is built

- One AER-1 0.4 execution receipt per step, in the reference-producer layout of `../aer1-decision` (the step's
  operation, target and request digest as inputs, the outputs the manifest records), each verified by the independent
  AER-1 verifier written from the draft (`../aer1/aer1_verify_independent.py`); each carries the Section 8.6 workflow
  pointer (`workflow.id`, `url`, `step_index`), outside its canonical bytes.
- The workflow receipt (Section 8, Table 2): `type`, `version`, `workflow_id`, `receipt_id`, `session_id`, `goal`,
  `status`, `steps` (`seq` 1-based, `tool`, `receipt_id`, `receipt_hash`, times, `status`, `output_hash`),
  `merkle_root` in `seq-output-v1`, `merkle_version`, `output_hash`, `verify_url`.

## What the texts leave open, and the reading taken

- Table 3 lists no per-step `output_hash`, which `seq-output-v1` consumes. The draft's own seq-output-v1 example takes
  each step's from its receipt; so does this case (the step receipt's `output_hash`, bare hex).
- The workflow `output_hash`: no layout is published here, so it is the Section 7.1 serialization of
  `{"output": <final output>}`, the draft's default, with the final output read as the last step's outputs.
- `seq-output-v1` support was added to the independent AER-1 verifier for this case and proved on the kit's
  `workflow-merkle-seq-output-v1.json` at the pinned commit: 7 of 7, the two cross-version must-fail cases included (the
  verifier now reports 126 of 126 across eight suites).

## What verifies (`out/summary.json`)

The plan's ten joins (`../plan-run`), the three step receipts, the workflow receipt's members, seq numbering, unique
receipt ids and recomputed root, and five joins of this case:

1. the workflow's step list is the approved plan's, in its order (count, `seq` = index + 1, tool = the approved
   operation);
2. each workflow step names the receipt that carries exactly the outputs the manifest records for that step, its
   `output_hash` is that receipt's, and the receipt points back to this workflow at that index;
3. the `merkle_root` recomputed from the manifest's steps and their receipts in `seq-output-v1` is the workflow's, and
   the workflow declares that construction;
4. the workflow's `output_hash` is the Section 7.1 digest of `{"output": <the last step's outputs>}`;
5. the workflow names this run, and its steps' times are the manifest's (the issuers' times, not an ordering proof).

## The failing cases (`negatives.py`)

Each is published as a directory `out/negatives/<case>/` with its documents, `what.txt` and, apart from them,
`result.json`.

| Case | Change | Caught by |
|---|---|---|
| N1 | the workflow lists two steps; the plan approved three | join 1 (and 2, 3) |
| N2 | two steps listed in the other order | join 1 (and 2, 3) |
| N3 | one step's `output_hash` is not its receipt's, the root recomputed over the substitute | joins 2 and 3 |
| N4 | the `merkle_root` is computed over other output hashes | the recomputed root (and join 3) |
| N5 | a fourth step the plan never approved | join 1 (and 2, 3) |
| N6 | the root computed in `seq-output-v1`, the workflow declaring `receipt-id-v0` | the recomputed root (and join 3) |

Synthetic: the run, its outputs, the receipts' ids and times. No AER-1 software of the author was run for this case;
the step receipts are checked by the independent verifier only.
