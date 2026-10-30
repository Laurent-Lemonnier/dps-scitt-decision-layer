# A decision record and an AER-1 receipt, composed — 2026-10-29

Built at the request of the author of draft-zambo-aer1 (29 October 2026): "a decision record whose execution attempt
carries the receipt id and output_hash, with the receipt's execution_context naming the decision record".

A support agent proposes a refund of 120.00 EUR for a duplicate charge. The support lead is shown the rendered refund,
approves it with a signature, and the agent runtime calls the payment gateway, which issues an AER-1 receipt of the
call (`OBSERVED VIA GATEWAY`). Two documents record it, each under its own text, nothing changed in either:

| Side | Text | Here |
|---|---|---|
| Decision | Decision Provenance Standard, action binding 0.3.0 and signatures 0.2.0, main at `007f8c9` | the Core v5.0 record; the attachment (proposal, review, approval, request, recheck, attempt, observed result) sealed by the merchant (`issuer_signature`); the support lead's `person_approval` |
| Execution | draft-zambo-aer1-26, receipt schema 0.4, kit v1.5.7 (`7d5947d`) | the gateway's receipt: canonical bytes `{caller, inputs, issuer_claims, outputs, receipt_schema_version, tool}`, `output_hash`, `metadata_hash`, `input_hash`, `execution_context` |

Synthetic data and test keys.

## What binds, and what only points

- **DPS → receipt, bound.** The attempt cites the receipt by id (`trace_refs`: `urn:aer1:receipt:<id>`) and the result
  names its `output_hash` (`evidence_ref`). Both values are in the receipt's metadata block (Section 3.1), and the
  stages citing them are under the merchant's seal.
- **Receipt → DPS, bound.** The tool's recorded input carries the DPS `request_id` as the idempotency key (the action
  binding's executor rule: "Where the target accepts an idempotency key, the executor sends the request_id as that
  key") and exactly the approved specification's parameters. The input is in the canonical bytes, under
  `output_hash`, under `metadata_hash`; `input_hash` (Section 3.3) commits to it as well.
- **Receipt → DPS, pointed.** `execution_context.decision_record` names the record (`decision_id`, the record's
  digest, the `request_id`). Section 3.2 puts `execution_context` outside `metadata_hash`: "anyone holding the
  receipt can add, change, or drop it without affecting any verification outcome". The report shows it as the
  producer's assertion, consistent or not, and nothing rests on it. Section 3.2 names no member for a decision record;
  `decision_record` is this example's choice.

## What verifies (`out/summary.json`)

- The receipt: the AER-1 verifier written from the text (`../aer1/aer1_verify_independent.py`, strict tier),
  `metadata_hash` recomputed, `input_hash` confirmed; and the kit's own checks at the pinned commit: `conformance.py`
  (core, version and binding, reference-producer profile) and the reference verifier `aer1-verifier/aer1_verify.py`.
- The decision: the four schemas; the eight action-binding dimensions; the merchant's seal (`issuer_recorded_claims_only`);
  the support lead's approval (signature, subject, key state, identity) against the verifier's trust policy.
- The joins: the attempt cites the receipt's id; the result names its `output_hash`; the receipt's recorded input is
  the approved parameters, exactly; its idempotency key is the DPS `request_id`; its `created_at` falls between the
  attempt and the observed result.

## The failing cases (`negatives.py`, `out/negatives/`)

| Case | Change | Caught by |
|---|---|---|
| N1 | the receipt's outputs say 150.00 EUR, `output_hash` not recomputed | AER-1 (both verifiers): `output_hash does not match sha256(canonical_bytes)` |
| N2 | the receipt issued again with another refund reference, all its hashes recomputed | the joins: the DPS result names the first `output_hash` |
| N3 | a receipt of the same refund under another idempotency key | the joins: not this request |
| N4 | the gateway recorded 150.00 EUR, the person approved 120.00 EUR (hashes recomputed) | the joins: the input is not the approved parameters |
| N5 | the attempt edited to cite another receipt after the seal | the merchant's seal fails; the joins |
| N5b | the same edit, sealed again by the merchant | the joins: the receipt held is not the one cited |
| N6 | the receipt's `created_at` moved, `metadata_hash` not recomputed | the independent verifier (`metadata_hash does not match`); the joins (time). The kit's checks pass it, see below |
| N7 | a receipt dated 14:06Z, before the approval and the attempt (hashes recomputed) | the joins: time |
| N8 | `execution_context` names another decision record | nothing fails, by design: the pointer is reported inconsistent |
| N9 | `execution_context` without the decision record | nothing fails, by design: the pointer is reported absent |

## A finding on the kit: the metadata block is not recomputed

Draft -26 Section 6 step 4: for a receipt carrying `metadata_hash`, or at schema 0.4 and later, "recompute the
metadata block from the receipt's stored member values per Section 3.1 and compare; a mismatch MUST cause
verification to fail". At the pinned kit commit, no code recomputes it (`aer-1/conformance.py`,
`aer-1/conformance.js`, `aer1-verifier/aer1_verify.py`), and one vector in the corpus carries `metadata_hash`
(`valid/real-04`), no invalid one. `out/negatives/metadata-probes.json` records four changes to members only that block
binds: `created_at` moved, `id` replaced, tool version changed, `metadata_hash` zeroed. The independent verifier fails
all four; the kit's checks pass all four, and its reference verifier reports the id as "a label outside the
commitment". The CI asserts the first and records the second.

## What it shows, and what it does not

It shows a person's approval of exact values and a gateway's receipt of the call joined both ways by values each side
commits to, so that either document held alone names the other and a verifier holding both confirms the join offline.
It does not show that the gateway's observation is true (`OBSERVED VIA GATEWAY` is the receipt's own class; the DPS
result's basis is `independent_observation` because the gateway is not the agent runtime), that the clocks agree beyond
the order checked, or that no other call was made under the same approval: the request limit is 1, and a second receipt
under the same idempotency key is something only the gateway can refuse.

## Reproduce

```sh
# cryptography, jsonschema, asn1crypto; the Standard at 007f8c9; the AER-1 kit at the commit in ../aer1/PINNED_COMMIT
DPS_STANDARD=/path/to/standard AER1_KIT=/path/to/zambo/aer-1 python3 build.py
DPS_STANDARD=/path/to/standard AER1_KIT=/path/to/zambo/aer-1 python3 negatives.py
```
The CI (`../run.sh`) runs both after the AER-1 replay, with the kit it cloned there.
