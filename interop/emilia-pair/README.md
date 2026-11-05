# An EP authorization bundle and a DPS decision, bound both ways (`emilia-pair/`)

Built at Iman Schrock's request (1 November 2026), against draft-schrock-ep-authorization-receipts-13 and the
Decision Provenance Standard's action binding 0.3.0 and signatures 0.2.0 (main `007f8c9`). A synthetic payment
release: one person approves the exact specification under the DPS; two EP approvers then sign Authorization
Contexts whose `authorization_binding` names that DPS approval by its native bytes; the EP Trust Receipt follows; and
a later DPS attachment cites the complete receipt by its digest. Run: `python3 build.py`, then `python3 negatives.py`.

## The order, so that no digest is circular

1. The DPS decision record and the action-binding attachment **A1** as issued at the approval: proposal, review,
   the person's approval of one specification, sealed by the issuer; the person's `person_approval` signed.
2. The **EP bundle** (`EP-AUTHORIZATION-BUNDLE-v1`, section 6): the Action Object derived from the approved
   specification by the profile's mapping (below); two Authorization Contexts carrying the same
   `authorization_binding`; two signoffs (Ed25519, class B).
3. The **EP Trust Receipt** (section 7.2), synthetic: same action, contexts and signoffs, `consumption.nonce` equal
   to the signed `authorization_instance`, and a one-leaf `log_proof` built here.
4. The later DPS attachment **A2**: A1's stages unchanged, then request, recheck, attempt and result; the recheck
   names the receipt by `base_receipt_digest` (section 8: SHA-256 over the JCS bytes of the complete, unchanged
   receipt), with its `receipt_id` and `action_hash`. A2 is sealed by the issuer.

The EP approval is bound to a fixed DPS version forward (A1's bytes), and the receipt reference sits in a later
attachment, as Iman set it out. **Neither reference alone establishes execution or its ordering**: the binding says
which DPS approval the EP approvers signed over; the reverse reference says which receipt the DPS executor rechecked
against; the times that order them are each issuer's.

## The binding profile `DPS-ACTION-BINDING-v1` (provisional, this repository's)

Section 6.1 leaves every member but `profile` to the binding profile, with its byte scope and its native
verification. This one defines:

- **Members**: `profile` = `DPS-ACTION-BINDING-v1`; `decision_record_digest` = `sha256:` + the record's `seal_hash`;
  `attachment_digest` = `sha256:` + SHA-256 over the action-binding attachment's bytes **as issued** (A1, the
  attachment at the approval, issuer seal included); `outcome_stage_id` = the approving outcome stage; 
  `approved_spec_digest` = `sha256:` + that stage's `approved_spec_digest`; `action_digest` = the EP `action_hash`.
- **Mapping** (specification to Action Object, with every minimum member of section 3): `action_type` = `operation`;
  `initiator` = `parameters.initiator`; `parameters` = the specification's other parameters, unchanged; `target` =
  `{system, resource}` split from the specification's `target` at its first `/`; `ep_version` = `1.0`; `policy_id` =
  the relying party's **pinned** EP policy identifier (`ep-pinned-inputs.json`); `requested_at` = the time of A1's
  **proposal stage**, in the bytes the binding names. The two last members are derived from explicit trusted inputs,
  never made up to fill the shape (Iman Schrock, 4 November 2026), and each is checked against its source.
- **Two limits, explicit.** The inverse reconstructs `operation`, `target` and `parameters` exactly, and nothing
  else: `input_version_refs`, `policy_version` and `valid_until` stay outside that projection. The full
  `approved_spec_digest` in the binding still binds those bytes, but **this is not an inverse of the entire
  specification**. Anything the Action Object carries beyond the mapping is a lossy mapping and is refused.
- **Verification** (step 10 of section 6.2, after the schema controls below): verify the DPS artifacts natively under
  the relying party's own trust policy (A1's binding dimensions, the issuer's seal, the person's approval); take the
  approved specification and the proposal stage from A1; check `policy_id` against the pinned policy and
  `requested_at` against the proposal time; derive the expected binding object; compare its JCS bytes with the signed
  binding; require the mapped Action Object to equal the bundle's, byte for byte in JCS, and its inverse to equal the
  specification's projected members. A source that does not verify, an unequal binding, a derived member that is not
  its source's or a lossy mapping is REFUSE; trust inputs the relying party does not hold are INDETERMINATE.
- **Schema controls** (sections 3 and 4, before anything is read from the bundle): the Action Object must carry
  `ep_version` (`1.0`), `action_type`, `target` (`system`, `resource`), `parameters`, `initiator`, `policy_id` and
  `requested_at`; every Authorization Context must carry `ep_version`, `context_type` (`ep.signoff.v1`),
  `action_hash`, `policy_id`, `policy_hash`, `initiator`, `authorization_instance`, `audience`, `approver`,
  `approver_index` (1 to n, each once), `required_approvals`, `nonce`, `issued_at` and `expires_at`, with the
  action's `initiator` and `policy_id`. A context issued without one of them and signed validly over the rest is
  REFUSE, not SATISFIED (added on 4 November 2026, after Iman Schrock found the earlier verifier accepted it).

## What verifies (`out/summary.json`)

- DPS, by the Standard's reference checks: A1 (every binding dimension; recheck and results not checked, as there are
  none at the approval), A2 (every dimension), the issuer's seal on each, the person's approval.
- EP, a bundle verifier written from section 6.2 in its order (the schema controls of sections 3 and 4, then steps 1
  to 8, 10 and 11; step 9 is not required by the pinned policy, and `approver_key_proofs` and `presentation_evidence`
  are empty as section 6 allows): **SATISFIED**.
- The same bundle verifier on the author's own example at the pin (`emiliaprotocol/emilia-protocol` `00fa00a7`,
  `conformance/vectors/authorization-bundle.v1.json`, case `valid-non-oauth-native-binding`; `vectors/`,
  `PINNED_COMMIT.txt`, `SHA256SUMS`): since 4 November 2026 **REFUSE**, where the case expects SATISFIED: the vector's
  action carries only `action_type`, `initiator` and `parameters`, and the schema controls refuse it for the four
  missing minimum members of section 3 (`ep_version`, `target`, `policy_id`, `requested_at`). The author wrote the
  same day that section 3's minimum applies and that the published vector is incomplete and needs correcting; the
  disagreement is expected until the corrected vector is pinned here (`summary.json` carries it as `published_example`,
  beside this pair's own result, not folded into it). Until 4 November the verifier had no schema controls and gave
  SATISFIED on it, with its binding profile's expected object taken from the case.
- Five joins, all true: the later attachment names the complete, unchanged receipt by SHA-256 over its JCS bytes,
  with its `receipt_id` and `action_hash`; the receipt is the bundle's (action, contexts, signoffs, consumption nonce);
  A2 extends A1 (A1's stages unchanged, its request and attempt for the approved specification); A1 carries no reverse
  reference; the issuers' times order the pair (DPS approval, contexts issued and signed, receipt committed, request).
- **What this establishes.** The passing pair and the nineteen failing cases establish *this fixture's checks*: that
  this verifier applies these readings of sections 3, 4, 6.1, 6.2, 7.2 and 8 to these documents. They do not
  establish EP conformance of anything, and no EP software was run.

## The failing cases (`negatives.py`)

Each case is published as a directory `out/negatives/<case>/` with the documents the checks ran on, `what.txt` and,
apart from them, `result.json`; `summary.json` gathers the verdicts.

| Case | Change | Caught by |
|---|---|---|
| N1 | the binding names A1 by the digest of other bytes of the same content | EP step 10: binding unequal |
| N2 | one context carries no binding | EP step 3: a mixture of bound and unbound contexts |
| N3 | the binding names another version of the specification | EP step 10: binding unequal |
| N4 | the Action Object carries a parameter the specification does not | EP step 10: mapping not lossless (and binding unequal) |
| N5 | the bundle's `action_hash` is not the recomputed one | EP step 2 (and step 3; the receipt join) |
| N6 | the receipt changed after A2 took its digest | join: the reverse reference |
| N7 | the receipt reference carried in A1, re-sealed after the binding was signed | join: no circular reference (and binding unequal) |
| N8 | a signoff by a key the relying party did not pin | EP step 5 (and the threshold) |
| N9 | the person's DPS approval signature broken | EP step 10: the source does not verify (and both DPS checks) |
| N10 | no DPS trust inputs held | EP step 10: INDETERMINATE, never SATISFIED |
| N11 | A2 executes another specification's digest | join: A2 extends A1 (and the DPS check of A2) |
| N12 | every context issued without `ep_version`, signed validly over the rest | schema control: `context_<i>_missing:ep_version` |
| N13 | every context issued without `context_type`, signed validly | schema control: `context_<i>_missing:context_type` |
| N14 | every context issued without `policy_id`, signed validly | schema control: `context_<i>_missing:policy_id` |
| N15 | every context issued without `initiator`, signed validly | schema control: `context_<i>_missing:initiator` |
| N16 | every context issued without `approver_index`, signed validly | schema control: `context_<i>_missing:approver_index` |
| N17 | the Action Object without `policy_id` and `requested_at`, as the pinned vector's | schema control: `action_missing:policy_id`, `action_missing:requested_at` |
| N18 | the Action Object's `policy_id` made up, carried consistently into the contexts | EP step 10: not the pinned policy (and binding unequal, mapping not lossless) |
| N19 | the Action Object's `requested_at` not the proposal time | EP step 10: not the proposal time (and binding unequal, mapping not lossless) |

N12 to N16 are the five omissions Iman Schrock found accepted by the verifier as it was on 3 November 2026; the
verifier then returned SATISFIED on each, which is why the schema controls exist.

## Readings, and what is synthetic

- "The approver signs the context hash" (section 4): the signature is over the 32 raw bytes of the digest; the
  `sha256:` text is only its representation. Shown by the published vector (both of its signoffs verify only that
  way) and confirmed by the author on 4 November 2026.
- Section 3's minimum members (`ep_version`, `action_type`, `target`, `parameters`, `initiator`, `policy_id`,
  `requested_at`) apply, the author confirmed on 4 November 2026; his published example's action, which carries only
  `action_type`, `initiator` and `parameters`, is incomplete against that list and will be corrected on his side. This
  pair's Action Object carries all seven: `policy_id` and `requested_at` are derived from explicit trusted inputs (the
  pinned policy, A1's proposal stage), as he asked, not invented to fill the shape.
- A source artifact that fails native verification is read as REFUSE (a definite mismatch), trust inputs not held as
  INDETERMINATE (section 6.1's split).
- Synthetic: every key (seeded, test only), the policy objects, the Trust Receipt's log (one leaf, a test log key) and
  the times. No EP software was run (the reference verifier is JavaScript; none was installed here).
- The binding profile is provisional and this repository's; the member names are offered to the EP author for his
  own naming, which would replace them.
