# An EP authorization bundle and a DPS decision, bound both ways (`emilia-pair/`)

Built at Iman Schrock's request (1 November 2026), against draft-schrock-ep-authorization-receipts-13 and the
Decision Provenance Standard's action binding 0.3.0 and signatures 0.2.0 (main `007f8c9`). A synthetic payment
release: one person approves the exact specification under the DPS; two EP approvers then sign Authorization
Contexts whose `authorization_binding` names that DPS approval by its native bytes; the EP Trust Receipt follows; and
a later DPS attachment cites the complete receipt by its digest. Run: `python3 build.py`, then `python3 negatives.py`;
`python3 build.py --vector <file> [--report <file>]` runs the same bundle verifier over every case of an EP vector
file (`EP-AUTHORIZATION-BUNDLE-CASES-v1`) and prints a report, writing nothing under `out/`.

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
  specification's projected members; apply the identity rule below. A source that does not verify, an unequal
  binding, a derived member that is not its source's, a lossy mapping or a broken identity rule is REFUSE; trust
  inputs the relying party does not hold, a DPS key state the Standard reports `unavailable` (a key revoked as
  compromised with no independent timestamp over the approval) or a DPS identity without a pinned link is
  INDETERMINATE (section 6.1's split).
- **Identity across the two systems, and separation of duties at the junction** (added 5 November 2026; a rule of
  this provisional profile, not of the draft). Section 1.2 leaves the link between an approver identifier and a person
  to the directory authority, and the draft says nothing about identities of another system. So the profile compares
  identities across the two systems **only through links the relying party pins** (`identity_links` in
  `ep-pinned-inputs.json`): for each DPS identity, the EP identifiers its own directories attribute to the same person.
  The DPS identities are the approving outcome's `actor_ref` and the holder, in the verifier's DPS trust policy, of the
  key that signed the verified `person_approval`; their linked EP identifiers must not include the Action Object's
  `initiator`. No identifier is compared with one of the other system by its text; a DPS identity with no link is
  INDETERMINATE. The rule extends SelfApprovalImpossible (section 7.1, approver != initiator) to the DPS approval the
  binding makes part of the evidence. In this fixture the DPS approver `treasury-controller-1` is linked to
  `ep:entity:treasury-controller-1`, who is neither the initiator (`ep:entity:agent-recon-7`) nor an EP approver. Not
  covered: the DPS approver being also one of the EP approvers (the policy may or may not count one person twice; this
  profile does not decide it).
- **Schema controls** (sections 3 and 4, before anything is read from the bundle): the Action Object must carry
  `ep_version` (`1.0`), `action_type`, `target` (`system`, `resource`), `parameters`, `initiator`, `policy_id` and
  `requested_at`; every Authorization Context must carry `ep_version`, `context_type` (`ep.signoff.v1`),
  `action_hash`, `policy_id`, `policy_hash`, `initiator`, `authorization_instance`, `audience`, `approver`,
  `approver_index`, `required_approvals`, `nonce`, `issued_at` and `expires_at`. A context issued without one of them
  and signed validly over the rest is REFUSE, not SATISFIED (added on 4 November 2026, after Iman Schrock found the
  earlier verifier accepted it). The consistency of these members (the action's `initiator` and `policy_id` in every
  context, indexes 1 to n each once) was checked here too until 5 November; it is now read at steps 3 and 6, once
  every member is known present, so that a duplicate approver is reported with the separation-of-duties failures
  rather than stopping the run (no published result changed by the move).

## What verifies (`out/summary.json`)

- DPS, by the Standard's reference checks: A1 (every binding dimension; recheck and results not checked, as there are
  none at the approval), A2 (every dimension), the issuer's seal on each, the person's approval.
- EP, a bundle verifier written from section 6.2 in its order (the schema controls of sections 3 and 4, then steps 1
  to 11, below; this pair's policy requires a binding and no current status, and `approver_key_proofs` and
  `presentation_evidence` are empty as section 6 allows): **SATISFIED**.
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
- **What this establishes.** The passing pair and the twenty-three failing cases establish *this fixture's checks*: that
  this verifier applies these readings of sections 3, 4, 6.1, 6.2, 7.2 and 8 to these documents. They do not
  establish EP conformance of anything, and no EP software was run.

## The bundle verifier, step by step (extended 5 November 2026)

`verify_bundle()` follows section 6.2 in its order. A definite mismatch at any step is REFUSE and outranks an
unavailable input elsewhere (the reasons then list the mismatches only); with no mismatch, an unavailable required
input is INDETERMINATE. Every definite failure found is reported, not only the first. The checks added on
5 November 2026 are marked *new*; each sits where the text places it, or where the reading in the last column says.

| Step | Check | From the text |
|---|---|---|
| 1 | closed bundle of eight members; then the schema controls of sections 3 and 4 (above) | section 6, 13.12 |
| 2 | `action_hash` recomputed | section 3 |
| 2 | *new*: the Action Object equals, in JCS, the action the relying party is about to admit (`expected_action`, when it holds one) | REFUSE lists an "action" mismatch; section 6.3 requires "approval of action A presented for materially different action B" and "a dynamic plan expansion beyond the approved action" to be refused. Step 6.2 names no separate step: this reading puts it with the action at step 2. The comparison is between two EP Action Objects, so section 3's CAID projection (for an action named by *another* artifact) does not apply. This pair holds no separate expected action: its action is the one the binding profile derives from A1 at step 10 |
| 3 | each context commits to the action hash; one policy hash, one audience, one `authorization_instance`, one binding; distinct nonces; *moved*: the action's `initiator` and `policy_id` in every context | step 3 |
| 4 | the signed `authorization_instance` equals the registered one; *new*: none held is INDETERMINATE | step 4 |
| 5 | each signoff: pinned key and accepted class; covers a selected context not already covered; key holder is the context's approver; *new*: the key's `valid_from`/`valid_to` contain the context's `issued_at` and the `signed_at` (section 5.2, 7.3 step 3), `signed_at` within the context's window; a key marked `compromised_at` (at or before now) refuses a signature stated at or after it, and makes one stated before it INDETERMINATE (section 13.3: a signer-asserted time cannot show the order), the signoff neither counted nor discarded, so that the m-of-n threshold cannot turn it into a REFUSE (corrected 5 November 2026 after Iman Schrock's probe; N23); signature over the 32 raw bytes; *new*: between m and n signoffs (section 6) | step 5, section 6 |
| 6 | the context approver set equals the selected one; *new*: initiator exclusion (the initiator is no context's approver and no signer: section 7.1, SelfApprovalImpossible); *new*: pairwise distinct approvers, one signoff per approver (section 6: "more than one signoff from the same approver is a refusal"); indexes 1 to n, each once; the m-of-n threshold over valid signoffs | step 6. Delegated-approver constraints are not exercised (no delegation evidence) |
| 7 | the relying party's clock within every context's window | step 7 |
| 8 | every context's audience is the configured one | step 8 |
| 9 | *new*: when the relying party requires current status (`require_current_status`), the status must be held, not marked unavailable, and fresh (`checked_at` <= now <= `expires_at`), else INDETERMINATE; a signoff key listed in `revoked_key_ids` is REFUSE (a revocation is read as one even from a stale list; no case of the vector distinguishes it) | step 9; REFUSE lists "revocation" |
| 10 | *new*: when the relying party requires a binding (`require_authorization_binding`) and every context omits it, REFUSE; *new*: a binding without a non-empty `profile` is malformed, REFUSE (section 6.1); for this repository's profile, the native verification above (*new*: a DPS key state `unavailable` is INDETERMINATE, and the identity rule); for another profile, the relying party's derived object, when it holds one (`expected_authorization_binding`), compared in JCS, else INDETERMINATE (no native verifier here) | step 10, section 6.1. Requiring a binding is the relying party's selected evidence profile ("SATISFIED: the bundle satisfies the selected evidence profile"), and section 6.3's "generic UI confirmation that is not bound to the native grant or transaction" is a required refusal; the absence of a required binding is a definite mismatch, hence REFUSE |
| 11 | *new*: the current policy evaluation must be held, not marked unavailable, and fresh, else INDETERMINATE; a decision other than PERMIT is REFUSE; then every context's `policy_hash` equals the current one, else REFUSE | step 11, section 4 (`policy_hash` X does not satisfy a requirement under Y), section 13.3 |

For the vector cases, the relying party's inputs are those each case gives (`pinned_of_case()`): `expected_action`,
`expected_authorization_instance`, `audience`, `now`, `current_policy`, `expected_approvers`, `approver_keys`,
`accepted_key_classes`, `require_authorization_binding`, `require_current_status`, `current_status`, and
`expected_authorization_binding`, which stands for the object a native verifier would derive (the native source is
outside the vector, so the lossless mapping of step 10 is taken as given for those profiles).

## Reason names: this verifier's and the vector's

The verifier keeps its own reason names (the published failing cases use them). For a vector run, each is reported
under the vector's name where the reading of the text supports it; a reason with no counterpart keeps its own name.

| This verifier | The vector's name | Step |
|---|---|---|
| `bundle_malformed` | `bundle_malformed` | 1 |
| `action_mismatch` | `action_mismatch` | 2 |
| `context_policy_hash_not_shared`, `context_audience_not_shared`, `authorization_binding_mixed_or_unequal` | `contexts_do_not_share_one_policy_audience_and_binding` | 3 |
| `context_authorization_instance_not_shared`, `authorization_instance_mismatch` | `authorization_instance_mismatch` | 3, 4 |
| `signoffs_fewer_than_m_or_more_than_n`, `signoff_covers_no_selected_context`, `signoff_covers_an_already_covered_context` | `signoff_context_coverage_failed` | 5 |
| `signoff_signature_invalid` | `signoff_signature_invalid` | 5 |
| `approver_set_not_the_selected_one` | `approver_selection_mismatch` | 6 |
| `initiator_is_an_approver`, `approvers_not_pairwise_distinct`, `threshold_not_met` | `separation_of_duties_or_quorum_failed` | 6 |
| `outside_validity_window` | `context_outside_validity_window` | 7 |
| `audience_mismatch` | `context_audience_mismatch` | 8 |
| `current_status_unavailable_or_stale` | `current_status_unavailable_or_stale` | 9 |
| `approver_key_revoked` | `approver_key_revoked` | 9 |
| `authorization_binding_required` | `authorization_binding_required` | 10 |
| `authorization_binding_malformed` | `authorization_binding_malformed` | 10 |
| `authorization_binding_unequal` | `authorization_binding_mismatch` | 10 |
| `native_binding_unavailable`, `dps_trust_inputs_unavailable`, `binding_source_state_unavailable` | `native_authorization_binding_unavailable` | 10 |
| `current_policy_unavailable_or_stale` | `current_policy_unavailable_or_stale` | 11 |
| no counterpart in the vector: the schema controls (`action_missing:<m>`, `context_<i>_missing:<m>`, ...), `action_hash_mismatch`, `context_action_hash_mismatch`, `context_initiator_not_the_actions`, `context_policy_id_not_the_actions`, `nonce_reused`, `authorization_instance_unavailable`, `approver_key_not_trusted`, `signoff_approver_not_the_contexts`, `approver_key_outside_its_validity`, `signoff_time_outside_the_context_window`, `approver_key_compromised_before_signing`, `approver_key_compromised_signing_order_unestablished`, `context_approver_index_not_1_to_n`, `binding_source_does_not_verify`, `mapping_not_lossless_to_the_action`, `action_policy_id_not_the_pinned_one`, `action_requested_at_not_the_proposal_time`, `dps_approver_is_the_ep_initiator`, `identity_link_unavailable`, `current_policy_refuses`, `policy_digest_mismatch` | (kept) | |

## Against the author's candidate vector of 5 November 2026

Run against the author's local candidate of 5 November 2026, not public, not pinned here (sent by Iman Schrock; its
file, SHA-256 `5b7d1f02c0d430ec6bbe9d396eeb4ddf71f92b2e609ba4fd5bdd83ce5d311d62`, is not in this repository), with
`build.py --vector <file>`: **27 of 27 verdicts agree** (19 of 27 before the additions above). At the level of
reasons, read under the vector's names: **24 of 27 equal**, and in all 27 the vector's reasons are among ours. The
three that are not equal report, besides the vector's reason, other definite failures the text also names:

- `duplicate-human-does-not-satisfy-quorum` (vector: `separation_of_duties_or_quorum_failed`): its two contexts are
  byte-identical (same approver, index 1 twice, same nonce) and both signoffs cover the one context. Ours add
  `nonce_reused` (step 3: "each context nonce remains distinct"), `signoff_context_coverage_failed` (step 5: "each
  signoff to cover one distinct selected context"), `approver_selection_mismatch` (step 6: the context approver set
  is {controller}, the selected one {controller, treasurer}) and `context_approver_index_not_1_to_n` (section 6).
- `mismatched-policy-between-contexts` (vector: `contexts_do_not_share_one_policy_audience_and_binding`): ours add
  `policy_digest_mismatch` (step 11: the current policy's digest must equal "the digest signed by every context"; the
  second context signed another).
- `invalid-approver-signature` (vector: `signoff_signature_invalid`): ours add `separation_of_duties_or_quorum_failed`
  (one valid signoff of the two required: section 6, "fewer than m valid signoffs ... is a refusal").

Nothing was forced to agree: no reason is suppressed to match a case. Whether a verifier reports every failure or the
first is not fixed by the text; the vector's expected reasons read as a minimum here.

The same run over the pinned public vector (`vectors/authorization-bundle.v1.json`, `00fa00a7`, 27 cases), as
`run.sh` does: 26 of its cases are refused by the schema controls for the four members of section 3 their actions lack,
and `closed-bundle-rejects-unknown-member` by `bundle_malformed`. 20 verdicts coincide (the 20 cases that expect
REFUSE, 19 of them for another reason than the case's), 7 differ (3 expect SATISFIED, 4 INDETERMINATE), and 1 of 27 has
equal reasons. This is the expected disagreement stated above for `valid-non-oauth-native-binding`, over every case;
`run.sh` reports this run and does not check it.

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

| N20 | the DPS trust policy states the person's key revoked (superseded) at 09:44, before the approval signed at 09:45 and the EP signoffs at 09:55 | EP step 10: the source does not verify (and both DPS checks) |
| N21 | the EP action is initiated as the EP identity linked to the person who approved under the DPS | EP step 10: the profile's identity rule, `dps_approver_is_the_ep_initiator` |
| N22 | the relying party's EP policy (same `policy_id`) changed after the DPS approval and the signoffs | EP step 11: `policy_digest_mismatch` |
| N23 | the first EP approver's key marked compromised at the relying party's clock, after the signoff's claimed `signed_at` | EP step 5: INDETERMINATE, `approver_key_compromised_signing_order_unestablished`, not REFUSE `threshold_not_met` |

N12 to N16 are the five omissions Iman Schrock found accepted by the verifier as it was on 3 November 2026; the
verifier then returned SATISFIED on each, which is why the schema controls exist.

N20 to N22 (5 November 2026) are failures at the junction of the two systems, each the valid pair changed in one
place:

- **N20** changes only the verifier's DPS trust policy (`trust-policy.json`): no signed byte changes. Every EP step
  but the source of step 10 passes (run without the DPS inputs, the bundle is INDETERMINATE only for those inputs);
  the person's approval fails its DPS key state, so A1, A2 and the binding's source fail. The time matters, and only
  this one is a published case: a key **superseded** after the approval (09:50) leaves the approval standing on its
  stated time, and the pair verifies; a key revoked as **compromised**, before or after the approval, with no
  independent timestamp over the approval, is a key state the Standard reports `unavailable`, which step 10 now reads
  as INDETERMINATE (`binding_source_state_unavailable`), not REFUSE (both checked by hand on 5 November 2026, not
  published as cases).
- **N21** changes only the specification's `initiator` (to `ep:entity:treasury-controller-1`); the A1 bytes, the
  binding, the action and the signoffs all follow from it consistently. The DPS checks verify, and EP alone is
  satisfied (the initiator is not an EP approver; without the DPS inputs, INDETERMINATE only for them); the identity
  rule of the profile, through the pinned link, refuses. The basis is this repository's profile, not the draft.
- **N22** changes only the relying party's current EP policy (`ep-pinned-inputs.json`, `current_policy`): same
  `policy_id`, another rule, so another digest. This is EP's own step 11, not a rule of the profile: what the junction
  shows is that A2's recheck stage still reads `authorised`, as its issuer wrote it, while the relying party's
  re-evaluation at the same point refuses; a DPS record of a recheck does not replace the relying party's own.

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
