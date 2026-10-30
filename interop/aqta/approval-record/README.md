# The approval record of Seal ACTION-v1 Section 8.3, as a DPS signed outcome — 2026-10-29

draft-chueayen-attestation-receipts-05, Section 8, states what an approval needs so that an action record can be read
as evidence that a person approved a specific action, and Section 8.3 says the document does not yet define the signed
approval record or the member of a future action record that would carry its digest. This directory is that example,
built with what already exists: the action binding 0.3.0 and signatures 0.2.0 extensions of the Decision Provenance
Standard, unchanged, at the repository's main branch commit `007f8c9`.

`build.py` makes every artefact from two test keys and verifies them three ways, then checks the bindings of §8.2.
Output in `out/`; the run's verdicts in `out/summary.json`.

**Revised on 29 October 2026, after the Standard's Steward answered issue 93.** The designating policy is the issuer's
document that names who may approve this operation for this target, not the verifier's trust policy (the first version
of this example used the trust policy, which was wrong). Nothing in the Standard changes: the policy is signed
*through the specification*, whose `policy_version` is the SHA-256 of the policy's bytes, and a short validity is the
policy's age limit and the specification's `valid_until`, checked at the recheck on the enforcement point's clock.

## The artefacts

| File | What it is |
|---|---|
| `out/arguments.canonical.json` | the proposed call's argument object, canonicalised as ACTION-v1 §6 says; its SHA-256 is `args_hash` |
| `out/policy.json` | **the designating policy**: the issuer's production change policy, naming the approver, independence, single use, an age limit of 900 s and the recheck rule; its SHA-256 is the specification's `policy_version` |
| `out/review-view.txt` | what the approver was shown: rendered by the enforcement point from the canonical arguments, carrying `args_hash`, the policy's identifier and digest, and `valid_until` (§8.2, "Rendering from the canonical action"); its digest is signed |
| `out/specification.bytes.json` | the DPS action specification: operation = tool, `parameters.org_id`, `parameters.args_hash`, the arguments, `policy_version` = the policy's digest, `valid_until`. Its digest is what the review showed and what the approval signed |
| `out/decision-record.json` | the decision record (Core v1.3 rev. 11, reference files 5.2.0) (options, rationale, accountable owner, affirmation) |
| `out/action-binding-attachment.json` | proposal → review (shown digest, view digest) → outcome `approved` by a named person, `request_limit` 1, `authority_ref` naming the same policy → request → recheck against the policy → attempt (the Seal action id) → result |
| `out/signatures-attachment.json` | **the approval record**: the person's Ed25519 `person_approval` over decision id, stage, outcome, shown digest, view digest, approved digest, time |
| `out/approval.canonical.json` | the RFC 8785 bytes of that assertion as issued; `sha256` of them is the reference an action record would carry |
| `out/trust-policy.json` | the verifier's own trust policy: it maps the approver's key to the person, in role `person`; it designates nobody |
| `out/action-record.json` | the Seal ACTION-v1 record, `ALLOWED`, issued by the enforcement point after the approval, valid under the ACTION-v1 text |
| `out/composition.json` | the sidecar: what a future ACTION-v1 member would carry (`approval_record.sha256`) and, for the reader, which policy the specification names; kept outside the v1 record because v1 rejects unknown members. Nothing in it is signed beyond what the approval already signs |

## What verifies (`out/summary.json`)

- `seal_action_record`: **valid** under the ACTION-v1 verifier written from the Seal text (`../aqta_verify_independent.py`),
  pinned to the enforcement point's test key.
- `dps_action_binding`: every dimension of the DPS reference check **verified** (specification digests and statements,
  record statements, action binding, stage order, authorisation recheck, observed results, rationale provenance).
- `dps_person_approval`: `signature`, `subject`, `key_state`, `identity` all **verified** against the trust policy.
- `policy_checks`, what a verifier holding the issuer's policy adds, each on its own: the policy held is the one the
  specification names (`policy_digest`); the attempt is within the policy's age limit (`approval_age`) and the
  specification's `valid_until`; the policy names the approver (`designated_approver`). All **verified**.
- The ten cross-checks of §8.2, all true: exact values; single use; expiry (age limit and `valid_until`, both signed);
  policy version (the digest of the policy held); independence; designated approver (named by the signed policy, the
  key mapped to that person by the verifier's trust policy); rendering from the canonical action; the reference digest.

## The failing cases (`negatives.py`)

Each is the valid example changed in one place, run through the same verifications; `out/negatives/summary.json`
records where it fails and what the check says. The Seal action record itself stays valid in every case: it attests
what the enforcement point recorded, and the failure is found on the approval side, which is the point. N1–N3b were
asked for by the Seal author; N4–N7b are the cases the Standard's Steward listed on issue 93.

| Case | Change | Where it is caught | What the check says |
|---|---|---|---|
| N1 altered value | the request and the attempt carry pull_number 4522; the person approved 4521 | DPS action binding, `action_binding`; the composition's args_hash binding | "q1: the requested specification differs from the one approved"; the executed specification is reported `unbound` |
| N2 reused single-use approval | a second request, recheck, attempt and result rest on the same approval (`request_limit` 1) | DPS action binding, `action_binding` | "q2: o1 covers 1 request(s), already used by q1" |
| N3 approver outside the trust policy | the outcome is signed by a key the verifier's trust policy does not list | DPS signatures, `signature` (then `key_state` and `identity` not checked) | the assertion is not verified |
| N3b key in the wrong role | the same key, listed in the trust policy but in role `organisation` | DPS signatures, `signature` and `identity` | an organisation's key cannot give a person's approval |
| N4 policy digest mismatch | the verifier holds a policy edited after the approval (a day instead of 900 s) | `policy_digest` | the policy held is not the one the specification names |
| N5 policy not held | the verifier holds no copy of the policy | `policy_digest`, `approval_age`, `designated_approver` | **not checked**, never verified; `valid_until`, carried in the specification, is still checked |
| N6 attempt after the policy's limit | the attempt is 28 minutes after the approval; the executor's recheck recorded "authorised" anyway | `approval_age`, `valid_until` | attempt 1680 s after the approval, the policy allows 900; attempt after `valid_until` |
| N7 policy relabelled in the specification | the issuer rewrites the attachment so the specification names another policy | DPS signatures, `subject` | the person's signature covers the original digests |
| N7b `authority_ref` relabelled (documented, not a failure) | the outcome's `authority_ref` changed after signing | — | everything still verifies, by design: `authority_ref` is the issuer's statement, outside the person's signature; only `policy_version` is under it |

## What it shows, and what it does not

It shows that the approval record §8.3 asks for exists today in a form with a published verifier and test suite, that
it binds the values §8.2 names, the arguments, what the person saw, the designating policy and a deadline, all under one
signature over one specification digest, and that a verifier holding the action record, the attachment, the signatures
attachment, the issuer's policy and its own trust policy can confirm all of it offline. It does not show that the person
read the view, that the enforcement point rendered it faithfully, that the executor really applied the policy at the
recheck (N6 is exactly that), or that the key holder is the named person beyond what the trust policy states: the reports
say so, dimension by dimension, and this example does not claim more.

## Reproduce

```sh
# needs cryptography, jsonschema, asn1crypto (the DPS runners' pins) and a checkout of the Standard at 007f8c9
DPS_STANDARD=/path/to/decision-provenance-standard/standard python3 build.py
DPS_STANDARD=/path/to/decision-provenance-standard/standard python3 negatives.py
```
The CI (`../../run.sh`) clones the Standard at the commit pinned in `DPS_STANDARD_COMMIT` and runs both.
