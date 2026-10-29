# The approval record of Seal ACTION-v1 Section 8.3, as a DPS signed outcome — 2026-10-29

draft-chueayen-attestation-receipts-05, Section 8, states what an approval needs so that an action record can be read
as evidence that a person approved a specific action, and Section 8.3 says the document does not yet define the signed
approval record or the member of a future action record that would carry its digest. This directory is that example,
built with what already exists: the action binding 0.3.0 and signatures 0.2.0 extensions of the Decision Provenance
Standard, unchanged.

`build.py` makes every artefact from two test keys and verifies them three ways, then checks the bindings of §8.2.
Output in `out/`; the run's verdicts in `out/summary.json`.

## The artefacts

| File | What it is |
|---|---|
| `out/arguments.canonical.json` | the proposed call's argument object, canonicalised as ACTION-v1 §6 says; its SHA-256 is `args_hash` |
| `out/review-view.txt` | what the approver was shown: rendered by the enforcement point from the canonical arguments, carrying `args_hash` and the policy version (§8.2, "Rendering from the canonical action"); its digest is signed |
| `out/specification.bytes.json` | the DPS action specification: operation = tool, `parameters.org_id`, `parameters.args_hash`, the arguments, the policy version. Its digest is what the review showed and what the approval signed |
| `out/decision-record.json` | the Core v5.0 decision record (options, rationale, accountable owner, affirmation) |
| `out/action-binding-attachment.json` | proposal → review (shown digest, view digest) → outcome `approved` by a named person, `request_limit` 1 → request → recheck → attempt (the Seal action id) → result |
| `out/signatures-attachment.json` | **the approval record**: the person's Ed25519 `person_approval` over decision id, stage, outcome, shown digest, view digest, approved digest, time |
| `out/approval.canonical.json` | the RFC 8785 bytes of that assertion as issued; `sha256` of them is the reference an action record would carry |
| `out/trust-policy.json` | the verifier's policy that designates the approver's key in role `person` (§8.2, "Designated approver"); its digest is carried too |
| `out/action-record.json` | the Seal ACTION-v1 record, `ALLOWED`, issued by the enforcement point after the approval, valid under the ACTION-v1 text |
| `out/composition.json` | the sidecar: what a future ACTION-v1 member would carry (`approval_record.sha256`, `designating_policy.sha256`), kept outside the v1 record because v1 rejects unknown members |

## What verifies (`out/summary.json`)

- `seal_action_record`: **valid** under the ACTION-v1 verifier written from the Seal text (`../aqta_verify_independent.py`),
  pinned to the enforcement point's test key.
- `dps_action_binding`: every dimension of the DPS reference check **verified** (specification digests and statements,
  record statements, action binding, stage order, authorisation recheck, observed results, rationale provenance).
- `dps_person_approval`: `signature`, `subject`, `key_state`, `identity` all **verified** against the trust policy.
- The ten cross-checks of §8.2, all true: exact values (`args_hash` recomputed from the canonical arguments equals the
  record's and the specification's; tool and org bound; the approval signed the digest of those bytes); single use
  (`request_limit` 1, one request rests on the approval); the approval precedes the record and the key has a validity
  window; the policy version named; the approver is neither the agent nor the requesting service; the approver's key is
  designated by the policy, whose digest is carried; the view was rendered from the canonical arguments and its digest
  is signed; the sidecar's digest equals the SHA-256 of the assertion's RFC 8785 bytes as issued.

## What it shows, and what it does not

It shows that the approval record §8.3 asks for exists today in a form with a published verifier and test suite, that
it binds the four values §8.2 names plus the arguments and what the person saw, and that a verifier holding the action
record, the attachment, the signatures attachment and its own policy can confirm all of it offline. It does not show
that the person read the view, that the enforcement point rendered it faithfully, or that the key holder is the named
person: the DPS reports say so, dimension by dimension, and this example does not claim more.

One member is missing on the DPS side for §8.2 as written: the digest of the designating policy inside the signed
assertion. Here it travels in the sidecar. Adding it to `person_approval` would be a change to signatures 0.2.0, to be
proposed to the Standard's Steward if the Seal side wants it signed rather than carried beside.

## Reproduce

```sh
# needs cryptography, jsonschema, asn1crypto (the DPS runners' pins) and a checkout of the Standard
DPS_STANDARD=/path/to/decision-provenance-standard/standard python3 build.py
```
The CI (`../../run.sh`) clones the Standard at the commit pinned in `DPS_STANDARD_COMMIT` and runs this.
