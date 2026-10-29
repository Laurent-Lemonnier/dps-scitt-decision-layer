# Case 08: a NOA Mandate receipt bound to the decision it executed

Built on 2026-10-29 from what Tora Toraman (NOA Mandate, draft-noa-scitt-ai-agent-receipt-01) wrote the same day: a
receipt is a closed object, so a decision-layer reference cannot go inside it; one way to carry it is a separate SCITT
Signed Statement with typed references to the receipt and to the decision record, under the Transparency Service's
registration policy, the receipt and its envelope bytes unchanged. The receipt side is his profile's published
conformance vector at commit `6642fb2` (`valid-chain.json`, receipt seq 2 of three; `keyring.json`, a test key).

## The declaration for the receipt type (the consuming profile's, as CPB asks)

- type token: `noa.receipt/0.1`, the `spec` identifier the receipts carry, confirmed as the token by the profile's
  author on 29 October 2026; the wire format and hashing rule are documented as frozen at `6642fb2`;
- digest context: the value the profile defines, `"sha256:"` followed by the lowercase hex of SHA-256 over
  UTF8(JCS(receipt with only `chain.hash` and `sig.value` removed)); for a valid receipt it equals `chain.hash`;
- representation: the prefixed form, kept as the profile writes it, stated in the declaration rather than converted;
- what it binds: the canonical receipt content with `chain.hash` and `sig.value` omitted. The reference does not
  itself authenticate the receipt's signature, and it does not bind the serialized file, a COSE Signed Statement
  carrying the receipt, or its Transparency Receipt, which are different objects with different digests.

## What was built and what verifies (`result.json`)

- `receipt.json`: the receipt held (seq 2). All three receipts of the vector recompute their `chain.hash` under the
  construction above, and each `prevHash` links to the previous `chain.hash`.
- `signed-statement-cpb-refs.cose`: an RFC 9943 Signed Statement (Ed25519 test key, content type `application/json`
  over `binding-payload.json`) whose protected header carries three typed references in `cpb-refs` (CPB -06 §9.3;
  label TBD1, private-use -65537 in this fixture), marked critical: the receipt (`acted_as`), the decision record by
  its seal (`ran_under`), the action-binding attachment by the SHA-256 of its bytes (`acted_on`). Signature valid;
  all three references **Verified** under their declared contexts.
- Negatives: the receipt's digest altered in the reference → **Failed**; a reference naming the receipt by the digest
  of its signed file instead of the profile's value → **Failed** (a different object, as the author says); the
  receipt's bytes changed after the reference was made (a parameter hash) → the reference **Fails**, and the changed
  receipt no longer recomputes its own `chain.hash` either.

## The receipt's own signature

Checked separately from the references, as the profile's own check. `sig.value` is Ed25519 (RFC 8032, pure) over a
53-byte message: UTF8(`"NOA-Receipt-v0.1-sig:"`), the 21-byte domain tag with its colon, followed by the raw 32-byte
SHA-256 of UTF8(JCS(receipt without `chain.hash` and `sig.value`)), the same digest whose lowercase hex follows
`sha256:` in `chain.hash`, not that hex text. Source: `docs/receipt-spec.md`, section "Hashing rule (frozen)", and
`src/signing.ts` (`signingMessage`), both at `6642fb2`; the raw-versus-hex encoding is made explicit in
NordenSoft/noa-mandate-core#75. With the test key of `keyring.json`, all three receipts of `valid-chain.json` verify;
the tag followed by the hex digest, and the bare digest, do not; the receipt changed after the reference was made does
not (`result.json`, `receipt_signature`). Thanks to Tora Toraman for stating the construction.

## What it does not do

A reference that resolves shows only that the cited bytes have the digest it carries; the signature above is a
separate result and is reported as one. The statement is not registered at a Transparency Service: the registration
policy is the operator's.

Run: `PYTHONPATH=<capsule library site> venv-scitt/bin/python noa_case.py` from `interop/`.
