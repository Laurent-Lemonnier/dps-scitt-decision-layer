# Case 18b: the same chain with a real approver

Case 18 (`../one-chain/`) runs one refund of 120.00 EUR through the four drafts of the IETF 127 SCITT adoption discussion,
with a finance controller whose approval is an Ed25519 test signature from a fixed seed. This subcase is the same chain with
one thing real: the person. On 6 November 2026 Laurent Lemonnier signed, with his own passkey (WebAuthn, ES256, iPhone,
Face ID) on https://sign.pria.fr, the DPS `person_approval` of this chain: decision DR-2026-1104, stage o1, outcome
approved, the SHA-256 of the specification bytes in `signed/action-specification.json` (`103ac55a…`) and of the view in
`signed/review-view.txt` (`d0a1daf0…`), `signed_at` 2026-11-06T19:05:00Z. The assertion the authenticator returned
(signature, authenticatorData, clientDataJSON), the credential id and the passkey's public key are pinned in `signed/`
(`SHA256SUMS`); the code holds no key that could make another. Nothing of case 18's code or outputs is changed; this
directory imports `../one-chain/build.py` and sets the person, the signature and the times.

An assistant wrote the code and the first draft of this README; Laurent Lemonnier read both, and signed.

## What is real, what is synthetic

Real: one person, one passkey, one signature. The Standard's reference check (`extensions/signatures/tests/run_checks.py`,
pinned commit) verifies it as it verifies any WebAuthn-ES256 person signature, under the trust policy this case pins
(`out/positive/trust-policy.json`: `laurent-passkey-1`, role person, holder `laurent-lemonnier`, the 65-byte P-256 point,
validity from the enrolment of 2026-11-04T23:06:01Z, relying party `sign.pria.fr`, origin `https://sign.pria.fr`):

| dimension | result | what was read |
|---|---|---|
| signature | verified | the challenge in clientDataJSON is the SHA-256 of the signed bytes the check rebuilt from the attachment's fields (profile, version, assertion, key_ref, decision, stage, outcome, the three digests, signed_at); type `webauthn.get`; origin `https://sign.pria.fr`, allowed by the policy; `crossOrigin` false, no `topOrigin`; rpIdHash = SHA-256(`sign.pria.fr`); ECDSA P-256 over authenticatorData ‖ SHA-256(clientDataJSON) under the pinned point |
| authenticator facts | UP true, UV true | flags byte 0x1d (UP, UV, BE, BS); signature counter 0 (as iPhone passkeys report it) |
| subject | verified | against A1: o1 is an outcome stage, `approved`; its review v1 was shown the same specification digest and the same view digest; o1's `approved_spec_digest` is the signed one |
| key state | verified | `signed_at` 19:05:00Z inside [not_before, not_after], basis: the stated time (no independent timestamp yet, see Anchoring) |
| identity | verified | the actor o1 names (`laurent-lemonnier`) is the holder the policy binds the key to; source `urn:pria:sign:enrolment:laurent-passkey-1` |

The same check, read through case 17's `dps_checks`, is what `person_approval: verified` means on A1 and A2 in `summary.json`;
`real_approval` there is the full reading (facts above, findings, the digest of the signed bytes `56cd9dea…`, the digest of
the signature value `9cdba62a…`). `pinned_inputs` records that the specification bytes in A1, the view digest in v1, the
`person_approval` in the signatures attachment and o1's moment are exactly the pinned ones.

Synthetic, as in case 18 and said so in every file: the Harness and its receipts, the agent, the payment and its API, the DPS
issuer's seals on A1 and A2 (Ed25519 test key `example-corp-seal-1`), the decision record's charter and employer, the
auditor and the verdict's key, the merchant's dispute desk, its ledger and its rail, every moment other than the signature's
(laid around it the same evening: proposal and review at 19:04, the Harness's confirm at 19:04:02.5, the allow outcome and the
attempt at 19:07:08, A2 sealed 19:08, the verdict 20:00, the packet 21:00, all before the specification's `valid_until`
2026-11-07T12:00:00Z). The Harness's principal (Thaha key 10) is the pepper hash of a synthetic canonical identifier
(`user:laurent-lemonnier@example.com`). The refunds policy is case 18's bytes unchanged (its digest is inside the signed
specification); it names the role, finance controller, that the person acted in for this case. Two details worth knowing:
the server received the assertion at 19:06:54Z while `signed_at` reads 19:05:00Z, the moment the request was prepared and
the bytes fixed (sign.py writes `signed_at` before the ceremony; the stages that follow the approval are placed after
19:06:54Z); and `signed_at` is the person's statement, bounded by nothing independent until a timestamp covers the signature.

## The chain, as case 18 ran it

Positive (`out/positive/`): Thaha's verifier CHECKS_PERFORMED over the Bundle; A1 verified on its six applicable dimensions
and A2 on all eight, both seals verified, the person's approval verified (above), trust policy verified, route 1 bound; the
verdict released (`state released; step 1 PASS; step 2 PASS; step 3 PASS`, rule `executed-as-approved:v1`, re-run equal to the
stated result); the packet VERIFIED, `scope_conformance in_scope`, settlement 120.00 EUR; the twelve joins K1-K12 true and
case 17's J1-J7 true.

Stated negative (`out/stated-negative/`, 150.00 EUR executed for 120.00 approved): the real approval verifies here too (it is
the approval of 120.00); Thaha's J1 false, the Standard's `action_binding` failed on A2, the verdict stating `not_as_approved`
released, the packet `BREACH:amount_minor` VERIFIED with 150.00 moved, twelve joins true.

The joins are case 18's, read on these bytes: K2 reads the person's `signed_at` and o1 at the same moment (19:05:00Z), after
the confirm receipt and before the allow outcome; K10 reads one person in every link; K11 the order of moments. What they do
not read: the signature. The joins and the verdict's rule read the Standard's dimensions and the digests; only the Standard's
signatures check reads the assertion. Five of the failing cases (R1-R4, R6) are seen by it alone.

## The failing cases (`negatives.py`, 8/8 where expected)

Each is the valid chain changed in one place. The first six touch the one real thing; R5 moves the chain around it.

| case | changed | caught by |
|---|---|---|
| R1 assertion presented over other bytes | the chain rebuilt around a specification of 150.00 EUR (A1 names it, the review was shown it, the run executed it: every other check passes) and the real assertion attached to the `person_approval` whose digests are its | the Standard only: `the challenge is not the SHA-256 of the signed bytes`; the person signed the 120.00 approval. Receipts, verdict and packet read the approval event by digest and see nothing |
| R2 client data from another origin | clientDataJSON `origin` → `https://sign.example.org` | the Standard: `the origin … is not one the policy allows for laurent-passkey-1`; and the signature no longer verifies (the client data hash is signed) |
| R3 UV flag cleared | authenticatorData flags 0x1d → 0x19 | the Standard: `user_verified false` reported as a fact, and the signature fails (the flags are signed). The check itself requires UP, not UV; here the forgery is seen because the bytes are signed |
| R4 another credential under the same key_ref | the policy binds `laurent-passkey-1` to another P-256 point (a key of nobody, fixed seed) | the Standard: the signature does not verify under that key; identity not checked |
| R5 approval after the allow, on this timeline | the signature stays at 19:05:00Z (the one moment that cannot move); the allow outcome, request, recheck and attempt placed at 19:04:55-19:04:59 | J2, K2; `stage_order` failed on A2; the verdict refused at step 3 (K5, K7, K12 follow). The passkey signature verifies: it says when the person signed, not when the call proceeded; Thaha's receipts alone cannot see it |
| R6 case 18's test signature under this policy | the finance controller's Ed25519 signature (`finance-controller-1-key-1`) in place of the assertion | the Standard: `not a key in the trust policy`; the policy binds one person's key |
| R7 confirm without approval | no person signature, o1 still claimed (case 18's N4) | the Standard (`person_approval` absent), J2, K2; the packet verifies |
| R8 signed_at moved by one second | the attachment says 19:05:01Z over bytes signed as 19:05:00Z | the Standard (challenge mismatch); J2, K2: o1 is no longer the signature's moment |

Each case's directory holds every document, `what.txt`, `result.json` and `real-approval.json` (the Standard's full reading of
the person's signature for that case, with the findings quoted above).

## Anchoring (prepared, not submitted)

`anchoring/subjects/` holds the five subjects to timestamp for this chain, in the shape used for case 18: the raw DER
signature value of the passkey assertion (`approval-signature.bin`, 72 bytes, SHA-256 `9cdba62a…`), A1, A2, the verdict record
and the dispute packet of `out/positive/`, with `SHA256SUMS`; `anchoring/stamp.sh` submits them with the OpenTimestamps client
and is not run by `build.py`, `run.sh` or CI. The five OpenTimestamps proofs submitted on 2026-11-06T17:34:21Z
(`/root/claude-ops/ietf/horodatage-20261106-case18/`, to be added to case 18 once a block includes them) are over **case
18's** bytes, the finance controller's test signature and that chain's attachments: they cover nothing here. The proofs for
18b are to be submitted when Laurent Lemonnier decides; once upgraded, a proof over `approval-signature.bin` gives the key
state check an upper bound from a clock none of the parties controls (anchoring 0.2.0, `time_basis independent_timestamp`),
where today it rests on the stated time.

## For the pre-read

One sentence (item 14 of `../one-chain/PRE-READ-CHAIN-NOTES.md`, if wanted): The same chain was run with a real approver, Laurent
Lemonnier signing the exact approval bytes with his own passkey on sign.pria.fr; the Standard's check verified the signature,
user presence and verification, origin, relying party, key state and identity under a pinned trust policy, the other three
verifiers and the twelve joins held as before, and eight failing cases (the assertion over other bytes, another origin, UV
cleared, another credential, the approval after the allow, among them) failed where expected, five of them seen by the
Standard's check alone.

## Running

```
DPS_STANDARD=/path/to/decision-provenance-standard/standard python3 build.py      # exit 0 when all_verified
DPS_STANDARD=... python3 negatives.py                                            # exit 0 when 8/8 where expected
```

Python 3.12, `cryptography`, `cbor2`, `jsonschema`, `referencing`. Both scripts are deterministic: two runs write the same
bytes (344 files, the two run logs included). `signed/` is the input and is never written; `out/positive/`, `out/stated-negative/` and
`out/negatives/<case>/` hold every document (as in case 18, plus `passkey.json` and the trust policy with the passkey
entry); `out/summary.json` adds `real_approval`, `pinned_inputs` and the anchoring subjects' digests.
