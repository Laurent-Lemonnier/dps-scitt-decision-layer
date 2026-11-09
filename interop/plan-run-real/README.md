# Case 13b: the plan, approved by a real person

Case 13 (`../plan-run/`) runs one three-step onboarding plan, approved as a whole by an office manager whose approval is an
Ed25519 test signature from a fixed seed, and carried by three Agent Action Capsules (library 0.16.0) under a run manifest.
This subcase is the same run with one thing real: the person. Steven Mih asked for it: that the three capsules his library
verifies sit under an approval by a real person. On 7 November 2026 Laurent Lemonnier signed, with his own passkey (WebAuthn,
ES256, iPhone, Face ID) on https://sign.pria.fr, the DPS `person_approval` of this plan: decision DR-2026-1106, stage o0,
outcome approved, the SHA-256 of the specification bytes in `signed/action-specification.json` (`f6027c81…`) and of the view
in `signed/review-view.txt` (`11314ec5…`), `signed_at` 2026-11-07T09:49:59Z. The assertion the authenticator returned (signature,
authenticatorData, clientDataJSON), the credential id and the passkey's public key are pinned in `signed/` (`SHA256SUMS`);
the code holds no key that could make another. Nothing of case 13's code or outputs is changed; this directory imports
`../plan-run/build.py` for every builder (plan hash, references, resolution, view, context chain, capsule shape, joins,
checks, writer) and reproduces its `assemble` with the person, the approval's moment and the signature taken from `signed/`.
`build.py` checks, on every run, that with case 13's person and case 13's clock this `assemble` writes case 13's documents
byte for byte (`pinned_inputs.assemble_reproduces_case_13`).

An assistant wrote the code and the first draft of this README; Laurent Lemonnier read both, and signed.

## What is real, what is synthetic

Real: one person, one passkey, one signature. The Standard's reference check (`extensions/signatures/tests/run_checks.py`,
pinned commit) verifies it as it verifies any WebAuthn-ES256 person signature, under the trust policy this case pins
(`out/trust-policy.json`: `laurent-passkey-1`, role person, holder `laurent-lemonnier`, the 65-byte P-256 point, validity
from the enrolment of 2026-11-04T23:06:01Z, relying party `sign.pria.fr`, origin `https://sign.pria.fr`):

| dimension | result | what was read |
|---|---|---|
| signature | verified | the challenge in clientDataJSON is the SHA-256 of the signed bytes the check rebuilt from the attachment's fields (profile, version, assertion, key_ref, decision, stage, outcome, the three digests, signed_at); type `webauthn.get`; origin `https://sign.pria.fr`, allowed by the policy; `crossOrigin` false; rpIdHash = SHA-256(`sign.pria.fr`); ECDSA P-256 over authenticatorData ‖ SHA-256(clientDataJSON) under the pinned point |
| authenticator facts | UP true, UV true | flags byte 0x1d; signature counter 0 |
| subject | verified | against A1: o0 is an outcome stage, `approved`; its review v0 was shown the same specification digest and the same view digest; o0's `approved_spec_digest` is the signed one |
| key state | verified | `signed_at` inside [not_before, not_after], basis: the stated time (no anchoring here; see case 18b for an independent time bound) |
| identity | verified | the actor o0 names (`laurent-lemonnier`) is the holder the policy binds the key to; source `urn:pria:sign:enrolment:laurent-passkey-1` |

The same check, read through case 13's `verify`, is what `dps_person_signatures: 1 of 1` means in `summary.json`;
`real_approval` there is the full reading (facts above, findings, the digest of the signed bytes and of the signature value).
`pinned_inputs` records that the specification bytes in A1, the view the review stage names, the `person_approval` in the
signatures attachment and o0's moment are exactly the pinned ones.

Synthetic, as in case 13 and said so in every file: the brokerage, the client, the use case and the brief, the onboarding
assistant, the executor and its three effects (`effect_attestation: runtime_claimed`), the issuer's seal on the attachment
(Ed25519 test key `example-brokerage-issuer-key-1`), the record's charter and employer, every moment other than the
signature's. Those moments are case 13's laid around the signature: case 13 approved at its minute 25 and ran at minute 30;
here minute 25 is `signed_at`, and the proposal (-13 min), the review (-5), the request, recheck and attempt (+5), the three
steps (+5:12, +5:40, +6:05), the result (+6:20), the seal (+7) and the record's closing (+15) keep their distances. Two
details worth knowing: the specification's `valid_until` is 2026-11-09T12:00:00Z where case 13 had 2026-11-07T09:25:00Z (the
one field of the plan changed, fixed before the request so the plan could be signed when the person was free; the plan hash
does not cover it); and `signed_at` is the moment the request was prepared and the bytes fixed (sign.py writes it before the
ceremony; the server received the assertion at 2026-11-07T10:03:33Z), the person's statement, bounded by nothing from outside here.

## The run, as case 13 ran it

`out/`: the eight DPS action-binding dimensions verified, the one specification verified, the plan `shown_to_reviewer` and
requested once, the issuer's seal verified; the person's approval verified (above); the trust policy verified; the three
capsules parse and verify with the library 0.16.0 and every reference resolves against the record held or a context state
recomputed from the manifest held; the ten joins of case 13 true (plan hash, manifest, result, membership, completeness,
order, resolved arguments, disposition, context chain, policy).

The joins and the capsule library do not read the signature: the joins read digests and stages, the library reads capsules.
Only the Standard's signatures check reads the assertion; nine of the failing cases below are seen by it alone.

## The failing cases (`negatives.py`, 24/24 where expected)

Two families. N1 to N14 are case 13's own (`../plan-run/negatives.py`, imported and run unchanged on this run); the real
approval is attached to each and verifies in each but N5, where the plan the person is said to have approved (its
`plan_hash` zeroed) is not the plan he signed: the Standard's check fails there too, beside join 1. R1 to R10 touch the one
real thing or move the run around it.

| case | changed | caught by |
|---|---|---|
| R1 assertion presented over another plan | step 1 creates the CRM record under another legal name; the plan hash follows, A1 names that plan, the review was shown it, the run executed it, capsules and manifest agree (every join true); the real assertion attached to the `person_approval` whose digests are that plan's | the Standard only: `the challenge is not the SHA-256 of the signed bytes`; the person signed the other plan |
| R2 client data from another origin | clientDataJSON `origin` → `https://sign.example.org` | the Standard: `the origin … is not one the policy allows for laurent-passkey-1`; and the signature no longer verifies (the client data hash is signed) |
| R3 UV flag cleared | authenticatorData flags, UV bit cleared | the Standard: the signature fails (the flags are signed) |
| R4 another credential under the same key_ref | the policy binds `laurent-passkey-1` to another P-256 point (a key of nobody, fixed seed) | the Standard: the signature does not verify under that key |
| R5 run before the approval | the signature stays at its moment; request, recheck, attempt, the three steps and the result placed five minutes before it | `stage_order` failed (a request authorised by an outcome that did not yet exist). The passkey signature verifies: it says when the person signed, not when the run proceeded; capsules and joins read no approval time |
| R6 case 13's test signature under this policy | the office manager's Ed25519 signature (`office-manager-1-key-1`) in place of the assertion | the Standard: `not a key in the trust policy`; the policy binds one person's key |
| R7 approval absent | no person signature, o0 still claimed, the run proceeds | the Standard (`person_approval` absent) and the signatures schema (an empty list); the eight dimensions, the seal, the capsules and the joins hold |
| R8 signed_at moved by one second | the attachment says one second later than the bytes signed | the Standard (challenge mismatch) |
| R9 another view shown | the review stage and the approval carry the digest of a view without its plan-hash line, as if the person had been shown it | the Standard (the view digest is among the signed bytes); the subject dimension agrees (A1 and the approval name the same view) |
| R10 assertion moved to another decision | the whole run issued under DR-2026-1107 (record, A1, manifest, capsules agree), the assertion attached to its o0 | the Standard (challenge mismatch); the person approved the plan of DR-2026-1106 |

Each case's directory holds every document, `what.txt`, `result.json` and `real-approval.json` (the Standard's full reading of
the person's signature for that case, with the findings quoted above).

## Running

```
python3 build.py prepare                                                          # writes the two files to sign; prints the sign.py command
DPS_STANDARD=/path/to/decision-provenance-standard/standard python3 build.py      # once signed/ is complete; exit 0 when all_verified
DPS_STANDARD=... python3 negatives.py                                            # exit 0 when 24/24 where expected
```

Python 3.12, `cryptography`, `jsonschema`, `referencing`, `agent-action-capsule==0.16.0`. Both scripts are deterministic:
two runs write the same bytes. `signed/` is the input and is never written by the build (`prepare` writes its two unsigned
members); `out/` holds every document of the run (as in case 13, plus `passkey.json`, `keys.json` and the trust policy with
the passkey entry), `out/negatives/<case>/` the failing cases, `out/summary.json` adds `real_approval` and `pinned_inputs`.
