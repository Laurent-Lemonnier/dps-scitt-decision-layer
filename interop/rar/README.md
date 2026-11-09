# Case 19: the approved plan of case 13b, as OAuth 2.0 Rich Authorization Requests (RFC 9396)

Yaroslav Rosomakho asked on the AUDIT list whether approval could be handled in OAuth, expressed as RAR `authorization_details`
and included in the audit context. This case tries it on a run we already have, and says what it shows. It builds on case 13b
(`../plan-run-real/`): the three-step onboarding plan approved by a real passkey signature (Laurent Lemonnier, 7 November 2026) and
run under an Agent Action Capsule manifest. Nothing of case 13b is changed; this directory reads its `signed/` and `out/`.

An assistant wrote the code and this README. Laurent Lemonnier read them.

**What was read.** RFC 9396 in full from the RFC Editor's text: Sections 1 to 3.2, 5, 6.1, 7, 7.1, 9 to 9.2, 10, 11 to 13 closely;
the remaining sections (the error and IANA registrations) only for what they register. A first version of this case was written
before the RFC was read; the second pass changed the projection (below) and several statements of this README.

## What it does

1. `rar.py` projects the signed action specification onto `authorization_details` (`out/authorization-details.json`): one element
   for the run and one per step, each with `type`, `actions`, `identifier` and type-specific members (`step_index`,
   `parameters_digest`, `plan_hash`, `policy_version`, `valid_until`). The projection is a pure function of the specification:
   whoever has it can recompute the details, and the details carry nothing it does not say.
   - Section 2.2 makes `locations` "typically URIs identifying the location of the RS" and `identifier` "a specific resource
     available at the API". The specification names the resource each step touches and no resource server, so the target goes in
     `identifier` and `locations` is left out rather than invented. (The first version had put the target in `locations`.)
   - Types are ours (`urn:example:rar:*`): Section 2.1 gives the type's meaning to the AS and recommends a collision-resistant
     namespace; Section 5 has an AS refuse unknown fields of a known type, so the type-specific members would have to be part of
     the type's definition.
2. The decision record carries a typed digest reference to the details (`out/rar-reference.json`), not the details. The details
   digested are the ones granted: Sections 7 and 7.1 say the granted details may differ from the requested ones.
3. Five checks. V1: the specification bytes, the signed approval and the run name one digest (`f6027c81…`). V2: the details
   presented are what the specification implies (byte equality of a deterministic projection, not a semantic comparison:
   Section 6.1 says there is no standard way to compare arbitrary details and an AS should not rely on object comparison).
   V3: the reference matches the details and names that specification. V4: every executed step is inside the details and nothing
   ran beyond them (each step has one action and one resource, so membership is the whole test; Section 2.2 makes several
   values the product of the fields). V5: the shape of Section 2 (an array of objects, a string `type`, the common fields' types).
4. Filtered views. Sections 7, 9.1, 9.2 and 13 let an AS give a client or a resource server less than the full details.
   `is_filtered_view` accepts a view whose every element is one of the full set's.

Run: `python3 build.py` (exit 0 when all five pass), `python3 negatives.py` (exit 0 when 12/12 are as expected), both standard
library only; `python3 token_cases.py` (9/9) and `python3 evidence_cases.py` (7/7), both needing `cryptography`. Deterministic.

## Results

The real run passes all five layers. Nine failing cases and three filtered views (`out/negatives.json`); "details alone" is what a
party holding only the details and the run (V4 and V5: no specification, no approval, no reference) would say:

| case | changed | caught by | details alone |
|---|---|---|---|
| N1 | step 2 may also delete messages; reference recomputed | V2 | accepts |
| N2 | a delete step added to the details | V2, V4 | rejects (V4) |
| N3 | the chat step dropped from the details; the run still sent it | V2, V4 | rejects (V4) |
| N4 | the CRM step ran on another target | V4 | rejects |
| N5 | a fourth step ran that no detail describes | V4 | rejects |
| N6 | the record carries another digest | V3 | accepts (it has no reference) |
| N7 | a parameter edited after approval; details and reference follow | V1 | accepts |
| N8 | two elements swapped | V2 | accepts |
| N9 | an element without `type` | V2, V4, V5 | rejects |
| P1 | the CRM server's view: its element and its part of the run | accepted as a subset | |
| N10 | a view that grants more than the full details | not a subset | its coverage check passes |
| N11 | a view whose parameters digest is not the approved one | not a subset | its coverage check passes |

## The same details in an access token (`rar_token.py`, `token_cases.py`)

RFC 9396 Section 9.1 has the AS put the details in a JWT access token. Here the details of this case are carried that way
(`typ at+jwt`, `aud`, `iat`, `exp`, `txn` = the decision, `authorization_details`), signed by a **synthetic** AS: an Ed25519 test key
from a fixed seed, `https://as.example.test`. No real authorization server issued anything. The token is built after the real
approval (`iat` 2026-11-07T09:55:00Z, the signature is 09:49:59Z). The run element carries one more member, `approved_spec_digest`:
the AS's enrichment in the sense of Section 7.1, which the type definition would have to allow (Section 5). Two readers:

- the **resource server** with the token alone: signature, issuer, audience, time, and that the action asked is among the details;
- the **auditor** with the token, the signed specification, the approval record and the run: T1 AS signature; T2 the details are
  within what the specification implies; T3 the link names the specification the person signed; T4 the time (`iat` after the
  signature, `exp` not beyond `valid_until`, every step inside the token's life).

| case | token | resource server | auditor |
|---|---|---|---|
| P2 | as issued after the approval, with the link | accepts | passes |
| TN1 | the right details, no link (as if no person approved) | accepts | T3 |
| TN2 | link to a digest the person did not sign | accepts | T3 |
| TN3 | issued before the approval | accepts | T4 |
| TN4 | outlives `valid_until` | accepts | T4 |
| TN5 | widened details, valid AS signature; the server is asked the widened action | accepts | T2 |
| TN6 | another audience | rejects | |
| TN7 | tampered signature | rejects | T1 |
| TN8 | the second step ended after the token expired | accepts | T4 |

What this adds to the earlier finding. In OAuth's own terms the token works as designed: the resource server enforces what the
token says, and refuses another audience or a bad signature. The resource server cannot tell, from the token, whether a person
approved (TN1), whether the AS granted what was approved (TN5), or when the approval happened relative to issuance (TN3). Those need
an independent record of the approval, here the person's signature of case 13b, and the AS's link to it (TN2) is only as good as the
AS: the link is a claim of the AS until it is checked against the person's signed record. That is a statement about this
construction. It does not say an AS cannot be built to retain and export such a record.

## Authorization evidence: the OAuth work that already exists (`rar_evidence.py`, `evidence_cases.py`)

After the first version of this case, a search found `draft-liu-oauth-authorization-evidence-01` (D. Liu and H. Zhu, Alibaba; S. Krishnan,
Cisco; A. Parecki, Okta; 23 June 2026). It defines a RAR type, `authorization_evidence`, which the AS fills in during consent: an `id`, a
`user_confirmation` (`displayed_content`, `user_action`, `timestamp`) and an `as_signature` (detached JWS over the JCS of `id` and
`user_confirmation`, Section 3.6). A resource server MAY check the signature and that the confirmation is not after the token's `iat` (7.1).
I read Sections 1, 1.2, 3.4 to 3.6, 7.1 and 8.1 to 8.6 of its text. I did not check whether the working group adopted it.

Its own Section 8.2 says the AS signature "provides cryptographic proof that the AS *recorded* a user confirmation. It does not
independently prove that the user *actually* consented", and that deployments needing stronger non-repudiation "SHOULD supplement this
mechanism with user-side signatures or independent consent auditing". Case 13b's approval is a user-side signature, and this
directory is an independent check. `rar_evidence.py` fills the draft's object from the real approval (`displayed_content` = the view the
person signed, `user_action` = `biometric_confirmation`, a value of its list) under the synthetic AS key, and adds one check the draft
does not have: the displayed content is the text whose digest the person's signature covers, and the confirmation is not before the
signature. The passkey signature itself is not re-verified here; case 13b's check did.

| case | evidence | the draft's checks (7.1) | the person binding |
|---|---|---|---|
| P3 | as issued after the real approval | accepts | holds |
| P4 | recorded at the server's receipt time, 14 minutes after `signed_at`, token issued after | accepts | holds |
| N12 | the AS fabricates a confirmation the person never gave | accepts | fails |
| N13 | `displayed_content` altered afterwards | rejects | fails |
| N14 | the AS signs another text than the one the person was shown | accepts | fails |
| N15 | confirmation one hour after the token's `iat` | rejects | holds |
| N16 | confirmation five minutes before the person signed | accepts | fails |

N12, N14 and N16 are Section 8.2 in action: a valid AS signature over evidence that the person did not give. They are caught only
by the person's signature. Two readings of the text, not defects: the signature covers `id` and `user_confirmation` and no other
member (3.6), so the link between a record taken out of its token and the exact authorization details is the text of
`displayed_content` and not a digest of the details; and the person's `signed_at` is the moment the request was prepared, the server
received the assertion later (case 13b: 14 minutes), so a token and an evidence timestamp earlier than the receipt would fail the
draft's own check (P4 against N15). Synthetic: the AS and its key, everything but the person's signature.

## What this shows, and does not

- **RAR expresses the approved scope well.** Actions, an identifier per step and type-specific members fit, in a standard
  carrier that an AS, a client and a resource server already know. V4 gives a resource server a cheap check of what ran.
- **The details alone cannot say they are the approved ones.** N1, N7 and N8 are accepted by a check that has only the details and
  the run, and a widened view (N10, N11) passes the coverage check of the resource server that holds it. What catches them is the
  link to the signed specification (V1, V2, and the subset test against the full set) and to the reference (V3). That link is
  what the audit record adds. RFC 9396 does not claim to provide it.
- **The RFC already points at the pieces.** Section 3 lists CIBA among the places where `authorization_details` can be used.
  Section 11.2 says an AS should support storage of consented authorization details as part of a grant. Section 12 asks the client
  to protect the details against tampering, for instance with signed request objects (RFC 9101). Section 9.1 puts the details in
  a signed access token. What the sections read here do not define: an exportable, offline-verifiable record of the grant for a
  third party; the signature of the person on the exact details and the view shown (Section 11.1 leaves "how authorization details
  are shown to the user" to the deployment); how long any of it is kept. An RFC 9101 request object is signed by the client over
  the request, which is not the person's approval of the granted details.
- **Not common fields:** an expiry (here `valid_until` is a type-specific member; Section 11.1 mentions an AS setting expirations
  during consent, and a JWT access token has `exp`), the exact arguments (a digest in a type-specific member), the references
  between steps (`$ref` outputs: the digest covers them, the details do not interpret them).
- **Disclosure.** Section 13 asks that details be shared with a client or a resource server on a need-to-know basis and warns that
  they may hold personal data. That governs what the AS gives a party in the flow. It is a different thing from an audit record
  that lets a later reader check a decision while the sensitive parts stay out, which is what a digest reference is for here
  (P1 to N11 show a filtered view checked against the full set; they do not implement conditional release).
- **Not tried:** a real authorization server, a real token exchange, a CIBA flow, a type registered in AS metadata (Section 10). The
  token above is issued by a synthetic AS. In the real run the approval is a passkey signature at `sign.pria.fr` with no
  authorization server in the loop. Whether an AS could issue the same approval as a retained, offline-verifiable artefact is
  not answered here.
- **Synthetic, as in case 13b:** the brokerage, the client, the plan, the executor and its effects, the `urn:example:rar:*` types,
  the authorization server and its key.
  Real: the person's signature, the specification bytes, the digests.
