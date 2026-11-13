# A decision and the authority behind it: a decision record composed with an OMP record, from the text — 2026-11-11

Tolulope Adebayo, author of the Operating Model Protocol (OMP), read the -00 of
draft-lemonnier-scitt-decision-provenance against his Invariant 3 and answered on 2 November 2026: citing a delegation
instrument by its hash gives non-modification and nothing about timing; a reference added once a decision record
exists is `post_hoc_attached`; a BOUND record needs the registry snapshot; the instrument stays the deploying
organisation's to produce; AUTHORITY_UNBOUND is a result, not an error. He agreed to a worked case with four failing
forms. This folder is that case, built before any vector of his exists.

One synthetic insurance advice in a brokerage firm is recorded twice. The Decision Provenance Standard (DPS) records
what the adviser decided, what she was shown and the exact recommendation she approved and that was issued. An OMP
Audit Trace records whether she held the mandate at that moment; its delegation instrument is her mandate. The two
answer different questions about the same act, and neither format is changed.

Written from the text alone; no code of the OMP authors was read or run. Everything is synthetic: no firm, person,
client, contract or registration here exists; test keys from fixed seeds; a test time-stamping authority. Two runs
write the same bytes.

**What this is not.** The text of OMP Core does not define everything a record needs. Twenty places where it leaves a
choice are logged below; six of them are definitions without which no record can be built (what is hashed, what the
registry is, what the binding timestamp is over). This folder fills each with a stand-in of its own, named in the code
and in every result. The records here are therefore a reading of the text with those stand-ins, not OMP-conformant
records, and "BOUND" below means BOUND under that reading.

## What was read

| Document | Revision / URL | SHA-256 of the text read |
|---|---|---|
| draft-veridom-omp-core-00, "OMP Core: Invariant 3 -- Verifiable Delegation Binding" | -00, 13 May 2026 (latest on datatracker on 2026-11-11; no -01), https://www.ietf.org/archive/id/draft-veridom-omp-core-00.txt | `c756525d2d9c419caf3b9f9dcff774547ee27a6ee4ca74c1e831ea843a61d78b` |
| draft-veridom-omp-00, read through section 12.2; sections 5, 7, 8 and 11 are used (the routing tree, the Audit Trace and its sealing, which core-00 section 3 calls "unchanged from -00") | -00, 21 March 2026, https://www.ietf.org/archive/id/draft-veridom-omp-00.txt | `ee9a21d2992e49352e8273bce5869c741622de42c95f7bf93b20842183578b1b` |
| draft-veridom-omp-02 | compared line by line with core-00: the same text under its earlier name (title and version wording differ) | `a357d0a4d009beed3eaf6167a43e31d96143b551fb3fd8adc8c7a4bd5de69a98` |
| The author's mail of 2 November 2026 | private; the five points above are used, restated in our words | — |
| DPS Standard, action binding 0.3.0, signatures 0.2.0, anchoring test generator | `decision-provenance-standard/standard` at `007f8c9` | — |

Not read: draft-veridom-omp-01 beyond its table of contents; the "OMP Technical Specification" on Zenodo that core-00
cites informatively; the OMP domain profiles. RFC 8785 and RFC 3161 are relied on and were not read again for this
case. Of `veridomltd/omp-open-core`, only the list of files and the commit dates were looked at, on 11 November 2026,
to see whether vectors had been published: none (README, CONTRIBUTING, LICENSE, three JSON schemas dated 8 April 2026,
before Invariant 3, and empty `validator/`, `docs/`, `watchtower-framework/`; last push 8 April 2026, head `a0114c2`,
the same on 13 November 2026).
No file of it was opened. **The vectors here are our own.**

## The case

Client file CF-2026-0042 (invented): a bakery asks for professional multi-risk cover. An assistant drafts a
recommendation among three contracts; adviser-1 is shown the options, the reasons and the mandate she acts under, and
approves option B; the advice statement is issued to the client. Times are those of 9 November 2026.

| Moment (UTC) | DPS (`decision-record.json`, `action-binding-attachment.json`, `signatures-attachment.json`) | OMP (`omp-audit-trace.json`) |
|---|---|---|
| 2 March, 09:00:05 | | the mandate's hash time-stamped (`registration-token.tsr`); entered in the firm's registry |
| 10:02:01 | | routed ASSISTED (omp-00 5.1); Invariant 3 evaluated; registry state taken |
| 10:02:02 | | binding token over the `authority_binding` object (`binding-token.tsr`) |
| 10:03 | record created; proposal by the assistant | |
| 10:10 | review: the adviser is shown the specification and the view (`review-view.txt`) | |
| 10:12:00 | outcome approved; her Ed25519 signature over the digests shown and approved | `assisted_resolution`: RA-1 APPROVE, same time |
| 10:12:06 | | trace sealed: content hash, time-stamp token, chain hash |
| 10:12:40 | recheck: reads the sealed trace's `execution_permission` | |
| 10:12:45 | attempt and result: the advice statement issued | |
| 10:20:30 | attachment sealed by the firm | |

How each record points at the other. Nothing is added to the DPS documents. On the OMP side one member of our own is
added (`decision_context`, A9), and the content of `assisted_resolution`, which omp-00 leaves open, is ours (A15):

- The DPS specification's `policy_version` is the OMP `instrument_hash`. The adviser's signature covers the
  specification's digest, so it covers the mandate's hash.
- The DPS outcome's `authority.authority_ref` is `urn:omp:authority-binding:sha256:…`, the SHA-256 of the RFC 8785
  bytes of the OMP `authority_binding` object, fixed when the binding was evaluated, before the approval.
- The DPS recheck's `authority_source_ref` is `urn:omp:audit-trace:<trace_id>#trace_content_hash=…`, the sealed trace.
- The OMP trace's `assisted_resolution.proposed_response_hash` is the DPS specification's digest, and its scope was
  evaluated on the product, jurisdiction and premium of that specification.

## Results (`build.py`, `out/summary.json`)

Two variants. Both are expected results; neither is a failure.

| | `out/bound/` | `out/unbound-sealed/` |
|---|---|---|
| The firm | keeps an authority registry; the mandate is in it since March | has the same mandate, time-stamped in March, and keeps no registry |
| OMP result | BOUND, ALLOWED | AUTHORITY_UNBOUND, BLOCKED, `REGISTRY_PROOF_MISSING` |
| OMP reader (`omp_from_text.py`): schema, routing, content hash, chain hash, trace token, three axes | verified | verified |
| binding token (stand-in A5) | verified | verified |
| `instrument_hash` against the mandate held (stand-in A1) | verified | verified, on the instrument published beside the trace (A14) |
| registry state against `authority_registry_snapshot_hash` (stand-in A4) | verified | none exists: the reason the record states |
| Invariant 3 evaluated again from the trace and the documents held | BOUND, as stated | AUTHORITY_UNBOUND, same reason, as stated |
| DPS: four schemas, eight action-binding dimensions, the firm's seal, the adviser's signed approval | all verified | all verified; `observed_results` not checked (nothing was attempted) |
| DPS stages | proposal, review, approval, request, recheck `authorised`, attempt, result | proposal, review, approval, request, recheck `not_authorised`; no attempt |
| J1 same person | holds | holds |
| J2 same decision | holds | holds |
| J3 same instrument | holds | holds |
| J4 the decision record cites this authority record | holds | holds |
| J5 permission and recheck | holds (ALLOWED, authorised, one attempt) | holds (BLOCKED, not authorised, no attempt) |
| J6 moments in order | holds | holds |
| J7 the instrument covers the approved action at the approval | holds | does not hold: `REGISTRY_PROOF_MISSING` |

The second variant is the situation the author described on 2 November: a deployer's charter has no registry, so the
snapshot hash cannot be produced from it as things stand. The adviser approved, and her approval verifies; the binding could
not be made; that absence is sealed and time-stamped; the recheck refused; nothing was issued. Whether a time-stamp
over the instrument's hash, earlier than the decision, could stand for registration is the question put to the author
on 2 November; until he answers, this folder reads the text as requiring the registry (A11).

### The joins

| Join | What is compared | What it rests on |
|---|---|---|
| J1 same person | OMP `named_accountable_officer.officer_id` (or `attempted_officer_id`), the instrument's `officer_id`, `assisted_resolution.officer_id`, the officer in the mandate held; DPS reviewer, outcome actor, the record's `affirmation_record`, and the holder of the key that signed, under the verifier's trust policy | DPS: a verified signature under a key the verifier's policy gives to that person. OMP: the emitter's sealed statement |
| J2 same decision | OMP `proposed_response_hash` against the digest shown, approved, signed and recomputed from the specification's bytes; the values OMP evaluated the scope on against the values approved | DPS: signed. OMP: two members of this folder's (A9, A15) under the trace's seal; the text names no member for what was decided |
| J3 same instrument | the specification's `policy_version`, the instrument's `instrument_hash`, the hash of the mandate held | the adviser's signature covers the hash: it was fixed no later than her signature. Non-modification only (the author's first point) |
| J4 references | the two references the attachment carries against the object and the trace held, recomputed | the firm's seal over the attachment; the authority member is not under the person's signature |
| J5 permission and recheck | `execution_permission` against the recheck's result and the attempts recorded | two statements of the firm, each under its own seal |
| J6 moments in order | the nine or ten moments of the table above (ten when the advice is issued), and that the approval carries one time in both records and in the signature | three tokens of a test time-stamping authority and the two parties' clocks between them |
| J7 the instrument covers the approved action | Section 3.3's conditions run on the DPS values: the approver, the approved specification, the approval time | the mandate and the registry state are the firm's own (core-00 section 8.1) |

### Section 5 of core-00, on our inputs (`out/section5-cases.json`)

core-00 lists twenty minimum conformance cases and gives no vector. One input of ours per case, run through
`evaluate()`: **20 of 20 give what the text states.** Cases 15 to 17 depend on stand-ins (the window of A6, the
profile's choices of A10 and A16). Case 18 uses `corporate_delegation_root`, the value section 6 of core-00 writes
for three profiles and Appendix A does not list.

## The failing cases (`negatives.py`, `out/negatives/`)

Each case states the exact set of checks expected not to pass; one more or one less fails the script. Where an emitter
lies, seals, tokens and signatures are made again so that what fails is what the record says. **13 of 13 failing cases
fail where expected**, and P1 gives the result expected.

| Case | Change | Expected to fail at, and does |
|---|---|---|
| N1 `post_hoc_attached`, stated BOUND | the record states the mode and BOUND, ALLOWED | OMP Invariant 3: evaluated again as AUTHORITY_UNBOUND, `POST_HOC_ATTACHMENT_DETECTED`, review flag; J7 |
| P1 `post_hoc_attached` as the text has it (not a failure) | the same attachment by an emitter that follows the text under our stand-in profile | AUTHORITY_UNBOUND, BLOCKED, sealed, review flag; recheck refused, nothing issued; J7 does not hold, as it should |
| N2 post hoc, relabelled `pre_registered` | on 20 November the firm writes a wider mandate, backdates its registry entry, issues the trace again as BOUND with times written as on 9 November | OMP Invariant 3: `BINDING_TIMESTAMP_OUTSIDE_WINDOW` (the binding token is of 20 November); J3 (the adviser signed the first mandate's hash); J4 (the decision record cites the first binding and trace); J6 |
| N2b the same, and the decision record issued again too | specification, signature and seal made again, all written as on 9 November | OMP Invariant 3 and J6 only: J3 and J4 now hold. What is left is the tokens |
| N3 instrument altered after hashing | the mandate held has a wider scope than the one hashed | OMP `instrument_hash`; Invariant 3: `INSTRUMENT_HASH_MISMATCH`; J3; J7 |
| N4 no registry state, BOUND stated | no `authority_registry_snapshot_hash`, BOUND all the same | OMP schema (member absent), registry state, Invariant 3: `REGISTRY_PROOF_MISSING`; J7 |
| N5a the approver is not the officer named | adviser-2 reviews, approves and signs with her own listed key; the OMP trace names adviser-1 throughout | J1 and J7 only. Each record verifies alone |
| N5b the officer named is not the instrument's | the trace names adviser-2, bound to adviser-1's mandate, BOUND | OMP Invariant 3: `OFFICER_ID_MISMATCH`; J1; J7 |
| N6 revoked instrument | the registry state says REVOKED; the record states ACTIVE and BOUND | OMP Invariant 3: `INSTRUMENT_REVOKED`; J7 |
| N7 outside `mandate_scope` | an insurance-based investment product under a non-life mandate, BOUND stated | OMP Invariant 3: `MANDATE_SCOPE_MISMATCH`; J7. Every DPS check verifies: she approved exactly what was issued |
| N8 a sealed AUTHORITY_UNBOUND relabelled | `execution_permission` changed to ALLOWED in the sealed trace, nothing recomputed | OMP content hash, three axes, binding token, Invariant 3; J4, J5, J7 |
| N9 another decision | the trace carries the digest and the premium of option C; option B was approved | J2 only |
| N10 authority result sealed after the issue | the trace token is of 10:15, the advice was issued at 10:12:45 | J6 only |
| N11 the decision record cites another binding | `authority_ref` names another `authority_binding` object | J4 only |

Three observations for the two drafts.

1. N5a, N9, N10 and N11 pass every check of each format taken alone. Only a verifier holding both records sees them.
2. In N2 and N2b the firm rewrites everything it controls: the mandate, its own registry, its clocks, both seals; in
   N2b the adviser signs again. The registry does not catch it, being the same party's (core-00 section 8.1). What
   catches it is a time the firm does not control: the binding token. In this folder that token is a stand-in (A5);
   the text names `binding_timestamp` and does not say what it is over.
3. N7 is the case the two formats exist for together: the approval is exact and verifies, and the authority is absent.

## Ambiguity log

Each entry: what the text says, what it leaves open, what this folder does. Entries marked **(blocking)** are
definitions without which a record cannot be built at all.

| # | Text | Left open | Here |
|---|---|---|---|
| A1 **(blocking)** | core-00 4.4.4: `instrument_hash` is "SHA-256 of the canonical form of the authority document" | what an authority document is (a PDF, a JSON object, the DelegationInstrument itself) and what its canonical form is. The author, 2 November: the canonical form is to be stated with the vectors | the mandate is a JSON document; canonical form RFC 8785 |
| A2 | omp-00 section 7 types hashes "sha256"; core-00 4.1 writes "sha256:hexstring"; omp-00 8.4 concatenates `trace_content_hash + '|' + previous_H_c` | hex case; whether the -00 members carry the prefix; whether 8.4 joins the hex text or the raw bytes | lower-case hex; bare in the -00 members, prefixed in the core-00 members; 8.4 joins the hex text |
| A3 | Section 5 cases 6 and 7 compare `effective_date` and `expiry_date` ("ISO 8601 date") with "the decision timestamp" | which member is the decision timestamp (no Section 4 structure carries one); how a date compares with an instant; whether the first and last day count | `routing_decided_at` (3.3: "the moment of the routing state"); UTC calendar days; both days count |
| A4 **(blocking)** | core-00 4.4.4: `authority_registry_snapshot_hash` is "the hash of the registry state at decision time"; `registry_inclusion_proof` is "string or null" | the registry, what a state is, the hash over it, the proof's format, and who may keep the registry | a state is one JSON document listing instrument id, hash, registration time and status; SHA-256 over RFC 8785; no proof; the firm keeps it |
| A5 **(blocking)** | core-00 4.1, 4.2: `binding_timestamp` is an "RFC 3161 token reference" | what the token is over, and what a reference is. The member sits inside the object the trace's own token covers (omp-00 8.2), so it cannot name that token, whose serial number and bytes exist only once the trace is hashed | a second token, over the RFC 8785 bytes of `authority_binding` without this member; the member is `sha256:` + the hash of the token's DER bytes; the token is kept beside the trace |
| A6 | Section 5 case 15: "binding_timestamp outside window" | the window, and what it is measured from | 300 s after `routing_decided_at` (a stand-in profile value) |
| A7 **(blocking)** | omp-00 8.2 lists nine members left out of the content hash; section 7 says `tst_message_imprint` "must equal trace_content_hash" and it is not in the list | as written, the hash covers its own value | `tst_message_imprint` is left out as well; `tst_hash_alg` stays in |
| A8 **(blocking)** | omp-00 section 7: `schema_version` is fixed, and an implementation that extends the schema MUST use a distinct string; core-00 adds `authority_binding` and names none; core-00 section 7 speaks of "the core-00 schema"; omp-00 has `routing_path`, core-00 `routing_state` | the schema string of a core-00 trace; whether `routing_state` replaces `routing_path`; where `named_accountable_officer` sits in a full trace | a string of our own (`X-DSDL-OMP-CORE-00-FROM-TEXT-1`); both routing members, required equal; `named_accountable_officer` at the top level as 4.1 shows |
| A9 **(blocking)** | Section 5 cases 11 to 13 compare the decision's type, jurisdiction and value with `scope_constraints` | no member of the trace carries them (`intent_class` is the nearest for the type) | one member of our own, `decision_context` |
| A10 | 4.4.3: a decision outside `scope_constraints` MUST produce `MANDATE_SCOPE_MISMATCH`; cases 12 and 13 give other reasons for jurisdiction and amount | which reason for `product_scope`; whether 12 and 13 add to or replace the general reason; an amount in another currency; `risk_threshold` (a string, no comparison); a root type the profile does not accept (4.4.2) | `product_scope` and another currency give `MANDATE_SCOPE_MISMATCH`; 12 and 13 give their own reason alone; `risk_threshold` is not evaluated; an unaccepted root gives `NO_VALID_DELEGATION_INSTRUMENT` |
| A11 | 4.1 shows `authority_registry_snapshot_hash` in every BOUND record; 4.4.1 defines it under `pre_registered` only; the author, 2 November: a BOUND record requires `authority_registry_snapshot_hash` | whether `policy_resolved` and `manual_selected_at_decision` need it; which reason when it is absent (case 16 is about the inclusion proof) | required for BOUND in every mode; its absence gives `REGISTRY_PROOF_MISSING` |
| A12 | omp-00 section 11: RFC 8785, and floating-point values "with minimum 15 significant digits" | RFC 8785 fixes the ECMAScript number form, which is not that | RFC 8785 is followed |
| A13 | core-00 section 9: writing `post_hoc_attached` as `pre_registered` "will be detectable through the binding_timestamp and authority_registry_snapshot_hash fields" | how | detected when the instrument is not in the registry state at decision time, is dated there after the decision, or `instrument_selected_at` is outside the window; a late binding token gives case 15's reason |
| A14 | 4.2: an AUTHORITY_UNBOUND record has `failure_reasons`, `attempted_officer_id`, `binding_timestamp` | it shows neither the instrument that was tried nor `named_accountable_officer`: a third party cannot evaluate the reasons again from the record | exactly the members shown; the instrument tried is published beside the trace (`candidate-instrument.json`) and what is found about it is reported apart |
| A15 | omp-00 7: `assisted_resolution` is "object or null"; 5.3.2: RA-1 logs "Officer ID and approval timestamp" | the object's members; any member for the digest of what the officer approved; whether an ASSISTED trace is sealed at routing or after the resolution | `resolution_action`, `officer_id`, `approved_at`, `proposed_response_hash`; one trace, sealed after the resolution |
| A16 | 4.4.1: `post_hoc_attached` "MUST trigger a review flag", "SHOULD NOT" be treated as fully BOUND, profiles MAY choose AUTHORITY_UNBOUND or AUTHORITY_RETROSPECTIVELY_ATTACHED; 8.3: it "cannot receive BOUND status" | SHOULD NOT against cannot; the second result is not in Appendix A; no member carries the review flag | never BOUND; AUTHORITY_UNBOUND with `POST_HOC_ATTACHMENT_DETECTED`; the flag is in the reader's report |
| A17 | 4.4.2: three root classes; for `corporate_delegation`, `issuing_authority_id` "references the corporate registration number and the specific delegation instrument"; section 6 writes "corporate_delegation_root anchored in statutory" | one string for two things; no member chains an instrument to the registration above it, so a firm's public registration and an officer's mandate inside the firm cannot both be in one record; section 6's value is not in the enumeration | `corporate_delegation`, `issuing_authority_id` as `<company registration>#<instrument id>`; the firm's intermediary registration appears in the mandate document only |
| A18 | core-00 3.2: "an optional institutional signature"; omp-00 8.3: "Proof-Point = Institution.sign(trace + TST)" | no member of the trace carries a signature | none is made |
| A19 | 4.4.1: `post_hoc_attached` is "attached after the decision record was created" | which record and which of its times; for a record of another format, its creation or its decision | within OMP, A13; across the two formats, J6 and the references of J3 and J4 |
| A20 | omp-00 8.3: an accredited time-stamping authority; self-operated ones MUST NOT be used in regulated deployments | — | a test authority from a fixed seed: the tokens show the order of moments and bound nothing |

### What a builder needs from the text

In order of what blocks first: the canonical form of an authority document (A1); the registry, its state and the
snapshot hash (A4); what `binding_timestamp` is over and how it is referenced (A5); the content hash's exclusion list
(A7); the schema of a core-00 trace, with its schema string and the place of the three new members (A8); the members
that carry the decision's type, jurisdiction and value (A9); the window of case 15 (A6); the instrument in an
AUTHORITY_UNBOUND record (A14). The published example instrument and vectors would settle A1, A2 and probably A4 and A5.

## What it shows, and what it does not

It shows that the two records join with no change to the DPS documents and two named stand-ins on the OMP side, on
three values (the instrument's hash, the digest of what was approved, the trace's content hash); that the four failing
forms agreed on 2 November are caught, each at a named place; that a sealed AUTHORITY_UNBOUND composes with a decision
record as a result (approved, refused at the recheck, not issued); and which failures only the pair can see.

It does not show that the adviser held any authority in law: the mandate, the registry and both clocks are the firm's
(core-00 section 8.1), and the firm's registration as an intermediary, which is the one fact here a public register
could ground, has no member to sit in (A17). It does not show conformance to OMP: no vector of the authors exists and
six definitions are stand-ins. The time-stamping authority is a test one. The DPS times are the issuer's own; no
anchoring extension is used on that side. Nothing here is a statement about any regulation.

## Reproduce

```sh
# Python 3.12, cryptography, asn1crypto, jsonschema, referencing; the Standard at 007f8c9. Nothing of OMP's is needed.
DPS_STANDARD=/path/to/standard python3 build.py        # exit 0: both variants as expected, Section 5 20/20
DPS_STANDARD=/path/to/standard python3 negatives.py    # exit 0: 14/14 as expected (13 failing cases, P1)
```

`omp_from_text.py` is the evaluator and the reader; `out/<variant>/` holds every document of the case and
`report.json`; `out/negatives/<case>/` the same with `what.txt` and `result.json`; `out/section5-cases.json` the twenty
inputs; `out/profile-stand-in.json` the values a profile would set. `../run.sh` runs both scripts and compares `out/`
with the committed files.

The Operating Model Protocol is Tolulope Adebayo's and Oluropo Apalowo's; the reading of it here is ours and may be
wrong. Written with an AI assistant.
