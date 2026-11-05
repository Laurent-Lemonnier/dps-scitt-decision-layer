# Case 15: an AgentInteractionRecord citing a decision record by typed digest — 2026-11-05

Built for a call with the author of draft-emirdag-scitt-ai-agent-execution-01 (Pinar Emirdag, VERIDIC), so that there
is something concrete on the screen. Section 10.1 of the draft says that "an AIR can carry a reference to a Permit or
equivalent authorisation record in `external_refs`, so that a Relying Party can pair the authorisation record with the
execution record for the same Material Action", and that "this profile does not define the authorisation record
itself". Here the authorisation record is a Decision Provenance Standard record with its action binding and a person's
signature; the execution record is an AgentInteractionRecord (AIR). Each is under its own text, nothing changed in
either; the pairing is the additional step this case adds, and it is named as such.

The story is the refund of `../aer1-decision`: a support agent proposes a refund of 120.00 EUR (12000 cents) for a
duplicate charge; the support lead is shown the rendered refund and approves it under their signature; the decision
record is closed at the sign-off; the agent runtime requests, rechecks and executes the refund through the payment
gateway. The agent's operator records two AIRs in one Evidence Chain: sequence 0, a read-only lookup of the order's
charges earlier in the session, unrelated to the decision; sequence 1, the execution of the approved refund, whose
`external_refs` cite the decision record, the signatures attachment holding the person's approval and the approved
specification by typed digest, whose `input_hash` is the SHA-256 of the approved specification's bytes, and whose
`outcome_hash` is the SHA-256 of the gateway's response. The issuer's attachment, sealed afterwards, cites the AIR
back by `record_id`, `chain_hash` and `outcome_hash`.

| Side | Text | Here |
|---|---|---|
| Decision | Decision Provenance Standard, action binding 0.3.0 and signatures 0.2.0, main at `007f8c9` | the decision record (Core v1.3 rev. 11, reference files 5.2.0); the attachment (proposal, review, approval, request, recheck, attempt, observed result) sealed by the merchant (`issuer_signature`); the support lead's `person_approval` |
| Execution | draft-emirdag-scitt-ai-agent-execution-01, Emirdag and Feichtinger, Informational, 12 October 2026: Sections 5.2 (CDDL), 5.3, 5.6 (COSE encoding), 5.7 (chain), 5.8 (verification), 6.1, 6.3, 6.4 (registration policy), 10.1; the EES v0.2 `air.schema.json` (THEVERIDIC/VERIDIC, Apache-2.0, commit `f4cbcea4`, 8 August 2026, SHA-256 `a23bdbf2b628a81aa035b1bf5811e15b383721f17aca28afad7e106d1d2f7353`, pinned in `vectors/`) | two COSE_Sign1 with ES256: `air-0.cose` (the lookup) and `air-1.cose` (the execution), payloads in RFC 8785 form, protected headers with `alg`, `kid`, CWT Claims and the six integrity fields of 5.5 |

The draft publishes no test vectors or examples; the AIRs here are built from its text and verified by a verifier
written from it (`air_verify_independent.py`). Synthetic data and test keys; deterministic (fixed seeds, RFC 6979
signatures, fixed times, UUID v7 record ids built from the action time and a seed rather than random bits, which is said
here because 5.3 asks for v7 and a reader may expect randomness in the low bits).

## What binds, and what only points

- **AIR → DPS, bound by the operator's signature.** `external_refs` is in the payload, under `content_hash` and the
  COSE_Sign1 signature. The three typed digests (`org.decisionprovenancestandard.decision_record`,
  `.signatures_attachment`, `.action_specification`, each `sha256:` + lowercase hex of the exact bytes, `ref_system` a
  URL of this repository with `main` as the commit placeholder) are therefore the operator's signed statement of which
  record, which approval and which specification the agent executed under. `input_hash` is the SHA-256 of the approved
  specification's bytes: the shown, approved and executed values are one byte string. `intent_attestation` (5.3:
  "reference to a signed attestation of the principal's intent", unstructured) carries the typed digest string of the
  signatures attachment, the document that holds the person's signature; this is our reading of an unstructured member.
- **DPS → AIR, bound by the issuer's seal.** The attempt's `trace_refs` names the AIR (`urn:air:record:<record_id>`) and
  the result's `evidence_ref` names its `chain_hash` (the position in the Evidence Chain that the Evidence Receipt of
  Section 7 would attest) and its `outcome_hash`. Both stages are under the merchant's seal.
- **Not both ways by whole-document digest, and why.** The attachment's result stage names the AIR's `chain_hash`, so
  the AIR cannot name the attachment's final bytes: it would have to carry a digest that depends on its own. The AIR
  names what existed when it was signed (the record closed at the sign-off, the approval, the specification); the
  attachment, written after the observed result, names the AIR. `../aer1-decision` has the same shape with its receipt.
- **Pointed.** `principal_id` names the approver; `policy_refs` names the refund policy; `ref_system` names where the
  bytes are published. These are the operator's assertions, consistent with the bound values and checked as such (J6),
  never a binding on their own. The `refund_ref` in `external_refs` is another system's reference, not resolved here.
- **Outside the draft's MUSTs.** Section 5.8 verifies a record and its chain; it does not resolve `external_refs`, and
  10.1 defines no resolution rule, no type names and no digest form for `ref_value`. The resolution (J1) and the joins
  are this repository's additional step. The type names are the namespace `agent-pass` and `plan-run` use for CPB
  typed references; neither text defines them.

## What verifies (`out/summary.json`)

Each AIR passes the 32 checks of the verifier written from the text, every check named with its section; the chain of
two is VERIFIED (the draft's word). The checks, grouped:

| Group | Checks | Section |
|---|---|---|
| Structure | COSE_Sign1 of four elements (tag 18 accepted, not required); `alg` = -7; `kid` present, a bstr; CWT Claims (15) with `iss` and `sub`; the six integrity fields present and typed; header `agent_id` = CWT `sub` | 5.5, 5.6, 6.1; RFC 9052 4.2; RFC 9943 6; RFC 9597 |
| The four steps | step 1 SHA-256(payload) = `content_hash`; step 2 `chain_hash` recomputed from the header's members with the 5.7 encoding (76 + len(agent_id) bytes); step 3 ES256 over the Sig_structure with the operator's public key; step 4 sequence 0 with zero `prev_chain_hash`, or one more than the preceding record with its `chain_hash` | 5.8, 5.7, 6.3 |
| Payload | RFC 8785 form (re-serialisation gives the same bytes); `schema_version` = `air-1.0`; every REQUIRED member present, non-null, typed; every OPTIONAL member present (null when absent), typed when not null; no member outside the CDDL; `action_type` in Table 2 or reverse-DNS namespaced; `outcome_state`, `retention_class`, `jurisdiction` forms; `record_id` a UUID v7; `session_id` a UUID; `input_hash` and `outcome_hash` 32 bytes; ToolCallRecord, ExternalRef, RedactionReceipt, AuthContext shapes; `policy_refs` and `delegation_chain` arrays of tstr | 4.2, 5.2, 5.3, 5.6, 6.1 |
| Header and payload agree | payload `agent_id` = header `agent_id` = CWT `sub`; payload `action_timestamp_ms` = header's; `operator_id` = CWT `iss`; `operator_pubkey_id` = `kid` | 5.3, 5.6 |
| Policy | `action_timestamp_ms` <= `captured_timestamp_ms`; a RedactionReceipt present for the action types 6.4 names (`payment_execution` here) | 6.3, 6.4 |

Also run, as a shape check only and not a check of the draft: both payloads against the pinned EES v0.2 JSON Schema
with its `integrity` member excluded (ambiguity (b) below); no error. The DPS side as in `../aer1-decision`: the four
schemas; the eight action-binding dimensions; the merchant's seal (`issuer_recorded_claims_only`); the support lead's
approval (signature, subject, key state, identity) against the verifier's trust policy.

Not checked, and said: "captured within 300s of submission" (6.3) needs a submission time no record carries; the
pre-registration of the operator's key (5.4, Level 1) is the verifier's own trust input, `out/operator-public-key.pem`;
Levels 2 and 3 are not required here. Byte strings in the JSON payload are read as base64url without padding, the
EES v0.2 schema's provisional encoding (its `$defs/bytes` says "pending Engineering confirmation"); the draft's CDDL
`bstr` is native and says nothing about JSON.

## The joins (`out/summary.json`, `joins`)

| Join | What is checked | Rests on |
|---|---|---|
| J1 | the AIR's `external_refs` name the decision record, the signatures attachment and the approved specification by the digests of the bytes held; every reference of this namespace resolves, none mismatches | the operator's signature over the payload; the bytes held |
| J2 | `input_hash` = SHA-256 of the approved specification's bytes = `o1.approved_spec_digest` = the person's `approved_spec_digest` | the operator's signature; the person's signature; the seal |
| J3 | the attempt cites the AIR by `record_id`, the result names its `chain_hash` and `outcome_hash`; `outcome_hash` = SHA-256 of the raw output held (`out/air-1.outcome.json`) | the seal; the operator's signature |
| J4 | sequence 1's `action_timestamp_ms` is after the approval, not before the request, not after the observed result | times asserted by the issuer and the operator (Section 7: "the timestamps inside the AIR are asserted by the Issuer") |
| J5 | the chain of two is VERIFIED; sequence 1's `prev_chain_hash` is sequence 0's `chain_hash`; the numbers are 0 and 1 | the operator's signatures |
| J6 | the approver (the signer the trust policy names, `o1.actor_ref`) is neither `operator_id` nor `agent_id`; the AIR names them as `principal_id` | the trust policy; the operator's assertion |

What each party proves: the person's signature proves that a named person approved exact bytes; the operator's
signature proves that the operator states its agent executed those bytes, with this outcome, in this position of its
chain; the issuer's seal proves that the merchant records the attempt and result as citing this AIR. No one of the three
proves the other two.

The binding is reported in one word beside the joins: `BOUND` when the AIR names the record held; `NOT_BOUND` when it
carries no reference of this namespace (not an error of either document); `UNRESOLVED` when it carries references of
this namespace that this reader cannot resolve; `MISMATCH` when a known type names other bytes.

## The failing cases (`negatives.py`, `out/negatives/`)

Each case is published as a directory `out/negatives/<case>/` holding the documents the verification ran on, as they
were at that moment (the DPS documents as JSON; each AIR as COSE bytes, hex, payload, canonical bytes and header, as in
`out/`), the description (`what.txt`) and, apart from them, the verdicts (`result.json`); `summary.json` gathers them.
Where a case changes the AIR the DPS cites, the attachment is made to cite the AIR held and sealed again, so the failure
is in what the AIR binds and not in a stale citation (as `../aer1-decision` does with its receipt).

| Case | Change | Caught by |
|---|---|---|
| N1 | the header's `content_hash` is another digest, signed again | 5.8 step 1 (and step 2, which starts from the header's `content_hash`) |
| N2 | the payload re-serialised with members in another order, header and signature kept | 5.8 step 1; 5.6 canonical form; 5.8 step 3 |
| N2b | the header's `chain_hash` is another digest, signed again | 5.8 step 2 alone |
| N3 | sequence 1 numbered 2, signed again | 5.8 step 4 |
| N4 | sequence 0 with a non-zero `prev_chain_hash`, `chain_hash` recomputed, signed again | 5.8 step 4 on record 0, and on record 1 (its `prev_chain_hash` no longer matches) |
| N5 | the payload changed after signing, `content_hash` and `chain_hash` made consistent, signature kept | 5.8 step 3 alone |
| N6 | the decision record edited after the AIR cited it (`seal_hash` recomputed, the record consistent on its own) | J1: the typed digest no longer names the bytes held; `MISMATCH` |
| N7 | the agent executed a specification of 150.00 EUR; the person approved 120.00 EUR; the AIR verifies and cites the record | J2: `input_hash` is not the approved bytes |
| N8 | a valid AIR with empty `external_refs` | nothing fails, by design: `NOT_BOUND`, J1 not applicable |
| N9 | the record cited under a type this reader does not know (`…decision_record_v2`) | nothing fails, by design: `UNRESOLVED`, reported |
| N10 | the action timestamped 09:06:00Z, before the approval (09:07:00Z) and the request (09:08:00Z) | J4 |
| N11 | the header's `agent_id` names another agent, `chain_hash` recomputed with it, signed again | 5.6: header `agent_id` ≠ CWT `sub`; payload `agent_id` ≠ header's; the chain is no longer one agent's |
| N12 | `jurisdiction` null in a REQUIRED position, reissued | 6.1: a REQUIRED member null; the EES schema as well |

In every case where the chain fails, J5 fails with it (it includes the chain's verdict); the table names the first
place.

## Ambiguity log — questions for the authors

| Where | Reading taken, and the other reading |
|---|---|
| (a) 5.7, `content_hash = SHA-256(COSE_Sign1.payload)` | read as the bytes inside the payload byte string ("the raw byte string from the COSE structure's payload field"), not the CBOR-encoded byte string (which would add the major-type-2 length prefix). A reader hashing the encoded item gets another `content_hash`; the text could say "the content of the payload byte string" |
| (b) 5.5, 5.8 step 3 vs the EES envelope | the draft signs the RFC 9052 Sig_structure over the protected header and payload, with the integrity fields in the header; the EES v0.2 schema carries an `integrity` object in the JSON with a `signature` "ECDSA-P256 over chain_hash". Followed the draft; the EES schema is used here only with `integrity` excluded. Section 9 calls the Section 5.2 schema "a conformant subset of the EES schema"; the two signatures are over different bytes, and an EES verifier would not verify these records as they stand |
| (c) 5.9, `key_rotation` | 5.9 allows "a key rotation record (action_type: key_rotation)"; Table 2 (4.2) does not list it, and "values without a namespace prefix are reserved for this profile". Not used here; this verifier would refuse a non-namespaced `key_rotation` under 6.1 "valid action_type". The EES schema's examples list `key_rotation` (and `contract_formation`, `authorisation_grant`, which Table 2 does not; Table 2 lists `contract_execution` and `configuration_change`, which the examples do not) |
| 5.3, JSON form of `bstr` members | base64url without padding, the EES v0.2 provisional encoding; the CDDL is silent on JSON. A reader using hex or base64 with padding would reject these payloads at the CDDL type check |
| 5.8 step 2, which `content_hash` | recomputed "from the COSE protected header", so the header's `content_hash` is the input, and step 1 binds it to the payload; a reader starting from the recomputed payload hash reaches the same verdict on an intact record and a different first failure on N1 |
| 10.1, the reference's form | no type names, no digest algorithm, no encoding for `ref_value`; this repository's typed digest is one form. The draft could name a form, or say that the authorisation record's own text does |
| 5.3, `input_hash` ("the raw input to the agent") | read as the bytes the agent was given to execute, the approved specification; another reading is the user's prompt or the tool call's arguments (recorded here in `tool_calls[0].input_hash`) |
| 5.6, tag 18 | the draft says "COSE_Sign1 structures"; emitted with tag 18 here, accepted with or without by the verifier |

## What this does not show

- No human approval is proven by the AIR itself: `principal_id` and `intent_attestation` are the operator's assertions.
  The person's approval is proven by the DPS signature, and only the join (J1, J2) connects the two.
- The timestamps are asserted by the Issuer (Section 7); J4 checks their order, not their truth. No Evidence Receipt
  (Section 7) is built: nothing here attests when the records existed.
- The resolution of `external_refs` is outside 5.8; a verifier following the draft alone verifies both AIRs and learns
  nothing about the decision record. The form of the reference is this repository's.
- The chain shows two records of one agent; nothing about other agents, the Transparency Service's admission (6.3's
  300 s rule, 6.5), Levels 2 and 3 (6.2), redaction beyond one receipt per record, or the EES capture interface.
- That the gateway's response is true (`outcome_state` is the operator's word; the DPS result's basis is
  `executor_observation` because the AIR is the executor's own record), or that no other call was made under the same
  approval (the request limit is 1; a second AIR citing the same record would be a second record in the chain, which a
  verifier holding the chain can count and this case does not).

Nothing here is a conformance claim by the draft's authors, and no claim of priority or influence is made.

## Reproduce

```sh
# cryptography, cbor2, jsonschema, asn1crypto; the Standard at 007f8c9
DPS_STANDARD=/path/to/standard python3 build.py
DPS_STANDARD=/path/to/standard python3 negatives.py
# the two records alone, with the verifier written from the text
python3 air_verify_independent.py --key out/operator-public-key.pem out/air-0.cose out/air-1.cose
```
The CI (`../run.sh`) checks the pinned schema's digest, then runs both after the `aer1-decision` case, with the
Standard it cloned there.
