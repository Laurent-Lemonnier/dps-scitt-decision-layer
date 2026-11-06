# Case 17: the proof behind `confirm`

Agent Execution Evidence (draft-thaha-scitt-agent-execution-evidence-02, Shameer Thaha and co-author, November 2026)
and the Decision Provenance Standard (action binding 0.3.0, signatures 0.2.0, main `007f8c9`), composed on the one
point where each leaves off and the other begins. Built on 6 November 2026, before the IETF 127 SCITT session where both
drafts are up for an adoption discussion. An assistant wrote the code and the first draft of this README; Laurent
Lemonnier read both.

## What the two texts say

His Execution Receipt (Section 6.7) records every call an agent makes, hash-chained (6.7.1), with a `decision` among
allow, block, confirm and record. A `confirm` receipt says that "policy required confirmation from a Principal or
operator before the call could proceed"; it "MUST be followed by exactly one tool_call receipt with the same parent_seq,
target, request_digest and Task that records the outcome: allow if confirmation was granted, or block". The outcome
carries `confirm_seq`. Neither receipt has a member for who confirmed, what they confirmed, or the evidence of it;
Section 15 says the prototype has "separately recorded approvals", and Section 10 says "Content MUST NOT be included in
a receipt". His map is closed (integer keys 1 to 29), each receipt is a COSE_Sign1 Signed Statement per Section 6 of
RFC 9943 with a content type of his and the `aee_type` CWT claim, and a Bundle (Section 8) is what a Relying Party
verifies offline (Section 9, eighteen ordered steps).

Our action-binding attachment records the stages of one decision: the specification proposed, the view shown, the
person's signed approval of the exact specification (the outcome stage, with the `person_approval` assertion of the
signatures extension), then the request, recheck, attempt and observed result of its execution. It defines no receipt
and cites execution evidence by digest. The approval stage is the separate record his `confirm` presupposes.

## What is built

`build.py`, deterministic, synthetic, test keys from fixed seeds. The author publishes Appendix A vectors in diagnostic
notation (and the full COSE objects in his repository, not fetched here), but no vector with a confirmation record, so
the run is ours, modelled on his Appendix A.5 scenario (an invoicing agent, a `send_invoice` tool door, a Serving Party
at `api.customer.example`):

- **AEE side.** Six receipts of one Task: seq 0 task_start, 1 inference, 2 tool_call `confirm` (parent 1, request_digest
  over the tool arguments, egress_host, decision_point tool, `agent_sig`), 3 the `allow` outcome (`confirm_seq` 2, same
  parent, target, request_digest and Task; actor_chain, principal_link, txn, call_digest in the HTTP form of 6.7), 4
  tool_result (parent 3, response_digest), 5 task_end. Canonical CBOR (RFC 8949 4.2.1), record-hash per 6.7.1. Each
  receipt is registered individually as a Signed Statement (6.7.4 permits it) with the protected header of Section 5
  (alg EdDSA, content type `application/aee-statement+cbor`, kid, CWT Claims iss, sub = agent_id, `aee_type` as the
  text-string key of 12.2). The six statements and the six receipts form a Bundle (Section 8, keys 1 and 2). No
  Transparency Service: these are Signed, not Transparent, Statements; no Execution Epoch; no Agent Credential, Policy
  Pack, Configuration Integrity or Assurance Statement. `out/aee-bundle.cbor`, `out/receipt-N.cbor`, `out/receipts.diag.json`.
- **DPS side.** A decision record; the attachment **A1** sealed at the approval (proposal by the agent at the moment the
  Harness held the call, review by the finance controller with the view's digest, outcome `approved` with the
  controller's Ed25519 `person_approval` over the specification whose `parameters` are the exact tool arguments the
  Harness hashed into request_digest); the attachment **A2** sealed after the run (A1's stages unchanged, then request
  authorised by o1, recheck, attempt citing the allow outcome by record-hash, result citing the tool_result by
  record-hash and response_digest). `out/decision-record.json`, `out/action-binding-attachment-a1.json`, `-a2.json`,
  `out/signatures-attachment.json`.
- **Route 1, the join by a separate Signed Statement** (our draft, Section 5.4). A COSE_Sign1 by the DPS issuer in the
  shape of RFC 9943 Section 6 (alg, content type of ours, kid, CWT Claims iss and sub = the decision record), whose
  payload carries four typed digest references: A2 and the signatures attachment by SHA-256 of exact bytes, the confirm
  receipt and the allow outcome by their record-hash (his profile's own value, as our 5.4 does for a closed receipt).
  `out/binding-statement.cose`. Nothing in his text changes. It is registered beside his statements, not inside his
  Bundle: see the ambiguity log, item 4.
- **Route 2, a proposal, not his text.** An optional key 30 on the allow outcome receipt, `[ + { 1 => tstr type, 2 =>
  digest } ]`, naming A1 and the signatures attachment (what existed when the outcome was recorded; A2 cannot be named
  there, since A2 names the outcome). Built as a second rendering of the same run under `out/proposal/`, verified only
  by our verifier with that key accepted (`ACCEPT_PROPOSED_KEYS = {30}`), and nowhere else. The record-hashes of
  receipts 3 to 5 differ from the main run's, as they must.

## What is verified

`aee_verify_from_text.py` is written from his text alone (each check names its section; module docstring lists the
coverage): canonical CBOR and the no-float, UTF-8 rules of Section 5; the closed receipt map, required keys,
enumerations and digest shapes of 6.7; `confirm` only on tool_call, `confirm_seq` only on an outcome; the confirm and
outcome pairing (same parent_seq, target, request_digest and Task, one outcome each, no tool_result before an allow
outcome, no Task ending with a confirm pending); the Task rules of 6.7.1 (earlier allow task_start, not ended, same
principal); parent_seq types; the chain (seq by one, prev_hash by record-hash, zero at seq 0); ts non-decreasing;
`agent_sig` as a detached-payload COSE_Sign1 over the canonical receipt without key 15; the Signed Statement header of
Section 5 and the Registration Policy checks of Section 7 that need no other statement (aee_type equals key 1, content
type among 12.1, sub equals agent_id, call_digest only with egress_host); the Bundle shape of Section 8 and, in key 1,
a Signed Statement for every receipt of key 2. The result is **CHECKS_PERFORMED**, never **PASS**: Section 9 says "A
verifier that does not perform a step MUST NOT report PASS", and steps 1 (TS Receipts), 4, 5, 7 and 11 to 17 are not
performed here. This is not a conformance claim.

The same file reproduces Appendix A from the text: the principal digest of A.3, the policy pack digest, record-hash(0),
record-hash(1), record-hash(3) (the allow outcome), principal_link, the HTTP call_digest, the Serving Party's principal
digest and the admission record-hash of A.7 all agree with the published values (9 of 10). record-hash(2) is not
reproducible from the text: it includes the 226 octets of `agent_sig`, which the text elides. The 6.7 pairing rules
hold on his receipts 0 to 3 as written.

The Standard's own checks (its `run_checks.py` for action binding and signatures, its JSON Schemas): A1 verified on the
six dimensions that apply before execution (recheck and results not_checked by design), A2 verified on all eight, the
issuer's seal on both, the controller's approval (signature, subject, key state, identity). Then seven joins:

| | |
|---|---|
| J1 | the confirm receipt's request_digest is the SHA-256 of the approved specification's `parameters`; its target is the specification's operation; its egress_host is the host of the specification's target |
| J2 | the person's approval names the same specification, signed after the confirm receipt and before the allow outcome |
| J3 | the allow outcome resolves the confirm (his rules) and comes after the DPS request stage authorised by o1 |
| J4 | the DPS attempt cites the allow outcome by record-hash, the result the tool_result by record-hash and response_digest, under the seal |
| J5 | the receipts' peppered principal is SHA-256(pepper ‖ canonical identifier of the person o1 names), the pepper obtained from the Harness out of band (`out/harness-pepper.txt`, a test value; his Section 10 keeps it off the TS) |
| J6 | A2 extends A1: the first three stages are A1's unchanged |
| J7 | the agent asked for this call: `agent_sig` on the confirm receipt verifies with the agent key |

Route 1: the statement's signature verifies and all four references resolve against the bytes held (`route1.bound`).
Route 2: both references resolve (`proposal_route2.route2.bound`). A probe places the route 1 statement inside the
Bundle's key 1: his step 3 refuses it (`E_TYPE_MISMATCH`, content type not among 12.1), which is why it lives beside.

## Failing cases (`negatives.py`, 12/12 caught where expected)

| | changed | fails at |
|---|---|---|
| N1 | no person signature behind the claimed `confirm` | DPS approval, J2 |
| N2 | the person approved another specification | DPS, J2 |
| N3 | the approval is dated after the allow outcome and the tool_result | DPS stage order, J2 |
| N4 | the allow outcome's prev_hash is another digest | his verifier, `E_CHAIN_HASH` |
| N5 | the route 1 statement names another attachment | route 1 not bound |
| N6 | one byte of the person's signature | DPS approval |
| N7 | no DPS request and recheck stage behind the executed `allow` | DPS action binding and recheck, J3 |
| N8 | the receipts' principal is another person than the one o1 names | J5 (both sides verify alone) |
| N9 | the tool_result's parent is the confirm receipt, not the allow outcome | his verifier, `E_TASK` |
| N10 | the outcome's request_digest differs from the confirm's | his verifier, `E_TASK` |
| N11 | the Task ends with the confirm pending | his verifier, `E_TASK` |
| N12 | route 2: key 30 names another attachment | route 2 not bound (our verifier only) |

In N4, N9 and N10 the joins that read his verifier's pairing (J3, J7) are also false; that is reported, not required.

## Ambiguity log (his text, by section)

1. **6.7, `confirm`.** Who confirmed, what exactly, and on what evidence is not a member of the confirm receipt or of its
   outcome. "Confirmation from a Principal or operator" is the only description. The pairing can be checked; the
   confirmation cannot. This case supplies that record from outside; the join is J2 and J5.
2. **6.7, deadline.** "Not given before its deadline" is the Policy Pack's deadline; nothing in 6.7 bounds the time
   between the confirm receipt and its outcome, so the approval-after-the-call case (N3) is visible only from our side.
3. **3 and 10, the Principal.** "The canonical identifier of the person (Section 10)": Section 10 does not define the
   canonical form. Appendix A uses the literal `user:alice@example.com`, and it reproduces; this case uses the same
   shape. The pepper is the Issuer's and off the TS, so J5 needs it out of band.
4. **8 and 9 step 3, a foreign statement.** Key 1 "MUST contain" his types; step 3 checks every Transparent Statement for
   the `aee_type` claim and a 12.1 content type. A Signed Statement of another profile in key 1 therefore fails step 3.
   The text does not say so in words; the probe shows it. Route 1 lives beside the Bundle.
5. **5, duplicate keys.** "A payload ... that has duplicate map keys, is malformed": after a generic CBOR decode the
   duplicate is gone. This verifier checks that the canonical re-encoding equals the bytes, which catches ordering and
   non-shortest forms, not duplicates.
6. **6.7, `agent_sig`.** "Detached payload ... whose Sig_structure payload is the canonical encoding of the receipt
   without key 15": external_aad is not mentioned, taken as empty; the alg is not stated (Appendix A's keys are
   Ed25519).
7. **5 and Appendix A, `kid`.** Its value is not defined (8 octets in A.3); taken as opaque.
8. **8, key 2.** The CDDL says `execution-receipt` maps, not byte strings; an individually registered receipt is also the
   payload of its Signed Statement in key 1. This verifier checks that each receipt of key 2 is the payload of a
   statement in key 1 by record-hash.
9. **Appendix A, A.5.** record-hash(2) depends on `agent_sig` octets the text elides, and request_digest `989a65...` is
   over octets the text does not give; both are taken from the text as published.

## What his draft would need

For route 1: nothing. A separate Signed Statement with its own content type, registered on the same Transparency
Service beside his, cites his receipts by record-hash and our attachment by digest; his Bundle, receipts and
Registration Policy are untouched.

For route 2: one optional key on the tool_call receipt (here 30), an array of typed digest references, so that the
allow outcome itself names the record of the confirmation it rests on. His map is closed, so this is a change to the
CDDL of 6.7, to the "Content MUST NOT be included" sentence (a digest is not content), and to the Registration Policy of
Section 7 if the TS is to check anything about it. Everything else in this case runs on his text as written.

## What is not shown

No Transparency Service, so no TS Receipts, no Transparent Statements, no inclusion proofs, no Execution Epoch; no Agent
Credential, Registration, Policy Pack, Configuration Integrity or Assurance Statements, so steps 4, 5, 11 to 17 are not
run and the verdict is never PASS; the JSON alternative encoding of 5.1; admission receipts and Linked Verification
(6.7.2, 6.7.3, 9.1); the author's reference implementation (not fetched, not read). Synthetic data and test keys
throughout; never use them for anything real.

## Run

    DPS_STANDARD=<checkout of decision-provenance-standard/standard at 007f8c9> python3 build.py
    DPS_STANDARD=... python3 negatives.py
    python3 aee_verify_from_text.py        # Appendix A reproduction alone

Needs `cbor2`, `cryptography`, `jsonschema`, `referencing`. Outputs under `out/`: `summary.json`,
`out/proposal/` (route 2) and `out/negatives/<case>/`. Two runs write the same bytes.
