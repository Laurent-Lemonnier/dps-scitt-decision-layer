# Case 18: one chain

One payment action, a refund of 120.00 EUR on order 8812, runs through the four Internet-Drafts put to the IETF 127 SCITT
adoption discussion of 18 November 2026, in the order Darren Wright proposed on 6 November: the agent's run
(draft-thaha-scitt-agent-execution-evidence-02), the person's decision (Decision Provenance Standard, the subject of
draft-lemonnier-scitt-decision-provenance-01), the auditor's verdict (draft-wright-verdict-record-02), the dispute
packet (draft-xg-payment-dispute-profile-01, a vendor profile of draft-farley-acta-signed-receipts-03). Each format
records a different moment; none is changed; each is verified by the verifier its own text yields; twelve joins across
the four say what no single verifier says. The same chain is run twice: executed as approved, and 150.00 EUR executed
for 120.00 approved. Seventeen failing cases, each the valid chain changed in one place, fail where expected.

Everything here is synthetic: test keys from fixed seeds, fixed times, no real payment, no real person. Two runs write
the same bytes. An assistant wrote the code and the first draft of this README; Laurent Lemonnier read both.

**Who has seen what.** Links 1 and 3 reuse the code of cases 17 and 16, which their authors (Thaha, Wright) have been
sent and are reviewing; nothing in those two links is new here beyond the scenario. Link 4 is Laurent Lemonnier's
composition from the Goshi and Farley texts alone, with no code of either author read and no review by either author:
it shows one way the packet can carry the chain, not the way ActaSeal's implementation does. The sixteen-entry
ambiguity log below is where that composition made choices the text does not make.

## The chain

| link | record | built by | verified by | proves | does not prove |
|---|---|---|---|---|---|
| 1 | six hash-chained Execution Receipts: task_start, inference, a tool_call `payments.refund.create` whose decision is `confirm`, its `allow` outcome (confirm_seq 2, transaction id key 25), the tool_result, task_end; each a Signed Statement in a Bundle | `../agent-execution-evidence/build.py` (case 17), the tool and arguments set to this scenario | `aee_verify_from_text.py` (case 17, from Thaha's text): CHECKS_PERFORMED, never PASS (steps 1, 4, 5, 7, 11-17 are not performed) | the Harness recorded that this call, with these argument bytes (request_digest), required confirmation and then proceeded; the agent asked for it (agent_sig) | who confirmed, what exactly, on what evidence: no member of his receipts carries it (6.7; Section 15: approvals "separately recorded") |
| 2 | the decision record, the action-binding attachment as sealed at the approval (A1: proposal, review, outcome) and after the run (A2: + request, recheck, attempt citing the allow outcome by record-hash, result citing the tool_result by record-hash and response digest), the finance controller's `person_approval` over the exact specification whose parameters are the tool arguments | case 17's DPS builders | the Standard's checks (eight dimensions, seal, person signature, trust policy), schemas | the person approved these bytes, before the call proceeded; what was then requested and executed is bound to that approval | that the run happened as the receipts say: it cites them, Thaha's verifier checks them |
| 3 | one verdict record: evidence A1, A2 and the record's file by the SHA-256 of their exact bytes, rule `executed-as-approved:v1`, five inputs bound to evidence, result `executed_as_approved` (positive) or `not_as_approved` (negative) | `../verdict-record/build.py` (case 16) | `verdict.py` (case 16, from Wright's text): released, step 3 re-run equal to the stated result | a third party re-derived, from the bytes cited, that what executed is what was approved (or is not) | anything about the person: that the approval verifies is the Standard's check, read by the rule as a format rule |
| 4 | a dispute packet: one Farley decision receipt populated per Goshi Section 3 (`type actaseal:policy_decision`, decision `allow`, `scope_conformance`, `action_hash`, `ledger_entry_hash`, `rail_anchors_hash`, …; Ed25519 over the JCS payload), a manifest with `agent_anchors` (approval event = the typed digest of A1), further anchors (the verdict record, the signatures attachment, the two receipts by record-hash), the intent scope and executed action, a `settlement_anchor` recording what moved, the CE 3.0 / FPT categories with gap notes; a five-event ledger slice; the FRE 901 wrapper (acquisition, custody bound to ledger events, authentication statement) | `build.py` here, from the text | `goshi_from_text.py` (here, from the Goshi and Farley texts): VERIFIED, eight checks, every failure named | the receipt is the merchant's (signature over canonical bytes, key out of band); the scope headline is re-derived, not asserted; the settlement block's hash and the ledger's hashes recompute; custody closes on the ledger | that the verdict it cites was released, that the person it names approved, that the receipts it names verify: the packet verifier holds digests, the other three verifiers hold the bytes |

Positive chain: Thaha CHECKS_PERFORMED; DPS A1 and A2 verified on every dimension, seal and approval verified; verdict
released (`state released; step 1 PASS; step 2 PASS; step 3 PASS`); packet VERIFIED, `scope_conformance in_scope`,
settlement 120.00 EUR. Case 17's seven joins J1-J7 between links 1 and 2 are true as well.

Stated negative chain (`out/stated-negative/`): the tool door hashed and executed 150.00 EUR where the person approved
120.00. Thaha's J1 is false (the confirm receipt's request_digest is not the approved parameters); the Standard's
`action_binding` dimension fails on A2; the auditor's verdict stating `not_as_approved` is released by the checker (the
re-run agrees); the packet states `BREACH:amount_minor`, the verifier re-derives the same from the intent scope (120.00)
and the executed action (150.00), the settlement anchor records 150.00 EUR moved, and the packet VERIFIES: it is an
honest packet about a breach. The twelve joins hold on it too (K8 reads: moved ≠ approved and the BREACH names the amount).

## The joins (K1-K12, `build.joins`)

What none of the four verifiers says alone. Every one is a comparison of values already present in the records.

- K1 one action digest end to end: the confirm receipt's request_digest (Thaha key 12) = SHA-256 of the parameters of the
  specification the DPS attempt names = the packet's `action_hash` = its `executed_action_sha256`; the intent scope the
  packet re-derives from has the digest of the approved specification's parameters, whose digest the person signed. The
  parameters' keys are in sorted order so that the Harness's compact JSON and the packet's JCS are the same bytes.
- K2 approval before allow in every record of it: the person's `signed_at` and o1 at the same moment, after the confirm
  receipt and before the allow outcome; the ledger's ApprovalRecorded event names that moment and precedes ActionExecuted;
  ActorValidated precedes the approval.
- K3 what executed is cited by record-hash in three places: the DPS attempt and result, the ledger's ActionExecuted event
  (both record-hashes and the response digest), the packet's further anchors; the settlement `txn_ref` is the outcome
  receipt's transaction id (key 25) and the attempt's trace_ref.
- K4 the verdict's evidence is the exact bytes of A1, A2 and the record's file (Wright 2.1, 7); the route 1 statement cites
  A2 and the signatures attachment by the same digests.
- K5 the verdict's result is the re-run's and the Standard's: `executed_as_approved` exactly when A2 verifies on all
  eight dimensions natively; `not_as_approved` exactly when `action_binding` fails.
- K6 the packet's approval event is our attachment: `agent_anchors.approval_event_hash` is the typed digest of A1's
  exact bytes, the same hex as the verdict's evidence[0] and the ledger's ApprovalRecorded event; the signatures
  attachment anchor is the route 1 statement's reference; the packet verifier resolved the anchor against the bytes held.
- K7 the packet cites the verdict the checker released, by the digest of its bytes, and its `scope_conformance` says what
  the verdict's result says (`in_scope` ⇔ `executed_as_approved`, `BREACH:amount_minor` ⇔ `not_as_approved`); the packet
  verifier re-derived the same headline.
- K8 what moved is what the result stage observed: the settlement amount = the executed specification's amount = the
  ActionExecuted event's amount = the manifest's headline; = the approved amount in the positive chain, ≠ in the negative,
  where the BREACH names `amount_minor`.
- K9 the custody chain closes on the ledger: every custody event bound to a ledger event that recomputes; the receipt's
  `ledger_entry_hash` is the ApprovalRecorded event, whose data are the digests of A1 and the signatures attachment held.
- K10 one person in every link: the receipts' principal (Thaha 3) is the pepper hash of the canonical identifier of the
  person o1 names; the ledger's ActorValidated event and the packet's identity category name that identifier.
- K11 the moments are in order: task_end < A2 sealed < verdict act_time < the checker's intake (upper bound) < the packet's
  issued_at; the settlement was captured after the result stage and before the packet.
- K12 four verifiers, the same bytes: CHECKS_PERFORMED, the seal verified, the verdict released, the packet VERIFIED, and the
  hex digest of the verdict in the checker's report is the one the packet cites.

## The failing cases (`negatives.py`, 17/17 where expected)

Each is the valid positive chain changed in one place. "Expected" lists where the case must be caught; a case may also
fail elsewhere (K12 summarises, so it fails in most). Where a link says nothing, that is recorded as the finding.

| case | changed | caught by |
|---|---|---|
| N1 approval of other arguments, everything downstream claims as approved | executed 150.00, verdict states `executed_as_approved`, packet asserts `in_scope` | Thaha J1 false; DPS `action_binding` failed; verdict refused at step 3 (re-run `not_as_approved`); packet SCOPE_HEADLINE_MISMATCH (re-derived `BREACH:amount_minor`); K5, K7 |
| N2 verdict altered after the packet cited it | the verdict re-issued one second later | packet ANCHOR_UNRESOLVED; K7 |
| N3 settlement 150 with headline 120 | the rail witnessed 150.00 | packet SETTLEMENT_HEADLINE_MISMATCH (this verifier's name); K8 |
| N4 confirm without approval | no person signature, o1 still claimed | DPS person_approval absent; J2, K2. Thaha's receipts cannot see it; the packet verifies |
| N5 packet cites another verdict about the same chain | the anchor names a verdict held but refused (it states the other result) | K7 only: the packet verifier resolves the digest and says nothing about the verdict's state |
| N6 custody event altered | one `ledger_event_hash` changed | packet CUSTODY_EVENT_UNBOUND; K9 |
| N7 ledger event altered after chaining | the ActionExecuted amount changed | packet LEDGER_EVENT_HASH_MISMATCH (the next event still links to the stale hash); K8, K9 |
| N8 settlement content changed, hash stale | the block's amount changed, `anchor_hash` not | packet SETTLEMENT_ANCHOR_HASH_MISMATCH (and the headline mismatch); K8 |
| N9 manifest without settlement block | | packet SETTLEMENT_UNANCHORED; K3, K8, K11 |
| N10 receipt payload edited after signing | `scope_conformance` → `not_evaluated` | packet RECEIPT_SIGNATURE_INVALID, SCOPE_HEADLINE_MISMATCH; K7 |
| N11 receipt signed by a key not the issuer's | | packet RECEIPT_SIGNATURE_INVALID |
| N12 issuer_id not the kid | | packet RECEIPT_ISSUER_KID_MISMATCH (Farley 2.2); the signature itself verifies |
| N13 A2 altered after the verdict cited it | observed succeeded → failed in the bytes held | verdict held (step 2: evidence[1] not held); K5, K7, K12. The packet anchors on A1, not A2, and verifies |
| N14 dispute reason code missing | | packet DISPUTE_REASON_CODE_MISSING (Goshi 4.1: the mapper MUST raise) |
| N15 approval after the allow outcome | signed at 10:01:19, outcome at 10:01:18 | J2, K2; DPS `stage_order` and `record_statements` failed; verdict refused (the rule reads the dimensions). Thaha's receipts alone cannot see it |
| N16 one approval used twice | a second confirm/allow/tool_result triple (txn `…-8812-2`) in the run, a second request, recheck, attempt and result resting on o1 (`request_limit` 1), the packet citing the same approval event for two transfers (`additional_executions`, a second settlement anchor) | DPS `action_binding` failed first (rule 5: `q2: o1 covers 1 request(s), already used by q1`; the specification requested twice); verdict refused at step 3 (re-run `not_as_approved`: no approval covers the second attempt); packet APPROVAL_EVENT_CITED_TWICE (it sees the duplicate, not whether a limit allows it); K5, K7. Thaha CHECKS_PERFORMED and J1-J6 true: each receipt is fine on its own, the run alone cannot see it (J7 false by its wording only: two signed confirms, not one) |
| N17 money moved, nothing recorded | a settlement anchor for 120.00 EUR (txn `…-0931`, final) with no confirm/allow receipt, no DPS request or attempt, no verdict: approval event null, `further_anchors` empty, intent scope and executed action null | packet NOTHING_RECORDED, a result of its own (not VERIFIED, not a BREACH: scope `not_evaluated`); K3, K6, K7 (and K1, K2, K8-K10: no record to join). Thaha CHECKS_PERFORMED, DPS verified, verdict released: their documents are the recorded refund's and name no such transfer; they have nothing to say |

**What N17 shows: the absent record.** The AUDIT charter discussion (Mirja, correctover) separates three outcomes a verifier can
reach: denied (a record says no), could not be determined (a record exists and does not settle it), nothing recorded (no record
at all). The first fifteen cases and N16 are of the first two kinds: a document is present and fails, or a verifier holds a
document and cannot decide. N17 is the third: money moved and no link recorded a decision about it. Links 1 to 3 cannot raise it,
not by weakness but by construction: Thaha's receipts, the Standard's attachment and Wright's verdict each verify what they hold,
and they hold nothing about this transfer; in `out/negatives/N17…/` their documents are those of the recorded refund and verify
as in the positive chain. Only the dispute layer holds the settlement, so only the packet can state that nothing stands behind it;
the verifier's third result, NOTHING_RECORDED (this module's name, like `additional_executions` and APPROVAL_EVENT_CITED_TWICE
in N16), keeps that statement apart from a pass and from a breach. N16 is the mirror: every link holds a document, and the
first to see the second use is the one whose rule counts requests (action binding rule 5, `request_limit`); the packet sees
one approval cited twice and cannot know whether a limit allowed it; the run sees two well-formed pairs and nothing wrong.

## The Goshi/Farley link, from the text: ambiguity log

The full log is `goshi_from_text.AMBIGUITIES` (sixteen entries, written to `out/summary.json`). By section:

- **3, canonical form.** The payload is strings, null, objects and arrays with amounts as decimal strings, so JCS and
  sorted-key compact JSON coincide; the verifier uses the latter, extended to integers below 2^53 (JCS formats those the
  same way) so that the intent scope keeps the chain's integer amounts and hashes to the same bytes. Floats, booleans
  and non-BMP keys are refused rather than claimed JCS.
- **3, `action_hash`.** Not defined. Farley's `action_ref` hashes {agentId, actionType, scopeRequired, timestamp}, a
  different thing. Here: the SHA-256 of the executed action's argument bytes, which is what the other three links hash.
- **3, `evidence_set_hash`, `ledger_entry_hash`, `rail_anchors_hash`, `key_id`, `signer_pubkey_hash`, `timestamp`.** Named,
  not constructed. Each is given one construction (see the module); `rail_anchors_hash` = the settlement `anchor_hash` is
  the reading that makes Section 5's "headline consistency across manifest, receipt" checkable at all.
- **3, `mandate_hash`.** The AP2 mandate. A chain whose mandate is a person's signed approval has no source for it: null,
  as 4.2 does for the network token and the 3DS result. Whether null is allowed there is not said.
- **4.1.** Three categories, gap notes, "MUST NOT invent evidence", a missing dispute reason code MUST raise: no field
  names. Here `{category: {populated, value, gap_note}}`; one identity data point (the ActorValidated login), as the text
  says the implementation holds.
- **4.2, approval event hash.** Named with no construction and no type. Here a typed digest `{type, alg, digest}` so a
  verifier knows which bytes to look for; the type is this repository's namespace. Which field a BREACH names when several
  differ is not said (here: the first in sorted order); what intent scope and executed action look like is not said (here:
  JSON objects in the manifest, each bound by digest to an item the packet cites).
- **4.3.** `anchor_hash` "a canonical hash of the anchor content": SHA-256 of the block without `anchor_hash`. Which
  headline the settlement amount is compared with is not said: here `manifest.headline.amount_minor`, and the mismatch is
  named SETTLEMENT_HEADLINE_MISMATCH, this verifier's name.
- **4.4.** Described, not specified: acquisition `{captured_by, captured_at, tool, clock_source, gaps}`, custody
  `[{event, at, actor, ledger_event_hash}]`, authentication statement `{re_derivable: [...]}`; Section 7's "host clock
  MUST be declared untrusted" is checked as a word in `clock_source` or an `external_time_anchor`.
- **5, failure names.** SCOPE_HEADLINE_MISMATCH, SETTLEMENT_ANCHOR_HASH_MISMATCH and SETTLEMENT_UNANCHORED are the text's;
  the forty other codes this verifier can emit are its own, each marked `named_in_text: false` in the report.
- **Farley 2.1.** The envelope shape only; the flat shape (2.1, 6.6) is refused, not verified.
- **Farley 9.8.** "Decisions are not executions": the receipt's `decision allow` records permission; what executed is in
  the settlement anchor, the ledger slice and, outside the packet, in the DPS result stage and Thaha's tool_result. The
  packet's `timestamp` is the moment of the allow outcome, its `issued_at` the moment the packet was signed.

New for Thaha and Wright (beyond the logs of cases 16 and 17): none in their texts. One reading of ours: the outcome
receipt's transaction id (Thaha key 25) is joined to the settlement `txn_ref` (K3); his text does not name the namespace
of that id, so the join is this repository's.

## What each author's draft would need

Nothing, for the chain to be built as it is here: a verdict record cites our attachment's bytes as they are; a decision
record's attempt cites Thaha's outcome by record-hash as it cites any trace; Goshi's agent anchors take a typed digest
where his text says "approval event hash". What would make the joins checkable by the authors' own verifiers rather
than by this case: in Thaha's receipts, a member for the reference to the approval the confirm required (case 17, route
2, one optional key); in Goshi's text, a construction for `action_hash`, the approval event hash and the ledger event, so
that a second implementation of the profile could compute them.

## Running

```
DPS_STANDARD=/path/to/decision-provenance-standard/standard python3 build.py      # exit 0 when all_verified
DPS_STANDARD=... python3 negatives.py                                            # exit 0 when 17/17 where expected
```

Python 3.12, `cryptography`, `cbor2`, `jsonschema`, `referencing`. Both scripts are deterministic. `out/positive/` and
`out/stated-negative/` hold every document of their chain (the receipts as CBOR and in diagnostic form, the Bundle, the
record, A1, A2, the signatures attachment, the route 1 statement, the verdict record and its container, the dispute
packet and the receipt's canonical payload, the keys) and `summary.json` with the four reports and the joins;
`out/negatives/<case>/` the same for each failing case with `what.txt` and `result.json`; `out/summary.json` the digest
of both chains and the ambiguity log. `PRE-READ-CHAIN-NOTES.md` is the short form for the pre-read.
