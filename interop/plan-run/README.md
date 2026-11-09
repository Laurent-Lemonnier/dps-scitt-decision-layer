# One plan approved as a whole, executed as steps — 2026-10-31

An office manager at a brokerage onboards a client. The onboarding assistant compiles a plan of three steps from a
use case and the client's brief: create the onboarding document, create the CRM record with it, tell the onboarding
channel. The manager sees the plan and approves it once, as a whole. The runtime executes the three steps, one after
the other; two of them carry arguments that did not exist when the plan was approved (the document's identifier, the
CRM record's identifier), written in the plan as references to an earlier step's outputs.

This directory carries that run two ways, with existing texts and existing code, nothing changed in either, and one
object of its own between them:

| Layer | Text | What it records here |
|---|---|---|
| WHO: who approved what | Decision Provenance Standard, action binding 0.3.0 and signatures 0.2.0, main at `007f8c9` | the decision record; **one specification, the plan** (its steps and their hash), proposed by the assistant, shown, approved once and signed with `person_approval`; one request, recheck, attempt and observed result for the plan as a whole; the issuer's seal over the attachment |
| WHAT: what happened | Agent Action Capsule format 4, draft-mih-scitt-agent-action-capsule, library 0.16.0 (0.15.0 from 7 to 9 November 2026, 0.12.0 before) | **one capsule per step**, citing the decision record and the state of the run's context it ran under (`ran_under`), each chained to the step before it (`chain.relation: follows`) |
| the mother | `out/plan-run-manifest.json`, a provisional shape of this repository (`net.isoluce.plan_run` 0.1.0), of neither text | names the approved specification and its plan hash; lists, for each step of the plan, the capsule that executed it, the request it sent, the outputs it recorded, and the state of the context before and after it; the DPS result names it by its digest, under the issuer's seal |

The data is synthetic: a plan of the shape a broker's runtime runs, with no real client, document or person. The keys
are test keys.

## The point

The authorisation has the granularity of the plan; the execution has the granularity of the step. The Standard says
what a person approved (one specification, exactly) and that the plan was requested once; the capsule says what one
step did. Neither says how a verifier holding one approval and N capsules tells that a capsule is step *i* of that
plan, that no step is missing, that none ran outside it, that they ran in its order, or what was approved for an
argument that only exists after an earlier step ran. The joins below say it, from the bytes held; the manifest is
what they need, and it is the only thing here that neither text provides.

Three readings this case fixes:

- **A plan is approved on its executable steps.** The specification carries `plan_hash`, the hash of the steps in
  order (operation, target, arguments), and the policy held (`out/policy.json`, signed through `policy_version`) says
  that is what an approval of a plan rests on. A plan whose hash is not that of its steps is refused before anything
  runs (N5).
- **A reference is approved as a reference.** An argument written `{"$ref": "steps[0].outputs.document_ref"}` is
  approved as that reference, not as a value. The executor substitutes the output step 0 recorded, and the verifier
  checks that the recorded output is the one step 0's own capsule committed to (`response_digest`). So a step whose
  every argument was literal in the plan is one a person disposed of (`human_disposed: true`); a step with a resolved
  argument was authorised by the plan's approval, and its capsule says so (`human_disposed: false`, `approver: human`).
- **The context grows one step at a time, and each step reads the state just before it.** The run starts from an
  initial context (tenant, client, use case, brief); after each step the state is the digest of the state before it,
  the step and the outputs it recorded (`context_after = H(context_before, step, outputs)`). The manifest carries
  every state; each capsule cites, as `ran_under`, the state it read; and since each capsule commits to its own
  outputs, the whole chain recomputes from what the capsules committed to. A capsule that cites a state other than
  the one just before it, or a link that does not recompute, is refused (N13, N14).

## What verifies (`out/summary.json`)

- Schemas: the record (Core v1.3 rev. 11, reference files 5.2.0), the attachment, the signatures attachment and the
  trust policy, no error.
- DPS action binding: all eight dimensions verified; the one specification verified; the report says the plan was
  `shown_to_reviewer` and requested once; the issuer's seal of kind attachment verified (`issuer_recorded_claims_only`).
- DPS signatures: the manager's `person_approval` verified against the verifier's trust policy.
- Capsules: 3 of 3 parse and verify with the library; every reference resolves against the record held or a context
  state recomputed from the manifest held. The library reports that chain parent-existence is a store-level check it
  does not run; the joins run it against the capsules held.
- Joins, which neither check makes:
  1. the approved plan's `plan_hash` is the hash of its executable steps;
  2. the manifest names the approved specification, the same plan hash and the approval stage;
  3. the DPS result names the manifest held, by its digest;
  4. every step of the plan has exactly one capsule whose request is that step, with the arguments the plan resolves
     from the outputs recorded, and the manifest lists that capsule at that index;
  5. no capsule run under this decision is a step outside the plan;
  6. the steps ran in plan order: the manifest lists them in it, each capsule follows the previous step's capsule, and
     the issuer's times do not go backwards;
  7. an argument resolved from an earlier step's output equals the output that step recorded, which its own capsule
     committed to;
  8. a capsule says a person disposed of a step only where every argument of that step was literal in the plan;
  9. the context grows one step at a time: each state recomputes from the state before it and the outputs that step's
     capsule committed to, the manifest carries every state, and each capsule cites the state just before it;
  10. the specification names the plan policy by the digest of the policy held.

## The failing cases (`negatives.py`, `out/negatives/summary.json`)

Each case is published as a directory `out/negatives/<case>/` holding the documents the verification ran on, as they were at that moment (`<name>.json`; where the bytes as issued are also an input, `<name>.as-issued.json` beside it), the description (`what.txt`) and, apart from them, the verdicts (`result.json`); `summary.json` gathers the verdicts. Layout adopted on 3 November 2026 after an outside reading found the cases could not be rerun from the published verdicts alone.


Each is the valid run changed in one place.

| Case | Change | Caught by | What the check says |
|---|---|---|---|
| N1 | the CRM step has no capsule; the manifest lists it | join 4 | a step of the plan has no capsule |
| N2 | the message is sent before the CRM record exists | joins 6 and 9, the capsules' references | the capsules and the manifest are out of plan order; the context states they cite were never produced in it |
| N3 | a capsule citing this decision executes another client's step | join 5 | a step outside the plan |
| N4 | the CRM record is created with another legal name | joins 4 and 5 | no capsule is the approved step; one is outside the plan |
| N5 | the approved plan carries a `plan_hash` that is not the hash of its steps | join 1 | the person signed a plan that does not describe its steps |
| N6 | the DPS result names another manifest | the issuer's seal, join 3 | the attachment changed after sealing; the manifest held is not the one named |
| N7 | the manifest records another document than step 0's capsule committed to; the later steps carry it | join 7 | the recorded output is not what its capsule committed to |
| N8 | the CRM step runs twice | join 4 | two capsules for one step |
| N9 | the message's capsule says a person disposed of it | join 8 | two of its arguments were resolved at run time |
| N10 | the plan is requested a second time under the same approval | DPS action binding | `o0 covers 1 request(s), already used by q0` |
| N11 | a fourth step, not in the plan, runs after the third | join 5 | a step outside the plan |
| N12 | the CRM step's capsule cites another decision record | the capsules' references, join 4 | the reference does not resolve; the step has no capsule run under this decision |
| N13 | the message's capsule cites the context before the CRM step, not the state after it | join 9 | the capsule read a state other than the one just before it |
| N14 | the manifest's context after the CRM step is not the state before it plus that step's outputs | join 9 | the link does not recompute from the outputs its capsule committed to |

## What it shows, and what it does not

It shows that one exact approval can cover a plan without a review per step and without a blanket "run whatever
follows": the person signs the steps' hash; each step's capsule is joined to one step of that plan by the request it
executed; completeness, membership, order, the provenance of run-time arguments and the growth of the context are
checked from the bytes held; and the manifest that makes this possible is bound to the sealed attachment by its digest. It does not show that the
person read the plan, that the effects are what the executor observed (`effect_attestation` is `runtime_claimed`),
or that a step the executor ran and did not record exists: the joins see the capsules held, and a capsule left out
of the export is invisible to them (an export's completeness is anchoring's question, not this case's).

## The question this case asks the capsule's author

The capsule cites the decision it ran under (`references[]`, `ran_under`); it cannot say which step of a plan it is,
nor that another step is missing. Here that is said by the manifest and checked by the joins. Section 5.5.5 of the
capsule draft keeps `chain.relation` for same-stream transitions and sends every cross-stream citation to
`references[]` with a `citation_purpose`, new purposes being registrations; so the question is not a new relation but
this: is "step *i* of this plan" a `citation_purpose` worth registering (the capsule naming the plan it is a step of,
by digest), or is it the "layer above" of the composition draft (section 6.2), to be defined there and never in the
capsule? Either answer is fine; this case works with the current text and needs nothing changed in it.

## Neighbouring texts, read for this case

- **draft-zambo-aer1-26, section 8 (workflow receipts)**: an ordered list of step receipts under one goal, with a
  Merkle root over the sequence (`seq-output-v1`) and the final output's hash, assembled after the run; step pages
  point to the parent workflow. It is the closest shape to the manifest here, from the other side: it binds what ran,
  not what was approved, carries no arguments, no context states and no approval. The two compose: the manifest's
  step list could carry that Merkle construction, as `aer1-decision/` already composes a record with a receipt.
- **draft-schrock-ep-bounded-execution-program-00**: a signed, finite DAG of nodes, each binding an exact action (a
  CAID and an action digest) or a pinned action-matching profile, with dependencies on predecessors' terminal outcomes,
  occurrence ceilings and budgets; replanning is a new signed version, never an edit. This is the CAN-slot form of
  "a plan approved as a whole", and the nearest text to this case. What it does not carry is what the second reading
  above needs: an argument that exists only after an earlier node ran is, there, a profile-mode node with
  authenticated match evidence; here it is a reference the person approved as such, resolved from a committed output.
- **draft-schrock-ep-authorization-receipts-13**: "a dynamic plan expansion beyond the approved action or trusted
  effect envelope requires a new bundle" — the rule N11 enforces.
- **draft-mih-sato-agent-accountability-composition-01, section 6.2**: "was this authorization sufficient for this
  action" is a layer above the composition; joins 4 to 9 are that layer for a plan.
- **draft-sharif-agent-audit-trail-05**: a session as a hash chain from a genesis record to a close record, no
  branching, child sessions by delegation; ordering without a plan.
- **draft-kuehlewind-audit-architecture-01, section 7.1**, and **draft-farley-acta-signed-receipts-03**: an audit
  context propagated as identifiers (`trace_id`, `parent_id`; `parent_session_id`) across sub-agents; correlation, not
  a committed state.
- **draft-luna-eagf-agent-delegation-semantics-00, REQ-3**: material context must survive a delegation or handoff and
  its transfer must not be assumed; the context chain here is one way to show it did.

## Where this comes from

The author's runtime has executed plans this way for some time: a parent that carries the context, the plan and the
authorisation, children that carry one step's result each, and, since the spring of 2026, an approval that carries
the hash of the plan's executable steps and a resumed run that refuses a plan whose hash changed (the deployment
bullet of draft-lemonnier-scitt-decision-provenance-01, section 11). That runtime is private; nothing of it is in
this directory. This case is a projection of that shape onto the two public texts, built from them, with synthetic
data; the manifest is what the projection needed and found in neither.

## Reproduce

```sh
# cryptography, jsonschema, asn1crypto, agent-action-capsule==0.16.0, and the Standard at 007f8c9
DPS_STANDARD=/path/to/standard python3 build.py
DPS_STANDARD=/path/to/standard python3 negatives.py
```
The CI (`../run.sh`) runs both against the Standard pinned in `../aqta/approval-record/DPS_STANDARD_COMMIT`. Without
the capsule library, the capsule side is reported not checked, never verified. The build is deterministic: the same
bytes in `out/` on every run.
