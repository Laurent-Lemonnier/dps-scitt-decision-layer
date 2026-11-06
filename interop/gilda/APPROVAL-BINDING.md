# approval-binding/v1 read against the DPS action binding — 1 November 2026, extended 7 November 2026

`approval_binding_verify_independent.py` is a verifier of the `approval-binding/v1` contract written from the text
that defines it, the README of `vectors-approval-binding` in `agent-evidence-vectors` ("The checks, in order", 1 to
11 at release 0.31.0), importing nothing from the package and sharing no code with its reference reader. Run on the
corpus's 23 cases (6 controls that allow, 17 that deny, each one binding changed), at releases 0.31.0 and 0.28.0 (same
corpus digest): **23 of 23 agree with the manifest on the decision and the reason**, by our judge and by the corpus's
own harness driving the verifier through its command-line contract (`record.json --json`, exit 0 allow, 1 deny).
Reports: `judge-approval-binding-20261101-0.31.0.json`, `-0.28.0.json`; log: `run-approval-binding-20261101.txt`.

**7 November 2026.** The text grew to sixteen checks at release 0.35.0 (36 cases, 8 allow, 28 deny: the use must cite
the approval checked, supersession by an accepted replacement, renewal by replacement, a closed effect) and PR #472
(not yet merged) adds a 37th case and says which members check 4 compares. The verifier was extended from that text
alone, in the README's order, the reference reader still unread; the readings it takes are in its docstring and below.
Run on the four corpora: **36 of 36 (0.35.0), 37 of 37 (PR #472), 23 of 23 (0.31.0) and 23 of 23 (0.28.0) agree
with the manifest on the decision and the reason**; the corpus's own harness driving the verifier answers 36 of 36 at
0.35.0 with 0 disagreements. The eleven cases the 1 November verifier allowed (25/36) are each refused on the member
the manifest's edit names, by the check the text names. Reports: `judge-approval-binding-20261107-0.35.0.json`,
`-pr472.json`, `-0.31.0.json`, `-0.28.0.json`; log: `run-approval-binding-20261107.txt`.

The contract asks one question: is this approval the right approval for the use in front of the verifier? The DPS
action binding asks the same question of a specification and the stages that bind it. The table maps the sixteen
checks onto the Standard's rules and cases (action binding 0.3.0 and signatures 0.2.0 at main `007f8c9`), with the
places where the Standard has no analogue stated as such. The rows are numbered as the 0.35.0 text numbers them; a
row carried over from 1 November keeps its text and gives its 0.31.0 number in brackets; the rows added on
7 November 2026 (3, 6, 7, 8, 14) are marked so.

| # | approval-binding/v1 check (reason when it fails) | Where the DPS carries it | Status |
|---|---|---|---|
| 1 | the record carries `contractId` (`contract_id_missing`) | the attachment's `profile` and `profile_version`, required by the schema (`execution-evidence.schema.json`) | meets |
| 2 | `contractId` is the v1 contract (`contract_id_unknown`) | `profile: dps-action-binding`, `profile_version: 0.3.0`, fixed by the schema; another version is refused (schema cases) | meets |
| 3 (added 7 Nov.) | the use's `approvalId` is the approval's; a use naming another approval, or none, is not judged against the one presented (`approval_not_cited`) | a request rests on the stage it names: `authorised_by` is required of every request (schema) and names "the approval, authorised change or standing approval this request rests on"; the executor executes "through a request that names that approval, change or standing approval" (executor rule 1); the verifier checks that the requested digest agrees with the approved one and that no request rests on a rejection or an escalation | meets: the same join, by stage identifier instead of `approvalId`; a request naming no approval is not a valid request, and one naming another approval is judged against that one |
| 4 [3] | no other presented approval has the same identifier with different content (`approval_id_ambiguous`) | stage identifiers are unique in an attachment (schema), one outcome binds one `approved_spec_digest`, and "a core field backs at most one outcome" (rule 4; L62, L63) | meets with note: the DPS has no presentation list; ambiguity is impossible inside one attachment rather than detected |
| 5 [4] | the identifier is not already consumed (`approval_replayed`) | "an approval covers one request unless it states a `request_limit`" (rule 5); `request_id` unique in the attachment, sent as the idempotency key (L30, L31, L59, L60); for bounds, `max_requests` (S21) | meets with note: the count is of requests recorded in the attachment, not of a consumed set held elsewhere (README, "Standing approvals") |
| 6 (added 7 Nov.) | no replacement accepted at or before `usedAt` has taken the approval's place (`approval_superseded`) | no stage replaces an approval of the same specification: a second approval of one digest adds to it ("however many approvals and changes bind one specification, the requests for it number at most the largest `request_limit` any of them states", rule 5; the binding cases accept "a renewed approval"); a changed specification goes through an authorised change that "uses up one request of the approval or change it names" (rule 6, schema `change_authorisation`), so the earlier approval is spent, not superseded; `supersedes` (Core §5.1(3), §6.2.3) replaces a whole affirmed record, retained in full, not one approval inside an attachment; a withdrawn standing approval is a `standing_revocation` (rule 12), and the live state of any authority is the executor's recheck before the attempt (rule 11; executor rule 2) | **gap**: the Standard has no accepted-replacement object between two approvals of one specification; the effect the check wants (A refused once B is accepted) is where a deployment's recheck says `not_authorised`, which fails the attempt (L24, L25) but is a runtime result, not a record-level check; for a different specification the change spends the earlier approval (rule 5 count) |
| 7 (added 7 Nov.) | a use claiming `authorityForm: renewed` has a transition accepted at or before `usedAt` whose successor is the approval; one accepted after the use does not establish it (`renewal_transition_missing`) | no claim member: a request's `authorised_by` is at once the claim and the reference, and the verifier checks "that each stage comes after the stages it names" (a request before the approval it rests on, a change dated before its `from_ref`, fail: "execution before approval", "a review naming a proposal dated after it"); a change is a `change_authorisation` stage with its own `at`, `from_ref` and a different `spec_digest` | **partial**: the time half meets (a stage counts from its own `at`, and nothing rests on a stage dated after it); the object half has no analogue over equal bounds, where the Standard's renewal is a second review and outcome on the same digest and no stage joins them |
| 8 (added 7 Nov.) | that transition binds successor to predecessor: the predecessor's decision cited, two distinct decisions, equal bounds, the presented records under the predecessor's identifier agreeing (`renewal_binding_invalid`) | distinct decisions: "a review has one outcome" and "a core field backs at most one outcome" (rule 4; "two approvals backed by one core field" detected, L62, L63); equal bounds: both outcomes bind the one `approved_spec_digest` over the exact bytes (rules 2, 4), stronger than six members equal; the predecessor cited: only in a change (`from_ref`, required by the schema; "a change names a different specification" is checked), never between two approvals of one digest; agreeing records: stage identifiers are unique (schema), so a predecessor cannot be presented twice | meets with note: each binding has a rule, through other members (the digest for the bounds, `core_ref` uniqueness for the two decisions, `from_ref` for the citation, but only when the specification changes); the transition as an object, over equal bounds, does not exist in the Standard, and `decisionId` is the Standard's `core_ref` rather than a member of the approval |
| 9 [5] | the approver's trusted key is the approval's key (`key_not_bound`) | signatures: the person's `key_ref` resolves only in the verifier's trust policy, to a `holder` in role `person`; `identity` is verified only when the holder is the actor the issuer names (verifier rules 1 and 4; N27, N31, N69) | meets: the same check, with the key list on the verifier's side, never in the record |
| 10 [6] | the use's principal is the approval's; a client identifier does not stand in (`principal_mismatch`) | not carried: the DPS binds an approval to a specification, not to a principal who may use it; the executor is named (`executor_ref`) and the person who approved is the one who was shown the specification (rule 4, L35), but no stage names a using principal | **gap**: a different model (the approval follows the action, not the user); a deployment that needs the user in the binding puts the principal in the specification's parameters, which the person then signs through its digest |
| 11 [7] | the use's event and phase are the approved ones (`event_phase_mismatch`) | the specification's `operation` (rule 2), and the stage kinds: a request, a recheck before the attempt, the attempt (rules 11 to 13; L26: a recheck after the attempt fails); "pre-execution" is the recheck before the attempt | meets with note: the phase is the order of the stages, not a member |
| 12 [8] | the used tool, target and payload bytes are the approved ones (`payload_mismatch`) | `spec_digest` over the exact bytes of `operation`, `target`, `parameters` (rule 2; L12, L13, L14: amount, target, destination changed; D06, D07: re-serialised bytes) | meets: the same check, over the whole specification rather than three members and a file |
| 13 [9] | used at or after issued and before expiry (`approval_outside_validity`) | for a standing approval, `valid_from` and `valid_until` in the signed bounds (S22, S16); for a single approval, a `valid_until` the deployer declares material in the specification (the Steward's reading of #93): it stays the deployer's member, signed with the specification and enforced at the executor's recheck; the reference check does not read it, and will not under 0.3.0 (the Steward on #94, 5 November 2026) | **partial**: carried for bounds, declared but not checked for a single approval (the WHO table's B-5) |
| 14 (added 7 Nov.) | the effect the use's `effectKey` names is not `CONSUMED` or `UNCERTAIN_CLOSE` in `effectRegistry`; a new grant does not reopen a closed effect (`effect_already_closed`) | consumed: `request_id` unique in the attachment, "MUST NOT run a second request with the same `request_id` as a new action", sent as the idempotency key where the target accepts one (executor rule 3; L30, L31); uncertain: the observed result `indeterminate` "when the outcome cannot be established, as after a timeout", and "a result is never inferred from the attempt" (executor rule 4; the report carries it through as recorded, and a missing result as missing); "a retry is a new attempt, with its own recheck" (executor rule 2), bounded by the request count (rule 5) | **partial**: both closings exist, as the identity of the request and as a recorded `indeterminate` that nothing turns into "nothing happened"; but the Standard has no effect key across approvals: a new approval may give a new `request_id` for the same logical effect, and only the target's idempotency key, outside the record, would refuse it; a deployment that needs the effect in the binding names it in the specification's parameters, so that the retry is the same digest and counts under rule 5 |
| 15 [10] | the policy lookup succeeded; a failed lookup is not a match (`comparison_unavailable`) | the recheck stage's `result` (`authorised`, else the request fails: L24, L25, and L07 where nothing is attempted; no case uses `unavailable`, which fails the attempt the same way at `authorisation_recheck`; corrected 5 November 2026 after the Steward's reading on #94, the earlier L19 and L20 being executions after a rejection and an escalation) and the report's rule that `unavailable` and `not_checked` are never verified (G04, L39, portable verification) | meets: the same refusal to read "not checked" as "matched" |
| 16 [11] | the policy release was served at decision time, within grace (`release_not_served_at_decision`) | `policy_version` as the digest of the policy held (#93) and the recheck's `authority_source_ref`: the policy is pinned by content, not by a service window | **gap**: the DPS has no served-window members (`firstServedAt`, `lastServedAt`, `graceSeconds`); it asks which policy bytes, not when they were served |

On 1 November, over eleven checks: five meet, three meet with a note, one partial, two gaps. The two gaps are two
models, not two oversights: the contract binds an approval to a user, an event, a phase and a policy service window;
the Standard binds it to the bytes of a specification and the digest of a policy, and leaves who may use it and when
the policy was served to the deployment. A shared profile, which the corpus's author proposed, would say which of the
two readings each member follows; this table is the input to that decision, not the decision.

On 7 November, over sixteen: six meet (1, 2, 3, 9, 12, 15), four meet with a note (4, 5, 8, 11), three partial (7, 13,
14), three gaps (6, 10, 16). The five new checks add a third difference of model: the contract records a renewal as an
object (a `transitions` entry with a status, an acceptance time, two approvals and two decisions) and an effect as a
registry entry; the Standard records a renewal as a second review and a second outcome over the same digest, each
backed by its own core field, and a change of specification as a stage that spends one request of the approval it
names. The time rule (nothing counts before its own time; nothing rests on a stage dated after it) is common to both.
What the Standard does not have, and the contract does: an accepted replacement that retires an unexpired, unconsumed
approval of the same bytes (6), and an effect key that outlives the approval that reserved it (14).

## Readings the contract leaves to the verifier

Stated in the verifier's docstring. On 1 November: "the approval" is `record.approval`, and a use naming another
identifier is not a listed check; "different content" compares every member; the payload file is read beside the
record and hashed with SHA-256; times are instants. None of these readings changed a verdict in the 23 cases.

Added 7 November 2026, for checks 3, 4, 6, 7, 8 and 14 (the text at 0.35.0 and PR #472):
- check 3: a use with no `approvalId` member, or one that is not a string equal to the approval's, is "a use that names
  another approval, or none"; the 1 November reading (not a listed check) is withdrawn, the text now listing it;
- checks 4 and 8 compare presented records as parsed JSON values over the whole object, unread members included: for
  check 4 this is now PR #472's own wording; for check 8 the text says only that the records "must agree";
- a replacement, for checks 6 and 7, is a `transitions` entry with `status` exactly `accepted` and a readable
  `acceptedAt` at or before `usedAt` ("a transition counts from `acceptedAt` on"): a proposed transition, one with
  no or an unreadable `acceptedAt`, counts never; an unreadable `usedAt` places no transition at or before the use,
  so check 6 passes, check 7 fails, and check 13 fails later on the same member; `mode` is read as this suite's only
  policy (`exclusive-replacement`) and not tested, the text giving no other value to test against;
- check 7 applies only when `use.authorityForm` is exactly the string `renewed`; every accepted transition that
  establishes the approval must then bind under check 8;
- check 8, read from "Renewal by replacement": at least one presented record carries the predecessor's identifier and
  all that do are equal; the transition's `predecessorDecisionId` is that record's `decisionId` and its
  `successorDecisionId` the approval's; the two `decisionId`s are present and distinct; the predecessor and the
  approval agree on `event`, `payloadSha256`, `phase`, `principal`, `target` and `tool`; the validity window is the
  successor's own and is not compared;
- check 14 passes when the use names no `effectKey` or the registry has no entry for it: the text forbids reopening a
  closed effect and says nothing of a missing one; the 23 cases of 0.31.0 have neither member and still pass.
None of these readings decided a case: each refused case fails on the member the manifest's edit names, and no case
disagreed under them (36/36, 37/37, 23/23, 23/23). A disagreement found honestly would have been recorded here; there
was none to record.

## Where the new checks come from (credit, 7 November 2026)

The README's axis table says where each case class comes from, and this document repeats it so that the credit travels
with the mapping: the check-4 wording (whole-object comparison) and the 37th case `approval-id-reused-unread-member`
come from Sankalp Gilda's PR #472 on probityai/agent-evidence-vectors, in answer to our issue #401 (the second of the
"two things to report" below); the two use-cites cases (`approval-use-cites-predecessor`, `-no-approval`, check 3) come
from AAkhtanin's review of the renewal cases on #292; the renewal cases (checks 6, 7, 8 and the two
`effect_already_closed` cases) come from the approval-renewal thread in aaif/wg-observability-and-traceability#66,
where narko4u asked for the cases and the sequence is AAkhtanin's.

## Two things to report to the author

- The `contractId` the records carry, `https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v1`,
  does not resolve (GitHub Pages 404 on 1 November 2026): the contract text lives in the corpus README, and a verifier
  that followed the identifier would find nothing.
- Check 3 says "different content" without saying which members count: a second presentation that differs only in a
  member the contract does not read (say, a comment) is ambiguous under a whole-object comparison and not under a
  member-by-member one. The corpus's case changes the payload digest, so both readings agree today.
  *7 November 2026:* reported as probityai/agent-evidence-vectors#401; answered by Gilda's PR #472, which writes the
  whole-object reading into check 4 ("compared as parsed JSON values over the whole object, including members the
  contract does not otherwise read") and adds the case `approval-id-reused-unread-member` (a duplicate differing only
  in a `note` member, `approval_id_ambiguous`). Our verifier read it so from the start, and agrees 37/37 on the PR's
  corpus. The first item (the `contractId` URL) stands as reported on 1 November.
