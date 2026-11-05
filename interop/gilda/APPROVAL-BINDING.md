# approval-binding/v1 read against the DPS action binding — 1 November 2026

`approval_binding_verify_independent.py` is a verifier of the `approval-binding/v1` contract written from the text
that defines it, the README of `vectors-approval-binding` in `agent-evidence-vectors` ("The checks, in order", 1 to
11), importing nothing from the package and sharing no code with its reference reader. Run on the corpus's 23 cases
(6 controls that allow, 17 that deny, each one binding changed), at releases 0.31.0 and 0.28.0 (same corpus digest):
**23 of 23 agree with the manifest on the decision and the reason**, by our judge and by the corpus's own harness
driving the verifier through its command-line contract (`record.json --json`, exit 0 allow, 1 deny).
Reports: `judge-approval-binding-20261101-0.31.0.json`, `-0.28.0.json`; log: `run-approval-binding-20261101.txt`.

The contract asks one question: is this approval the right approval for the use in front of the verifier? The DPS
action binding asks the same question of a specification and the stages that bind it. The table maps the eleven
checks onto the Standard's rules and cases (action binding 0.3.0 and signatures 0.2.0 at main `007f8c9`), with the
two places where the Standard has no analogue stated as such.

| # | approval-binding/v1 check (reason when it fails) | Where the DPS carries it | Status |
|---|---|---|---|
| 1 | the record carries `contractId` (`contract_id_missing`) | the attachment's `profile` and `profile_version`, required by the schema (`execution-evidence.schema.json`) | meets |
| 2 | `contractId` is the v1 contract (`contract_id_unknown`) | `profile: dps-action-binding`, `profile_version: 0.3.0`, fixed by the schema; another version is refused (schema cases) | meets |
| 3 | no other presented approval has the same identifier with different content (`approval_id_ambiguous`) | stage identifiers are unique in an attachment (schema), one outcome binds one `approved_spec_digest`, and "a core field backs at most one outcome" (rule 4; L62, L63) | meets with note: the DPS has no presentation list; ambiguity is impossible inside one attachment rather than detected |
| 4 | the identifier is not already consumed (`approval_replayed`) | "an approval covers one request unless it states a `request_limit`" (rule 5); `request_id` unique in the attachment, sent as the idempotency key (L30, L31, L59, L60); for bounds, `max_requests` (S21) | meets with note: the count is of requests recorded in the attachment, not of a consumed set held elsewhere (README, "Standing approvals") |
| 5 | the approver's trusted key is the approval's key (`key_not_bound`) | signatures: the person's `key_ref` resolves only in the verifier's trust policy, to a `holder` in role `person`; `identity` is verified only when the holder is the actor the issuer names (verifier rules 1 and 4; N27, N31, N69) | meets: the same check, with the key list on the verifier's side, never in the record |
| 6 | the use's principal is the approval's; a client identifier does not stand in (`principal_mismatch`) | not carried: the DPS binds an approval to a specification, not to a principal who may use it; the executor is named (`executor_ref`) and the person who approved is the one who was shown the specification (rule 4, L35), but no stage names a using principal | **gap**: a different model (the approval follows the action, not the user); a deployment that needs the user in the binding puts the principal in the specification's parameters, which the person then signs through its digest |
| 7 | the use's event and phase are the approved ones (`event_phase_mismatch`) | the specification's `operation` (rule 2), and the stage kinds: a request, a recheck before the attempt, the attempt (rules 11 to 13; L26: a recheck after the attempt fails); "pre-execution" is the recheck before the attempt | meets with note: the phase is the order of the stages, not a member |
| 8 | the used tool, target and payload bytes are the approved ones (`payload_mismatch`) | `spec_digest` over the exact bytes of `operation`, `target`, `parameters` (rule 2; L12, L13, L14: amount, target, destination changed; D06, D07: re-serialised bytes) | meets: the same check, over the whole specification rather than three members and a file |
| 9 | used at or after issued and before expiry (`approval_outside_validity`) | for a standing approval, `valid_from` and `valid_until` in the signed bounds (S22, S16); for a single approval, a `valid_until` the deployer declares material in the specification (the Steward's reading of #93): it stays the deployer's member, signed with the specification and enforced at the executor's recheck; the reference check does not read it, and will not under 0.3.0 (the Steward on #94, 5 November 2026) | **partial**: carried for bounds, declared but not checked for a single approval (the WHO table's B-5) |
| 10 | the policy lookup succeeded; a failed lookup is not a match (`comparison_unavailable`) | the recheck stage's `result` (`authorised`, else the request fails: L24, L25, and L07 where nothing is attempted; no case uses `unavailable`, which fails the attempt the same way at `authorisation_recheck`; corrected 5 November 2026 after the Steward's reading on #94, the earlier L19 and L20 being executions after a rejection and an escalation) and the report's rule that `unavailable` and `not_checked` are never verified (G04, L39, portable verification) | meets: the same refusal to read "not checked" as "matched" |
| 11 | the policy release was served at decision time, within grace (`release_not_served_at_decision`) | `policy_version` as the digest of the policy held (#93) and the recheck's `authority_source_ref`: the policy is pinned by content, not by a service window | **gap**: the DPS has no served-window members (`firstServedAt`, `lastServedAt`, `graceSeconds`); it asks which policy bytes, not when they were served |

Five meet, three meet with a note, one partial, two gaps. The two gaps are two models, not two oversights: the
contract binds an approval to a user, an event, a phase and a policy service window; the Standard binds it to the
bytes of a specification and the digest of a policy, and leaves who may use it and when the policy was served to the
deployment. A shared profile, which the corpus's author proposed, would say which of the two readings each member
follows; this table is the input to that decision, not the decision.

## Readings the contract leaves to the verifier

Stated in the verifier's docstring: "the approval" is `record.approval`, and a use naming another identifier is not a
listed check; "different content" compares every member; the payload file is read beside the record and hashed with
SHA-256; times are instants. None of these readings changed a verdict in the 23 cases.

## Two things to report to the author

- The `contractId` the records carry, `https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v1`,
  does not resolve (GitHub Pages 404 on 1 November 2026): the contract text lives in the corpus README, and a verifier
  that followed the identifier would find nothing.
- Check 3 says "different content" without saying which members count: a second presentation that differs only in a
  member the contract does not read (say, a comment) is ambiguous under a whole-object comparison and not under a
  member-by-member one. The corpus's case changes the payload digest, so both readings agree today.
