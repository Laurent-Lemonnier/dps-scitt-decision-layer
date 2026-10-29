# One agent pass, three layers — 2026-10-29

An engagement assistant works for one account holder on a professional social network. In one pass it reads the
account's feed, replies and invitations, and proposes 20 likes, 5 invitations and 11 comments; its own rules set five
more actions aside before anyone sees them. The holder approves the likes and the invitations once, as bounds, and each
comment on its own: nine as proposed, one after rewriting it, one rejected. The enforcement point then lets 35 actions
through and records each effect it observes.

This directory carries that pass three ways, with existing texts and existing code, nothing changed in any of them:

| Layer | Text | What it records here |
|---|---|---|
| WHO: who approved what | Decision Provenance Standard, action binding 0.3.0 and signatures 0.2.0, main at `007f8c9` | the decision record; two **standing approvals** (each an exact list of posts or members, a count and a period, signed with `person_standing_approval`); eleven **exact approvals or rejections** of a comment's text (signed with `person_approval` or `person_review`); for each action, its request, its recheck, its attempt and the result observed |
| CAN: what the gate let through | Seal ACTION-v1, draft-chueayen-attestation-receipts-05 | 35 `ALLOWED` records and 5 `BLOCKED` records naming the rule that stopped them |
| WHAT: what happened | Agent Action Capsule format 4, draft-mih-scitt-agent-action-capsule, library 0.12.0 | one capsule per action, citing the decision record and the attachment by CPB typed digest references; `human_disposed` is true only for an action a person approved exactly |

The data is synthetic: it has the shape of a real pass (the same counts, the same kinds of action and of refusal) and
no real person, post or text. The keys are test keys.

## The point

An agent's own log can show that an effect happened. It cannot show that a person approved *that* content. A pass of
35 actions does not need 35 reviews, and it should not get a blanket "the holder said go" either: a like carries no
text, so approving the list of posts, a count and a period is an honest approval; a comment carries text, so the
holder sees and approves each one. The Standard has both forms (action binding 0.3.0, items 3–6 and 9–13), and its
report says which applied to each execution: `shown_to_reviewer` for the 10 comments, `via_standing_approval` for the
25 likes and invitations. The capsule says the same thing in its own vocabulary (`approver: human`, with
`human_disposed` true or false), and the Seal record says what the gate allowed or blocked.

The routine's policy is the issuer's document (`out/policy.json`); its digest is the `policy_version` of every
specification and every bound, so each signature signs it, as the Steward read it on
[#93](https://github.com/decision-provenance-standard/standard/issues/93). It says which operations need an exact
approval. That matters: bounds constrain each parameter on its own, so they cannot say "this text on that post"
(N10 below).

## What verifies (`out/summary.json`)

- Schemas: the record (Core v5.0), the attachment, the signatures attachment and the trust policy, no error.
- Seal: 40 of 40 records valid under the ACTION-v1 verifier written from the text (`../aqta/aqta_verify_independent.py`),
  35 `ALLOWED`, 5 `BLOCKED`.
- DPS action binding: all eight dimensions verified, every specification verified, the record's review log backing
  each of the 13 decisions.
- DPS signatures: 13 of 13 person assertions verified against the verifier's trust policy (2 standing approvals,
  10 approvals, 1 review that rejects).
- Capsules: 41 of 41 parse and verify with the library; every reference resolves against the bytes held.
- Joins across the three, which no single check makes: each `ALLOWED` record has its DPS attempt with the same tool
  and `args_hash` and an observed result; no `BLOCKED` record's arguments were requested; each executed capsule cites
  the executed specification and the observed evidence, and says a person disposed of it only where an exact approval
  exists; each `BLOCKED` record has a capsule with a never-dispatch verdict and no effect; the DPS report and the
  stages agree on how each execution was authorised; every operation the policy lists for exact approval has one;
  every specification and bound names the policy held.

## The failing cases (`negatives.py`, `out/negatives/summary.json`)

Each is the valid pass changed in one place.

| Case | Change | Caught by | What the check says |
|---|---|---|---|
| N1 | a like on a post the bounds do not list | DPS action binding | `outside the bounds of saL: parameter post_ref is outside its constraint` |
| N2 | a 21st like under bounds of 20 | DPS action binding | `saL covers 20 request(s), already used by q0 … q19` |
| N3 | a like at 12:40Z, after the bounds' `valid_until` | DPS action binding | `dated outside the period of saL` |
| N4 | the comment published is not the text approved | DPS action binding | `the requested specification differs from the one approved` |
| N5 | the holder withdraws the likes' approval at 10:36:30Z, the routine goes on | DPS action binding, recheck | `rests on saL after rvL revoked it`; `the recheck authorised a request under saL after rvL revoked it` |
| N6 | a like's capsule says a person disposed of it | the joins | only bounds were approved for that like |
| N7 | an invitation to the member rule R-DECLINED blocked | DPS action binding, the joins | outside the bounds; a `BLOCKED` record's arguments were requested |
| N8 | the holder's signature names bounds of 30 likes, the stage carries 20 | DPS signatures, `subject` | the signature does not name these bounds |
| N9 | the rejected comment is published, citing the rejection | DPS action binding | `rests on o7 (rejected); only an approval or an authorised change authorises a request` |
| N10 | two comments approved as bounds (two posts, two texts) and published with the texts swapped | the joins only | every DPS check verifies: bounds cannot pair a text with a post; the routine's policy, held and signed through `policy_version`, requires an exact approval for comments |

## What it shows, and what it does not

It shows that one approval can cover a batch without pretending a person looked at each action, that the three
records agree where they overlap, and that a verifier holding them all, the routine's policy and its own trust policy
can tell an action a person approved from one the bounds allowed, and either from one nobody allowed. It does not show
that the holder read what was shown, that the effects are what the executor observed (`effect_attestation` is
`runtime_claimed`, the lowest grade), or that the record lists every action the agent took: an export can leave some
out, and the count under a standing approval is of requests recorded.

## Reproduce

```sh
# cryptography, jsonschema, asn1crypto, agent-action-capsule==0.12.0, and the Standard at 007f8c9
DPS_STANDARD=/path/to/standard python3 build.py
DPS_STANDARD=/path/to/standard python3 negatives.py
```
The CI (`../run.sh`) runs both against the Standard pinned in `../aqta/approval-record/DPS_STANDARD_COMMIT`. Without
the capsule library, the capsule side is reported not checked, never verified.
