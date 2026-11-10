# A real AER-1 receipt and a decision record, composed — 2026-11-10

Built at the request of the author of draft-zambo-aer1, who sent a receipt his service issued that morning and asked:
"compose it with a decision record ... and tell me what joins and what does not".

| | Real or synthetic | Here |
|---|---|---|
| The receipt | **Real.** Issued by zambo.dev on 10 November 2026 at 10:51:44.721Z, `live_price`, symbol BTC, recorded value $74,135.08; id `e9106453-b8b2-4784-992b-1211bfc1a353`, sent by Brennan Zambo on 10 November 2026 | `receipt.json`: the bytes served by the public API (`https://zambo.dev/api/receipt/<id>`, API version 1), unchanged; digest, URL and retrieval time in `SOURCE.txt` |
| The decision | **Synthetic**, test keys: "read the BTC price through live_price for a valuation", Decision Provenance Standard action binding 0.3.0 and signatures 0.2.0 at main `007f8c9` | two variants, `out/after-the-fact/` and `out/under-the-decision/` |
| The receipt of variant (b) | **Synthetic**, built here in the real one's layout, never issued by zambo.dev; its committed output text starts with "SYNTHETIC, not issued by zambo.dev" | `out/under-the-decision/aer1-receipt.SYNTHETIC.json` |

The receipt is read with the AER-1 verifier written from the text of draft-zambo-aer1-26 (`../aer1/aer1_verify_independent.py`).
No code of the author's is run, and nothing is fetched: the Nostr anchor and the upstream evidence are described, not checked.

## The receipt (`out/receipt-verification.json`)

| Check | Result |
|---|---|
| `output_hash` (Section 4, Section 6 step 3) | **verifies**: sha256 of the 669 decoded canonical bytes is `56114d61…a9ed6ac2` |
| `metadata_hash` (Section 3.1, Section 6 step 4) | **verifies**: the block recomputed from id, created_at, tool, provenance class, schema version and output_hash gives `d750472d…66cd4bbd` |
| version and provenance class inside the canonical bytes | equal to the outer members (`0.4`, `EXECUTED BY ZAMBO`) |
| id | lowercase UUID, version 4 with RFC 4122 variant bits (strict tier); `id_verdict` **matched** against the id in the author's mail, which is the issuer's own channel (Section 6: it binds the record to the issuer's assertion and no further) |
| `verification_status` | `"commitment_matches"`, not Table 1's `"verified"`: Section 6 names it as the passing value of the deprecated version 1 API, which served this record. The verifier, as written, therefore **rejects** the receipt as is (`rejected: verification_status is not verified`) |
| `input_hash` (Section 3.3) | **not confirmed**: the canonical bytes record no input, and the layout is named (`input_hash_layout: zambo-json-sorted-keys-utf8-v1`), not published in the receipt. Read from its name (sorted members, no whitespace, UTF-8), the input `{"symbol":"BTC"}` taken from `provenance.request` and `job_summary` gives exactly `input_hash`. All three are outside every commitment |
| anchor | the Section 6 report says **absent**: the `anchor` member is in the profile's shape `zambo-receipt-anchor/1`, not Section 10's Table 4. Read offline, its envelope is consistent: `envelope_bytes` is the canonical JSON of `envelope`, which names this id, this `output_hash`, the evidence digest and `anchored_at` = `created_at`. The Nostr event (`3377252b…`, relay `wss://relay.primal.net`) is **not checked**: no relay was contacted |
| issuer | **not authenticated**: draft -26 has no signature in the core, and the receipt's own `checks` say so (`issued_by_zambo_dev: not_checked`) |
| evidence | the upstream response's digest (61 bytes from the Coinbase spot endpoint) equals `provenance.response_sha256`; the bytes were not fetched |

A probe on a copy, with `verification_status` read as `"verified"`, passes the verifier, `input_hash` reported not
confirmed: the receipt's commitments hold; what stops it is the presentation, not the bytes. Until 10 November 2026 the
verifier (`../aer1/aer1_verify_independent.py`) rejected a receipt carrying `input_hash` without recorded inputs;
Section 3.3 only says the commitment must not be reported as confirmed. Corrected while building this case.

## What joins and what does not (`out/summary.json`)

(a) **After the fact.** The record is written after the call, from the receipt read through the public API at
10:57:15Z: the attempt is the real call (dated with the receipt's own `steps[0].started_at`, 10:51:44.650Z), cites the
receipt by id, names its caller, and the result names its `output_hash`; proposal, review and approval come after
(approval at 11:00:00Z), and the reviewer is shown a view that names the receipt. The request and recheck the
attachment requires are dated when written, and the recheck says what happened: `unavailable`, "no recheck before the
call".

(b) **Under the decision.** What it would have taken: approval at 10:45Z, request 10:51:40Z, recheck 10:51:42Z, the
call at 10:51:44.650Z with the DPS `request_id` among its inputs, a receipt of it whose canonical bytes record those
inputs and whose `execution_context` names the record. Shown on a synthetic receipt.

| Join | (a) after the fact, real receipt | (b) under the decision, synthetic receipt | What it rests on |
|---|---|---|---|
| the DPS attempt cites the receipt by id | holds | holds | the issuer's seal over the attachment; the id is in the receipt's metadata block |
| the DPS result names the receipt's `output_hash` | holds | holds | the seal; `output_hash` commits to the canonical bytes |
| the attempt's executor names the caller committed in the receipt | holds, but the caller is anonymous (`ip_ua_30d`, rotates 3 December 2026): a pseudonym, not an identity | holds (a declared service) | the canonical bytes |
| the receipt records the DPS `request_id` (idempotency key) | **absent**: the canonical bytes record no input at all | holds | the canonical bytes, under `output_hash` |
| the receipt's input is the approved parameters | consistent, **unbound**: only through `input_hash`, outside both commitments | holds, bound; `input_hash` confirmed | (b) the canonical bytes |
| the receipt's `execution_context` names the record | **absent** (it names `source`, `environment`, `quota_identity`) | consistent, producer-asserted, not a binding (Section 3.2) | nothing: outside `metadata_hash` |
| the attempt is dated no later than `created_at` | holds (10:51:44.650Z ≤ 10:51:44.721Z) | holds | the issuer's clock against the receipt store's |
| the result naming `output_hash` is dated no earlier than `created_at` | holds (10:57:15Z) | holds | same |
| a review shown the receipt is dated no earlier than `created_at` | holds (10:59Z) | not applicable | the view's digest is in the person's signed bytes |
| approval and effect | **approval after the effect** (11:00:00Z, receipt 10:51:44.721Z) | approval dated before the effect, by the issuer's clock only | no independent timestamp on either side |
| DPS stage order and recheck | **failed**: the attempt is dated before the request and recheck it names; the recheck comes after it and found `unavailable` | verified | the Standard's reference check |

Every other DPS check verifies in both variants: the four schemas, the specification digests and statements, the record
statements, the action binding, the observed result, the rationale timing, the issuer's seal and the valuation lead's
signed approval.

In short: from the DPS side the real receipt is cited and named, and both citations are bound by values the receipt
commits to. From the receipt's side nothing names the decision: no request_id in its committed bytes (they hold no
input), no `execution_context` pointer, and the approval comes after the effect. A record written after the call says
so through its own checks; it is never reported as approved before.

## The failing cases (`negatives.py`, `out/negatives/`)

One directory per case, as in `../aer1-decision/`: the documents the checks ran on, `what.txt`, `result.json`; the
receipt in a case directory is the parsed receipt written out, the bytes as served are `receipt.json` here.

| Case | Change | Verdict |
|---|---|---|
| L1 | the real receipt's committed output says $84,135.08, `output_hash` not recomputed | the receipt: `output_hash` fails |
| L2 | its `created_at` moved to 10:40Z, `metadata_hash` not recomputed | the receipt: `metadata_hash` fails; the time join too |
| L3 | the attempt cites another receipt id (resealed) | the join: id cited |
| L4 | the result names another `output_hash` (resealed) | the join: `output_hash` named |
| L5 | attempt 10:40Z and result 10:45Z, both before the receipt existed (resealed) | the join: a result names an `output_hash` before `created_at` |
| L5b | the attempt dated 10:55Z, after the receipt of the call (resealed) | the join: attempt no later than `created_at` |
| L6 | (a) backdated as a whole: approval 10:45Z, an authorising recheck before the call, record, seal and signature made again, the signed view still naming the receipt | the DPS checks pass; the join catches it: a review shown the receipt is dated before the receipt. Order: "contradicted" |
| L7 | (a) with request and recheck re-dated before the call, the approval left after it | the order stays "approval after the effect"; stage order still fails |
| L8 | documented limit: L6 with a view that no longer names the receipt | everything verifies; the order is "issuer dated before the effect", the issuer's statement, never verified: nothing on the receipt's side can contradict it |
| L9 | documented: a holder adds `execution_context.decision_record` to the real receipt | no receipt check changes (Section 3.2); the pointer reads consistent, the request_id is still absent from the committed bytes |
| L10 | documented: `input_hash` replaced by the digest of `{"symbol":"ETH"}` | `output_hash` and `metadata_hash` still verify; only the consistency with the approved parameters turns |
| L11 | (b) a synthetic receipt of the same read under another request_id, cited (resealed) | the join: the committed request_id is not this request's |

## Where the real receipt differs from the draft text

- `verification_status` is `"commitment_matches"`, the version 1 API's value (Section 6), where Table 1 says
  `"verified"`; Section 6 points new clients to `/api/v2/receipt/<id>/verify`, not fetched here.
- The canonical bytes are `{caller, issuer_claims, output, receipt_schema_version, side_effects, tool}`: `output`, not
  `outputs`, and no `inputs`. The kit's reference-producer profile (`inputs`, `tool`, `outputs`) is not met, and
  Section 3.3's input commitment cannot be confirmed from the receipt. The bytes keep non-ASCII characters literal
  (`·`, `▲`): exact bytes, as Section 4 allows, not the escaped Section 7.1 serialization.
- `input_hash_layout` names the layout; Section 3.3 asks the producer to publish it alongside the receipt.
- `anchor` is in the profile's shape (`event_id`, `pubkey`, `relays`, `status`, `published_at`, `envelope`,
  `envelope_bytes`), not Table 4's; its envelope carries `output_sha256` with the `sha256:` prefix where Table 4's
  `anchored_digest` is bare hex. A verifier implementing Section 10 alone reports it absent.
- `execution_context.quota_identity` is not among Section 3.2's members.
- 33 members the draft does not define (it names some kinds as examples, Section 3), from the hosted profile `zambo-hosted-receipt/1` (`schema_url`
  `https://zambo.dev/aer-1/hosted-profile.schema.json`, not fetched): among them `checks`, `provenance`, `evidence_*`,
  `side_effects`, `caller`, `steps`, `job_summary`, `result_preview*`, `free_used`, `free_remaining`, `free_limit`.
  The last three look like the service's quota state rather than the receipt's; whether they change between fetches
  was not tested (one retrieval; the same bytes at `/api/receipt/` and `/api/receipts/`).
- `workflow` (Section 8.6, unbound) names workflow `8ffefd4b…`, step 0; the workflow was not fetched.

## What it shows, and what it does not

It shows what a real AER-1 receipt of today's hosted service commits to, checked from the draft's text, and how far a
decision record can join it: the record can cite the receipt by values the receipt binds, and the record's own checks
report a call made before its approval. It does not show that the price was right, that the issuer is zambo.dev, that
the Nostr event exists, or when anything happened beyond the clocks' own statements; and it does not show that the
call was made for this decision, which only a receipt recording the request_id among its committed inputs could.

## Reproduce

```sh
# cryptography, jsonschema; the Standard at 007f8c9. No AER-1 kit is needed.
DPS_STANDARD=/path/to/standard python3 build.py
DPS_STANDARD=/path/to/standard python3 negatives.py
```
The CI (`../run.sh`) runs both after `../aer1-decision/`.

The receipt is Brennan Zambo's service's; the decision, the second receipt and every key are synthetic test values.
Written with an AI assistant.
