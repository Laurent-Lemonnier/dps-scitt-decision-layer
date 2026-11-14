# Interop cases: an Agent Action Capsule citing a decision of the Decision Provenance Standard

Eleven cases for an interop between two independent implementations: the library of the Agent Action Capsule
(draft-mih-scitt-agent-action-capsule, 0.16.0 since 9 November 2026, 0.15.0 from 7 November, 0.12.0 before) with its CPB typed digest references on one side, and the reference
checks of the Decision Provenance Standard (record schema 5.2.0, action binding 0.3.0, signatures 0.2.0, at the
repository's main `007f8c9`, 28 October 2026, re-run on 29 October) on the other. Each case is a folder holding a capsule, the decision record and the
action-binding attachment it cites, the signatures attachment and trust policy that travel beside when there are any,
`expected.json` (what each side is expected to report, with the reason) and `result.json` (what each side reported).

| Case | Capsule / CPB | Standard |
|---|---|---|
| `01-valid` | verifies; both references resolve | binding verified; the person's signed approval verified on every dimension |
| `02-altered-reference-digest` | verifies as a document; the record's reference does **not** resolve | not consulted |
| `03-unsigned-attachment` | verifies; both references resolve | binding verified; the approval's signature **absent**, reported as such, never as verified |
| `04-attachment-fails-its-own-check` | verifies; both references resolve (the bytes are the ones cited) | binding **failed**, the signed approval's subject **failed**: resolution is not validity |
| `05-reencoded-record` | verifies; the record's reference does **not** resolve: an `as-transmitted` context hashes the bytes received | not consulted (the seal does not recompute either) |
| `06-transparency-receipt` | the capsule_id registered as a Signed Statement at the capsule library's own Transparency Service (`ts.agentactioncapsule.org`), Receipt returned and verified with `scitt-cose` under the service's leaf | not the Standard's concern here; what anchoring 0.2.0 would say of that receipt is in the findings below |
| `07-cose` | **07a** Producer Envelope (AAC -05 §3.1) over the capsule_id of case 01, produced by us, verified by the library's `verify_producer_envelope` (the library only verifies); **07b** a CPB-bound Signed Statement (CPB -06 §9.3) carrying the two typed references in the protected header `cpb-refs` (label TBD1 → private-use -65537 in the fixture), in `crit`: both references Verified under the Standard's declared contexts; altered digest Failed, extra map key Malformed, refs in the unprotected header nonconforming, a reader that does not understand `cpb-refs` rejects on `crit` | not the Standard's concern: the references resolve to the same bytes as case 01 |
| `08-noa-receipt` | a NOA Mandate receipt (draft-noa-scitt-ai-agent-receipt-01, published vector at commit 6642fb2) bound to the decision it executed: a separate Signed Statement with three typed references in `cpb-refs` (the receipt by the profile's own digest value, `sha256:` + hex over JCS(receipt without `chain.hash` and `sig.value`) = `chain.hash`; the record by its seal; the attachment by its bytes); all Verified; negatives Failed (altered digest, the signed file instead of the object, receipt changed after the reference) | not the Standard's concern here; the receipt's own signature is its profile's check, not run (construction not stated) |
| `14-capsule-cites-another-action` | verifies; both references resolve: valid documents, of another action (the capsule's `effect.request_digest` names a specification the attachment never attempted) | binding verified, the approval verified on every dimension; the **join fails**: `effect.request_digest` is not the `spec_digest` of any attempt stage |
| `15-attachment-reference-missing` | case 01 with the attachment's reference removed and `capsule_id` recomputed by the library: verifies as a document; the record's reference resolves; the attachment's is **missing** | **not consulted**, join not checked: `required_reference_missing:…action_binding_attachment`; the attachment beside the capsule is not one it cites |
| `16-no-references` | case 01 with every reference removed and `capsule_id` recomputed: verifies as a document, cites nothing | **not consulted**, join not checked: both references `required_reference_missing`; never verified |

What the two sides agree on, and where each stops: a reference that resolves shows only that the cited bytes have the
digest it carries (the Standard's own words); whether the approval inside them is valid is the Standard's check. The
capsule's `approver` and `human_disposed` stay the producer's claim whatever the Standard reports.

The join (`check_case.py`, `join`, since 5 November 2026): once both references resolve, the capsule's
`effect.request_digest` must be the `spec_digest` of an attempt stage of the attachment it cites; without an attempt it
is not checked. Neither side checks this alone: case 14 passes the capsule's own verification, the reference
resolution and every DPS check, and only the join catches it. (Numbered 14: 09 is reserved for the checkpoint at
the capsule witness, 10 to 13 for the composed cases beside this directory.)

Required references (since 6 November 2026, after Ivan Nestorov's outside review of that day): the composition runs
only when the capsule carries both typed references these cases expect, `org.decisionprovenancestandard.decision_record`
and `org.decisionprovenancestandard.action_binding_attachment` (draft -01 Section 5), and both resolve. Until then
`check_case.py` gated the Standard's side and the join on `all(r["resolved"] for r in refs.values())`, which holds over
an incomplete or empty reference set: a capsule citing only the record, or nothing, with its `capsule_id` recomputed,
verified under the library, had the Standard's checks run over the documents beside it, and the join reported
`request_digest: verified`. The composition verified against documents present beside the capsule without
establishing that the capsule cited them. Now a reference the capsule does not carry is a failure of its own,
`required_reference_missing:<type>` (`failures` in `result.json`, `required_references` naming each as `resolved`,
`unresolved` or `missing`); the Standard is not consulted and the join is `not_checked`. Cases 15 and 16 are his two
mutations, built from case 01 by `build_mutations.py`; cases 01 to 14 keep their verdicts (`result.json` gains the
`required_references` member and nothing else). This was a finding about this checker, not about the capsule profile.

## What the join establishes, and what it does not

The join establishes specification-digest agreement: the action the capsule records (`effect.request_digest`) is the
specification (`spec_digest`) the cited attachment says was attempted. That is its intended boundary. It does not
distinguish two execution occurrences of one specification: two attempts of the same `spec_digest`, in one attachment
or in two, satisfy it equally.

Telling occurrences apart is the action binding's work, not the join's: each request stage carries a `request_id` the
Standard forbids to reuse, each attempt stage names its request (`request_ref`) and is named by its result
(`attempt_ref`), and an approval covers one request unless it states a `request_limit` (rule 5): a second request of a
specification whose approval covers one is what the Standard's check fails first in case 18's N16 (`one-chain/`,
`q2: o1 covers 1 request(s), already used by q1`). A capsule that must say which occurrence it executed should cite
the attachment's `request_id` (or the attempt's `stage_id`), and a join would then check that the identifier names an
attempt of the cited attachment. No join in this directory reads those identifiers today: the capsule's `action_id`
and `effect.external_ref` are the producer's own names (`urn:example:invoice:request:0901` in case 01, against the
attachment's `luce:idem:invoice-0901`), and nothing compares them. That join is outside these cases' scope.

## Run

```
# the capsule library 0.16.0, jsonschema and referencing in the Python used; the Standard's checkout at 007f8c9
# (interop/run.sh clones it at interop/aqta/approval-record/dps-standard, the default; DPS_STANDARD names another)
python3 -m pip install "agent-action-capsule==0.16.0" jsonschema referencing cryptography
export DPS_STANDARD=/path/to/decision-provenance-standard   # optional when run.sh's checkout exists
DPS_INVOICE_EXAMPLE=/path/to/invoice-example python3 build_cases.py   # rebuilds cases 01 to 05 from the source examples (the invoice example is not in this repository; it clears cases/ first: rebuild 06 to 08 and 14 after it)
python3 build_mutations.py   # cases 15 and 16 from case 01
python3 check_case.py cases/0[1-5]-* cases/1[4-6]-*   # both sides and the join; PASS when result matches expected (06 to 08 have their own scripts)
./venv-scitt/bin/python cose_case.py   # case 07, both COSE forms (scitt-cose, cbor2), with the capsule library on its path
```

`check_case.py` resolves a reference as a CPB `as-transmitted` context does: it hashes the bytes it received, nothing
re-encoded; for the decision record, the covered bytes (the record's bytes with the seal's value zeroed, byte for byte);
for the attachment, its bytes. It consults the Standard's checks only when both required references are cited and
resolved, as a verifier would. The Standard's checks are run unchanged from its repository. Its schemas are validated
with every relative `$ref` resolved against the schema's own file (a `referencing.Registry` built from the files beside
it, never the network: the record schema's `../mode-drift/layer-4-attestation.schema.json`), so that current
`jsonschema` runs it without remote retrieval.

## Replayed by CI

`interop/run.sh` (the GitHub Actions workflow) runs `check_case.py` over cases 01 to 05 and 14 to 16 on every push and
weekly, from a clean machine with `agent-action-capsule==0.16.0` installed and the Standard cloned at its pin, and
fails if any case differs from its `expected.json` or any `result.json` differs from the committed one (`check-ci.log`
is its output). Before 6 November 2026 the AAC cases were not in `run.sh`, although the repository's README said
everything under `interop/` was replayed; Ivan Nestorov's review of that day found both, and the two portability
obstacles he met (a machine-specific default for the Standard's path, the relative `$ref`) are removed above. Cases
06 to 08 are not replayed: 06 registers at the live Transparency Service, 07 needs `scitt-cose` in its own venv, 08
has its own script (`noa_case.py`); their outputs are committed as run.

## Findings from case 06, for the call

1. The capsule library's `submit_anchor` (0.12.0) expects the service's `entry_hash` to be SHA-256 of the statement bytes and raises on the service's answer; the service hashes the statement's `Sig_structure` (`entry_hash_scheme: sig_structure`). Registering by hand (`anchor_probe.py`) and verifying the receipt under the service's leaf works: library and service disagree on what a leaf is.
2. The receipt's protected header carries alg -8 (EdDSA), the verifiable data structure (395: 1) and only `iat` in its CWT claims: no `iss`, no `sub`, no `kid`, which RFC 9943 section 6 makes a MUST for a receipt (the library's own docstring says so).
3. The diagnosis as it stands since 28 October 2026 (`cases/06-transparency-receipt/anchoring-result.json`). The receipt's signature verifies when the entry is taken to be SHA-256(Sig_structure(statement)) and the leaf SHA-256(0x00 || entry): that is the service's construction, and not the RFC 9162 leaf over the statement's bytes that anchoring 0.2.0 takes. Since the merge of Standard PR #91 on 28 October, the anchoring reference accepts a -8 receipt under an Ed25519 service key, with a deprecation finding; a statement stays pinned to -19. Its check of this receipt now stops on the missing `kid`. The missing mandatory headers (finding 2) and the different entry construction are separate issues. The first version of this finding said the reference reported -8 as `not_supported`; that is no longer the case.

## Open with Steven Mih (call of 29 October 2026)

- JSON capsules, as here, or COSE envelopes with the `cpb-refs` protected header; if COSE, which tool makes the envelope.
- AAC -06 listing the two artifact-type declarations, so that the capsule library resolves the references itself.
- Where the cases live (one shared repository), and the hackathon report at IETF 127.

Not yet here: a COSE-enveloped capsule (the library's producer envelope, EdDSA, over the capsule_id, and the `cpb-refs`
header); the anchoring extension's witness checkpoint registered as a statement in a service and its receipt read by
anchoring's check. These are the next steps, after the call.

`anchor_case.py` is the library's own path (it raises on finding 1); `anchor_probe.py` does the same steps by hand and
writes every artefact of case 06.
