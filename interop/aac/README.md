# Interop cases: an Agent Action Capsule citing a decision of the Decision Provenance Standard

Five cases for an interop between two independent implementations: the library of the Agent Action Capsule
(draft-mih-scitt-agent-action-capsule, 0.12.0) with its CPB typed digest references on one side, and the reference
checks of the Decision Provenance Standard (record schema 5.2.0, action binding 0.3.0, signatures 0.2.0, at the
repository's main `bcbe8a6`) on the other. Each case is a folder holding a capsule, the decision record and the
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

What the two sides agree on, and where each stops: a reference that resolves shows only that the cited bytes have the
digest it carries (the Standard's own words); whether the approval inside them is valid is the Standard's check. The
capsule's `approver` and `human_disposed` stay the producer's claim whatever the Standard reports.

## Run

```
export PYTHONPATH=/root/claude-ops/ietf/demo/venv312/site   # the capsule library 0.12.0
P=/root/claude-ops/dps/venv/bin/python                       # jsonschema, cryptography; the Standard at dps/wt-main
$P build_cases.py          # rebuilds cases/ from the invoice example (signed) and the release example (unsigned)
$P check_case.py cases/0*  # both sides on every case; PASS when result matches expected
PYTHONPATH=/root/claude-ops/ietf/demo/venv312/site ./venv-scitt/bin/python cose_case.py   # case 07, both COSE forms (scitt-cose, cbor2)
```

`check_case.py` resolves a reference as a CPB `as-transmitted` context does: it hashes the bytes it received, nothing
re-encoded; for the decision record, the covered bytes (the record's bytes with the seal's value zeroed, byte for byte);
for the attachment, its bytes. It consults the Standard's checks only when every reference resolved, as a verifier
would. The Standard's checks are run unchanged from its repository.

## Findings from case 06, for the call

1. The capsule library's `submit_anchor` (0.12.0) expects the service's `entry_hash` to be SHA-256 of the statement bytes and raises on the service's answer; the service hashes the statement's `Sig_structure` (`entry_hash_scheme: sig_structure`). Registering by hand (`anchor_probe.py`) and verifying the receipt under the service's leaf works: library and service disagree on what a leaf is.
2. The receipt's protected header carries alg -8 (EdDSA), the verifiable data structure (395: 1) and only `iat` in its CWT claims: no `iss`, no `sub`, no `kid`, which RFC 9943 section 6 makes a MUST for a receipt (the library's own docstring says so).
3. The Standard's anchoring 0.2.0 pins alg -19 (Ed25519, RFC 9864) for statements and receipts and reports -8 as `not_supported`; it needs `kid` on the receipt, and reads the inclusion proof at label 396 key -1 as `[tree-size, leaf-index, path]`. The proof shape is the right one; the algorithm label and the missing `kid` are what keep a DPS verifier from reading this receipt as it stands. Whether anchoring should also admit -8, or the service move to -19, is a question for both Steward and author.

## Open with Steven Mih (call of 29 October 2026)

- JSON capsules, as here, or COSE envelopes with the `cpb-refs` protected header; if COSE, which tool makes the envelope.
- AAC -06 listing the two artifact-type declarations, so that the capsule library resolves the references itself.
- Where the cases live (one shared repository), and the hackathon report at IETF 127.

Not yet here: a COSE-enveloped capsule (the library's producer envelope, EdDSA, over the capsule_id, and the `cpb-refs`
header); the anchoring extension's witness checkpoint registered as a statement in a service and its receipt read by
anchoring's check. These are the next steps, after the call.

`anchor_case.py` is the library's own path (it raises on finding 1); `anchor_probe.py` does the same steps by hand and
writes every artefact of case 06.
