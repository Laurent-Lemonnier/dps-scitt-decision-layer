# A second dispute packet for the one chain, built to the letter of -02 as we read it

The one-chain case (`../`) carries a dispute packet built from draft-xg-payment-dispute-profile-01. That packet is
registered on two logs and is not changed. draft-xg-payment-dispute-profile-02 was posted on 16 November 2026
(`../refs/draft-xg-payment-dispute-profile-02.txt`). This folder holds a second packet for the same fictional action,
the refund of 120.00 EUR on order 8812, built to the letter of -02 as we read it, and the Signed Statement its Section 6
describes. Both were registered on ts.isoluce.net on 16 November 2026 as new entries.

This is one reading of the text by a party other than its author. It is not a claim of conformance: where the text
leaves a choice open, one choice was made, and each is listed below with the sentence that leaves it open.

Everything here is synthetic: no real payment, no real person, fixed times. The receipt key is a test key whose seed
is public. Two runs write the same bytes. Written with an AI assistant.

## What is built (`build.py`)

`build.py` starts from the published packet of the parent case (`../out/positive/dispute-packet.json`, SHA-256
`6ac56ce9…d03d`) and keeps what it records of the action: the intent scope, the executed action, the settlement anchor,
the ledger's six events, the digests of the verdict record and of the other records of the chain. It changes five things:

1. The receipt payload has the eleven members of Section 4 and no other. The parent's receipt also carries `type`,
   `issued_at` and `issuer_id`, the members of the base draft that -01 required.
2. The manifest names `draft-xg-payment-dispute-profile-02` and no base draft.
3. The `ApprovalGranted` event no longer carries `dps_approval`, the pointer to an approval held outside the ledger
   (Section 5: "An approval held outside the ledger is out of scope for this revision"). The ledger is chained again from
   that event on, so five of the six event hashes are new, and with them `ledger_entry_hash` and the approval event hash.
4. The receipt is signed with a key made for this case.
5. The Signed Statement of Section 6 is built: a COSE_Sign1 whose payload is the receipt's canonical bytes, signed with
   the receipt's own key, with the manifest's action identifier as subject.

`out/result.json` (`same_action_as_the_parent_packet`) lists what the two packets have in common (action identifier,
`action_hash`, intent scope and executed action, settlement anchor block, verdict record digest, `scope_conformance`,
the producer-claimed `timestamp`) and what differs (the receipt key, `ledger_entry_hash`).

| File in `out/` | What | Octets | SHA-256 |
|---|---|---|---|
| `dispute-packet.json` | the packet: receipt, manifest, ledger slice, FRE 901 wrapper | 10155 | `09002911476ed6e3a1721da3e1d975b2ce4473bc26ef72eeddc2ca0002538dd6` |
| `dispute-receipt.json` | the receipt envelope `{payload, signature}` in canonical form (JCS), as Appendix A prints its envelope R | 857 | `c9756009db10994587b12730e9c1ac91f3ba54d4d03880d95b341f2160b941f3` |
| `dispute-receipt.canonical-payload.json` | the canonical bytes of the payload member, which the receipt signature covers | 635 | `d107a126d4eb0724e226ba11331289a1a3c58a96f0156bc2d717ce4afdf89bd5` |
| `section-6.signed-statement.cose` | the Signed Statement of Section 6; its payload is `dispute-receipt.json`, byte for byte | 1062 | `e9cf80fb1f0a3c37d25080c878eb8b5ae9ea2775d1e225d0547dbd1449c0d85b` |
| `keys.json` | the test key: seed label, seed, public key, key identifier | | |
| `result.json` | the three reports, the comparison with the parent packet, the readings | | |
| `negatives.json` | the fourteen failing cases | | |

The leaf hash in the form Appendix A states for its own vector, SHA-256(0x00 || R) over the receipt envelope, is
`c515a9d22a2a511eb5bf0360d9fd405d20fbf0e728a14dd3cbea3e0fdfe20c7d` here. It is not the entry on ts.isoluce.net, whose
leaf is the Signed Statement (see Registration).

### The test key

TEST ONLY. As in Appendix A of the draft, the seed is public and must not be used to sign anything other than test
material.

| | |
|---|---|
| Seed label | `dps-scitt-decision-layer one-chain/goshi-02-letter: dispute receipt key (TEST ONLY, public seed) v1` |
| Seed (SHA-256 of the label) | `23d704b4838452acff698034748cb75b7c5c8c61152f3d2911f49d0092eb988c` |
| Ed25519 public key (raw, hex) | `c48b4defbd14d776470a016134b8b02924e481941c08191038e81d31b23794cd` |
| `key_id`, also the COSE `kid` | `one-chain-goshi-02-letter-test-key-1` |

## Three checks

| Check | Code | Result on this packet |
|---|---|---|
| The packet verifier of the parent case, written from the text | `../goshi_from_text.py`, unchanged since commit 0f9ade4 | VERIFIED, 10 checks: signature over the canonical payload with the key resolved out of band, the eleven members, `signer_pubkey_hash`, settlement `anchor_hash`, headline, 6 ledger events, `ledger_entry_hash`, the scope verdict re-derived (`in_scope`), `action_hash`, custody bindings |
| The letter | `letter.check_letter` | VERIFIED, 6 checks: eleven members and no other; every value a string, a boolean or null; the manifest names -02; the manifest carries `receipt_public_key_hex`; the approval event carries the receipt's `action_hash`; no approval held outside the ledger |
| The Signed Statement of Section 6 | `letter.check_statement` | VERIFIED, 5 checks: the payload is the receipt's canonical bytes; the signature verifies with the receipt key; the `kid` is the receipt's `key_id`; an issuer is present; the subject is the manifest's action identifier |

The packet verifier reports, and does not report as checked, what -02 asks it not to: `evidence_set_hash` and
`rail_anchors_hash` are under `signed_not_checked` (Section 5); the acquisition, custody and authentication records are
reported as the producer's claims (Section 8.4). It is given the verdict record and the signatures attachment of
`../out/positive/` and resolves their two digests; the two digests of execution receipts are named and not resolved,
since it is given nothing of that type.

## Choices of reading (`letter.READINGS`)

Each line is a point the text leaves open for this packet, and the one choice made. Where ts.isoluce.net already had a
practice (algorithm, content type, `kid` as a byte string), the choice is that practice.

| | The text | Left open | Choice here |
|---|---|---|---|
| R1 | Section 6: "The Signed Statement is a COSE_Sign1 [RFC9052] whose payload is the receipt's canonical bytes"; Section 3: a dispute receipt is a signature over a canonicalized payload "in an envelope of the form {payload, signature{alg, kid, sig}}" | whether the canonical bytes are those of the whole envelope or of its payload member alone | the whole envelope, in JCS form (857 octets): the receipt is the envelope, and Appendix A gives SHA-256(R) and a leaf hash for its envelope R. The receipt's own signature is then inside the registered bytes |
| R2 | Section 6: "signed with the receipt's own signing key"; Section 4: "Signature: Ed25519, lowercase hex (alg = EdDSA)" | the integer COSE algorithm identifier: -8 (EdDSA) or -19 (Ed25519, RFC 9864) | -19, as the receipts of ts.isoluce.net and the statements of `../registration/` carry. `check_statement` accepts -8 as well |
| R3 | Section 6 names the statement's payload, key, issuer and subject | the content type (COSE header 3) | `application/json`, as the statements of `../registration/` carry for a JSON payload |
| R4 | Section 6: "A party that already trusts the receipt key needs no other key to check the statement"; Section 5: "key_id names that key in the operator's published keyring" | how the COSE_Sign1 names the key | `kid` = the receipt's `key_id`, as a byte string |
| R5 | Section 6: "with the CWT claims issuer set to an identifier the registering party supplies (the receipt payload carries none)" | which identifier | `urn:example:merchant:dispute-desk`, the fictional desk of the packet's acquisition record: the key's seed is public, so the statement is put under no real identifier |
| R6 | Section 4 lists eleven payload members; Section 5: "the receipt fields that bind to other parts of the packet are built as follows", a list that includes `approval_event_hash` and `anchor_hash`; Section 8.2 puts the "approval event hash" in the `agent_anchors` block | whether `approval_event_hash` and `anchor_hash` are members of the receipt payload | no: eleven members, as the vector of Appendix A has; `approval_event_hash` is in the manifest's `agent_anchors` block, `anchor_hash` in its settlement block |
| R7 | Section 8.2: "AP2 mandate_hash"; "Network token id and 3DS/ACS result are part of the block's shape but null when the implementation has no source for them" | whether `mandate_hash` may be null when the approval is a person's and not an AP2 mandate | null, in the receipt and in the `agent_anchors` block |
| R8 | Section 5: "evidence_set_hash and rail_anchors_hash are signed but not re-derived by the reference verifier in this revision; a verifier MUST NOT report them as checked" | what the two values are built from | the parent case's constructions (SHA-256 of the canonical JSON of the sorted digests the packet cites; the settlement `anchor_hash`); signed, not reported as checked |
| R9 | Appendix B: "The packet manifest, the ledger slice and the ledger event hash are named but not yet defined in this document" | their shapes | those of the parent case, which `../goshi_from_text.py` reads. The manifest member `profile`, which names the revision, is ours: the text asks for no such member |
| R10 | Section 5: "action_hash: the canonical hash of the executed-action object recorded in the action's ScopeEvaluated ledger event"; Section 4: "the receipt dict is strings, booleans, null, and nested objects/arrays of the same, with amounts pre-converted to decimal strings before canonicalization" | whether the value domain stated for the receipt also binds the recorded executed-action and intent-scope objects | no: the two recorded objects keep `amount_minor` as the integer the tool door saw (12000), which JCS writes as a plain integer, so that `action_hash` is the digest the other three links of the chain carry. The receipt itself holds strings and null only |

Also ours, as in the parent case: the members of the manifest beyond those the text names (`further_anchors`, the copies
of the intent scope and executed action with their sources, `headline`), and the `VerdictReceived` event of the ledger.

## Failing cases (`negatives.py`, 14 of 14)

Each is the valid packet and its Signed Statement changed in one place. A case is as expected when the places that
fail are exactly the places it names, and no other. `reader` is the packet verifier of the parent case.

| Case | Change | Fails at |
|---|---|---|
| M1 | a twelfth member (`issued_at`), covered by the signature | letter: RECEIPT_MEMBER_NOT_IN_SECTION_4. The reader names the member and verifies |
| M2 | ten members (`rail_anchors_hash` absent), covered by the signature | reader: RECEIPT_MEMBER_MISSING; letter: RECEIPT_MEMBER_MISSING |
| M3 | the manifest names `draft-xg-payment-dispute-profile-01` | letter: MANIFEST_NAMES_ANOTHER_REVISION |
| M4 | the Signed Statement is signed with another key than the receipt's | statement: STATEMENT_NOT_SIGNED_BY_THE_RECEIPT_KEY |
| M5 | the subject names another action than the manifest's | statement: STATEMENT_SUBJECT_NOT_THE_ACTION_IDENTIFIER |
| M6 | the statement's payload is the whole packet file, the form of the parent case's registration | statement: STATEMENT_PAYLOAD_NOT_THE_RECEIPT |
| M7 | the statement's payload is the receipt as indented JSON, not its canonical bytes | statement: STATEMENT_PAYLOAD_NOT_THE_RECEIPT |
| M8 | the statement's payload is the canonical bytes of the parent packet's receipt | statement: STATEMENT_PAYLOAD_NOT_THE_RECEIPT |
| M9 | the statement's payload is the canonical bytes of the payload member alone: the other reading of R1 | statement: STATEMENT_PAYLOAD_IS_THE_PAYLOAD_MEMBER_ALONE. It fails because one reading was chosen, not because the text excludes it |
| M10 | the CWT claims carry no issuer | statement: STATEMENT_ISSUER_MISSING |
| M11 | the `ApprovalGranted` event keeps `dps_approval`, an approval held outside the ledger | letter: APPROVAL_HELD_OUTSIDE_THE_LEDGER |
| M12 | `mandate_hash` is the number 0, covered by the signature | letter: RECEIPT_VALUE_OUTSIDE_THE_STATED_DOMAIN |
| M13 | receipt and statement signed end to end with another key, which the manifest and `signer_pubkey_hash` declare | reader: RECEIPT_SIGNATURE_INVALID, RECEIPT_SIGNER_PUBKEY_HASH; statement: STATEMENT_NOT_SIGNED_BY_THE_RECEIPT_KEY. The letter check, which reads only the packet, passes: the case of Section 11, "without a key resolved out of band, a packet re-signed end to end with another key verifies" |
| M14 | the statement's protected header names alg -7 over an Ed25519 signature | statement: STATEMENT_ALG |

The failure names of `letter.py` are ours. The parent case's failing cases are unchanged and are not repeated here.

## Registration on ts.isoluce.net (16 November 2026)

Two Signed Statements were registered, as new entries. The earlier entries of the one-chain case are untouched.

| Statement | Signed by | iss, sub | Octets | SHA-256 | Leaf | Entry |
|---|---|---|---|---|---|---|
| `out/section-6.signed-statement.cose`, the Signed Statement of Section 6 | the receipt key (the test key above), alg -19 | `urn:example:merchant:dispute-desk`, `urn:example:action:refund-8812` | 1062 | `e9cf80fb1f0a3c37d25080c878eb8b5ae9ea2775d1e225d0547dbd1449c0d85b` | 53 | `431009a9ee3cd08e8fdc18578871fc7a7a3e2eac80ea1f847bf595a17d166490` |
| `registration/dispute-packet.signed-statement.cose`, the file `out/dispute-packet.json` as payload, in the form of `../registration/` | `isoluce-case18-issuer-1`, the issuer key of `../registration/`, alg -19 | `https://isoluce.net`, `urn:isoluce:dps:case-18:dispute-packet-goshi-02-letter` | 10355 | `c1e352055456d8030db26ccb4993766c5d3e6b65732402c247bdb9df76377eae` | 54 | `0d4f366fabcf0fbbba235fa39d460956551e8dbf659f57c273eed055b1b78a66` |

The first is the statement Section 6 describes. The second is not in the text: it is what the parent case does for
its own packet, and it gives the manifest, the ledger slice and the wrapper, which the receipt signature does not
cover, an entry of their own. An entry id on ts.isoluce.net is the hex of the Merkle leaf, SHA-256(0x00 || the bytes of
the Signed Statement). A fresh receipt of an entry is at `https://ts.isoluce.net/entries/<entry id>`.

`registration/section-6.receipt.cose` and `registration/dispute-packet.receipt.cose` are the Receipts the service
returned at registration (tree sizes 54 and 55). `check_registration.py` verifies them offline with the reader of
`../../receipt-size/` against the service key set pinned there on 15 November 2026: the inclusion proof reaches a root,
the signature verifies over that root, and the tree size and leaf index in the protected header equal those of the
proof. Three altered copies of the first Receipt are refused (given the other statement; one bit of its signature
changed; one bit of its inclusion path changed), for Section 6: "A Receipt that is only structurally valid MUST NOT be
reported as verified". The result is in `registration/result.json`.

Two times, reported separately (Section 11): the receipt's `timestamp`, claimed by its producer, is
`2026-11-04T10:01:18.000Z`; the registration time the service states in its Receipt is `2026-11-16T21:34:03Z`. The
first is fictional. The second says that the receipt's bytes existed no later than that moment, as far as the service
is trusted.

The service registers a statement only when its `kid` names a configured issuer. The test key was among the configured
issuers for this registration only and was removed right after: its seed is public, so anyone could sign under it. A
new statement under that `kid` is refused. Nothing was registered on the second log of the parent case.

## Running

```
python3 build.py                 # exit 0 when the three reports say VERIFIED
python3 negatives.py             # exit 0 when 14/14 fail exactly where expected
python3 check_registration.py    # exit 0 when both Receipts verify offline and the three altered ones are refused
```

Python 3.12, `cryptography`, `cbor2`. No network. `build.py` reads `../out/positive/` (the published packet, the
verdict record, the signatures attachment). `../../run.sh` replays the three scripts and requires the committed outputs
to be unchanged.
