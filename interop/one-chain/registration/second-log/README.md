# One record, two logs: the same four Signed Statements on a second Transparency Service (14 November 2026)

During the IETF 127 Hackathon, Steven Mih registered the four Signed Statements of this folder, unchanged, on the
log he operates, https://witness.agentactioncapsule.org, on 14 November 2026 between 19:33:52 and 19:33:59 UTC. He
sent the four receipts, which are kept here as received and published with his agreement. The same bytes are on ts.isoluce.net as leaves 0, 1, 2 and
32 (see `../README.md`).

| Signed Statement | Leaf index | Tree size | Entry (SHA-256 of the Sig_structure) | Receipt (SHA-256 of the file) |
|---|---|---|---|---|
| `action-binding-attachment-a1` | 23909 | 23910 | `a8e680512533f5a91c8f10b058f999dc09ff84dff83b144312039a43f4a19f7d` | `3e2ec5807069b36b66eca33af5b10f18d9e7f079c4dac86ada92d2c8a463606c` |
| `action-binding-attachment-a2` | 23910 | 23911 | `fe538388eb1573598d54bdd5020da6fc3fd77084ecd246732c0d14cdc3cb75db` | `fe5458b51f8e267dd806b09da704b182dd2d9649144160330e319a4c3367caf0` |
| `verdict-record` | 23911 | 23912 | `49a7159ecb07be9b014cf16bad1bdcdd7b346190432fecba4dc7765b2566ee28` | `6e9a8df44949f67d70adb6bbf01143644db45fde05aa4151f7d18e8313d0adf9` |
| `dispute-packet` | 23912 | 23913 | `1a5c49194a428800b8756a7213b0b3f509912e04b4a1a2a3d3fba02cac33a601` | `66b0455312bb8dfacdd95c9c6ad48797111fde0e91ea2ddb91364224fdebb606` |

## What was checked here

`verify_witness.py`, written from RFC 9162 section 2.1.3.2 and the operator's description of the entry, with no
code of the operator read or run. For each statement: the entry recomputed from our own file equals the one the
operator stated; the leaf is SHA-256(0x00 || entry); the inclusion proof leads to a root; the receipt's Ed25519
signature verifies over that root under the key the service publishes (`witness-did.2026-11-14.json`, fetched on
14 November 2026, `did:web:witness.agentactioncapsule.org#19a9ab3e02fad55c`); the index and tree size are those
stated. Two negative controls per receipt, another leaf and one flipped bit in the proof, are rejected. Output:
`result.txt`. All four verify.

## What it shows, and what it does not

It shows that two logs run by two different operators each state that these exact bytes were registered, and that
the second operator's four receipts verify from outside. It does not show anything about what the statements say,
nor that the two logs are independent in any stronger sense than having different operators and keys.

Nor does it establish the leaf indexes and tree sizes in the table. A receipt's signature covers the root, not the
tree size, which sits in the unprotected header; the same path reaches the same root under several sizes, and, with
the size free, under other indexes (scitt@ietf.org, "RFC 9942 inclusion receipts: tree-size is not authenticated by
the signed root", 15 November 2026). The check above compares them with what the operator stated; it does not bind
them. For ts.isoluce.net the binding is available: its signed tree heads (`/checkpoint.cose`) carry the size and the
root under the service key, and its receipt reader checks a receipt against one (`--checkpoint`). Since 15 November
2026 the receipts of ts.isoluce.net also repeat, in their protected header, the tree size and the leaf index (labels
-65537 and -65538, private use; by default, `?signed-size=0` for the earlier form): the signature then binds them
without a checkpoint. Here,
no signed tree head of the second log was checked.

## The reverse check, as the second operator reports it

Steven Mih wrote on 14 November 2026 (23:16 UTC) that the four receipts of ts.isoluce.net for the same statements
verify on his side: the leaf is SHA-256(0x00 || the bytes of the statement), the inclusion proofs of leaves 0, 1, 2
and 32, in a tree of 33, reach the same signed root, and the Ed25519 signatures (`alg` -19) verify under the key
ts.isoluce.net publishes. He made that check with a script of his own written from RFC 9162, and said he would
confirm it on his hosted verifier once its fix is deployed. This is his report; his script and its output are not in
this repository.

## Differences found between the two services

Reported at the operator's request.

- Leaf definition. Here the entry is SHA-256 of the statement's Sig_structure and the leaf is SHA-256(0x00 || entry);
  ts.isoluce.net uses SHA-256(0x00 || the bytes of the Signed Statement). The same statement has a different leaf
  on each log, so a receipt cannot be checked without knowing which rule the service follows.
- Receipt headers. These receipts carry `alg` -8 (EdDSA, deprecated by RFC 9864 in favour of -19), `vds` 1 and an
  `iat` claim, and no `kid`, `iss` or `sub`; the verifier has to be told which key to use.
- The operator reports that its hosted verifier does not parse Signed Statements with `alg` -19, which these four use.

The operator confirmed these three points on 14 November 2026 and said both are filed on his side: the parsing of
`alg` -19 in the hosted verifier (scitt-cose#108, a fix merged and being deployed), and `kid`, `iss`, `sub` and -19
on the receipts (capsule-anchor#92). The issue numbers are as he gave them; they were not opened by us.
