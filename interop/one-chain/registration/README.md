# The four records of the one-chain case, as Signed Statements

For anyone who runs a SCITT Transparency Service and wants to register them, and for anyone who wants to check the
receipts of a service that did. Prepared for the IETF 127 Hackathon (14 and 15 November 2026).

## The statements

Each file is a tagged COSE_Sign1 (tag 18) with an empty unprotected header. Its payload is attached and is, byte for
byte, the file of the same name in `../out/positive/`. Protected header:

| Label | Value |
|---|---|
| 1 (alg) | **-19**, Ed25519 as a fully specified algorithm (RFC 9864). Not -8 |
| 3 (content type) | `application/json` |
| 4 (kid) | `isoluce-case18-issuer-1`, as a byte string |
| 15 (CWT Claims) | `{1: "https://isoluce.net", 2: "urn:isoluce:dps:case-18:<name>"}` (iss, sub) |

The signature is over the Sig_structure of RFC 9052 Section 4.4. These statements are signed under kid
`isoluce-case18-issuer-1`. The issuer's public key is `issuer-ed25519.pub.pem`; its raw public bytes are
`bfe07446773cb19de0699bc782ed8e3df489ea9e006dfeffbc11da3b12544771`. This is distinct from the Transparency Service's
receipt verification key and from both public-seed keys in `../../registration-vectors/`. A service must apply its own
authentication and registration policy; please report any refusal and its reason.

| File | Bytes | SHA-256 of the Signed Statement | Entry on ts.isoluce.net |
|---|---|---|---|
| `action-binding-attachment-a1.signed-statement.cose` | 2769 | `67e8c6a5163b866b02413e12f084477b4edb186a73775ccf6c642669c4857323` | leaf 0, entry `03cabe49ce79f40b50e4b0744469dede7fc19123c998474f2fc1d7419634fda8`, registered 8 November 2026 |
| `action-binding-attachment-a2.signed-statement.cose` | 3999 | `8d55eb43663529ec45cc9d1a8409bf9d30373032e019c52aa379c1373b3d1cb9` | leaf 1, entry `f5b4486b9ad95bd74cc68e6cb58df3955d8b024cfd584efb0703b78bf5f36aad`, registered 8 November 2026 |
| `verdict-record.signed-statement.cose` | 1735 | `0f4686fdc4bcaa44b05bc4b88f8c0f6f90522c44d2ccb051689fd50fbe3d2e32` | leaf 2, entry `52bf19f55d61278e5baff38d487878c31e93da07f222c3f9e2ecada6fcf68880`, registered 8 November 2026 |
| `dispute-packet.signed-statement.cose` | 10820 | `73c98d14e0d05d7d3d9672582d3fb6dac5d8ea7525556806820ed646c97e25d3` | entry `13bbf54e2c1d93bb25a1efb2ef6f52b3f13b4cb3f648dda42fe413b6fc9f286e`, registered 14 November 2026 |
| `dispute-packet.2026-11-08.signed-statement.cose` | 8939 | `d328894f075a7241380ae18e44fb84f046c047b0def4d4836f22e3645886a3ea` | leaf 3, entry `5f0fac2384f13bc571f60254ca7e21c74f1ef6c763b04e465cb07c23154da57f`, registered 8 November 2026 |

An entry id on ts.isoluce.net is the hex of the Merkle leaf, SHA-256(0x00 || the bytes of the Signed Statement)
(RFC 9162 Section 2.1.1). The receipt of an entry is at `https://ts.isoluce.net/entries/<entry id>`.

## Why there are two dispute packets

The earlier packet was registered on 8 November 2026 before the case's four hash constructions were corrected later
that day (commit d6cd12c33e6b43a0fd9cd47b28ae9c75b40acdd1). Leaf 3 retains the earlier Signed Statement, archived here
as `dispute-packet.2026-11-08.signed-statement.cose`. `dispute-packet.signed-statement.cose` carries the corrected
packet in `../out/positive/` and was registered on 14 November as leaf 32. The other three Signed Statements still
carry the same payload bytes as their registrations on 8 November.

## Checking a receipt from another service

A receipt must be checked against the registered entry bytes, the service's verification key, and the service's entry
and leaf construction. ts.isoluce.net uses SHA-256(0x00 || registered Signed Statement bytes). For the archived case-06
receipt dated 27 October 2026, entry = SHA-256(Sig_structure(statement)) and leaf = SHA-256(0x00 || entry); its
signature verifies under that construction. That receipt carries alg -8 but no kid, iss or sub. Since the merge of
Standard PR #91 on 28 October, the anchoring reference accepts -8 receipts under an Ed25519 service key, with a
deprecation finding; its case-06 check stops on the missing kid. The missing mandatory SCITT headers and the different
entry construction are separate issues. See `../../aac/cases/06-transparency-receipt/anchoring-result.json`. Please
provide the registered bytes, service verification key and entry construction with any new receipts.
