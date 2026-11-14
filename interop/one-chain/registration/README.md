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

The signature is over the Sig_structure of RFC 9052 Section 4.4. The key is a test key made for this case and used for
nothing else. Its public half is `issuer-ed25519.pub.pem` (raw key, hex:
`bfe07446773cb19de0699bc782ed8e3df489ea9e006dfeffbc11da3b12544771`). No service other than ts.isoluce.net has been
told about it, so a registration policy that wants a known issuer will refuse these statements. If it does, that is a
result to write down.

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

The dispute packet was registered on 8 November in the afternoon. That evening the author of
draft-xg-payment-dispute-profile gave the four constructions his -01 names and does not build, and the packet was
corrected (see the case's README). The log is append-only, so leaf 3 still holds the packet as it was that afternoon;
`dispute-packet.2026-11-08.signed-statement.cose` is that statement. `dispute-packet.signed-statement.cose` is the
packet as it is in `../out/positive/` today. The three other records have not changed since they were registered.

## Checking a receipt from another service

A receipt is checked against three things: the bytes of the Signed Statement as the service registered them, the
service's key, and the way the service computes its leaf. On the third point services differ. ts.isoluce.net hashes
the registered statement, as RFC 9162 does. In case 06 of `../../aac/` (27 October) the service met there hashed the
statement's Sig_structure, and its receipt carried alg -8 with no `iss`, `sub` or `kid`; the anchoring reference of
the Decision Provenance Standard reads -19 and needs a `kid`, so it reported that receipt as not supported
(`../../aac/README.md`, "Findings from case 06"). Whoever registers these statements elsewhere: please say which
bytes your leaf covers and which algorithm your receipts carry, so that a refusal can be told from a difference of
reading.
