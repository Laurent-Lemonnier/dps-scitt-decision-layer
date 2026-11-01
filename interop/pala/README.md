# PALA-1 bridge run B3: the SCITT-bridge Signed Statement, construction v3, from the text — 2026-11-01

An outside reading of `docs/interop/SCITT-STATEMENT-V3-VERIFICATION-TASK.md` of Assault-Consulting/Palimpsests, at
commit `131fc7ae6fdb30a7658c19563527d84da4b2fb0a` (`vectors/PINNED_COMMIT.txt`; the eight files read are copied under
`vectors/` with `SHA256SUMS`; the v3 vector file's SHA-256 is `9cf9761e…`, the task file's `685314d8…`). Within the
task's boundary: the RFCs it lists, the two vectors, PALA-1 sections 1.2, 4.1 and 4.3, `consistency-proof.md` sections
1 and 2, the published vector data, the draft's section on transparency services, and the v2 task; nothing under
`src/`, `tests/`, `benchmarks/`, no generator, no reference implementation, no issue, pull request or history. The
construction is taken as published, alg -8 included.

`verify_statement_v3.py` is the verifier and the constructor, in the state it ran: CBOR (RFC 8949, deterministic
encoding and a strict reader that reports order and duplicate findings), COSE_Sign1 and the Sig_structure (RFC 9052),
the key thumbprint (RFC 9679), the derived tree (PALA-1 4.3, both the promote-not-duplicate and the RFC 6962 recursive
forms), the consistency proof (RFC 9162 2.1.4.2 behind the companion's two pre-checks). Ed25519 is the `cryptography`
library's, with the RFC 8032 5.1.7 range check on S made explicit beside it.

## Run report (`out/report-b3.json`): 99 of 99 checks as the task states

In the task's order:

1. **Roots.** The derived root over the first 8 and over all 12 record hashes equals `root_hex` of each statement, by
   both constructions (they agree, as 4.3 says). Stretch: the 12 record hashes recompute from the published headers
   (`record_hash = SHA-256(header_bytes)`, 4.1), and every proof of `consistency-vectors.json` verifies while its three
   negatives fail. Not attempted: the companion's roots by count, whose leaves come from a file the boundary does not
   list.
2. **Parse and verify.** Both statements: tag 18, four elements, protected bytes, empty unprotected map, attached
   payload, 64-byte signature; the signature over the Sig_structure assembled here, with the public key given; S in
   range; the protected header exactly labels 1, 3, 4, 15 in deterministic order, alg -8, kid equal to the thumbprint,
   CWT claims 1 and 2 with the issuer and the full-head subject; the payload read against the inputs. SHA-256 and
   length as expected.
3. **The new parts.** Content type `application/vnd.palimpsests.pala1-head-v3+cbor`; exactly keys 1 to 5; key 5 the
   root over 0..last_seq, for `later` 0..11 though its first_seq is 8.
4. **The case v3 exists for.** The proof from size 8 to 12 verifies from the two roots read from the statements'
   payloads, with nothing but the two statements, the proof's path and the public key; the document's own root copies
   equal them and were not used. What it establishes: a relation between the two roots; nothing about either head.
5. **Reproduce.** Both statements rebuilt byte for byte from the inputs and the seed (369 bytes each, no differing
   offset).
6. **Tamper.** Each of the seven expectations fails as it claims to (a flipped root bit fails the signature; a root
   that is not the derived root, a root over first_seq..last_seq, over last_seq or last_seq + 2 records, each refused
   against the chain, the first also failing the proof; a dropped path node and swapped roots fail the proof; without
   the chain the root is carried). The version rule with statements of our own: the v3 type without key 5 and key 5
   under the v2 type are refused though their signatures verify.
7. **Regression.** The v2 statement verifies and reads as v2, no root.
8. **Adversarial.** Payload keys out of order: the signature verifies and the values read, the encoding is reported as
   not deterministic (see the ambiguity log). Key 5 duplicated: refused, the root the signature covers is ambiguous.
   Key 5 of 31 or 33 bytes: refused by the version rule. first_seq greater than last_seq: refused by the range rule.
   A statement pairing record 11's head with the root over 0..7: accepted without the chain, as the task's F3 says
   it must be, and refused with it.

Wall clock: the verifier's run, 0.01 s; reading the task, the texts and the vectors and writing the code, about two
hours on 1 November 2026. An assistant wrote the code and the first draft of this report; Laurent Lemonnier read both;
it is a reading under his review, the kind the task's author described.

## Ambiguity log

| Where | Reading taken, and the other reading |
|---|---|
| task, step 2, via the v2 task's step 4 | the protected header carries "exactly these labels": this reader refuses a fifth label (`protected_labels_exactly_1_3_4_15`); the text does not say whether a fifth label is a refusal or is skipped |
| task, "Construction v3" | "encoded in ascending order": read as RFC 8949 4.2.1 deterministic order (length, then bytes), which equals numeric order for these labels and keys; a reader taking numeric order reads the same bytes |
| task, version rule | a key 5 that is a byte string of another length fails the version rule here, since that is where the text names the length; it could also be reported as a malformed root |
| task, step 4 | the proof document carries `first_root` and `second_root`; this reader takes the roots from the statements, reports whether the document's copies equal them, and never verifies against the document's copies, as `consistency-proof.md` section 3 asks |
| RFC 9162 2.1.4.2 vs `consistency-proof.md` 2 | `first == second` (empty path, equal roots) and `first == 0` are settled before the RFC's algorithm, which fails any empty path; a reader entering the RFC directly refuses a proof the companion accepts (the companion's own F1) |
| RFC 8032 5.1.7 | the library's verify plus an explicit S < L check, since the v2 history records that libraries differ; both statements pass |
| task, step 8 | "payload keys out of order": RFC 9052 does not require a deterministic payload, the construction does; this reader reports the encoding and keeps the verdict on the values apart from it; a reader that refuses is also defensible, and the text could say which it wants |

## Not attempted, and said

The companion's roots by count (leaves outside the boundary); the repository's Python and other readers (outside
the boundary); any claim about the transparency service the draft's section 8 describes, since no receipt is in the
vector. Nothing here is a conformance claim by the task's author; the record lives in this repository, as agreed with
him, and he links it from his.

## Reproduce

```sh
# cryptography
python3 verify_statement_v3.py --vectors vectors --report out/report-b3.json
```
The CI (`../run.sh`) runs it from the pinned copy. Exit 0 when every check the task states holds.
