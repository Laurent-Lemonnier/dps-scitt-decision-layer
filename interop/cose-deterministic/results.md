| Vector | Expected | Obtained | Draft outcome | Signature | Reason |
|---|---|---|---|---|---|
| Na-header-absent | cannot-recompute | cannot-recompute | unverified | valid | structured value held but deterministic-encodings absent (draft Section 4.3) |
| Nb-encoding-not-implemented | unsupported-encoding | unsupported-encoding | unverified | valid | deterministic-encodings=2 not recognized/implemented (draft Section 4.3) |
| Nc-preimage-not-canonical | not-canonical | not-canonical | verified | valid | preimage bytes are not core-deterministic: argument 10 encoded on 1 byte(s), shortest form is 0 (at byte offset 9) |
| Nd1-hash-over-length-first | hash-mismatch | hash-mismatch | failed | valid | SHA-256 of the re-created preimage does not match the payload |
| Nd2-hash-over-json-text | hash-mismatch | hash-mismatch | failed | valid | SHA-256 of the re-created preimage does not match the payload |
| P1-capsule-bytes | pass | pass | verified | valid | preimage bytes match the payload and are in the declared encoding |
| P2-capsule-value | pass | pass | verified | valid | re-created preimage matches the payload |
| P3-cf60-stored-noncanonical | pass | pass | verified | valid | re-created preimage matches the payload |
| Xa-header-absent-bytes | cannot-recompute | cannot-recompute | verified | valid | deterministic-encodings absent: the preimage bytes match the payload (RFC 9995 Section 5.3), but no declared encoding to check; this checker never passes without the header |
| Xe-ct-json | inconsistent-header | inconsistent-header | failed | valid | 259 does not match encoding 1: application/json is not an Applicable Content Type of core-deterministic (draft Section 4.2) |
| Xf-ct-absent | inconsistent-header | inconsistent-header | failed | valid | deterministic-encodings present but preimage-content-type (259) absent (draft Section 4.2) |
| Xg-unknown-enc-ct-absent | inconsistent-header | inconsistent-header | failed | valid | deterministic-encodings present but preimage-content-type (259) absent (draft Section 4.2) |
| Xh-label-unprotected | inconsistent-header | inconsistent-header | failed | valid | deterministic-encodings (label 271) in the unprotected header (draft Section 3) |
| Xi-label-in-crit | inconsistent-header | inconsistent-header | failed | valid | deterministic-encodings (label 271) listed in crit (draft Section 3) |
| Xj-cf50-json | inconsistent-header | inconsistent-header | failed | valid | 259 does not match encoding 1: Content-Format 50 = 'application/json': application/json is not an Applicable Content Type of core-deterministic (draft Section 4.2) |
| Xk-bad-signature | bad-signature | bad-signature | verified | invalid | COSE_Sign1 signature invalid (content binding alone: pass: preimage bytes match the payload and are in the declared encoding) |

Mutation verdict counts:

- envelope byte flips (key given): bad-signature 240, invalid-envelope 3, malformed 65
- envelope byte flips (no key): cannot-recompute 4, hash-mismatch 64, inconsistent-header 18, invalid-envelope 7, malformed 65, pass 148, unsupported-encoding 1, unsupported-hash-alg 1
- preimage byte flips: hash-mismatch 240
- preimage truncated/extended: hash-mismatch 3
- structured-value mutations: hash-mismatch 11
- deterministic-encodings value sweep (value mode): unsupported-encoding 6

Conformance checks: 51/51 true (0 skipped)
Failures: 0
