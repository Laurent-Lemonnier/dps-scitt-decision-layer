| Vector | Expected (authors) | Draft outcome obtained here | Agrees | This checker's verdict |
|---|---|---|---|---|
| verify-preimage | verified (preimage-digest-match) | verified | yes | pass |
| verify-value | verified (recreated-digest-match) | verified | yes | pass |
| verify-value-modified | failed (recreated-digest-mismatch) | failed | yes | hash-mismatch |
| verify-preimage-mismatch | failed (preimage-digest-mismatch) | failed | yes | hash-mismatch |
| verify-value-no-encoding | unverified (encoding-absent) | unverified | yes | cannot-recompute |
| verify-preimage-no-encoding | verified (preimage-digest-match) | verified | yes | cannot-recompute |
| verify-value-unknown-encoding | unverified (encoding-not-implemented) | unverified | yes | unsupported-encoding |
| verify-preimage-unknown-encoding | verified (preimage-digest-match) | verified | yes | unsupported-encoding |
| verify-nothing-held | unverified (no-content) | unverified | yes | cannot-recompute |
| verify-ctype-absent | failed (content-type-absent) | failed | yes | inconsistent-header |
| verify-ctype-absent-value | failed (content-type-absent) | failed | yes | inconsistent-header |
| verify-ctype-json | failed (content-type-mismatch) | failed | yes | inconsistent-header |
| verify-ctype-params-case | verified (recreated-digest-match) | verified | yes | pass |
| verify-ctype-suffix | verified (recreated-digest-match) | verified | yes | pass |
| verify-ctype-suffix-sd-cwt | verified (preimage-digest-match) | verified | yes | pass |
| verify-ctype-not-suffix | failed (content-type-mismatch) | failed | yes | inconsistent-header |
| verify-ctype-cf-cbor | verified (recreated-digest-match) | verified | yes | pass |
| verify-ctype-cf-json | failed (content-type-mismatch) | failed | yes | inconsistent-header |
| verify-ctype-unknown-encoding-json | verified (preimage-digest-match) | verified | yes | unsupported-encoding |
| verify-binary64-held | verified (recreated-digest-match) | verified | yes | pass |
| verify-binary64-hashed | failed (recreated-digest-mismatch) | failed | yes | hash-mismatch |
| verify-length-first-hashed | failed (recreated-digest-mismatch) | failed | yes | hash-mismatch |
| verify-length-first-preimage | verified (preimage-digest-match) | verified | yes | not-canonical |
| verify-sha384 | verified (recreated-digest-match) | verified | yes | pass |
| verify-hash-alg-unknown | unverified (hash-alg-not-implemented) | unverified | yes | unsupported-hash-alg |

| Emit vector | Preimage | Digest | Header labels |
|---|---|---|---|
| emit-draft-example | same | same | same |
| emit-intro-key-order | same | same | same |
| emit-intro-float | same | same | same |
| emit-indefinite | same | same | same |
| emit-non-preferred-int | same | same | same |
| emit-nested | same | same | same |
| emit-sha384 | same | same | same |
| emit-content-format | same | same | same |
