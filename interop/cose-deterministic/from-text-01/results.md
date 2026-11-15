| Vector | Expected (authors) | Encoder rejects non-trivial NaNs | Encoder writes them as 0xf97e00 |
|---|---|---|---|
| verify-preimage | verified | verified | verified |
| verify-value | verified | verified | verified |
| verify-value-modified | failed | failed | failed |
| verify-preimage-mismatch | failed | failed | failed |
| verify-value-no-encoding | unverified | unverified | unverified |
| verify-preimage-no-encoding | verified | verified | verified |
| verify-value-unknown-encoding | unverified | unverified | unverified |
| verify-value-integer-1 | unverified | unverified | unverified |
| verify-value-nan-payload | unverified | unverified | verified (differs) |
| verify-preimage-unknown-encoding | verified | verified | verified |
| verify-nothing-held | unverified | unverified | unverified |
| verify-ctype-absent | failed | failed | failed |
| verify-ctype-absent-value | failed | failed | failed |
| verify-ctype-json | failed | failed | failed |
| verify-ctype-params-case | verified | verified | verified |
| verify-ctype-suffix | verified | verified | verified |
| verify-ctype-suffix-sd-cwt | verified | verified | verified |
| verify-ctype-not-suffix | failed | failed | failed |
| verify-ctype-cf-cbor | verified | verified | verified |
| verify-ctype-cf-json | failed | failed | failed |
| verify-ctype-unknown-encoding-json | verified | verified | verified |
| verify-binary64-held | verified | verified | verified |
| verify-binary64-hashed | failed | failed | failed |
| verify-length-first-hashed | failed | failed | failed |
| verify-length-first-preimage | verified | verified | verified |
| verify-sha384 | verified | verified | verified |
| verify-hash-alg-unknown | unverified | unverified | unverified |
| reject-nan-payload | encoder error | refused | encoded a16178f97e00 |
| reject-nan-signaling | encoder error | refused | encoded a16178f97e00 |
| reject-nan-sign-bit | encoder error | refused | encoded a16178f97e00 |
| reject-nan-binary64-payload | encoder error | refused | encoded a16178f97e00 |

Emit: 10/10 (reject mode), 10/10 (canonical mode).
