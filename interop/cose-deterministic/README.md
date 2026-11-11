# cose-deterministic: a checker for draft-mih-sokolov-cose-deterministic-encodings, from the text

An independent checker and test vectors for the `deterministic-encodings`
protected-header parameter of a COSE Hash Envelope.

Written from the text alone; no code from the authors read or run; written
with an AI assistant (Claude), reviewed and run by Laurent Lemonnier.

## What was read

| Document | Revision / URL | SHA-256 of the text read |
|---|---|---|
| draft-mih-sokolov-cose-deterministic-encodings | **-00**, dated 27 October 2026 (latest on datatracker on 2026-11-10), https://www.ietf.org/archive/id/draft-mih-sokolov-cose-deterministic-encodings-00.txt | `536607ce…b19164` |
| RFC 9995 (COSE Hash Envelope) | https://www.rfc-editor.org/rfc/rfc9995.txt | `bdc665c4…003d3d` |
| RFC 9052 / RFC 9053 (COSE structures, EdDSA) | rfc-editor.org | `01eecd7f…0a45` / `3d470615…6ab0` |
| RFC 8949 (CBOR), Sections 3, 4.1, 4.2.1-4.2.3, 5.6 | rfc-editor.org | `f1164a5b…8a214a` |
| RFC 8032 (Ed25519) | rfc-editor.org | `ed63657f…93c4c3` |
| IANA CoAP Content-Formats (CSV snapshot, 2026-11-10) | https://www.iana.org/assignments/core-parameters/content-formats.csv | `dbd114fe…93444e` |

Copies are in `refs/` (full hashes: `sha256sum refs/*`). The draft's
"Note to Readers" points to a repository with a reference emitter, verifier
and vectors; its code and files were not read. On 11 November 2026 the list
of files at its root was looked at to see whether vectors had been published:
none were (the draft's .md, .txt and .xml, licence and governance files; last
push 28 October). No positive vectors from the authors were available to us
when this was written, so all vectors here are our own.

Only the Python 3.12 standard library is used. CBOR (encoder, decoder,
core-deterministic validator) and Ed25519 are implemented in this folder
(`cbor_det.py`, `ed25519_pure.py`). The pure-Python Ed25519 is for
verification and demo signing only (not constant-time). It is checked against
RFC 8032 TEST 1 and TEST 2, and the P1 signature is cross-checked with the
operating system's `python3-cryptography` package (EL8 platform-python).

## Files

| File | Role |
|---|---|
| `verify_from_text.py` | the checker (CLI and `verify()` function) |
| `cbor_det.py` | CBOR encoder (core-deterministic, length-first, as-given), decoder, strict validator |
| `ed25519_pure.py` | Ed25519, RFC 8032 Section 5.1 |
| `make_vectors.py` | builds `vectors/` from `demo-key.json` |
| `demo-key.json` | **demonstration** Ed25519 key, private seed published on purpose |
| `run_tests.py` | rebuilds the vectors, runs them through the CLI, conformance and mutation tests; writes `results.json`, `results.md` |
| `prepare_registration.py`, `registration/` | Signed Statement prepared for SCRAPI registration (not sent), see `REGISTRATION-PLAN.md` |
| `refs/` | the texts read |

## Verdicts

The draft defines three outcomes (Section 2): verified, failed, unverified.
The checker gives a finer verdict and also prints the draft's literal outcome
(`draft_outcome`), so that every place where this checker is stricter than
the text stays visible.

| Verdict | Meaning | Draft outcome |
|---|---|---|
| `pass` | binding established, header consistent, signature valid (or no key given) | verified |
| `cannot-recompute` | `deterministic-encodings` absent (or nothing held). Never `pass`. | unverified (value held) / verified (bytes held, see A3) |
| `unsupported-encoding` | value not implemented here (only 1 is) | unverified |
| `not-canonical` | held preimage bytes are not in the declared encoding | verified (see A2) |
| `hash-mismatch` | digest of the (re-created) preimage differs from the payload | failed |
| `inconsistent-header` | Section 3 placement or Section 4.2 consistency rule violated | failed |
| `bad-signature` | key given and the signature is invalid or cannot be checked | (independent of the binding) |
| `unsupported-hash-alg`, `cannot-encode-value` | not implemented / value has no encoding here | unverified |
| `invalid-envelope`, `malformed` | not an RFC 9995 Hash Envelope / not CBOR | n/a |

Order of checks: CBOR and COSE_Sign1 structure; signature (if a key is
given); RFC 9995 header rules; draft Section 3 placement; Section 4.2
consistency (before any recomputation, as the draft requires); hash
algorithm; content binding (Section 4.3).

## Results

Run on 2026-11-10 (`run_tests.py`). 16 vectors, 51 conformance checks,
≈880 mutation checks; 0 failures.

| Vector | Expected | Obtained | Draft outcome | Reason (abridged) |
|---|---|---|---|---|
| P1-capsule-bytes | pass | pass | verified | preimage bytes match and are core-deterministic |
| P2-capsule-value | pass | pass | verified | JSON value re-encoded, digest matches (259 `application/vnd.example.capsule+cbor`, suffix match) |
| P3-cf60-stored-noncanonical (extra) | pass | pass | verified | 259 = Content-Format 60; value stored in non-deterministic CBOR, decoded and re-encoded |
| Na-header-absent | cannot-recompute | cannot-recompute | unverified | value held, `deterministic-encodings` absent |
| Nb-encoding-not-implemented | unsupported-encoding | unsupported-encoding | unverified | value 2 not recognized |
| Nc-preimage-not-canonical | not-canonical | not-canonical | **verified** | argument 10 on 1 byte where 0 suffice (keys also unsorted) |
| Nd1-hash-over-length-first | hash-mismatch | hash-mismatch | failed | digest over RFC 8949 Section 4.2.3 order; re-encoding gives 4.2.1 order |
| Nd2-hash-over-json-text | hash-mismatch | hash-mismatch | failed | digest over JSON text of the same capsule |
| Xa-header-absent-bytes | cannot-recompute | cannot-recompute | **verified** | bytes match (RFC 9995 Section 5.3) but no declared encoding |
| Xe-ct-json | inconsistent-header | inconsistent-header | failed | core-deterministic with `application/json` |
| Xf-ct-absent | inconsistent-header | inconsistent-header | failed | 259 absent |
| Xg-unknown-enc-ct-absent | inconsistent-header | inconsistent-header | failed | value 2 and 259 absent: Section 4.2 takes precedence |
| Xh-label-unprotected | inconsistent-header | inconsistent-header | failed | label 271 in unprotected header |
| Xi-label-in-crit | inconsistent-header | inconsistent-header | failed | label 271 listed in crit |
| Xj-cf50-json | inconsistent-header | inconsistent-header | failed | 259 = Content-Format 50 (`application/json`) |
| Xk-bad-signature | bad-signature | bad-signature | verified | signed with another key |

The four requested negatives are Na (header absent), Nb (encoding not
implemented), Nc (preimage not in the declared form), Nd1/Nd2 (hash over
another serialization). Full reasons and commands: `results.md`,
`results.json`.

Mutation tests (on P1 and P2): every byte of the P1 envelope flipped two
ways (with key: never `pass`; without key: a `pass` only when the flip leaves
payload, 258 and the encoding value unchanged, e.g. in the signature or the
`payload-location` text); every byte of the preimage flipped (240 ×
`hash-mismatch`); truncation and extension; eleven structured-value
mutations (int 1000 → float 1000.0, float 0.5 → int 0, true → 1, text →
bytes, added tag 32, key added or dropped, array order…, all
`hash-mismatch`); six other encoding values (0, 2, 3, 5, -1, 65536, all
`unsupported-encoding`).

Conformance checks include the RFC 8949 Section 4.1 and 4.2.1 examples
(floats, integer boundaries, the eight-key ordering list), the draft's
Section 1 example (`a21903e801616102` vs `a26161021903e801`) and its
Section 5 example (preimage `a2616101616202`, SHA-256 `a0d3af9e…c893b5e3`),
NaN payload preservation, and validator rejections (non-shortest argument
and float, indefinite length, unsorted and duplicate keys, reserved
additional information, invalid UTF-8, trailing bytes).

## Replay

```
cd interop/cose-deterministic
python3.12 run_tests.py                       # rebuilds vectors, runs everything, exit 0 if all match
python3.12 verify_from_text.py vectors/P1-capsule-bytes/envelope.cbor \
    --preimage vectors/P1-capsule-bytes/capsule-1.cbor --pubkey demo-key.json
python3.12 verify_from_text.py vectors/P2-capsule-value/envelope.cbor \
    --value-json vectors/P2-capsule-value/capsule-2.json --pubkey demo-key.json
```

Options: `--value-cbor FILE` (value held as any CBOR), `--label N` (label
used for TBD_1, default 271), `--rfc9995-bytes-only` (draft-literal handling
of held bytes, see A2). Exit status 0 only for `pass`.

To run on someone else's vectors: one call per vector with the envelope, the
preimage or value, and their public key (Ed25519 only for now).

## Ambiguity log

Each entry: where the text leaves a choice, and the reading taken here.

1. **Parameter name and label.** The parameter is `deterministic-encodings`
   (Section 3), label TBD_1, value an integer from the new registry (not the
   name). The hackathon brief called it `payload-preimage-encoding`; we
   follow the text. TBD_1 is unassigned; we use the suggested 271
   (Section 8.1), configurable with `--label`. Vectors from other
   implementations must say which label they use.
2. **Held bytes not in the declared encoding.** Section 4.3: a verifier
   holding the preimage checks the digest only; "that check needs no
   encoding information". Section 4.1 says the value "MUST identify the
   encoding actually applied", but gives the verifier no duty to check it.
   Read literally, Nc is *verified*. We report `not-canonical` by default
   (the header is false), and print `draft_outcome: verified`.
   `--rfc9995-bytes-only` gives the literal behaviour.
3. **Header absent, bytes held.** Section 4.3 and the RFC 9995 Section 5.3
   check give *verified*; the brief for this work says never pass without
   the header. Verdict `cannot-recompute`, `draft_outcome: verified` (Xa).
4. **Outcome vocabulary.** Three outcomes in the draft; our finer verdicts
   map onto them as in the table above. `not-canonical` is our own: the draft
   has no outcome for it.
5. **Signature and binding.** Section 4.3: "signature validity is unaffected
   by any content-binding outcome". We report both; when a key is given, an
   invalid signature, or one that cannot be checked (alg absent or not
   implemented), turns the overall verdict into `bad-signature`, with the
   binding result kept in the reason. Without a key, `pass` means the
   binding only (`signature: not-checked`).
6. **Unknown value and Section 4.2.** The 259 matching can only be done for
   an encoding the verifier recognizes, but "deterministic-encodings present
   with preimage-content-type (259) absent" is failed whatever the value.
   Xg (value 2, no 259) is therefore `inconsistent-header` (failed), not
   unverified.
7. **Producer-side MUST NOTs.** Section 3 forbids the label in the
   unprotected header and in `crit`, and Section 4.2 forbids mismatched
   pairs, but only 4.2 says what a verifier reports. We treat Section 3
   violations as failed too (Xh, Xi).
8. **Content-Format numbers.** Matching needs a copy of the CoAP
   Content-Formats registry. We use a dated snapshot; a number missing from
   it does not match (failed), so a stale copy can fail a newly registered
   number. Registry entries with parameters (e.g. 18, `application/cose;
   cose-type="cose-sign1"`) are compared after removing the parameters, as
   for media-type names.
9. **Structured syntax suffix.** Read as the part after the last `+`
   (RFC 6838 Section 4.2.8): `+cbor-seq` does not match `+cbor`, and the
   reverse.
10. **What a "structured value" is.** Section 6 puts the int / float and tag
    choices in the value, not the encoding. A verifier holding JSON needs a
    JSON → CBOR mapping the draft does not give. Ours: JSON integer literals
    → CBOR integers, other numbers → floats (shortest form), objects → maps
    with text keys, duplicate JSON keys refused. P2-style vectors only
    interoperate if both sides use the same mapping; a value held as CBOR
    (`--value-cbor`, P3, Nd1) avoids the question.
11. **Floats.** RFC 8949 Section 4.2.1: shortest form preserving the value.
    Negative zero is kept (`f98000`); NaN payloads are kept and shortened
    only when zero-padding restores them (Section 4.1). Section 8.2 of the
    draft says rules that only restrict data items (e.g. no non-trivial NaN)
    still use value 1, which we read as: value 1 does not forbid NaN
    payloads.
12. **Duplicate map keys.** Section 4.2.1 does not say "no duplicates"; the
    strict bytewise order implies it, and RFC 8949 Section 5.6 makes such a
    map invalid. Rejected as `malformed`.
13. **Large integers.** Integers outside the 64-bit range and the choice of
    tags 2/3 are left to the protocol (RFC 8949 Section 4.2.2). Our encoder
    refuses them (`cannot-encode-value`); the validator accepts tags 2/3
    without checking their content.
14. **Registry value range.** The CDDL says `int`, the registry template
    says "unsigned integer". Negative values and 0 are treated as
    unrecognized (`unsupported-encoding`).
15. **Tag 18 and detached payload.** RFC 9995's CDDL uses `#6.18`; untagged
    COSE_Sign1 is accepted with a note. A nil (detached) payload is not
    supported (`invalid-envelope`): the digest must be in the envelope.
16. **Order of checks.** Section 4.2 comes before Section 4.3; the text does
    not place the hash-algorithm check or the signature. We check the
    signature first (independent), then 4.2, then the hash algorithm.
17. **CBOR sequences.** Each item encoded separately (Section 8.2); a value
    for a sequence is given as a list of items. Not exercised by the
    vectors yet.
18. **Protected header encoding.** Nothing requires the protected header
    itself to be deterministic; not checked.

## Limits

- Positive vectors from the authors were not published at the time of
  writing; nothing here has yet been run on them.
- Signatures: EdDSA (-8) only; ES256 (used in the draft's example) is not
  implemented yet. Hash algorithms: SHA-256, SHA-384, SHA-512.
- Only encoding value 1 is implemented.
- This README will name the commit that produced each result once the
  folder is committed; results here come from the working copy of
  2026-11-10.
