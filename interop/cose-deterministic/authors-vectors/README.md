# The authors' vectors, run through the checker of this folder — 14 November 2026

On 14 November 2026, the checker written from draft-mih-sokolov-cose-deterministic-encodings-00
(`../verify_from_text.py`) was run on the authors' pinned vectors, as documented below.

| | |
|---|---|
| Vectors | `vectors/vectors.json` of `action-state-group/cose-deterministic-encodings`, read at commit `b892e0d23c68422ab58bd0f2edd1a6114158a718`; the file last changed at `37fa8eee92737107922f19c275766eb24a2e2b77`; SHA-256 `ca5044045f4da2f5360eb133cc2db683f644efc0fde3ddad2d655ef523c71006` |
| What they are | 8 "emit" cases (a structured value, the expected preimage, digest and protected header) and 25 "verify" cases (a protected header, a payload, and the preimage or the value a verifier holds), at header label 271 |
| Checker | `../verify_from_text.py` and `../cbor_det.py`, unchanged; the adapter is `run_authors_vectors.py` |
| Result | **emit 8 of 8, verify 25 of 25**: every preimage, digest and draft outcome is the one the authors expect |

The file is data and is not copied here. None of the authors' code (`lib/`) was read or run.

## What was compared

For a verify case, the outcome the draft defines (verified, failed, unverified, Section 2), as this checker reports it
in `draft_outcome`. The authors' second field, the reason, is theirs; this checker's own verdict is listed beside it in
[results.md](results.md) and they can be read against each other, but they were not compared mechanically.

For an emit case, the preimage re-created by this folder's core-deterministic encoder and its digest. The protected
header is not re-created (this folder has no emitter of headers): it is decoded, and its labels 258, 259 and 271 are
checked against the vector's inputs.

The vectors carry no signature. Each verify case is wrapped as an unsigned COSE_Sign1 and checked with no key, so
nothing here says anything about signatures.

## Where this checker is stricter

On four cases the draft outcome agrees (verified) and this checker still does not report a pass:

| Case | This checker | Why |
|---|---|---|
| `verify-preimage-no-encoding` | cannot-recompute | the preimage matches (RFC 9995), but with no encoding declared there is nothing of this draft to check; this checker never passes without the header |
| `verify-preimage-unknown-encoding` | unsupported-encoding | the bytes match, the declared encoding is one it does not implement |
| `verify-ctype-unknown-encoding-json` | unsupported-encoding | same |
| `verify-length-first-preimage` | not-canonical | the bytes match, and they are not in the encoding the header declares (length-first key order under value 1) |

Section 4.3 permits the content binding to verify from matching preimage bytes, subject to Section 4.2. The
additional encoding-conformance result is this checker's own policy and must be reported separately; it is not a
disagreement on the draft's outcome.

## Proposed additions and vector-format extensions

[proposed-additions.json](proposed-additions.json) contains additional tests and reporting questions. The
unknown-encoding cases use the authors' existing format. The CBOR-sequence cases and the unprotected-header case
require the format extensions stated in the file. They include new tests beyond this folder's original 16 vectors.
`run_authors_vectors.py` reproduces the authors' pinned file only; `run_proposed_additions.py` replays these
proposals with the same checker and prints its answer for each. They are offered to the authors, to take or to leave.

| Case | What it adds | Expected, and why |
|---|---|---|
| `verify-unknown-encoding-ctype-absent`, and the same holding the value | an encoding value the verifier does not recognize, with 259 absent | failed: Section 4.2 fails the binding when 259 is absent, with no condition on the encoding value, and says the check comes first |
| `emit-cbor-seq`, `verify-cbor-seq-value` | a CBOR sequence under `application/cbor-seq`, which Section 8.2 lists | each item encoded on its own; `value_cbor` is the two items one after the other, which needs the format extension named above |

The following three inputs violate Section 3: label 271 in crit, a non-integer encoding value, and label 271 in the
unprotected header. This checker rejects all three and reports failed. The draft does not explicitly map each Section 3
violation to one of its content-binding outcomes. The question for the authors is how to report these nonconforming
inputs, including whether envelope validity should be reported separately from content binding. An RFC 9995-only
recipient that cannot process label 271 must not ignore it when crit requires its processing.

| Case | The rule the input breaks | This checker |
|---|---|---|
| `open-label-in-crit` | Section 3: a producer MUST NOT list the label in crit | failed |
| `open-encoding-not-int` | Section 3: the CDDL makes the value an int | failed |
| `open-label-unprotected` | Section 3: the label MUST NOT be present in the unprotected header | failed |

## Reproduce

```sh
curl -sO https://raw.githubusercontent.com/action-state-group/cose-deterministic-encodings/b892e0d23c68422ab58bd0f2edd1a6114158a718/vectors/vectors.json
python3.12 run_authors_vectors.py vectors.json     # standard library only; exit status 0 when all outcomes agree
```

`results.json` and `results.md` are what that run wrote here. The script stops with exit status 2, and writes nothing, when the
file's SHA-256 is not the one pinned above.

```sh
python3.12 run_proposed_additions.py               # the proposed additions and the three open inputs, same checker
```

## What this does not show

That the two implementations in the authors' `lib/` agree with this checker on this folder's own 16 vectors: that is
the authors' run. Anything about signatures, about encoding values other than 1, or about a Hash Envelope registered
on a Transparency Service.
