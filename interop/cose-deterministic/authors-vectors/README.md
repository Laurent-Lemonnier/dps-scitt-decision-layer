# The authors' vectors, run through the checker of this folder — 14 November 2026

Steven Mih asked for it on 13 November: run the checker written from the text of
draft-mih-sokolov-cose-deterministic-encodings-00 (`../verify_from_text.py`) on the vectors the authors publish.

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

That is a choice of this checker, said in its README, and not a disagreement on the draft: Section 4.3 lets the
RFC 9995 check stand when the preimage is held. A reader who wants "verified" to also mean "in the declared encoding"
gets a different answer on the fourth case, and the draft could say which it intends.

## Reproduce

```sh
curl -sO https://raw.githubusercontent.com/action-state-group/cose-deterministic-encodings/b892e0d23c68422ab58bd0f2edd1a6114158a718/vectors/vectors.json
python3.12 run_authors_vectors.py vectors.json     # standard library only; exit status 0 when all outcomes agree
```

`results.json` and `results.md` are what that run wrote here. The script reports whether the file's SHA-256 is the one
pinned above.

## What this does not show

That the two implementations in the authors' `lib/` agree with this checker on this folder's own 16 vectors: that is
the authors' run. Anything about signatures, about encoding values other than 1, or about a Hash Envelope registered
on a Transparency Service.
