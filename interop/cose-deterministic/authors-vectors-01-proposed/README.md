# The vectors proposed for -01 ("dtrm"), run through the checker of this folder — 14 November 2026

During the IETF 127 Hackathon one of the authors of draft-mih-sokolov-cose-deterministic-encodings told us what the
next revision changes, and pointed at the vectors proposed for it. This folder runs the checker written from -00 on
those vectors, with the change applied in front of it.

**No text of -01 exists yet.** What is applied here is the authors' description, from a message of 14 November 2026
and from the description inside their vector file. It is not a reading of a draft, and it will have to be redone
from the text when -01 is posted.

| | |
|---|---|
| Vectors | `vectors/vectors.json` of `action-state-group/cose-deterministic-encodings`, read at commit `3e3440db01c597701d019a49dc0054c66e7b7010` (a pull request of the authors, not merged on 14 November 2026); SHA-256 `799b2b05c0a7ad469dfc049c7003cbe7f963865d4f6f35fa2757bfc1a8fad3c2` |
| What they are | 10 "emit" cases, 27 "verify" cases and 4 "reject" cases, at header label 271 |
| The change, as described | label 271 stays; the value is the text string `"dtrm"` and the registry of -00 is gone; any other value, the integer 1 of -00 included, is unrecognized (unverified, never failed); the only NaN emitted is `0xf97e00`, and an encoder rejects any other NaN |
| Checker | `../verify_from_text.py` and `../cbor_det.py`, the -00 checker, which knows nothing of `"dtrm"`; `run_dtrm_vectors.py` rewrites the protected header before the check (`"dtrm"` becomes the value the -00 checker knows, the integer 1 one it does not know) and refuses a value holding another NaN before encoding |
| Result | **emit 10 of 10, verify 27 of 27, reject 4 of 4** |

The file is data and is not copied here. None of the authors' code was read or run. The vectors carry no signature;
the header rewriting would not be possible on a signed envelope, so this run says nothing about signatures.

## Controls

- The -00 checker alone, with no rewriting (`control_minus_00_checker_alone` in `results.json`): 14 of the 27 verify
  cases give the expected outcome and 13 differ, none of them by a failure that was not expected. Where only the
  value is held under `"dtrm"`, it answers unverified, since it does not know that encoding; where the preimage is
  held, it answers from the RFC 9995 check alone; and it still verifies the integer 1, which -01 makes unrecognized.
- With the NaN rule removed, 5 cases differ: the four reject cases and `verify-value-nan-payload`.
- With one bit of each expected emit preimage changed, none of the 10 emit cases agrees.

## What this run changed in the -00 checker

Before this run the -00 checker reported failed for a value that is not an integer, reading the CDDL of Section 3 as
a rule a verifier enforces. On the proposed -01 vectors that gave failed on twelve envelopes carrying `"dtrm"`, where
a verifier that does not know the encoding should say unverified. The -00 text states no verifier outcome for a value
of another type, so the reading was changed on 14 November 2026: such a value is one the checker does not recognize
(entry 19 of the ambiguity log in `../README.md`). No -00 vector is affected: the 16 of this folder and the authors'
33 give the same results before and after.

## Where this checker is stricter

As on the -00 vectors, four cases agree on the outcome (verified) and are not a pass for this checker:
`verify-preimage-no-encoding`, `verify-preimage-unknown-encoding`, `verify-ctype-unknown-encoding-json` and
`verify-length-first-preimage`. See `../authors-vectors/README.md`.

## Replay

```sh
curl -sO https://raw.githubusercontent.com/action-state-group/cose-deterministic-encodings/3e3440db01c597701d019a49dc0054c66e7b7010/vectors/vectors.json
python3.12 run_dtrm_vectors.py vectors.json     # exit 0; writes results.json and results.md
```

Written with an AI assistant (Claude), reviewed and run by Laurent Lemonnier.
