# The -01 text, run on the authors' vectors — 15 November 2026

On 14 November 2026 the vectors proposed for -01 of draft-mih-sokolov-cose-deterministic-encodings were run from the
authors' description, because no -01 text existed (`../authors-vectors-01-proposed/`, 41 of 41). The authors merged
-01 into their repository the same evening. This folder redoes the pass from the text.

Written from the text alone; no code from the authors read or run; written with an AI assistant (Claude), reviewed and
run by Laurent Lemonnier.

| Read | Where | SHA-256 |
|---|---|---|
| draft-mih-sokolov-cose-deterministic-encodings-01.txt | authors' repository, commit `0621eca4dd59002a92e3eb4781ad1371aaa53bb5` (not yet on the Datatracker on 15 November 2026) | `b7a3d0a6e0e5db08184b4667ff6e3021d09964d7890bb3b8a936c23dc8d9b25e` |
| draft-ietf-cbor-serialization-12.txt (cited by -01 Section 3.1 for "dtrm") | https://www.ietf.org/archive/id/draft-ietf-cbor-serialization-12.txt | `1ebad1e4bf28b60212c851fbe21f270bb8ea9e94f3c8728e10063b8be2bb539c` |
| vectors/vectors.json (data) | same commit; the same file as on 14 November | `799b2b05c0a7ad469dfc049c7003cbe7f963865d4f6f35fa2757bfc1a8fad3c2` |

## The checker

`verify_from_text_01.py` is a copy of `../verify_from_text.py` changed where -01 changes the text: the value is a text
string and "dtrm" is the one value defined (Section 3.1), with the Applicable Content Types of Section 4.2; any other
value, the integer 1 of -00 included, is not recognized (Appendix A); held preimage bytes holding a non-trivial NaN are
not in the declared encoding; a held value holding one is handled by the encoder as below. Nothing is translated in
front of it, unlike the pass of 14 November.

## Results (`run_01_vectors.py`, `results.json`, `results.md`)

| Encoder, for a non-trivial NaN in a value | Emit | Verify | Reject |
|---|---|---|---|
| rejects it | 10 / 10 | 27 / 27 | 4 / 4 |
| encodes it as 0xf97e00 | 10 / 10 | 26 / 27 | 0 / 4 |

Both behaviours are allowed by the text: -01 Section 3.1 defines "dtrm" by draft-ietf-cbor-serialization-12, whose
Section 4.1 says the encoder "MUST either reject it or encode it as 0xf97e00"; -01 Section 4.3 gives the rejection as
an example ("for example, when its encoder rejects a NaN"). The authors' vectors expect the rejection. With the other
branch, the four reject cases encode to `a16178f97e00`, and `verify-value-nan-payload` (a held value with the NaN
0xf97e01, a payload computed over the same map with 0xf97e00) becomes verified instead of unverified. Either the text
narrows the encoder to rejection, or those five vectors accept both outcomes.

Four verify cases agree on the outcome without being a pass for this checker, as on 14 November (the preimage bytes
match, but no declared encoding is checked): verify-preimage-no-encoding, verify-preimage-unknown-encoding,
verify-ctype-unknown-encoding-json, verify-length-first-preimage.

## Run

```
curl -sO https://raw.githubusercontent.com/action-state-group/cose-deterministic-encodings/0621eca4dd59002a92e3eb4781ad1371aaa53bb5/vectors/vectors.json
python3.12 run_01_vectors.py vectors.json
```

Python standard library only. `interop/run.sh` runs it and fails if the committed results change.
