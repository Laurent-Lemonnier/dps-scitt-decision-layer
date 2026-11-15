# mmr-profile: what an MMR receipt binds, tested from the text of draft-bryce-cose-receipts-mmr-profile-03

On scitt@ietf.org on 15 November 2026, Bassem Kudsi showed that an RFC 9942 inclusion receipt (RFC9162_SHA256) does
not cover its tree size or leaf index with the signature ("RFC 9942 inclusion receipts: tree-size is not authenticated
by the signed root"); it was reproduced on several logs, ours included. Jon Geater answered that the MMR profile covers
this case. This folder runs the same question against that profile.

Written from the text alone; no code from the authors read or run; the draft gives no vectors. Written with an AI
assistant (Claude), reviewed and run by Laurent Lemonnier. The log, its leaves and the signing key are synthetic.

| Document | URL | SHA-256 of the text read |
|---|---|---|
| draft-bryce-cose-receipts-mmr-profile-03 | https://www.ietf.org/archive/id/draft-bryce-cose-receipts-mmr-profile-03.txt | `fba4838118dad19733ab6c6dbdcb92f799ccfa35db38ae3a6c1e17b84b8b56d7` |

## Run

```
curl -fsSL -o /tmp/mmr-03.txt https://www.ietf.org/archive/id/draft-bryce-cose-receipts-mmr-profile-03.txt
python3 mmr_test.py /tmp/mmr-03.txt      # inclusion receipts -> results.json
python3 mmr_consistency.py               # consistency receipts -> consistency-results.json
```

Python 3, `cbor2` and `cryptography`. `interop/run.sh` runs both and fails if the committed results change.

## Results

**Inclusion receipts (sections 4 and 5), `mmr_test.py`.** Each interior hash commits to its one-based position
(section 8.2.1), so the receipt's index is bound: on a log of 200 entries, for 7 receipts, the same path and signature
verify at the entry's index and at no other index from 0 to 1594; another entry, a shortened or a lengthened path are
refused. One exception, found by Bassem Kudsi on the list the same day and reproduced here: when the entry is itself a
peak (the last leaf at an odd leaf count), the path is empty and the index is not used; 60 of 60 such receipts verify at
every index. The receipt states no log size: the signed payload is a peak, the same for a whole range of sizes (entry 0:
the same receipt from 128 to 255 entries), and it still verifies once the log has grown past it.

**Consistency receipts (sections 6 and 7), `mmr_consistency.py`.** This is where an MMR receipt states a size. The
signature covers the list of peaks; the verification of section 7.1 never ties those peaks to positions in tree-size-2.
Three verifiers are run: the steps as written; plus a check of the number of right-peaks; plus the path-length check
that 7.1 recommends. On a log of 400 entries, 9 pairs of sizes, a receipt with tree-size-2 changed to another valid size
is accepted in 18 of 18 cases by the first two and in 10 of 18 by the strictest (from 100 to 200 entries: 20 other
sizes, between 131 and 224 entries). tree-size-1 holds under the strictest verifier. A chain of consistency receipts
catches the wrong size at the next link; a single receipt does not.

## Where the text, read literally, does not work

| | Section | What | Reading used |
|---|---|---|---|
| A | Appendix A.4 | `mask = (1 << (msb + 1)) - 1`, but `msb` is already a mask (A.2): `all_ones(1)`, `all_ones(3)`, `all_ones(7)` are false and `index_height(0)` never ends | `mask = (msb << 1) - 1`, as the prose of A.4 says |
| B | 8 | `append(entry) -> index` does not say which index; the index of the entry just appended gives a malformed log (after 200 leaves, peaks of heights 7, 6, 2, 1, 0, 0) | the index the next entry will take (397 nodes, peaks 7, 6, 3) |
| C | 7.1 | the detached payload is "the consistent accumulator", a list; how it becomes bytes is not said | a CBOR array of bstr; the concatenation gives the same results |
| D | 6.1, 7.1 | 6.1 builds right-peaks by discarding `length(proofs)` peaks, 7.1 step 7 discards the number of roots; they differ when several peaks of tree-size-1 end under one peak of tree-size-2 (4 of 9 pairs) | the receipt is built as 7.1 verifies it |

A and B were sent to the authors on 15 November 2026; C, D and the consistency result were posted on the scitt@ietf.org
thread the same day.

## Already resolved in the authors' editor's copy

Checked on 15 November 2026, after the fact: every point above is already resolved in the editor's copy on GitHub
(robinbryce/draft-bryce-cose-receipts-mmr-profile, main at `f1320c0d63`, 10 October 2026; SHA-256 of
`draft-bryce-cose-receipts-mmr-profile.md`: `1c5f55fa55b591d75f66942421b4570e206e559960bf72e2f9379afe214755fd`), which no
published revision carries yet. A: `mask = (most_sig_bit(pos) << 1) - 1`. B: `append(entry) -> count`, the number of
nodes after the append. C: the detached payload is the accumulator's node values concatenated in descending height
order (#45). D: right-peaks are the peaks of tree-size-2 no consistency path leads to (#17, #44). The consistency
result: tree-size-2 is a REQUIRED protected header parameter, equal to tree-size-2 of the last proof, and tree-size-1
must equal the size the verifier already trusts (#39, #40); "Declared tree sizes" in its Security Considerations
states the case tested here. The empty path: allowed (#28), and "Tree size of a receipt of inclusion" states that the
index is then not bound. The path-length remark of 5.1 is gone (#48). Bassem Kudsi pointed this out on 15 November
2026; issue #58 asks for executable known-answer values.

The results of this folder therefore describe the published -03 text, not the profile as its authors now write it.

## What this does not show

Nothing about a production MMR log: no receipt of a running service was checked. Nothing about the authors'
implementations.
