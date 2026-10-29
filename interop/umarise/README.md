# Independent implementation of VERIFY-ANCHOR (draft-fassbender-scitt-time-anchor-08) — 2026-10-29

`verify_anchor.py` implements the verification procedure of Section 4.1 and the replay semantics of Section 5 from the
draft's text, and the OpenTimestamps byte format from the description in Appendix D.4 plus the public format
documentation. It uses no OpenTimestamps software and no third-party library: SHA-256 from the standard library, nothing
else. This is route 2 of Appendix D.7.

## Vectors (Appendix D), replayed

| Case | Expected (draft) | Got |
|---|---|---|
| Vectors 1–4, artifact + proof, validated chain reaching 957289 with ≥ 6 confirmations | valid, H = 957289 | **valid**, H = 957289, RWCP 1783591379 = 2026-07-09T10:02:59Z, 12 confirmations established |
| D.6, any byte of the artifact changed, original proof | invalid | **invalid** (the proof's message is not the recomputed hash) |
| D.6, no validated chain at all | unverifiable | **unverifiable** (branch unavailable) |
| D.6, validated chain that does not reach the attested height | unverifiable | **unverifiable** |
| fewer than 6 confirmations established (step 9) | unverifiable | **unverifiable** ("5 confirmations established, 6 required") |
| a header in the set altered (proof-of-work fails) | — | header set rejected by the verifier's own check; result unverifiable, never valid |

Route 1 (D.7): the four artifact hashes, the four leaves SHA-256(hash ‖ nonce), node_12, node_34 and the root
b4d19ae2… recompute exactly from the values printed in D.1 and D.2. The four proof files decoded from D.5 are 1877
bytes each and match the file digests printed beside them.

Commands: see `run.sh` in the parent directory; locally
`python3 verify_anchor.py --artifact vectors/vector1.txt --proof vectors/vector1.ots --chain headers-957289-957300.json --checkpoint 957289:000000000000000000018e5b8c68a63c45b3eeac3a05ecf621a3b3f7890e3534`.

## What "validated chain" means here, honestly

The draft requires the verifier's *own* validated view of the most-work chain (a node it runs, or a header set whose
proof-of-work it verified from a checkpoint it holds), and says that bytes reported by a block explorer are not that.
What this implementation holds:

- `headers-957289-957300.json`: twelve 80-byte headers obtained on 2026-10-29 from two independent public sources
  (blockstream.info and mempool.space), byte-identical between the two (`headers-sources.json`).
- `validate_chain()` checks, offline, that every header meets its own target (proof-of-work), that each links to the
  previous by hash, and that the set is anchored at a checkpoint the verifier holds: the hash of block 957289 as printed
  in Appendix D.3 and as reported by both sources.

So the residual trust is in that checkpoint: twelve headers of valid proof-of-work above it show real work, but not that
this is the most-work chain from genesis. A verifier with its own node would replace the checkpoint by its chain tip.
Under the draft's note on header sources this result is therefore conditional on the checkpoint, and the README says so
rather than reporting an unconditional valid.

## Observations from reading the text

1. The OTS serialisation is, as the draft says (Section 7.2.1), the one thing the profile does not specify. Appendix D.4
   gives enough (tags for append, prepend, SHA-256, fork, attestation; the Bitcoin and pending attestation tags; varint
   lengths) to write the deserialiser from the document plus the public format notes; the magic header and the
   varint-encoded height were the two things taken from outside the text.
2. The step-2 comparison (claimed hash) is only reachable when a claimed hash is supplied; without one, a modified
   artifact is still caught at step 3 (proof message ≠ recomputed hash). Both end in invalid, as D.6 expects.
3. Each proof carries one Bitcoin branch and three pending calendar branches; the fork handling of step 5 matters even
   for these single-attestation vectors.
