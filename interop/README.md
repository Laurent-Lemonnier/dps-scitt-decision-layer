# Interop: independent verifiers for neighbouring SCITT drafts

Verifiers written from the text of other authors' drafts, run against their published test vectors, as a third party.
Each one imports nothing from the author's reference code; the point is to check that the text alone is enough to
reach the published verdicts, and to say where it is not. Results as of 2026-10-29.

| Draft | Vectors | Result | Not covered |
|---|---|---|---|
| draft-chueayen-attestation-receipts-05 (Seal ATTESTATION-v1, ACTION-v1) | 33 + 34, release 1.4.0 | 33/33 and 34/34 verdicts match `valid/` and `invalid/` | the chain, complete, transparency, witnessed, acceptance and bytes suites; one ambiguity found in ATTESTATION-v1 §4 (see `aqta/README.md`) |
| draft-gilda-audit-agent-audit-record-02 (corpus v0.28.0) | 141 members | 141/141 agree on verdict, refusal codes, derived tier, withinLimit and the set checks; first refusal code agrees on 81/81 reject members | anchor validation of retained records (Section 4.7.2), so R3, R7, R11 dating and `datedAt` were not attempted |

- `aqta/aqta_verify_independent.py` — Ed25519 over the canonical payload of §6, UTF-16 key order, literal UTF-8,
  ECMA-262 number form, whole-value ASCII-digit patterns of §7. Runs: `run-attestation-20261029.txt`, `run-action-20261029.txt`.
- `gilda/gilda_verify_independent.py` — RFC 7493 strict parse, RFC 8785 bytes under DSSE PAE, the membership and closed
  vocabularies of Section 5, the recomputes of Section 4.6 (request digest, write chain, agreement, commitment, evaluation
  freshness, tier), the set checks of 5.9 and 5.10, and the parts of 4.7 that need no anchor. Report: `judge-20261029.json`.

Both are offered to their authors for review. They are not conformance claims by the authors, and the README in each
directory lists what was left out. Licence: Apache-2.0, as the rest of this repository.
