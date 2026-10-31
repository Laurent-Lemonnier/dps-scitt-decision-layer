# Interop: independent verifiers for neighbouring SCITT drafts

Verifiers written from the text of other authors' drafts, run against their published test vectors, as a third party.
Each one imports nothing from the author's reference code; the point is to check that the text alone is enough to
reach the published verdicts, and to say where it is not. Results as of 2026-10-29.

| Draft | Vectors | Result | Not covered |
|---|---|---|---|
| draft-chueayen-attestation-receipts-05 (Seal ATTESTATION-v1, ACTION-v1) | 33 + 34, release 1.4.0 | 33/33 and 34/34 verdicts match `valid/` and `invalid/` | the chain, complete, transparency, witnessed, acceptance and bytes suites; one ambiguity found in ATTESTATION-v1 §4 (see `aqta/README.md`) |
| Seal ACTION-v1 §8.3 (Chueayen): the approval record as a DPS signed outcome | 1 worked example, 3 verifications + 10 §8.2 checks, 9 failing cases | action record valid under the Seal text; DPS action binding and person approval verified; all §8.2 bindings hold; N1–N7 fail where they should | since the Steward's answer on [#93](https://github.com/decision-provenance-standard/standard/issues/93), the designating policy is signed through the specification (`policy_version` = SHA-256 of the issuer's policy); the sidecar only names it; see `aqta/approval-record/README.md` |
| One agent pass, three layers (`agent-pass/`): DPS standing and exact approvals (WHO), Seal ACTION-v1 (CAN), Agent Action Capsule 0.12.0 (WHAT) | 1 synthetic pass: 35 effects, 5 refusals, 13 signatures, 40 Seal records, 41 capsules; 10 failing cases | every side verified on its own, and 7 joins across them true; each failing case caught where expected | synthetic data modelled on a real pass; see `agent-pass/README.md` |
| draft-fassbender-scitt-time-anchor-08 (Appendix D) | 4 proofs + the D.6 negative and unverifiable cases | all 4 valid at height 957289 by route 2 (replay without OTS software, against a header set the verifier checks for proof-of-work and linkage); D.6 cases give invalid and unverifiable | the result is conditional on the checkpoint the verifier holds (block 957289's hash, from two explorers), not on a node of its own; see `umarise/README.md` |
| draft-zambo-aer1-26 (conformance kit v1.5.7) | 119: receipt-level (52), unicode (3), id-binding (6), anchor report (6), chains -06 and -07 (35), commitments (8), Merkle (9) | 119/119 | the kit's frozen-corpus manifests and cross-runner checks; four draft-vs-kit discrepancies found (the fourth: the kit never recomputed the Section 3.1 metadata block; fixed by the author in both runners at `5d1504b`, verified here, the pin moved there), see `aer1/README.md` |
| A decision record and an AER-1 receipt, composed (`aer1-decision/`), at the AER-1 author's request | 1 refund: a DPS attachment sealed by the issuer with a person's approval, and the gateway's 0.4 receipt; 10 failing cases, 4 metadata probes | receipt verified by the independent verifier and the kit's own checks; DPS dimensions, seal and approval verified; 5 joins true (attempt cites id and output_hash; the receipt's input carries the DPS request_id and the approved values) | `execution_context` naming the record is outside metadata_hash (Section 3.2): reported as a pointer, never a binding; see `aer1-decision/README.md` |
| draft-gilda-audit-agent-audit-record-02 (corpus v0.28.0) | 141 members | 141/141 agree on verdict, refusal codes, derived tier, withinLimit and the set checks; first refusal code agrees on 81/81 reject members | anchor validation of retained records (Section 4.7.2), so R3, R7, R11 dating and `datedAt` were not attempted |

- `aqta/aqta_verify_independent.py` — Ed25519 over the canonical payload of §6, UTF-16 key order, literal UTF-8,
  ECMA-262 number form, whole-value ASCII-digit patterns of §7. Runs: `run-attestation-20261029.txt`, `run-action-20261029.txt`.
- `gilda/gilda_verify_independent.py` — RFC 7493 strict parse, RFC 8785 bytes under DSSE PAE, the membership and closed
  vocabularies of Section 5, the recomputes of Section 4.6 (request digest, write chain, agreement, commitment, evaluation
  freshness, tier), the set checks of 5.9 and 5.10, and the parts of 4.7 that need no anchor. Report: `judge-20261029.json`.

- `composition-who/README.md` — not a verifier of another author's vectors but a reading: the DPS action-binding
  attachment and person approval against the producer and verifier requirements and the negative classes of the WHO
  slot in draft-mih-sato-agent-accountability-composition, section 6.2, with the existing DPS cases named for each
  class (`cases-map.json`) and the gaps stated as gaps. Read on 29 October against -01, revised on 31 October against
  the -02 candidate at commit f79f9d1 at a co-author's request: one producer rule is new there, the commitment to the
  principal at the seam, and it is recorded as a gap.

Both are offered to their authors for review. They are not conformance claims by the authors, and the README in each
directory lists what was left out. Licence: Apache-2.0, as the rest of this repository.
