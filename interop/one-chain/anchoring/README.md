# Case 18, independent time bound: five OpenTimestamps proofs over the chain's bytes

Five objects of the positive chain of `out/positive/` were submitted to OpenTimestamps calendars on 2026-11-06T17:34:21Z
(`subjects/STAMPED-AT.txt`), as the stamping note of that day planned (kept outside this repository), and the proofs were
upgraded on 7 November 2026 once Bitcoin blocks included the calendars' commitments. This directory holds the exact bytes,
the proofs, the block headers the verifier holds, the anchoring 0.2.0 attachment and trust policy, and `verify.py`, which
re-checks everything offline. An assistant wrote the code and the first draft of this README; Laurent Lemonnier read both.

## What was anchored (`subjects/`, `SHA256SUMS`)

| Subject | Bytes | SHA-256 | What it is |
|---|---|---|---|
| `approval-signature.bin` | 64 | `160475c5…` | the raw Ed25519 signature value of the `person_approval` (finance-controller-1-key-1, DR-2026-1104, stage o1): `value_b64` of `out/positive/signatures-attachment.json` |
| `action-binding-attachment-a1.json` | 2,571 | `0c51d7ce…` | the attachment at approval, the bytes the approval covers |
| `action-binding-attachment-a2.json` | 3,801 | `fc818ef4…` | the attachment after execution (attempt and result citing the Harness receipts) |
| `verdict-record.json` | 1,551 | `875dfb88…` | Wright's verdict record (its SHA-256 is `record_sha256` of the container) |
| `dispute-packet.json` | 8,755 | `5bcbfea4…` | the Goshi/Farley dispute packet |

They are byte-identical to the files of `out/positive/` at `341545a` and today (`verify.py` checks both equalities on every run).

## What the proofs reach

Each proof carries four calendar branches, each upgraded to a Bitcoin block header attestation (`ots info`):

| Calendar | Block | Header's time (`miner_stated_time`) |
|---|---|---|
| alice.btc.calendar.opentimestamps.org | 974838 | 2026-11-06T18:44:06Z |
| finney.calendar.eternitywall.com | 974839 | 2026-11-06T18:45:37Z |
| bob.btc.calendar.opentimestamps.org | 974842 | 2026-11-06T18:59:20Z |
| btc.calendar.catallaxy.com | 974847 | 2026-11-06T19:42:53Z |

Both verifiers report the lowest block whose header they hold and which matches: **974838**, hash
`00000000000000000001df1dcade8183e39a15562f369d470e42d9d965f8b1fb`, `miner_stated_time` **2026-11-06T18:44:06Z**, for all
five subjects.

## The header set (`headers/`)

`headers-974838-974852.json`: fifteen 80-byte mainnet headers, 974838 to 974852, fetched on 7 November 2026 from
blockstream.info and from mempool.space (byte-identical between the two; URLs and times in `SOURCES.json`), each with its
block hash recomputed locally (double SHA-256, reversed) and its nTime as UTC. This is the verifier's own file, which the
trust policy names as a `header_file` source (`header-file-one-chain-20261107`): the attachment carries no header, as
anchoring 0.2.0 requires. `verify_anchor.py` validates the set from the checkpoint (block 974838's hash): linkage, proof of
work under each target, target under mainnet's limit (powLimit), nBits constant between retarget boundaries. Two explorers
are not a node: the set shows real work above the checkpoint, not that this is the most-work chain from genesis.

## The two checks (`verify.py`, `result.json`)

1. **Anchoring 0.2.0, the Standard's reference check** (`extensions/anchoring/tests/run_checks.py` at `DPS_STANDARD`, here
   `007f8c9`). `anchoring-attachment.json` is a `dps-anchoring` 0.2.0 attachment, valid against its schema, with one
   `opentimestamps` timestamp whose subject is the signature value, named as the profile names an assertion of the
   signatures profile (`person_approval`, `finance-controller-1-key-1`, `DR-2026-1104`, stage `o1`).
   `trust-policy-anchoring.json` is the case's trust policy plus the `bitcoin_header_sources` entry. `check_timestamp`
   reports `proof`, `operations`, `attestation` and `header` **verified**, block 974838 and `miner_stated_time`
   2026-11-06T18:44:06Z; `subject_bytes` is **not_checked** by design (the reference check holds checkpoints only and says
   the signatures profile checks an assertion's signature), so the result's status is `not_checked`; `verify.py` checks
   that the value is the one `signatures-attachment.json` carries. The four documents are **not** subjects anchoring 0.2.0
   defines (a seal, a chain link, a signature value), so they cannot be carried in the attachment: `document-proofs.json`
   holds them in a shape local to this case, and `verify.py` runs the reference check's OpenTimestamps path (`check_ots`)
   over each, with the subject's bytes checked by `verify.py` against `SHA256SUMS` and `out/positive/`: all five checks
   **verified**, block 974838, the same `miner_stated_time`.
2. **draft-fassbender-scitt-time-anchor-08, route 2** (`../../umarise/verify_anchor.py`, no OpenTimestamps software): each
   subject and proof against the validated header set: **valid**, `block_height_H` 974838, `block_time_RWCP` 1793990646
   (= 2026-11-06T18:44:06Z), 15 confirmations established (6 required).

`verify.py` exits 0 only when every proof is verified on both routes and both report the same block and the same header
time; `run.sh` runs it offline and compares `result.json` with the committed one.

## What this shows, and does not

The proofs show that these exact bytes existed before block 974838 was mined, according to the header the verifier
holds: the five objects of this chain (the person's signature value among them) were fixed by 2026-11-06T18:44:06Z as the
miner states it. That time is the miner's statement, reported as `miner_stated_time` and never as a time the bytes
existed at (consensus only holds it above the median of the previous eleven blocks). The proofs do not show who wrote
an object, nor that its content is true, nor the order of two objects anchored in the same block. The case's own times
(the approval at `2026-11-04T10:01:10Z`, the run) are synthetic and fixed: the time bound is real, the operation is not.
Nothing in the chain's outputs or verdicts changes: the reference check does not compare an issuer's time with a block,
and no key state rests on it.

One observation for the Standard: for a signature subject of the signatures profile, `check_timestamp` returns the block
and `miner_stated_time` with status `not_checked`, while `verification-report.schema.json` allows `block` and
`miner_stated_time` only on a `verified` result (`result_against_report_schema` in `result.json`); a report writer has to
drop them, and the time bound the proof gives on the signature is then not in the report.

## Running

```
DPS_STANDARD=/path/to/decision-provenance-standard/standard python3 verify.py      # exit 0 when all_verified; writes result.json
/path/to/ots info subjects/verdict-record.json.ots                                 # the proof as the OpenTimestamps client reads it
```

Python 3.12, `cryptography`, `jsonschema`, `asn1crypto` (the reference check's imports). No network: `ots verify` would
need a Bitcoin node and is not used; the headers are the pinned file.

## History note (7 November 2026)

The anchoring files landed in two commits by mistake of the push tooling: 0c44f18 and 35e6d64 carried the directory
without `subjects/verdict-record.json`, `subjects/verdict-record.json.ots` and case 18b's `verdict-record.json.ots`,
which arrived in 647ceba with unrelated files; CI was red on 35e6d64 for that reason only. `verify.py` now names a
missing subject or proof instead of failing on it, and `SHA256SUMS` lists the `.ots` files too.
