# Case 18b, independent time bound: five OpenTimestamps proofs, the real signature value among them

The five subjects `build.py` wrote under `subjects/` on 6 November 2026 (`SHA256SUMS`) were submitted to OpenTimestamps calendars by
`stamp.sh` on 2026-11-06T19:52:59Z (`subjects/STAMPED-AT.txt`), on Laurent Lemonnier's decision, and the proofs were upgraded
on 7 November 2026 once Bitcoin blocks included the calendars' commitments. `verify.py` re-checks them offline with the two
verifiers of case 18 (`../../one-chain/anchoring/verify.py`, which it imports; same file names, this directory's files).
An assistant wrote the code and the first draft of this README; Laurent Lemonnier read both.

## What was anchored (`subjects/`)

| Subject | Bytes | SHA-256 | What it is |
|---|---|---|---|
| `approval-signature.bin` | 72 | `9cdba62a…` | the raw DER signature value of the passkey assertion (WebAuthn-ES256, `laurent-passkey-1`, DR-2026-1104, stage o1), `value_b64` of `out/positive/signatures-attachment.json`: **Laurent Lemonnier's real signature** |
| `action-binding-attachment-a1.json` | 2,613 | `c22c454f…` | the attachment at approval, the bytes the assertion's challenge covers |
| `action-binding-attachment-a2.json` | 3,843 | `a09cb632…` | the attachment after execution |
| `verdict-record.json` | 1,551 | `f2c1b153…` | Wright's verdict record |
| `dispute-packet.json` | 8,749 | `c0769496…` | the Goshi/Farley dispute packet, **as read on 6 November** (see below) |

Four of them are byte-identical to `out/positive/` (`verify.py` checks it; `run.sh` checks `SHA256SUMS` before and after
the build, and `build.py` no longer writes this directory: today's subjects go to `out/anchoring-subjects/`). The fifth,
the dispute packet, is not since 8 November 2026: the anchored bytes (`c0769496…`) are the first reading of
draft-xg-payment-dispute-profile-01 (commit `896cc8e`); the packet the chain now builds (`364477d5…`,
`out/positive/dispute-packet.json`) follows the constructions the profile's author gave by mail on 8 November 2026
(`../../one-chain/README.md`, ambiguity log). The packet is downstream of the approval: the real signature value, A1, A2
and the verdict are unchanged, and their proofs cover them as before. The proof `subjects/dispute-packet.json.ots` is over
the 6 November bytes and over nothing else; nothing in `subjects/` was changed. `readings.json` records both digests and
`verify.py` reports the difference (`known_difference` in `result.json`) instead of failing on it, while still requiring
that the current packet be the one recorded. The 8 November packet is not stamped.

## What the proofs reach

Each proof carries four calendar branches; three are upgraded to a Bitcoin block header attestation, one is still the
calendar's promise (`ots info`): in every proof, either alice or bob (the two opentimestamps.org calendars) reaches block
974850 and the other is pending; finney and catallaxy reach their own blocks.

| Calendar | Block | Header's time (`miner_stated_time`) |
|---|---|---|
| alice.btc.calendar.opentimestamps.org or bob.btc.calendar.opentimestamps.org (one per proof) | 974850 | 2026-11-06T20:01:21Z |
| finney.calendar.eternitywall.com | 974877 | 2026-11-07T01:59:37Z |
| btc.calendar.catallaxy.com | 974890 | 2026-11-07T04:12:53Z |

Both verifiers report the lowest matching block held: **974850**, hash
`00000000000000000000d541103f1d49fd6b0e382efbbbabfc5b4093dea4b5c5`, `miner_stated_time` **2026-11-06T20:01:21Z**, for all
five subjects.

## The header set (`headers/`)

`headers-974850-974895.json`: forty-six mainnet headers, 974850 to 974895, fetched on 7 November 2026 from blockstream.info
and mempool.space (byte-identical; `SOURCES.json`), block hash recomputed locally, nTime as UTC. The trust policy names it as
the `header_file` source `header-file-one-chain-real-20261107`; `verify_anchor.py` validates it from the checkpoint (block
974850's hash): linkage, proof of work, powLimit, the difficulty rule. Two explorers are not a node: real work above the
checkpoint, not the most-work chain from genesis.

## The two checks (`verify.py`, `result.json`)

As in case 18 (`../../one-chain/anchoring/README.md`): the anchoring 0.2.0 reference check at `DPS_STANDARD` (`007f8c9`) over
`anchoring-attachment.json` (one `opentimestamps` timestamp, subject the signature value of the `person_approval`,
`laurent-passkey-1`, `DR-2026-1104`, `o1`) with `trust-policy-anchoring.json` (the case's policy plus the header source):
`proof`, `operations`, `attestation`, `header` **verified**, block 974850, `miner_stated_time` 2026-11-06T20:01:21Z,
`subject_bytes` **not_checked** by design (status `not_checked`; `verify.py` checks the value against the signatures
attachment). The four documents, not a subject kind anchoring 0.2.0 defines, are in `document-proofs.json` and go through
the reference check's `check_ots` with the bytes checked by `verify.py`: all five checks **verified**. Route 2 of
draft-fassbender-scitt-time-anchor-08 (`../../umarise/verify_anchor.py`): **valid**, `block_height_H` 974850,
`block_time_RWCP` 1793995281, 46 confirmations established.

## What this shows, and does not

The signature value existed before block 974850 was mined, according to the header the verifier holds: by
2026-11-06T20:01:21Z as the miner states it, where the assertion's `signed_at` reads 19:05:00Z and sign.pria.fr received
it at 19:06:54Z. That is an upper bound from a clock none of the parties controls, on the bytes of the signature; the key
state check of the signatures profile in `build.py` still reads the stated time (it is not rewired to this proof), and
nothing in the chain's outputs changes. The same bound holds for A1, A2, the verdict and the packet. The header's time is
the miner's statement (`miner_stated_time`), never a time the bytes existed at. The proofs do not show who wrote an
object (the signature's author is what the signatures check establishes, not the proof), nor that an object's content is
true, nor the order of two objects anchored in the same block. The five proofs of 2026-11-06T17:34Z in `../../one-chain/anchoring/`
are over case 18's bytes and cover nothing here.

## Running

```
DPS_STANDARD=/path/to/decision-provenance-standard/standard python3 verify.py      # exit 0 when all_verified; writes result.json
```

`stamp.sh` is not run by `build.py`, `run.sh` or CI; it refuses to stamp a subject that already has a proof.
