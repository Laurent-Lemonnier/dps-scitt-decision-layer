# The header set the verifier holds

`SOURCES.json` says where each header came from (blockstream.info, then mempool.space, byte-identical), when (UTC start
and end of each fetch, 7 November 2026), the checkpoint the set is validated from, and the rule for the two values
computed locally: `block_hash` = SHA-256(SHA-256(header)) with the bytes reversed; `miner_stated_time` = the header's
nTime (bytes 68 to 71, little-endian) as UTC. The headers file is read offline by `../verify.py`, by the Standard's
reference check as a `header_file` source (named in `../trust-policy-anchoring.json`, never carried in the attachment)
and by `../../../umarise/verify_anchor.py` as its validated chain (`--chain`, `--checkpoint`). A block's time is the
miner's statement; it is reported as `miner_stated_time`, never as a time anything existed at.
