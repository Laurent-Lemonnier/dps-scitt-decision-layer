#!/usr/bin/env bash
# Case 18b: submit the five subjects of this chain to OpenTimestamps calendars. NOT run by build.py, run.sh or CI: a
# submission is a public act with a real clock behind it, and Laurent Lemonnier decides when (and whether) to make it.
#
# The subjects are the exact bytes build.py wrote under subjects/ (SHA256SUMS): the raw DER signature value of the
# passkey assertion (approval-signature.bin), A1, A2, the verdict record and the dispute packet of out/positive/. The
# five proofs of 2026-11-06T17:34:21Z under /root/claude-ops/ietf/horodatage-20261106-case18/ are over CASE 18's bytes
# (the finance controller's Ed25519 test signature, commit 341545a), not these: a different signature, different
# attachments, different times. Nothing here is covered by them.
#
# Usage, from this directory, with the OpenTimestamps client of /root/claude-ops/ietf/ots-venv (opentimestamps-client 0.8.0):
#   ./stamp.sh            # verifies SHA256SUMS, then `ots stamp` each subject, writes <subject>.ots and STAMPED-AT.txt
#   OTS=/path/to/ots ./stamp.sh
# Later, once a Bitcoin block includes the commitments (hours): `ots upgrade *.ots`, then the anchoring 0.2.0 attachment
# and the two verifiers, as planned for case 18 (NOTE.md there).
set -euo pipefail
cd "$(dirname "$0")/subjects"
OTS="${OTS:-/root/claude-ops/ietf/ots-venv/bin/ots}"
[ -x "$OTS" ] || { echo "no ots client at $OTS (set OTS=...)"; exit 2; }
sha256sum -c --quiet SHA256SUMS || { echo "the subjects are not the bytes build.py wrote; rebuild first"; exit 1; }
for f in approval-signature.bin action-binding-attachment-a1.json action-binding-attachment-a2.json verdict-record.json dispute-packet.json; do
  [ -e "$f.ots" ] && { echo "$f.ots exists; not stamping twice"; continue; }
  "$OTS" stamp "$f"
done
date -u +%Y-%m-%dT%H:%M:%SZ > STAMPED-AT.txt
echo "submitted at $(cat STAMPED-AT.txt); proofs pending until a block: $OTS upgrade *.ots"
