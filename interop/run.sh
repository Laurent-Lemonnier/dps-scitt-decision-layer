#!/usr/bin/env bash
# Replays the published test vectors of two neighbouring drafts through the
# independent verifiers in this directory. Exits non-zero if any vector's
# verdict differs from what its author published. Used by the CI workflow and
# runnable locally: ./interop/run.sh
set -euo pipefail
cd "$(dirname "$0")"

AQTA_REPO=https://github.com/Aqta-ai/attestation-spec.git
AQTA_COMMIT="${AQTA_COMMIT:-$(cat aqta/PINNED_COMMIT)}"
AQTA_ATTESTATION_KEY=alWzEnrA_z9McN9z_MFfQCnH9mVgOwRZ26wrI7oix4E   # test-vectors/README.md
AQTA_ACTION_KEY=pOaccW6Csyo1POtxjixPH80oux9--YC1tzzaENT4vQ0        # test-vectors/action/README.md
GILDA_VERSION=0.28.0

python3 -m pip install --quiet "cryptography>=42" "agent-evidence-vectors==${GILDA_VERSION}"

if [ ! -d aqta/attestation-spec ]; then
  git clone --quiet "$AQTA_REPO" aqta/attestation-spec
fi
git -C aqta/attestation-spec checkout --quiet "$AQTA_COMMIT"
V=aqta/attestation-spec/test-vectors

echo "== Seal ATTESTATION-v1 (draft-chueayen-attestation-receipts), attestation-spec @ ${AQTA_COMMIT:0:12}"
python3 aqta/aqta_verify_independent.py --profile attestation --key "$AQTA_ATTESTATION_KEY" "$V"/valid/*.json "$V"/invalid/*.json | tail -1
echo "== Seal ACTION-v1"
python3 aqta/aqta_verify_independent.py --profile action --key "$AQTA_ACTION_KEY" "$V"/action/valid/*.json "$V"/action/invalid/*.json | tail -1

echo "== Seal ACTION-v1 Section 8.3: the approval record as a DPS signed outcome (aqta/approval-record)"
python3 -m pip install --quiet jsonschema "asn1crypto==1.5.1"
DPS_STANDARD_COMMIT="${DPS_STANDARD_COMMIT:-$(cat aqta/approval-record/DPS_STANDARD_COMMIT)}"
if [ ! -d aqta/approval-record/dps-standard ]; then
  git clone --quiet https://github.com/decision-provenance-standard/standard.git aqta/approval-record/dps-standard
fi
git -C aqta/approval-record/dps-standard checkout --quiet "$DPS_STANDARD_COMMIT"
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 aqta/approval-record/build.py > aqta/approval-record/out/build-ci.log
grep -q '"all_verified": true' aqta/approval-record/out/build-ci.log || { echo "approval record: not all verified"; tail -20 aqta/approval-record/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 aqta/approval-record/negatives.py > aqta/approval-record/out/negatives-ci.log || { echo "approval record: a negative case did not fail where it should"; tail -30 aqta/approval-record/out/negatives-ci.log; exit 1; }
echo "# action record valid under the Seal text; DPS action binding and person approval verified; 10 Section 8.2 checks true; 8 failing cases (N1-N7) fail where they should; N7b (authority_ref relabelled) verifies by design"

echo "== One agent pass, three layers (agent-pass): DPS standing and exact approvals, Seal ACTION-v1, Agent Action Capsule"
python3 -m pip install --quiet "agent-action-capsule==0.12.0"
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 agent-pass/build.py > agent-pass/out/build-ci.log || { echo "agent pass: not all verified"; tail -30 agent-pass/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 agent-pass/negatives.py > agent-pass/out/negatives-ci.log || { echo "agent pass: a failing case was not caught where expected"; cat agent-pass/out/negatives-ci.log; exit 1; }
echo "# 40 Seal records valid; 8 DPS dimensions and 13 person signatures verified; 41 capsules verified; 7 joins true; 10 failing cases caught where expected"

echo "== draft-fassbender-scitt-time-anchor-08, Appendix D vectors, route 2 (no OTS software)"
CP=957289:000000000000000000018e5b8c68a63c45b3eeac3a05ecf621a3b3f7890e3534
for n in 1 2 3 4; do
  python3 umarise/verify_anchor.py --artifact umarise/vectors/vector$n.txt --proof umarise/vectors/vector$n.ots \
    --chain umarise/headers-957289-957300.json --checkpoint "$CP" | grep -q '"result": "valid"' || { echo "vector$n: not valid"; exit 1; }
done
printf 'draft-fassbender-scitt-time-anchor-03 vector X' > /tmp/umarise-bad.txt
# the verifier exits 1 for anything but valid, which is the expected outcome here
neg=$(python3 umarise/verify_anchor.py --artifact /tmp/umarise-bad.txt --proof umarise/vectors/vector1.ots \
  --chain umarise/headers-957289-957300.json --checkpoint "$CP" || true)
grep -q '"result": "invalid"' <<<"$neg" || { echo "D.6 negative: not invalid: $neg"; exit 1; }
nochain=$(python3 umarise/verify_anchor.py --artifact umarise/vectors/vector1.txt --proof umarise/vectors/vector1.ots || true)
grep -q '"result": "unverifiable"' <<<"$nochain" || { echo "D.6 no chain: not unverifiable: $nochain"; exit 1; }
echo "# 4 vectors valid at height 957289; D.6 negative invalid; no validated chain unverifiable"

echo "== draft-zambo-aer1-26, conformance kit v1.5.7 (all seven vector suites)"
AER1_REPO=https://gitlab.com/rambozambodotdev/zambo.git
AER1_COMMIT="${AER1_COMMIT:-$(cat aer1/PINNED_COMMIT)}"
if [ ! -d aer1/zambo ]; then
  git clone --quiet "$AER1_REPO" aer1/zambo
fi
git -C aer1/zambo checkout --quiet "$AER1_COMMIT"
python3 aer1/aer1_verify_independent.py --kit aer1/zambo/aer-1 --report aer1/judge-ci.json | tail -1

echo "== draft-gilda-audit-agent-audit-record, corpus vectors-agent-audit-record from agent-evidence-vectors ${GILDA_VERSION}"
CORPUS=$(python3 -c "import agent_evidence_vectors,os;print(os.path.join(os.path.dirname(agent_evidence_vectors.__file__),'corpora','vectors-agent-audit-record'))")
python3 gilda/gilda_verify_independent.py --corpus "$CORPUS" --report gilda/judge-ci.json | tail -1
