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
GILDA_VERSION=0.31.0

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
grep -q '"dps_extensions_verified": true' aqta/approval-record/out/build-ci.log && grep -q '"outside_the_extensions_verified": true' aqta/approval-record/out/build-ci.log && grep -q '"policy_checks_verified": true' aqta/approval-record/out/build-ci.log || { echo "approval record: not all verified"; tail -20 aqta/approval-record/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 aqta/approval-record/negatives.py > aqta/approval-record/out/negatives-ci.log || { echo "approval record: a negative case did not fail where it should"; tail -30 aqta/approval-record/out/negatives-ci.log; exit 1; }
echo "# action record valid under the Seal text; DPS action binding and person approval verified; 10 Section 8.2 checks true; 8 failing cases (N1-N7) fail where they should; N7b (authority_ref relabelled) verifies by design"

echo "== One agent pass, three layers (agent-pass): DPS standing and exact approvals, Seal ACTION-v1, Agent Action Capsule"
python3 -m pip install --quiet "agent-action-capsule==0.12.0"
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 agent-pass/build.py > agent-pass/out/build-ci.log || { echo "agent pass: not all verified"; tail -30 agent-pass/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 agent-pass/negatives.py > agent-pass/out/negatives-ci.log || { echo "agent pass: a failing case was not caught where expected"; cat agent-pass/out/negatives-ci.log; exit 1; }
echo "# 40 Seal records valid; 8 DPS dimensions and 13 person signatures verified; 41 capsules verified; 7 joins true; 10 failing cases caught where expected"

echo "== One plan approved as a whole, executed as steps (plan-run): one DPS exact approval, N capsules, a run manifest between them"
mkdir -p plan-run/out
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 plan-run/build.py > plan-run/out/build-ci.log || { echo "plan run: not all verified"; tail -30 plan-run/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 plan-run/negatives.py > plan-run/out/negatives-ci.log || { echo "plan run: a failing case was not caught where expected"; cat plan-run/out/negatives-ci.log; exit 1; }
echo "# 8 DPS dimensions, the issuer's seal and the person's approval of the plan verified; 3 capsules verified; 10 joins true (membership, completeness, order, resolved arguments, context chain); 14 failing cases caught where expected"

echo "== A human checkpoint in the middle of the plan, under an undecided claim (plan-checkpoint): a second decision record on a context state and an adjudication in the shape of P10"
mkdir -p plan-checkpoint/out
(cd plan-checkpoint/vectors && sha256sum -c --quiet SHA256SUMS) || { echo "plan checkpoint: the pinned copy of the P10 executed instance changed"; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 plan-checkpoint/build.py > plan-checkpoint/out/build-ci.log || { echo "plan checkpoint: not all verified"; tail -30 plan-checkpoint/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 plan-checkpoint/negatives.py > plan-checkpoint/out/negatives-ci.log || { echo "plan checkpoint: a failing case was not caught where expected"; cat plan-checkpoint/out/negatives-ci.log; exit 1; }
echo "# the plan's checks again, the checkpoint record's dimensions, seal and approval verified, 15 joins true; 8 failing cases caught where expected; the adjudication is synthetic and says so; the P10 executed instance's adjudication statement (leaf 7) held at its pinned digest"

echo "== Case 13: the approved plan and an AER-1 workflow receipt in seq-output-v1, composed (plan-workflow)"
mkdir -p plan-workflow/out
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 plan-workflow/build.py > plan-workflow/out/build-ci.log || { echo "plan workflow: not all verified"; tail -30 plan-workflow/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 plan-workflow/negatives.py > plan-workflow/out/negatives-ci.log || { echo "plan workflow: a failing case was not caught where expected"; cat plan-workflow/out/negatives-ci.log; exit 1; }
echo "# the plan's ten joins and five more true; three AER-1 step receipts verified; the workflow root recomputed in seq-output-v1; 6 failing cases caught where expected"

echo "== An EP authorization bundle and a DPS decision, bound both ways (emilia-pair), at the EP author's request"
(cd emilia-pair/vectors && sha256sum -c --quiet SHA256SUMS) || { echo "emilia-pair: the pinned EP vector file changed"; exit 1; }
mkdir -p emilia-pair/out
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 emilia-pair/build.py > emilia-pair/out/build-ci.log || { echo "emilia pair: not all verified"; tail -30 emilia-pair/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 emilia-pair/negatives.py > emilia-pair/out/negatives-ci.log || { echo "emilia pair: a failing case was not caught where expected"; cat emilia-pair/out/negatives-ci.log; exit 1; }
echo "# DPS A1 and A2 verified; EP bundle SATISFIED by a verifier written from section 6.2, and the author's valid-non-oauth-native-binding example SATISFIED; 5 joins true; 11 failing cases caught where expected"

echo "== PALA-1 bridge run B3 (Assault-Consulting/Palimpsests, SCITT-bridge statement v3) from the text, pinned at $(awk '{print substr($NF,1,12)}' pala/vectors/PINNED_COMMIT.txt)"
(cd pala/vectors && sha256sum -c --quiet SHA256SUMS) || { echo "pala: pinned vector files changed"; exit 1; }
mkdir -p pala/out
python3 pala/verify_statement_v3.py --vectors pala/vectors --report pala/out/report-ci.json | tail -1

echo "== P10 S2b, the replay verifier of draft-nestorov-scitt-p10-underdetermination-02, read from the text (first pass), pinned at $(awk '{print substr($2,1,12)}' p10/PINNED_COMMIT.txt)"
if [ ! -d p10/s2b ]; then
  git clone --quiet https://github.com/VolMax-Studio/p10-replay-verifier.git p10/s2b
fi
git -C p10/s2b checkout --quiet "$(awk '{print $2}' p10/PINNED_COMMIT.txt)"
(cd p10/s2b && sha256sum -c --quiet ../SHA256SUMS) || { echo "p10: a file read by the reading changed at the pin"; exit 1; }
mkdir -p p10/out
python3 p10/replay_from_text.py --vectors p10/s2b --report p10/out/report-ci.json | tail -1

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

echo "== draft-zambo-aer1-26, conformance kit v1.5.7 (all seven vector suites, and the seq-output-v1 workflow vectors)"
AER1_REPO=https://gitlab.com/rambozambodotdev/zambo.git
AER1_COMMIT="${AER1_COMMIT:-$(cat aer1/PINNED_COMMIT)}"
if [ ! -d aer1/zambo ]; then
  git clone --quiet "$AER1_REPO" aer1/zambo
fi
git -C aer1/zambo checkout --quiet "$AER1_COMMIT"
python3 aer1/aer1_verify_independent.py --kit aer1/zambo/base --report aer1/judge-ci.json | tail -1

echo "== A decision record and an AER-1 receipt, composed (aer1-decision), at the author's request"
mkdir -p aer1-decision/out
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" AER1_KIT="$PWD/aer1/zambo/base" python3 aer1-decision/build.py > aer1-decision/out/build-ci.log || { echo "aer1-decision: not all verified"; tail -30 aer1-decision/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" AER1_KIT="$PWD/aer1/zambo/base" python3 aer1-decision/negatives.py > aer1-decision/out/negatives-ci.log || { echo "aer1-decision: a failing case was not caught where expected"; cat aer1-decision/out/negatives-ci.log; exit 1; }
echo "# receipt verified (independent and kit), DPS attachment, seal and approval verified, 5 joins true; 10 failing cases as expected; 4 metadata probes failed by the independent verifier and by the kit runner at this pin"

echo "== draft-gilda-audit-agent-audit-record-03, corpus vectors-agent-audit-record from agent-evidence-vectors ${GILDA_VERSION} (anchors validated offline against the manifest's tree heads and test-chain headers; dating complete)"
CORPUS=$(python3 -c "import agent_evidence_vectors,os;print(os.path.join(os.path.dirname(agent_evidence_vectors.__file__),'corpora','vectors-agent-audit-record'))")
python3 gilda/gilda_verify_independent.py --corpus "$CORPUS" --report gilda/judge-ci.json | tail -1

echo "== approval-binding/v1 (the same package's vectors-approval-binding contract), verifier written from the corpus README's eleven checks"
AB_CORPUS=$(python3 -c "import agent_evidence_vectors,os;print(os.path.join(os.path.dirname(agent_evidence_vectors.__file__),'corpora','vectors-approval-binding'))")
python3 gilda/approval_binding_verify_independent.py --corpus "$AB_CORPUS" --report gilda/judge-approval-binding-ci.json | tail -1
