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
# The agent-evidence-vectors release is pinned in requirements-gilda.txt (Dependabot opens a weekly PR when a new one
# is published, .github/dependabot.yml). The pin moves only when both verifiers in gilda/ agree with the release in
# full: 0.36.3 since 8 November 2026 (audit-record 217/217, approval-binding 37/37; gilda/run-20261108.txt); 0.35.0
# from 7 November (193/193, 36/36; gilda/run-20261107b.txt).
GILDA_VERSION=$(sed -n 's/^agent-evidence-vectors==//p' requirements-gilda.txt)

python3 -m pip install --quiet "cryptography>=42" "cbor2>=5" -r requirements-gilda.txt

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
python3 -m pip install --quiet "agent-action-capsule==0.16.0"
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 agent-pass/build.py > agent-pass/out/build-ci.log || { echo "agent pass: not all verified"; tail -30 agent-pass/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 agent-pass/negatives.py > agent-pass/out/negatives-ci.log || { echo "agent pass: a failing case was not caught where expected"; cat agent-pass/out/negatives-ci.log; exit 1; }
echo "# 40 Seal records valid; 8 DPS dimensions and 13 person signatures verified; 41 capsules verified; 7 joins true; 10 failing cases caught where expected"

echo "== Agent Action Capsule interop cases (aac): the capsule library 0.16.0 and the Standard's reference checks, both sides and the join, cases 01 to 05 and 14 to 16"
# cases 06 to 08 (the live Transparency Service, the COSE forms under scitt-cose, the NOA receipt) have their own scripts and are not replayed here
python3 -m pip install --quiet jsonschema referencing "agent-action-capsule==0.16.0"
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 aac/check_case.py aac/cases/0[1-5]-* aac/cases/1[4-6]-* > aac/check-ci.log || { echo "aac: a case did not report what its expected.json says"; cat aac/check-ci.log; exit 1; }
git diff --exit-code --quiet -- aac/cases/*/result.json || { echo "aac: a result.json differs from the committed one"; git --no-pager diff -- aac/cases/*/result.json; exit 1; }
echo "# 8 cases as expected: 01 verified on both sides and the join; 02 and 05 reference unresolved, Standard not consulted; 03 approval absent; 04 resolution is not validity; 14 join failed; 15 and 16 required reference missing, never verified (Ivan Nestorov's review of 6 November 2026); result.json byte-identical to the committed ones"

echo "== One plan approved as a whole, executed as steps (plan-run): one DPS exact approval, N capsules, a run manifest between them"
mkdir -p plan-run/out
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 plan-run/build.py > plan-run/out/build-ci.log || { echo "plan run: not all verified"; tail -30 plan-run/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 plan-run/negatives.py > plan-run/out/negatives-ci.log || { echo "plan run: a failing case was not caught where expected"; cat plan-run/out/negatives-ci.log; exit 1; }
echo "# 8 DPS dimensions, the issuer's seal and the person's approval of the plan verified; 3 capsules verified; 10 joins true (membership, completeness, order, resolved arguments, context chain); 14 failing cases caught where expected"

echo "== Case 13b: the plan, approved by a real person (plan-run-real): Laurent Lemonnier's passkey assertion (WebAuthn-ES256, sign.pria.fr) over the exact person_approval bytes of the plan, pinned in signed/, verified by the Standard's check; the three capsules under it"
(cd plan-run-real/signed && sha256sum -c --quiet SHA256SUMS) || { echo "plan-run-real: the pinned signed inputs changed"; exit 1; }
mkdir -p plan-run-real/out
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 plan-run-real/build.py > plan-run-real/out/build-ci.log || { echo "plan-run-real: not all verified"; tail -30 plan-run-real/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 plan-run-real/negatives.py > plan-run-real/out/negatives-ci.log || { echo "plan-run-real: a failing case was not caught where expected"; cat plan-run-real/out/negatives-ci.log; exit 1; }
echo "# one real signature: verified (signature, UP, UV, origin, rpId, key state, identity under the pinned trust policy); the run as in case 13: 8 DPS dimensions, the issuer's seal, 3 capsules verified, 10 joins true; assemble reproduces case 13 byte for byte; 24 failing cases caught where expected (case 13's 14 and 10 on the real thing), nine of them by the Standard's signatures check alone"

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
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 emilia-pair/build.py --vector emilia-pair/vectors/authorization-bundle.v1.json > emilia-pair/out/vector-ci.log || { echo "emilia pair: the vector run did not complete"; tail -5 emilia-pair/out/vector-ci.log; exit 1; }
echo "# DPS A1 and A2 verified; EP bundle SATISFIED by a verifier written from section 6.2 (steps 1 to 11); 5 joins true; 23 failing cases caught where expected (3 at the DPS/EP junction, 1 on a compromised key's signing order); the author's pinned vector (00fa00a7) predates section 3's minimum: run over its 27 cases and reported, not checked (emilia-pair/README.md)"

echo "== PALA-1 bridge run B3 (Assault-Consulting/Palimpsests, SCITT-bridge statement v3) from the text, pinned at $(awk '{print substr($NF,1,12)}' pala/vectors/PINNED_COMMIT.txt)"
(cd pala/vectors && sha256sum -c --quiet SHA256SUMS) || { echo "pala: pinned vector files changed"; exit 1; }
mkdir -p pala/out
python3 pala/verify_statement_v3.py --vectors pala/vectors --report pala/out/report-ci.json | tail -1

echo "== P10 S2b, the replay verifier of draft-nestorov-scitt-p10-underdetermination-02, read from the text (first and second pass), pinned at $(awk '{print substr($2,1,12)}' p10/PINNED_COMMIT.txt)"
if [ ! -d p10/s2b ]; then
  git clone --quiet https://github.com/VolMax-Studio/p10-replay-verifier.git p10/s2b
fi
git -C p10/s2b checkout --quiet "$(awk '{print $2}' p10/PINNED_COMMIT.txt)"
(cd p10/s2b && sha256sum -c --quiet ../SHA256SUMS) || { echo "p10: a file read by the reading changed at the pin"; exit 1; }
mkdir -p p10/out
python3 p10/replay_from_text.py --vectors p10/s2b --pass 1 --report p10/out/report-ci.json | tail -1
python3 p10/replay_from_text.py --vectors p10/s2b --pass 2 --report p10/out/report-ci-pass2.json \
  --pass1-report p10/out/report-pass1.json | tail -1

echo "== P10 Appendix A (M1-M35, AP1) read from the text, the profile, S1 and S2a pinned per the draft's Appendix C.1"
for pin in "p10-underdetermination-profile e2a02a73df9e50f624512043dcb007fc337ba587" \
           "p10-underdetermination-lean-s1 e4db3747eaeeb1a07227bb9029f9a9c3b566cdb1" \
           "p10-coverage-lean-s2 741d56d36d7b2bfe2e9e0080a1cba4393e4a47da"; do
  set -- $pin
  [ -d "p10/appendix-a/repos/$1" ] || git clone --quiet "https://github.com/VolMax-Studio/$1.git" "p10/appendix-a/repos/$1"
  git -C "p10/appendix-a/repos/$1" checkout --quiet "$2"
done
(cd p10/appendix-a/repos && sha256sum -c --quiet ../SHA256SUMS) || { echo "p10 appendix A: a file read changed at the pin"; exit 1; }
python3 p10/appendix-a/appendix_a_checks.py | grep -q 'S1 vectors: 15/15 agree' || { echo "p10 appendix A: S1 vectors"; exit 1; }
python3 p10/appendix-a/s2a_from_text.py | grep -q '72 vectors, 72 agree' || { echo "p10 appendix A: S2a coverage"; exit 1; }
git diff --exit-code --quiet -- p10/appendix-a/out || { echo "p10 appendix A: the outputs differ from the committed ones"; exit 1; }
echo "# Appendix A: S1 15/15, S2a coverage 72/72 with exact reason codes, TB7 72/72"

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
python3 umarise/synthetic_headers_check.py || { echo "umarise: synthetic linked headers above mainnet's target were validated"; exit 1; }
echo "# 4 vectors valid at height 957289; D.6 negative invalid; no validated chain unverifiable; synthetic headers with nBits 0x207fffff refused"

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

echo "== A real AER-1 receipt (zambo.dev, 10 November 2026) and a decision record, composed (aer1-live), at the author's request; no kit code, nothing fetched"
mkdir -p aer1-live/out
(cd aer1-live && sha256sum -c --quiet <(echo "9e6aff78d4d0f64685d069988f2bccdbcc6f771b76cf33aeb86292b88c0aa8d6  receipt.json")) || { echo "aer1-live: receipt.json is not the bytes as served"; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 aer1-live/build.py > aer1-live/out/build-ci.log || { echo "aer1-live: not as expected"; tail -30 aer1-live/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 aer1-live/negatives.py > aer1-live/out/negatives-ci.log || { echo "aer1-live: a failing case was not caught where expected"; cat aer1-live/out/negatives-ci.log; exit 1; }
git diff --exit-code --quiet -- aer1-live/out/summary.json aer1-live/out/receipt-verification.json || { echo "aer1-live: the results differ from the committed ones"; git --no-pager diff -- aer1-live/out/summary.json aer1-live/out/receipt-verification.json; exit 1; }
echo "# real receipt: output_hash and metadata_hash verify, input_hash not confirmed, verifier as is: rejected (verification_status commitment_matches, the v1 API value); (a) after the fact: cited and named, no link back, approval after the effect; (b) synthetic: all joins; 12 cases as expected"

echo "== Case 15: an AgentInteractionRecord citing a decision record by typed digest (air): draft-emirdag-scitt-ai-agent-execution-01 Sections 5.6-5.8, 6.1, 10.1"
(cd air/vectors && sha256sum -c --quiet SHA256SUMS) || { echo "air: the pinned copy of the EES v0.2 air.schema.json changed"; exit 1; }
mkdir -p air/out
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 air/build.py > air/out/build-ci.log || { echo "air: not all verified"; tail -30 air/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 air/negatives.py > air/out/negatives-ci.log || { echo "air: a failing case was not caught where expected"; cat air/out/negatives-ci.log; exit 1; }
echo "# two AIRs VERIFIED by the verifier written from the text (32 checks each, 5.8 four steps and 6.1/6.3/6.4), chain of two VERIFIED; DPS dimensions, seal and approval verified; 6 joins true, binding BOUND; 13 failing cases caught where expected (N8 NOT_BOUND and N9 UNRESOLVED by design)"

echo "== Case 16: a verdict record over the signed decision chain, and a decision over a verdict (verdict-record): draft-wright-verdict-record-02 Sections 2, 3, 4, 6, 7, checker written from the text"
mkdir -p verdict-record/out
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 verdict-record/build.py > verdict-record/out/build-ci.log || { echo "verdict record: not all verified"; tail -30 verdict-record/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 verdict-record/negatives.py > verdict-record/out/negatives-ci.log || { echo "verdict record: a failing case was not caught where expected"; cat verdict-record/out/negatives-ci.log; exit 1; }
echo "# DPS: A1, A2, the closing decision and the corrected pair verified (dimensions, seals, approvals); verdict version 1, the stated negative over the 150/120 chain and version 2 released by the checker written from the text; Wright's Appendix A digests reproduced and his A.2 record released, held, refused and held as his text predicts; 11 joins true; 16 failing cases as expected (N10b released and named by design)"

echo "== Case 17: the proof behind confirm (agent-execution-evidence): draft-thaha-scitt-agent-execution-evidence-02 Sections 5, 6.7, 6.7.1, 7, 8, 9 and Appendix A, and the DPS signed outcome"
mkdir -p agent-execution-evidence/out
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 agent-execution-evidence/build.py > agent-execution-evidence/out/build-ci.log || { echo "agent-execution-evidence: not all verified"; tail -30 agent-execution-evidence/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 agent-execution-evidence/negatives.py > agent-execution-evidence/out/negatives-ci.log || { echo "agent-execution-evidence: a failing case was not caught where expected"; cat agent-execution-evidence/out/negatives-ci.log; exit 1; }
echo "# 9 Appendix A digests reproduced from the text; Bundle of 6 receipts and 6 Signed Statements: CHECKS_PERFORMED (never PASS: steps 1, 4, 5, 7, 11-17 not performed); DPS A1, A2, seal and approval verified; route 1 bound, route 2 (proposal) bound; 7 joins true; 12 failing cases caught where expected"

echo "== Case 18: one chain (one-chain): Thaha confirm/allow -> DPS approval and execution -> Wright verdict -> Goshi/Farley dispute packet, each verified by the verifier its text yields, twelve joins across the four"
mkdir -p one-chain/out
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 one-chain/build.py > one-chain/out/build-ci.log || { echo "one-chain: not all verified"; tail -30 one-chain/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 one-chain/negatives.py > one-chain/out/negatives-ci.log || { echo "one-chain: a failing case was not caught where expected"; cat one-chain/out/negatives-ci.log; exit 1; }
echo "# positive chain: CHECKS_PERFORMED, A1/A2 verified on every dimension, verdict released, packet VERIFIED, 12 joins true (+ case 17's 7); stated negative (150 executed for 120 approved): J1 false, action_binding failed, verdict not_as_approved released, packet BREACH:amount_minor VERIFIED, 12 joins true; 22 failing cases caught where expected (one approval used twice: the Standard's request_limit first; money moved with nothing recorded: only the packet, NOTHING_RECORDED); the Goshi/Farley link follows the constructions its author gave on 8 November 2026 (four cases, one per construction); since 11 November 2026 N13's directory holds the altered A2 the checker held, and N22 is an A2 whose issuer seal is broken (the verdict held on the checker's format rules), both after Darren Wright's run of 10 November"

echo "== Case 18, independent time bound (one-chain/anchoring): five OpenTimestamps proofs of 2026-11-06T17:34:21Z over the chain's exact bytes, re-checked offline against the pinned header set by the Standard's anchoring 0.2.0 reference check and by umarise/verify_anchor.py (route 2); no calendar, explorer or node is contacted"
(cd one-chain/anchoring/subjects && sha256sum -c --quiet SHA256SUMS) || { echo "one-chain anchoring: the anchored subjects changed"; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 one-chain/anchoring/verify.py > one-chain/out/anchoring-verify-ci.log || { echo "one-chain anchoring: a proof did not verify on both routes"; cat one-chain/out/anchoring-verify-ci.log; exit 1; }
git diff --exit-code --quiet -- one-chain/anchoring/result.json || { echo "one-chain anchoring: result.json differs from the committed one"; git --no-pager diff -- one-chain/anchoring/result.json; exit 1; }
echo "# 5/5 proofs verified on both routes (the signature value's subject_bytes not_checked by the reference check by design, the four document proofs outside the profile's subject kinds, checked by its OpenTimestamps path): the bytes existed before block 974838 per the held header, miner_stated_time 2026-11-06T18:44:06Z, never a time they existed at; four calendars, blocks 974838, 974839, 974842, 974847; 15 headers validated from the checkpoint; result.json byte-identical to the committed one"

echo "== Case 18b: the same chain with a real approver (one-chain-real): Laurent Lemonnier's passkey assertion (WebAuthn-ES256, sign.pria.fr) over the exact person_approval bytes, pinned in signed/, verified by the Standard's check"
(cd one-chain-real/signed && sha256sum -c --quiet SHA256SUMS) || { echo "one-chain-real: the pinned signed inputs changed"; exit 1; }
mkdir -p one-chain-real/out
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 one-chain-real/build.py > one-chain-real/out/build-ci.log || { echo "one-chain-real: not all verified"; tail -30 one-chain-real/out/build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 one-chain-real/negatives.py > one-chain-real/out/negatives-ci.log || { echo "one-chain-real: a failing case was not caught where expected"; cat one-chain-real/out/negatives-ci.log; exit 1; }
(cd one-chain-real/anchoring/subjects && sha256sum -c --quiet SHA256SUMS) || { echo "one-chain-real: the anchoring subjects of 6 November changed (build.py writes today's to out/anchoring-subjects/; the packet is known to differ since 8 November, anchoring/readings.json)"; exit 1; }
echo "# one real signature: verified (signature, UP, UV, origin, rpId, key state, identity under the pinned trust policy); the chain as in case 18: CHECKS_PERFORMED, A1/A2 verified, verdict released, packet VERIFIED, 12 joins true; stated negative as expected; 8 failing cases caught where expected, five of them by the Standard's signatures check alone; the anchoring subjects of 6 November are untouched (stamp.sh is never run here; since 8 November the packet built differs from the anchored one, recorded in anchoring/readings.json)"

echo "== Case 18b, independent time bound (one-chain-real/anchoring): the five proofs of 2026-11-06T19:52:59Z, the real passkey signature value among the subjects, re-checked offline against the pinned header set by both verifiers"
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 one-chain-real/anchoring/verify.py > one-chain-real/out/anchoring-verify-ci.log || { echo "one-chain-real anchoring: a proof did not verify on both routes"; cat one-chain-real/out/anchoring-verify-ci.log; exit 1; }
git diff --exit-code --quiet -- one-chain-real/anchoring/result.json || { echo "one-chain-real anchoring: result.json differs from the committed one"; git --no-pager diff -- one-chain-real/anchoring/result.json; exit 1; }
echo "# 5/5 proofs verified on both routes: the signature value and the four documents existed before block 974850 per the held header, miner_stated_time 2026-11-06T20:01:21Z (signed_at 19:05:00Z, received 19:06:54Z), never a time they existed at; three blocks reached, 974850, 974877, 974890; 46 headers validated from the checkpoint; the key state check still reads the stated time"

echo "== draft-gilda-audit-agent-audit-record-03, corpus vectors-agent-audit-record from agent-evidence-vectors ${GILDA_VERSION} (anchors validated offline against the manifest's tree heads and test-chain headers; dating complete)"
CORPUS=$(python3 -c "import agent_evidence_vectors,os;print(os.path.join(os.path.dirname(agent_evidence_vectors.__file__),'corpora','vectors-agent-audit-record'))")
python3 gilda/gilda_verify_independent.py --corpus "$CORPUS" --report gilda/judge-ci.json | tail -1

echo "== approval-binding/v1 (the same package's vectors-approval-binding contract), verifier written from the corpus README's checks (eleven at 0.31.0, sixteen at 0.35.0: 23/23 here, 36/36 and 37/37 on 0.35.0 and PR #472 in gilda/run-approval-binding-20261107.txt)"
AB_CORPUS=$(python3 -c "import agent_evidence_vectors,os;print(os.path.join(os.path.dirname(agent_evidence_vectors.__file__),'corpora','vectors-approval-binding'))")
python3 gilda/approval_binding_verify_independent.py --corpus "$AB_CORPUS" --report gilda/judge-approval-binding-ci.json | tail -1
# Local candidate addition (2026-10-30): source-to-record aggregation controls.
GILDA_CORPUS="$CORPUS" python3 -m unittest discover -s gilda -p 'test_gilda_aggregation.py' -v

echo "== draft-izmaylov-agent-permission-receipts-02 (Provared, 31 October 2026): verifier written from the text alone (izmaylov/verify_from_text.py), vectors of provared/provared at tag v0.6.0 and at main 24cac84; none of his code is read or run"
python3 -m pip install --quiet "cryptography>=42" "pqcrypto>=1.0"
izmaylov_vectors() {   # $1 = v0.6.0 | main: fetch the pinned commit as a tarball, keep test-vectors/ only, check the digests
  local label=$1 here=$PWD commit dir
  commit=$(cut -d' ' -f1 izmaylov/vectors/PINNED_COMMIT.$label)
  dir=izmaylov/vectors/cache/$label
  if [ ! -f "$dir/.verified" ]; then
    rm -rf "$dir"; mkdir -p "$dir"
    curl -fsSL "https://codeload.github.com/provared/provared/tar.gz/$commit" | tar -xz -C "$dir" --strip-components=2 --wildcards '*/test-vectors/*'
    (cd "$dir" && sha256sum -c --quiet "$here/izmaylov/vectors/SHA256SUMS.$label") || { echo "izmaylov: the vectors differ from the pinned digests ($label)"; exit 1; }
    touch "$dir/.verified"
  fi
}
(cd izmaylov/draft && sha256sum -c --quiet SHA256SUMS) || { echo "izmaylov: the pinned draft text changed"; exit 1; }
for L in v0.6.0 main; do
  izmaylov_vectors "$L"
  echo "# vectors at $L ($(cut -c1-12 izmaylov/vectors/PINNED_COMMIT.$L))"
  python3 izmaylov/run_vectors.py --vectors "izmaylov/vectors/cache/$L" --report "izmaylov/judge-ci-$L.json" --check "izmaylov/judge-$L.json" | tail -4
done
python3 izmaylov/mutation_tests.py --vectors izmaylov/vectors/cache/v0.6.0 | tail -1

echo "== case 19: the approved plan of case 13b as RFC 9396 authorization_details, referenced by digest (rar/)"
(cd rar && python3 build.py && python3 negatives.py | tail -1 && python3 token_cases.py | tail -1 && python3 evidence_cases.py | tail -1)

echo "== draft-mih-sokolov-cose-deterministic-encodings-00 (cose-deterministic/): a checker from the text, on our own vectors (the authors' were not published on 11 November 2026)"
(cd cose-deterministic && python3 run_tests.py | tail -1 && git diff --exit-code --quiet -- results.json results.md vectors) || { echo "cose-deterministic: a check failed or the committed results differ"; exit 1; }

echo "== A decision record and an OMP record, composed (omp-authority/): draft-veridom-omp-core-00 read from the text, our own vectors (the authors had published none on 13 November 2026)"
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 omp-authority/build.py > /tmp/omp-authority-build-ci.log || { echo "omp-authority: not as expected"; tail -30 /tmp/omp-authority-build-ci.log; exit 1; }
DPS_STANDARD="$PWD/aqta/approval-record/dps-standard" python3 omp-authority/negatives.py > /tmp/omp-authority-negatives-ci.log || { echo "omp-authority: a failing case was not caught where expected"; tail -40 /tmp/omp-authority-negatives-ci.log; exit 1; }
tail -1 /tmp/omp-authority-negatives-ci.log
git diff --exit-code --quiet -- omp-authority/out || { echo "omp-authority: the results differ from the committed ones"; git --no-pager diff --stat -- omp-authority/out; exit 1; }
