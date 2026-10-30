# Decision provenance under SCITT action profiles

[![interop](https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/actions/workflows/interop.yml/badge.svg)](https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/actions/workflows/interop.yml)

Working material for an Internet-Draft, `draft-lemonnier-scitt-decision-provenance`, by Laurent Lemonnier (iSoluce):
how a decision record and its action-binding attachment, as the extensions of the Decision Provenance Standard define
them, sit under the SCITT profiles that record agent actions (the Agent Action Capsule, the AI Agent Execution profile,
the AI-Agent Action Receipt) by typed digest references, and how the same model applies to a software release decision.

**Independence.** This repository and the draft are independent of the Decision Provenance Standard™. They are not part
of it, do not change it, and are not endorsed by its Steward. The Standard and its extensions are the source: where a
text here and the repository https://github.com/decision-provenance-standard/standard differ, the repository governs,
and any change in a format is made there first, as a pull request.

"Decision Provenance Standard" is a trademark of Etsion Brands Ltd., used here to identify the Standard. Attribution:
The Decision Provenance Standard, Yohay Etsion, 2026, CC-BY 4.0, https://decisionprovenancestandard.org.

## Where things stand (29 October 2026)

| Item | State |
|---|---|
| Draft | `-00` posted on the IETF Datatracker on 26 October 2026 and announced on scitt@ietf.org; `-01` due before the 2 November cutoff, with a Related Work section (the SCITT group holds some thirty drafts on agent decision records) and an Implementation Status section (RFC 7942) that names the Standard's reference checks and the interop below |
| Standard | all four extensions written against the Standard's main branch (`007f8c9`); the commit each artefact is pinned to is stated in its directory. [#93](https://github.com/decision-provenance-standard/standard/issues/93) answered by the Steward with no change to the Standard: the designating policy is signed through the specification (`policy_version` = SHA-256 of the issuer's policy), and a short validity is checked at the recheck |
| Interop with the Agent Action Capsule (Steven Mih) | seven cases, both sides passing, including the two COSE forms; the service's transparency receipt read by the Standard's anchoring check; see `interop/aac/` |
| Independent verifiers of neighbouring drafts | written from the drafts' text and run on their published vectors: Seal (Chueayen) 67/67, VERIFY-ANCHOR (Fassbender) 4/4, AER-1 (Zambo) 119/119, agent audit record (Gilda) 141/141; discrepancies found are listed in each README and reported to the authors |
| Seal Section 8.3 | the approval record that draft calls for, as a DPS signed outcome, with the failing cases its author asked for and those proposed on #93, which the Steward agreed fit; see `interop/aqta/approval-record/` |
| AER-1 composed (Zambo) | at the author's request, a decision record and an AER-1 receipt bound both ways (the attempt cites the receipt's id and output_hash; the receipt's recorded input carries the DPS request_id and the approved values), with 10 failing cases; building it found that the AER-1 kit never recomputed the receipt's metadata block, which the author confirmed and reports fixed in the kit's runners, with credit; see `interop/aer1-decision/` |
| One agent pass, three layers | a synthetic pass of 35 actions and 5 refusals carried by the DPS (two standing approvals of exact lists, ten exact approvals of comments, one rejection, 13 signatures), Seal ACTION-v1 (40 records) and the capsule (41), with the joins across them and 10 failing cases; see `interop/agent-pass/` |
| IETF 127 (San Francisco, 14–20 November) | Hackathon 14–15 November (capsule interop, remote); AUDIT BoF Tuesday 17 November; SCITT session Wednesday 18 November |

Everything under `interop/` is replayed by the CI from a clean machine on every push and weekly (`interop/run.sh`).

## What is here

- `examples/release-decision/`: a decision record (record schema of the reference files 5.2.0) for shipping release
  2.3.1 of a claims-intake service, and the action-binding 0.3.0 attachment of its deploy pipeline (proposal, review,
  approval under the release charter, unsigned in this example, request, re-check, attempt, observed result).
  `build.py` builds both, validates them against the Standard's schemas and runs the action binding reference check;
  `summary.json` is its output. Nothing in it is specific to AI.
- `examples/public-procurement/`: three decision records of one public purchase (the decision to buy a fleet
  maintenance contract, priced against the open procurement data; the award among four bids, one rejected as abnormally
  low; the review at twelve months as a re-decision stating what was planned, what was paid and what is decided next),
  and the action-binding attachment of the award's notification. Each record carries its price context and how it will
  be measured, so that waste shows. `summary.json` holds the validation and the measure.
- `demo/`: an Agent Action Capsule (format 4) that cites the record and the attachment in `references[]` as Canonical
  Payload Binding typed digest references. `build_demo.py` computes its `capsule_id`, parses and verifies it with the
  capsule reference library (`agent-action-capsule` 0.12.0), and resolves the two references on the decision side.
  `demo-result.json` is its output. The artifact types are named under the Standard's own namespace,
  `org.decisionprovenancestandard`, with its Steward's agreement; the Standard's repository declares the names and their
  digest rules (#73, then #87 for the CPB digest contexts). The effect's `response_digest` is the JSON digest (JCS,
  then SHA-256) of the observed deploy response, as the capsule profile requires for a confirmed effect.
- `interop/aac/`: the interop cases with the capsule library, one folder per case with `expected.json` and
  `result.json`: 01–05 typed digest references (valid; altered digest; unsigned attachment; an attachment that fails
  its own check, which resolves and then fails; a re-encoded record), 06 the capsule registered at the library's
  Transparency Service with its COSE Receipt, 07 the two COSE forms (a Producer Envelope the library verifies; a
  CPB-bound Signed Statement with the references in the protected `cpb-refs` header, with negatives), and
  `anchoring_case06.py`, the receipt of case 06 read by the Standard's anchoring extension.
- `interop/aqta/`, `interop/umarise/`, `interop/aer1/`, `interop/gilda/`: verifiers written from the text of four
  neighbouring drafts, their replays and what each left out; `interop/README.md` has the table.
  `interop/aqta/approval-record/`: the Seal §8.3 example and its failing cases.
- `interop/aer1-decision/`: a decision record and an AER-1 receipt composed, its failing cases and the metadata probes.
- `interop/agent-pass/`: one agent pass carried three ways (WHO: DPS standing and exact approvals; CAN: Seal
  ACTION-v1; WHAT: Agent Action Capsule), the joins across them, and its failing cases.
- `draft/`: the draft's source (kramdown-rfc), written against the Standard's main branch at the commit it names.

## Running

```
pip install jsonschema agent-action-capsule==0.12.0 cbor2
git clone https://github.com/decision-provenance-standard/standard ../standard   # or set DPS_REPO / DPS_STANDARD
python examples/release-decision/build.py
python demo/build_demo.py
bash interop/run.sh        # the four verifiers, the Seal example, the agent pass and the AER-1 composition, as the CI runs them
```

## Licence

Code and data in this repository: Apache-2.0 (see LICENSE). The draft text, once submitted, is subject to the IETF
Trust's Legal Provisions. The Standard's own texts and schemas keep their licences (CC-BY 4.0 and Apache-2.0).
