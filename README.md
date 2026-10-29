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
| Standard | all four extensions written against the Standard's main branch; the commit each artefact is pinned to is stated in its directory. Open question to the Steward: [#93](https://github.com/decision-provenance-standard/standard/issues/93), a designating-policy digest and a short validity on a person's approval |
| Interop with the Agent Action Capsule (Steven Mih) | seven cases, both sides passing, including the two COSE forms; the service's transparency receipt read by the Standard's anchoring check; see `interop/aac/` |
| Independent verifiers of neighbouring drafts | written from the drafts' text and run on their published vectors: Seal (Chueayen) 67/67, VERIFY-ANCHOR (Fassbender) 4/4, AER-1 (Zambo) 119/119, agent audit record (Gilda) 141/141; discrepancies found are listed in each README and reported to the authors |
| Seal Section 8.3 | the approval record that draft calls for, as a DPS signed outcome, with the failing cases its author asked for; see `interop/aqta/approval-record/` |
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
- `draft/`: the draft's source (kramdown-rfc), written against the Standard's main branch at the commit it names.

## Running

```
pip install jsonschema agent-action-capsule==0.12.0 cbor2
git clone https://github.com/decision-provenance-standard/standard ../standard   # or set DPS_REPO / DPS_STANDARD
python examples/release-decision/build.py
python demo/build_demo.py
bash interop/run.sh        # the four verifiers and the Seal example, as the CI runs them
```

## Licence

Code and data in this repository: Apache-2.0 (see LICENSE). The draft text, once submitted, is subject to the IETF
Trust's Legal Provisions. The Standard's own texts and schemas keep their licences (CC-BY 4.0 and Apache-2.0).
