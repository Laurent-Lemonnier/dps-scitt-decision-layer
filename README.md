# Decision provenance under SCITT action profiles

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

## What is here

- `examples/release-decision/`: a decision record (record schema of the reference files 5.2.0) for shipping release 2.3.1 of a claims-intake
  service, and the action-binding 0.3.0 attachment of its deploy pipeline (proposal, review, approval under the
  release charter, unsigned in this example, request, re-check, attempt, observed result). `build.py` builds both, validates them against the
  Standard's schemas and runs the action binding reference check; `summary.json` is its output. Nothing in it is
  specific to AI.
- `examples/public-procurement/`: three decision records of one public purchase (the decision to buy a fleet
  maintenance contract, priced against the open procurement data; the award among four bids, one rejected as abnormally
  low; the review at twelve months as a re-decision stating what was planned, what was paid and what is decided next),
  and the action-binding attachment of the award's notification. Each record carries its price context and how it will
  be measured, so that waste shows. `summary.json` holds the validation and the measure.
- `demo/`: an Agent Action Capsule (format 4) that cites the record and the attachment in `references[]` as Canonical
  Payload Binding typed digest references. `build_demo.py` computes its `capsule_id`, parses and verifies it with the
  capsule reference library (`agent-action-capsule` 0.12.0), and resolves the two references on the decision side.
  `demo-result.json` is its output. The artifact types are named under the Standard's own namespace, `org.decisionprovenancestandard`, with its
  Steward's agreement; the Standard's repository declares the names and their digest rules.
- `draft/`: the draft's source (kramdown-rfc), revision -00 in preparation, written against the repository's main branch
  at the commit it names.

## Running

```
pip install jsonschema agent-action-capsule==0.12.0 cbor2
git clone https://github.com/decision-provenance-standard/standard ../standard   # or set DPS_REPO
python examples/release-decision/build.py
python demo/build_demo.py
```

## Licence

Code and data in this repository: Apache-2.0 (see LICENSE). The draft text, once submitted, is subject to the IETF
Trust's Legal Provisions. The Standard's own texts and schemas keep their licences (CC-BY 4.0 and Apache-2.0).
