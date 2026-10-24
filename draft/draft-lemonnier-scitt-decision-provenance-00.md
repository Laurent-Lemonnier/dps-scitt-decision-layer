---
title: "Decision Provenance for SCITT Action Profiles: binding agent actions and software releases to the decisions behind them"
abbrev: "SCITT Decision Provenance"
docname: draft-lemonnier-scitt-decision-provenance-00
category: info
ipr: trust200902
area: Security
workgroup: SCITT
keyword: [SCITT, provenance, decision, human approval, action binding, transparency service, software release]
stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  -
    ins: L. Lemonnier
    name: Laurent Lemonnier
    organization: iSoluce
    email: laurent@isoluce.net
    country: France

normative:
  RFC2119:
  RFC8174:
  RFC9052:
  RFC9162:
  RFC9942:
  RFC9943:
  DPS-ANCHORING:
    title: "Anchoring extension 0.2.0 of the Decision Provenance Standard"
    author:
      - name: Laurent Lemonnier
    date: 2026-10
    target: https://github.com/decision-provenance-standard/standard/tree/COMMIT-TBD/extensions/anchoring
  DPS-ACTION-BINDING:
    title: "Action binding extension 0.3.0 of the Decision Provenance Standard"
    author:
      - name: Laurent Lemonnier
    date: 2026-10
    target: https://github.com/decision-provenance-standard/standard/tree/COMMIT-TBD/extensions/action-binding

informative:
  DPS-CORE:
    title: "The Decision Provenance Standard, Core v1.3 (reading edition rev. 11)"
    author:
      - name: Yohay Etsion
    date: 2026
    target: https://decisionprovenancestandard.org
  DPS-SIGNATURES:
    title: "Signatures extension 0.2.0 of the Decision Provenance Standard"
    target: https://github.com/decision-provenance-standard/standard/tree/COMMIT-TBD/extensions/signatures
  DPS-PV:
    title: "Portable verification extension 0.3.0 of the Decision Provenance Standard"
    target: https://github.com/decision-provenance-standard/standard/tree/COMMIT-TBD/extensions/portable-verification
  I-D.mih-scitt-agent-action-capsule:
  I-D.mih-sokolov-scitt-payload-binding:
  I-D.rampalli-scitt-capsule-provenance-binding:
  I-D.emirdag-scitt-ai-agent-execution:
  I-D.noa-scitt-ai-agent-receipt:
  RFC3161:
  RFC9597:

--- abstract

Several SCITT statement profiles record what an AI agent did. None records the decision behind the action: the options considered, the rationale, who approved it and on what authority, and what the approver was shown. This document describes how a decision record and its action-binding attachment, as defined by the extensions of the Decision Provenance Standard, sit under those profiles by typed digest references, how the approver's own signature and the chain from what was shown to what was executed are verified offline, and how the Standard's witness checkpoints are registered in a SCITT Transparency Service. The same model applies to a software release decision, with no feature specific to AI. This document is independent of the Decision Provenance Standard, is not part of it, does not change it, and is not endorsed by its Steward.

--- middle

# Introduction

An action profile for SCITT {{RFC9943}} records an action: its disposition {{I-D.mih-scitt-agent-action-capsule}}, its inputs and outcomes {{I-D.emirdag-scitt-ai-agent-execution}}, or its risk class and verdict {{I-D.noa-scitt-ai-agent-receipt}}. Each of them says, rightly, that a human-approval field is the producer's claim: an enumeration value or an opaque label, not an authenticated act. None of them carries the decision behind the action.

The Decision Provenance Standard {{DPS-CORE}} records decisions: what was decided, under which charter, which options were considered, with what rationale, and the affirmative human act that closed the record. Its action binding extension {{DPS-ACTION-BINDING}} records the stages from a proposed action specification to its execution: what the reviewer was shown, what they approved and signed, what was requested, re-checked and executed, bound to one another by equal digests. Its anchoring extension {{DPS-ANCHORING}} gives those records independent time and independent checkpoints, including, since its SCITT source, a witness-signed checkpoint registered in a Transparency Service with its receipt {{RFC9942}}.

This document does three things. It declares two artifact types so that an action record may cite, by typed digest reference {{I-D.mih-sokolov-scitt-payload-binding}}, the decision record and the action-binding attachment it executes. It describes how a verifier holding both checks the approval and the binding offline. And it describes the registration of the Standard's checkpoints in a Transparency Service, by reference to the anchoring extension at a fixed commit. A worked example is a software release decision, since that is where the SCITT charter lives today.

## Relation to the Decision Provenance Standard

This document is an independent, downstream description. It is not part of the Decision Provenance Standard, does not change it, and is not endorsed by its Steward. The name is used only to identify the Standard and its extensions, which are the source: where this document and the repository differ, the repository governs, and any change a reader asks for in a format described here is made in the repository first, as a pull request.

"Decision Provenance Standard" is a trademark of Etsion Brands Ltd., used here to identify the Standard, with attribution: The Decision Provenance Standard, Yohay Etsion, 2026, CC-BY 4.0, https://decisionprovenancestandard.org.

## Versions and commit

This document is written against the extensions as they stand on the repository's main branch at commit COMMIT-TBD: anchoring 0.2.0, signatures 0.2.0, portable verification 0.3.0 and action binding 0.3.0. Each extension states its version in every document it defines; this document names them so that a reader can check the same tree.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Decision record, action-binding attachment, stage, checkpoint, witness, trust policy and verification report are used as the Standard and its extensions define them. Signed Statement, Transparency Service and Receipt are used as {{RFC9943}} and {{RFC9942}} define them.

# What the decision layer adds

A verifier holding an action record and the decision record and attachment it cites can establish, offline:

- that the approver signed the outcome stage with a key the verifier's own trust policy maps to a person in role person, under an authority reference that points into the deployer's charter;
- that the specification the approver was shown, the one they approved, the one that was requested, re-checked and executed, are one and the same, by equal digests, or exactly where they differ;
- the options considered and the rationale as the record states them, with the time the rationale was recorded relative to the decision;
- and, through the anchoring extension, by when those bytes existed, from an RFC 3161 token {{RFC3161}}, a SCITT receipt, or an OpenTimestamps proof, each with what it does and does not show.

It cannot establish that the decision was right, that the action was, or that the reviewer read what they were shown: the verification reports of the extensions say so in every result, and this document inherits those limits.

# Artifact types for typed digest references

The Canonical Payload Binding {{I-D.mih-sokolov-scitt-payload-binding}} defines a typed digest reference, {type, purpose, digest_alg, digest}, and leaves artifact types to the consuming profile. This document declares two.

## dps.decision_record

- type: TBD-NAMESPACE.decision_record
- digest context: the record's seal_hash as the Standard defines it: SHA-256 over the record's bytes with the value of seal_hash replaced by 64 zeros, in lowercase hexadecimal. A record exported under portable verification {{DPS-PV}} carries the same digest as its entry's seal.
- what a verified reference shows: the cited bytes are the affirmed decision record, under the trust the verifier gives the seal's source; not that the record is true, complete or the latest.

## dps.action_binding_attachment

- type: TBD-NAMESPACE.action_binding_attachment
- digest context: SHA-256 over the attachment's bytes as issued, with every character of issuer_signature.value_b64 replaced by A where the attachment carries a copy of its seal, as the signatures extension defines it {{DPS-SIGNATURES}}; lowercase hexadecimal.
- what a verified reference shows: the cited bytes are the attachment as its issuer sealed them; the attachment's own check then says what the stages show.

## Carrying the references

In a capsule, the references are carried in references[] as the capsule profile allows; in an AgentInteractionRecord, in external_refs; in a receipt that keeps its object closed, as a separately signed claim linked by digest. Nothing in the citing profile's protected header or verification changes. The cited artifacts travel beside the action record, in a portable verification export and a signatures attachment, or are obtained from the issuer.

# Verification

A verifier that holds the action record, the decision record, the attachment and its own trust policy:

1. resolves each typed digest reference as CPB describes, and stops at Failed for a digest that does not match;
2. runs the action binding reference check on the attachment with the record, which reports the stages' consistency, the issuer signature where there is one, the time, and the pairing of the report with its documents;
3. runs the signatures check on the approver's signature over the outcome stage, where one is carried beside;
4. reads the result dimension by dimension; it MUST NOT merge them into one pass or fail, and it MUST NOT report more than those checks find.

The reference checks, their cases and their vectors are in the repository under extensions/*/tests; this document does not restate them.

# Checkpoints in a Transparency Service

A witness's checkpoint over a chain of decision records is a signed statement whose payload is the checkpoint's signed bytes under the Standard's shared rule, with its receipt, as the anchoring extension defines under "A transparency service as a checkpoint source" at commit COMMIT-TBD. This document adds no rule; it names what a Transparency Service operator and a verifier need:

- the statement's protected header: alg -19, kid the witness key's reference, CWT claims {{RFC9597}} iss the key's holder and sub the chain;
- the leaf: the statement's bytes as registered; a Transparent Statement is carried with its receipts taken out;
- what a receipt shows: that the service signed the statement into its log at a tree size; not the log's consistency, which the extension reports as not checked in this version, nor a registration time;
- a registration policy for the service side (TBD, with the Steward's input): which witness keys a service registers for, and under which chain identifiers.

# Worked example: a software release decision

The appendix carries a decision record for shipping release 2.3.1 of a claims-intake service, and the action-binding attachment of its deploy pipeline: the assistant's proposal, the release manager's review and signed approval under the release charter, the orchestrator's request, the permission re-check, the deployer's attempt and the observed result. The record states three options and why the first was chosen. Nothing in it is specific to AI: the same model fits any decision a pipeline executes.

# Security Considerations

The decision layer authenticates the approver's act and binds it to the executed specification; it does not establish the truth of the decision's inputs. A relying party that needs a signed approval requires one in its own configuration and does not accept an unsigned attachment: anyone holding a signed attachment can remove its signature and present it as unsigned, and only a seal beside it shows that. Keys and sources of trust come from the verifier's own trust policy, never from the artifacts. Time from a receipt is the service's statement; time from a block is the miner's; only an RFC 3161 token from an authority the verifier trusts gives a bound. The anchoring extension's security considerations apply.

# IANA Considerations

This document registers no media type in this revision. A later revision may register, in the vendor tree, a media type for the checkpoint payload, with the Steward of the Decision Provenance Standard as change controller; the content type stays optional in the anchoring extension.

--- back

# Acknowledgments
{:numbered="false"}

Yohay Etsion, Founding Steward of the Decision Provenance Standard, for discussion. The authors of the capsule, payload binding, AI agent execution and action receipt drafts, whose care in stating what their records do not prove made the junction clear.

# Appendix: the worked example
{:numbered="false"}

The files are kept with this document's source (exemple-release/ and demo/); the digests below let a reader check them.

- Decision record DR-2026-0412 (Core v5.0 schema, state closed): "Ship claims-intake 2.3.1 to production on 2026-10-23", three options considered, the first chosen; affirmed by the release manager on 2026-10-23T14:20:00Z. seal_hash: `34ba302a668e9200017a1083a92e88773dab1ca620faeaac8cd8bb7747596ba5`.
- Action-binding attachment (0.3.0, unsigned in this example): seven stages, proposal by the release assistant, review and signed approval by the release manager under the release charter, request, re-check, attempt, observed result; one specification, digest `19ade2a46319ac6622333cd6731ac400ed11daa7d6955b5daa5864da91c2b711`, carried in full. Attachment digest: `5086c7674db770c6d01592ba697722a2fb468c16d1d5ab9226a7b5217c4bc1a8`.
- The action binding reference check on the attachment with the record: specification digests, record statements, action binding, stage order, authorisation re-check, observed results and rationale provenance all verified; execution state attempted, result succeeded.
- A capsule (format 4, action_type decide, disposition accept by a human, effect confirmed) citing both by typed digest references in references[] with citation_purpose ran_under and acted_on: capsule_id `8ffac39fe42e5d1b9dcbff838ec5c3aad749a3e8a32e3157791297f5f325b6e7`; the capsule library (0.12.0) parses it strictly and its Class 1 verification passes with two informational findings (an effect type and a domain outside the seeded values); a DPS verifier resolves both references to the documents it holds.

~~~
[
 {
  "type": "org.decisionprovenance.decision_record",
  "digest_alg": "SHA-256",
  "digest": "34ba302a668e9200017a1083a92e88773dab1ca620faeaac8cd8bb7747596ba5",
  "citation_purpose": "ran_under"
 },
 {
  "type": "org.decisionprovenance.action_binding_attachment",
  "digest_alg": "SHA-256",
  "digest": "5086c7674db770c6d01592ba697722a2fb468c16d1d5ab9226a7b5217c4bc1a8",
  "citation_purpose": "acted_on"
 }
]
~~~
