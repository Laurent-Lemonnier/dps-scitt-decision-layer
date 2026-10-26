---
title: "Decision Provenance for SCITT: binding software releases and agent actions to the decisions behind them"
abbrev: "SCITT Decision Provenance"
docname: draft-lemonnier-scitt-decision-provenance-00
category: info
ipr: trust200902
area: Security
workgroup: SCITT
keyword: [SCITT, provenance, decision, human approval, software release, action binding, transparency service]
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
    target: https://github.com/decision-provenance-standard/standard/tree/5b0534d/extensions/anchoring
  DPS-ACTION-BINDING:
    title: "Action binding extension 0.3.0 of the Decision Provenance Standard"
    author:
      - name: Laurent Lemonnier
    date: 2026-10
    target: https://github.com/decision-provenance-standard/standard/tree/5b0534d/extensions/action-binding

informative:
  DPS-CORE:
    title: "The Decision Provenance Standard, Core v1.3 (reading edition rev. 11)"
    author:
      - name: Yohay Etsion
    date: 2026
    target: https://decisionprovenancestandard.org
  DPS-SIGNATURES:
    title: "Signatures extension 0.2.0 of the Decision Provenance Standard"
    target: https://github.com/decision-provenance-standard/standard/tree/5b0534d/extensions/signatures
  DPS-PV:
    title: "Portable verification extension 0.3.0 of the Decision Provenance Standard"
    target: https://github.com/decision-provenance-standard/standard/tree/5b0534d/extensions/portable-verification
  DPS-NAMES:
    title: "Extensions of the Decision Provenance Standard, Names for typed references"
    target: https://github.com/decision-provenance-standard/standard/blob/5b0534d/extensions/README.md#names-for-typed-references
  I-D.ietf-scitt-software-use-cases:
  I-D.mih-scitt-agent-action-capsule:
  I-D.mih-sokolov-scitt-payload-binding:
  I-D.rampalli-scitt-capsule-provenance-binding:
  I-D.emirdag-scitt-ai-agent-execution:
  I-D.noa-scitt-ai-agent-receipt:
  RFC3161:
  RFC9597:
  SLSA:
    title: "SLSA: Supply-chain Levels for Software Artifacts, provenance predicate"
    target: https://slsa.dev/spec/
  IN-TOTO:
    title: "in-toto Attestation Framework"
    target: https://github.com/in-toto/attestation
  SPDX:
    title: "SPDX Specification"
    target: https://spdx.dev/specifications/

--- abstract

A software supply chain records what was built, from what, and by whom: build attestations, bills of materials, signed statements registered in a Transparency Service. It does not record the decision to ship: who approved the release, on what authority, what they were shown, which options were weighed and why. The statement profiles that record AI agent actions have the same gap, and say so: their human-approval fields are the producer's claim. This document describes how a decision record and its action-binding attachment, as the extension proposals of the Decision Provenance Standard define them, sit under both kinds of record by typed digest references; how a verifier checks offline the approval stage, the approver's signature where one is carried, and the chain of digests from what the attachment says was shown to what was executed; and how the witness checkpoints of the anchoring extension are registered in a SCITT Transparency Service. A software release decision is the first worked example and an agent action capsule the second; the model has no feature specific to either. This document is independent of the Decision Provenance Standard, is not part of it, does not change it, and is not endorsed by its Steward.

--- middle

# Introduction

The SCITT use cases {{I-D.ietf-scitt-software-use-cases}} and the formats a software supply chain already carries, build provenance {{SLSA}}, attestations {{IN-TOTO}} and bills of materials {{SPDX}}, answer the question "what is this artifact, and how was it built". Registered as Signed Statements in a Transparency Service {{RFC9943}}, with Receipts {{RFC9942}}, they become evidence anyone can check later. None of them answers "who decided to ship it, on what, and under which authority": the release decision is a ticket, a chat message or a button, and the record of it, where one exists, is neither signed by the decider nor bound to the artifact that shipped.

The statement profiles written for AI agent actions have the same gap, and are careful to say so. A capsule records an action's disposition {{I-D.mih-scitt-agent-action-capsule}}; an AgentInteractionRecord its inputs and outcomes {{I-D.emirdag-scitt-ai-agent-execution}}; a receipt its risk class and verdict {{I-D.noa-scitt-ai-agent-receipt}}. Each says that its human-approval field is the producer's claim: an enumeration value or an opaque label, not an authenticated act, and that the reasoning behind the action stays private or reduced to a hash.

The Decision Provenance Standard {{DPS-CORE}} records the decision: what was decided, under which charter, which options were considered and with what rationale, and the affirmative human act that closed the record. Its action binding extension {{DPS-ACTION-BINDING}}, a proposal in the Standard's repository, records the stages from a proposed action specification to its execution: what the attachment states the reviewer was shown, what was approved, signed where a signature is carried, what was requested, re-checked and executed, bound to one another by equal digests. Its anchoring extension {{DPS-ANCHORING}}, also a proposal, gives those records evidence that their bytes existed by a given point, and witness checkpoints, including, since its SCITT source, a witness-signed checkpoint registered in a Transparency Service with its Receipt. A deploy pipeline and an AI agent are two executors of decisions; the Standard does not distinguish them.

This document does three things. It declares two artifact types so that a build attestation, a release statement or an agent action record may cite, by typed digest reference {{I-D.mih-sokolov-scitt-payload-binding}}, the decision record and the action-binding attachment it executes. It describes how a verifier holding both checks the approval and the binding offline. And it describes the registration of the anchoring extension's checkpoints in a Transparency Service, by reference to the anchoring extension at a fixed commit. Two worked examples: a software release decision, and an agent action capsule citing a decision.

## Relation to the Decision Provenance Standard

This document is an independent, downstream description. It is not part of the Decision Provenance Standard, does not change it, and is not endorsed by its Steward. The name is used only to identify the Standard and its extensions, which are the source: where this document and the repository differ, the repository governs, and any change a reader asks for in a format described here is made in the repository first, as a pull request. The extensions are proposals in the repository; they are not part of the Standard itself.

"Decision Provenance Standard" is a trademark of Etsion Brands Ltd., used here to identify the Standard, with attribution: The Decision Provenance Standard, Yohay Etsion, 2026, CC-BY 4.0, https://decisionprovenancestandard.org.

## Versions and commit

This document is written against the extensions as they stand on the repository's main branch at commit 5b0534d: anchoring 0.2.0, signatures 0.2.0, portable verification 0.3.0 and action binding 0.3.0, each a proposal written against Core v1.3 rev. 11 and the reference files 5.2.0. The names of {{artifact-types}} are those the extensions index declares at the same commit {{DPS-NAMES}}. Each extension states its version in every document it defines; this document names them so that a reader can check the same tree.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Decision record, action-binding attachment, stage, checkpoint, witness, trust policy and verification report are used as the Standard and its extensions define them. Signed Statement, Transparency Service and Receipt are used as {{RFC9943}} and {{RFC9942}} define them. Build attestation, provenance predicate and bill of materials are used as {{IN-TOTO}}, {{SLSA}} and {{SPDX}} define them.

# What the decision layer adds

A verifier holding an action record (a release statement, a build attestation, a capsule) and the decision record and attachment it cites can establish, offline:

- where the approver's signature is carried, that the approver signed the outcome stage with a key the verifier's own trust policy maps to a person in role person; the authority reference that points into the deployer's charter stays the issuer's statement unless the verifier checks it against an independent source, such as the permission system;
- that the specification the attachment says was shown to the approver, the one approved, the one that was requested, re-checked and executed, are one and the same, by equal digests, or exactly where they differ; for a release, that specification names the artifact digest, the bill of materials digest, the migrations and the rollback;
- the options considered and the rationale as the record states them, with the time the rationale was recorded relative to the decision;
- and, through the anchoring extension, evidence about when those bytes existed, each source with what it does and does not show: an RFC 3161 token {{RFC3161}} gives a time from an authority the verifier trusts; a SCITT Receipt states no time, only that the service registered the statement into its log; an OpenTimestamps proof shows only that the bytes existed before a block was mined.

It cannot establish that the decision was right, that the action was, or what the reviewer actually saw or read: the check shows what the attachment says was shown; the verification reports of the extensions say so in every result, and this document inherits those limits.

# Where it attaches in the software supply chain

Nothing here replaces a build attestation, a provenance predicate or a bill of materials; they say what was built, and they say it well. The decision layer sits beside them and is linked to them in both directions by digests:

- The action specification the approver sees, carried in full in the attachment, names the artifact by its digest, the bill of materials by its digest, and the build by its identifier. A verifier that holds the SLSA provenance or the SBOM recomputes those digests and reads whether the release that was approved is the artifact that was built.
- A release statement registered in a Transparency Service, or the build attestation itself where its format allows additional references, cites the decision record and the attachment by the typed digest references of {{artifact-types}}. The SCITT Receipt then covers the decision together with the artifact.
- A Transparency Service that registers the anchoring extension's witness checkpoints ({{checkpoints}}) gives each checkpoint over one issuer's chain of release decisions a Receipt from the same service the artifacts use. A Receipt shows the statement's inclusion; the anchoring extension does not yet check that the log only grew, so this is not evidence of an append-only history of decisions.

The stages an action-binding attachment records map onto a release pipeline without change: the proposal is the release candidate as the assistant or the pipeline drafted it; the review is the release manager's reading of it; the outcome is the approval under the release charter, signed by the release manager where a signature is carried; the request is the deploy job; the re-check is the permission or policy gate just before deployment; the attempt and the result are the deployment and what the target reported. A change of the artifact digest between the approval and the attempt fails the binding, by construction.

# Artifact types for typed digest references {#artifact-types}

The Canonical Payload Binding {{I-D.mih-sokolov-scitt-payload-binding}} defines a typed digest reference, {type, purpose, digest_alg, digest}, and leaves artifact types to the consuming profile; the Agent Action Capsule profile {{I-D.mih-scitt-agent-action-capsule}} (section 9.1) asks that a declared type name carry a URI or reverse-DNS prefix. This document uses two, both declared in the Standard's repository under its own namespace, `org.decisionprovenancestandard` {{DPS-NAMES}}. The repository declares each name, what it identifies and which digest it uses; this document does not restate the digest rules and only says how the references are carried. A name never changes meaning; a different digest rule would get a new name.

## decision_record

- type: org.decisionprovenancestandard.decision_record
- digest: as {{DPS-NAMES}} declares it for this name, by reference to portable verification {{DPS-PV}}; the same value as the entry's seal_hash.

## action_binding_attachment

- type: org.decisionprovenancestandard.action_binding_attachment
- digest: as {{DPS-NAMES}} declares it for this name: the plain SHA-256 of the attachment's bytes, computed as the action binding report computes its attachment_digest; not the sealed digest of the signatures extension {{DPS-SIGNATURES}}.

## What a verified reference shows

A reference that verifies shows only that the cited bytes have the digest it carries. It does not show that they are a decision record or an attachment, which one they are, or anything they state: that is for the document's own check, which reports it.

## Carrying the references

In a capsule, the references are carried in references[] as the capsule profile allows, in the style of {{I-D.rampalli-scitt-capsule-provenance-binding}}; in an AgentInteractionRecord, in external_refs; in a receipt that keeps its object closed, as a separately signed claim linked by digest; in a release statement, in the cpb-refs protected header or in the statement's own payload. Nothing in the citing profile's protected header or verification changes. The cited artifacts travel beside the citing record, in a portable verification export and a signatures attachment, or are obtained from the issuer.

# Verification

A verifier that holds the citing record, the decision record, the attachment and its own trust policy:

1. resolves each typed digest reference as CPB describes, and stops at Failed for a digest that does not match;
2. runs the action binding reference check on the attachment with the record, which reports the stages' consistency, the issuer signature where there is one, the time, and the pairing of the report with its documents;
3. runs the signatures check on the approver's signature over the outcome stage, where one is carried beside;
4. where it holds the artifact, the build attestation or the bill of materials, recomputes the digests the approved specification names and reports each agreement on its own;
5. reads the result dimension by dimension; it MUST NOT merge them into one pass or fail, and it MUST NOT report more than those checks find.

The reference checks, their cases and their vectors are in the repository under extensions/*/tests; this document does not restate them.

# Checkpoints in a Transparency Service {#checkpoints}

A witness's checkpoint over a chain of decision records is a signed statement whose payload is the checkpoint's signed bytes under the anchoring extension's shared rule, with its Receipt, as the anchoring extension defines under "A transparency service as a checkpoint source" at commit 5b0534d. This document adds no rule; it names what a Transparency Service operator and a verifier need:

- the statement's protected header: alg -19, kid the witness key's reference, CWT claims {{RFC9597}} iss the key's holder and sub the chain;
- the leaf: the statement's bytes as registered; a Transparent Statement is carried with its receipts taken out;
- what a Receipt shows: that the service signed the statement into its log at a tree size; not the log's consistency, which the extension reports as not checked in this version, nor a registration time;
- the registration policy is the operator's {{RFC9943}}. A verifier never relies on it: it accepts only statements from the witness keys and chains its own trust policy lists for that service. A service may mirror that list in its policy.

# Worked examples

## A software release decision

The appendix carries a decision record for shipping release 2.3.1 of a claims-intake service, and the action-binding attachment of its deploy pipeline: the release assistant's proposal, the release manager's review and approval under the release charter, the orchestrator's request, the permission re-check, the deployer's attempt and the observed result. The approved specification names the build, the artifact digest, the bill of materials digest, the migration and the rollback. The record states three options and why the first was chosen. The action binding reference check verifies the stage dimensions; the example carries no signature, so the issuer signature and the time are not checked.

## An agent action capsule citing a decision

The same record and attachment, cited from an Agent Action Capsule by two typed digest references in references[]. The capsule reference library parses the capsule strictly and verifies it; a verifier of the Standard resolves both references to the documents it holds. Nothing in the capsule's protected header or verification changed.

# Security Considerations

Where the approver's signature is carried, the decision layer authenticates the approver's act and binds it to the executed specification; an authority reference stays the issuer's statement unless checked against an independent source; it does not establish the truth of the decision's inputs, nor that the artifact a specification names is safe: that stays with the build attestations and the reviews they record. A relying party that needs a signed approval requires one in its own configuration and does not accept an unsigned attachment: anyone holding a signed attachment can remove its signature and present it as unsigned, and only a seal beside it shows that. Keys and sources of trust come from the verifier's own trust policy, never from the artifacts. A Receipt states no time; an OpenTimestamps proof shows only that bytes existed before a block was mined; only an RFC 3161 token from an authority the verifier trusts gives a time bound. The anchoring extension's security considerations apply.

# IANA Considerations

This document registers no media type in this revision. A later revision may register, in the vendor tree, a media type for the checkpoint payload, with the Steward of the Decision Provenance Standard as change controller; the content type stays optional in the anchoring extension.

--- back

# Acknowledgments
{:numbered="false"}

Yohay Etsion, Founding Steward of the Decision Provenance Standard, for discussion. The authors of the capsule, payload binding, AI agent execution and action receipt drafts, whose care in stating what their records do not prove made the junction clear.

# Appendix: the worked examples
{:numbered="false"}

The files are kept with this document's source (https://github.com/laurent-star/dps-scitt-decision-layer, examples/release-decision/ and demo/); the digests below let a reader check them.

- Decision record DR-2026-0412 (record schema of the reference files 5.2.0, state closed): "Ship claims-intake 2.3.1 to production on 2026-10-23", three options considered, the first chosen; affirmed by the release manager on 2026-10-23T14:20:00Z. seal_hash: `34ba302a668e9200017a1083a92e88773dab1ca620faeaac8cd8bb7747596ba5`.
- Action-binding attachment (0.3.0, unsigned in this example): seven stages, proposal by the release assistant, review and approval by the release manager under the release charter, without signature in this example, request, re-check, attempt, observed result; one specification, digest `19ade2a46319ac6622333cd6731ac400ed11daa7d6955b5daa5864da91c2b711`, carried in full, naming build 2.3.1+git.5d1c9f0, the artifact digest, the SBOM digest, migration 0042 and the rollback. Attachment digest: `5086c7674db770c6d01592ba697722a2fb468c16d1d5ab9226a7b5217c4bc1a8`.
- The action binding reference check on the attachment with the record: specification digests, record statements, action binding, stage order, authorisation re-check, observed results and rationale provenance verified; execution state attempted, result succeeded; issuer signature and time not checked, as the attachment is unsigned.
- A capsule (format 4, action_type decide, disposition accept by a human, effect confirmed) citing both by typed digest references in references[] with citation_purpose ran_under and acted_on: capsule_id `8ffac39fe42e5d1b9dcbff838ec5c3aad749a3e8a32e3157791297f5f325b6e7`; the capsule library (0.12.0) parses it strictly and its Class 1 verification passes with two informational findings (an effect type and a domain outside the seeded values); a verifier of the Standard resolves both references to the documents it holds.

~~~
[
 {
  "type": "org.decisionprovenancestandard.decision_record",
  "digest_alg": "SHA-256",
  "digest": "34ba302a668e9200017a1083a92e88773dab1ca620faeaac8cd8bb7747596ba5",
  "citation_purpose": "ran_under"
 },
 {
  "type": "org.decisionprovenancestandard.action_binding_attachment",
  "digest_alg": "SHA-256",
  "digest": "5086c7674db770c6d01592ba697722a2fb468c16d1d5ab9226a7b5217c4bc1a8",
  "citation_purpose": "acted_on"
 }
]
~~~
