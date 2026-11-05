# The SmartOffice execution envelope, December 2025 – January 2026: a selection of the sources

Published on 5 November 2026 from the private SmartOffice repository of iSoluce, with the agreement of the company's
court-appointed administrator (iSoluce has been in *redressement judiciaire* since 25 October 2026). These are the
files behind the "deployment" paragraph of Section 11 of draft-lemonnier-scitt-decision-provenance: the envelope that
carried a plan, its authorisation and the results of its steps, before the Decision Provenance Standard existed in the
deployment and before the interoperability cases of this repository.

This folder states dates and bytes. It makes no claim about any other draft or standard.

## What the files are

| Date (UTC, author/committer) | Commit | Files here |
|---|---|---|
| 2025-12-22 00:53:27 | `c55d1bcd271c324fe111d9e9b8fd3d18113d62b9` | `contracts/` (envelope, step, tool-call, result, memory JSON Schemas), `formats/` (examples), `workflows/executor/executor.workflow.json` |
| 2025-12-26 18:31:51 and 21:37:07 | `878060e6773e54458b7e40fde200ea0e50e30cc4`, `c91521e79b48696886b3b093476d7d6ffdfbd2e8` | `contracts/envelope.schema.json`, `formats/envelope.json` (header/payload form, registry carried in the payload) |
| 2026-01-08 21:31:40 to 23:05:30 | `41081d137268cdfaa881cdd51523fa318f6244da`, `a4b60859550ab65f09d2b2f67f50f3a1780ff01b`, `3ebad4330b2556e1db8c20e83150a4d70802939d` | `envelope-preservation-pattern.md`, `envelope-preservation-test.json`, four n8n workflow exports (agent, executor, human-approval, tool-gateway) |
| 2026-01-11 18:33:35 | `60d2c0e2b6aed4603fa077383bcfb425d1315582` | `envelope.md` (fields and flow), four n8n exports |
| 2026-01-13 | `5351a88` (tree) | `fixtures/` (plans valid and invalid, trigger payloads, preservation test), `specs-envelope.schema.json` |

The design is hierarchical: a parent envelope holds `payload.intent`, `payload.input`, `payload.context`, the registry,
`plan.steps[]`, `authorization` (mode, use-case reference, human validation data) and `execution.results[]`; a step and
its result are interpreted inside that scope. The authorisation guard reads `state.authorization.mode` at the parent;
nothing in the code requires a child to repeat it. The schema of 22 December already defines a `ToolCall` unit (call id,
tool, action, parameters, timeout/retry) and a distinct `Result` unit.

## What this does and does not show

- The commits exist in the private repository; their existence was checked through GitHub on 31 October 2026. The
  repository is private: these files were **not public** at those dates, and this folder does not say they were.
- Author and committer dates are Git metadata, not an independent timestamp. No independent anchor of these bytes
  earlier than this publication is claimed here.
- Example dates inside payloads (such as `2025-01-01T12:00:00Z` in `formats/envelope.json`) are fixture values, not
  evidence of existence at that date.
- The n8n exports are workflow definitions. Pinned data, which n8n lets a user set by hand, has been removed; it would
  not have proved a real execution anyway.
- A nested JSON object inherits operational context from its parent, not a cryptographic signature or authority. The
  envelope of this period records an approval; it does not sign one.

## What was removed, and how to check

29 files are verbatim copies of the blobs named in `MANIFEST.json` (commit, Git blob id, SHA-256 of the original,
SHA-256 as published: identical for these). 9 n8n exports are **derived**: the top-level `pinData`, `staticData`,
`shared`, `meta`, `id`, `versionId`, timestamps and `tags` were removed, node `credentials` and `webhookId` members were
removed, and e-mail addresses, Google document ids, Slack channel ids and personal names were replaced by placeholders. For those, `MANIFEST.json` gives the
original blob id and SHA-256 next to the published SHA-256, so that anyone with access to the private repository can
confirm the derivation. `SHA256SUMS` covers the published files.

The working notes these files were selected from, and the analysis of the selection, are kept private.
