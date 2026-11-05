Envelope — SmartOffice
======================

Champ principaux (structure logique)
- `payload`
  - `intent` : texte d’entrée (user/request)
  - `input` : données brutes (facultatif)
  - `context` : métadonnées (ex: request_text, correlation_id, memory…)
  - `registry` : tools/usecases/capabilities (défaut injecté si absent)
- `agent`
  - `mode` : `compile` (certifié) ou `plan` (LLM)
  - `detected_usecase` : id du usecase certifié (ou null)
- `plan`
  - `steps` : liste de steps `{ tool_ref, args, outputs?, inputs? }`
  - `contract_version` : ex: "1.0"
  - `status` : proposed/…
- `authorization`
  - `mode` : `preapproved`, `human_required`, `human_approved`
  - `usecase_ref` : id du usecase (certifié) si applicable
- `execution`
  - `session_id` : identifiant de session
  - `status` : running/completed/failed
  - `cursor` : index de step en cours
  - `results` : [{ step, status, result, error }]
- `output`
  - résumé final éventuel (Executor)

Flux runtime
- Trigger Router : normalise l’événement en enveloppe (`payload`, `agent`, `execution.session_id`), injecte registry par défaut, détecte un usecase certifié → `agent.mode=compile`.
- Agent :
  - Préflight : vérifie `payload/agent`, injecte registry/policies par défaut.
  - Mode `compile` : résout le usecase certifié, compile `plan.steps` (steps_template), autorise `preapproved`.
  - Mode `plan` : construit prompt LLM → steps ; compile/valide → `plan.steps`, autorise `human_required`.
- Executor : vérifie `authorization.mode` (preapproved/human_approved), exécute `plan.steps` via Tool Gateway, met à jour `execution` (cursor/results/status), produit `output`.
- Tool Gateway : exécute `step.tool_ref` (connector) et normalise en `toolResult` (via registry Tools normalize).

Validation conseillée (AJV/Code)
- `payload` et `agent` obligatoires (Trigger/Agent préflight).
- `plan.steps` : array non vide, chaque step avec `tool_ref` string, `args` objet, refs `{{$step[i].outputs.key}}` pointant vers des steps antérieurs.
- `authorization.mode` ∈ {preapproved, human_required, human_approved}.
- `execution.session_id` string non vide ; `execution.results` array.

Contrats / sources
- Contracts : specs/contracts/ (schémas minimaux envelope/plan/execution).
- Registry : specs/registry/tools.json (normalize), usecases.json (steps_template), capabilities.json.
- Runtimes : doc/agent-runtime.md, doc/executor-runtime.md, doc/triggers-runtime.md, doc/tool-gateway.md, doc/.codex/ArchiPlan.md.
