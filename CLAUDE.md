# Probative AI

Probative AI is a Tier-1 SOC alert triage system: a deterministic pipeline with ONE LLM judgment call,
a code-owned verifier, and a bounded read-only investigator for hard cases.
Portfolio project; success is measured, not demoed.

Full design: `docs/design.md`. Read the section relevant to the task before planning.
Phase prompts and gates: `docs/build-prompts.md`.

## The system in one view

```
logs -> detect (Sigma/Hayabusa) -> parse -> noise filter -> context -> enrich
     -> evidence score (deterministic baseline)
     -> triage call (LLM, structured output only)
     -> verifier + router (code)
          -> analyst queue | suggested close | auto-close (promoted rules) | investigator
     -> record
```

The model PROPOSES. Code DECIDES and EXECUTES. Never the other way round.

## Hard rules (never)

- Never edit anything under `eval/labels/`, `.claude/`, or `.importlinter`. Hooks block this; do not try to work around them.
- Never weaken, skip, or delete a test or assertion to make something pass. If a test seems wrong, stop and explain why.
- Never put a policy rule (thresholds, overrides, allowlists) in a prompt. Policy lives in `verify/` and `pipeline/`.
- Never give the model write access or side effects. The triage call has no tools. Investigator tools are read-only.
- Never swallow a verifier failure (no bare `except`, no silent fallback to "benign"). Failure means escalate.
- Never send data to a cloud model unless `allow_cloud=true` AND every alert is tagged `dataset=public`.
- Never add a dependency, service, vector store, or framework that the design does not name. Ask first.

## Module boundaries (enforced by `lint-imports` after every edit)

- `triage/domain` imports nothing from the project.
- `triage/pipeline`, `judge`, `verify`, `investigate` never import `store`, `services`, or `api`.
- Only `triage/services` and `triage/api` import `triage/store`.
- `triage/verify` never imports `triage/judge`.

Pure logic in the middle, I/O only at the edges. If a change needs to break a
boundary, STOP and ask. That is a design decision, not a refactor.

## Output contract (triage call and investigator)

```
Verdict:
  alert_id: str
  verdict: "benign" | "suspicious" | "malicious"
  confidence: float in [0, 1]
  cited_event_ids: list[str]        # must all exist in the evidence bundle
  summary: str                      # <= 80 words
  missing_context: list[str]        # what more evidence would settle it; may be empty
```

Off-schema output is a failure: retry once, then escalate. Never parse loosely.

## How to work

1. Plan first. State assumptions and the files you will touch. Wait for approval.
2. Tests first for new behaviour. Write the failing test, then the code.
3. Surgical changes. Touch only what the task needs; do not tidy unrelated code.
4. Simplest thing that passes. No speculative config, abstractions, or features.
5. Done means the phase gate in `docs/build-prompts.md` is met, with evidence (command output), not a claim.

## Commands

```
pytest -q                         # tests
lint-imports                      # module boundaries
python -m eval.harness run        # eval report over labelled alerts
docker compose up                 # full system (from Phase 4)
```

## Current phase

<!-- Update by hand at the start of each phase. -->
Phase: 1
