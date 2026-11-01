# Probative AI: Design

Exported from the design doc on 2026-10-31. Source of truth for architecture; CLAUDE.md is the short version.

## Problem and hypothesis

Probative AI is a measured Tier-1 alert triage system: a deterministic pipeline with one LLM judgment call, plus a bounded investigator for the hard cases. The goal is career first (a credible, benchmarked portfolio system), product second (the demo becomes the opener for SOC analyst interviews).

**Observation (secondhand, to verify).** SOC teams are widely reported to drown in alerts, most of them false positives. LLM triage exists but is not trusted, because almost nobody measures whether its verdicts are right. This is industry consensus, not a lived observation; the product track must confirm or kill it through interviews.

**Hypothesis.** We believe Tier-1 triage of rule-based detections can be done by a bounded LLM step with measured reliability. If we run Sigma rules over public attack telemetry (OTRF Security-Datasets, Splunk BOTS) and add LLM triage that cites its evidence, then the analyst review queue shrinks by at least 50% while recall on truly malicious alerts stays at or above 95%, within 6 weeks.

**Kill conditions.**

- Recall falls below 90% at any meaningful queue reduction.
- A deterministic baseline (rule severity, allowlists, dedup, evidence scoring) lands within 5 points of the LLM. The model has not earned its place; publish that finding.

## Inputs, outputs and success

| Item | Definition |
| --- | --- |
| Input | Raw host and network logs (Sysmon, Windows events, Zeek) from public datasets |
| Output | A triaged alert queue: verdict, confidence, cited event IDs, and a short evidence summary per alert |
| Second output | An eval report scoring every component against hand-built per-alert labels |
| Baseline | Week-1 null test: hand-labelling time per alert, raw-model accuracy on 30 alerts, severity-only accuracy on the same 30 |
| Success | Queue reduced by 50% or more at 95% or higher recall on malicious alerts |
| Falsifier | The two kill conditions above |

Open question: per-alert ground truth does not exist in these datasets. Building it from the scenario write-ups is week-1 work and sets how many alerts per rule type we can evaluate.

**Phase 0 dataset (verified 2026-10-31).** OTRF atomic scenario `empire_mimikatz_logonpasswords` (credential access, T1003):

- URL: `https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip` (about 0.7 MB zipped)
- Contents: one JSON-lines file, `empire_mimikatz_logonpasswords_2020-08-07103224.json`, 6,026 events in NXLog-flattened format. Channels: Windows PowerShell 2,949; PowerShell/Operational 1,695; Security 702; Sysmon 679; WMI 1.
- Hayabusa v4.3.1 reads it directly: `hayabusa dfir-timeline -f <file>.json -J -w -q -K -U -t jsonl -o data/alerts_raw.jsonl -C`. Result: 2,389 detections: 2,036 info, 344 low, 9 medium, 0 high.
- Medium alerts include LSASS access from a non-system account and potential credential dumping; low alerts are dominated by process access (272) and network connections (70).
- Informational detections are event-logging rules, not alerts. The null-test sample of 30 should be drawn from the 353 low and medium alerts: all 9 medium plus 21 low, sampled across rule titles.
- Note: in Hayabusa v4.x the timeline command is `dfir-timeline`; older guides say `json-timeline`.

## Decomposition and classification

Six of seven Tier-1 steps are deterministic; only the judgment step needs a model. The slow steps (context, enrichment) are slow for humans because of tool-switching, not because they need intelligence.

| Step | Mechanism | Why | How verified |
| --- | --- | --- | --- |
| 1 Read the alert | [D] | Structured fields; rule meaning is a lookup | Schema validation on parse |
| 2 Check known noise | [D] | Allowlists, dedup counts, frequency | Unit tests on allowlist and dedup rules |
| 3 Gather context | [D] | Fixed, process-scoped queries: the triggering event, events from the same process, its parent and children, and that process's network events; plus user baseline and asset tier. Not a host time window | Query tests against fixture logs |
| 4 Enrich indicators | [D] | Lookups against local threat-intel feeds (abuse.ch) | Known-bad fixtures must hit |
| 4b Score evidence | [D] | Deterministic risk score; the baseline the LLM must beat | Scored on labelled set |
| 5 Judge | [P] | Weighing mixed evidence, reading obfuscated command lines | Runtime verifier plus offline labels |
| 5b Investigate (subset) | [A] | Next query depends on what the last one found | Same verifier; loop contract |
| 6 Act | [D] | Threshold and override policy in code | Policy unit tests |
| 7 Record | [D] | Database write | Integration test |

## Control graph

A deterministic pipeline carries every alert end to end; the model holds no execution authority, and the agent is one small, bounded piece on the exception path.

```text
[X] Raw logs
  -> [D] Sigma detection (Hayabusa / Chainsaw)
  -> [D] 1 Parse alert
  -> [D] 2 Noise filter (allowlist, dedup)  --known noise--> [D] Close as noise -> [S] Record
  -> [D] 3 Context bundle, process-scoped (trigger event, same-process events,
         parent and children, that process's network events; user baseline, asset tier)
       reads [S] human-confirmed prior verdicts only
  -> [D] 4 Enrichment (local threat-intel feeds)
  -> [D] 4b Evidence score (baseline)
  -> [P] 5 Triage call: verdict + confidence + cited event IDs
  -> [V] Verifier: schema, citation grounding, hard overrides,
         baseline disagreement, injection tripwire, trigger anchoring
  -> [D] 6 Route:
       malicious / any check failed      -> [H] Analyst queue (escalate)
       benign + rule type promoted        -> [D] Auto-close -> random audit sample -> [H]
       benign + rule type not promoted    -> [H] Suggested close (shadow / assisted)
       suspicious, insufficient context   -> [A] Investigator loop
  [A] Investigator loop (max 6 steps, token budget):
       context -> [P] decide next query -> read-only tool -> append result -> context
       exits: verified verdict -> [D] 6 Route | budget hit -> [H] Analyst queue
  -> [S] 7 Record verdict, evidence, human decision
```

Legend: [D] deterministic, [P] probabilistic call, [A] agentic loop, [V] verifier, [H] human gate, [S] state, [X] external system.

## Node explanations

Two probabilistic pieces exist; each carries the evidence that would remove it.

| Field | [P] 5 Triage call | [A] Investigator |
| --- | --- | --- |
| Responsibility | Judge one alert from a fixed evidence bundle | Gather missing evidence for alerts the triage call marks insufficient |
| Why not deterministic | Mixed evidence and obfuscated command lines resist rules at reasonable cost | The next query depends on what the previous one returned |
| Input | Alert, context bundle, enrichment, evidence score | Same bundle plus the triage call's stated gap |
| Output contract | verdict (benign, suspicious, malicious), confidence 0 to 1, cited event IDs, summary under 80 words | Same contract, plus the list of queries it ran |
| Verifier | Runtime verifier (section below); offline labels | Same verifier; loop contract |
| Failure path | Malformed output: retry once, then escalate | Budget or step cap hit: escalate with its query log |
| Falsifier | Baseline evidence score within 5 points of it on labelled data | On the escalated subset, no recall gain over escalating straight to a human |

## Investigator loop contract

The loop is read-only, capped at 6 steps, and always ends in either a verified verdict or a human.

| Clause | Contract |
| --- | --- |
| Goal | Resolve a "suspicious, insufficient context" alert to a verdict the verifier accepts |
| Observation | The evidence bundle plus every prior tool result, appended in order |
| Actions | Read-only tools only: host timeline, process tree, network connections, entity lookup. No containment, ever |
| Argument checks | Code validates every call: host must exist, time window capped, no free-text queries |
| Progress signal | Each step must add at least one new event or entity to the bundle; two empty steps in a row end the loop |
| Verifier | The same runtime verifier as the triage call |
| Retry budget | One retry per malformed tool call |
| Stop condition | Verified verdict returned |
| Failure condition | 6 steps, token budget, or no-progress rule reached |
| Escalation | To the analyst queue, carrying its full query log as evidence |

## Verifier design

The verifier guards only the close path, because errors are asymmetric: escalating a benign alert costs an analyst minutes, closing a real attack can cost the company. Escalation is always allowed.

1. **Schema.** Verdict is one of three values, confidence is numeric, citations are a list of event IDs. Malformed output: retry once, then escalate.
2. **Citation grounding.** Every cited event ID exists in the bundle, and quoted field values match the real events. Catches invented evidence.
3. **Hard overrides.** A threat-intel hit, a critical asset, or a known-bad hash can never be closed by the model.
4. **Baseline disagreement.** Model says benign while the evidence score says high risk: escalate.
5. **Injection tripwire.** Instruction-like text in any log field is flagged in code and treated as an attack signal.
6. **Calibrated confidence.** Close thresholds are set per rule type from the labelled set, never taken from the model's self-reported number.
7. **Trigger anchoring.** The verdict must cite the triggering event; otherwise escalate. Catches verdicts reasoned from neighbouring activity instead of the alert itself (seen in the Phase 0 null test).

Offline, every component is scored against the labels; the evidence score is the baseline row in every report.

## Human gates and earned autonomy

Auto-close is earned per rule type through measured evidence, never switched on globally.

| Mode | What the system does | What the human does |
| --- | --- | --- |
| Shadow (default) | Records what it would close | Reviews everything |
| Assisted | Ranks the queue, suggests closes | Accepts or rejects each suggestion |
| Auto-close | Closes benign alerts for promoted rule types | Reviews a random audit sample |

- **Promotion gate:** zero missed malicious alerts across at least 300 closes for that rule type. By the rule of three, 30 clean closes still allows a miss rate up to about 10%; 300 brings it near 1%.
- **Demotion:** one malicious alert found among closes drops that rule type back to shadow automatically.
- **Audit sample:** a fixed share of auto-closes goes to a human, producing fresh labels in production.
- **Gate shape:** every human gate is a queued request (alert, evidence, suggested action, options) the pipeline resumes from, never a blocking prompt.

## State model and memory rationale

The system needs state, not memory: every cross-alert fact is an ordinary query by host, user and time.

| Kind | What it holds | Where |
| --- | --- | --- |
| Working context | The evidence bundle for one alert | Dies with the call |
| Workflow state | Each alert's stage and mode | Postgres |
| Application state | Alerts, verdicts, cited evidence, human decisions, rule-type promotion status | Postgres |
| External sources | Raw logs, threat-intel feeds | Queried, never copied into prompts wholesale |
| Execution history | Every model call, tool call and verifier result | Postgres audit table |

- **Attack chains** are a deterministic join on ATT&CK tags carried by Sigma rules, grouped by host and time window.
- **Compounding-error rule:** only human-confirmed verdicts enter later context; unconfirmed prior alerts enter as raw facts only. This blocks an attacker from priming the model with benign-looking noise.
- **No vector store.** Retrieval over past analyst notes is earned only if notes prove too varied to codify as allowlist rules in step 2.
- **No subagents.** One reasoning context per alert; nothing in the design needs isolation or parallel exploration.

## Architectures compared

Recommendation: A first for evidence, refactored into B as the backbone, with C added only as a bounded investigator on the escalated subset.

| Criterion | A: Minimal | B: Decoupled | C: Agent only |
| --- | --- | --- | --- |
| LLM calls per alert | 1 | 1 | 5 to 15 |
| Testability | High | High | Low: variable paths |
| Eval baseline | Built in | Built in | None |
| Injection blast radius | One skewed verdict | One skewed verdict | Attacker can steer queries |
| Scales horizontally | No | Yes, per tier | Costly |
| Hiring signal | Solid | Strong: infra plus eval | Common, unmeasured |

**Rejected:** C as the main architecture, because it has no baseline to measure against, multiplies GPU cost, and widens the attack surface. A as the final form, because it cannot show independent scaling, which the career goal needs.

## Critique and sign-off

Signed off: every node is classified, every probabilistic piece has a verifier and a falsifier, the loop has a stop condition, and the model holds no execution authority. What remains fragile:

- **Lab data flatters the queue number.** Public datasets carry far less benign noise than a real SOC, so queue-reduction figures will be optimistic. State this in every report; only the product track's real data can fix it.
- **Labels are the whole eval, and one person makes them.** Write a labelling rubric first; re-label a random 20% a week later and report your own agreement rate.
- **Auto-close may never promote.** 300 clean closes per rule type is unlikely on public data. That is an honest result: report shadow-mode metrics and the promotion math.
- **Local models may lose to the baseline.** Run one strong cloud model on the same public alerts as a ceiling, so a loss can be attributed to model size rather than design.
- **Citation grounding is not semantic verification.** It proves the evidence exists, not that the reasoning about it is right. Offline labels remain the real check.
- **The injection tripwire is bypassable** (encoding, obfuscation). It is a detection signal, not the defense; the defense is that the model can only propose, and code overrides it.

## MVP cut and sequencing

Build the null test first; each later phase starts only when the previous gate passes.

1. **Week 1: null test and labels.** One OTRF scenario, Sigma via Hayabusa, 30 hand-labelled alerts, raw model versus severity baseline. Gate: labelling rubric written and baseline numbers recorded.
2. **Weeks 2 to 3: Architecture A as clean modules.** Steps 1 to 7, verifier, eval harness, one process. Gate: full eval report on all labelled alerts, LLM versus evidence-score baseline.
3. **Week 4: refactor into B.** Queue between ingestion, triage and inference; Postgres state. Gate: identical eval numbers to A, proving the split changed deployment and not behaviour.
4. **Weeks 5 to 6: bounded investigator.** Loop contract enforced in code. Gate: agent versus escalate-to-human recall on the escalated subset, published either way.

If labelling overruns, phase 4 drops; B with a strong eval report is a complete project.

## LLD 1: Open-source stack

Every component is free; the only real cost is GPU time, which the demo sidesteps by running evals as batch jobs instead of serving 24/7.

| Node | Component | Why this one |
| --- | --- | --- |
| Detection | Hayabusa (Sigma rules over EVTX/JSON); Chainsaw as fallback | Reads Windows logs directly, ships Sigma support; verified on the Phase 0 dataset |
| Domain contracts | Python, Pydantic models | One schema enforced at every boundary |
| API and human gates | FastAPI | Queue views, accept/reject actions |
| Queue | A Postgres queue table (lease, ack, reclaim on expiry, priority, `FOR UPDATE SKIP LOCKED`) | Same guarantees as Redis Streams with no extra service; Redis does not run on the build laptop (decision 2026-11-01) |
| State | Postgres (Neon free tier), JSONB for evidence bundles | One store for alerts, verdicts, audit; no pgvector, since the design has no retrieval |
| Threat intel | abuse.ch feeds synced to Postgres on a cron | Free, local, no per-lookup API limits |
| Inference, dev | Ollama with a small instruct model | Runs on a laptop; fine for one alert at a time |
| Inference, eval | vLLM on a free notebook GPU (Kaggle or Colab) | Batches the labelled set; schema-guided output |
| Inference interface | One OpenAI-compatible client | Ollama and vLLM both expose it, so switching is config |
| Eval | pytest plus a small harness writing results to Postgres | Every run comparable to the last |
| Packaging | One Render free web service: FastAPI plus the workers as threads (`render.yaml`) | A public link with no Docker; workers talk only through the queue, so they can move to their own services unchanged |

Ceiling check: run one strong cloud model on the same public alerts. Allowed only because the data is public; the flag is enforced in code (next section).

Not chosen: Ollama for concurrent serving (degrades under parallel load), Kafka (operational weight with no benefit at this volume), a vector database (no retrieval earned).

## LLD 2: Data and AI hardening

The defense is structural: log text is treated as hostile data, the model can only emit a validated object, and code owns every decision that matters.

**Data locality**

- Inference defaults to the local endpoint. A cloud call requires `allow_cloud=true` AND every alert in the request tagged `dataset=public`; the client refuses otherwise.
- No secrets, hostnames from a real network, or credentials ever enter a prompt; config comes from environment variables.

**Prompt-injection defense, in layers**

1. **Sanitise before the prompt.** Strip control characters, cap each field's length, and wrap all log content in a clearly delimited data block the instructions refer to as untrusted.
2. **Constrain the output.** Schema-guided decoding (vLLM) plus Pydantic validation; anything off-schema is a failure, never parsed loosely.
3. **No tools on the triage call.** Only the investigator has tools, all read-only, with arguments validated in code (host exists, window capped, no free-text queries).
4. **Verify after.** Citation grounding, hard overrides and baseline disagreement (Verifier design above).
5. **Tripwire.** Instruction-like strings in log fields raise an attack signal on the alert.

**Least privilege**

| Service | Can read | Can write |
| --- | --- | --- |
| Inference | Nothing; no database credentials | Nothing |
| Triage worker | Evidence bundles | Verdict rows only |
| Investigator | Read-only views over logs and entities | Its own query log |
| API | Queue views | Human decisions only |

Every model call, tool call and verifier result lands in an append-only audit table.

## LLD 3: Independent scaling

Each tier scales on its own bottleneck because tiers talk only through streams; inference is the one scarce resource, so everything upstream is designed to wait for it rather than overwhelm it.

| Service | Consumes | Produces | Scales with | Bottleneck |
| --- | --- | --- | --- | --- |
| Ingest worker | Log files | `alerts.raw` | Log volume | CPU |
| Enrich worker | `alerts.raw` | `alerts.enriched` | Alert rate | Postgres queries |
| Triage worker | `alerts.enriched` | `alerts.triaged` | Inference capacity | GPU concurrency |
| Inference server | HTTP from triage and investigator | Verdicts | GPU replicas | GPU |
| Investigator worker | `alerts.investigate` | Verdicts back to triage | Escalated volume | GPU and step cap |
| API | Postgres | Human decisions | Analyst count | Rarely |

**Rules that make it work**

- **At-least-once delivery, idempotent writes.** Streams may redeliver, so every write is an upsert keyed by alert ID.
- **Backpressure by waiting.** Triage workers cap in-flight inference requests; excess alerts sit in the stream, never dropped. Pending-entry recovery reclaims messages from crashed workers.
- **Priority lane.** Critical-asset alerts are queued at a higher priority and claimed first.
- **As deployed (2026-11-01).** The streams are rows in one Postgres queue table, and the workers run as threads in a single free web service. Scaling is therefore processes on one host, not separate machines; moving a worker to its own service needs configuration only.
- **Same code, two shapes.** Pure step functions are called in-process in Architecture A and by stream consumers in B; the eval numbers must match exactly.

**Unit economics, measured not guessed.** Once the first triage call works, record tokens per alert and the GPU's tokens per second under load. Sustainable incoming alerts per minute = (GPU tokens per minute ÷ tokens per alert) ÷ the share of alerts that survive noise filtering and reach the model. Put the measured figures in the README.

## LLD 4: Repo layout and enforced boundaries

The architecture survives Claude Code only if the boundaries are checked by tools, not remembered by prompts: pure logic in the middle, I/O only at the edges.

```text
triage/
  domain/       Pydantic models: Alert, EvidenceBundle, Verdict, LoopState. Imports nothing internal.
  pipeline/     parse, noise, context, enrich, score. Pure functions over domain objects.
  judge/        prompt builder, sanitiser, inference client, output parser. No database.
  verify/       checks and routing policy. Pure; the safety core.
  investigate/  loop runner with step and token budgets, read-only tool specs.
  store/        Postgres repositories, one per table.
  services/     stream consumers that wire steps to Redis and store. The only I/O layer.
  api/          FastAPI routes for queues and human decisions.
eval/
  labels/       hand-built ground truth. Protected: never edited by Claude Code.
  harness/      runs any step or the whole pipeline over labels, writes reports.
tests/
```

**Import contracts** (checked by import-linter on every change):

- `domain` imports nothing from the project.
- `pipeline`, `judge`, `verify` and `investigate` never import `store`, `services` or `api`.
- Only `services` and `api` import `store`.
- `verify` never imports `judge`, so the checker cannot share the generator's code paths.

If a change needs to break a contract, that is a design question for you, not a refactor for the agent.

## LLD 5: Claude Code handoff

CLAUDE.md tells Claude Code the architecture; hooks and tests enforce it. Instructions in CLAUDE.md are advisory, while a hook runs every time regardless of what the model decides.

**One-time setup**

- **CLAUDE.md (under about 200 lines):** the control graph, the import contracts, the output contract, and a short never-list: never edit `eval/labels/`, never loosen a test to make it pass, never put a policy rule in a prompt, never give the model write access.
- **PreToolUse hook:** block any edit under `eval/labels/`, `.claude/` or `.importlinter`, through edit tools, Bash and PowerShell, with forward or back slashes. Ground truth is the one thing the agent must not touch.
- **PostToolUse hook:** run `lint-imports` and `pytest -q` after edits, so a broken boundary fails immediately.
- **Session habits:** plan mode (Shift+Tab or /plan) at the start of each phase; /clear between phases; /rewind when a session goes wrong; commit at every gate.

**Phases** (one per session; full prompts in `docs/build-prompts.md`)

| Phase | Prompt core | Gate before the next phase |
| --- | --- | --- |
| 0 Null test | Scripts to run Hayabusa over one OTRF scenario, export alerts to JSONL, and a terminal labelling tool I run myself | 30 labelled alerts, raw-model and severity-baseline scores recorded |
| 1 Contracts | Pydantic models for the domain from the output contract; failing tests from golden alerts. No implementation | Tests fail for the right reason |
| 2 Pipeline | Implement `pipeline/` until tests pass; pure functions only | Green tests, import contracts pass |
| 3 Judge and verify | Inference client from env config; the six checks, each with adversarial fixtures; harness comparing LLM to the evidence score | First full eval report |
| 4 Services | Wrap existing steps as Redis Streams consumers in `services/`. Do not modify `pipeline`, `judge` or `verify` | Harness numbers identical through Docker Compose |
| 5 Investigator | Tests first for step cap, no-progress stop, budget escalation and argument validation; then the loop | Agent versus escalate-to-human report |

**Review by hand, every phase:** any diff to `tests/` or `verify/`. The usual way an agent breaks an architecture is not a bad design choice; it is a weakened assertion or a `try/except` that quietly swallows a verifier failure.

## Sources

- Claude Code features: plan mode, CLAUDE.md, hooks: https://dev.to/codingcapybaras/claude-codes-most-underused-features-53am
- CLAUDE.md as context versus PreToolUse hooks as enforcement: https://dev.to/promptmaster/coming-to-claude-code-from-codex-7-things-to-set-up-on-day-one-1n14
- OTRF Security-Datasets: https://github.com/OTRF/Security-Datasets
- Hayabusa: https://github.com/Yamato-Security/hayabusa (v4.3.1 tested on the Phase 0 dataset)

Other tool names (Chainsaw, Splunk BOTS, abuse.ch, vLLM, Ollama, import-linter) are from general knowledge; check each project's current docs before using it.

## Change log

- 2026-11-01: Phase 4 stack. Redis Streams replaced by a Postgres queue table; Docker Compose replaced by one Render free web service (API plus worker threads); Postgres hosted on Neon. Reason: Redis does not run on the build laptop, and a free public link was wanted. The Phase 4 gate replays the recorded Phase 3c judge results through the stack: 0 route or score differences on the 35 labelled alerts.

- 2026-10-31: After the Phase 0 null test (`docs/null-test-results.md`). Step 3's context bundle is now process-scoped (trigger event, same-process events, parent and children, that process's network events) instead of a host time window. Added verifier check 7, trigger anchoring: the verdict must cite the triggering event, else escalate. Reason: both false alarms cited neighbouring PowerShell events and not their own triggering event.
