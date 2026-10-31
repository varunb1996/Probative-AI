# Phase 0c null test: results

Gate evidence for Phase 0 (`docs/build-prompts.md`, 0c). Bring to the design chat before Phase 1.

## Run

| Item | Value |
| --- | --- |
| Date | 2026-10-31, run started 09:11:55 UTC |
| Model | `nvidia/nemotron-3-ultra-550b-a55b:free` via OpenRouter (non-Claude, as the rubric requires) |
| Settings | one call per alert, temperature 0, no retries, strict JSON parsing, no provider JSON mode |
| Input per alert | the alert plus its 20 surrounding events on the same host (21 events), collector boilerplate dropped, values capped at 2,000 characters |
| Labels | 30 assisted (Claude-proposed, Varun-reviewed) + 6 spot-check (from scratch) = 36 |
| Baseline | severity only: rule level high or critical = malicious |
| Script | `scripts/null_test/run.py` |
| Raw replies | `data/nulltest_nvidia_nemotron-3-ultra-550b-a55b_free_20261031T091155Z.jsonl` (gitignored) |

## Results

Recall = share of malicious alerts not closed. Closed = share of all alerts closed (a benign verdict, or below high for severity).

| Set | Method | n | Malicious | Recall | Closed | Invented citations | Off-schema |
| --- | --- | --- | --- | --- | --- | --- | --- |
| assisted | severity | 30 | 14 | 0% | 100% | - | - |
| assisted | model | 30 | 14 | 93% | 43% | 0 | 0 |
| spotcheck | severity | 6 | 3 | 0% | 100% | - | - |
| spotcheck | model | 6 | 3 | 67% | 67% | 0 | 0 |
| **all** | **severity** | 36 | 17 | **0%** | **100%** | - | - |
| **all** | **model** | 36 | 17 | **88%** | **47%** | **0** | **0** |

Model verdicts: 17 benign, 16 malicious, 3 suspicious.

Run integrity: 36 rows, one per labelled alert, no duplicates. Every reply was on-schema on the first and only try. No reply cited an event ID that was not in its input. Re-parsing every raw reply reproduces every stored decision.

## Findings

**Both missed malicious alerts are the two `UNSURE:` labels.** Both were labelled malicious only because the rubric's step 6 sends unclear cases to malicious.

| alert_id | Set | Alert | Label rationale | Model |
| --- | --- | --- | --- | --- |
| `2db5a6f88af687da` | assisted | Proc Access, WORKSTATION5 | UNSURE: lsass opens the attacker process (target PID 1648) with 0x1000 | benign, 0.8 |
| `985211e48cc2f591` | spotcheck | Proc Access, WORKSTATION5 | UNSURE: cannot see the details (a tool display issue, since fixed) | benign, 0.9 |

On the 15 malicious labels not marked UNSURE, the model missed none.

**Four false alarms**, all on WORKSTATION5. The model closed 15 of the 19 benign alerts.

| alert_id | Alert | Model |
| --- | --- | --- |
| `c69c93079157d036` | Proc Access: svchost (lsm.dll) opens svchost, 0x1000 | malicious, 0.9 |
| `27881e43475ab248` | Proc Access: svchost (lsm.dll) opens svchost, 0x1000 | malicious, 0.95 |
| `3846ccc12ddc25f4` | Proc Access: lsass opens svchost, 0x1000 | suspicious, 0.85 |
| `aeeb5148df3ed07b` | Raw Access Read: svchost (SysMain) | suspicious, 0.8 |

**The severity baseline cannot separate anything here.** No high or critical rule fired in this scenario, so it closes every alert and catches nothing.

## Against the hypothesis and kill conditions (`docs/design.md`)

| Test | Result |
| --- | --- |
| Success: queue reduced ≥ 50% at ≥ 95% recall | Not met: 47% closed at 88% recall |
| Kill: recall below 90% at a meaningful queue reduction | 88% at 47% closed is below the line; both misses are the UNSURE labels |
| Kill: deterministic baseline within 5 points of the model | Not triggered by severity (0% recall). The real baseline, the evidence score, arrives in Phase 2 |

## Caveats

- **Assisted labels.** 30 of 36 labels were proposed by a Claude model and reviewed, not labelled from scratch. A non-Claude model was tested for that reason, but the labels may still share a model's way of reading the evidence.
- **Small sample.** 17 malicious alerts. Zero misses on the 15 sure labels still allows a true miss rate of up to 3/15 = 20% (rule of three, 95%).
- **One run of one model.** No repeat runs and no second model, so neither run-to-run variance nor the effect of model size is measured.
- **Free endpoint.** Free OpenRouter endpoints may log prompts. That is acceptable only because this dataset is public (OTRF).
- **Lab data.** One scripted attack in a small lab. Lab data underestimates the benign noise of a real network.
- **Token count** was printed at run time but not stored.

## Open questions for the design chat

1. How are UNSURE labels scored: as malicious (recall 88%), left out (100% on 15), or relabelled?
2. Is one run of one model enough, or should a second, smaller model and a repeat run come before Phase 1?
3. Do the kill conditions apply at n = 17 malicious, given the uncertainty is wider than the 2-point gap to 90%?

## Decisions (design chat, 2026-10-31): GO for Phase 1

- **Scoring.** UNSURE counts as malicious (pre-registered). Headline: **88% recall at 47% closed** (n = 36). Sensitivity: 100% recall on the 15 sure labels. Second sensitivity line, with the excluded alert below removed: 94% recall (15/16) at 46% closed (16/35).
- **Excluded measurement.** Spot-check alert `985211e48cc2f591` is excluded as an invalid measurement: a tool display bug hid the triggering event's details, since fixed. The spot check is n = 5 (model: 2/2 recall, 3/5 closed).
- **Human baseline.** Median 168 s per label (n = 5, after the exclusion above). The first label, 1,922 s, includes learning the tool.
- **Second baseline added.** Rule level medium or higher = malicious: 6/14 recall, 21/30 closed on the 30 assisted labels.
- **Finding: false alarms were not anchored on the triggering event.** The two benign alerts called malicious cited neighbouring PowerShell events and never their own triggering event. `27881e43475ab248` cited 13 Windows PowerShell 800 events. `c69c93079157d036` cited PowerShell 800 and 4103 events, a Security 5156 event and a Sysmon 12 event from powershell.exe. Design response: a process-scoped context bundle and verifier check 7, trigger anchoring (`docs/design.md`).
- **Kill conditions** are not applied at n = 17 malicious. They apply to the Phase 3 eval.
- **Before Phase 3:** run a small local model via Ollama, and repeat the Nemotron run.
