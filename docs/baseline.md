# Phase 2 baseline: deterministic evidence score

Recorded 2026-10-31 from `python -m eval.harness baseline`, run on the code after commit
`a6591c1`, where the weights and `CLOSE_BELOW` were committed before this first scored run.
Dataset: OTRF `empire_mimikatz_logonpasswords`, the 353 low and medium Hayabusa alerts, scored on the 30 assisted labels
(14 malicious, 16 benign).

## Result

| Method | Recall on malicious | Close rate (labelled) | Malicious among closes | Close rate (all low+) |
| --- | --- | --- | --- | --- |
| Evidence score | 13/14 = 93% | 17/30 = 57% | 1 | 273/353 |
| Severity only | 0/14 = 0% | 30/30 = 100% | 14 | 353/353 |

This is the bar the triage call has to beat by more than 5 points (kill condition 2). The score is already
above the 90% recall kill line and below the 95% success line, so the LLM's room to add value is narrow on this dataset.

## Caveats (read before quoting the numbers)

1. **Signal selection was not blind.** The behavioural signals (script host, LSASS target, encoded command, actor
   network) were picked after reading the label rationales, which name PowerShell PID 1648 and LSASS access as the
   attack. The weights are generic and were fixed before scoring, but the baseline is probably optimistic for this
   scenario. Check it on a second OTRF scenario before trusting it.
2. **One scenario, 30 labels.** There are 17 closes and 1 of them is malicious, so the miss rate is barely
   constrained (the promotion gate needs 300 clean closes per rule type). Lab data also underestimates real benign noise.
3. **No allowlist and no intel.** No allowlist rules were written (writing them from the labelled benigns would
   leak), and no abuse.ch feed is synced. `intel_hit` and `prior_confirmed_malicious` never fired.
4. **Dedup did not change any labelled outcome.** A duplicate takes its group head's disposition. Running with
   `--dedup-minutes 0` gives identical numbers, and no labelled duplicate's own score disagrees with its head's.

## The miss

`2db5a6f88af687da` (Proc Access, low): lsass (768) opens the attacker process with `0x1000`. It scores 1
(`level_low` only), because the attacker is the *target* here and every behavioural signal looks at the actor. It is
also the one label marked UNSURE in review. It is the clearest case for the LLM to earn its place, or for a
"target is a known-bad process" signal that would need confirmed verdicts (Phase 4).

## Not in the score yet

User baseline and asset tier (design step 3) are not built: the Phase 2 prompt does not list them and the dataset
has no asset inventory. Raise them in the design chat.

## Per rule type (evidence score, labelled)

| Rule | Labelled | Malicious | Closed | Malicious closed |
| --- | --- | --- | --- | --- |
| Proc Access | 14 | 1 | 14 | 1 |
| Network Connection Initiated By PowerShell Process | 5 | 5 | 0 | 0 |
| Raw Access Read | 3 | 0 | 3 | 0 |
| Potentially Suspicious AccessMask Requested From LSASS | 2 | 2 | 0 | 0 |
| Process Ran With High Privilege | 2 | 2 | 0 | 0 |
| Local Accounts Discovery | 2 | 2 | 0 | 0 |
| Potential Credential Dumping Attempt Via PowerShell | 1 | 1 | 0 | 0 |
| LSASS Access From Non System Account | 1 | 1 | 0 | 0 |

The full per-alert table (score and fired signals) is printed by the harness.
