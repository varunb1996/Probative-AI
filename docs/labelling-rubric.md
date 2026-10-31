# Labelling rubric: Phase 0

Scenario: OTRF `empire_mimikatz_logonpasswords` (T1003, credential dumping from LSASS).
Labeller: Varun. Written before labelling; any change after labelling starts is logged at the bottom with a date.

## What I am labelling

One Hayabusa alert at a time (level low or medium). The question is not "does this rule look scary?" but:

> **Was the event behind this alert caused by the attacker's activity?**

- **malicious**: yes. The event is part of the attack, directly or as a side effect, even if the event looks routine on its own.
- **benign**: no. The event comes from normal Windows, domain or admin activity with no link to the attacker.

The rule's name and its severity level do not decide the label. A low alert can be malicious; a medium alert can be benign.

## What the scenario tells me (verified against the dataset on 2026-10-31)

- Attacked machine: `WORKSTATION5.theshire.local` (5,188 of 6,026 events; MORDORDC 528, WORKSTATION6 310).
- Recording window: 2020-08-07, 14:32:25 to 14:35:26 UTC. This is the whole recording, so time alone does not separate attack from background; steps 1 to 3 do.
- Attacker process: `powershell.exe` on WORKSTATION5
  - **PID 1648 (decimal) = 0x670 (hex).** Sysmon events show 1648; Security-channel events show 0x670. Same process.
  - **ProcessGuid {297bc33e-65d0-5f2d-8207-000000000400}** (Sysmon only; the most reliable match when present).
- It is the only process that talks to `10.10.10.5:80` (Empire agent calling its controller).
- It is the only non-svchost process that touches LSASS (access `0x1010`).

## Decision steps, in order

Stop at the first step that settles it.

1. **Same process as the attacker?** The alert's process (source, parent or child) is the attacker process, matched by ProcessGuid, or by PID **1648 or 0x670** on WORKSTATION5, or is anything it started. → **malicious**
2. **Talking to the attacker's server?** Destination is 10.10.10.5, in either field name: `DestinationIp` (Sysmon event 3) or `DestAddress` (Security event 5156). → **malicious**
3. **Reading LSASS memory from a non-system process?** PowerShell, cmd, rundll32 or an unknown binary opening `lsass.exe` with any access mask that includes memory read, for example `0x10`, `0x1010`, `0x1410`, `0x1fffff`. → **malicious**
4. **Known Windows behaviour with no link to the attacker?** For example `svchost.exe`, `MsMpEng.exe`, `wininit.exe`, `csrss.exe` accessing processes; `dns.exe` or `lsass.exe` network traffic on the domain controller; routine service activity. → **benign**
5. **On a different host with no link to the attacker?** Events on MORDORDC or WORKSTATION6 that do not involve the attacker process, 10.10.10.5, or activity started from WORKSTATION5's attacker process. → **benign**. This includes the two "Raw Access Read" alerts from `lsass.exe` on MORDORDC, unless the surrounding events show a link to the attacker; record what I checked.
6. **Still unclear after checking the 20 surrounding events?** → label **malicious**, start the rationale with `UNSURE:`. (Missing an attack costs more than a false alarm; UNSURE labels are counted and reported separately.)

## What I record for every alert

- label: malicious or benign
- rationale: one line naming the step that decided it and the evidence, for example
  `step 1: SourceProcessId 0x670 = attacker PowerShell` or `step 4: svchost accessing lsass with 0x1000, routine`
- `UNSURE:` prefix when step 6 was used

## Worked examples (patterns from this dataset)

| Alert | Evidence | Label | Step |
| --- | --- | --- | --- |
| Potentially Suspicious AccessMask Requested From LSASS | powershell.exe (PID 1648) opens lsass.exe with 0x1010 | malicious | 1 |
| Network Connection Initiated By PowerShell Process | PID 1648 to 10.10.10.5:80 (DestinationIp or DestAddress) | malicious | 1 or 2 |
| Proc Access | svchost.exe opens lsass.exe with 0x1000 | benign | 4 |
| Proc Access | source process is PID 1648 / 0x670 | malicious | 1 |

## Sample: 30 alerts

There are only three low-level rule titles, so the split is fixed:

| Group | Count | How chosen |
| --- | --- | --- |
| All medium alerts | 9 | all of them |
| Local Accounts Discovery (low) | 2 | all of them |
| Network Connection Initiated By PowerShell (low) | 5 | random; these are near-identical callbacks, so more copies add little |
| Proc Access (low) | 14 | random, spread across hosts: 8 WORKSTATION5, 3 MORDORDC, 3 WORKSTATION6 (or as close as the data allows) |

Random picks use a fixed seed (42) so the sample can be reproduced. The sampling script records which alert IDs were chosen.

## Quality check

- Time each label; record the average (this is the human baseline).
- One week after finishing, re-label a random 6 of the 30 without looking at the first labels. Report how many matched. Disagreements are reviewed and the rubric is updated if a rule was unclear.

## Change log

- 2026-10-31: Rubric written. Filled in the attacker process (PID 1648 / 0x670, ProcessGuid). Step 1 now matches decimal or hex PID. Step 2 names both destination fields (DestinationIp, DestAddress). Step 3 covers any memory-read mask, including 0x10. Step 5 names the DC "Raw Access Read" alerts. Sample split made concrete (9 medium, 2 discovery, 5 network, 14 process access), weighted toward Proc Access, where judgment is needed.
- 2026-10-31: 30 sample labels proposed by Claude and reviewed by Varun (labeller field records this). Human baseline comes from a 6-alert from-scratch spot check instead. Phase 0c must use a non-Claude model.
