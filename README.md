# Atomic Red Team → Microsoft Sentinel Detection Lab

> **Status: in progress.** Environment built and secured; telemetry pipeline (Sysmon → Sentinel) next.

Simulate → detect → investigate → respond: running [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests on a Windows Server VM in Azure, collecting Sysmon telemetry into Microsoft Sentinel, and writing KQL analytics rules to detect each technique.

## Scope

| ATT&CK technique | What it simulates | Primary telemetry |
|---|---|---|
| T1059.001 | PowerShell execution | Sysmon Event ID 1 (process creation) |
| T1053.005 | Scheduled task persistence | Sysmon Event ID 1, Security 4698 |
| T1547.001 | Registry Run key persistence | Sysmon Event ID 13 (registry value set) |

## Architecture

- **Target:** Windows Server 2022 VM (Azure, Trusted launch), RDP restricted to a single source IP
- **Telemetry:** Sysmon → Azure Monitor Agent → Data Collection Rule → Log Analytics workspace
- **SIEM:** Microsoft Sentinel, custom KQL analytics rules
- **Cost control:** VM deallocated between sessions; nightly scheduled runbook as a backstop

## Progress

- [x] **Phase 0: Environment audit & cost cleanup.** Found a leftover threat-intel connector driving 100% of workspace cost; portal deletion silently failed, removed via the ARM API and verified against telemetry.
- [x] **Phase 1: VM build.** Worked around capacity limits and a region-allowlist policy; replaced unsupported auto-shutdown with a tested, least-privilege runbook (and removed stale over-scoped permissions found during access review).
- [ ] Phase 2: Sysmon + data collection rule
- [ ] Phase 3: Run atomic tests, validate telemetry
- [ ] Phase 4: KQL detections
- [ ] Phase 5: Investigate & respond

## Repository layout

```
docs/         phase-by-phase write-ups
detections/   KQL analytics rules, one file per technique
infra/        ARM template and automation scripts
images/       screenshots referenced by the docs
```

## Safety

All tests run on an isolated lab VM in a dedicated resource group. Defender for Cloud server plans were confirmed off so simulated activity does not generate alerts in any production environment.
