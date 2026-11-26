# Phase 4: Detection rules

**Definition of done:** one Sentinel analytics rule per technique, written in KQL against parsed Sysmon data, each firing on its Atomic Red Team test without firing on normal Windows activity.

**Result:** done. All three rules produced exactly one alert for their atomic test in the final validation run. Getting there surfaced three false-positive sources and a duplicate-alert bug, all fixed narrowly. Triaging the resulting incidents (Phase 5) led to one more improvement.

Rule files: [`detections/`](../detections/)

## Approach

- **Parse once, detect many.** Sysmon stores its fields as XML in one column. A shared parser function (`Sysmon`) turns them into typed columns (`Image`, `CommandLine`, `ParentImage`, `TargetObject`, ...), so each rule stays short and readable.
- **Rules as code.** In this tenant, the Azure portal's analytics blade redirects to the organization's production Defender portal. I chose not to connect a lab workspace to production, so I deployed the rules through the Sentinel REST API from Cloud Shell and read each rule back to confirm what was actually running.
- **Behavior, not hashes.** Every atomic used genuine signed Windows binaries (PowerShell, cmd, schtasks, reg), so file hashes were useless. All three rules key on command lines, process trees, and registry targets.

| Setting | Value |
|---|---|
| Schedule / lookback | every 5 min / 15 min |
| Trigger | results > 0, one alert per run |
| Entities | host, account, process |
| MITRE | tactic + technique per rule |

---

## Rule 1: Encoded PowerShell (T1059.001)

**Why attackers do it:** encoding makes a malicious command unreadable to a person skimming logs and gets it past security tools that look for keywords.

**What the rule does:** it looks at process-creation events where the process is PowerShell, then for an encoded-command flag followed by a long base64 string.
- **Any abbreviation of the flag:** PowerShell accepts `-e`, `-ec`, `-enc`, and `-EncodedCommand` (and the `/e` form). Checking only for `-EncodedCommand` would be easy to get past; the atomic itself used `-e`.
- **A 20+ character base64 argument:** keeps ordinary flags like `-ExecutionPolicy Bypass` from matching.
- **`OriginalFileName` as well as the path:** catches a renamed copy of PowerShell, because the name embedded in the binary doesn't change.
- **Decodes the command inside the rule:** the analyst sees the suspicious command line and what it actually does in one place, instead of decoding by hand. The test payload decoded to an obfuscated `Invoke-Expression`.

**Blind spots:**
- Encoding handled *inside* a script (for example `-Command` with `[Convert]::FromBase64String(...)`), so no encoded-command flag ever appears.
- PowerShell's engine loaded into another process, so no `powershell.exe` exists for `Image` or `OriginalFileName` to match.

## Rule 2: Suspicious scheduled task (T1053.005)

**Why it's hard:** Windows already runs a lot of scheduled tasks on its own, so separating malicious ones from normal ones takes precise filtering.

**What the rule does:** it fires on either of two signals.
1. **Creation:** `schtasks /create` with a task that runs a shell or script tool, or points to a user-writable folder. This shows who created the task and what it's meant to do.
2. **Execution:** a shell or script tool launched by the Task Scheduler service (`svchost.exe ... -s Schedule`). This shows that the task actually ran and what it ran.

Two signals give **redundancy**. A task created through PowerShell, the COM API, or remotely never runs `schtasks.exe`, so only the execution signal would catch it. During triage, one incident contained only the execution signal because the creation event had fallen outside that run's window, and the rule still fired.

**Learned in triage:** the alert originally carried only `Signal` and `TaskRun`. `TaskRun = cmd.exe` looked identical for my authorized test and for a built-in SYSTEM task, so I had to go back to the raw Sysmon events to tell them apart. I added `User` and `CommandLine` to the alert's custom details so the alert alone is enough to triage.

## Rule 3: Registry Run key persistence (T1547.001)

**Why it's normal:** many applications legitimately add Run keys so they start automatically at user logon (OneDrive, Teams, and so on). Alerting on every Run key write would be noise.

**What the rule does:** it looks at registry-value-set events on `Run` / `RunOnce` keys and fires if either is true:
- **Suspicious writer:** the value was written by a shell or script tool (`reg.exe`, `powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe`, ...) instead of an installer.
- **Suspicious target:** the value launches something from a user-writable folder (AppData, Temp, Downloads, ProgramData, Public) or through an interpreter. Legitimate software normally lives in `Program Files`.

**Blind spot (accepted):** a binary planted under `Program Files` and registered by a custom installer meets neither condition. Catching it would mean flagging Run key writes to normal paths, which legitimate installers do all the time. Planting a file there also requires admin rights, which raises the bar for an attacker.

---

## Tuning: false positives and duplicates

On an idle Windows Server VM with nothing installed, the scheduled-task rule still fired on Windows' own activity:

| What fired | Cause | Fix |
|---|---|---|
| `MpCmdRun.exe` (Defender scanner) | Unanchored regex: `cmd` matched inside "Mp**Cmd**Run" | Anchored the match to the whole file name (`^cmd\.exe$`) |
| `rundll32.exe` | Built-in maintenance tasks launch it through Task Scheduler | rundll32 alerts only when loading from a user-writable path |
| `cmd.exe` running `silcollector.cmd` | Software Inventory Logging, a built-in SYSTEM scheduled task | One exception tied to the exact process, account (SYSTEM), and system32 path |

**Why narrow fixes instead of broad exclusions:** every broad exclusion is an evasion path. Attackers use rundll32 to hide malicious activity, so excluding it entirely would create a blind spot. An exception on any command line containing "silcollector" would let an attacker through just by naming their script that.

**Duplicate alerts:** the rules ran every 5 minutes with a 15-minute lookback, so every event fell inside three runs and alerted up to three times. Incident grouping didn't merge them. The fix filters on **when each event arrived in the workspace** (`IngestionTime`), not when it happened:

```kql
| where IngestionTime > ago(5m)
```

Each run only evaluates events that arrived since the previous run. Every event arrives exactly once, so it lands in exactly one run and alerts once. The 15-minute lookback still matters, because the filter is on arrival time: an event that happened 12 minutes ago but arrived 2 minutes ago is still caught.

## Validation

| Run | Encoded PowerShell | Scheduled task | Run key |
|---|---|---|---|
| Before tuning | 1 alert | 3 incidents (1 also containing 2 FPs; 2 duplicates) | 2 incidents (1 duplicate) |
| Final, after tuning | 1 alert | 1 alert (both signals) | 1 alert |

Each alert carried mapped entities (host, account, process) and the rule's custom details: the decoded command, the scheduled-task signal and run target, or the Run key, its value, and the writer.

## Takeaways

- **Test against the baseline, not just the attack.** All three rules caught their atomic on the first try. The real work was making them quiet on normal Windows activity.
- **Tune narrowly.** Fix the cause (anchor the regex, scope the condition) instead of excluding the process.
- **Verify what's deployed.** Reading each rule back from the API caught differences between what I meant to deploy and what was running.
- **Triage feeds back into detection.** Working the incidents showed what the alert was missing.
