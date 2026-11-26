# Phase 3: Running the atomics and validating telemetry

**Definition of done:** one benign Atomic Red Team test executed for each scoped technique, its telemetry found in the workspace, and the detection signal identified.

**Result:** done. All three techniques were visible in Sentinel within 5–10 minutes. Every test used genuine signed Windows binaries (PowerShell, cmd, schtasks, reg), so **file hashes were useless. Detection had to key on behavior: command lines, process trees, and registry targets.**

| Technique | Atomic test | Key signal | Sysmon event IDs |
|---|---|---|---|
| T1059.001 PowerShell | #17 PowerShell Command Execution | `powershell.exe -e <base64>` | 1 |
| T1053.005 Scheduled Task | #2 Scheduled task Local | `schtasks /create ... /tr cmd.exe`, then cmd.exe launched by Task Scheduler | 1 |
| T1547.001 Registry Run Keys | #1 Reg Key Run | `reg add ...\CurrentVersion\Run`, then the registry value set | 1, 13 |

## Safety workflow

```powershell
Invoke-AtomicTest <Technique> -ShowDetailsBrief             # list the tests
Invoke-AtomicTest <Technique> -TestNumbers N -ShowDetails   # read it before running
Invoke-AtomicTest <Technique> -TestNumbers N                # run
Invoke-AtomicTest <Technique> -TestNumbers N -Cleanup       # clean up
```

- **Read every test before running it.** This is the core safety habit with Atomic Red Team.
- **Benign tests only.** I skipped credential theft, recon, and privilege-escalation tests, malware emulations, and Run key variants that touch boot or logon (Winlogon, BootExecute), which could break the VM if cleanup failed.
- **A Defender exclusion scoped to the atomics folder only.** The library contains payloads Defender would quarantine. An AV exclusion is itself a risk on a real system; it's acceptable here on an isolated lab VM, and Defender stays on everywhere else.

## T1059.001: Encoded PowerShell

```
powershell.exe                          <- Invoke-AtomicTest session
└─ cmd.exe /c powershell.exe -e ...
   └─ powershell.exe -e JgAgACgA...     <- payload
```

The payload decodes (base64 → UTF-16LE) to:

```powershell
& (gcm ('ie{0}' -f 'x')) ("Wr"+"it"+"e-H"+"ost 'H"+"el"+"lo, fr"+"om P"+"ow"+"erS"+"h"+"ell!'")
```

`'ie{0}' -f 'x'` builds "iex" (Invoke-Expression) without ever writing it, and the command is split into fragments to dodge keyword matching. The payload is harmless, but the technique is real.

## T1053.005: Scheduled task

The test's default start time had already passed (the VM clock is UTC), so the task would have been created but never run. I passed a start time 3 minutes ahead to capture both signals:

```powershell
$t = (Get-Date).AddMinutes(3).ToString("HH:mm")
Invoke-AtomicTest T1053.005 -TestNumbers 2 -InputArgs @{ "time" = $t }
```

```
Creation:   cmd.exe /c SCHTASKS /Create ...
            └─ schtasks.exe /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST <time>
Execution:  svchost.exe -k netsvcs -p -s Schedule      <- Task Scheduler service
            └─ cmd.exe                                  <- at exactly /ST
```

The execution event carries no task name. Linking it to the creation means matching `/TR` to the launched image and `/ST` to the timestamp.

## T1547.001: Registry Run key

| Event ID | Event |
|---|---|
| 1 | `reg.exe ADD "HKCU\...\CurrentVersion\Run" /V "Atomic Red Team" /D "C:\Path\AtomicRedTeam.exe"` |
| 13 | Registry value set: `HKU\<SID>\...\CurrentVersion\Run\Atomic Red Team` → `C:\Path\AtomicRedTeam.exe` |
| 1 | `reg.exe DELETE ...` (cleanup) |

The SwiftOnSecurity config already tags Run key writes (`RuleName: T1060,RunKey`; T1060 is the old MITRE ID for T1547.001), and the shared ProcessId links the process event to the registry change.

## Noise in the same windows

| Event | Cause | Why it matters |
|---|---|---|
| `hostname.exe` and `whoami.exe` around every run | The test framework logging host and user | `whoami` after initial access is real recon. Same event, different meaning in context |
| `csc.exe` spawned by PowerShell | The framework compiling helper code on import | "PowerShell spawns the C# compiler" is a known attacker pattern; a rule on it would fire on this tool |
| `cmd.exe /c` with an empty command | Cleanup for a test with no cleanup steps | Harmless |

These were the first hint of what Phase 4 confirmed: the hard part is not catching the attack, it's staying quiet on everything else.
