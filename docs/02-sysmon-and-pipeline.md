# Phase 2: Sysmon and the data pipeline

**Definition of done:** Sysmon running on the VM with a real config, the Azure Monitor Agent installed, a data collection rule shipping only the Sysmon channel to the Sentinel workspace, and Sysmon events queryable there.

**Result:** done. The pipeline works end to end: **Sysmon → Azure Monitor Agent → data collection rule → Log Analytics `Event` table**. The first events arrived about 10 minutes after the rule was created.

## Build

| Component | Choice |
|---|---|
| Sysmon | v15.22 with the community [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) |
| Agent | Azure Monitor Agent, automatic upgrade enabled |
| Data collection rule | Windows event logs, custom XPath `Microsoft-Windows-Sysmon/Operational!*` only |
| Destination | The lab's Sentinel workspace (`Event` table) |

Install on the VM (PowerShell as Administrator):

```powershell
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath .\Sysmon -Force
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
.\Sysmon\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
```

## Design choices

- **A community config, not Sysmon's defaults.** The default logs little of value. The SwiftOnSecurity baseline keeps high-value events and filters routine noise, which matters because Sentinel bills per GB ingested.
- **Collect only the Sysmon channel.** The portal's standard Windows log options don't include Sysmon, and adding the Application, System, and Security logs would add cost without serving the three planned detections.
- **The rule lives in the workspace's region.** A data collection rule has to be in the same region as its destination workspace; the VM can be elsewhere. Here the VM and the workspace are in different regions, and cross-region collection works.
- **Read the configuration back instead of trusting the portal.** The review screen doesn't show which logs are collected, and Phase 0 had already shown that a "saved" portal setting can differ from what's stored. The CLI confirmed a single XPath:

```bash
az monitor data-collection rule show -g <RG> -n <DCR> \
  --query "dataSources.windowsEventLogs[].xPathQueries" -o json
# -> ["Microsoft-Windows-Sysmon/Operational!*"]
```

## Verification

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| summarize Count = count() by EventID
```

First ~10 minutes on an idle server:

| Event ID | Count | Meaning | Used for |
|---|---|---|---|
| 11 | 140 | File created | |
| 13 | 26 | Registry value set | Run key detection |
| 1 | 13 | Process created | PowerShell and scheduled task detections |
| 22 | 4 | DNS query | |
| 12 | 3 | Registry key created/deleted | |
| 8 | 1 | CreateRemoteThread | Logged for later triage |

**Cost:** about 0.44 MB in two hours of idle runtime, a fraction of a cent. The cost risk in this workspace was never Sysmon (see Phase 0).
