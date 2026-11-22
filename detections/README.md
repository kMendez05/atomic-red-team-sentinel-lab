# Detections

KQL analytics rules for Microsoft Sentinel, built on the `Sysmon` parser function and validated against [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests.

| File | Technique | Signal | Atomic used to validate |
|---|---|---|---|
| [`sysmon_parser.kql`](sysmon_parser.kql) | n/a | Parser saved as workspace function `Sysmon` | n/a |
| [`T1059.001_encoded_powershell.kql`](T1059.001_encoded_powershell.kql) | T1059.001 PowerShell | `-e/-enc/-EncodedCommand` + base64, decoded for the analyst | T1059.001-17 |
| [`T1053.005_scheduled_task.kql`](T1053.005_scheduled_task.kql) | T1053.005 Scheduled Task | Task created to run a shell/script tool; shell launched by Task Scheduler | T1053.005-2 |
| [`T1547.001_run_key.kql`](T1547.001_run_key.kql) | T1547.001 Registry Run Keys | Run/RunOnce written by a shell/script tool or pointing to a user-writable path | T1547.001-1 |

## Deployment
Rules are deployed as code through the Microsoft Sentinel REST API (`Microsoft.SecurityInsights/alertRules`, kind `Scheduled`) from Azure Cloud Shell, not the portal. Common settings: run every 5 minutes, 15-minute lookback, alert when results > 0, entity mapping for host, account, and process. Each rule only evaluates events ingested since its previous run (`IngestionTime > ago(5m)`), so delayed logs are still caught but every event alerts exactly once.

## Validation
- **True positives:** each rule produced exactly one alert for its atomic test, with entities (host, account, process) and custom details (decoded command, scheduled-task signal, Run key and value) populated.
- **False positives:** an idle Windows Server 2022 VM surfaced Windows maintenance tasks (Defender `MpCmdRun.exe`, built-in `rundll32` maintenance DLLs, Software Inventory Logging). Fixed with exact filename matching, a user-writable-path condition for `rundll32`, and one documented exception. Zero false positives over the final baseline window.
- **Duplicates:** overlapping lookback windows initially produced repeat alerts; fixed with ingestion-time windowing.
