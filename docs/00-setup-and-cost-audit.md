# Phase 0: Environment audit & cost cleanup

**Goal:** confirm the existing Azure lab (Log Analytics workspace + Microsoft Sentinel, Azure for Students credit) was ready for an attack-simulation VM: enough credit, no surprise costs, no Defender onboarding that could raise real alerts, and VM quota available.

**Outcome:** found and removed a leftover threat-intelligence pipeline that was driving **100% of workspace cost** (\~$20/month). The fix took three attempts, because each "fixed" state shown by the portal turned out not to be the real state. Every step below was verified against telemetry or the resource itself, not the UI.

---

## Finding 1: Leftover threat-intel connectors were driving all cost

Billing showed \~$21/month with no VM running, 100% of it Sentinel pay-as-you-go. Sentinel bills per GB ingested, so the question became: *what is ingesting?*

```kql
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize GB = round(sum(Quantity)/1000, 3) by DataType
| sort by GB desc
```

**Result:** `ThreatIntelIndicators` 4.15 GB, everything else \~0. A daily breakdown showed \~0.06 GB/day plus \~0.44 GB weekly spikes.

```kql
ThreatIntelIndicators
| where TimeGenerated > ago(7d)
| summarize count() by SourceSystem
```

**Result:** two feeds, Microsoft Defender Threat Intelligence and *Premium* MDTI, both left connected by an earlier Sentinel training exercise. The project's detections key on host behavior (Sysmon), not IOC matching, so neither feed was needed.

## Finding 2: The portal "deleted" a connector that kept running

The standard connector disconnected normally. The deprecated Premium connector had its Disconnect button greyed out, so it was deleted from the connector list instead. An hour later:

```kql
ThreatIntelIndicators
| where TimeGenerated > ago(1h)
| summarize Count = count(), LastSeen = max(TimeGenerated) by SourceSystem
```

**Result:** Premium MDTI still ingesting, last row one minute earlier. The portal had removed the connector from its *view*, but the underlying Azure Resource Manager (ARM) resource still existed. Listing connectors directly from ARM confirmed it:

```bash
az rest --method get \
  --url "https://management.azure.com/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<WORKSPACE>/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2024-09-01" \
  --query "value[].{name:name, kind:kind}" -o table
# -> one orphaned connector of kind PremiumMicrosoftDefenderForThreatIntelligence

az rest --method delete \
  --url "https://management.azure.com/.../dataConnectors/<CONNECTOR_ID>?api-version=2024-09-01"
```

Re-listing returned empty, and ingestion stopped within minutes.

**Lesson:** the portal is a view over ARM; ARM is the source of truth.

## Finding 3: Sentinel kept republishing the stored indicators weekly

Ingestion resumed in weekly bursts (\~150K rows each), with no connector present. Two hypotheses were tested and disproven (revocation cleanup, then a final in-flight sync) before the cause showed up in the data:

```kql
ThreatIntelIndicators
| where TimeGenerated > ago(10d)
| summarize Rows = count() by LastUpdateMethod, Day = bin(TimeGenerated, 1d)
```

**Result:** every row was `LogARepublisher`. Per Microsoft's documentation, Sentinel republishes **all** stored threat intelligence to Log Analytics every 7–10 days, independent of connectors. The store held \~172K indicators with expiry dates out to 2036, so waiting would not fix it (\~$7/month).

**Fix:** an ingestion-time transformation on the table that drops every row before it is stored. On a Sentinel-enabled workspace, transformations into Analytics tables carry no filtering charge.

```kql
source | where false
```

## Finding 4: The transformation looked applied but wasn't saved

Two more republishes were still billed after the fix. Reading the data collection rule back showed the saved transform was `source` (pass-through), not the filter, even though the portal editor had shown it. It was re-applied through ARM and read back to confirm:

```bash
az monitor data-collection rule show -g <RG> -n <WORKSPACE_TRANSFORM_DCR> \
  --query "dataFlows[].{streams:streams, transform:transformKql}" -o json
# -> "transform": "source | where false" on Microsoft-Table-ThreatIntelIndicators
```

*Verified:* the republish arrived every Tuesday through 11/3; the next cycle (11/10) never landed in the table. Nothing stored, nothing billed.

---

## Other pre-flight checks

| Check | Result |
|---|---|
| Defender for Cloud **Servers** plan | Off, so simulated attacks can't onboard the VM to Defender for Endpoint or raise alerts outside the lab |
| Compute / Network resource providers | Registered (`az provider register`) |
| VM quota | Confirmed per region with `az vm list-usage` |
| Budget | $10/month alert threshold (remaining credit ÷ months of planned use), with 50% / 80% actual and 100% forecast alerts |

## Takeaways

- **Verify the outcome, not the control screen.** Three of the four findings were cases where the portal showed a fixed state that wasn't real; each was caught by checking telemetry or reading the resource back.
- **Leftover assets from past projects are a real risk.** Nothing here was malicious, but an unmanaged, forgotten pipeline consumed a third of the lab's budget before anyone looked.
- **A budget is an alert threshold, not an allowance.** It was set from what the remaining credit can sustain, not from what was being spent.
