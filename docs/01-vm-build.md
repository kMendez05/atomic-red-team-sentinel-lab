# Phase 1: VM build

**Definition of done:** a Windows Server VM running in Azure, RDP allowed from a single IP only, a working nightly shutdown control, and a successful RDP login.

**Result:** done. Getting there required working around capacity limits, a region-allowlist policy, and a region with no auto-shutdown support, plus an access-review finding on a reused automation identity.

## Final build

| Item | Value |
|---|---|
| VM | Windows Server 2022 Datacenter **[smalldisk]**, Gen2, Trusted launch (Secure Boot + vTPM) |
| Size / region | Standard_B2als_v2 (2 vCPU / 4 GB), ~$0.05/hr |
| Disk | 30 GB Standard SSD, deleted with VM |
| Network | NSG with one custom rule: TCP 3389 from a single `/32`; everything else hits the default `DenyAllInBound` |
| Shutdown | Automation runbook, nightly, managed identity scoped to this VM only |
| Tag | `project = atomic-red-team`, so project cost can be isolated in Cost analysis |

Design choices:
- **Server 2022 over Windows 11:** closer to what enterprises actually defend.
- **smalldisk:** the disk keeps billing while the VM is deallocated, so smaller is cheaper.
- **No public inbound ports at create time:** Azure's default for Windows opens RDP to the whole internet.
- **Cost is controlled by runtime, not size:** the VM is deallocated after every session; scheduled shutdown is the backstop.

---

## Problem 1: No capacity, then a policy wall

- `Standard_B2s` failed with **SkuNotAvailable** (capacity) in two regions on consecutive days, even though `az vm list-skus` showed no restrictions. That check reflects subscription-level blocks, not live capacity.
- Another region failed with **RequestDisallowedByAzure**. Reading the policy gave the real constraint instead of guessing:

```bash
az policy assignment list \
  --query "[].{name:displayName, allowed:parameters.listOfAllowedLocations.value}" -o json
# -> "Allowed resource deployment regions": 5 regions
```

- The portal's size picker then showed the entire B-series unavailable to the subscription in most allowed regions. The cheapest available option there was ~4x the price. One allowed region had **B2als_v2** (same 2 vCPU / 4 GB, current generation), and quota was confirmed before deploying:

```bash
az vm list-usage --location <REGION> -o table | grep -iE "BASv2|Total Regional"
```

Logs travel cross-region to the workspace; for one lab VM that transfer is negligible.

*An allowed-regions policy is a preventive cloud governance control. This phase hit one from the user's side.*

## Problem 2: Auto-shutdown doesn't exist in that region

```bash
az vm auto-shutdown -g <RG> -n <VM> --time 0000 --location <REGION>
# -> LocationNotAvailableForResourceType: Microsoft.DevTestLab/schedules
```

The portal's Auto-shutdown page still displayed **On**, but saving failed with the same error.

**Compensating control:** a PowerShell runbook in an Azure Automation account deallocates the VM nightly, authenticating with a system-assigned managed identity.

```powershell
Connect-AzAccount -Identity | Out-Null
$rg = "<RG>"; $name = "<VM>"
$state = ((Get-AzVM -ResourceGroupName $rg -Name $name -Status).Statuses |
          Where-Object Code -like 'PowerState/*').Code
if ($state -ne 'PowerState/deallocated') {
    Stop-AzVM -ResourceGroupName $rg -Name $name -Force | Out-Null
    Write-Output "Deallocated $name (was $state)"
} else {
    Write-Output "$name already deallocated"
}
```

It was tested against a **running** VM, because testing against a stopped one only proves the identity can read the VM, not stop it. **Result:** `Deallocated <VM> (was PowerState/running)`.

The schedule was later found to exist without being linked to the runbook: four nights with no jobs. It was linked and then verified by a **Completed** scheduled job, not by the schedule page.

## Problem 3 (security finding): The reused identity was over-privileged

The Automation account was reused from an earlier exercise, so its identity was reviewed before being granted anything new:

```bash
az role assignment list --assignee <PRINCIPAL_ID> --all \
  --query "[].{role:roleDefinitionName, scope:scope}" -o table
```

| Role | Scope |
|---|---|
| Log Analytics Contributor | entire resource group |
| Monitoring Contributor | entire resource group |
| Monitoring Metrics Publisher | entire resource group |
| Virtual Machine Contributor | this VM only (newly granted) |

Checking what the broadest stale role could actually do:

```bash
az role definition list --name "Log Analytics Contributor" \
  --query "[].permissions[].actions" -o tsv | grep -i extensions
# -> Microsoft.Compute/virtualMachines/extensions/*
#    Microsoft.Storage/storageAccounts/listKeys/action  (also present)
```

`virtualMachines/extensions/*` means the identity could deploy a Custom Script extension and **run code on any VM in the resource group**, including the attack VM. All three stale roles were removed, and a re-list confirmed a single remaining assignment: **Virtual Machine Contributor scoped to this VM**.

## Problem 4: RDP blocked by the wrong source IP

RDP failed with error 0x204 twice:
1. The browser's "what is my IP" returned an **iCloud Private Relay** address, and so did the Azure Connect page, which reads it from the browser.
2. `curl ifconfig.me` returned the machine's **IPv6** address, but the VM's public IP is IPv4.

**Fix:** `curl -4 ifconfig.me` for the address RDP actually uses, then the rule was updated. A reachability test for next time:

```bash
nc -vz -G 5 <VM_PUBLIC_IP> 3389
```

Client settings: credentials are not saved in the client, and no local folders are redirected into the VM, since it will run attack simulations.

---

## Takeaways

- **When the native control isn't available, build a compensating one and test it.**
- **Review an identity's existing access before reusing it.** Inherited permissions are invisible until you look.
- **Verify by outcome.** The schedule, the auto-shutdown page, and the IP lookups all displayed values that weren't real; job history, error messages, and `curl -4` were.
