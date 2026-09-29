# Storm-3168 Azure Service Principal Mass Resource Deletion

## Description

Detects agentic cloud-destruction attacks by Storm-3168 (JADEPUFFER) using compromised Azure service principal credentials to enumerate and mass-delete cloud resources. The attack pattern involves 15+ hours of automated Azure ARM API reconnaissance followed by a rapid 7-minute destructive sequence deleting storage accounts, Key Vaults, Function Apps, App Service plans, and — critically — Site Recovery locks and Azure Backup configurations to prevent victim recovery. Credentials are typically obtained from exposed GitHub repository secrets.

This pattern represents "agentic ransomware" — fully automated cloud infrastructure destruction orchestrated via an AI agent framework without deploying traditional malware on endpoints.

False positives: Legitimate administrative operations (e.g., environment teardowns, DR testing) may trigger this. Suppress known authorized deprovisioning automation service principals.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Impact |
| Tactic ID | TA0040 |
| Technique | Data Destruction |
| Technique ID | T1485 |

Secondary: T1490 (Inhibit System Recovery), T1078.004 (Valid Accounts: Cloud Accounts), T1526 (Cloud Service Discovery)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`azure_audit`
  OperationNameValue IN ("Microsoft.Storage/storageAccounts/delete",
                          "Microsoft.KeyVault/vaults/delete",
                          "Microsoft.Web/sites/delete",
                          "Microsoft.Web/serverFarms/delete",
                          "Microsoft.RecoveryServices/vaults/delete",
                          "microsoft.recoveryservices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/delete",
                          "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/delete")
  status=Succeeded
| `security_content_ctime(_time)`
| bin _time span=15m
| stats count as deletion_count dc(OperationNameValue) as resource_types
        dc(ResourceId) as resources_deleted values(OperationNameValue) as operations_list
  by _time caller initiatedBy
| where deletion_count >= 2
| eval risk_score=case(
    match(operations_list, "(?i)recovery|backup") AND deletion_count >= 3, 95,
    match(operations_list, "(?i)keyvault") AND deletion_count >= 3, 90,
    deletion_count >= 5, 85,
    deletion_count >= 2, 70,
    1=1, 50)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| table _time caller initiatedBy deletion_count resources_deleted resource_types operations_list risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Recovery/Backup resource deletion + 3+ total deletions | 95 | Recovery inhibition is a strong ransomware pre-deployment signal |
| Key Vault deletion + 3+ total deletions | 90 | Key Vault destruction is high-impact and rarely legitimate in bulk |
| 5+ resource deletions in 15 min | 85 | Bulk deletion at speed consistent with automated attack scripting |
| 2–4 resource deletions in 15 min | 70 | Suspicious volume; warrants investigation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Storm-3168 / JADEPUFFER | [Microsoft — Storm-3168 (2026-09-25)](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/), [Sysdig — JADEPUFFER (2026-07-04)](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion) |

## References

- [Microsoft Security Blog — Storm-3168 (2026-09-25)](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
- [Sysdig — JADEPUFFER Agentic Ransomware (2026-07-04)](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion)
- [MITRE ATT&CK T1485 — Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [MITRE ATT&CK T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
