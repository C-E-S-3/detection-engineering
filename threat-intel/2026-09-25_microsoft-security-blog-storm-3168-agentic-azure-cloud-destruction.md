---
scraped_at: 2026-09-29T02:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/
report_type: threat-intel
severity: high
title: "Storm-3168 (JADEPUFFER): Agentic-Driven Azure Cloud Attacks via Compromised Service Principals — Data Destruction and Ransomware"
---

# Storm-3168 (JADEPUFFER): Agentic-Driven Azure Cloud Attacks via Compromised Service Principals

## 1. IOCs

### IP Addresses
| Indicator | Type | Context |
|-----------|------|---------|
| `45.131.66[.]106` | IPv4 | Storm-3168 infrastructure; Azure App Service probing and malicious ARM API requests (**already tracked from Sysdig July 2026**) |
| `34.153.223[.]102` | IPv4 | Storm-3168 infrastructure; App Service probing (**already tracked from Sysdig July 2026**) |
| `64.20.53[.]230` | IPv4 | Storm-3168 infrastructure; App Service probing (**already tracked from Sysdig July 2026**) |

### User-Agent String
| Indicator | Context |
|-----------|---------|
| `python-requests/2.34.2` | Storm-3168 automated Azure ARM API requests; distinctive UA in cloud audit logs |

*Note: The above IPs were first observed in Sysdig's July 2026 analysis of the JADEPUFFER agentic ransomware campaign and are already tracked in `iocs/ip.csv`. No new network IOCs were disclosed in the Microsoft September 2026 report.*

---

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | T1190 | Exploit Public-Facing Application | Storm-3168 infrastructure repeatedly probed sensitive Azure App Service application paths to identify credential exposure opportunities |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials in Files | Compromised service principal credentials sourced from GitHub repository history containing exposed secrets |
| Defense Evasion | T1078.004 | Valid Accounts: Cloud Accounts | Compromised Azure service principals used for all discovery and destruction operations — all activity appears as legitimate service account behavior in audit logs |
| Discovery | T1526 | Cloud Service Discovery | Enumerated Azure subscriptions, virtual machines, resource groups, storage accounts, web apps, function apps, Key Vaults, and Site Recovery locks across 15+ hours of pre-attack reconnaissance |
| Impact | T1485 | Data Destruction | Deleted Azure storage accounts, Key Vaults, Function Apps, and App Service plans in a 7-minute destructive sequence |
| Impact | T1490 | Inhibit System Recovery | Targeted and deleted Azure Site Recovery locks and Azure Backup protection configurations to prevent victim recovery |

---

## 3. Malware & Tools

No custom malware tools were deployed in the documented incident. Storm-3168 operated exclusively through:
- **Compromised Azure service principals** — used for all API calls
- **Azure Resource Manager (ARM) API** — for enumeration and resource deletion
- **python-requests/2.34.2** — identifying automated agentic script-driven attack orchestration

This attack pattern is consistent with JADEPUFFER's previously documented use of AI agent frameworks (Hermes, Langflow) to automate cloud infrastructure attacks without deploying traditional malware.

---

## 4. Threat Actor / Campaign Attribution

**Storm-3168** — Microsoft designation (equivalent to JADEPUFFER, first identified by Sysdig, July 2026)

- **Designation origin:** Microsoft Threat Intelligence, September 25, 2026
- **Prior research:** Sysdig documented the same actor as JADEPUFFER in July 2026 (agentic ransomware targeting AI/ML infrastructure via Langflow CVE-2025-3248)
- **Classification:** Microsoft describes Storm-3168 as "the first documented agentic ransomware operation"
- **Motivation:** Financial — ransomware/extortion
- **Attack pattern:** Automated agentic AI-driven infrastructure destruction followed by ransom demand

**Attack timeline documented by Microsoft:**
- **15+ hours:** Automated reconnaissance of Azure subscriptions, resource groups, and recovery configurations
- **7 minutes:** Destructive sequence deleting storage accounts, Key Vaults, Function Apps, and recovery infrastructure
- **Post-destruction:** Ransom demand presented to victim

**Previous JADEPUFFER activities (already tracked):**
- July 2026: Ransomware targeting AI/ML infrastructure via Langflow CVE-2025-3248 RCE
- August 2026: ENCFORGE ransomware encrypting AI/ML model files
- September 2026: Carbonato Docker botnet (see `2026-09-28_threatdown-carbonato-docker-hermes-ai-agent-botnet.md`)

---

## 5. Splunk Detection Searches

### 5.1 — Azure Service Principal Mass Resource Deletion
Detects rapid deletion of Azure resources consistent with Storm-3168 destructive operations. Requires Azure Activity Log ingestion.

```spl
`azure_audit`
  OperationNameValue IN ("Microsoft.Storage/storageAccounts/delete",
                          "Microsoft.KeyVault/vaults/delete",
                          "Microsoft.Web/sites/delete",
                          "Microsoft.Web/serverFarms/delete",
                          "Microsoft.RecoveryServices/vaults/delete")
  status=Succeeded
| bin _time span=5m
| stats count as deletion_count dc(OperationNameValue) as resource_types dc(ResourceId) as resources_deleted
  by _time caller initiatedBy
| where deletion_count >= 3
| eval risk_score=case(
    deletion_count >= 10, 95,
    deletion_count >= 5,  85,
    deletion_count >= 3,  70,
    1=1, 50)
| `security_content_ctime(_time)`
| table _time caller initiatedBy deletion_count resources_deleted resource_types risk_score
```

### 5.2 — Azure Site Recovery Lock and Backup Deletion (Recovery Inhibit)
Detects deletion of Site Recovery and Backup configurations — a specific indicator of ransomware-preparation activity.

```spl
`azure_audit`
  OperationNameValue IN ("microsoft.recoveryservices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectedItems/delete",
                          "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/delete",
                          "microsoft.recoveryservices/vaults/delete")
  status=Succeeded
| eval risk_score=95
| stats count values(OperationNameValue) as operations values(ResourceId) as resources
  min(_time) as firstTime max(_time) as lastTime
  by caller initiatedBy risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime caller initiatedBy operations resources risk_score
```

### 5.3 — Azure Service Principal Enumeration Sweep (Pre-Destruction Recon)
Detects broad Azure subscription enumeration by a service principal — consistent with the 15+ hour pre-attack reconnaissance phase.

```spl
`azure_audit`
  OperationNameValue IN ("Microsoft.Resources/subscriptions/resources/read",
                          "Microsoft.Compute/virtualMachines/read",
                          "Microsoft.Storage/storageAccounts/read",
                          "Microsoft.KeyVault/vaults/read",
                          "Microsoft.RecoveryServices/vaults/read",
                          "Microsoft.Web/sites/read")
  identity.authorization.evidence.principalType=ServicePrincipal
| bin _time span=1h
| stats count as read_ops dc(OperationNameValue) as operation_types dc(ResourceId) as resources_enumerated
  by _time caller initiatedBy
| where operation_types >= 4 AND resources_enumerated >= 20
| eval risk_score=case(
    operation_types >= 6 AND resources_enumerated >= 50, 80,
    operation_types >= 4 AND resources_enumerated >= 20, 60,
    1=1, 40)
| `security_content_ctime(_time)`
| table _time caller initiatedBy read_ops resources_enumerated operation_types risk_score
```

### 5.4 — Storm-3168 Infrastructure IP IOC — Azure App Service Probing
Hunts for requests from known Storm-3168 IP addresses in Azure App Service or web application logs.

```spl
index=* sourcetype IN ("azure:waf", "azure:appservice", "iis") src_ip IN ("45.131.66.106", "34.153.223.102", "64.20.53.230")
| eval risk_score=100
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip dest_url status
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest_url status risk_score
```

---

## 6. Executive Summary

**Storm-3168** (Microsoft designation for the threat actor previously tracked as JADEPUFFER by Sysdig) conducted a destructive Azure cloud attack documented by Microsoft in September 2026. The attack represents the first publicly documented case of an agentic AI-driven ransomware operation against cloud infrastructure.

**Attack Method:**
The threat actor compromised Azure service principal credentials — most likely exposed in a GitHub repository history — and used automated scripting (`python-requests/2.34.2`) to conduct 15+ hours of reconnaissance across Azure subscriptions. In a rapid 7-minute destructive phase, the actor deleted critical cloud resources including storage accounts, Key Vaults, Function Apps, App Service plans, and — critically — Site Recovery locks and Azure Backup protections to prevent victim recovery.

**Significance:**
- Demonstrates a shift from traditional endpoint-based ransomware to cloud infrastructure destruction
- The agentic automation pattern (long reconnaissance + rapid destruction) parallels JADEPUFFER's earlier attacks on AI/ML infrastructure
- Service principal credential exposure via public source code repositories remains the primary attack vector
- The 7-minute destruction window outpaces most incident response procedures

**Defensive priorities:**
- Audit service principal credentials in all repositories (GitHub secret scanning, mandatory)
- Enable Azure Resource Lock on critical resources (Key Vaults, Recovery Services vaults)
- Monitor Azure Activity Logs for bulk resource deletion operations
- Implement just-in-time service principal access patterns

---

## References

- [Microsoft Security Blog — Storm-3168 (2026-09-25)](https://www.microsoft.com/en-us/security/blog/2026/09/25/storm-3168-agentic-driven-cloud-attacks-using-compromised-service-principals/)
- [Sysdig — JADEPUFFER Agentic Ransomware (2026-07-04)](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion)
- [MITRE ATT&CK T1485 — Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [MITRE ATT&CK T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
