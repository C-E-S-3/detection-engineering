---
scraped_at: "2026-10-21T00:00:00Z"
source_url: "https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/"
report_type: threat-intel
severity: critical
title: "Storm-0940 (China) Uses ARTEX Agentic AI Framework in ConnectWise Supply Chain Compromise — 2,250 Microsoft 365 Tenants Targeted"
---

# Storm-0940 (China) Uses ARTEX Agentic AI Framework in ConnectWise Supply Chain Compromise — 2,250 Microsoft 365 Tenants Targeted

## Executive Summary

On October 21, 2026, Microsoft attributed the ConnectWise Cloud Backup OAuth supply chain compromise (first disclosed October 17, 2026) to **Storm-0940**, a China state-aligned threat actor. Storm-0940 weaponized the stolen ConnectWise OAuth application credentials using **ARTEX** — an open-source agentic AI penetration-testing framework released in July 2026 — to automate cross-tenant identity abuse at scale. ARTEX accelerated the speed at which compromised OAuth credentials were used to authenticate to Microsoft 365 customer environments, bypassing per-tenant MFA entirely because the access occurred through an already-trusted application identity rather than an interactive user sign-in.

Microsoft observed Storm-0940 using ARTEX to attempt sign-ins to more than **2,250 M365 tenants**. A separate, concurrent password-spray campaign using Storm-0940 infrastructure targeted **327 accounts across 8 organizations** between October 10–14, 2026. Application credential modifications made during the intrusion can persist as a backdoor even after the compromised ConnectWise application identity is remediated.

This report supplements the initial ConnectWise breach report (`2026-10-19_bleepingcomputer-com-connectwise-cloud-backup-oauth-m365-supply-chain.md`) with Microsoft's formal attribution and additional IOCs.

---

## 1. Indicators of Compromise

### IP Addresses

| Indicator | Type | Confidence | Notes |
|-----------|------|-----------|-------|
| `144.172.64[.]99` | IPv4 | High | Storm-0940 password-spray infrastructure observed conducting automated cross-tenant password spray against 327 accounts across 8 organizations, October 10–14, 2026; attributed by Microsoft MSTIC |

### OAuth Application Identifiers (see also prior report)

| Indicator | Type | Notes |
|-----------|------|-------|
| `506e08f9-6e9a-4da4-942b-a099a03644ae` | OAuth App ID | ConnectWise Cloud Backup / SkyKick first-party app identity abused in supply chain compromise (also in prior report) |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|---------------|-------|
| Initial Access | T1199 | Trusted Relationship | Supply chain compromise via ConnectWise Cloud Backup OAuth credential theft |
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | Storm-0940 used stolen OAuth app credentials to authenticate as trusted ConnectWise app identity to M365 tenants |
| Credential Access | T1110.003 | Brute Force: Password Spraying | Password spray against 327 accounts at 8 organizations from 144.172.64.99, Oct 10–14, 2026 |
| Credential Access | T1528 | Steal Application Access Token | OAuth application credentials stolen from ConnectWise infrastructure |
| Defense Evasion | T1550.001 | Use Alternate Authentication Material: Application Access Token | Authenticated to M365 tenants using stolen OAuth app token, bypassing per-tenant MFA |
| Execution | T1059 | Command and Scripting Interpreter | ARTEX agentic AI framework automated cross-tenant authentication and persistence actions |
| Persistence | T1098.003 | Account Manipulation: Additional Cloud Credentials | Application credential modifications made in victim tenants persist as backdoors after initial app revocation |

---

## 3. Malware & Tools

| Tool | Type | Notes |
|------|------|-------|
| ARTEX | Agentic AI penetration-testing framework | Open-source (released July 2026); went closed-source October 2026 following reported misuse; used to automate cross-tenant OAuth credential abuse at scale |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Actor | Storm-0940 |
| Nation-State Nexus | China (Microsoft attribution) |
| Campaign | ConnectWise Cloud Backup Supply Chain Compromise |
| Target Sectors | MSPs, organizations using ConnectWise Cloud Backup / SkyKick product |
| Target Count | 2,250+ M365 tenant sign-in attempts; 327 accounts at 8 orgs directly sprayed |
| Related Actor | Overlaps with broader ConnectWise partner ecosystem targeting |

---

## 5. Splunk Detection Searches

### Detect Cross-Tenant OAuth Password Spray from Suspicious IPs

```spl
`o365`
  sourcetype="o365:management:activity" Operation="UserLoginFailed"
  ResultStatus="50126"
| stats dc(UserId) as unique_targets dc(OrganizationId) as unique_tenants
        min(_time) as firstTime max(_time) as lastTime count
  by ActorIpAddress UserAgent
| where unique_targets >= 10 OR unique_tenants >= 3
| eval risk_score=case(
    unique_tenants >= 5, 90,
    unique_targets >= 25, 80,
    unique_targets >= 10, 70,
    1=1, 60)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime ActorIpAddress UserAgent unique_targets unique_tenants count risk_score
```

**Detects:** High-volume cross-tenant password spraying from a single IP — matches Storm-0940's spray against 327 accounts across 8 tenants.

### Detect OAuth App Sign-In Anomalies (ARTEX-style Bulk Authentication)

```spl
`o365`
  sourcetype="o365:management:activity"
  Operation IN ("Add service principal.", "Update service principal.")
  OR (Operation="UserLoggedIn" AND ExtendedProperties{}.Name="RequestType"
      AND ExtendedProperties{}.Value="OAuth2:Authorize")
| eval app_id=mvindex('ModifiedProperties{}.NewValue', 0)
| stats dc(OrganizationId) as unique_tenants min(_time) as firstTime max(_time) as lastTime count
  by app_id ActorIpAddress
| where unique_tenants >= 3
| eval risk_score=case(unique_tenants >= 10, 95, unique_tenants >= 5, 85, 1=1, 75)
| where risk_score >= 75
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime app_id ActorIpAddress unique_tenants count risk_score
```

**Detects:** OAuth application identity used to authenticate across multiple tenants in a short window — characteristic of ARTEX-driven bulk access via compromised vendor OAuth credentials.

### Hunt for Known Storm-0940 Infrastructure

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("144.172.64.99", "144.172.64.128")
  by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest_ip dest_port app risk_score
```

**Detects:** Any network connection to known Storm-0940 infrastructure IPs.

---

## 6. Executive Summary

Microsoft MSTIC attributed the ConnectWise Cloud Backup OAuth supply chain compromise to Storm-0940, a China state-aligned threat actor, on October 21, 2026. The actor used the ARTEX agentic AI penetration-testing framework — released publicly in July 2026 — to automate the abuse of stolen ConnectWise OAuth application credentials at scale, achieving unauthenticated access to over 2,250 Microsoft 365 tenants. A parallel password-spray campaign targeted 327 accounts across 8 organizations from the infrastructure IP `144.172.64.99` between October 10–14, 2026.

The primary risk is persistence: application credential modifications made during the intrusion survive revocation of the compromised ConnectWise app identity, leaving potential backdoor access in affected tenants. Organizations should audit their Azure Entra ID app registrations and service principal credentials for unauthorized modifications, and hunt for sign-in events from the listed infrastructure IPs.

---

## References

- [Microsoft Security Blog: Storm-0940 Uses ARTEX in ConnectWise Supply Chain Compromise](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/)
- [BleepingComputer: ConnectWise Cloud Backup OAuth Supply Chain Attack (initial reporting)](https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/)
- [MITRE ATT&CK: T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK: T1550.001 - Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
- [MITRE ATT&CK: T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [MITRE ATT&CK: T1199 - Trusted Relationship](https://attack.mitre.org/techniques/T1199/)
- [SecurityWeek: China APT Uses AI Pentest Tool ARTEX in ConnectWise Attacks](https://www.securityweek.com/china-apt-uses-ai-pentest-tool-artex-in-connectwise-attacks/)
