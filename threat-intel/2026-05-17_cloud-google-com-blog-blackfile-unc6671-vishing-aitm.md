---
scraped_at: 2026-05-17T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation
report_type: threat-intel
severity: high
title: "Welcome to BlackFile: Inside a Vishing Extortion Operation (UNC6671)"
---

# Welcome to BlackFile: Inside a Vishing Extortion Operation (UNC6671)

Google Threat Intelligence Group (GTIG) published a comprehensive analysis of **UNC6671**, a financially motivated threat actor that operated under the brand name **BlackFile** from February through May 2026. UNC6671 targeted dozens of organizations across North America, Australia, and the UK using vishing (voice phishing) calls combined with real-time Adversary-in-the-Middle (AiTM) credential harvesting to bypass MFA, then conducted bulk cloud data exfiltration followed by extortion demands. The group announced a shutdown "under this name" on May 11, 2026, assessed as a likely rebranding rather than permanent cessation.

---

## 1. IOCs

### Domains — Credential Harvesting Infrastructure (Registrar: Tucows)

UNC6671 uses a subdomain-based model where the victim organization name is prepended to a shared base domain (e.g., `<victim-org>.enrollms[.]com`). The root domains below are the blockable indicators.

| Indicator | Type | Context |
|-----------|------|---------|
| `enrollms[.]com` | Domain | Base domain for SSO enrollment–themed AiTM credential harvesting portals |
| `passkeyms[.]com` | Domain | Base domain for passkey migration–themed AiTM portals |
| `setupsso[.]com` | Domain | Base domain for SSO setup–themed AiTM portals |

### IP Addresses

| Indicator | Context |
|-----------|---------|
| `179.43.185.226` | Observed exfiltration source IP in M365 UAL audit logs; `python-requests/2.28.1` user agent; commercial VPN exit node |

### No file hashes published in this report.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | UNC6671 Usage |
|--------|-------------|----------------|---------------|
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Vishing call directs victim to lookalike SSO portal hosted under `<org>.<base-domain>` |
| Credential Access | T1111 | Multi-Factor Authentication Interception | Attacker intercepts MFA code in real time during vishing call; submits to legitimate IdP within seconds |
| Credential Access | T1556 | Modify Authentication Process | Registers new attacker-controlled MFA device/authenticator immediately after authentication succeeds |
| Credential Access | T1557.002 | Adversary-in-the-Middle: AiTM | Lookalike portal acts as transparent proxy; captures session cookies alongside credentials |
| Discovery | T1087 | Account Discovery | Queries Entra/Azure AD for corporate directory (employee names, mobile numbers, job titles, hierarchy) |
| Discovery | T1526 | Cloud Service Discovery | Enumerates SaaS applications (SharePoint, OneDrive, Salesforce, Zendesk, ServiceNow) |
| Discovery | T1580 | Cloud Infrastructure Discovery | Scans ServiceNow for IT infrastructure records (computers, servers, cloud resources) |
| Collection | T1530 | Data from Cloud Storage | Bulk exfiltration from SharePoint and OneDrive via Microsoft Graph API and direct streaming |
| Collection | T1213.002 | Data from Information Repositories: SharePoint | Programmatic document downloads using `python-requests` and `WindowsPowerShell` with stolen FedAuth cookies |
| Exfiltration | T1567.002 | Exfiltration Over Web Service | Data streamed to attacker infrastructure using `FileAccessed` events (evasion from `FileDownloaded` DLP rules) |
| Exfiltration | T1537 | Transfer Data to Cloud Account | Exfiltrated to attacker-controlled external storage via Microsoft Graph |
| Impact | T1657 | Financial Theft / Extortion | Ransom demands in low-to-mid six figures; threats of public data release; swatting escalation |

### Key Evasion Behaviors

- **FileAccessed vs. FileDownloaded:** Attacker pivoted to `FileAccessed` events (treated as benign) instead of `FileDownloaded`, bypassing many DLP and SIEM rules.
- **User-Agent spoofing:** `ClientAppId` spoofed as `d3590ed6-52b3-4102-aeff-aad2292ab01c` (Microsoft Office App ID), but actual `UserAgent` header reveals `python-requests/2.28.1` or `WindowsPowerShell/5.1`.
- **Token timing artifact:** `TokenIssuedAtTime: "1601-01-01T00:00:00"` (Unix epoch default) in M365 audit logs is a reliable indicator of stolen session cookie reuse.
- **IsManagedDevice: false:** All sessions from attacker infrastructure consistently report as non-corporate-managed devices.

---

## 3. Malware & Tools

No custom malware used. UNC6671 relies exclusively on:
- **Scripting tools:** Python (`python-requests`), PowerShell
- **Microsoft Graph API:** Bulk document enumeration and download
- **AiTM framework:** Custom phishing kit using subdomain infrastructure
- **Commercial VPN services:** Continuous IP rotation to evade geographic blocking
- **Communication:** Tox (early), Session (February 2026+), hijacked corporate email accounts (March 2026+)

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Cluster | UNC6671 |
| Brand | "BlackFile" (February–May 2026) |
| Motivation | Financial extortion (no ransomware encryption) |
| Targeting | North America, Australia, UK; enterprises with M365/Okta, extensive SaaS footprint |
| Sectors | Retail, hospitality, finance (inferred from targets' SaaS stacks) |
| Distinction | Not affiliated with ShinyHunters/UNC6240, despite briefly co-opting their brand |
| Status | Announced shutdown May 11, 2026 ("under this name") — assessed as rebranding |
| Data Leak Site | Launched Feb 6, 2026; closed late April; briefly reopened May 11; inaccessible at time of publication |

---

## 5. Splunk Detection Searches

### Search 1 — Okta: MFA Device Registration from Suspicious Source

Detects MFA factor setup events on Okta following authentication from a non-standard IP. The critical window is any MFA device registration that occurs within minutes of an Okta authentication challenge — a strong AiTM indicator.

```spl
`okta` eventType="system.multifactor.factor.setup" outcome.result="SUCCESS"
| rename actor.login as user, client.ipAddress as src_ip, target{0}.displayName as enrolled_factor, client.geographicalContext.country as country
| eval firstTime=_time, lastTime=_time
| stats count as setup_count
    min(_time) as firstTime
    max(_time) as lastTime
    values(src_ip) as src_ips
    values(country) as countries
    values(enrolled_factor) as enrolled_factors
    by user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    setup_count >= 3, 90,
    setup_count >= 1, 75)
| where risk_score >= 75
| table firstTime lastTime user src_ips countries setup_count enrolled_factors risk_score
```

### Search 2 — M365: SharePoint Bulk File Access via Scripting User Agent

Detects high-volume SharePoint file access using Python, PowerShell, or other scripting engines from non-managed devices. UNC6671 pivoted from `FileDownloaded` to `FileAccessed` to evade DLP; this search covers both.

```spl
`o365` Workload="SharePoint"
    (Operation="FileAccessed" OR Operation="FileDownloaded")
    (UserAgent="python-requests*" OR UserAgent="WindowsPowerShell*" OR UserAgent="curl/*" OR UserAgent="Go-http-client/*")
| rename UserId as user, ClientIP as src_ip, SourceFileName as file_name, SiteUrl as site_url
| eval is_unmanaged=if(IsManagedDevice="false", 1, 0)
| stats count as file_access_count
    min(_time) as firstTime
    max(_time) as lastTime
    values(src_ip) as src_ips
    values(UserAgent) as user_agents
    values(Operation) as operations
    dc(SourceFileName) as unique_files
    by user site_url
| where file_access_count >= 100
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    file_access_count >= 10000, 95,
    file_access_count >= 1000, 85,
    file_access_count >= 100, 65)
| where risk_score >= 65
| table firstTime lastTime user src_ips user_agents file_access_count unique_files operations site_url risk_score
```

### Search 3 — M365: User-Agent / App ID Mismatch (Session Token Abuse)

Detects M365 audit events where `ClientAppId` identifies Microsoft Office but the `UserAgent` reveals a scripting engine — the exact pattern observed in UNC6671 exfiltration. The `TokenIssuedAtTime` epoch artifact is also searched.

```spl
`o365` Workload="SharePoint"
    (Operation="FileAccessed" OR Operation="FileDownloaded")
    ClientAppId="d3590ed6-52b3-4102-aeff-aad2292ab01c"
    (UserAgent="python-requests*" OR UserAgent="WindowsPowerShell*" OR UserAgent="curl/*")
| rename UserId as user, ClientIP as src_ip, SourceFileName as file_name
| stats count as access_count
    min(_time) as firstTime
    max(_time) as lastTime
    values(src_ip) as src_ips
    values(UserAgent) as user_agents
    values(file_name) as files_accessed
    by user ClientAppId
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime user src_ips user_agents access_count files_accessed ClientAppId risk_score
```

---

## 6. Executive Summary

UNC6671 (BlackFile) represents a financially motivated cloud-native extortion operation requiring no malware or vulnerability exploitation. The attack chain relies entirely on social engineering (vishing) to induce victims to hand over credentials and MFA codes, after which the actor uses legitimate APIs and scripting tools to exfiltrate terabytes of data.

Key defensive priorities:
1. **Deploy phishing-resistant MFA** (FIDO2/WebAuthn passkeys) — SMS, push notification, and TOTP MFA are all vulnerable to this attack chain.
2. **Alert on MFA device registration events** — any new authenticator registration should be treated as critical and correlated with prior authentication events.
3. **Elevate `FileAccessed` to the same severity as `FileDownloaded`** in SIEM rules — UNC6671 specifically exploited the common misconfiguration of treating `FileAccessed` as benign.
4. **Alert on scripting user agents in cloud storage audit logs** — `python-requests` and `WindowsPowerShell` accessing SharePoint at scale are near-certain indicators of programmatic exfiltration.
5. **Monitor Tucows-registered domains matching enrollment/passkey/SSO themes** — the subdomain-based model makes individual IOC blocking insufficient; alert on pattern-matched domains from this registrar.

The group's stated shutdown is assessed as a rebranding; organizations should expect reemergence under a new brand name with the same or similar TTPs.
