---
scraped_at: 2026-08-05T06:00:00Z
source_url: https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-threat-hunting-report/
report_type: threat-intel
severity: high
title: "CrowdStrike 2026 Threat Hunting Report: STARDUST CHOLLIMA npm Supply Chain, Device Code Phishing Surge, Sub-5-Minute E-Crime Breakout"
---

# CrowdStrike 2026 Threat Hunting Report — Key Intelligence Highlights

**Source:** CrowdStrike  
**Published:** 2026-08-03  
**Severity:** High  

## Summary

CrowdStrike released its annual Threat Hunting Report on 2026-08-03, covering intelligence from threat-hunting operations in 1H 2026. The report documents three major trends with significant detection engineering implications: (1) DPRK-nexus actor **STARDUST CHOLLIMA** compromised the **Mastra AI** developer framework via a malicious npm package that reached 131 downstream AI applications; (2) device code phishing attacks increased **15× in 1H 2026** as adversaries pivot away from credential-phishing sites blocked by MFA; and (3) financially motivated actors (**SNARKY SPIDER** and similar groups) are compressing initial-access-to-data-theft timelines to **under 5 minutes**.

No specific hashes, domains, or IP indicators were disclosed in the publicly available report content. The intelligence value is in the durable TTPs and detection logic they imply.

## Key Findings

### STARDUST CHOLLIMA — DPRK npm Supply Chain Attack on Mastra AI

**STARDUST CHOLLIMA** (CrowdStrike's name for a DPRK-nexus threat group with software supply chain and IT worker infiltration focus) injected a malicious npm package into the **Mastra AI** open-source agent framework, reaching **131 dependent AI applications** downstream. The report notes this incident is representative of a broader trend: **87% of all software registry threats in 1H 2026** involved npm packages, an increase CrowdStrike attributes to DPRK-affiliated actors' systematic targeting of AI developer toolchains.

**Mastra AI** is an open-source TypeScript framework for building AI agents; its compromise illustrates the attack surface created by AI-framework supply chains, where a single dependency injection can affect hundreds of production agent deployments.

This campaign overlaps in technique with previously tracked DPRK supply chain operations (Glassworm sinkholed May 2026; ViteVenom DEV#POPPER Tailwind npm campaign July 2026).

### Device Code Phishing — 15× Increase in 1H 2026

Adversaries are abusing the **OAuth device code flow** to bypass MFA: victims are directed to `microsoft.com/devicelogin` (or equivalent legitimate endpoints) and asked to enter an attacker-controlled code. Because authentication is completed on a legitimate Microsoft page, MFA prompts are satisfied by the victim themselves. Resulting access tokens can be replayed for long-lived access to M365, Teams, SharePoint, and other OAuth-integrated services.

CrowdStrike reports a **15× year-over-year increase** in observed device code phishing in 1H 2026. Detection opportunity: monitor for `user_code` parameters in browser history or proxy logs, or use Microsoft Entra ID sign-in logs filtered for `grant_type=device_code` authentications from unexpected geolocations or user agents.

### SNARKY SPIDER — Sub-5-Minute Initial-Access-to-Data-Theft

**SNARKY SPIDER** (a financially motivated cybercrime group tracked by CrowdStrike) has been observed compressing the attack timeline from initial account takeover to active data exfiltration to **under 5 minutes**. The group leverages:
- Purchased or stolen session tokens eliminating authentication dwell time
- Pre-built automation for rapid data enumeration and staged exfiltration
- Cloud storage services (SharePoint, OneDrive, Google Drive) for in-environment data staging before exfil

This sub-5-minute breakout time challenges detection strategies that rely on analyst-reviewed alerts with normal SOC response windows.

## MITRE ATT&CK TTPs

| Technique | ID | Actor / Context |
|-----------|----|-----------------|
| Supply Chain Compromise: Compromise Software Dependencies | T1195.001 | STARDUST CHOLLIMA — malicious npm package in Mastra AI framework |
| User Execution: Malicious File | T1204.002 | Downstream developers install compromised Mastra AI dependency |
| Phishing: Spearphishing Link (Device Code) | T1566.002 | Device code phishing — OAuth token theft bypassing MFA |
| Steal Application Access Token | T1528 | Device code phishing — OAuth `device_code` grant yields long-lived token |
| Exfiltration Over Web Service | T1567.002 | SNARKY SPIDER — data staged to OneDrive/SharePoint/Google Drive pre-exfil |
| Valid Accounts: Cloud Accounts | T1078.004 | Session token replay for sustained M365/cloud access |

## Detection Opportunities

### 1. Device Code Phishing — OAuth Sign-In Monitoring

Monitor Microsoft Entra ID / Azure AD sign-in logs for `grant_type=urn:ietf:params:oauth:grant-type:device_code` authentications, especially from:
- IP addresses outside expected user geolocation
- User agents consistent with headless token-replay tooling (Python, curl, PowerShell)
- First-seen devices

```spl
index=o365 sourcetype=o365:management:activity Operation="UserLoggedIn"
    AuthenticationDetails{}.RequestType="device_code"
| eval risk = if(like(lower(UserAgent), "%python%") OR like(lower(UserAgent), "%curl%") OR like(lower(UserAgent), "%powershell%"), "high", "medium")
| stats count min(_time) as firstTime max(_time) as lastTime values(ClientIP) as src_ips
    values(UserAgent) as user_agents by UserId risk
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where risk="high" OR count > 3
| table firstTime lastTime UserId src_ips user_agents risk count
```

### 2. STARDUST CHOLLIMA / AI Framework Supply Chain — postinstall Network Activity

Monitor for npm/node processes making network connections immediately after package installation:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.app IN ("node", "npm", "npx") AND All_Traffic.dest_port IN (443, 80)
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| lookup threat_intel_lookup dest as dest OUTPUT threat_category confidence
| where isnotnull(threat_category)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest dest_port app user threat_category confidence
```

## Kill Chain

- **Delivery** — Malicious npm package published to public registry; device code phishing links distributed via email/messaging
- **Exploitation** — Developer installs compromised AI framework dependency; user completes OAuth device code flow on legitimate Microsoft page
- **Actions on Objectives** — Malicious code executes in 131+ AI frameworks; session token replayed for data exfiltration in under 5 minutes

## Threat Actor Profiles

| Actor | Type | Campaign | Reference |
|-------|------|----------|-----------|
| STARDUST CHOLLIMA | Nation-State (DPRK) | Malicious npm → Mastra AI framework supply chain (131 downstream apps affected); 87% of H1 2026 software registry threats = npm | [CrowdStrike 2026 Threat Hunting Report](https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-threat-hunting-report/) |
| SNARKY SPIDER | Financially Motivated Cybercrime | Account takeover to data theft in <5 minutes; cloud storage staging | [CrowdStrike 2026 Threat Hunting Report](https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-threat-hunting-report/) |

## References

- [CrowdStrike — 2026 Threat Hunting Report (2026-08-03)](https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-threat-hunting-report/)
- [MITRE ATT&CK — T1195.001: Supply Chain Compromise: Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK — T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK — G0032: Lazarus Group (overlapping DPRK supply chain TTPs)](https://attack.mitre.org/groups/G0032/)
