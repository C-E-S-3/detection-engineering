---
scraped_at: 2026-11-24T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/com-affiliate-vishing-attacks/
report_type: threat-intel
severity: high
title: "Bling Libra (ShinyHunters) Com Affiliate Vishing: New Clusters Vortex (CL-CRI-1264) and Cinder (CL-CRI-1274) Target Healthcare, Finance, and Legal Sectors"
---

# Bling Libra Com Affiliate Vishing: New Clusters Target Cloud Data and Extortion

Unit 42 published "Dialing for Data: Inside the Com's High-Profile Heists" on November 20, 2026, documenting an expanded campaign by Bling Libra (ShinyHunters) and Com-affiliated actors. The report introduces two new activity clusters — Vortex (CL-CRI-1264) and Cinder (CL-CRI-1274) — and describes an evolved attack chain combining vishing, adversary-in-the-middle (AiTM) credential capture, and scripted bulk M365 data exfiltration targeting healthcare, financial services, and legal firms in the US, UK, and Australia.

---

## 1. IOCs

### User-Agent Strings (Post-Compromise Automation Indicator)

| Indicator | Type | Context |
|-----------|------|---------|
| `python-httpx` | HTTP User-Agent | Identified in Microsoft Entra ID and M365 Unified Audit Log sign-in and resource-access events; indicates attacker-side Python automation scripts (using the `httpx` async HTTP library) replaying captured session tokens or performing bulk M365 data enumeration and collection post-compromise |

### File Hashes

None published for this campaign in public sources.

### Domains / IPs

No specific C2 domains or operator IPs confirmed from public sources. Attackers route activity through:
- Residential proxy networks (observed in Entra ID sign-in logs as ISP-variety IP blocks)
- Commercial VPN services
- Tor-hosted extortion/negotiation sites (victim-specific URLs sent via Microsoft Teams or email)

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1598.004 | Phishing for Information: Spearphishing Voice | Vishing calls impersonate IT helpdesk or vendor support; victim directed to attacker-controlled tailored credential-capture portal themed as SSO enrollment or MFA re-registration |
| Credential Access | T1557 | Adversary-in-the-Middle | Real-time reverse-proxy (AiTM) captures credentials and live MFA session cookies/tokens during victim's browser interaction with the fake portal |
| Credential Access | T1621 | Multi-Factor Authentication Request Generation | Push notification fatigue used in some variants to coerce MFA approval |
| Persistence | T1098.005 | Account Manipulation: Device Registration | After AiTM token capture, attacker immediately enrolls an attacker-controlled authenticator (phone/app) on the victim's Entra ID, Okta, or Duo account — persistent access survives password resets |
| Collection | T1119 | Automated Collection | Python-httpx–based automation scripts perform bulk scripted collection from Exchange Online (mail), SharePoint Online, and OneDrive for Business — `python-httpx` user-agent appears in M365 Unified Audit Log |
| Collection | T1530 | Data from Cloud Storage | Exfiltration of business-sensitive data from M365 Exchange Online, SharePoint, and OneDrive via scripted download |
| Command and Control | T1090.003 | Proxy: Multi-hop Proxy | Residential proxy networks and commercial VPN services mask attacker source IPs in Entra ID sign-in logs and M365 audit events |
| Impact | T1657 | Financial Theft / Extortion | Extortion via internal Teams messages or email directing victim organizations to Tor-hosted negotiation sites; threat to publish exfiltrated data publicly |

### Cinder (CL-CRI-1274) — Distinct TTP

Cinder replays **persistent session tokens** through proxy infrastructure to bypass subsequent Duo MFA prompts — the attacker avoids requesting new MFA approvals by reusing the initial captured session, reducing detectable MFA-push noise after the initial vishing call.

---

## 3. Malware & Tools

| Tool / Artifact | Type | Description |
|----------------|------|-------------|
| AiTM Phishing Kit | Phishing Infrastructure | Custom reverse-proxy portal per victim organization; themed as "SSO enrollment" or "MFA re-registration"; captures credentials and live MFA session cookies in real time |
| Python-httpx Automation | Post-Compromise Script | Python scripts using the `httpx` async HTTP client library to authenticate to M365 Graph API or legacy endpoints and perform bulk mail/file collection; operator-side tooling not publicly available |

---

## 4. Threat Actor / Campaign Attribution

**Bling Libra** (also tracked as ShinyHunters, UNC6240) is a financially motivated threat actor and extortion group operating since at least 2020 with a history of large-scale cloud data theft.

Unit 42 introduced two new clusters within the broader Com ecosystem in this November 2026 report:

| Cluster | Unit 42 ID | First Observed | Distinguishing TTP |
|---------|-----------|---------------|-------------------|
| Vortex | CL-CRI-1264 | November 2026 (newly designated) | Vishing + AiTM credential capture; standard Com TTPs |
| Cinder | CL-CRI-1274 | November 2026 (newly designated) | Persistent session token replay through proxy to bypass Duo MFA re-challenges — avoids new MFA push requests after initial credential capture |

Previously tracked related clusters: Redact, Pink, Falcon, Helix.

**Targeting:**
- **Sectors:** Healthcare, Financial Services, Legal Services
- **Geographies:** United States, United Kingdom, Australia
- **Verticals at risk:** Organizations using Microsoft 365 with Duo MFA, with IT helpdesk processes that allow users to self-service MFA device enrollment

**Attribution confidence:** High for Bling Libra / Com affiliation (Unit 42 primary source). Actor nationality/state affiliation not asserted.

---

## 5. Splunk Detection Searches

### Search 1 — Entra ID Sign-In with `python-httpx` User-Agent (Primary IoA)

Detects successful M365/Entra ID authentications where the client user-agent matches the `python-httpx` library. This user-agent has no legitimate business justification in enterprise Entra ID sign-in logs and indicates attacker-side automation scripts replaying captured tokens.

```spl
`o365` Workload="AzureActiveDirectory" Operation="UserLoggedIn"
| rex field=_raw "\"Name\":\"UserAgent\",\"Value\":\"(?P<user_agent>[^\"]+)\""
| where match(user_agent, "(?i)python-httpx")
| stats count min(_time) as firstTime max(_time) as lastTime
        values(user_agent) as user_agents values(ClientIP) as src_ips
        by UserId UserDisplayName ResultStatus
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    ResultStatus="Succeeded", 90,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime UserId UserDisplayName src_ips user_agents ResultStatus count risk_score
```

### Search 2 — Bulk M365 Cloud Data Access via Non-Browser Python Client

Detects high-volume scripted access to SharePoint, OneDrive, or Exchange content via Python HTTP libraries — the bulk collection phase of the Com exfiltration chain. Thresholds may need tuning per environment.

```spl
`o365` Workload IN ("SharePoint", "OneDrive", "Exchange")
    (Operation="FileAccessed" OR Operation="MailItemsAccessed" OR
     Operation="SearchQueryInitiatedSharePoint" OR Operation="ListItems")
| rex field=_raw "\"Name\":\"UserAgent\",\"Value\":\"(?P<user_agent>[^\"]+)\""
| where match(user_agent, "(?i)python-httpx|python-requests|requests/[0-9]")
| bucket _time span=5m
| stats count as access_count
        min(_time) as firstTime max(_time) as lastTime
        values(user_agent) as user_agents values(ClientIP) as src_ips
        values(Operation) as operations dc(FileName) as unique_files
        by UserId _time
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    access_count >= 100, 95,
    access_count >= 25, 85,
    access_count >= 5, 70)
| where risk_score >= 70
| table firstTime lastTime UserId src_ips user_agents operations access_count unique_files risk_score
```

### Search 3 — MFA Device Registration at Non-Corporate IP Following Authentication Challenge

Cross-environment correlation: MFA device enrollment events from residential proxy or VPN IP ranges, especially when preceded by an authentication challenge in the same session window. Correlates with Cinder and Vortex TTPs.

```spl
`o365` Operation IN ("Add method for MFA", "Register security info",
    "Update user.", "MFA enrollment") OR
(`okta` eventType="system.multifactor.factor.setup" outcome.result="SUCCESS")
| eval user=coalesce(UserId, 'actor.login'),
       src_ip=coalesce(ClientIP, 'client.ipAddress')
| stats count min(_time) as firstTime max(_time) as lastTime
        values(src_ip) as src_ips values(Operation) as operations
        by user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(count >= 2, 90, count=1, 75)
| where risk_score >= 75
| table firstTime lastTime user src_ips operations count risk_score
```

---

## 6. Executive Summary

Unit 42's November 20, 2026 "Dialing for Data" report reveals an expansion of the Com-affiliate vishing ecosystem, with two newly designated clusters — Vortex (CL-CRI-1264) and Cinder (CL-CRI-1274) — joining the established Bling Libra / ShinyHunters network. These actors use voice phishing to impersonate IT support, capture Microsoft 365 credentials and MFA tokens in real time via AiTM proxies, enroll attacker-controlled MFA devices for persistent access, and then automate bulk data collection from Exchange, SharePoint, and OneDrive using Python-based scripting tools. The `python-httpx` user-agent string appearing in Entra ID sign-in and M365 Unified Audit Logs is a high-fidelity indicator of attacker-side automation specific to this campaign.

Cinder's distinguishing technique of replaying persistent session tokens through proxy infrastructure allows the actor to bypass subsequent Duo MFA challenges without triggering new push notifications — reducing the alert noise that might otherwise warn the victim. Organizations in healthcare, finance, and legal sectors are priority targets.

**Immediate recommended actions:**
1. Search Entra ID sign-in logs and M365 Unified Audit Log for `python-httpx` user-agent strings
2. Alert on MFA device registration events from non-corporate IP ranges
3. Implement session-binding controls (Conditional Access: require compliant device or IP restriction) to limit token replay
4. Enable phishing-resistant MFA (FIDO2/passkeys) and restrict self-service MFA enrollment to IT-managed processes
5. Monitor for unusual bulk SharePoint/OneDrive/Exchange access volume per user in short windows

**Severity:** High — durable, actor-independent technique; active targeting of high-value sectors
