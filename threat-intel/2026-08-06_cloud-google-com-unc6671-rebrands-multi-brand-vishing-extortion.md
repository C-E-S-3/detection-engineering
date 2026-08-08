---
scraped_at: "2026-08-08T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/unc6671-targets-financial-services-and-enterprise-cloud-environments"
report_type: threat-intel
severity: high
title: "UNC6671 Rebrands as REDACT/Pink/Helix/Falcon — Multi-Brand Vishing Extortion Targeting Financial Services and Enterprise Cloud"
---

# UNC6671 Rebrands as REDACT/Pink/Helix/Falcon — Multi-Brand Vishing Extortion Targeting Financial Services and Enterprise Cloud

## 1. IOCs

### Domains (Phishing / AiTM)

| Domain | Role | Notes |
|--------|------|-------|
| `passkeyhelpdesk[.]com` | AiTM lure | IT helpdesk passkey enrollment pretense |
| `createssopasskey[.]com` | AiTM lure | SSO passkey creation lure |
| `addssopasskey[.]com` | AiTM lure | SSO passkey addition lure |
| `oskeysync[.]com` | AiTM lure | OS key synchronization lure |
| `keysyncos[.]com` | AiTM lure | Key sync OS lure variant |
| `activatepasskey[.]com` | AiTM lure | Passkey activation lure |
| `enrollpasskey[.]com` | AiTM lure | Passkey enrollment lure |
| `myoktasso[.]com` | AiTM lure | Okta SSO impersonation |
| `setupssopasskey[.]com` | AiTM lure | SSO passkey setup lure |

> Note: Previously tracked domains from July 2026 (deploypasskey.com, passkeydeploy.com, assignpasskey.com, passkeyadd.com) continue in active use. Full IOC set of 65+ domains available via VirusTotal GTI Collection.

### IP Addresses (Infrastructure)

| IP | Role | ASN |
|----|------|-----|
| `31.7.56.61` | Panel AiTM reverse proxy | AS51852 Private Layer INC (Switzerland) |
| `31.7.56.52` | Panel AiTM reverse proxy | AS51852 Private Layer INC (Switzerland) |
| `193.34.212.132` | Phishing kit backend proxy | AS201814 MEVSPACE (Poland) |
| `23.234.75.84` | Automated SaaS data exfiltration | AS11878 Tzulo, Inc. (US) |
| `195.140.213.114` | Automated SaaS data exfiltration | AS25369 Hydra Communications (UK) |
| `195.140.213.115` | Automated SaaS data exfiltration | AS25369 Hydra Communications (UK) |
| `107.128.45.122` | M365/Okta residential proxy | AS7018 AT&T (US) |
| `76.103.148.180` | M365/Okta residential proxy | AS7922 Comcast (US) |

### Suspicious User-Agent Strings

- `python-requests/2.28.1`
- `WindowsPowerShell/5.1`
- `0811A9866E.com.okta.android.auth/8.18.0`
- `Google/Pixel_9_Pro_XL`

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566 | Phishing | Vishing calls to personal mobile numbers spoofing corporate helpdesk numbers |
| Credential Access | T1111 | Multi-Factor Authentication Interception | AiTM proxy intercepts credentials and MFA tokens at lookalike Entra/Okta portals |
| Credential Access | T1621 | Multi-Factor Authentication Request Generation | Forces MFA enrollment via IT mandate pretense |
| Defense Evasion | T1070.008 | Indicator Removal: Clear Mailbox Data | Systematically deletes password-reset confirmations, security alerts, and MFA modification notifications from victim mailboxes |
| Defense Evasion | T1090.002 | Proxy: External Proxy | Uses commercial VPN and residential proxy IPs (AT&T, Comcast, Charter ranges) for operations |
| Collection | T1530 | Data from Cloud Storage Object | Automated bulk SharePoint/OneDrive exfiltration via python-requests and WindowsPowerShell scripting |
| Exfiltration | T1567.004 | Exfiltration Over Web Service: Exfiltration to Code Repository | Uses scripted M365 APIs for bulk file access |

### Operational Tempo Escalation

| Period | Domain Registration Rate |
|--------|--------------------------|
| April–May 2026 | 1 domain per 2.2 days |
| June–July 2026 | 1 domain per 1.6 days (+33% acceleration) |
| July 20–22, 2026 | 7 domains in 72 hours (highest recorded burst) |

### Targeting Evolution

| Period | Primary Targets |
|--------|----------------|
| April–May 2026 | Manufacturing, healthcare, insurance (broad) |
| June 2026 | Technology, transportation, hospitality (IP/source code) |
| July 2026 | Financial services, legal, private equity (M&A and litigation data) |

---

## 3. Malware & Tools

No custom malware deployed. Attack relies on:
- Custom phishing/AiTM panels (credential and MFA token harvesting)
- Automated Python and PowerShell exfiltration scripts
- Commercial VPN and residential proxy services
- Scripted Okta and M365 SDK access

---

## 4. Threat Actor / Campaign Attribution

**UNC6671** (Google GTIG designation) — vishing-based extortion group that emerged under the **BlackFile** brand in early 2026. As of August 2026, the group operates simultaneously under four brands:

| Brand | Status | Focus |
|-------|--------|-------|
| **BlackFile** | Allegedly retired (May 2026) | Original brand; claimed compromised |
| **REDACT** | Active (announced June 27, 2026) | Official rebranding of BlackFile |
| **Pink** | Active | Distinct data leak site; shared infrastructure |
| **Helix** | Active | Overlapping root domains with Falcon |
| **Falcon** | Active (newest) | Operational since July 2026 |

**Financial Metrics (BlackFile Jan–May 2026):**
- 141.65 BTC (~$10.69M USD) tracked to 18 wallets
- Initial ransom demands: $1–3M USD
- Actual payments (53% of cases): ~$750K USD average
- Negotiated discounts: 50–75% off initial demand

**Overlapping infrastructure** links all four brands via shared registrar patterns (TUCOWS, NICENIC), shared reverse proxy ASNs (AS51852), and root domain relationships.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.http_user_agent IN ("python-requests*", "WindowsPowerShell*", "0811A9866E.com.okta.android.auth*")
  AND Web.url IN ("*/SharePoint/*", "*/OneDrive/*", "*/api/v2.0/*")
  by Web.src Web.dest Web.http_user_agent Web.user Web.url
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(http_user_agent,"python-requests"), 80,
    match(http_user_agent,"WindowsPowerShell"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest user http_user_agent url risk_score
```

> Detects scripting-language user agents making bulk requests to M365 SharePoint/OneDrive APIs — characteristic of UNC6671 automated SaaS exfiltration phase post-AiTM credential theft.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.action=success
  AND Authentication.src IN ("31.7.56.61","31.7.56.52","193.34.212.132","23.234.75.84","195.140.213.114","195.140.213.115")
  by Authentication.src Authentication.dest Authentication.user Authentication.app
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest user app risk_score
```

> Detects successful authentications from known UNC6671 AiTM proxy infrastructure. High-fidelity indicator of active session hijacking.

```spl
index=o365 Workload=Exchange Operation IN ("HardDelete","MoveToDeletedItems","SoftDelete")
  ClientInfoString="*Script*" OR ClientInfoString="*Python*" OR ClientAppName="Outlook REST API"
| where match(AffectedItems{}.Subject,"(?i)(security|passkey|mfa|password reset|account|sign.in)")
| stats count min(_time) as firstTime max(_time) as lastTime values(AffectedItems{}.Subject) as subjects by UserId ClientIPAddress ClientInfoString
| where count >= 5
| `o365`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime UserId ClientIPAddress subjects count risk_score
```

> Detects bulk deletion of security-related emails (password reset confirmations, MFA alerts) via scripting clients — indicator of UNC6671 defensive counter-forensics after AiTM compromise.

---

## 6. Executive Summary

**Severity: HIGH**

On August 6, 2026, Google Threat Intelligence Group (GTIG) published an updated profile of **UNC6671**, a financially motivated vishing and data-theft extortion group that has expanded from its original **BlackFile** brand into at least four active brands: **REDACT**, **Pink**, **Helix**, and **Falcon**. The group's operational tempo has increased by 33% since May 2026, with domain registrations now averaging one new phishing domain every 1.6 days.

**Attack chain:** Callers contact employees on personal mobile phones, spoofing the corporate IT helpdesk number. Victims are directed to passkey-themed AiTM phishing portals (e.g., `[company].createssopasskey[.]com`) where credentials and MFA tokens are captured in real time. Post-authentication, the group deploys automated Python/PowerShell scripts to bulk-exfiltrate SharePoint and Okta data using residential proxy IPs. Critically, they then delete security notification emails from victim mailboxes to hinder detection and incident response.

**Industry shift:** The group has pivoted from broad targeting to laser-focus on **financial services, legal, and private equity firms** where M&A, litigation, and deal documents command premium ransom value.

**New infrastructure**: This report adds 9 phishing domains and 8 new IP addresses to tracking, including dedicated AiTM proxy nodes in Switzerland (AS51852) and automated exfiltration servers in the US and UK.

**Defensive priority:** Enforce FIDO2 hardware security keys as the only accepted MFA factor, implement conditional access policies rejecting residential proxy ASNs, and monitor Exchange audit logs for bulk deletion of security-related emails.

---

## References

- [GTIG — UNC6671 Targets Financial Services and Enterprise Cloud (Aug 6 2026)](https://cloud.google.com/blog/topics/threat-intelligence/unc6671-targets-financial-services-and-enterprise-cloud-environments)
- [GTIG — BlackFile Vishing Extortion Operation (May 17 2026)](https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation)
- [BleepingComputer — Pink (UNC6671 rebrand) AiTM phishing (Jul 9 2026)](https://www.bleepingcomputer.com/news/security/pink-unc6671-rebrand-microsoft-365-passkey-aitm-phishing/)
- [MITRE ATT&CK T1621 — MFA Request Generation](https://attack.mitre.org/techniques/T1621/)
- [MITRE ATT&CK T1070.008 — Clear Mailbox Data](https://attack.mitre.org/techniques/T1070/008/)
