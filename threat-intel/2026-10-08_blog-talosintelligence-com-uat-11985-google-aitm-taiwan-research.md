---
scraped_at: "2026-10-10T00:00:00Z"
source_url: "https://blog.talosintelligence.com/uat-11985/"
report_type: threat-intel
severity: high
title: "UAT-11985: AI-Assisted Event Lures Delivering Real-Time Google AiTM Phishing Against Taiwan Research Organizations"
---

## 1. Indicators of Compromise (IOCs)

### File Hashes

No file hashes publicly available at time of report.

### Domains and URLs

No phishing infrastructure domains were published in available public reporting. The phishing kit was identified through behavioral signatures rather than static infrastructure.

### IP Addresses

No C2 or infrastructure IPs published in available public reporting.

### Network Signatures

| Indicator | Type | Description |
|-----------|------|-------------|
| `Html.Phishing.UAT11985-10060614-0` | ClamAV Signature | ClamAV signature covering phishing pages deployed in this campaign |
| `1:67198` | Snort SID | Snort/Talos rule detecting UAT-11985 phishing kit network activity |
| `7:31` | Snort SID | Supplemental Snort/Talos detection rule for UAT-11985 |

### Behavioral Indicator

The phishing kit contains a unique **mushroom emoji (🍄)** embedded as a signature string in the JavaScript source. This artifact has been observed in over 75 deployments and is assessable as a campaign fingerprint.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Usage |
|--------|-----------|----|-------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Targeted emails containing QR codes directing victims to adversary-controlled phishing pages |
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Event poster PDFs/images with QR codes altered to redirect to phishing pages |
| Credential Access | Adversary-in-the-Middle | T1557 | Real-time WebSocket relay proxies victim credentials and session cookies to threat actor as victim authenticates to Google |
| Collection | Browser Session Hijacking | T1185 | Google session cookies captured via AiTM relay enable post-authentication session takeover without requiring MFA bypass |
| Defense Evasion | Masquerading | T1036 | Event invitations impersonate legitimate institutional communications from Taiwan EU Center, NCCU IIR, and Taiwan Research Institute |
| Defense Evasion | Hide Artifacts | T1564 | Phishing pages clone legitimate event posters; QR code alteration is the only visible artifact |
| Resource Development | Establish Accounts | T1585 | Operator panel assessed to have been developed in Simplified Chinese; infrastructure appears newly registered per deployment |
| Execution | User Execution: Malicious Link | T1204.001 | Victim must scan altered QR code and visit phishing page to trigger credential capture |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| **UAT-11985 Phishing Kit** | AiTM Phishing Framework | Custom kit using WebSocket for real-time credential/session relay; HTTP POST for data exfiltration; mushroom emoji signature in JS source |
| **QR Code Generator** (attacker-modified) | Tool | Attackers scrape legitimate event posters and replace embedded QR codes with adversary-controlled destinations |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Designation | UAT-11985 (Cisco Talos unattributed cluster) |
| Suspected Nexus | China (moderate confidence); operator panel developed in Simplified Chinese |
| Named Attribution | No definitive group attribution by Talos at time of report |
| Targeting | Academia and policy research organizations in Taiwan; Taiwan EU Center, NCCU Institute of International Relations, Taiwan Research Institute impersonated as lure sources |
| Campaign Dates | Mid-2026 through at least October 2026 |
| Observed Scale | 75+ phishing kit deployments identified with shared mushroom emoji signature |
| AI Assessment | Email lures show evidence consistent with AI-assisted content generation from a reusable prompt template; Talos assesses with moderate-low confidence that LLM tooling was used |
| Motivation | Likely espionage; academic and policy research personnel targeted aligns with intelligence collection objectives |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.http_method="POST"
    Web.url="*/accounts.google.com/*" OR Web.url="*/myaccount.google.com/*"
    Web.src!="accounts.google.com"
  by Web.src Web.dest Web.url Web.http_user_agent Web.user
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime src dest url http_user_agent user risk_score
```
*Detects HTTP POST requests proxied through non-Google infrastructure to Google Account URLs — core AiTM relay pattern.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.app="websocket" OR All_Traffic.dest_port IN (80,443)
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| lookup threat_intel_domains domain as dest OUTPUT threat_type
| where isnotnull(threat_type) AND threat_type="AiTM"
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_port app user threat_type risk_score
```
*Correlates WebSocket/HTTPS connections against AiTM phishing domains in threat intel lookup.*

```spl
index=email sourcetype=email_headers
subject="*invitation*" OR subject="*seminar*" OR subject="*conference*" OR subject="*workshop*"
has_attachment=true attachment_type IN ("png","jpg","pdf")
| eval lure_score=case(
    match(subject,"(?i)(taiwan|research|policy|academia|institute)"), 20,
    match(from_domain,"(?i)(gmail|hotmail|yahoo|proton)"), 30,
    match(body,"(?i)(scan.*qr|qr.*code|register.*below)"), 25,
    true(), 0)
| where lure_score >= 30
| eval risk_score=50+lure_score
| table _time src_user subject from_domain attachment_type lure_score risk_score
```
*Heuristic detection for QR-code quishing lures using event-themed subject lines with image attachments sent from webmail providers.*

---

## 6. Executive Summary

Cisco Talos published research on October 8, 2026, documenting **UAT-11985**, a previously untracked threat cluster conducting targeted phishing against Taiwan's academic and policy research community. The campaign uses AI-assisted generation of convincing event invitation emails impersonating three prominent Taiwanese institutions: the Taiwan European Union Center, NCCU Institute of International Relations, and the Taiwan Research Institute.

The core technique is **QR code quishing (quishing)**: attackers scrape legitimate event posters from institutional websites, replace the embedded QR codes with adversary-controlled URLs, and attach the modified images to phishing emails. Victims who scan the codes are directed to a custom **Adversary-in-the-Middle (AiTM)** phishing kit that relays Google authentication sessions in real time via WebSocket, capturing credentials and session cookies even when MFA is enabled.

The operator panel for the phishing kit is assessed with moderate confidence to have been developed in Simplified Chinese. A unique mushroom emoji embedded in the kit's JavaScript source has been observed in over 75 deployments, suggesting a shared kit distributed across the campaign or a single operator running repeated iterations.

No concrete infrastructure IOCs (domains, IPs, file hashes) have been published in available public reporting. Detection should focus on behavioral indicators: AiTM traffic patterns, WebSocket relay to Google Account URLs, and QR code email attachment lure signatures.
