---
scraped_at: "2026-04-01T15:42:25-04:00"
source_url: "https://www.bleepingcomputer.com/news/security/new-eviltokens-service-fuels-microsoft-device-code-phishing-attacks/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified

### File Hashes
- None identified

### IP Addresses
- None identified

### Email Addresses
- None identified

### File Names/Paths
- None identified

### Registry Keys
- None identified

### Mutex Names
- None identified

### C2 Infrastructure
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic:** Credential Access
  - **Technique ID:** T1550.001 (Application Access Token)
    - **Description:** EvilTokens abuses OAuth 2.0 device authorization flow to hijack Microsoft accounts by tricking victims into authorizing malicious devices. This provides attackers with access and refresh tokens for persistent access to victim accounts.

- **Tactic:** Initial Access
  - **Technique ID:** T1566 (Phishing)
    - **Description:** Victims receive phishing emails containing QR codes or hyperlinks to phishing templates impersonating legitimate services like DocuSign or SharePoint.

- **Tactic:** Persistence
  - **Technique ID:** T1078 (Valid Accounts)
    - **Description:** Attackers use stolen tokens to maintain persistent access to victim accounts and services.

## 3. Malware & Tools

- **Malware/Tool Name:** EvilTokens
  - **Description:** A phishing-as-a-service (PhaaS) kit that integrates device code phishing capabilities to hijack Microsoft accounts. It is sold on Telegram and is under continuous development, with plans to expand support to Gmail and Okta phishing pages.

## 4. Threat Actor / Campaign Attribution

- **Threat Actors:**
  - Storm-237
  - UTA032
  - UTA0355
  - UNK_AcademicFlare
  - TA2723
  - ShinyHunters

- **Campaigns:**
  - EvilTokens campaigns have a global reach, targeting countries such as the United States, Canada, France, Australia, India, Switzerland, and the UAE.

- **Targeted Sectors/Geographies:**
  - Employees in finance, HR, logistics, or sales roles.
  - Victims in the United States, Canada, France, Australia, India, Switzerland, and the UAE.

## 5. Splunk Detection Searches

### Detecting OAuth 2.0 Device Authorization Flow Abuse
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/common/oauth2/deviceauth"
| stats count by src_ip, uri_path, http_user_agent
| where count > 10
| table src_ip, uri_path, http_user_agent, count
```
*Comment: This search identifies unusual activity related to the OAuth 2.0 device authorization flow, which is abused in EvilTokens attacks.*

### Detecting Phishing Emails with QR Codes or Hyperlinks
```spl
index=email_logs sourcetype=exchange
| search "QR code" OR "DocuSign" OR "SharePoint" OR "Microsoft device login"
| stats count by sender, recipient, subject, message_id
| where count > 5
| table sender, recipient, subject, message_id, count
```
*Comment: This search identifies phishing emails containing QR codes or hyperlinks impersonating legitimate services.*

### Detecting Access Token Usage
```spl
index=azure_logs sourcetype=azure:activity
| search "token" AND "access" AND "refresh"
| stats count by user, app_display_name, ip_address
| where count > 10
| table user, app_display_name, ip_address, count
```
*Comment: This search detects suspicious access token usage, which could indicate compromised accounts.*

## 6. Executive Summary

A new phishing-as-a-service (PhaaS) kit called EvilTokens has been identified, which exploits the OAuth 2.0 device authorization flow to hijack Microsoft accounts. The kit is sold on Telegram and is under active development, with plans to expand its capabilities to target Gmail and Okta. The attacks involve phishing emails containing QR codes or hyperlinks that redirect victims to phishing pages mimicking trusted services. The attackers use these pages to steal access and refresh tokens, enabling persistent access to victim accounts and services. Organizations are advised to monitor for suspicious OAuth 2.0 activity, educate employees about phishing risks, and implement multi-factor authentication to mitigate the impact of token theft.