---
scraped_at: "2026-04-02T14:02:18Z"
source_url: "https://www.bleepingcomputer.com/news/security/new-progress-sharefile-flaws-can-be-chained-in-pre-auth-rce-attacks/"
report_type: threat-intel
severity: "high"
title: "Progress ShareFile vulnerabilities enable pre-auth RCE exploit chain"
---

## 1. Indicators of Compromise (IOCs)
No specific IOCs (e.g., IPs, domains, hashes) were disclosed in the source.

## 2. TTPs (MITRE ATT&CK Mapping)
### Tactic: Initial Access
- **Technique ID:** T1190
- **Technique Name:** Exploit Public-Facing Application
- **Description:** Attackers exploit CVE-2026-2699 to bypass authentication and gain access to the ShareFile admin interface.

### Tactic: Execution
- **Technique ID:** T1059.007
- **Technique Name:** Command and Scripting Interpreter: ASP.NET
- **Description:** Attackers exploit CVE-2026-2701 to upload malicious ASPX webshells to the application's webroot for remote code execution.

### Tactic: Credential Access
- **Technique ID:** T1552
- **Technique Name:** Unsecured Credentials
- **Description:** Attackers extract and decrypt internal secrets and HMAC signatures after exploiting CVE-2026-2699.

### Tactic: Impact
- **Technique ID:** T1485
- **Technique Name:** Data Destruction
- **Description:** Exploitation of the vulnerabilities could lead to unauthorized file exfiltration and potential data destruction.

## 3. Malware & Tools
No specific malware families or tools were mentioned in the source.

## 4. Threat Actor / Campaign Attribution
No specific threat actor or campaign attribution was provided. However, ransomware groups may target these vulnerabilities, as similar file transfer solutions have been exploited in past attacks.

## 5. Splunk Detection Searches
### Detecting Exploitation of CVE-2026-2699 (Authentication Bypass)
```spl
index=web sourcetype=access_combined_wcookie
| search "HTTP redirect"
| stats count by uri, clientip
| where count > 10
| table uri, clientip, count
```
*This search identifies unusual HTTP redirects that could indicate exploitation of CVE-2026-2699.*

### Detecting Exploitation of CVE-2026-2701 (Webshell Upload)
```spl
index=web sourcetype=access_combined_wcookie
| search "POST" "ASPX"
| stats count by uri, clientip
| where count > 5
| table uri, clientip, count
```
*This search detects ASPX file uploads that may indicate webshell placement.*

### Detecting Unauthorized Configuration Changes
```spl
index=web sourcetype=access_combined_wcookie
| search "Storage Zone configuration"
| stats count by uri, clientip
| where count > 5
| table uri, clientip, count
```
*This search identifies suspicious modifications to Storage Zone configuration settings.*

## 6. Executive Summary
Two critical vulnerabilities (CVE-2026-2699 and CVE-2026-2701) in Progress ShareFile's Storage Zones Controller component enable a pre-authentication remote code execution exploit chain. Attackers can bypass authentication, access the admin interface, modify security-sensitive parameters, and upload malicious webshells for remote code execution. While no active exploitation has been observed, the public disclosure of these vulnerabilities increases the risk of exploitation by threat actors, including ransomware groups. Organizations using vulnerable versions of ShareFile should immediately apply the vendor's patch (version 5.12.4) to mitigate risk.