---
scraped_at: "2026-03-30T03:48:17-04:00"
source_url: "https://www.bleepingcomputer.com/news/security/critical-fortinet-forticlient-ems-flaw-now-exploited-in-attacks/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- **Indicator:** Multiple IPs (over 1,400 in the US and Europe)
  - **Context:** Exposed FortiClient EMS instances vulnerable to CVE-2026-21643 exploitation.

### Domains/URLs
- **No new domains or URLs identified.**

### File Hashes
- **No file hashes identified.**

### Email Addresses
- **No email addresses identified.**

### File Names/Paths
- **No file names or paths identified.**

### Registry Keys
- **No registry keys identified.**

### Mutex Names
- **No mutex names identified.**

### C2 Infrastructure
- **No specific C2 infrastructure identified.**

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic:** Execution
  - **Technique ID:** T1059.001 (Command and Scripting Interpreter: PowerShell)
  - **Description:** Exploitation of CVE-2026-21643 allows attackers to execute arbitrary commands via maliciously crafted HTTP requests targeting the FortiClient EMS GUI.

- **Tactic:** Initial Access
  - **Technique ID:** T1190 (Exploit Public-Facing Application)
  - **Description:** Attackers exploit the FortiClient EMS GUI (web interface) through SQL injection in the 'Site'-header of HTTP requests to gain unauthorized access.

## 3. Malware & Tools

- **Malware Families:** None explicitly mentioned.
- **Tools:** Exploitation of CVE-2026-21643 via malicious HTTP requests.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** None explicitly named in this report.
- **Campaign:** None explicitly named in this report.
- **Motivations:** Likely cyber espionage or ransomware campaigns, as Fortinet vulnerabilities have historically been exploited for these purposes.
- **Targeted Sectors/Geographies:** Over 1,400 exposed FortiClient EMS instances in the United States and Europe.

## 5. Splunk Detection Searches

### Detecting Exploitation Attempts via HTTP Requests
```spl
index=proxy OR index=web 
| search uri_path="/remote/fctems*" AND http_method="POST" AND http_header="*Site:*"
| stats count by src_ip, http_user_agent, uri_path, http_method, http_header
| table src_ip, http_user_agent, uri_path, http_method, http_header, count
```
*Comment:* This search identifies HTTP POST requests to the FortiClient EMS GUI with a suspicious 'Site'-header, which could indicate an attempt to exploit CVE-2026-21643.

### Identifying Exposed FortiClient EMS Instances
```spl
index=network 
| search dest_port=443 AND ssl_subject="*FortiClient EMS*"
| stats count by dest_ip, dest_port, ssl_subject
| table dest_ip, dest_port, ssl_subject, count
```
*Comment:* This search identifies publicly exposed FortiClient EMS instances by analyzing SSL certificate subjects.

## 6. Executive Summary

A critical SQL injection vulnerability (CVE-2026-21643) in Fortinet's FortiClient EMS platform is being actively exploited in the wild. This vulnerability allows unauthenticated attackers to execute arbitrary commands via maliciously crafted HTTP requests targeting the FortiClient EMS GUI. Over 1,400 vulnerable instances have been identified in the United States and Europe, posing a significant risk to organizations using this platform. Immediate patching to version 7.4.5 or later is strongly recommended to mitigate this threat. Organizations should also monitor for suspicious HTTP requests targeting the FortiClient EMS GUI and identify any exposed instances to prevent exploitation.