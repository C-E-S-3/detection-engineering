---
scraped_at: "2026-03-23T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified

### Domains/URLs
- None identified

### File Hashes
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

### Initial Access
- **T1190: Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**: High-interaction voice phishing (vishing) surged to 11%, becoming the second most common initial infection vector.
- **T1078: Valid Accounts**: Prior compromise accounted for 10% of initial infection vectors, with attackers leveraging previously stolen credentials.

### Persistence
- **T1505.003: Web Shell**: Attackers pre-stage secondary group malware or tunnels during initial infection.
- **T1547.003: Windows Management Instrumentation Event Subscription**: Misconfigured Active Directory Certificate Services templates exploited to create admin accounts that bypass password rotation.
- **T1547.001: Boot or Logon Autostart Execution**: Custom in-memory malware like BRICKSTORM deployed on network appliances to establish deep persistence.

### Credential Access
- **T1552.001: Credentials in Files**: Threat actors harvest long-lived OAuth tokens and session cookies.
- **T1557.002: Man-in-the-Middle**: Adversaries leverage native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware operators encrypt hypervisor datastores to render virtual machines inoperable.
- **T1485: Data Destruction**: Ransomware groups actively destroy backup infrastructure and virtualization management planes to deny recovery.

## 3. Malware & Tools

### Malware Families
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for extreme persistence.
- **QUIETVAULT**: Credential stealer targeting local AI command-line tools to extract configuration files.

### Tools and Techniques
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families leveraging large language models (LLMs) for detection evasion.
- **ClickFix**: Social engineering technique used for initial access.

## 4. Threat Actor / Campaign Attribution

### Named Threat Groups
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201**: Targets edge and core network devices for extreme persistence.
- **UNC5807**: Focuses on exploiting edge devices and routers for long-term persistence.

### Campaigns
- **North Korean IT Worker Incidents**: High dwell times (122 days) observed in cyber espionage campaigns.
- **Ransomware Operations**: Prior compromise as a top initial infection vector in ransomware campaigns (30%).

### Targeted Sectors/Geographies
- High-tech sector (17%) and financial sector (14.6%) were the most targeted industries in 2025.

## 5. Splunk Detection Searches

### Behavioral TTPs

#### Detecting Exploitation of Public-Facing Applications
```spl
index=web proxy
| search (http_method=POST OR http_method=GET) (uri_path IN ("/admin", "/login", "/wp-admin"))
| stats count by src_ip, uri_path
| where count > 10
```
*# This search identifies potential exploitation attempts by analyzing repeated access to sensitive endpoints.*

#### Detecting Voice Phishing (Vishing) Attempts
```spl
index=voip_logs
| search "call_type=outbound" AND "duration>300"
| stats count by caller_id, callee_id
| where count > 5
```
*# This search identifies repeated outbound calls with a duration longer than 5 minutes, which may indicate vishing attempts.*

#### Detecting OAuth Token Harvesting
```spl
index=cloud_logs
| search "action=token_request" AND "response=success"
| stats count by user, app_name
| where count > 10
```
*# This search identifies unusual OAuth token requests that may indicate token harvesting.*

#### Detecting Ransomware Targeting Backup Infrastructure
```spl
index=backup_logs
| search "action=delete" OR "action=modify" "object_type=backup"
| stats count by user, object_name
| where count > 5
```
*# This search identifies suspicious deletion or modification of backup objects.*

#### Detecting Anomalous Hypervisor Activity
```spl
index=vmware_logs
| search "event_type=datastore_encryption" OR "event_type=datastore_deletion"
| stats count by host, user
| where count > 2
```
*# This search identifies potential ransomware activity targeting hypervisor datastores.*

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including increased dwell times, the rise of voice phishing (vishing), and the evolution of ransomware into recovery denial attacks. Sophisticated threat actors are leveraging zero-day vulnerabilities and targeting edge devices for extreme persistence, while also exploiting AI technologies to enhance attack capabilities. Organizations must prioritize behavioral anomaly detection, extend log retention, and adopt advanced identity verification measures to counter these evolving threats. Immediate action is recommended to secure critical infrastructure, improve detection capabilities, and enhance operational resilience.