---
scraped_at: 2026-03-23T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified.

### File Hashes
- None identified.

### IP Addresses
- None identified.

### Other IOCs
- None identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1190: Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing Link**: High-interaction voice phishing (vishing) increased to 11% of initial access vectors, targeting IT help desks to bypass MFA.
- **T1078: Valid Accounts**: Attackers leverage stolen OAuth tokens, session cookies, and hard-coded keys to gain access to SaaS environments.

### Persistence
- **T1505.003: Web Shell**: Attackers deploy custom in-memory malware like the BRICKSTORM backdoor on edge and core network devices for extreme persistence.
- **T1078.003: Valid Accounts - Cloud Accounts**: Exploitation of misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Credential Access
- **T1552.001: Credentials in Files**: Threat actors use tools like QUIETVAULT to search for configuration files and harvest credentials.
- **T1557.002: Adversary-in-the-Middle**: Adversaries use native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware groups encrypt data and target virtualization storage layers to render virtual machines inoperable.
- **T1485: Data Destruction**: Ransomware operators destroy backup infrastructure, identity services, and virtualization management planes to deny recovery.

### Defense Evasion
- **T1070.004: File Deletion**: Attackers delete backup objects from cloud storage to hinder recovery.
- **T1027: Obfuscated Files or Information**: Malware families like PROMPTFLUX and PROMPTSTEAL use AI to evade detection.

## 3. Malware & Tools

### Malware Families
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **BRICKSTORM**: Custom in-memory backdoor deployed on edge and core network devices for extreme persistence.
- **PROMPTFLUX**: Malware leveraging AI to evade detection.
- **PROMPTSTEAL**: Malware leveraging AI to evade detection.
- **QUIETVAULT**: Credential stealer targeting local AI command-line tools.

### Tools
- **ClickFix**: Social engineering technique used for initial access.

## 4. Threat Actor / Campaign Attribution

### Threat Actors
- **UNC3944**: Engages in voice phishing to bypass MFA and gain access to SaaS environments.
- **UNC6201**: Targets edge and core network devices for extreme persistence.
- **UNC5807**: Targets edge and core network devices for extreme persistence.

### Campaigns
- None explicitly named in the source.

### Targeted Sectors/Geographies
- High-tech sector (17%)
- Financial sector (14.6%)
- North Korean IT worker incidents

## 5. Splunk Detection Searches

### Detection for Voice Phishing (Vishing)
```spl
index=voip_logs sourcetype=voip:logs "call_type=outbound" "destination_number=*" 
| stats count by src_ip, dest_number, user
| where count > 10
| table src_ip, dest_number, user
```
# This search identifies unusual patterns of outbound calls, which may indicate vishing attempts.

### Detection for OAuth Token and Session Cookie Theft
```spl
index=web sourcetype=web:access "Authorization: Bearer *"
| stats count by src_ip, user_agent
| where count > 5
| table src_ip, user_agent
```
# This search identifies suspicious use of OAuth tokens in web access logs.

### Detection for Backup Deletion
```spl
index=cloud sourcetype=cloud:storage "delete" "backup"
| stats count by user, src_ip
| where count > 5
| table user, src_ip
```
# This search identifies multiple backup deletion events from the same user or IP address.

### Detection for Edge Device Exploitation
```spl
index=network sourcetype=network:device_logs "packet_capture" OR "config_change"
| stats count by src_ip, dest_ip, action
| where count > 10
| table src_ip, dest_ip, action
```
# This search identifies suspicious activity on edge devices, such as unauthorized packet capturing or configuration changes.

### Detection for AI-Powered Malware
```spl
index=endpoint sourcetype=endpoint:process "process_name=*" "command_line=*AI*"
| stats count by host, process_name, command_line
| where count > 3
| table host, process_name, command_line
```
# This search identifies processes leveraging AI-related command-line tools, which could indicate malicious activity.

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing (vishing) as a key initial access vector, the evolution of ransomware into recovery denial operations, and the exploitation of edge devices for extreme persistence. Threat actors are increasingly leveraging AI to evade detection and accelerate attacks. Organizations must adopt behavioral anomaly detection, extend log retention, and isolate critical control planes to counter these advanced threats. Immediate action is recommended to address these evolving risks and enhance operational resilience.