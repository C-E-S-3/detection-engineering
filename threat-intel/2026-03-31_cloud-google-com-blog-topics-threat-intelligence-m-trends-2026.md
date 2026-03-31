---
scraped_at: 2026-03-23T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
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
- **T1566.002: Spearphishing via Service**: High-interaction voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**: Threat actors use compromised credentials, including long-lived OAuth tokens and session cookies, to gain unauthorized access to SaaS environments.

### Persistence
- **T1505.003: Web Shell**: Use of custom in-memory malware like BRICKSTORM to establish persistence on edge devices and network appliances.
- **T1098: Account Manipulation**: Exploitation of misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1556.004: Network Sniffing**: Leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1070.004: File Deletion**: Deleting backup objects from cloud storage to disrupt recovery efforts.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware groups encrypting data and targeting backup infrastructure.
- **T1485: Data Destruction**: Ransomware operators actively destroying recovery capabilities by targeting backup systems and virtualization management planes.

## 3. Malware & Tools
- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for extreme persistence.
- **PROMPTFLUX**: Malware leveraging large language models (LLMs) for evasion.
- **PROMPTSTEAL**: Malware using LLMs for detection evasion.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files in local AI command-line tools.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups focusing on recovery denial by targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token and Session Cookie Theft
```spl
index=proxy_logs
| search "OAuth" OR "session cookie"
| stats count by src_ip, user, uri_path
| where count > 10
```

### Detecting Exploitation of Public-Facing Applications
```spl
index=web_logs
| search "POST" AND ("/wp-admin" OR "/login")
| stats count by src_ip, uri_path
| where count > 5
```

### Detecting Backup Deletion in Cloud Storage
```spl
index=cloud_storage_logs
| search "delete" AND "backup"
| stats count by user, src_ip, resource
| where count > 1
```

### Detecting Anomalous SaaS API Activity
```spl
index=saas_logs
| search "api" AND ("bulk download" OR "token usage")
| stats count by user, api_endpoint
| where count > 10
```

### Detecting In-Memory Malware on Edge Devices
```spl
index=sysmon_logs EventCode=10
| search "BRICKSTORM"
| stats count by Computer, ProcessName
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of high-interaction voice phishing, increased exploitation of edge devices, and the evolution of ransomware into recovery denial attacks. Notable threat actors such as UNC3944, UNC6201, and ransomware groups like REDBIKE and AGENDA have adopted advanced TTPs to evade detection and maximize impact. Organizations are advised to prioritize behavioral anomaly detection, extend log retention policies, and implement strict access controls for critical systems. Immediate action is recommended to address these evolving threats and enhance organizational resilience.