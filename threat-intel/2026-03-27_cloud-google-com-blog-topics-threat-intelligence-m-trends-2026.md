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
- **T1566.002: Spearphishing via Service**: High interaction voice phishing surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**: Prior compromise ranked as the third-most common initial infection vector globally (10%) and the top vector in ransomware operations (30%).

### Persistence
- **T1505.003: Web Shell**: Adversaries are deploying custom, in-memory malware like the BRICKSTORM backdoor onto network appliances for deep persistence.
- **T1098: Account Manipulation**: Attackers exploit misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1556.004: Network Sniffing**: Adversaries leverage native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1558.003: Steal Application Access Token**: Threat actors harvest OAuth tokens and session cookies to bypass standard defenses.

### Impact
- **T1485: Data Destruction**: Ransomware groups are actively destroying recovery capabilities by targeting backup infrastructure and virtualization management planes.
- **T1486: Data Encrypted for Impact**: Attackers encrypt hypervisor datastores, rendering associated virtual machines inoperable.

## 3. Malware & Tools

### Malware Families
- **REDBIKE (Akira)**: Used in ransomware operations targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Another ransomware family targeting recovery capabilities.
- **BRICKSTORM**: Custom in-memory malware deployed on network appliances for extreme persistence.
- **QUIETVAULT**: Credential stealer leveraging local AI command-line tools to search for configuration files.

### Tools
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families querying large language models (LLMs) mid-execution to evade detection.

## 4. Threat Actor / Campaign Attribution

### Named Threat Groups
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.

### Campaigns
- **ClickFix**: Social engineering technique used by initial access brokers to gain a foothold.

### Targeted Sectors
- High-tech sector (17%) and financial sector (14.6%) were the most frequently targeted industries in 2025.

## 5. Splunk Detection Searches

### Detecting OAuth Token Harvesting
```spl
index=proxy_logs
| search uri_path="*/token"
| stats count by src_ip, user, uri_path
| where count > 10
| table src_ip, user, uri_path, count
```

### Detecting Voice Phishing Activity
```spl
index=voip_logs OR index=call_logs
| search "unexpected international calls" OR "unusual call duration"
| stats count by src_number, dest_number, duration
| where duration > 300
| table src_number, dest_number, duration, count
```

### Detecting Backup Infrastructure Targeting
```spl
index=backup_logs
| search "delete" OR "modify" AND "backup"
| stats count by user, action, target
| where count > 5
| table user, action, target, count
```

### Detecting Hypervisor Datastore Encryption
```spl
index=vmware_logs
| search "datastore" AND "encryption"
| stats count by host, user, action
| where count > 1
| table host, user, action, count
```

### Detecting In-Memory Malware on Edge Devices
```spl
index=network_device_logs
| search "in-memory execution" OR "unexpected process creation"
| stats count by device_ip, process_name, action
| where count > 1
| table device_ip, process_name, action, count
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, the collapse of the "hand-off" window in ransomware operations, and the increasing use of AI by adversaries. Notable threats include the BRICKSTORM backdoor, which achieves extreme persistence on network devices, and ransomware groups like REDBIKE and AGENDA targeting recovery infrastructure. Organizations are advised to prioritize behavioral anomaly detection, extend log retention, and implement strict access controls for critical systems. Immediate action is recommended to mitigate risks from these advanced threats.