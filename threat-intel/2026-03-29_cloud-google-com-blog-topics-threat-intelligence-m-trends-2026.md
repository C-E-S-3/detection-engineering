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

### Tactics and Techniques

#### Initial Access
- **T1190 - Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing Link**: High-interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078 - Valid Accounts**: Attackers are compromising third-party SaaS vendors to steal hard-coded keys and personal access tokens for downstream attacks.

#### Persistence
- **T1505.003 - Server Software Component: Web Shell**: Adversaries are deploying custom, in-memory malware like the BRICKSTORM backdoor on network appliances for extreme persistence.
- **T1556.004 - Network Device Authentication**: Exploitation of misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

#### Defense Evasion
- **T1556.004 - Credential Manipulation**: Attackers are harvesting long-lived OAuth tokens and session cookies to bypass traditional defenses.
- **T1562.001 - Disable or Modify Tools**: Attackers are actively deleting backup objects from cloud storage and targeting virtualization storage layers.

#### Credential Access
- **T1557.002 - Man-in-the-Middle**: Leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

#### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware operators are encrypting data and targeting backup infrastructure and virtualization management planes.
- **T1485 - Data Destruction**: Ransomware groups are actively destroying recovery capabilities by deleting backup objects and encrypting hypervisor datastores.

## 3. Malware & Tools

### Malware Families
- **BRICKSTORM**: A custom, in-memory backdoor deployed on network appliances to establish deep persistence.
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware with similar tactics to REDBIKE.
- **QUIETVAULT**: Credential stealer that targets local AI command-line tools to search for configuration files.

### Tools and Techniques
- **PROMPTFLUX and PROMPTSTEAL**: Malware families using large language models (LLMs) mid-execution to evade detection.

## 4. Threat Actor / Campaign Attribution

### Threat Actors
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices to establish extreme persistence.

### Campaigns
- **ShinyHunters-Branded SaaS Data Theft**: Campaign involving voice phishing and SaaS identity compromise.

### Targeted Sectors/Geographies
- High-tech sector (17%) and financial sector (14.6%) were the most frequently targeted industries in 2025.
- North Korean IT worker incidents and cyber espionage campaigns had a median dwell time of 122 days.

## 5. Splunk Detection Searches

### Detecting OAuth Token and Session Cookie Harvesting
```spl
index=proxy_logs
| search "OAuth" OR "session cookie"
| stats count by src_ip, dest_ip, user, uri
| where count > 10
| table src_ip, dest_ip, user, uri, count
```

### Detecting Anomalous Bulk API Operations
```spl
index=api_logs
| stats count by api_endpoint, user, action
| where count > 100
| table api_endpoint, user, action, count
```

### Detecting Backup Deletion Activities
```spl
index=cloud_storage_logs
| search "delete" AND ("backup" OR "snapshot")
| stats count by user, src_ip, resource
| where count > 5
| table user, src_ip, resource, count
```

### Detecting Packet-Capturing on Edge Devices
```spl
index=network_logs
| search "packet capture" OR "tcpdump" OR "wireshark"
| stats count by src_ip, dest_ip, command
| table src_ip, dest_ip, command, count
```

### Detecting Hypervisor Datastore Encryption
```spl
index=vmware_logs
| search "datastore" AND "encryption"
| stats count by host, user, action
| table host, user, action
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including increased dwell times, the rise of voice phishing, and the evolution of ransomware tactics to include recovery denial. Sophisticated threat actors are leveraging zero-day exploits and targeting edge devices for extreme persistence, while also exploiting SaaS identity vulnerabilities. Organizations are advised to adopt behavioral anomaly detection, extend log retention policies, and treat low-impact alerts as critical indicators to mitigate these advanced threats. Immediate action is recommended to secure critical infrastructure and enhance visibility across the network.