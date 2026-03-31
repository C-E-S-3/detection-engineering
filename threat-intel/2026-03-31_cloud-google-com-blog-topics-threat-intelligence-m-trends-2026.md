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

### Tactics and Techniques

#### Tactic: Initial Access
- **T1190 - Exploit Public-Facing Application**: Exploits were the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing via Service**: Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078 - Valid Accounts**: Threat actors used prior compromise as an initial infection vector in 10% of intrusions globally, and 30% in ransomware operations.

#### Tactic: Persistence
- **T1505.003 - Web Shell**: Threat actors pre-staged secondary group’s preferred malware or tunnels during initial infection.
- **T1505.003 - Web Shell**: Deployment of custom, in-memory malware like the BRICKSTORM backdoor onto network appliances for extreme persistence.

#### Tactic: Credential Access
- **T1552.001 - Credentials in Files**: Threat actors harvested long-lived OAuth tokens, session cookies, hard-coded keys, and personal access tokens from compromised SaaS vendors.
- **T1557.002 - Adversary-in-the-Middle**: Adversaries leveraged native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

#### Tactic: Impact
- **T1485 - Data Destruction**: Ransomware groups actively destroyed recovery capabilities by targeting backup infrastructure and virtualization management planes.
- **T1486 - Data Encrypted for Impact**: Attackers encrypted hypervisor datastores, rendering associated virtual machines inoperable.

#### Tactic: Defense Evasion
- **T1027 - Obfuscated Files or Information**: Malware families like PROMPTFLUX and PROMPTSTEAL used AI to evade detection by querying large language models (LLMs) mid-execution.

## 3. Malware & Tools

### Malware Families
- **REDBIKE (Akira)**: Used by ransomware operators to target backup infrastructure and identity services.
- **AGENDA (Qilin)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for extreme persistence.
- **PROMPTFLUX and PROMPTSTEAL**: Malware families leveraging AI to evade detection.
- **QUIETVAULT**: Credential stealer targeting local AI command-line tools.

### Tools
- Abuse of native packet-capturing functionality on edge devices.
- Exploitation of misconfigured Active Directory Certificate Services templates.

## 4. Threat Actor / Campaign Attribution

### Threat Actors
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.

### Campaigns
- **ShinyHunters-Branded SaaS Data Theft**: Leveraging vishing to bypass MFA and compromise SaaS environments.
- **UNC6201 Exploiting Dell RecoverPoint Zero-Day**: Exploiting zero-day vulnerabilities in Dell RecoverPoint for Virtual Machines.

### Targeted Sectors/Geographies
- High-tech sector (17%) and financial sector (14.6%) were the most frequently targeted industries in 2025.
- North Korean IT worker incidents and cyber espionage operations with a median dwell time of 122 days.

## 5. Splunk Detection Searches

### Behavioral TTPs

#### Detecting Exploitation of Public-Facing Applications
```spl
index=web proxy
| search "POST" OR "GET"
| stats count by src_ip, uri_path, http_user_agent
| where count > 100
```

#### Detecting Voice Phishing (Vishing) Activity
```spl
index=voip_logs
| search "caller_id"="*"
| stats count by caller_id, dest_number
| where count > 10
```

#### Detecting OAuth Token Harvesting
```spl
index=auth_logs
| search "OAuth token" AND "access"
| stats count by user, src_ip, dest_ip
| where count > 5
```

#### Detecting Backup Infrastructure Targeting
```spl
index=backup_logs
| search "delete" OR "modify" AND "backup"
| stats count by user, src_ip, dest_ip, action
| where action IN ("delete", "modify")
```

#### Detecting Hypervisor Datastore Encryption
```spl
index=vmware_logs
| search "datastore" AND "encryption"
| stats count by host, user, action
| where action="encrypt"
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including a rise in dwell time and the emergence of new TTPs such as voice phishing (vishing) and the exploitation of SaaS identity systems. Ransomware groups are evolving to target recovery capabilities, while espionage groups are focusing on extreme persistence through edge device exploitation and zero-day vulnerabilities. Additionally, adversaries are beginning to leverage AI to enhance their attack capabilities. Organizations are advised to prioritize behavioral anomaly detection, extend log retention, and adopt stringent identity verification measures to counter these evolving threats.