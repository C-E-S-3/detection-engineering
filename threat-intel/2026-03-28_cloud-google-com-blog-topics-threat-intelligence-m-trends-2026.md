---
scraped_at: "2026-03-27T00:00:00Z"
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
- **T1190 - Exploit Public-Facing Application**: Exploits remained the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing via Service**: High-interaction voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078 - Valid Accounts**: Threat actors leveraged stolen credentials, including OAuth tokens and session cookies, to gain access to SaaS environments.

### Persistence
- **T1505.003 - Server Software Component: Web Shell**: Adversaries pre-staged malware or tunnels during the initial infection phase.
- **T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**: Ransomware operators exploited misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.
- **T1505.003 - Server Software Component: Web Shell**: Deployment of custom in-memory malware like the BRICKSTORM backdoor on edge devices for extreme persistence.

### Defense Evasion
- **T1556.004 - Network Sniffing**: Adversaries leveraged native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1070.004 - Indicator Removal on Host: File Deletion**: Attackers deleted backup objects from cloud storage to prevent recovery.

### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware groups targeted backup infrastructure and virtualization management planes to encrypt hypervisor datastores and render virtual machines inoperable.
- **T1485 - Data Destruction**: Ransomware operators actively destroyed recovery capabilities by targeting backup environments and identity services.

## 3. Malware & Tools

### Malware Families
- **BRICKSTORM**: A custom in-memory backdoor deployed on network appliances to achieve extreme persistence.
- **QUIETVAULT**: Credential stealer that checks for local AI command-line tools and executes predefined prompts to search for configuration files.
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and identity services.
- **AGENDA (Qilin)**: Ransomware targeting virtualization management planes and backup environments.

### Tools
- **PROMPTFLUX**: Malware leveraging large language models (LLMs) mid-execution to evade detection.
- **PROMPTSTEAL**: Malware querying LLMs for evasion and operational purposes.

## 4. Threat Actor / Campaign Attribution

### Threat Groups
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201**: Exploits edge and core network devices for extreme persistence.
- **UNC5807**: Focuses on targeting edge devices like VPNs and routers.

### Campaigns
- **ClickFix**: A social engineering technique used by initial access brokers to gain a foothold before handing off access to secondary groups.

### Targeted Sectors/Geographies
- High-tech sector (17%) and financial sector (14.6%) were the most frequently targeted industries in 2025.

## 5. Splunk Detection Searches

### Behavioral TTPs

#### Detecting OAuth Token and Session Cookie Theft
```spl
| tstats `security_content_summariesonly` count from datamodel=Authentication where Authentication.action="success" Authentication.app="*SaaS*" by Authentication.src, Authentication.user
| `drop_dm_object_name("Authentication")`
| search [| inputlookup compromised_tokens.csv | fields token]
| table _time, src, user, token
```

#### Detecting Anomalous Bulk API Operations
```spl
index=api_logs sourcetype=api_calls
| stats count by api_endpoint, user, src_ip
| where count > 100
| table _time, api_endpoint, user, src_ip, count
```

#### Detecting Backup Object Deletion in Cloud Storage
```spl
index=cloud_storage_logs eventName="DeleteObject" 
| stats count by user, bucketName, objectName
| where count > 10
| table _time, user, bucketName, objectName, count
```

#### Detecting In-Memory Malware on Edge Devices
```spl
index=network_logs sourcetype=network_traffic
| search "BRICKSTORM"
| table _time, src_ip, dest_ip, dest_port, process_name
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including a rise in global median dwell time and the emergence of new TTPs such as high-interaction voice phishing and the exploitation of edge devices for extreme persistence. Notable malware families like BRICKSTORM and QUIETVAULT have been observed, alongside the evolution of ransomware tactics to include recovery denial. Organizations are advised to adopt behavioral anomaly detection, extend log retention policies, and implement strict access controls to counter these advanced threats. Immediate action is recommended to address these evolving risks and enhance operational resilience.