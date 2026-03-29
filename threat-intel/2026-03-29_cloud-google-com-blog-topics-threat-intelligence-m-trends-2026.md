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
- **T1190 - Exploit Public-Facing Application**: Exploits remained the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing via Service**: Highly interactive voice phishing (vishing) increased to 11%, becoming the second-most common initial infection vector.
- **T1078 - Valid Accounts**: Threat actors used stolen credentials, including hard-coded keys and personal access tokens, to gain access to SaaS environments.

#### Persistence
- **T1505.003 - Web Shell**: Attackers pre-staged secondary group malware or tunnels during initial infections.
- **T1505.003 - Web Shell**: Deployment of custom, in-memory malware like the BRICKSTORM backdoor on network appliances for extreme persistence.

#### Credential Access
- **T1552.001 - Credentials in Files**: Threat actors harvested long-lived OAuth tokens and session cookies.
- **T1557.002 - Man-in-the-Middle**: Adversaries leveraged native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

#### Defense Evasion
- **T1553.004 - Application Shimming**: Attackers exploited misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.
- **T1027 - Obfuscated Files or Information**: Malware families like PROMPTFLUX and PROMPTSTEAL used AI to evade detection.

#### Impact
- **T1485 - Data Destruction**: Ransomware groups actively destroyed backup infrastructure and virtualization management planes.
- **T1486 - Data Encrypted for Impact**: Attackers encrypted hypervisor datastores, rendering associated virtual machines inoperable.

## 3. Malware & Tools

### Malware Families
- **REDBIKE (Akira)**: Used by ransomware operators to target backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Another ransomware family targeting backup and identity services.
- **BRICKSTORM**: A custom, in-memory backdoor deployed on network appliances for extreme persistence.
- **PROMPTFLUX and PROMPTSTEAL**: Malware families leveraging AI to evade detection.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on targeted machines.

### Tools and Techniques
- **ClickFix**: A social engineering technique used by initial access brokers.
- **Native packet-capturing functionality**: Leveraged on edge devices to intercept sensitive data and credentials.

## 4. Threat Actor / Campaign Attribution

### Threat Actors
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.

### Campaigns
- **ShinyHunters-Branded SaaS Data Theft**: Campaign involving voice phishing to bypass MFA and compromise SaaS environments.

### Targeted Sectors/Geographies
- High-tech sector (17%) and financial sector (14.6%) were the most targeted industries in 2025.
- North Korean IT worker incidents and cyber espionage campaigns had a median dwell time of 122 days.

## 5. Splunk Detection Searches

### Behavioral TTPs

#### Detecting OAuth Token and Session Cookie Harvesting
```spl
index=proxy OR index=web 
| search "OAuth" OR "session cookie" 
| stats count by src_ip, dest_ip, user, uri_path, http_user_agent
| where count > 10
| table src_ip, dest_ip, user, uri_path, http_user_agent
```
# This search identifies potential OAuth token or session cookie harvesting by looking for unusual access patterns in web and proxy logs.

#### Detecting Anomalous Bulk API Operations
```spl
index=api_logs 
| stats count by api_endpoint, user, action 
| where count > 100
| table api_endpoint, user, action, count
```
# This search identifies bulk API operations that deviate from normal behavior, which could indicate malicious activity.

#### Detecting Backup Infrastructure Tampering
```spl
index=backup_logs 
| search "delete" OR "modify" 
| stats count by user, action, resource
| where action IN ("delete", "modify")
| table user, action, resource, count
```
# This search detects unauthorized deletion or modification of backup resources, which could indicate ransomware activity.

#### Detecting Hypervisor Datastore Encryption
```spl
index=vm_logs 
| search "datastore" AND "encryption" 
| stats count by host, user, action
| table host, user, action, count
```
# This search identifies potential encryption activities targeting hypervisor datastores.

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, the collapse of the "hand-off" window between initial access and secondary operations, and the evolution of ransomware into recovery denial attacks. Espionage groups are increasingly targeting edge devices for extreme persistence, leveraging zero-day vulnerabilities and deploying in-memory malware like BRICKSTORM. Organizations are advised to prioritize behavioral anomaly detection, extend log retention, and secure critical control planes to mitigate these emerging threats. Immediate action is recommended to address these advanced tactics and enhance organizational resilience.