---
scraped_at: 2026-03-23T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified.

### Domains/URLs
- None identified.

### File Hashes
- None identified.

### Email Addresses
- None identified.

### File Names/Paths
- None identified.

### Registry Keys
- None identified.

### Mutex Names
- None identified.

### C2 Infrastructure
- None identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques

#### Initial Access
- **T1190 - Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing via Service**: Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector. Groups like UNC3944 use vishing to target IT help desks and bypass MFA.
- **T1078 - Valid Accounts**: Prior compromise was the third-most common initial infection vector globally (10%) and the top vector for ransomware operations (30%).

#### Persistence
- **T1505.003 - Server Software Component: Web Shell**: Adversaries pre-stage secondary group malware or tunnels during the initial infection.
- **T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**: Attackers exploit misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.
- **T1547.012 - Boot or Logon Autostart Execution: Image File Execution Options Injection**: Custom in-memory malware like BRICKSTORM is deployed on network appliances for deep persistence.

#### Credential Access
- **T1552.001 - Unsecured Credentials: Credentials In Files**: Threat actors harvest long-lived OAuth tokens, session cookies, and hard-coded keys from SaaS vendors to pivot into downstream environments.
- **T1557.002 - Adversary-in-the-Middle: Application Layer Protocol**: Adversaries leverage native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

#### Impact
- **T1485 - Data Destruction**: Ransomware operators actively destroy recovery capabilities by targeting backup infrastructure, identity services, and virtualization management planes.
- **T1486 - Data Encrypted for Impact**: Ransomware groups encrypt hypervisor datastores, rendering associated virtual machines inoperable.

## 3. Malware & Tools

### Malware Families
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and identity services.
- **AGENDA (Qilin)**: Ransomware targeting virtualization management planes and backup systems.
- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for deep persistence.
- **PROMPTFLUX**: Malware leveraging AI to query large language models (LLMs) mid-execution for evasion.
- **PROMPTSTEAL**: Malware using AI to evade detection.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on targeted machines.

### Tools and Techniques
- **ClickFix**: Social engineering technique used by initial access brokers.

## 4. Threat Actor / Campaign Attribution

### Threat Actors
- **UNC3944**: Known for using vishing to target IT help desks and bypass MFA to gain access to SaaS environments.
- **UNC6201**: Targets edge and core network devices, leveraging zero-day vulnerabilities and deploying custom malware like BRICKSTORM.
- **UNC5807**: Focuses on extreme persistence by targeting network devices and exploiting vulnerabilities.

### Campaigns
- **ShinyHunters-Branded SaaS Data Theft**: Campaign involving voice phishing and SaaS identity compromise.

### Targeted Sectors
- High-tech sector (17%) and financial sector (14.6%) were the most frequently targeted industries in 2025.

## 5. Splunk Detection Searches

### Network IOCs

#### Detecting OAuth Token Harvesting
```spl
index=proxy_logs
| search uri_path="*/oauth/token"
| stats count by src_ip, user_agent, uri_path
| where count > 10
```
*# This search identifies potential OAuth token harvesting by detecting repeated requests to OAuth token endpoints.*

#### Detecting Anomalous API Usage
```spl
index=api_logs
| stats count by user, api_endpoint, http_method
| where count > 100
```
*# This search identifies anomalous bulk API operations that may indicate malicious activity.*

### Endpoint IOCs

#### Detecting BRICKSTORM Backdoor Activity
```spl
index=endpoint_logs sourcetype=XmlWinEventLog
| search process_name="*BRICKSTORM*"
| stats count by host, process_name, user
```
*# This search identifies processes related to the BRICKSTORM backdoor on endpoints.*

#### Detecting Credential Stealing via Configuration Files
```spl
index=endpoint_logs sourcetype=XmlWinEventLog
| search file_path="*\config\*.json" OR file_path="*\config\*.yaml"
| stats count by host, file_path, user
```
*# This search identifies suspicious access to configuration files potentially used for credential stealing.*

### Behavioral TTPs

#### Detecting Anomalous Edge Device Activity
```spl
index=network_device_logs
| stats count by device_type, action, src_ip
| where device_type IN ("VPN", "Router") AND action="packet_capture"
```
*# This search identifies unauthorized packet-capturing activities on edge devices.*

#### Detecting Hypervisor-Level Attacks
```spl
index=hypervisor_logs
| search event_type="datastore_encryption" OR event_type="datastore_deletion"
| stats count by host, event_type, user
```
*# This search identifies suspicious activities targeting hypervisor datastores.*

## 6. Executive Summary

The M-Trends 2026 report highlights significant advancements in adversary tactics, techniques, and procedures (TTPs) observed in 2025. Key trends include the rise of voice phishing (vishing) as a major initial access vector, the evolution of ransomware to target recovery capabilities, and the use of AI by threat actors to evade detection and accelerate attacks. Sophisticated groups are also exploiting zero-day vulnerabilities and targeting edge devices for extreme persistence. Organizations are advised to adopt behavioral anomaly detection, extend log retention policies, and enhance security measures for critical infrastructure to mitigate these evolving threats.