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
- **T1190 - Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing Link**: High-interaction voice phishing surged to 11%, becoming the second most common initial infection vector.
- **T1078 - Valid Accounts**: Prior compromise ranked as the third-most common initial infection vector globally (10%) and the top vector in ransomware operations (30%).

### Persistence
- **T1505.003 - Web Shell**: Adversaries are deploying custom, in-memory malware like the BRICKSTORM backdoor on network appliances for deep persistence.
- **T1078.004 - Cloud Accounts**: Attackers are stealing hard-coded keys and personal access tokens from SaaS vendors to pivot into downstream environments.

### Credential Access
- **T1552.001 - Credentials in Files**: Threat actors are harvesting long-lived OAuth tokens and session cookies.
- **T1557.002 - Adversary-in-the-Middle**: Adversaries are leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware operators are encrypting hypervisor datastores to render all associated virtual machines inoperable.
- **T1490 - Inhibit System Recovery**: Attackers are actively deleting backup objects from cloud storage and targeting backup infrastructure.

## 3. Malware & Tools

### Malware Families
- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for extreme persistence.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on targeted machines.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families using large language models (LLMs) to evade detection.

### Tools
- **Native Packet-Capturing Functionality**: Used on edge devices to intercept sensitive data and credentials.

## 4. Threat Actor / Campaign Attribution

### Named Threat Groups
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.

### Campaigns
- **ShinyHunters-Branded SaaS Data Theft**: Leveraging voice phishing to bypass MFA and compromise SaaS environments.
- **North Korean IT Worker Incidents**: Associated with extended dwell times of up to 122 days.

### Targeted Sectors
- High-tech sector (17%) and financial sector (14.6%) were the most frequently targeted industries in 2025.

## 5. Splunk Detection Searches

### Behavioral TTPs

#### Detecting OAuth Token Harvesting
```spl
| tstats `security_content_summariesonly` count from datamodel=Authentication where Authentication.action="success" Authentication.app="*OAuth*" by _time, Authentication.src, Authentication.user
| stats count by Authentication.src, Authentication.user
| where count > 10
```
*Detects unusual OAuth token usage by analyzing authentication events.*

#### Detecting Anomalous API Operations
```spl
index=api_logs sourcetype="api:json" action IN ("create", "delete", "update")
| stats count by user, action, endpoint
| where count > 100
```
*Flags anomalous bulk API operations that may indicate malicious activity.*

#### Detecting Hypervisor Datastore Encryption
```spl
index=vmware sourcetype="vmware:logs" "datastore" AND "encryption"
| stats count by host, user, action
| where count > 5
```
*Detects potential encryption activity targeting hypervisor datastores.*

### Network IOCs

#### Detecting Packet-Capturing on Edge Devices
```spl
index=network sourcetype="network:traffic" "packet capture"
| stats count by src_ip, dest_ip, action
| where count > 10
```
*Identifies unauthorized packet-capturing activity on network devices.*

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, extreme persistence on edge devices, and the evolution of ransomware into recovery denial. Key threat actors such as UNC3944, UNC6201, and UNC5807 are leveraging advanced techniques like OAuth token harvesting, in-memory malware, and hypervisor datastore encryption. Organizations must prioritize behavioral anomaly detection, extend log retention policies, and isolate critical control planes to counter these threats. Immediate action is recommended to address these evolving tactics and secure critical infrastructure.