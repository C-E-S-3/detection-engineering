---
  scraped_at: "2026-03-23T00:00:00Z"
  source_url: "https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/"
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

### Initial Access
- **T1190: Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing Link**: Highly interactive voice phishing surged to 11%, becoming the second-most commonly observed vector.
- **T1078: Valid Accounts**: Prior compromise ranked as the third-most common initial infection vector (10%) globally and the top initial infection vector in ransomware operations (30%).

### Persistence
- **T1505.003: Server Software Component - Web Shell**: Adversaries are deploying custom, in-memory malware like the BRICKSTORM backdoor on edge devices to establish deep persistence.
- **T1098: Account Manipulation**: Exploiting misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1556.004: Network Device Authentication**: Adversaries are bypassing MFA by targeting IT help desks using voice phishing and harvesting long-lived OAuth tokens and session cookies.
- **T1557.002: Man-in-the-Middle - Application Layer Protocol**: Leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware groups are encrypting hypervisor datastores, rendering associated virtual machines inoperable.
- **T1485: Data Destruction**: Ransomware operators are actively deleting backup objects from cloud storage and targeting virtualization storage layers.

## 3. Malware & Tools
- **BRICKSTORM**: A custom, in-memory backdoor deployed on network appliances to establish deep persistence.
- **PROMPTFLUX and PROMPTSTEAL**: Malware families leveraging AI to evade detection by querying large language models (LLMs) mid-execution.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on targeted machines.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware operators targeting backup infrastructure, identity services, and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting Voice Phishing Activity
```spl
index=voip_logs sourcetype=voip:logs "call" AND ("MFA" OR "password reset")
| stats count by src_ip, dest_number, user
| where count > 10
```
*Comment: Identifies unusual patterns of voice calls potentially indicative of voice phishing targeting IT help desks.*

### Detecting OAuth Token Abuse
```spl
index=auth_logs sourcetype=auth:logs "OAuth token" AND "access"
| stats count by user, src_ip, dest_app
| where count > 5
```
*Comment: Flags suspicious activity involving OAuth token usage.*

### Detecting Backup Deletion in Cloud Storage
```spl
index=cloud_storage_logs action=delete resource_type=backup
| stats count by user, src_ip, resource_name
| where count > 1
```
*Comment: Detects potential malicious deletion of backup objects in cloud storage.*

### Detecting Hypervisor Datastore Encryption
```spl
index=vmware_logs sourcetype=vmware:logs "datastore" AND "encryption"
| stats count by host, user, action
| where count > 0
```
*Comment: Monitors for encryption activities targeting hypervisor datastores.*

### Detecting In-Memory Malware on Network Appliances
```spl
index=network_device_logs sourcetype=network:device "in-memory" AND "malware"
| stats count by device_ip, process_name, user
| where count > 0
```
*Comment: Detects signs of in-memory malware like BRICKSTORM on network appliances.*

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, the collapse of the "hand-off" window in ransomware operations, and the increasing use of AI by adversaries. Sophisticated threat actors are targeting edge devices and exploiting zero-day vulnerabilities for extreme persistence, while ransomware groups are evolving to destroy recovery capabilities. Organizations are advised to prioritize behavioral anomaly detection, extend log retention, and adopt robust identity verification measures to counter these emerging threats.