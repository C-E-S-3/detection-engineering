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

#### Initial Access
- **T1190: Exploit Public-Facing Application**
  - Exploits remained the most common initial infection vector, accounting for 32% of intrusions.
- **T1598.002: Spearphishing via Service**
  - High-interaction voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**
  - Attackers used compromised credentials, including OAuth tokens and session cookies, to gain unauthorized access to SaaS environments.

#### Persistence
- **T1505.003: Server Software Component**
  - Custom in-memory malware like BRICKSTORM was deployed on edge devices to establish deep persistence.
- **T1098: Account Manipulation**
  - Attackers exploited misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

#### Defense Evasion
- **T1070.004: File Deletion**
  - Attackers actively deleted backup objects from cloud storage.
- **T1562.001: Impair Defenses: Disable or Modify Tools**
  - Exploitation of hypervisors to bypass guest-level defenses.

#### Impact
- **T1486: Data Encrypted for Impact**
  - Ransomware groups encrypted hypervisor datastores, rendering associated virtual machines inoperable.
- **T1485: Data Destruction**
  - Ransomware operators targeted backup infrastructure and virtualization management planes to destroy recovery capabilities.

## 3. Malware & Tools

### Malware Families
- **BRICKSTORM**: Custom in-memory malware deployed on edge devices for deep persistence.
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware with similar destructive capabilities as REDBIKE.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on local machines.

### Tools
- **PROMPTFLUX**: Malware leveraging large language models (LLMs) to evade detection.
- **PROMPTSTEAL**: Malware using LLMs for evasion and data theft.

## 4. Threat Actor / Campaign Attribution

### Threat Actors
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201**: Focused on exploiting edge and core network devices for extreme persistence.
- **UNC5807**: Similar to UNC6201, targeting edge devices for long-term persistence.

### Campaigns
- **ClickFix**: Social engineering technique used by initial access brokers to gain a foothold before handing off access to secondary threat groups.

### Targeted Sectors/Geographies
- High-tech sector (17%) and financial sector (14.6%) were the most targeted industries in 2025.
- North Korean IT worker incidents and cyber espionage campaigns had a median dwell time of 122 days.

## 5. Splunk Detection Searches

### Behavioral TTPs

#### Detecting Exploitation of Public-Facing Applications
```spl
index=web sourcetype=web_proxy
| search "POST" OR "GET"
| stats count by src_ip, uri_path
| where count > 100
| table src_ip, uri_path, count
```
# This search identifies potential exploitation attempts by looking for high-frequency requests to specific web application paths.

#### Detecting Voice Phishing (Vishing) Attempts
```spl
index=voip sourcetype=voip_logs
| search "call_type=outbound" AND "duration>300"
| stats count by src_number, dest_number
| where count > 10
| table src_number, dest_number, count
```
# This search identifies potential vishing attempts by analyzing outbound calls with unusually long durations.

#### Detecting OAuth Token Abuse
```spl
index=auth sourcetype=oauth_logs
| search "action=token_use" AND "token_type=OAuth"
| stats count by user, src_ip, app_name
| where count > 50
| table user, src_ip, app_name, count
```
# This search identifies potential abuse of OAuth tokens by monitoring high-frequency token usage.

#### Detecting Backup Object Deletion
```spl
index=cloud_storage sourcetype=storage_logs
| search "action=delete" AND "resource_type=backup"
| stats count by user, resource_name, src_ip
| where count > 10
| table user, resource_name, src_ip, count
```
# This search identifies suspicious deletion of backup objects in cloud storage environments.

#### Detecting Hypervisor Exploitation
```spl
index=vmware sourcetype=vmware_logs
| search "action=datastore_delete" OR "action=datastore_encrypt"
| stats count by user, vm_name, src_ip
| where count > 5
| table user, vm_name, src_ip, count
```
# This search identifies potential exploitation of hypervisors by monitoring datastore deletion or encryption activities.

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in adversary tactics, including the rise of voice phishing, the collapse of the hand-off window between initial access and secondary operations, and the evolution of ransomware into a recovery denial model. Sophisticated threat actors are increasingly targeting edge devices and exploiting zero-day vulnerabilities to establish extreme persistence. Organizations must adopt behavioral anomaly detection, extend log retention policies, and implement strict access controls to counter these advanced threats. Immediate action is recommended to isolate critical control planes, enhance visibility, and prepare for AI-driven threats.