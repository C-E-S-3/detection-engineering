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
- **T1190: Exploit Public-Facing Application**
  - Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**
  - High-interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**
  - Attackers use stolen credentials, including OAuth tokens and session cookies, to gain unauthorized access.

### Persistence
- **T1505.003: Web Shell**
  - Adversaries deploy custom in-memory malware like the BRICKSTORM backdoor on network appliances for deep persistence.
- **T1556.004: Network Device Authentication**
  - Exploitation of misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1070: Indicator Removal on Host**
  - Attackers delete backup objects from cloud storage to prevent recovery.
- **T1562.001: Disable or Modify Tools**
  - Exploitation of hypervisors to bypass guest-level defenses.

### Credential Access
- **T1552.001: Credentials in Files**
  - Harvesting long-lived OAuth tokens and session cookies from compromised SaaS environments.
- **T1557.002: Man-in-the-Middle**
  - Leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

### Impact
- **T1486: Data Encrypted for Impact**
  - Ransomware operators encrypt hypervisor datastores, rendering associated virtual machines inoperable.
- **T1485: Data Destruction**
  - Ransomware groups actively destroy recovery capabilities by targeting backup infrastructure and virtualization management planes.

## 3. Malware & Tools

### Malware Families
- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for deep persistence.
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware with similar destructive capabilities as REDBIKE.
- **PROMPTFLUX**: Malware leveraging large language models (LLMs) for detection evasion.
- **PROMPTSTEAL**: Malware using LLMs to evade detection.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on compromised machines.

### Tools
- Native packet-capturing functionality on edge devices used for data interception.
- AI command-line tools exploited for configuration file searches.

## 4. Threat Actor / Campaign Attribution

### Threat Actors
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201**: Targets edge and core network devices for extreme persistence.
- **UNC5807**: Similar to UNC6201, focuses on edge and core network devices.

### Campaigns
- **ShinyHunters-Branded SaaS Data Theft**: Focused on harvesting OAuth tokens and session cookies to compromise SaaS environments.

### Targeted Sectors/Geographies
- High-tech sector (17%) and financial sector (14.6%) were the most targeted industries in 2025.
- North Korean IT worker incidents and cyber espionage campaigns had a median dwell time of 122 days.

## 5. Splunk Detection Searches

### Behavioral TTPs
#### Detecting OAuth Token Harvesting
```spl
| tstats `security_content_summariesonly` count from datamodel=Authentication where Authentication.action="success" Authentication.app="SaaS" by Authentication.src, Authentication.user
| search Authentication.src IN ("known_suspicious_ips")
| table Authentication.src, Authentication.user, count
```
*Comment: This search identifies successful SaaS logins from known suspicious IPs, which could indicate OAuth token abuse.*

#### Detecting Hypervisor Targeting
```spl
index=vmware sourcetype="vmware:vsphere:log" "backup deletion" OR "datastore encryption"
| stats count by host, user, _time
```
*Comment: This search identifies suspicious activities targeting hypervisor datastores or backup deletion events.*

#### Detecting Voice Phishing Attempts
```spl
index=voip_logs "unusual call patterns" OR "high call volume" | stats count by src_ip, dest_number, _time
```
*Comment: This search identifies unusual call patterns or high call volumes that may indicate voice phishing attempts.*

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including a rise in global median dwell time and an increase in sophisticated tactics by both cybercriminals and espionage groups. Key trends include the rise of voice phishing, the collapse of the hand-off window between initial access and secondary operations, and the evolution of ransomware into recovery denial attacks. Notable malware families such as BRICKSTORM, REDBIKE, and QUIETVAULT have emerged, targeting edge devices, SaaS environments, and virtualization layers. Organizations are advised to adopt behavioral anomaly detection, extend log retention, and implement strict access controls to counter these evolving threats.