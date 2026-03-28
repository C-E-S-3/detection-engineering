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

### Initial Access
- **T1190: Exploit Public-Facing Application**
  - Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**
  - High-interaction voice phishing (vishing) increased to 11%, becoming the second most common initial infection vector.
- **T1078: Valid Accounts**
  - Threat actors are using compromised credentials, including OAuth tokens and session cookies, to gain unauthorized access to systems.

### Persistence
- **T1098: Account Manipulation**
  - Attackers exploit misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.
- **T1547: Boot or Logon Autostart Execution**
  - Deployment of in-memory malware like BRICKSTORM on network appliances for extreme persistence.

### Credential Access
- **T1552: Unsecured Credentials**
  - Threat actors steal hard-coded keys and personal access tokens from third-party SaaS vendors.
- **T1557.002: Man-in-the-Middle: ARP Cache Poisoning**
  - Adversaries leverage native packet-capturing functionality on network devices to intercept sensitive data and plaintext credentials.

### Impact
- **T1485: Data Destruction**
  - Ransomware groups actively destroy backup infrastructure and virtualization management planes to prevent recovery.
- **T1486: Data Encrypted for Impact**
  - Attackers encrypt hypervisor datastores, rendering all associated virtual machines inoperable.

## 3. Malware & Tools
- **BRICKSTORM**: Custom in-memory malware deployed on network appliances for extreme persistence.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on local machines.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families that query large language models (LLMs) mid-execution to evade detection.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Behavioral TTPs

#### Detecting Exploitation of Public-Facing Applications
```spl
index=web sourcetype=webserver
| search "POST" OR "GET"
| stats count by src_ip, uri_path
| where count > 100
| table src_ip, uri_path, count
```
# This search identifies IPs making excessive requests to public-facing applications, which could indicate exploitation attempts.

#### Detecting Vishing Attempts
```spl
index=voip sourcetype=voip:logs
| search "call" AND "failed authentication"
| stats count by src_ip, dest_number
| where count > 10
| table src_ip, dest_number, count
```
# This search identifies repeated failed authentication attempts via voice calls, which could indicate vishing attempts.

#### Detecting OAuth Token Abuse
```spl
index=auth sourcetype=auth_logs
| search "OAuth" AND "token" AND "access"
| stats count by user, src_ip, action
| where action="token_used"
| table user, src_ip, action
```
# This search identifies suspicious OAuth token usage.

#### Detecting Backup Infrastructure Targeting
```spl
index=backup sourcetype=backup:logs
| search "delete" OR "modify"
| stats count by user, action, target
| where action IN ("delete", "modify")
| table user, action, target
```
# This search identifies unauthorized deletion or modification of backup objects.

#### Detecting Anomalous SaaS Token Usage
```spl
index=saas sourcetype=saas:logs
| search "token" AND "access"
| stats count by user, token_id, action
| where action="bulk_operation"
| table user, token_id, action
```
# This search identifies anomalous bulk operations using SaaS integration tokens.

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing (vishing) as a major initial access vector and the evolution of ransomware tactics to target recovery capabilities. Espionage groups are increasingly exploiting edge devices and zero-day vulnerabilities to establish extreme persistence, while cybercriminals are leveraging AI to enhance attack effectiveness. Organizations are advised to adopt behavioral anomaly detection, extend log retention, and implement strict access controls to mitigate these evolving threats.