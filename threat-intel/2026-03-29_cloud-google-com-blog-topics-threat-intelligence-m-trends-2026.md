---
  scraped_at: "2026-03-23T00:00:00Z"
  source_url: "https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/"
  report_type: "threat-intel"
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
- **T1190: Exploit Public-Facing Application**: Exploits remained the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**: High-interaction voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**: Threat actors are leveraging stolen credentials, including hard-coded keys and personal access tokens, to gain unauthorized access to SaaS environments.

### Persistence
- **T1505.003: Server Software Component - Web Shell**: Adversaries are deploying custom, in-memory malware like the BRICKSTORM backdoor onto edge devices for extreme persistence.
- **T1098: Account Manipulation**: Attackers exploit misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1556.004: Network Sniffing**: Adversaries leverage native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1552.004: Unsecured Credentials - Private Keys**: Threat actors steal hard-coded keys and personal access tokens from compromised SaaS vendors.
- **T1558.004: Steal or Forge Kerberos Tickets - Golden Ticket**: Attackers exploit Active Directory misconfigurations to create admin accounts.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware groups encrypt hypervisor datastores, rendering all associated virtual machines inoperable.
- **T1485: Data Destruction**: Ransomware operators actively destroy backup infrastructure and virtualization management planes to deny recovery.

## 3. Malware & Tools
- **BRICKSTORM**: A custom, in-memory backdoor deployed on edge devices for extreme persistence.
- **QUIETVAULT**: A credential stealer that targets local AI command-line tools to extract sensitive configuration files.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families that use large language models (LLMs) mid-execution to evade detection.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting Voice Phishing (Vishing) Attempts
```spl
index=voip_logs sourcetype=voip:logs
| search "call_type=external" "duration>300"
| stats count by src_ip, dest_ip, user
| where count > 10
| table src_ip, dest_ip, user, count
```
# This search identifies external calls lasting longer than 5 minutes, which may indicate vishing attempts.

### Detecting OAuth Token Misuse
```spl
index=saas_logs sourcetype=saas:auth
| search "action=token_use" "token_type=oauth"
| stats count by user, src_ip, app_name
| where count > 5
| table user, src_ip, app_name, count
```
# This search identifies anomalous OAuth token usage across SaaS applications.

### Detecting Hypervisor Datastore Access
```spl
index=vmware sourcetype=vmware:logs
| search "datastore" "delete" OR "encrypt"
| stats count by user, action, target
| where count > 1
| table user, action, target, count
```
# This search identifies suspicious access or modification of hypervisor datastores.

### Detecting Packet Capturing on Edge Devices
```spl
index=network_logs sourcetype=network:device
| search "packet_capture" "start"
| stats count by src_ip, dest_ip, action
| where count > 1
| table src_ip, dest_ip, action, count
```
# This search identifies unauthorized packet-capturing activity on network devices.

## 6. Executive Summary
The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, the evolution of ransomware into recovery denial, and the exploitation of edge devices for extreme persistence. Notable threat actors such as UNC3944, UNC6201, and ransomware groups like REDBIKE and AGENDA have adopted advanced TTPs to evade detection and maximize impact. Organizations are advised to prioritize behavioral anomaly detection, extend log retention policies, and implement robust identity verification measures to counter these evolving threats. Immediate action is recommended to address vulnerabilities in Active Directory, SaaS environments, and virtualization platforms.