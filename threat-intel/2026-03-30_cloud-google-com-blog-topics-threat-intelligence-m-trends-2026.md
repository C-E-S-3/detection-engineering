---
scraped_at: "2026-03-23T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified

### File Hashes
- None identified

### IP Addresses
- None identified

### Other IOCs
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques

- **Tactic: Initial Access**
  - **T1190: Exploit Public-Facing Application**: Exploits remained the most common initial infection vector, accounting for 32% of intrusions.
  - **T1566.002: Spearphishing via Service**: Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
  - **T1078: Valid Accounts**: Threat actors leveraged prior compromises (10% of intrusions globally) to gain initial access.

- **Tactic: Persistence**
  - **T1505.003: Web Shell**: Adversaries pre-staged secondary group malware or tunnels during initial infections.
  - **T1547.001: Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder**: Attackers exploited misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.
  - **T1547.006: Boot or Logon Autostart Execution: Kernel Modules and Extensions**: Custom in-memory malware like BRICKSTORM was deployed on network appliances to establish deep persistence.

- **Tactic: Credential Access**
  - **T1552.001: Unsecured Credentials: Credentials In Files**: Attackers stole hard-coded keys and personal access tokens from third-party SaaS vendors.
  - **T1557.002: Man-in-the-Middle: ARP Cache Poisoning**: Adversaries used native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

- **Tactic: Impact**
  - **T1485: Data Destruction**: Ransomware groups actively destroyed recovery capabilities by targeting backup infrastructure and deleting backup objects from cloud storage.
  - **T1486: Data Encrypted for Impact**: Ransomware operators encrypted hypervisor datastores, rendering associated virtual machines inoperable.

## 3. Malware & Tools

- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for extreme persistence.
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware targeting backup and identity services.
- **PROMPTFLUX and PROMPTSTEAL**: Malware families leveraging AI to evade detection.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **North Korean IT workers**: Associated with cyber espionage campaigns with a median dwell time of 122 days.

## 5. Splunk Detection Searches

### Detecting Voice Phishing (T1566.002)
```spl
index=voip_logs sourcetype=voip:logs "call" AND ("MFA" OR "password reset" OR "authentication")
| stats count by src_ip, dest_ip, user, call_id
| where count > 10
```
*# This search identifies unusual patterns in VoIP logs, such as repeated calls involving MFA or password reset requests.*

### Detecting OAuth Token Abuse
```spl
index=cloud_logs sourcetype=google:workspace "OAuth token" AND ("access" OR "refresh")
| stats count by user, app_name, action
| where count > 5
```
*# This search detects suspicious activity involving OAuth tokens in Google Workspace logs.*

### Detecting Backup Infrastructure Targeting (T1485)
```spl
index=backup_logs sourcetype=backup:events "delete" OR "remove" OR "destroy"
| stats count by user, action, target
| where count > 10
```
*# This search identifies potential malicious deletion of backup objects.*

### Detecting Hypervisor Targeting (T1486)
```spl
index=vmware sourcetype=vmware:logs "datastore" AND ("delete" OR "encrypt")
| stats count by host, action, user
| where count > 5
```
*# This search detects suspicious activity targeting hypervisor datastores.*

### Detecting Edge Device Exploitation (T1557.002)
```spl
index=network_logs sourcetype=network:device "packet capture" OR "sniffing" OR "ARP poisoning"
| stats count by src_ip, dest_ip, action
| where count > 5
```
*# This search identifies potential exploitation of edge devices for packet capturing or ARP poisoning.*

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, the collapse of the hand-off window between initial access and secondary operations, and the evolution of ransomware into a recovery denial model. Espionage groups are increasingly targeting edge devices for extreme persistence, leveraging zero-day vulnerabilities and custom in-memory malware like BRICKSTORM. Organizations are advised to prioritize behavioral anomaly detection, extend log retention policies, and implement strict access controls for critical infrastructure. Immediate action is recommended to address these emerging threats and enhance operational resilience.