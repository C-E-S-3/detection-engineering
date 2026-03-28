---
scraped_at: 2026-03-23T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
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

### Initial Access
- **T1190: Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions in 2025.
- **T1566.002: Spearphishing via Service**: Highly interactive voice phishing surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**: Threat actors are leveraging compromised credentials, including OAuth tokens and session cookies, to gain unauthorized access to systems and SaaS environments.

### Persistence
- **T1505.003: Web Shell**: Threat actors are deploying custom, in-memory malware like the BRICKSTORM backdoor on network appliances for deep persistence.
- **T1098.001: Account Manipulation**: Attackers exploit misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1558.003: Steal Application Access Token**: Adversaries are harvesting OAuth tokens and session cookies to bypass authentication mechanisms.
- **T1562.001: Impair Defenses - Disable or Modify Tools**: Ransomware operators target backup infrastructure and virtualization management planes to disable recovery capabilities.

### Credential Access
- **T1552.001: Credentials In Files**: Attackers steal hard-coded keys and personal access tokens from SaaS vendors to pivot into downstream environments.
- **T1557.002: Adversary-in-the-Middle**: Espionage groups leverage native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware operators encrypt data and target virtualization storage layers to render virtual machines inoperable.
- **T1485: Data Destruction**: Ransomware groups actively destroy backup objects and recovery capabilities, forcing organizations to rebuild or pay ransom.

## 3. Malware & Tools
- **BRICKSTORM**: A custom, in-memory backdoor deployed on network appliances for deep persistence.
- **QUIETVAULT**: A credential stealer that executes predefined prompts to search for configuration files on compromised machines.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families that query large language models (LLMs) mid-execution to evade detection.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token and Session Cookie Theft
```spl
index=* sourcetype=aws:cloudtrail eventName=GetSessionToken OR eventName=AssumeRole
| stats count by userName, sourceIPAddress, awsRegion, eventName
| where count > 1
```
# This search identifies unusual patterns of OAuth token or session cookie usage in AWS CloudTrail logs.

### Detecting Backup Infrastructure Targeting
```spl
index=* (sourcetype=aws:cloudtrail OR sourcetype=azure:activity) eventName IN ("DeleteBackup", "DeleteSnapshot", "DeleteVolume")
| stats count by userName, sourceIPAddress, eventName, awsRegion
| where count > 1
```
# This search identifies malicious activity targeting backup infrastructure in cloud environments.

### Detecting Anomalous SaaS Token Usage
```spl
index=* sourcetype=okta* "token" "access"
| stats count by user, client.ipAddress, client.userAgent
| where count > 1
```
# This search detects suspicious use of SaaS integration tokens in Okta logs.

### Detecting Hypervisor Targeting
```spl
index=* sourcetype=vmware:vsphere* "datastore" "delete"
| stats count by user, host, source
| where count > 1
```
# This search identifies potential malicious activity targeting VMware vSphere datastores.

### Detecting In-Memory Malware on Edge Devices
```spl
index=* sourcetype=network:device_logs "BRICKSTORM"
| stats count by src_ip, dest_ip, process_name
| where count > 0
```
# This search identifies the presence of the BRICKSTORM backdoor on network devices.

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, the collapse of the "hand-off" window between initial access and secondary operations, and the evolution of ransomware into a recovery denial model. Espionage groups are increasingly targeting edge devices and leveraging zero-day vulnerabilities for extreme persistence, while cybercriminals are exploiting SaaS environments and AI technologies to evade detection. Organizations must prioritize behavioral anomaly detection, extend log retention, and adopt robust identity verification measures to counter these advanced threats effectively.