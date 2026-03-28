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
- **T1190: Exploit Public-Facing Application**
  - Exploits remained the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**
  - Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**
  - Threat actors are leveraging stolen credentials, including OAuth tokens and session cookies, to gain unauthorized access to SaaS environments.

#### Persistence
- **T1505.003: Web Shell**
  - Adversaries are deploying custom, in-memory malware like the BRICKSTORM backdoor on edge devices to establish deep persistence.

#### Defense Evasion
- **T1027: Obfuscated Files or Information**
  - Malware families like PROMPTFLUX and PROMPTSTEAL use AI to evade detection by querying large language models (LLMs) mid-execution.
- **T1556.004: Network Device Authentication**
  - Exploitation of misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

#### Credential Access
- **T1552.001: Credentials in Files**
  - Threat actors are stealing hard-coded keys and personal access tokens from third-party SaaS vendors.
- **T1557.002: Man-in-the-Middle**
  - Adversaries are leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

#### Impact
- **T1486: Data Encrypted for Impact**
  - Ransomware operators are encrypting hypervisor datastores to render associated virtual machines inoperable.
- **T1485: Data Destruction**
  - Ransomware operators are actively destroying backup infrastructure and virtualization management planes to prevent recovery.

## 3. Malware & Tools

- **BRICKSTORM**: A custom, in-memory backdoor deployed on network appliances to establish deep persistence.
- **PROMPTFLUX**: Malware family that queries large language models (LLMs) mid-execution to evade detection.
- **PROMPTSTEAL**: Malware family leveraging AI for evasion.
- **QUIETVAULT**: Credential stealer that targets local AI command-line tools to extract configuration files.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201**: Targets edge and core network devices, leveraging zero-day vulnerabilities and deploying custom malware for persistence.
- **UNC5807**: Similar to UNC6201, focuses on extreme persistence by targeting edge devices and core network appliances.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups targeting backup infrastructure, identity services, and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token Theft
```spl
index=proxy_logs sourcetype=bluecoat:proxysg OR sourcetype=pan:threat
| search uri_path="*/oauth2/token"
| stats count by src_ip, dest_ip, uri_path, user_agent
| where count > 10
```

### Detecting Voice Phishing Activity
```spl
index=voip_logs sourcetype=cisco:voip OR sourcetype=asterisk:voip
| search "call_type=outbound" AND "destination_country=US"
| stats count by src_ip, dest_ip, caller_id, callee_id
| where count > 5
```

### Detecting Hypervisor Datastore Encryption
```spl
index=vmware_logs sourcetype=vmware:vsphere
| search "datastore" AND ("encryption" OR "lock")
| stats count by host, user, action
| where count > 3
```

### Detecting Packet Capturing on Edge Devices
```spl
index=network_device_logs sourcetype=cisco:ios OR sourcetype=juniper:junos
| search "packet capture" OR "tcpdump"
| stats count by src_ip, dest_ip, command
| where count > 2
```

### Detecting Backup Deletion in Cloud Environments
```spl
index=cloud_logs sourcetype=aws:cloudtrail OR sourcetype=azure:activity OR sourcetype=gcp:activity
| search "DeleteObject" AND ("backup" OR "snapshot")
| stats count by user, src_ip, resource_name
| where count > 1
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing (vishing) as a major initial access vector and the increasing use of AI by adversaries to evade detection. Ransomware groups are evolving their tactics to target backup infrastructure and virtualization management planes, creating systemic resilience challenges for organizations. Espionage groups are focusing on extreme persistence by exploiting zero-day vulnerabilities in edge devices and deploying in-memory malware like BRICKSTORM. Organizations are advised to adopt behavioral anomaly detection, extend log retention policies, and implement strict access controls to counter these emerging threats.