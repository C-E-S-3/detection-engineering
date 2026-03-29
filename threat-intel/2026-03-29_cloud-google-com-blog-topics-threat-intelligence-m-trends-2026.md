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
- **T1190 - Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions in 2025.
- **T1566.002 - Spearphishing via Service**: Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078 - Valid Accounts**: Threat actors are leveraging prior compromises as an initial infection vector, particularly in ransomware operations (30%).

#### Persistence
- **T1505.003 - Server Software Component: Web Shell**: Threat actors are deploying custom, in-memory malware like the BRICKSTORM backdoor onto network appliances for deep persistence.
- **T1098 - Account Manipulation**: Exploiting misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

#### Defense Evasion
- **T1556.004 - Network Sniffing**: Adversaries are leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1556.004 - Credential Dumping**: Attackers are harvesting long-lived OAuth tokens and session cookies to bypass standard defenses.

#### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware groups are encrypting hypervisor datastores to render associated virtual machines inoperable.
- **T1485 - Data Destruction**: Ransomware operators are actively targeting backup infrastructure and deleting backup objects from cloud storage.

## 3. Malware & Tools
- **BRICKSTORM**: A custom, in-memory backdoor deployed on network appliances to achieve extreme persistence.
- **PROMPTFLUX and PROMPTSTEAL**: Malware families leveraging large language models (LLMs) mid-execution to evade detection.
- **QUIETVAULT**: A credential stealer that checks for local AI command-line tools and executes predefined prompts to search for configuration files.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira) and AGENDA (Qilin)**: Ransomware groups focusing on recovery denial by targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token and Session Cookie Harvesting
```spl
index=proxy_logs sourcetype=proxy 
| search "OAuth" OR "session cookie" 
| stats count by src_ip, dest_ip, user_agent, uri_path 
| table src_ip, dest_ip, user_agent, uri_path, count
```

### Detecting Malicious Activity on Edge Devices
```spl
index=network sourcetype=network_logs 
| search "packet-capture" OR "plaintext credentials" 
| stats count by src_ip, dest_ip, action 
| table src_ip, dest_ip, action, count
```

### Detecting Ransomware Targeting Backup Infrastructure
```spl
index=cloud sourcetype=cloud_storage_logs 
| search "delete" AND "backup" 
| stats count by user, src_ip, action 
| table user, src_ip, action, count
```

### Detecting Hypervisor Datastore Encryption
```spl
index=vmware sourcetype=vmware_logs 
| search "datastore" AND "encryption" 
| stats count by host, user, action 
| table host, user, action, count
```

### Detecting Voice Phishing Attempts
```spl
index=voip sourcetype=voip_logs 
| search "interactive" AND "voice" AND "phishing" 
| stats count by caller_id, callee_id, duration 
| table caller_id, callee_id, duration
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including a rise in global median dwell time and the emergence of new TTPs such as voice phishing and the use of AI in attacks. Notable threat actors like UNC3944 and ransomware groups such as REDBIKE and AGENDA are employing advanced techniques to evade detection and disrupt recovery efforts. Organizations are advised to adopt behavioral anomaly detection, extend log retention policies, and enhance identity verification processes to counter these evolving threats. Immediate action is recommended to address the risks posed by these sophisticated adversaries and their innovative attack methods.
