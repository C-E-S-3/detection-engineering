---
  scraped_at: "2026-03-23T00:00:00Z"
  source_url: "https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/"
  report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- No new IP addresses identified.

### Domains/URLs
- No new domains/URLs identified.

### File Hashes
- No new file hashes identified.

### Email Addresses
- No new email addresses identified.

### File Names/Paths
- No new file names/paths identified.

### Registry Keys
- No new registry keys identified.

### Mutex Names
- No new mutex names identified.

### C2 Infrastructure
- No new C2 infrastructure identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1190 - Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing via Service**: Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078 - Valid Accounts**: Prior compromise ranked as the third-most common initial infection vector (10%) globally and the top vector in ransomware operations (30%).

### Persistence
- **T1505.003 - Server Software Component: Web Shell**: Adversaries are deploying custom, in-memory malware like the BRICKSTORM backdoor onto network appliances for extreme persistence.
- **T1078.003 - Valid Accounts: Local Accounts**: Attackers exploit misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1556.004 - Network Sniffing**: Adversaries use native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1558.003 - Steal Application Access Token**: Threat actors harvest long-lived OAuth tokens and session cookies to bypass standard defenses.

### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware operators encrypt hypervisor datastores, rendering associated virtual machines inoperable.
- **T1485 - Data Destruction**: Ransomware groups actively destroy backup infrastructure, identity services, and virtualization management planes to deny recovery.

## 3. Malware & Tools
- **BRICKSTORM**: A custom, in-memory backdoor deployed on network appliances for extreme persistence, capable of surviving system reboots and standard remediation efforts.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families that query large language models (LLMs) mid-execution to evade detection.
- **QUIETVAULT**: A credential stealer that executes predefined prompts to search for configuration files on compromised machines.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge and core network devices like VPNs and routers for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups targeting backup infrastructure, identity services, and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token and Session Cookie Harvesting
```spl
index=proxy OR index=web
| search "OAuth" OR "session cookie"
| stats count by src_ip, dest_ip, http_user_agent, uri_path
| where count > 10
```

### Detecting Anomalous Bulk API Operations
```spl
index=api_logs
| stats count by user, api_endpoint, action
| where count > 100
```

### Detecting BRICKSTORM Backdoor Activity
```spl
index=network_logs
| search "BRICKSTORM"
| stats count by src_ip, dest_ip, protocol, action
```

### Detecting Ransomware Targeting Backup Infrastructure
```spl
index=filesystem_logs OR index=cloud_storage
| search "delete" OR "encrypt" AND ("backup" OR "snapshot")
| stats count by user, file_path, action
```

### Detecting Exploitation of Active Directory Certificate Services
```spl
index=wineventlog
EventCode=4662
| search "Certificate Services" AND "admin account"
| stats count by user, target_object, operation
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant advancements in adversary tactics, techniques, and procedures (TTPs) observed in 2025. Key trends include the rise of highly interactive voice phishing (vishing) as a major initial access vector, the evolution of ransomware to target recovery capabilities, and the increasing use of AI by threat actors to evade detection. Espionage groups are leveraging zero-day vulnerabilities and deploying in-memory malware like BRICKSTORM to achieve extreme persistence on edge devices. Organizations are advised to prioritize behavioral anomaly detection, extend log retention policies, and adopt continuous identity verification to counter these evolving threats.