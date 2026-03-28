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

### Initial Access
- **T1190: Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**: Increased use of highly interactive voice phishing (vishing) to bypass MFA and gain access to SaaS environments.
- **T1078: Valid Accounts**: Threat actors are leveraging stolen credentials, including OAuth tokens and session cookies, to gain unauthorized access to SaaS environments.

### Persistence
- **T1505.003: Web Shell**: Threat actors deploy custom in-memory malware like the BRICKSTORM backdoor on network appliances to achieve persistence.
- **T1098: Account Manipulation**: Exploiting misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1556.004: Network Sniffing**: Leveraging native packet-capturing functionality on edge devices to intercept sensitive data and credentials.
- **T1557.002: Man-in-the-Middle**: Exploiting zero-day vulnerabilities in edge devices to intercept network traffic.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware groups encrypting hypervisor datastores to render all associated virtual machines inoperable.
- **T1485: Data Destruction**: Ransomware operators actively targeting backup infrastructure and deleting backup objects from cloud storage.

## 3. Malware & Tools
- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for extreme persistence.
- **QUIETVAULT**: Credential stealer that targets local AI command-line tools to extract configuration files.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families leveraging large language models (LLMs) to evade detection.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge and core network devices like VPNs and routers for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting Voice Phishing Attempts
```spl
index=voip_logs sourcetype=voip:logs "call setup" AND "unknown number"
| stats count by src_ip, dest_ip, caller_id
| where count > 10
| table src_ip, dest_ip, caller_id, count
```

### Detecting OAuth Token and Session Cookie Abuse
```spl
index=web_logs sourcetype=web:proxy "OAuth" OR "session cookie"
| stats count by user, src_ip, dest_ip, uri
| where count > 5
| table user, src_ip, dest_ip, uri, count
```

### Detecting Exploitation of Public-Facing Applications
```spl
index=web_logs sourcetype=web:access "POST" AND ("/wp-admin" OR "/login")
| stats count by src_ip, uri, user_agent
| where count > 10
| table src_ip, uri, user_agent, count
```

### Detecting Backup Infrastructure Targeting
```spl
index=backup_logs sourcetype=backup:events "delete" OR "remove" OR "purge"
| stats count by user, src_ip, dest_ip, action
| where count > 5
| table user, src_ip, dest_ip, action, count
```

### Detecting Edge Device Exploitation
```spl
index=network_logs sourcetype=network:firewall "VPN" OR "router" AND "packet capture"
| stats count by src_ip, dest_ip, action
| where count > 5
| table src_ip, dest_ip, action, count
```

## 6. Executive Summary
The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing (vishing) as a major initial access vector and the evolution of ransomware tactics to target backup infrastructure and virtualization management planes. Espionage groups are increasingly exploiting zero-day vulnerabilities in edge devices for extreme persistence, while cybercriminals are leveraging AI to enhance their attack capabilities. Organizations are advised to adopt behavioral anomaly detection, extend log retention policies, and implement strict access controls to counter these emerging threats. Immediate action is recommended to address these evolving tactics and bolster resilience against sophisticated adversaries.
