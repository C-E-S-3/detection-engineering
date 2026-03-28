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
- **T1190: Exploit Public-Facing Application**
  - Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**
  - Surge in highly interactive voice phishing (vishing) targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **T1078: Valid Accounts**
  - Attackers leveraging stolen OAuth tokens, session cookies, and hard-coded keys to gain unauthorized access to SaaS environments.

### Persistence
- **T1505.003: Server Software Component**
  - Deployment of in-memory malware like BRICKSTORM on edge devices for extreme persistence.
- **T1098: Account Manipulation**
  - Exploitation of misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Credential Access
- **T1552.001: Credentials In Files**
  - Harvesting long-lived OAuth tokens and session cookies.
- **T1557.002: Adversary-in-the-Middle**
  - Leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

### Impact
- **T1486: Data Encrypted for Impact**
  - Ransomware groups encrypting hypervisor datastores to render associated virtual machines inoperable.
- **T1490: Inhibit System Recovery**
  - Targeting backup infrastructure, identity services, and virtualization management planes to destroy recovery capabilities.

## 3. Malware & Tools

- **BRICKSTORM**: Custom in-memory malware deployed on network appliances for deep persistence.
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware targeting backup environments and hypervisor datastores.
- **QUIETVAULT**: Credential stealer that checks for local AI command-line tools to execute predefined prompts for configuration file searches.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families leveraging large language models (LLMs) for detection evasion.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups focusing on recovery denial by targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token and Session Cookie Harvesting
```spl
index=proxy OR index=web
| search uri_path="*/oauth2/token" OR uri_path="*/session/cookie"
| stats count by src_ip, dest_ip, uri_path, user_agent
| where count > 10
| table src_ip, dest_ip, uri_path, user_agent, count
```

### Detecting Ransomware Targeting Hypervisor Datastores
```spl
index=vmware OR index=virtualization
| search "datastore" AND ("encrypt" OR "delete")
| stats count by host, user, command, _time
| where count > 5
| table host, user, command, _time, count
```

### Detecting Edge Device Packet Capturing
```spl
index=network
| search "packet capture" OR "pcap" OR "tcpdump"
| stats count by src_ip, dest_ip, process_name, _time
| where count > 5
| table src_ip, dest_ip, process_name, _time, count
```

### Detecting Voice Phishing Attempts
```spl
index=voip OR index=telephony
| search "call" AND ("help desk" OR "password reset" OR "MFA")
| stats count by caller_id, callee_id, call_duration, _time
| where call_duration > 60
| table caller_id, callee_id, call_duration, _time
```

### Detecting BRICKSTORM Malware on Edge Devices
```spl
index=network OR index=firewall
| search "BRICKSTORM" OR "in-memory malware"
| stats count by src_ip, dest_ip, file_name, process_name, _time
| table src_ip, dest_ip, file_name, process_name, _time
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant advancements in adversary tactics, including a rise in dwell times, increased use of voice phishing, and the evolution of ransomware into a recovery denial model. Sophisticated threat actors are leveraging edge devices and zero-day vulnerabilities to establish extreme persistence, while cybercriminals are accelerating the attack lifecycle through pre-staged malware and rapid hand-offs. Organizations are advised to prioritize behavioral anomaly detection, extend log retention, and secure critical control planes to counter these emerging threats effectively.