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

- **Tactic: Initial Access**
  - **Technique ID:** T1190 (Exploit Public-Facing Application)
    - **Description:** Exploits remain the most common initial infection vector, accounting for 32% of intrusions in 2025.
  - **Technique ID:** T1566.002 (Spearphishing via Service)
    - **Description:** Surge in highly interactive voice phishing (vishing) targeting IT help desks to bypass MFA and gain access to SaaS environments.
  - **Technique ID:** T1078 (Valid Accounts)
    - **Description:** Threat actors are harvesting long-lived OAuth tokens and session cookies to bypass authentication mechanisms.

- **Tactic: Persistence**
  - **Technique ID:** T1505.003 (Server Software Component: Web Shell)
    - **Description:** Deployment of custom, in-memory malware like BRICKSTORM on edge devices to establish deep persistence.

- **Tactic: Impact**
  - **Technique ID:** T1486 (Data Encrypted for Impact)
    - **Description:** Ransomware operators targeting backup infrastructure, identity services, and virtualization management planes to destroy recovery capabilities.

- **Tactic: Credential Access**
  - **Technique ID:** T1552 (Unsecured Credentials)
    - **Description:** Threat actors steal hard-coded keys and personal access tokens from SaaS vendors to pivot into downstream environments.

## 3. Malware & Tools

- **BRICKSTORM:** Custom in-memory malware deployed on edge devices to establish deep persistence.
- **PROMPTFLUX and PROMPTSTEAL:** Malware families leveraging AI and large language models (LLMs) to evade detection.
- **QUIETVAULT:** Credential stealer that executes predefined prompts to search for configuration files on targeted machines.

## 4. Threat Actor / Campaign Attribution

- **UNC3944:** Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201 and UNC5807:** Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira) and AGENDA (Qilin):** Ransomware groups targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token Harvesting
```spl
index=proxy OR index=web
| search "OAuth" AND "token"
| stats count by src_ip, dest_ip, uri_path, user_agent
| where count > 10
| table src_ip, dest_ip, uri_path, user_agent
```

### Detecting Voice Phishing Activity
```spl
index=voip OR index=call_logs
| search "help desk" OR "MFA" OR "password reset"
| stats count by caller_id, callee_id, call_duration
| where call_duration > 300
| table caller_id, callee_id, call_duration
```

### Detecting In-Memory Malware (BRICKSTORM)
```spl
index=sysmon EventCode=10
| search "in-memory" AND "BRICKSTORM"
| stats count by ComputerName, ProcessName, ProcessID
| table _time, ComputerName, ProcessName, ProcessID
```

### Detecting Ransomware Targeting Backup Infrastructure
```spl
index=wineventlog EventCode=4663
| search Object_Type="File" AND Access_Mask="DELETE"
| stats count by ComputerName, Object_Name, Access_Mask
| table _time, ComputerName, Object_Name, Access_Mask
```

### Detecting Suspicious SaaS Token Usage
```spl
index=saas_logs
| search "token" AND "access"
| stats count by user, action, app_name
| where count > 5
| table _time, user, action, app_name
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in adversary tactics, including the rise of voice phishing, the use of AI-driven malware, and the targeting of edge devices for extreme persistence. Ransomware operators are increasingly focusing on destroying recovery capabilities, while espionage groups exploit zero-day vulnerabilities to establish long-term footholds. Organizations are advised to prioritize behavioral anomaly detection, extend log retention, and adopt robust identity verification measures to counter these evolving threats. Immediate action is recommended to address these advanced tactics and protect critical infrastructure.