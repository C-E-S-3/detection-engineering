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

### Other IOCs
- No other IOCs identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1190: Exploit Public-Facing Application**: Exploits remained the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing Link**: Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**: Prior compromise was the third-most common initial infection vector globally (10%) and the top vector in ransomware operations (30%).

### Persistence
- **T1505.003: Web Shell**: Adversaries pre-stage secondary group malware or tunnels during the initial infection.
- **T1505.003: Web Shell**: Deployment of custom, in-memory malware like the BRICKSTORM backdoor on network appliances for deep persistence.

### Credential Access
- **T1552.001: Credentials in Files**: Threat actors steal hard-coded keys and personal access tokens from compromised third-party SaaS vendors.
- **T1557.002: Adversary-in-the-Middle**: Adversaries use native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

### Defense Evasion
- **T1556.004: Network Sniffing**: Adversaries leverage native packet-capturing functionality on edge devices to evade detection.
- **T1556.005: Network Device Authentication**: Exploitation of misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware groups encrypt hypervisor datastores to render associated virtual machines inoperable.
- **T1485: Data Destruction**: Ransomware groups destroy backup infrastructure and delete backup objects from cloud storage to prevent recovery.

## 3. Malware & Tools

- **BRICKSTORM**: A custom, in-memory backdoor deployed on network appliances for extreme persistence.
- **PROMPTFLUX**: Malware leveraging large language models (LLMs) mid-execution to evade detection.
- **PROMPTSTEAL**: Malware leveraging LLMs for evasion.
- **QUIETVAULT**: Credential stealer targeting local AI command-line tools to search for configuration files.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201**: Targets edge and core network devices for extreme persistence.
- **UNC5807**: Focuses on exploiting edge devices and leveraging zero-day vulnerabilities.
- **REDBIKE (Akira)**: Ransomware group targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware group employing destructive tactics.

## 5. Splunk Detection Searches

### Detecting Exploitation of Public-Facing Applications
```spl
index=web proxy
| search "POST" OR "GET"
| stats count by uri_path, src_ip, http_user_agent
| where count > 100
```

### Detecting Voice Phishing (Vishing) Activity
```spl
index=telephony_logs
| search "interactive voice" OR "vishing"
| stats count by caller_id, callee_id, call_duration
| where call_duration > 300
```

### Detecting Misconfigured Active Directory Certificate Services
```spl
index=windows
sourcetype=XmlWinEventLog:Security
EventCode=4769
| stats count by TargetUserName, ServiceName, TicketOptions
| where TicketOptions="0x40810000"
```

### Detecting BRICKSTORM Backdoor Activity
```spl
index=network
| search "packet capture" OR "BRICKSTORM"
| stats count by src_ip, dest_ip, protocol
| where protocol="TCP" AND count > 100
```

### Detecting OAuth Token Abuse
```spl
index=saas_logs
| search "OAuth token" OR "session cookie"
| stats count by user, app, action
| where action="access" AND user="unknown"
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant advancements in adversary tactics, including the rise of voice phishing (vishing), extreme persistence on edge devices, and destructive ransomware operations. Key malware families such as BRICKSTORM and PROMPTFLUX demonstrate the increasing sophistication of attackers. Organizations are urged to adopt behavioral anomaly detection, extend log retention, and secure critical control planes to mitigate these threats. Immediate action is recommended to address visibility gaps and enhance resilience against evolving adversary techniques.