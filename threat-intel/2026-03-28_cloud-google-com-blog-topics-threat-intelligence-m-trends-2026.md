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
- **T1190: Exploit Public-Facing Application**: Exploits were the most common initial infection vector, accounting for 32% of intrusions in 2025.
- **T1566.002: Spearphishing via Service**: Highly interactive voice phishing (vishing) surged to 11%, becoming the second most common initial infection vector.
- **T1078: Valid Accounts**: Prior compromise was the third-most common initial infection vector globally (10%) and the top vector in ransomware operations (30%).

### Persistence
- **T1505.003: Server Software Component - Web Shell**: Threat actors deploy custom in-memory malware like the BRICKSTORM backdoor directly onto network appliances for deep persistence.
- **T1098.003: Additional Cloud Credentials**: Attackers steal hard-coded keys and personal access tokens from third-party SaaS vendors to pivot into downstream environments.

### Defense Evasion
- **T1556.004: Network Sniffing**: Adversaries leverage native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1558.004: Steal or Forge Authentication Certificates**: Exploiting misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware operators encrypt hypervisor datastores, rendering associated virtual machines inoperable.
- **T1485: Data Destruction**: Ransomware groups actively destroy backup infrastructure and virtualization management planes to prevent recovery.

## 3. Malware & Tools
- **BRICKSTORM**: A custom in-memory backdoor deployed on network appliances for extreme persistence.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families leveraging AI/LLMs to evade detection.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on compromised machines.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups focusing on recovery denial by targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting BRICKSTORM Backdoor on Network Appliances
```spl
index=network_logs sourcetype=network:device
| search "BRICKSTORM"
| stats count by src_ip, dest_ip, dest_port
| table src_ip, dest_ip, dest_port, count
```

### Detecting OAuth Token and Session Cookie Harvesting
```spl
index=proxy_logs OR index=web_logs
| search "OAuth" OR "session cookie"
| stats count by src_ip, dest_ip, uri_path
| table src_ip, dest_ip, uri_path, count
```

### Detecting Exploitation of Active Directory Certificate Services
```spl
index=windows_logs EventCode=4662
| search "Certificate Services" "Admin Accounts"
| stats count by user, host, message
| table user, host, message, count
```

### Detecting Hypervisor Datastore Encryption
```spl
index=vmware_logs sourcetype=vmware:esxi
| search "datastore encryption" OR "hypervisor attack"
| stats count by host, message
| table host, message, count
```

### Detecting Voice Phishing (Vishing) Attempts
```spl
index=voip_logs sourcetype=voip:call_logs
| search "interactive voice" OR "vishing"
| stats count by caller_id, callee_id, duration
| table caller_id, callee_id, duration, count
```

## 6. Executive Summary
The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of highly interactive voice phishing (vishing) and the evolution of ransomware into recovery denial attacks. Threat actors are increasingly targeting edge devices and exploiting zero-day vulnerabilities to establish extreme persistence. Additionally, adversaries are leveraging AI to evade detection and accelerate attack lifecycles. Organizations must adopt behavioral anomaly detection, extend log retention policies, and implement strict identity verification measures to counter these advanced threats. Immediate action is recommended to enhance visibility, secure critical infrastructure, and prepare for AI-driven threats.