---
scraped_at: 2026-03-23T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified in the source.

### Domains/URLs
- None identified in the source.

### File Hashes
- None identified in the source.

### Email Addresses
- None identified in the source.

### File Names/Paths
- None identified in the source.

### Registry Keys
- None identified in the source.

### Mutex Names
- None identified in the source.

### C2 Infrastructure
- None identified in the source.

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1190: Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**: High-interactive voice phishing surged to 11%, becoming the second-most common vector.
- **T1078: Valid Accounts**: Prior compromise ranked as the third-most common initial infection vector globally (10%).

### Persistence
- **T1505.003: Web Shell**: Adversaries deploy custom in-memory malware like BRICKSTORM on edge devices for extreme persistence.
- **T1098: Account Manipulation**: Exploitation of misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1556.004: Network Sniffing**: Adversaries use native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1552.004: Credential Dumping**: Harvesting long-lived OAuth tokens and session cookies to bypass standard defenses.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware operators encrypt hypervisor datastores, rendering associated virtual machines inoperable.
- **T1485: Data Destruction**: Attackers actively delete backup objects from cloud storage and target virtualization storage layers.

## 3. Malware & Tools

### Malware Families
- **BRICKSTORM**: Custom in-memory backdoor deployed on edge devices for extreme persistence.
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware targeting backup environments and identity services.
- **PROMPTFLUX**: Malware leveraging large language models (LLMs) for evasion.
- **PROMPTSTEAL**: Malware querying LLMs mid-execution to evade detection.
- **QUIETVAULT**: Credential stealer targeting local AI command-line tools to extract configuration files.

### Tools
- **Native Packet-Capturing Functionality**: Used on edge devices to intercept sensitive data and credentials.

## 4. Threat Actor / Campaign Attribution

### Threat Actors
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201**: Exploits edge and core network devices for extreme persistence.
- **UNC5807**: Targets VPNs and routers for long-term persistence.

### Campaigns
- **ShinyHunters-Branded SaaS Data Theft**: Focused on harvesting OAuth tokens and session cookies from SaaS environments.

### Targeted Sectors/Geographies
- High-tech sector (17% of incidents in 2025).
- Financial sector (14.6% of incidents in 2025).

## 5. Splunk Detection Searches

### Detecting OAuth Token and Session Cookie Harvesting
```spl
index=proxy_logs sourcetype=proxy_logs
| search "OAuth" OR "session cookie"
| stats count by src_ip, dest_ip, user, uri_path
| where count > 10
| table src_ip, dest_ip, user, uri_path, count
```

### Detecting Malicious Edge Device Activity
```spl
index=network sourcetype=network_logs
| search "packet capture" OR "plaintext credentials"
| stats count by src_ip, dest_ip, device_type
| where count > 5
| table src_ip, dest_ip, device_type, count
```

### Detecting Ransomware Targeting Backup Infrastructure
```spl
index=cloud sourcetype=cloud_storage_logs
| search "delete" AND "backup"
| stats count by user, action, resource
| where action="delete" AND resource="backup"
| table user, action, resource, count
```

### Detecting Voice Phishing Activity
```spl
index=call_logs sourcetype=voip_logs
| search "interactive voice" OR "vishing"
| stats count by caller_id, callee_id, call_duration
| where call_duration > 300
| table caller_id, callee_id, call_duration
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, the evolution of ransomware into recovery denial, and the exploitation of edge devices for extreme persistence. Notable malware families like BRICKSTORM and PROMPTFLUX demonstrate advanced adversary capabilities, including the use of AI for evasion. Organizations must prioritize behavioral anomaly detection, extend log retention policies, and isolate critical control planes to mitigate these emerging threats. Immediate action is recommended to address these vulnerabilities and enhance resilience against sophisticated adversaries.
