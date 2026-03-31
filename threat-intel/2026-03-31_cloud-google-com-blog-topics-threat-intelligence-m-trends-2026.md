---
scraped_at: 2026-03-23T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified.

### Domains/URLs
- None identified.

### File Hashes
- None identified.

### Email Addresses
- None identified.

### File Names/Paths
- None identified.

### Registry Keys
- None identified.

### Mutex Names
- None identified.

### C2 Infrastructure
- None identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1190 - Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing via Service**: High-interactive voice phishing surged to 11% of intrusions, targeting IT help desks to bypass MFA.
- **T1078 - Valid Accounts**: Adversaries use stolen OAuth tokens and session cookies to bypass standard defenses.

### Persistence
- **T1505.003 - Server Software Component**: Deployment of custom in-memory malware like BRICKSTORM on edge devices to establish persistence.

### Defense Evasion
- **T1070.004 - File Deletion**: Attackers actively delete backup objects from cloud storage.
- **T1553.004 - Abuse Elevation Control Mechanism: Certificate Authority**: Exploiting misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware operators encrypt hypervisor datastores, rendering virtual machines inoperable.
- **T1490 - Inhibit System Recovery**: Targeting backup infrastructure and virtualization management planes to destroy recovery capabilities.

## 3. Malware & Tools
- **BRICKSTORM**: Custom in-memory malware deployed on network appliances for deep persistence.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families leveraging AI to evade detection.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on compromised machines.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge devices like VPNs and routers for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token and Session Cookie Theft
```spl
index=proxy OR index=web
| search "OAuth" OR "session cookie"
| stats count by src_ip, dest_ip, uri_path, user_agent
| where count > 10
| table src_ip, dest_ip, uri_path, user_agent
```

### Detecting Backup Object Deletion in Cloud Storage
```spl
index=cloud_logs sourcetype=aws:cloudtrail
| search eventName=DeleteObject
| stats count by userIdentity.arn, requestParameters.bucketName, requestParameters.key
| where count > 5
```

### Detecting Hypervisor Datastore Encryption
```spl
index=vmware sourcetype=vmware:esxi
| search "datastore" AND "encryption"
| stats count by host, user, message
| where count > 1
```

### Detecting BRICKSTORM Malware Activity
```spl
index=network sourcetype=network_traffic
| search "packet-capture" OR "plaintext credentials"
| stats count by src_ip, dest_ip, protocol
| where count > 5
```

### Detecting Voice Phishing Attempts
```spl
index=telephony sourcetype=voip:logs
| search "help desk" OR "MFA" OR "password reset"
| stats count by caller_id, callee_id, duration
| where duration > 300
```

## 6. Executive Summary

The M-Trends 2026 report highlights evolving adversary tactics, including the rise of voice phishing, the use of AI in malware, and ransomware targeting recovery infrastructure. Espionage groups are leveraging zero-days and targeting edge devices for extreme persistence. Organizations must prioritize behavioral anomaly detection, extend log retention, and isolate critical control planes to mitigate these threats. Immediate action is recommended to address these advanced tactics and secure critical infrastructure.