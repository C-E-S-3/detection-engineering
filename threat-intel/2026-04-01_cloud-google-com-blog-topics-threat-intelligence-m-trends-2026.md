---
scraped_at: 2026-03-23T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
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
- **T1190 - Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spear Phishing via Service**: High-interaction voice phishing (vishing) surged to 11%, becoming the second-most common vector.
- **T1078 - Valid Accounts**: Prior compromise ranked as the third-most common initial infection vector globally (10%) and the top vector in ransomware operations (30%).

### Persistence
- **T1505.003 - Server Software Component: Web Shells**: Attackers deploy custom, in-memory malware like BRICKSTORM on edge devices to establish deep persistence.
- **T1098 - Account Manipulation**: Misconfigured Active Directory Certificate Services templates exploited to create admin accounts bypassing password rotation.

### Defense Evasion
- **T1553.002 - Subvert Trust Controls: Code Signing**: Attackers exploit misconfigured certificate services to bypass defenses.
- **T1562.001 - Impair Defenses: Disable or Modify Tools**: Backup objects in cloud storage are actively deleted by attackers.

### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware groups encrypt hypervisor datastores, rendering virtual machines inoperable.
- **T1490 - Inhibit System Recovery**: Backup infrastructure and virtualization management planes are targeted to destroy recovery capabilities.

## 3. Malware & Tools

- **BRICKSTORM**: Custom in-memory malware deployed on network appliances for persistence.
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware with similar destructive capabilities.
- **QUIETVAULT**: Credential stealer leveraging local AI command-line tools for reconnaissance.
- **PROMPTFLUX & PROMPTSTEAL**: Malware families leveraging AI to evade detection.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain SaaS access.
- **UNC6201 & UNC5807**: Espionage groups targeting edge devices like VPNs and routers for extreme persistence.
- **North Korean IT Workers**: Associated with prolonged dwell times (122 days).

## 5. Splunk Detection Searches

### Behavioral Detection for Voice Phishing (T1566.002)
```spl
index=proxy OR index=firewall
| search "voice phishing" OR "vishing" OR "interactive social engineering"
| stats count by src_ip, dest_ip, user
| where count > 10
```

### Detection of BRICKSTORM Malware on Edge Devices (T1505.003)
```spl
index=network
| search "BRICKSTORM" OR "custom in-memory malware"
| stats count by device_ip, device_type
```

### Monitoring for Ransomware Targeting Backup Infrastructure (T1490)
```spl
index=cloud_storage
| search "delete" AND "backup" AND ("REDBIKE" OR "AGENDA")
| stats count by user, action, resource
```

### Detection of Misconfigured Certificate Services Exploitation (T1098)
```spl
index=windows
EventCode=4768 OR EventCode=4769
| search "certificate template" AND "admin account"
| stats count by user, template_name
```

### Monitoring for OAuth Token Abuse (T1553.002)
```spl
index=saas_logs
| search "OAuth token" AND ("long-lived" OR "hard-coded")
| stats count by user, application
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in adversary tactics, including the rise of voice phishing, destructive ransomware operations, and extreme persistence on edge devices. Notable malware families like BRICKSTORM and QUIETVAULT demonstrate advanced capabilities, while ransomware groups such as REDBIKE and AGENDA are actively targeting recovery infrastructure. Organizations must prioritize behavioral anomaly detection, extend log retention, and isolate critical control planes to mitigate these evolving threats. Immediate action is recommended to address these vulnerabilities and enhance resilience against modern adversaries.