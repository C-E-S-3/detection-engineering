---
scraped_at: "2026-03-23T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/"
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

### Tactics and Techniques

#### Initial Access
- **T1190 - Exploit Public-Facing Application**: Exploits were the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing Link**: Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078 - Valid Accounts**: Attackers exploited prior compromises to gain initial access, which accounted for 10% of intrusions globally and 30% in ransomware operations.

#### Persistence
- **T1505.003 - Web Shell**: Adversaries pre-staged secondary group malware or tunnels during initial infections.
- **T1505.003 - Implant Internal Image**: Custom in-memory malware like BRICKSTORM was deployed on network appliances for deep persistence.

#### Credential Access
- **T1552.001 - Credentials in Files**: Threat actors harvested long-lived OAuth tokens and session cookies.
- **T1557.002 - Man-in-the-Middle**: Adversaries leveraged native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

#### Defense Evasion
- **T1553.004 - Application Shimming**: Attackers exploited misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.
- **T1027 - Obfuscated Files or Information**: Malware families like PROMPTFLUX and PROMPTSTEAL used AI to evade detection.

#### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware operators targeted backup infrastructure, identity services, and virtualization management planes to destroy recovery capabilities.
- **T1490 - Inhibit System Recovery**: Attackers deleted backup objects from cloud storage and encrypted hypervisor datastores to render virtual machines inoperable.

## 3. Malware & Tools

- **REDBIKE (Akira)**: Ransomware used to target backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware targeting backup infrastructure and identity services.
- **BRICKSTORM**: Custom in-memory malware deployed on network appliances for extreme persistence.
- **PROMPTFLUX and PROMPTSTEAL**: Malware families leveraging AI to evade detection.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on compromised machines.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.

## 5. Splunk Detection Searches

### Detecting OAuth Token Harvesting
```spl
index=proxy_logs sourcetype=proxy_logs
| search "OAuth" AND ("token" OR "session")
| stats count by src_ip, dest_ip, uri_path, user
| where count > 10
```

### Detecting Suspicious SaaS API Activity
```spl
index=saas_logs sourcetype=saas:api
| stats count by user, action, app
| where action IN ("token_generation", "bulk_data_download")
```

### Detecting Backup Infrastructure Access
```spl
index=backup_logs sourcetype=backup:logs
| search "delete" OR "modify"
| stats count by user, action, target
| where action IN ("delete", "modify")
```

### Detecting Hypervisor Datastore Encryption
```spl
index=vmware_logs sourcetype=vmware:logs
| search "datastore" AND "encryption"
| stats count by host, user, action
```

### Detecting In-Memory Malware on Edge Devices
```spl
index=network_device_logs sourcetype=network:device
| search "in-memory execution" OR "BRICKSTORM"
| stats count by device_ip, event_type
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing (vishing) as a major initial access vector and the evolution of ransomware tactics to target recovery capabilities. Espionage groups are increasingly exploiting edge devices and zero-day vulnerabilities to establish extreme persistence, while cybercriminals are leveraging AI to enhance malware evasion and operational efficiency. Organizations are advised to prioritize behavioral anomaly detection, extend log retention policies, and adopt robust identity verification measures to counter these evolving threats. Immediate action is recommended to secure critical control planes and backup infrastructure against destructive attacks.