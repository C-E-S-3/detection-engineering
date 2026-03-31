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

### Initial Access
- **T1190 - Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing Link**: High interaction voice phishing (vishing) accounted for 11% of initial access vectors, targeting IT help desks to bypass MFA.
- **T1078 - Valid Accounts**: Prior compromise ranked as the third-most common initial infection vector globally (10%) and the top vector in ransomware operations (30%).

### Persistence
- **T1505.003 - Server Software Component: Web Shell**: Adversaries deploy custom, in-memory malware like the BRICKSTORM backdoor on edge devices for deep persistence.
- **T1098.004 - Application Access Token**: Threat actors harvest long-lived OAuth tokens and session cookies to maintain access.

### Defense Evasion
- **T1556.004 - Network Sniffing**: Adversaries leverage native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1556.003 - Credential Dumping: OS Credential Dumping**: Exploiting misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware operators encrypt hypervisor datastores to render virtual machines inoperable.
- **T1490 - Inhibit System Recovery**: Attackers actively delete backup objects from cloud storage and target backup infrastructure.

## 3. Malware & Tools

### Malware Families
- **BRICKSTORM**: Custom, in-memory backdoor deployed on network appliances for deep persistence.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families leveraging AI and large language models (LLMs) for detection evasion.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on compromised systems.

### Tools
- **Native Packet-Capturing Functionality**: Leveraged on edge devices to intercept sensitive data and credentials.

## 4. Threat Actor / Campaign Attribution

### Threat Groups
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.

### Campaigns
- **ShinyHunters-Branded SaaS Data Theft**: Leveraging vishing and OAuth token theft to compromise SaaS environments.
- **Ransomware Operations**: Groups like REDBIKE (Akira) and AGENDA (Qilin) targeting backup infrastructure and virtualization management planes.

### Targeted Sectors/Geographies
- High-tech sector (17%) and financial sector (14.6%) were the most frequently targeted industries in 2025.
- North Korean IT worker incidents and cyber espionage campaigns had a median dwell time of 122 days.

## 5. Splunk Detection Searches

### Detecting OAuth Token Harvesting
```spl
index=proxy sourcetype=bluecoat:proxysg OR sourcetype=pan:threat
| search uri_path="*/oauth/token"
| stats count by src_ip, dest_ip, uri_path, user
| where count > 10
| table src_ip, dest_ip, uri_path, user, count
```

### Detecting Anomalous Bulk API Operations
```spl
index=api_logs sourcetype=aws:cloudtrail OR sourcetype=azure:activitylogs
| search eventName IN ("ListBuckets", "DescribeInstances", "ListUsers")
| stats count by userName, eventName, src_ip
| where count > 50
| table userName, eventName, src_ip, count
```

### Detecting Suspicious Hypervisor Activity
```spl
index=vmware sourcetype=vmware:esxi
| search event_type="datastore_encryption"
| stats count by host, user, event_type
| where count > 5
| table host, user, event_type, count
```

### Detecting Edge Device Packet Capturing
```spl
index=network sourcetype=network:device
| search "packet capture" OR "pcap"
| stats count by src_ip, dest_ip, action
| table src_ip, dest_ip, action, count
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, the collapse of the "hand-off" window between initial access and secondary operations, and the evolution of ransomware into recovery denial attacks. Sophisticated threat actors are increasingly targeting edge devices and leveraging zero-day vulnerabilities for extreme persistence. The report also underscores the growing use of AI by adversaries to evade detection and accelerate attack lifecycles. Organizations are urged to adopt behavioral anomaly detection, extend log retention policies, and treat low-impact alerts as critical indicators to counter these evolving threats effectively.