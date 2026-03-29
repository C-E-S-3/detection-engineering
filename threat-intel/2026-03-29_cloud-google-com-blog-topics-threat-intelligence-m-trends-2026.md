---
scraped_at: 2026-03-23T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- No new IP addresses identified.

### Domains/URLs
- No new domains/URLs identified.

### File Hashes
- No new file hashes identified.

### Email Addresses
- No new email addresses identified.

### File Names/Paths
- No new file names/paths identified.

### Registry Keys
- No new registry keys identified.

### Mutex Names
- No new mutex names identified.

### C2 Infrastructure
- No new C2 infrastructure identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1190: Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**: Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**: Threat actors are leveraging prior compromises (10% of intrusions globally) as an initial infection vector, particularly in ransomware operations (30%).

### Persistence
- **T1505.003: Server Software Component**: Adversaries are deploying custom, in-memory malware like the BRICKSTORM backdoor onto edge and core network devices to establish deep persistence.
- **T1098: Account Manipulation**: Exploiting misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1556.004: Network Sniffing**: Leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1552.001: Credentials in Files**: Harvesting long-lived OAuth tokens, session cookies, hard-coded keys, and personal access tokens from SaaS environments.
- **T1027: Obfuscated Files or Information**: Use of custom, in-memory malware to evade detection.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware groups actively encrypting data and targeting backup infrastructure, identity services, and virtualization management planes.
- **T1485: Data Destruction**: Attackers are destroying the ability to recover by deleting backup objects from cloud storage and encrypting hypervisor datastores.

## 3. Malware & Tools

### Malware Families
- **BRICKSTORM**: Custom, in-memory backdoor deployed on network appliances for deep persistence.
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware targeting backup environments and hypervisors.
- **PROMPTFLUX**: Malware leveraging large language models (LLMs) for detection evasion.
- **PROMPTSTEAL**: Malware using LLMs to evade detection.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on compromised machines.

### Tools
- Abuse of native packet-capturing functionality on edge devices.
- Exploitation of Active Directory Certificate Services templates.

## 4. Threat Actor / Campaign Attribution

### Named Threat Groups
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201**: Targets edge and core network devices for extreme persistence.
- **UNC5807**: Focuses on exploiting vulnerabilities in edge devices and routers.

### Campaigns
- **ShinyHunters-Branded SaaS Data Theft**: Leveraging vishing techniques to bypass MFA and gain access to SaaS environments.
- **North Korean IT Worker Incidents**: High median dwell time of 122 days observed in cyber espionage campaigns.

### Targeted Sectors/Geographies
- High-tech sector (17%) and financial sector (14.6%) were the most targeted industries in 2025.
- North Korean IT worker incidents were highlighted as a significant threat.

## 5. Splunk Detection Searches

### Detecting OAuth Token Harvesting
```spl
index=proxy_logs sourcetype=proxy_logs
| search "OAuth" AND ("token" OR "session")
| stats count by src_ip, dest_ip, uri_path, user
| table src_ip, dest_ip, uri_path, user, count
```

### Detecting Anomalous Bulk API Operations
```spl
index=api_logs sourcetype=api_logs
| stats count by user, api_endpoint
| where count > 100
| table user, api_endpoint, count
```

### Detecting Edge Device Packet Capturing
```spl
index=network_logs sourcetype=network_logs
| search "packet capture" OR "sniffing"
| stats count by src_ip, dest_ip, action
| table src_ip, dest_ip, action, count
```

### Detecting Hypervisor Datastore Encryption
```spl
index=vmware_logs sourcetype=vmware:vsphere
| search "datastore" AND "encryption"
| stats count by host, user, action
| table host, user, action, count
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing (vishing) as a major initial access vector and the evolution of ransomware into recovery denial attacks. Sophisticated threat actors are increasingly targeting edge devices and leveraging zero-day vulnerabilities to establish extreme persistence. The report also underscores the growing use of AI by adversaries to evade detection and accelerate attack lifecycles. Organizations are advised to prioritize behavioral anomaly detection, enhance log retention policies, and adopt robust identity verification and backup isolation strategies to mitigate these emerging threats.