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

### Other IOCs
- No additional IOCs identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques

- **Tactic: Initial Access**
  - **Technique ID: T1190 (Exploit Public-Facing Application)**
    - **Description**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions in 2025.
  
  - **Technique ID: T1566.002 (Spearphishing via Service)**
    - **Description**: Surge in voice phishing (vishing) targeting IT help desks to bypass MFA and gain access to SaaS environments.

  - **Technique ID: T1078 (Valid Accounts)**
    - **Description**: Threat actors are leveraging stolen OAuth tokens, session cookies, and hard-coded keys to gain unauthorized access to SaaS environments.

- **Tactic: Persistence**
  - **Technique ID: T1547.001 (Registry Run Keys/Startup Folder)**
    - **Description**: Ransomware operators exploit misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

  - **Technique ID: T1547.006 (Boot or Logon Autostart Execution: Kernel Modules and Extensions)**
    - **Description**: Deployment of in-memory malware like BRICKSTORM backdoor on network appliances for deep persistence.

- **Tactic: Defense Evasion**
  - **Technique ID: T1070.004 (File Deletion)**
    - **Description**: Ransomware operators actively delete backup objects from cloud storage to prevent recovery.

  - **Technique ID: T1562.001 (Impair Defenses: Disable or Modify Tools)**
    - **Description**: Attackers exploit hypervisors to bypass guest-level defenses and encrypt virtualization storage layers.

- **Tactic: Credential Access**
  - **Technique ID: T1552.001 (Unsecured Credentials: Credentials In Files)**
    - **Description**: Threat actors steal hard-coded keys and personal access tokens from third-party SaaS vendors.

  - **Technique ID: T1557.002 (Man-in-the-Middle: ARP Cache Poisoning)**
    - **Description**: Adversaries use native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

- **Tactic: Impact**
  - **Technique ID: T1486 (Data Encrypted for Impact)**
    - **Description**: Ransomware operators encrypt hypervisor datastores to render associated virtual machines inoperable.

  - **Technique ID: T1485 (Data Destruction)**
    - **Description**: Ransomware groups actively destroy recovery capabilities by targeting backup infrastructure and virtualization management planes.

## 3. Malware & Tools

- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for extreme persistence.
- **PROMPTFLUX**: Malware family leveraging large language models (LLMs) mid-execution to evade detection.
- **PROMPTSTEAL**: Malware family using AI to evade detection.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on compromised machines.
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware targeting backup infrastructure and virtualization management planes.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201**: Targets edge and core network devices for extreme persistence, leveraging zero-day vulnerabilities.
- **UNC5807**: Focuses on edge and core network devices for long-term persistence.
- **ShinyHunters**: Associated with SaaS data theft campaigns using vishing techniques.

## 5. Splunk Detection Searches

### Detection for OAuth Token and Session Cookie Theft
```spl
index=proxy_logs
| search "OAuth" OR "session cookie"
| stats count by src_ip, dest_ip, user, uri
| where count > 10
| table src_ip, dest_ip, user, uri
```

### Detection for Backup Object Deletion in Cloud Storage
```spl
index=cloud_storage_logs action=delete
| stats count by user, src_ip, object_name
| where count > 5
| table user, src_ip, object_name
```

### Detection for Hypervisor Datastore Encryption
```spl
index=vmware_logs event_type=datastore_encryption
| stats count by host, user, datastore
| where count > 0
| table host, user, datastore
```

### Detection for Vishing Attempts
```spl
index=voip_logs
| search "call" AND "MFA" AND "help desk"
| stats count by src_ip, dest_number, user
| where count > 0
| table src_ip, dest_number, user
```

### Detection for Packet-Capturing on Edge Devices
```spl
index=network_device_logs
| search "packet capture" OR "sniffing"
| stats count by device_ip, user, action
| where count > 0
| table device_ip, user, action
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant advancements in adversary tactics, including the rise of voice phishing, the use of AI for evasion, and the exploitation of edge devices for extreme persistence. Ransomware groups have evolved to target recovery capabilities, while espionage actors leverage zero-day vulnerabilities for long-term access. Organizations must adopt behavioral anomaly detection, extend log retention, and secure critical control planes to mitigate these threats. Immediate action is recommended to address these emerging risks and enhance resilience against sophisticated cyber threats.