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

### Tactics and Techniques

- **Tactic: Initial Access**
  - **Technique ID:** T1190 (Exploit Public-Facing Application)
    - **Description:** Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
  - **Technique ID:** T1566.002 (Spearphishing via Service)
    - **Description:** High-interactive voice phishing surged to 11%, becoming the second-most common vector.
  - **Technique ID:** T1078 (Valid Accounts)
    - **Description:** Attackers leverage stolen OAuth tokens and session cookies to bypass authentication.

- **Tactic: Persistence**
  - **Technique ID:** T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder)
    - **Description:** Attackers exploit misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.
  - **Technique ID:** T1505.003 (Server Software Component: Web Shells)
    - **Description:** Custom in-memory malware like BRICKSTORM is deployed on network appliances for deep persistence.

- **Tactic: Defense Evasion**
  - **Technique ID:** T1070.004 (Indicator Removal on Host: File Deletion)
    - **Description:** Attackers delete backup objects from cloud storage to prevent recovery.
  - **Technique ID:** T1218 (Signed Binary Proxy Execution)
    - **Description:** Attackers exploit native packet-capturing functionality on edge devices to evade detection.

- **Tactic: Impact**
  - **Technique ID:** T1486 (Data Encrypted for Impact)
    - **Description:** Ransomware operators encrypt hypervisor datastores to render virtual machines inoperable.
  - **Technique ID:** T1485 (Data Destruction)
    - **Description:** Ransomware groups actively destroy recovery capabilities by targeting backup infrastructure and virtualization management planes.

## 3. Malware & Tools

- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for deep persistence.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families leveraging AI to evade detection.
- **QUIETVAULT**: Credential stealer targeting local AI command-line tools.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware operators targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Network IOCs

```spl
# Search for anomalous bulk API operations in SaaS environments
eval is_suspicious = if(like(uri_path, "%/api/%") AND method IN ("POST", "PUT", "DELETE"), "true", "false")
| search is_suspicious="true"
| stats count by src_ip, uri_path, method
```

### Endpoint IOCs

```spl
# Detect unauthorized access to edge devices
index=network_logs sourcetype=network:firewall
| search "VPN" OR "router"
| stats count by src_ip, dest_ip, action
| where action="allowed"
```

### Hash Lookups

```spl
# Search for known malicious hashes (if hashes are added in the future)
index=endpoint_logs sourcetype=endpoint:process
| lookup malicious_hashes hash AS file_hash OUTPUT hash AS match
| where isnotnull(match)
```

### Behavioral TTPs

```spl
# Detect suspicious use of SaaS integration tokens
index=auth_logs sourcetype=auth:saas
| stats count by user, token_id, action
| where action="bulk_download" OR action="admin_privileges"
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in adversary tactics, including the rise of voice phishing, the collapse of the "hand-off" window in ransomware operations, and the exploitation of edge devices for extreme persistence. Notable malware families like BRICKSTORM and PROMPTFLUX demonstrate the increasing sophistication of attackers. Organizations are advised to prioritize behavioral anomaly detection, extend log retention policies, and isolate critical control planes to mitigate these evolving threats.