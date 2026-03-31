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
- **T1566.002 - Spearphishing Link**: Highly interactive voice phishing (vishing) surged to 11%, becoming the second most common initial infection vector.
- **T1078 - Valid Accounts**: Threat actors are leveraging prior compromises (10% of intrusions globally) as an initial infection vector.

### Persistence
- **T1098 - Account Manipulation**: Exploiting misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.
- **T1505.003 - Web Shell**: Deployment of custom in-memory malware like BRICKSTORM on edge devices for extreme persistence.

### Defense Evasion
- **T1556.004 - Network Device Authentication Bypass**: Adversaries are targeting edge devices like VPNs and routers that lack standard EDR telemetry.
- **T1070.004 - File Deletion**: Attackers are actively deleting backup objects from cloud storage.

### Credential Access
- **T1552.001 - Credentials in Files**: Harvesting long-lived OAuth tokens and session cookies.
- **T1557.002 - Man-in-the-Middle**: Leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware operators encrypting hypervisor datastores to render virtual machines inoperable.
- **T1490 - Inhibit System Recovery**: Targeting backup infrastructure and identity services to destroy recovery capabilities.

## 3. Malware & Tools
- **BRICKSTORM**: Custom in-memory malware deployed on network appliances for extreme persistence.
- **PROMPTFLUX and PROMPTSTEAL**: Malware families using AI to evade detection.
- **QUIETVAULT**: Credential stealer leveraging AI command-line tools to search for configuration files.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain SaaS access.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira) and AGENDA (Qilin)**: Ransomware groups actively targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token Harvesting
```spl
index=proxy OR index=firewall
| search uri_path="*/oauth/token"
| stats count by src_ip, user, uri_path
| where count > 10
| table src_ip, user, uri_path, count
```
*Comment: Detects suspicious OAuth token harvesting activities by monitoring token-related API calls.*

### Detecting Backup Object Deletion
```spl
index=cloud_storage_logs action=delete
| stats count by user, resource_name, src_ip
| where count > 5
| table user, resource_name, src_ip, count
```
*Comment: Identifies anomalous deletion of backup objects in cloud storage.*

### Detecting Hypervisor Datastore Encryption
```spl
index=vmware_logs event_type=datastore
| search action="encrypt"
| stats count by host, user, action
| where count > 0
| table host, user, action, count
```
*Comment: Monitors for encryption actions on hypervisor datastores.*

### Detecting Packet-Capturing on Edge Devices
```spl
index=network_devices_logs
| search "packet capture started"
| stats count by device_ip, user, action
| where count > 0
| table device_ip, user, action, count
```
*Comment: Detects unauthorized packet-capturing activities on edge devices.*

### Detecting MFA Bypass via Help Desk
```spl
index=authentication_logs
| search "help desk" AND "MFA bypass"
| stats count by user, src_ip, action
| where count > 0
| table user, src_ip, action, count
```
*Comment: Flags MFA bypass attempts linked to help desk interactions.*

## 6. Executive Summary
The M-Trends 2026 report highlights significant shifts in adversary tactics, including the rise of voice phishing, extreme persistence on edge devices, and ransomware targeting recovery capabilities. Notable malware families like BRICKSTORM and PROMPTFLUX demonstrate the integration of AI into attack workflows. Organizations must prioritize behavioral anomaly detection, extend log retention, and isolate critical control planes to mitigate these evolving threats. Immediate actions include auditing SaaS integrations, securing edge devices, and implementing advanced threat detection across all layers of the IT ecosystem.