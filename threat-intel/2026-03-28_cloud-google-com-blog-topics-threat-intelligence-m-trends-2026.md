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
- **T1190: Exploit Public-Facing Application**: Exploits remained the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**: Highly interactive voice phishing surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**: Threat actors used stolen credentials, including OAuth tokens and session cookies, to gain access to SaaS environments.

### Persistence
- **T1505.003: Server Software Component**: Custom in-memory malware like BRICKSTORM was deployed on network appliances to achieve persistence.
- **T1098.003: Additional Cloud Credentials**: Attackers exploited misconfigured Active Directory Certificate Services templates to create admin accounts bypassing password rotation.

### Defense Evasion
- **T1562.001: Disable or Modify Tools**: Attackers actively deleted backup objects from cloud storage.
- **T1070.004: File Deletion**: Backup infrastructure and virtualization management planes were targeted to destroy recovery capabilities.

### Credential Access
- **T1557.002: Man-in-the-Middle**: Adversaries leveraged native packet-capturing functionality on edge devices to intercept plaintext credentials.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware operators encrypted hypervisor datastores, rendering virtual machines inoperable.
- **T1490: Inhibit System Recovery**: Backup environments were targeted to prevent recovery.

## 3. Malware & Tools
- **BRICKSTORM**: Custom in-memory malware deployed on network appliances for persistence.
- **QUIETVAULT**: Credential stealer targeting local AI command-line tools to extract sensitive data.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families leveraging AI to evade detection.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain SaaS access.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups targeting backup and virtualization infrastructure.

## 5. Splunk Detection Searches

### Detecting Voice Phishing Activity
```spl
index=voip_logs sourcetype=voip:events
| search "interactive voice phishing"
| stats count by caller_id, destination_number, duration
| where duration > 300
```
*Comment: Identifies potential voice phishing calls lasting longer than 5 minutes.*

### Monitoring OAuth Token Usage
```spl
index=auth_logs sourcetype=oauth:events
| search "token_usage"
| stats count by user, token_id, src_ip
| where count > 10
```
*Comment: Detects abnormal OAuth token usage patterns.*

### Detecting Backup Deletion Commands
```spl
index=cloud_logs sourcetype=cloud:admin
| search "delete backup"
| stats count by user, resource_name, src_ip
| where count > 5
```
*Comment: Flags suspicious deletion of backup objects in cloud environments.*

### Identifying Hypervisor Datastore Encryption
```spl
index=vmware_logs sourcetype=vmware:events
| search "datastore encryption"
| stats count by vm_name, user, src_ip
```
*Comment: Monitors for encryption activities targeting hypervisor datastores.*

### Detecting Packet-Capturing on Edge Devices
```spl
index=network_logs sourcetype=network:device
| search "packet capture"
| stats count by device_ip, user, command
```
*Comment: Detects unauthorized use of packet-capturing functionality on network devices.*

## 6. Executive Summary
The M-Trends 2026 report highlights significant advancements in adversary tactics, including the rise of voice phishing, the use of AI in malware, and the targeting of edge devices for extreme persistence. Ransomware operators are evolving their tactics to destroy recovery capabilities, while espionage groups exploit zero-day vulnerabilities to establish long-term persistence. Organizations are advised to prioritize behavioral anomaly detection, extend log retention policies, and secure critical infrastructure to mitigate these evolving threats.