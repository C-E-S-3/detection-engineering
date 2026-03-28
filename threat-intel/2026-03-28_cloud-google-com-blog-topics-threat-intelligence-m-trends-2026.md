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
- No other IOCs identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1190: Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**: High-interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**: Prior compromise ranked as the third-most common initial infection vector globally (10%), and the top vector in ransomware operations (30%).

### Persistence
- **T1505.003: Server Software Component**: Adversaries deploy custom in-memory malware like the BRICKSTORM backdoor onto network appliances for extreme persistence.
- **T1078.003: Valid Accounts - Cloud Accounts**: Attackers exploit hard-coded keys and personal access tokens from third-party SaaS vendors to pivot into downstream environments.

### Credential Access
- **T1552.001: Credentials in Files**: Threat actors harvest long-lived OAuth tokens and session cookies.
- **T1557.002: Adversary-in-the-Middle**: Adversaries leverage native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

### Impact
- **T1485: Data Destruction**: Ransomware groups actively destroy recovery capabilities by targeting backup infrastructure, identity services, and virtualization management planes.
- **T1486: Data Encrypted for Impact**: Attackers encrypt hypervisor datastores, rendering associated virtual machines inoperable.

### Defense Evasion
- **T1218: Signed Binary Proxy Execution**: Attackers exploit misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.
- **T1027: Obfuscated Files or Information**: Malware families like PROMPTFLUX and PROMPTSTEAL use AI to evade detection.

### Command and Control
- **T1573: Encrypted Channel**: Adversaries use pre-staged tunnels during initial infections to enable immediate operations.

## 3. Malware & Tools

- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware actively destroying recovery capabilities.
- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for extreme persistence.
- **PROMPTFLUX and PROMPTSTEAL**: Malware families leveraging AI to evade detection.
- **QUIETVAULT**: Credential stealer targeting local AI command-line tools to extract configuration files.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **North Korean IT workers**: Associated with cyber espionage incidents with a median dwell time of 122 days.

## 5. Splunk Detection Searches

### Detecting Voice Phishing Activity
```spl
index=voip_logs sourcetype=voip:call_logs
| search "caller_id"="*" "call_type"="incoming"
| stats count by caller_id, call_type
| where count > 10
| table caller_id, call_type, count
```
# This search identifies unusual patterns in incoming voice calls, which may indicate vishing attempts.

### Detecting OAuth Token Harvesting
```spl
index=cloud sourcetype=cloud:auth_logs
| search "action"="token_grant"
| stats count by user, client_ip, app_name
| where count > 5
| table user, client_ip, app_name, count
```
# This search detects abnormal OAuth token grants that may indicate token harvesting.

### Detecting Backup Infrastructure Targeting
```spl
index=backup sourcetype=backup:logs
| search "delete" OR "modify"
| stats count by user, action, target
| where action IN ("delete", "modify")
| table user, action, target, count
```
# This search identifies unauthorized deletion or modification of backup objects.

### Detecting Hypervisor Targeting
```spl
index=vmware sourcetype=vmware:logs
| search "datastore" AND ("delete" OR "encrypt")
| stats count by user, action, target
| where action IN ("delete", "encrypt")
| table user, action, target, count
```
# This search detects suspicious activity targeting hypervisor datastores.

### Detecting AI Tool Abuse
```spl
index=endpoint sourcetype=sysmon
| search "process_name"="*ai_tool*" "command_line"="*config*"
| stats count by host, process_name, command_line
| table host, process_name, command_line, count
```
# This search identifies potential abuse of local AI tools for malicious purposes.

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, extreme persistence by espionage groups, and the evolution of ransomware into recovery denial attacks. Threat actors are increasingly leveraging AI to evade detection and accelerate their operations. Organizations must prioritize behavioral anomaly detection, extend log retention policies, and adopt advanced security measures to counter these evolving threats. Immediate actions include treating low-impact alerts as critical indicators, isolating critical control planes, and enforcing continuous identity verification.