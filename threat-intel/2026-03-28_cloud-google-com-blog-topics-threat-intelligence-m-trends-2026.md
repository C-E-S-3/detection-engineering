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
  - **T1190: Exploit Public-Facing Application**: Exploits remained the most common initial infection vector, accounting for 32% of intrusions.
  - **T1566.002: Spearphishing Link**: Highly interactive voice phishing surged to 11%, becoming the second-most common initial infection vector.
  - **T1078: Valid Accounts**: Prior compromise was the third-most common initial infection vector (10%) globally and the top vector in ransomware operations (30%).

- **Tactic: Credential Access**
  - **T1552.001: Credentials in Files**: Adversaries are stealing hard-coded keys and personal access tokens from compromised third-party SaaS vendors.
  - **T1552.004: Credential Dumping**: Attackers are leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

- **Tactic: Persistence**
  - **T1547.003: Windows Management Instrumentation Event Subscription**: Attackers exploit misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.
  - **T1547.014: Hypervisor**: Attackers target hypervisor datastores to encrypt or render virtual machines inoperable.
  - **T1547.015: Application Shimming**: Deployment of custom, in-memory malware like the BRICKSTORM backdoor on network appliances for deep persistence.

- **Tactic: Defense Evasion**
  - **T1070.004: File Deletion**: Attackers actively delete backup objects from cloud storage.
  - **T1562.001: Disable or Modify Tools**: Exploiting the “Tier-0” nature of hypervisors to bypass guest-level defenses.

- **Tactic: Collection**
  - **T1123: Audio Capture**: Use of highly interactive voice-based social engineering to bypass MFA and gain initial access.
  - **T1114.003: Email Collection via Exchange**: Harvesting OAuth tokens and session cookies to access SaaS environments and execute data theft.

- **Tactic: Impact**
  - **T1485: Data Destruction**: Ransomware operators actively destroy recovery capabilities by targeting backup infrastructure and identity services.
  - **T1486: Data Encrypted for Impact**: Encryption of hypervisor datastores to render virtual machines inoperable.

## 3. Malware & Tools

- **BRICKSTORM**: A custom, in-memory backdoor deployed on network appliances to establish deep persistence.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families leveraging large language models (LLMs) for detection evasion.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on local machines.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups targeting backup infrastructure, identity services, and virtualization management planes.

## 5. Splunk Detection Searches

### Behavioral TTPs

#### Detecting Exploitation of Public-Facing Applications
```spl
index=web sourcetype=access_combined
| stats count by src_ip, uri, http_method
| where count > 100 AND like(uri, "%/admin%")
```
*# This search identifies potential exploitation attempts targeting public-facing applications by detecting high-frequency access to admin-related URIs.*

#### Detecting Voice Phishing Activity
```spl
index=voip_logs OR index=call_logs
| search "call_type=outbound" AND "destination_country=*
| stats count by src_number, dest_number, call_duration
| where call_duration > 300
```
*# This search identifies long-duration outbound calls, which may indicate voice phishing attempts.*

#### Detecting OAuth Token Harvesting
```spl
index=proxy OR index=cloud_logs
| search "action=token_request"
| stats count by src_ip, user_agent, app_name
| where count > 10
```
*# This search identifies suspicious OAuth token requests from unusual IPs or user agents.*

#### Detecting Hypervisor Targeting
```spl
index=vmware_logs OR index=hypervisor_logs
| search "event_type=datastore_encryption"
| stats count by host, user, action
```
*# This search detects potential encryption or tampering with hypervisor datastores.*

## 6. Executive Summary

The M-Trends 2026 report highlights significant advancements in adversary tactics, including a rise in dwell times, increased use of voice phishing, and the evolution of ransomware into recovery denial attacks. Notably, attackers are leveraging edge devices and zero-day vulnerabilities to establish extreme persistence, often evading detection for extended periods. Organizations are advised to prioritize behavioral anomaly detection, extend log retention, and implement strict access controls for critical infrastructure. Immediate action is recommended to address these emerging threats and enhance resilience against sophisticated adversaries.