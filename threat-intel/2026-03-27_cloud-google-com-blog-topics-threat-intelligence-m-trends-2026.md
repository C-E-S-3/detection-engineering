```markdown
---
scraped_at: 2026-03-23T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
report_type: threat-intel
---

# Threat Intelligence Report: M-Trends 2026

## 1. Indicators of Compromise (IOCs)
### IP Addresses
- None mentioned.

### Domains and URLs
- None mentioned.

### File Hashes
- None mentioned.

### Email Addresses
- None mentioned.

### File Names and Paths
- None mentioned.

### Registry Keys
- None mentioned.

### Mutex Names
- None mentioned.

### C2 Infrastructure Details
- None mentioned.

## 2. TTPs (MITRE ATT&CK Mapping)
### Initial Access
- **T1190 - Exploit Public-Facing Application**  
  Exploits remained the most common initial infection vector, accounting for 32% of intrusions globally.
- **T1566.002 - Spearphishing via Service**  
  Highly interactive voice phishing surged to 11%, targeting IT help desks to bypass MFA and gain access to SaaS environments.

### Persistence
- **T1505.003 - Web Shell**  
  Threat actors deploy custom in-memory malware like BRICKSTORM onto edge devices for deep persistence.
- **T1556.004 - Abusing Authentication Processes**  
  Attackers exploit misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1070.004 - File Deletion**  
  Ransomware groups actively delete backup objects from cloud storage to prevent recovery.
- **T1027 - Obfuscated Files or Information**  
  Malware families like PROMPTFLUX query large language models (LLMs) mid-execution to evade detection.

### Credential Access
- **T1557.002 - Adversary-in-the-Middle**  
  Adversaries leverage native packet-capturing functionality on edge devices to intercept plaintext credentials.

### Impact
- **T1486 - Data Encrypted for Impact**  
  Ransomware groups encrypt hypervisor datastores, rendering associated virtual machines inoperable.
- **T1490 - Inhibit System Recovery**  
  Attackers destroy backup infrastructure and virtualization management planes to deny recovery.

## 3. Malware & Tools
### Malware Families
- **REDBIKE (Akira)**  
  Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**  
  Similar ransomware group with destructive tactics.
- **BRICKSTORM**  
  In-memory malware deployed on edge devices for persistence.
- **PROMPTFLUX**  
  Malware querying LLMs for evasion.
- **QUIETVAULT**  
  Credential stealer targeting local AI command-line tools.

### Legitimate Tools Abused
- **OAuth Tokens and Session Cookies**  
  Harvested for bypassing defenses and pivoting into downstream environments.

### Custom Tooling
- **Custom In-Memory Malware**  
  Used for persistence on edge devices lacking traditional security telemetry.

## 4. Threat Actor / Campaign Attribution
### Named Threat Groups
- **UNC3944**  
  Known for targeting IT help desks to bypass MFA and compromise SaaS environments.
- **UNC6201**  
  Exploits edge devices and zero-days for espionage and persistence.
- **UNC5807**  
  Similar tactics targeting edge devices.

### Campaign Names
- None explicitly named.

### Known Affiliations or Motivations
- **Cyber Espionage**  
  Groups optimizing for extreme persistence and intelligence gathering.
- **Cyber Crime**  
  Groups specializing in ransomware and recovery denial.

### Targeted Sectors and Geographies
- **High Tech Sector** (17%)  
  Most frequently targeted industry in 2025.
- **Financial Sector** (14.6%)  
  Previously the top target but now second.

## 5. Splunk Detection Searches
### Detect Exploits as Initial Infection Vector
```spl
index=firewall OR index=proxy OR index=dns
sourcetype=network_traffic
| search "exploit" OR "public-facing application"
| stats count by src_ip, dest_ip, dest_port, signature
| where count > 10
```
*Detects exploit attempts against public-facing applications.*

### Detect Voice Phishing Activity
```spl
index=voip OR index=call_logs
sourcetype=voip_logs
| search "help desk" OR "MFA bypass"
| stats count by caller_id, recipient_id, call_duration
| where call_duration > 300
```
*Identifies suspicious voice phishing targeting IT help desks.*

### Detect Ransomware Backup Deletion
```spl
index=cloud_storage
sourcetype=storage_logs
| search "delete backup" OR "remove snapshot"
| stats count by user, action, resource
| where action="delete"
```
*Flags malicious deletion of backup objects in cloud environments.*

### Detect BRICKSTORM Malware Persistence
```spl
index=network_devices
sourcetype=device_logs
| search "packet capture" OR "plaintext credentials"
| stats count by device_ip, action
| where action="capture"
```
*Monitors for unauthorized packet capturing on edge devices.*

### Detect OAuth Token Abuse
```spl
index=saas_logs
sourcetype=application_logs
| search "OAuth token" OR "session cookie"
| stats count by user, action, resource
| where action="access"
```
*Detects suspicious use of OAuth tokens and session cookies.*

## 6. Executive Summary
The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of ransomware targeting recovery capabilities and espionage groups leveraging edge devices for extreme persistence. Adversaries are increasingly using voice phishing and exploiting SaaS integrations to bypass defenses. Organizations must prioritize behavioral anomaly detection, extend log retention policies, and isolate critical control planes to counter these evolving threats. Immediate actions include restructuring response playbooks to treat low-impact alerts as critical indicators and implementing continuous identity verification mechanisms.
```
