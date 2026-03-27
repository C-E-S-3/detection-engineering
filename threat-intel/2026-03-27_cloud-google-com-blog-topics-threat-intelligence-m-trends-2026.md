```markdown
---
scraped_at: 2026-03-23T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
report_type: threat-intel
---

# Threat Intelligence Report: M-Trends 2026

## 1. Indicators of Compromise (IOCs)
### IP Addresses
- None identified.

### Domains and URLs
- None identified.

### File Hashes
- None identified.

### Email Addresses
- None identified.

### File Names and Paths
- None identified.

### Registry Keys
- None identified.

### Mutex Names
- None identified.

### C2 Infrastructure Details
- None identified.

## 2. TTPs (MITRE ATT&CK Mapping)
### Initial Access
- **T1190 - Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing via Service**: Voice phishing surged to 11%, targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **T1078 - Valid Accounts**: Attackers use harvested OAuth tokens and session cookies to pivot into downstream environments.

### Persistence
- **T1505.003 - Web Shell**: Custom in-memory malware like BRICKSTORM deployed on edge devices for deep persistence.
- **T1556.004 - Abusing Certificate Templates**: Misconfigured Active Directory Certificate Services templates exploited to create admin accounts bypassing password rotation.

### Defense Evasion
- **T1070.004 - File Deletion**: Backup objects deleted from cloud storage to prevent recovery.
- **T1562.001 - Disable or Modify Tools**: Attackers exploit hypervisors to bypass guest-level defenses.

### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware groups encrypt hypervisor datastores to render virtual machines inoperable.
- **T1485 - Data Destruction**: Backup infrastructure and virtualization management planes targeted for destruction.

### Discovery
- **T1083 - File and Directory Discovery**: QUIETVAULT credential stealer searches for local AI configuration files.
- **T1040 - Network Sniffing**: Native packet-capturing functionality on edge devices used to intercept sensitive data and plaintext credentials.

## 3. Malware & Tools
### Malware Families
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization layers.
- **AGENDA (Qilin)**: Ransomware with similar destructive tactics.
- **BRICKSTORM**: In-memory backdoor deployed on network appliances for extreme persistence.
- **PROMPTFLUX**: Malware leveraging AI for detection evasion.
- **PROMPTSTEAL**: Malware querying LLMs mid-execution.
- **QUIETVAULT**: Credential stealer targeting local AI tools.

### Legitimate Tools Abused
- **OAuth Tokens**: Harvested for unauthorized access.
- **Session Cookies**: Used for seamless pivoting into downstream environments.

### Custom Tooling
- **Custom In-Memory Malware**: Designed for edge devices with minimal onboard storage.

## 4. Threat Actor / Campaign Attribution
### Named Threat Groups
- **UNC3944**: Known for voice phishing campaigns targeting IT help desks.
- **UNC6201**: Exploiting edge devices and zero-days for persistence.
- **UNC5807**: Similar tactics targeting network devices.

### Campaign Names
- **ClickFix**: Social engineering technique for initial access.
- **ShinyHunters-Branded SaaS Data Theft**: Campaign targeting SaaS environments.

### Known Affiliations or Motivations
- **Cyber Espionage**: Groups targeting edge devices for persistence and intelligence gathering.
- **Financial Gain**: Ransomware operators focusing on recovery denial.

### Targeted Sectors and Geographies
- **High Tech Sector**: Most frequently targeted (17% of incidents).
- **Financial Sector**: Second most targeted (14.6% of incidents).

## 5. Splunk Detection Searches
### Detect Exploit Attempts (T1190)
```spl
index=network sourcetype=firewall OR sourcetype=proxy
| search "exploit" OR "vulnerability"
| stats count by src_ip, dest_ip, dest_port, signature
| sort -count
```
*Comment: Identifies exploit attempts targeting public-facing applications.*

### Detect Voice Phishing (T1566.002)
```spl
index=voice sourcetype=voip
| search "help desk" OR "MFA bypass"
| stats count by caller_id, recipient_number, call_duration
| sort -count
```
*Comment: Flags suspicious voice calls targeting IT help desks.*

### Detect OAuth Token Abuse (T1078)
```spl
index=web sourcetype=application_logs
| search "OAuth token" OR "session cookie"
| stats count by user, action, resource
| sort -count
```
*Comment: Monitors unauthorized use of OAuth tokens and session cookies.*

### Detect Backup Deletion (T1070.004)
```spl
index=cloud sourcetype=storage_logs
| search "delete" AND "backup"
| stats count by user, resource, action
| sort -count
```
*Comment: Detects deletion of backup objects in cloud environments.*

### Detect Hypervisor Attacks (T1562.001)
```spl
index=virtualization sourcetype=hypervisor_logs
| search "datastore encryption" OR "virtual machine inoperable"
| stats count by host, action, error_code
| sort -count
```
*Comment: Identifies attacks targeting hypervisor storage layers.*

## 6. Executive Summary
The M-Trends 2026 report highlights a rapidly evolving threat landscape characterized by increased adversary sophistication and collaboration. Key trends include the rise of voice phishing, destructive ransomware tactics targeting recovery infrastructure, and extreme persistence via edge devices. Organizations must prioritize behavioral anomaly detection, extend log retention policies, and isolate critical control planes to mitigate these threats. Immediate action is recommended to address visibility gaps and enhance resilience against advanced adversaries.
```
