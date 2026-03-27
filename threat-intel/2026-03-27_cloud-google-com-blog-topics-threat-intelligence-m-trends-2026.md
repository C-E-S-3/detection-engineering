```markdown
---
scraped_at: 2026-03-23T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
report_type: threat-intel
---

# Threat Intelligence Report: M-Trends 2026

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified

### Domains and URLs
- None identified

### File Hashes
- None identified

### Email Addresses
- None identified

### File Names and Paths
- None identified

### Registry Keys
- None identified

### Mutex Names
- None identified

### C2 Infrastructure Details
- None identified

---

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Initial Access
- **T1190 - Exploit Public-Facing Application**: Exploits were the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing Link**: Highly interactive voice phishing surged to 11%, becoming the second-most common initial infection vector.
- **T1078 - Valid Accounts**: Threat actors compromised SaaS environments by bypassing MFA and harvesting long-lived OAuth tokens and session cookies.

### Tactic: Persistence
- **T1505.003 - Web Shell**: Deployment of custom in-memory malware like BRICKSTORM backdoor on network appliances for deep persistence.
- **T1556.004 - Credential API Hooking**: Harvesting long-lived OAuth tokens and session cookies to maintain access to SaaS environments.

### Tactic: Defense Evasion
- **T1218 - Signed Binary Proxy Execution**: Abuse of legitimate tools and native functionalities in edge devices for evasion.
- **T1562.001 - Disable or Modify Tools**: Exploiting misconfigured Active Directory Certificate Services templates to bypass password rotation.

### Tactic: Impact
- **T1485 - Data Destruction**: Ransomware groups actively destroying backup infrastructure and virtualization management planes.
- **T1486 - Data Encrypted for Impact**: Encrypting hypervisor datastores to render virtual machines inoperable.

---

## 3. Malware & Tools

### Malware Families
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware actively deleting backup objects from cloud storage.
- **BRICKSTORM**: In-memory malware deployed on network appliances for extreme persistence.
- **PROMPTFLUX**: Malware querying large language models (LLMs) mid-execution for evasion.
- **PROMPTSTEAL**: Malware leveraging AI to evade detection.
- **QUIETVAULT**: Credential stealer targeting local AI command-line tools.

### Legitimate Tools Abused
- **Active Directory Certificate Services**: Exploited to create admin accounts bypassing password rotation.
- **Hypervisors**: Targeted for encryption and bypassing guest-level defenses.

### Custom Tooling
- **Custom in-memory malware**: Designed for persistence on edge devices with minimal onboard storage.

---

## 4. Threat Actor / Campaign Attribution

### Named Threat Groups
- **UNC3944**: Known for voice phishing and targeting IT help desks to bypass MFA.
- **UNC6201**: Espionage group targeting edge devices and exploiting zero-days.
- **UNC5807**: Espionage group optimizing for extreme persistence.

### Campaign Names
- **ClickFix**: Social engineering technique used for initial access.
- **ShinyHunters-Branded SaaS Data Theft**: Campaign targeting SaaS environments.

### Known Affiliations or Motivations
- **Cyber Espionage**: Focused on persistence and intelligence gathering.
- **Cyber Crime**: Focused on immediate impact and recovery denial.

### Targeted Sectors and Geographies
- **High Tech Sector**: Most frequently targeted (17% of incidents).
- **Financial Sector**: Second most targeted (14.6% of incidents).
- **Global**: Incidents observed across 16 industry verticals.

---

## 5. Splunk Detection Searches

### Detecting Exploits (T1190)
```spl
index=firewall OR index=proxy OR index=dns
| search "exploit" OR "public-facing application"
| stats count by src_ip, dest_ip, dest_port
| table src_ip, dest_ip, dest_port, count
```
*Comment: Identifies traffic patterns indicative of exploitation attempts on public-facing applications.*

### Detecting Voice Phishing (T1566.002)
```spl
index=voice OR index=telephony
| search "vishing" OR "voice phishing"
| stats count by caller_id, recipient_number, duration
| table caller_id, recipient_number, duration, count
```
*Comment: Monitors for voice phishing attempts targeting IT help desks.*

### Detecting Ransomware Activity (T1486)
```spl
index=endpoint OR index=windows
| search "ransomware" OR "backup deletion" OR "datastore encryption"
| stats count by host, user, process_name, file_path
| table host, user, process_name, file_path, count
```
*Comment: Flags ransomware operations targeting backup infrastructure and hypervisors.*

### Detecting OAuth Token Harvesting (T1556.004)
```spl
index=saas OR index=identity
| search "OAuth token" OR "session cookie"
| stats count by user, app_name, action
| table user, app_name, action, count
```
*Comment: Detects unauthorized harvesting of OAuth tokens and session cookies.*

### Detecting Edge Device Persistence (T1505.003)
```spl
index=network OR index=appliance
| search "BRICKSTORM" OR "custom malware"
| stats count by device_ip, device_type, process_name
| table device_ip, device_type, process_name, count
```
*Comment: Identifies malware persistence on edge devices like VPNs and routers.*

---

## 6. Executive Summary

The M-Trends 2026 report highlights significant advancements in adversary tactics, including the collapse of the "hand-off" window to just 22 seconds, the rise of voice phishing, and the systemic evolution of ransomware into recovery denial operations. Espionage groups are leveraging zero-days and targeting edge devices for extreme persistence, while cybercriminals focus on rapid impact. Organizations must prioritize behavioral anomaly detection, extend log retention, and adopt advanced identity verification measures to counter these threats effectively. Immediate action is recommended to isolate critical control planes and enhance visibility across the ecosystem.
```
