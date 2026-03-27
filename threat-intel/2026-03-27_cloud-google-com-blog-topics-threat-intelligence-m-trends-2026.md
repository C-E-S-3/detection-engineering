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

---

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1190 - Exploit Public-Facing Application**  
  Exploits were the most common initial infection vector, accounting for 32% of intrusions.

- **T1566.002 - Spearphishing via Service**  
  Highly interactive voice phishing surged to 11%, targeting IT help desks to bypass MFA.

- **T1078 - Valid Accounts**  
  Attackers leveraged compromised SaaS vendor credentials and hard-coded keys to pivot into downstream environments.

### Persistence
- **T1505.003 - Web Shell**  
  Custom in-memory malware like BRICKSTORM deployed on edge devices for extreme persistence.

- **T1556.004 - Credential API Hooking**  
  Attackers harvested OAuth tokens and session cookies to maintain access.

### Impact
- **T1486 - Data Encrypted for Impact**  
  Ransomware groups encrypted hypervisor datastores, rendering associated virtual machines inoperable.

- **T1485 - Data Destruction**  
  Backup infrastructure and cloud storage objects were actively deleted.

### Defense Evasion
- **T1070.004 - File Deletion**  
  Attackers deleted backup objects from cloud storage to evade recovery.

- **T1027 - Obfuscated Files or Information**  
  Malware families like PROMPTFLUX queried LLMs mid-execution to evade detection.

---

## 3. Malware & Tools

### Malware Families
- **REDBIKE (Akira)**  
  Ransomware targeting backup infrastructure and virtualization management planes.

- **AGENDA (Qilin)**  
  Ransomware focused on recovery denial.

- **BRICKSTORM**  
  In-memory malware deployed on edge devices for deep persistence.

- **PROMPTFLUX / PROMPTSTEAL**  
  Malware leveraging AI models to evade detection.

- **QUIETVAULT**  
  Credential stealer targeting local AI command-line tools.

### Legitimate Tools Abused
- **OAuth Tokens**  
  Harvested for persistence and lateral movement.

- **Session Cookies**  
  Used to bypass authentication mechanisms.

---

## 4. Threat Actor / Campaign Attribution

### Named Threat Groups
- **UNC3944**  
  Known for voice phishing campaigns targeting IT help desks.

- **UNC6201**  
  Exploiting edge devices and zero-day vulnerabilities.

- **UNC5807**  
  Focused on extreme persistence via edge devices.

### Campaign Names
- None explicitly named.

### Known Affiliations or Motivations
- **Cyber Espionage**  
  Groups targeting edge devices for persistence and intelligence gathering.

- **Financial Gain**  
  Ransomware operators focusing on recovery denial.

### Targeted Sectors and Geographies
- **High-Tech Sector** (17%)  
  Most frequently targeted industry in 2025.  
- **Financial Sector** (14.6%)  
  Previously the top target in 2024 and 2023.

---

## 5. Splunk Detection Searches

### Detect Exploit Attempts on Public-Facing Applications
```spl
index=firewall OR index=proxy OR index=dns
sourcetype=firewall OR sourcetype=proxy OR sourcetype=dns
| search "exploit attempt" OR "public-facing application"
| stats count by src_ip, dest_ip, dest_port
| table src_ip, dest_ip, dest_port, count
```
*Detects exploit attempts targeting public-facing applications.*

### Detect Voice Phishing Activity
```spl
index=voice_logs OR index=call_center
sourcetype=voice:logs OR sourcetype=call:logs
| search "help desk" AND ("MFA bypass" OR "social engineering")
| stats count by caller_id, recipient_id
| table caller_id, recipient_id, count
```
*Identifies voice phishing targeting IT help desks.*

### Detect OAuth Token Harvesting
```spl
index=web OR index=application_logs
sourcetype=web:logs OR sourcetype=app:logs
| search "OAuth token" AND ("harvest" OR "compromise")
| stats count by user, app_name
| table user, app_name, count
```
*Flags suspicious OAuth token harvesting activities.*

### Detect Ransomware Backup Deletion
```spl
index=cloud_storage OR index=backup_logs
sourcetype=cloud:storage OR sourcetype=backup:logs
| search "delete" AND ("backup object" OR "cloud storage")
| stats count by user, action, resource
| table user, action, resource, count
```
*Detects deletion of backup objects in cloud storage.*

---

## 6. Executive Summary

The M-Trends 2026 report highlights a rapidly evolving threat landscape characterized by increased adversary sophistication and collaboration. Key trends include the rise of voice phishing, exploitation of edge devices for persistence, and ransomware operations targeting recovery capabilities. Threat actors are leveraging AI to evade detection and accelerate attacks, while organizations face growing challenges in maintaining visibility and resilience. Immediate actions include enhancing identity verification, implementing behavioral anomaly detection, and extending log retention policies to mitigate risks from advanced threats.
```
