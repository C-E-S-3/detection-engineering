```markdown
---
scraped_at: 2026-03-23T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
report_type: threat-intel
---

# Threat Intelligence Report: M-Trends 2026

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None observed.

### Domains and URLs
- None observed.

### File Hashes
- None observed.

### Email Addresses
- None observed.

### File Names and Paths
- None observed.

### Registry Keys
- None observed.

### Mutex Names
- None observed.

### C2 Infrastructure Details
- None observed.

---

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1190 - Exploit Public-Facing Application**  
  Exploits remain the most common initial infection vector, accounting for 32% of intrusions globally.
- **T1566.002 - Spearphishing via Service**  
  Highly interactive voice phishing surged to 11%, targeting IT help desks to bypass MFA and gain access to SaaS environments.

### Execution
- **T1203 - Exploitation for Client Execution**  
  Exploitation of zero-day vulnerabilities, including edge devices and network appliances, with a mean time to exploit of -7 days.

### Persistence
- **T1505.003 - Web Shell**  
  Deployment of custom in-memory malware like BRICKSTORM backdoor on network appliances for extreme persistence.
- **T1078.003 - Valid Accounts: Local Accounts**  
  Exploitation of Active Directory Certificate Services templates to create admin accounts bypassing password rotation.

### Defense Evasion
- **T1553.002 - Subvert Trust Controls**  
  Harvesting long-lived OAuth tokens and session cookies to bypass defenses and pivot into downstream environments.
- **T1027 - Obfuscated Files or Information**  
  Use of AI-powered malware families like PROMPTFLUX and PROMPTSTEAL to evade detection.

### Impact
- **T1486 - Data Encrypted for Impact**  
  Ransomware groups encrypt hypervisor datastores, rendering associated virtual machines inoperable.
- **T1485 - Data Destruction**  
  Systemic destruction of backup infrastructure and virtualization management planes to deny recovery.

---

## 3. Malware & Tools

### Malware Families
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware with similar destructive tactics.
- **BRICKSTORM**: Custom in-memory malware targeting edge devices for extreme persistence.
- **PROMPTFLUX**: AI-powered malware querying LLMs mid-execution for evasion.
- **PROMPTSTEAL**: AI-powered malware used for intellectual property theft.
- **QUIETVAULT**: Credential stealer leveraging local AI command-line tools.

### Legitimate Tools Abused
- **OAuth Tokens**: Harvested for unauthorized access.
- **Session Cookies**: Used to bypass authentication mechanisms.

### Custom Tooling
- **In-memory malware**: Designed for edge devices with minimal onboard storage, evading traditional security tooling.

---

## 4. Threat Actor / Campaign Attribution

### Named Threat Groups
- **UNC3944**: Known for voice phishing targeting IT help desks to bypass MFA.
- **UNC6201**: Exploiting edge devices and zero-days for extreme persistence.
- **UNC5807**: Similar tactics targeting VPNs and routers.

### Campaign Names
- **ShinyHunters-Branded SaaS Data Theft**: Focused on SaaS environments and OAuth token abuse.

### Known Affiliations or Motivations
- **Cyber Espionage**: Targeting edge devices for persistence and intelligence gathering.
- **Financial Gain**: Ransomware operations optimized for recovery denial.

### Targeted Sectors and Geographies
- **High-Tech Sector**: Most frequently targeted (17% of incidents).
- **Financial Sector**: Second most targeted (14.6% of incidents).

---

## 5. Splunk Detection Searches

### Detect OAuth Token Harvesting
```spl
index=proxy OR index=firewall sourcetype=pan:traffic OR sourcetype=bluecoat:proxy
| search "OAuth" OR "token"
| stats count by src_ip, dest_ip, dest_port, uri
| table src_ip, dest_ip, dest_port, uri, count
```
*Comment: Detects OAuth token-related activity in network traffic.*

### Detect Voice Phishing Attempts
```spl
index=crowdstrike:events:sensor OR index=XmlWinEventLog sourcetype=WinEventLog:Security
| search EventCode=4624 AccountName="helpdesk" AuthenticationPackageName="Interactive"
| stats count by AccountName, src_ip, dest_ip
| table AccountName, src_ip, dest_ip, count
```
*Comment: Flags interactive logins potentially linked to voice phishing targeting IT help desks.*

### Detect Ransomware Targeting Hypervisors
```spl
index=vmware sourcetype=vmware:logs
| search "datastore" AND ("encrypt" OR "delete")
| stats count by vm_name, user, action
| table vm_name, user, action, count
```
*Comment: Monitors VMware logs for encryption or deletion of datastores.*

### Detect BRICKSTORM Malware on Edge Devices
```spl
index=network sourcetype=cisco:ios OR sourcetype=juniper:logs
| search "packet capture" AND ("malware" OR "BRICKSTORM")
| stats count by src_ip, dest_ip, action
| table src_ip, dest_ip, action, count
```
*Comment: Identifies suspicious packet capture activity linked to BRICKSTORM malware.*

---

## 6. Executive Summary

The M-Trends 2026 report highlights a rapidly evolving threat landscape characterized by increased adversary specialization, collaboration, and technological sophistication. Key trends include the rise of voice phishing, destructive ransomware targeting recovery capabilities, and extreme persistence via edge devices and zero-day exploits. Organizations must prioritize behavioral anomaly detection, extend log retention policies, and isolate critical control planes to mitigate these threats effectively. Immediate action is recommended to address visibility gaps and enhance resilience against advanced adversary tactics.
```
