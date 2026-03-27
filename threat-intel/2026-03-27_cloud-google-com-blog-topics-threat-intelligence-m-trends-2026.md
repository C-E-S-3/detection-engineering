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
- **T1190 - Exploit Public-Facing Application**  
  Exploits remained the most common initial infection vector, accounting for 32% of intrusions globally.
- **T1566.002 - Spearphishing via Service**  
  Highly interactive voice phishing surged to 11%, targeting IT help desks to bypass MFA.

### Persistence
- **T1505.003 - Web Shell**  
  Attackers deploy custom in-memory malware like BRICKSTORM onto edge devices, achieving extreme persistence.
- **T1078.004 - Privileged Account Abuse**  
  Exploiting misconfigured Active Directory Certificate Services templates to create admin accounts bypassing password rotation.

### Defense Evasion
- **T1553.002 - Subvert Trust Controls**  
  Attackers harvest long-lived OAuth tokens and session cookies to bypass defenses.
- **T1027 - Obfuscated Files or Information**  
  Malware families like PROMPTFLUX query large language models (LLMs) mid-execution to evade detection.

### Impact
- **T1486 - Data Encrypted for Impact**  
  Ransomware groups encrypt hypervisor datastores, rendering associated virtual machines inoperable.
- **T1485 - Data Destruction**  
  Attackers actively delete backup objects from cloud storage and destroy recovery capabilities.

## 3. Malware & Tools

### Malware Families
- **REDBIKE (Akira)**  
  Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**  
  Ransomware with similar tactics to REDBIKE.
- **BRICKSTORM**  
  In-memory malware deployed on edge devices for extreme persistence.
- **PROMPTFLUX and PROMPTSTEAL**  
  Malware families leveraging AI to evade detection.
- **QUIETVAULT**  
  Credential stealer targeting local AI command-line tools.

### Legitimate Tools Abused
- **OAuth Tokens and Session Cookies**  
  Used to bypass authentication mechanisms in SaaS environments.
- **Native Packet-Capturing Functionality**  
  Leveraged on edge devices to intercept sensitive data and plaintext credentials.

### Custom Tooling
- **Custom In-Memory Malware**  
  Designed for deployment on edge devices to achieve persistence and evade detection.

## 4. Threat Actor / Campaign Attribution

### Named Threat Groups
- **UNC3944**  
  Known for voice phishing campaigns targeting IT help desks to bypass MFA.
- **UNC6201**  
  Exploits edge devices and zero-day vulnerabilities for extreme persistence.
- **UNC5807**  
  Focuses on edge and core network devices to evade detection.

### Campaign Names
- **ClickFix**  
  Social engineering technique used for initial access.

### Known Affiliations or Motivations
- **Cyber Espionage**  
  Groups like UNC6201 and UNC5807 optimize for persistence and intelligence gathering.
- **Cyber Crime**  
  Groups using REDBIKE and AGENDA focus on ransomware and recovery denial.

### Targeted Sectors and Geographies
- **High Tech Sector**  
  Most frequently targeted (17% of incidents).
- **Financial Sector**  
  Second-most targeted (14.6% of incidents).

## 5. Splunk Detection Searches

### Detect OAuth Token Abuse
```spl
index=proxy OR index=firewall
sourcetype=pan:traffic OR sourcetype=bluecoat:proxy
"OAuth" OR "session cookie"
| stats count by src_ip, dest_ip, uri
| where count > 10
```
*Detects anomalous OAuth token or session cookie usage.*

### Detect Ransomware Backup Deletion
```spl
index=aws:cloudtrail OR index=azure:activity
eventName="DeleteObject" AND bucketName="backup*"
| stats count by userIdentity.arn, bucketName
| where count > 5
```
*Identifies suspicious deletion of backup objects in cloud storage.*

### Detect Edge Device Packet Capturing
```spl
index=network
sourcetype=cisco:ios OR sourcetype=juniper:logs
"packet capture" OR "sniffer"
| stats count by src_ip, dest_ip
| where count > 10
```
*Flags unauthorized packet-capturing activity on edge devices.*

### Detect Hypervisor Datastore Encryption
```spl
index=vmware:vsphere
eventType="datastoreEncrypted"
| stats count by host, datastore
| where count > 0
```
*Detects hypervisor datastore encryption events.*

## 6. Executive Summary

The M-Trends 2026 report highlights a rapidly evolving threat landscape characterized by increased adversary sophistication and collaboration. Key trends include the rise of voice phishing, extreme persistence on edge devices, and destructive ransomware targeting recovery capabilities. Organizations must prioritize behavioral anomaly detection, extend log retention policies, and isolate critical control planes to mitigate these threats effectively. Immediate actions include restructuring response playbooks to address shrinking hand-off windows and implementing continuous identity verification to counter social engineering attacks.
```
