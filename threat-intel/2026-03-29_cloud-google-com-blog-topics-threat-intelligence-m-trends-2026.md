---
scraped_at: "2026-03-23T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified

### File Hashes
- None identified

### IP Addresses
- None identified

### Other IOCs
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques

#### Initial Access
- **T1190: Exploit Public-Facing Application**: Exploits remained the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**: Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**: Threat actors used stolen credentials, including OAuth tokens and session cookies, to gain unauthorized access to SaaS environments.

#### Persistence
- **T1505.003: Server Software Component - Web Shell**: Adversaries used in-memory malware like the BRICKSTORM backdoor to establish persistence on network appliances.
- **T1098: Account Manipulation**: Attackers exploited misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

#### Credential Access
- **T1552.001: Credentials In Files**: Threat actors stole hard-coded keys and personal access tokens from SaaS vendors to pivot into downstream environments.
- **T1557.002: Man-in-the-Middle - ARP Cache Poisoning**: Adversaries leveraged native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

#### Impact
- **T1485: Data Destruction**: Ransomware groups targeted backup infrastructure and virtualization management planes to destroy recovery capabilities.
- **T1486: Data Encrypted for Impact**: Ransomware operators encrypted hypervisor datastores, rendering associated virtual machines inoperable.

## 3. Malware & Tools

### Malware Families
- **REDBIKE (Akira)**: Used by ransomware groups to target backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Another ransomware family targeting backup systems and identity services.
- **BRICKSTORM**: Custom in-memory malware deployed on network appliances for deep persistence.
- **QUIETVAULT**: Credential stealer that checks for local AI command-line tools and executes predefined prompts to search for configuration files.

### Tools
- **PROMPTFLUX**: Malware that queries large language models (LLMs) mid-execution to evade detection.
- **PROMPTSTEAL**: Similar to PROMPTFLUX, used for evasion and data theft.

## 4. Threat Actor / Campaign Attribution

### Threat Actors
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices like VPNs and routers for extreme persistence.

### Campaigns
- **ShinyHunters-Branded SaaS Data Theft**: Campaign involving voice phishing to bypass MFA and steal SaaS credentials.

### Targeted Sectors
- High-tech sector (17%)
- Financial sector (14.6%)

## 5. Splunk Detection Searches

### Network IOCs

#### Detecting OAuth Token and Session Cookie Theft
```spl
index=network sourcetype=proxy OR sourcetype=firewall
| search "OAuth" OR "session cookie"
| stats count by src_ip, dest_ip, uri_path, user_agent
| table src_ip, dest_ip, uri_path, user_agent, count
```

### Endpoint IOCs

#### Detecting BRICKSTORM Backdoor
```spl
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| search EventCode=1 Image="*BRICKSTORM*"
| stats count by ComputerName, User, Image, CommandLine
| table _time, ComputerName, User, Image, CommandLine
```

#### Detecting Misconfigured Active Directory Certificate Services
```spl
index=wineventlog EventCode=4662
| search "Certificate Services" AND "Admin"
| stats count by ComputerName, User, ObjectName, AccessMask
| table _time, ComputerName, User, ObjectName, AccessMask
```

### Behavioral TTPs

#### Detecting Anomalous SaaS API Activity
```spl
index=api_logs sourcetype=aws:cloudtrail OR sourcetype=azure:activity OR sourcetype=gcp:activity
| search "api" AND ("token" OR "key" OR "access")
| stats count by user, action, resource, src_ip
| where count > 10
| table _time, user, action, resource, src_ip, count
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing (vishing) as a major initial access vector and the evolution of ransomware tactics to target recovery capabilities. Sophisticated threat actors are leveraging zero-day vulnerabilities and deploying in-memory malware like BRICKSTORM to achieve extreme persistence on edge devices. Additionally, attackers are increasingly exploiting SaaS environments by stealing OAuth tokens and session cookies. Organizations are advised to prioritize behavioral anomaly detection, extend log retention, and adopt stricter access controls to mitigate these advanced threats.