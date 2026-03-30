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
- **T1190 - Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing Link**: High-interactive voice phishing (vishing) surged to 11%, becoming the second-most common vector.
- **T1078 - Valid Accounts**: Prior compromise ranked as the third-most common initial infection vector globally (10%) and the top vector in ransomware operations (30%).

### Persistence
- **T1505.003 - Web Shell**: Attackers deploy custom, in-memory malware like the BRICKSTORM backdoor on network appliances for deep persistence.
- **T1574.010 - Services File Permissions Weakness**: Exploitation of misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1556.004 - Network Sniffing**: Adversaries leverage native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1552.001 - Credentials in Files**: Attackers steal hard-coded keys and personal access tokens from third-party SaaS vendors.
- **T1550.004 - Web Session Cookie**: Threat actors harvest long-lived OAuth tokens and session cookies to bypass standard defenses.

### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware operators encrypt hypervisor datastores to render all associated virtual machines inoperable.
- **T1485 - Data Destruction**: Attackers actively delete backup objects from cloud storage and target virtualization storage layers.

## 3. Malware & Tools

### Malware Families
- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for deep persistence.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families leveraging large language models (LLMs) to evade detection.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on targeted machines.

### Tools
- **AI Command-Line Tools**: Used by attackers to execute predefined prompts for reconnaissance and data theft.

## 4. Threat Actor / Campaign Attribution

### Threat Actors
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge and core network devices like VPNs and routers for extreme persistence.

### Campaigns
- **ClickFix**: Social engineering technique used by initial access brokers to gain a foothold in target networks.
- **ShinyHunters-Branded SaaS Data Theft**: Campaign involving the theft of hard-coded keys and personal access tokens from third-party SaaS vendors.

### Targeted Sectors
- High-tech sector (17%) and financial sector (14.6%) were the most frequently targeted industries in 2025.

## 5. Splunk Detection Searches

### Detecting OAuth Token and Session Cookie Harvesting
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="*/oauth2/token" OR uri_path="*/session/cookie"
| stats count by src_ip, dest_ip, uri_path, user
| where count > 10
```

### Detecting Exploitation of Public-Facing Applications
```spl
index=web_logs sourcetype=apache:access OR sourcetype=nginx:access
| search "POST" AND ("cmd=" OR "exec=" OR "shell=")
| stats count by src_ip, uri_path, http_user_agent
| where count > 5
```

### Detecting Anomalous SaaS API Usage
```spl
index=saas_logs sourcetype=okta:events OR sourcetype=azure:ad
| search event_type="api_call" AND ("token" OR "key" OR "session")
| stats count by user, app, action
| where count > 5
```

### Detecting Ransomware Targeting Backup Infrastructure
```spl
index=backup_logs sourcetype=aws:s3 OR sourcetype=azure:blob
| search "delete" AND "backup"
| stats count by src_ip, user, action
| where count > 10
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing (vishing) as a major initial access vector and the evolution of ransomware tactics to include recovery denial. Sophisticated espionage groups are leveraging zero-day vulnerabilities and targeting edge devices for extreme persistence, while cybercriminals are collapsing the "hand-off" window between initial access and secondary operations to mere seconds. Attackers are also increasingly abusing AI technologies to evade detection and accelerate their operations. Organizations are advised to adopt behavioral anomaly detection, extend log retention policies, and implement strict identity verification measures to counter these evolving threats.