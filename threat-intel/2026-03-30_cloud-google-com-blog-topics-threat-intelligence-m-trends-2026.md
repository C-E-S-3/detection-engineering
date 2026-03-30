---
scraped_at: "2026-03-23T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/"
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

### Tactics and Techniques

#### Initial Access
- **T1190 - Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002 - Spearphishing via Service**: High-interaction voice phishing surged to 11%, becoming the second-most common initial infection vector.
- **T1078 - Valid Accounts**: Prior compromise was the third-most common initial infection vector globally (10%) and the top vector in ransomware operations (30%).

#### Persistence
- **T1505.003 - Server Software Component: Web Shell**: Adversaries are deploying custom in-memory malware like the BRICKSTORM backdoor directly onto network appliances for deep persistence.
- **T1098 - Account Manipulation**: Exploiting misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

#### Defense Evasion
- **T1556.004 - Network Sniffing**: Leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1558.003 - Steal Application Access Token**: Harvesting long-lived OAuth tokens and session cookies to bypass defenses.

#### Impact
- **T1486 - Data Encrypted for Impact**: Ransomware groups encrypting hypervisor datastores to render associated virtual machines inoperable.
- **T1490 - Inhibit System Recovery**: Actively targeting backup infrastructure and deleting backup objects from cloud storage.

## 3. Malware & Tools

- **BRICKSTORM**: Custom in-memory malware deployed on network appliances for deep persistence.
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware exploiting misconfigured Active Directory Certificate Services templates.
- **PROMPTFLUX and PROMPTSTEAL**: Malware families leveraging AI to evade detection.
- **QUIETVAULT**: Credential stealer executing predefined prompts to search for configuration files.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **North Korean IT Workers**: Associated with prolonged dwell times (122 days) in cyber espionage incidents.

## 5. Splunk Detection Searches

### Network IOCs

#### Detecting OAuth Token Harvesting
```spl
index=proxy sourcetype=bluecoat:proxysg OR sourcetype=squid
| search uri_path="*/oauth2/token"
| stats count by src_ip, dest_ip, uri_path, user_agent
| where count > 10
```

### Endpoint IOCs

#### Detecting BRICKSTORM Malware
```spl
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=1 Image="*\\BRICKSTORM.dll"
| stats count by ComputerName, User, Image
```

### Behavioral TTPs

#### Detecting Anomalous Bulk API Operations
```spl
index=api_logs sourcetype=aws:cloudtrail
| search eventName IN ("ListBuckets", "GetObject", "PutObject")
| stats count by userIdentity.arn, eventName, sourceIPAddress
| where count > 100
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, the evolution of ransomware into recovery denial, and the exploitation of edge devices for extreme persistence. Notable malware families such as BRICKSTORM and PROMPTFLUX demonstrate advanced evasion techniques, including AI integration. Organizations must prioritize behavioral anomaly detection, extend log retention, and implement strict access controls to mitigate these evolving threats. Immediate action is recommended to isolate critical control planes and enhance detection capabilities for edge devices and SaaS environments.