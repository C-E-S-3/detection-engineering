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

### Initial Access
- **T1190: Exploit Public-Facing Application**: Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**: Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
- **T1199: Trusted Relationship**: Prior compromise ranked as the third-most common initial infection vector (10%) globally and the top vector in ransomware operations (30%).

### Persistence
- **T1505.003: Web Shell**: Adversaries are deploying custom, in-memory malware like the BRICKSTORM backdoor directly onto network appliances to establish deep persistence.
- **T1098.001: Account Manipulation - Additional Cloud Credentials**: Attackers exploit misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Credential Access
- **T1552.001: Credentials In Files**: Threat actors are stealing hard-coded keys and personal access tokens from third-party SaaS vendors.
- **T1557.002: Adversary-in-the-Middle - Application Layer Protocol**: Adversaries leverage native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

### Defense Evasion
- **T1027: Obfuscated Files or Information**: Malware families like PROMPTFLUX and PROMPTSTEAL query large language models (LLMs) mid-execution to evade detection.
- **T1556.004: Network Sniffing**: Adversaries use native packet-capturing functionality on edge devices to evade detection.

### Impact
- **T1485: Data Destruction**: Ransomware groups actively destroy recovery capabilities by targeting backup infrastructure and deleting backup objects from cloud storage.
- **T1486: Data Encrypted for Impact**: Ransomware operators encrypt hypervisor datastores, rendering associated virtual machines inoperable.

## 3. Malware & Tools
- **BRICKSTORM**: Custom, in-memory backdoor deployed on network appliances for extreme persistence.
- **PROMPTFLUX**: Malware that queries large language models (LLMs) mid-execution to evade detection.
- **PROMPTSTEAL**: Malware leveraging AI for evasion.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on targeted machines.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201 and UNC5807**: Espionage groups targeting edge and core network devices like VPNs and routers for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware operators targeting backup infrastructure, identity services, and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token Abuse
```spl
index=proxy sourcetype=access_combined
| search "Authorization: Bearer"
| stats count by src_ip, user, uri
| where count > 100
| table src_ip, user, uri, count
```

### Detecting Anomalous API Token Usage
```spl
index=api_logs sourcetype=aws:cloudtrail
| search eventName=AssumeRoleWithWebIdentity
| stats count by userIdentity.sessionContext.sessionIssuer.arn, src_ip
| where count > 50
| table userIdentity.sessionContext.sessionIssuer.arn, src_ip, count
```

### Detecting Hypervisor Datastore Encryption Attempts
```spl
index=vmware sourcetype=vmware:vsphere
| search "datastore" AND "encryption"
| stats count by host, user, _time
| table host, user, _time, count
```

### Detecting Packet-Capturing on Edge Devices
```spl
index=network sourcetype=firewall
| search "packet capture" OR "tcpdump" OR "wireshark"
| stats count by src_ip, dest_ip, _time
| table src_ip, dest_ip, _time, count
```

### Detecting BRICKSTORM Backdoor Activity
```spl
index=network sourcetype=network_traffic
| search "BRICKSTORM"
| stats count by src_ip, dest_ip, _time
| table src_ip, dest_ip, _time, count
```

## 6. Executive Summary
The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of sophisticated cyber espionage groups and the evolution of ransomware tactics to target recovery capabilities. Key findings include the increased use of voice phishing, the exploitation of edge devices for extreme persistence, and the abuse of AI for evasion and credential theft. Organizations are advised to prioritize behavioral anomaly detection, extend log retention policies, and implement strict access controls for critical infrastructure. Immediate action is recommended to address these emerging threats and enhance operational resilience.