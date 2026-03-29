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
- **T1190: Exploit Public-Facing Application**: Exploits remained the most common initial infection vector, accounting for 32% of intrusions.
- **T1566.002: Spearphishing via Service**: Highly interactive voice phishing surged to 11%, becoming the second-most common initial infection vector.
- **T1078: Valid Accounts**: Threat actors used compromised credentials, including hard-coded keys and personal access tokens, to gain access to SaaS environments.

### Persistence
- **T1505.003: Web Shell**: Threat actors deployed custom in-memory malware like the BRICKSTORM backdoor on network appliances for deep persistence.
- **T1098.004: Credential Switching**: Exploitation of misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

### Defense Evasion
- **T1556.004: Network Sniffing**: Adversaries leveraged native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.
- **T1558.003: Steal Application Access Token**: Threat actors harvested OAuth tokens and session cookies to bypass standard defenses.

### Impact
- **T1486: Data Encrypted for Impact**: Ransomware groups targeted backup infrastructure and virtualization management planes to encrypt data and destroy recovery capabilities.
- **T1485: Data Destruction**: Attackers actively deleted backup objects from cloud storage and targeted virtualization storage layers to render virtual machines inoperable.

## 3. Malware & Tools
- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for deep persistence.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families leveraging AI to evade detection.
- **QUIETVAULT**: Credential stealer that executes predefined prompts to search for configuration files on compromised systems.

## 4. Threat Actor / Campaign Attribution
- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201** and **UNC5807**: Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token Harvesting
```spl
index=proxy sourcetype=bluecoat:proxysg OR sourcetype=squid
| search "Authorization: Bearer"
| stats count by src_ip, dest_ip, dest_port, uri_path, user
| where count > 10
| table src_ip, dest_ip, dest_port, uri_path, user
```
*Comment: This search identifies anomalous OAuth token usage patterns by analyzing HTTP headers for repeated token usage.*

### Detecting Backup Object Deletion in Cloud Storage
```spl
index=aws sourcetype=aws:cloudtrail
| search eventName=DeleteObject
| stats count by userIdentity.arn, requestParameters.bucketName, requestParameters.key
| where count > 5
| table userIdentity.arn, requestParameters.bucketName, requestParameters.key
```
*Comment: This search detects suspicious deletion of backup objects in AWS S3 buckets.*

### Detecting Exploitation of Active Directory Certificate Services
```spl
index=wineventlog sourcetype=XmlWinEventLog:Security EventCode=4670
| search ObjectName="*Certificate Templates*"
| stats count by SubjectUserName, ObjectName, AccessMask
| where AccessMask="WRITE_OWNER"
| table SubjectUserName, ObjectName, AccessMask
```
*Comment: This search identifies unauthorized modifications to Active Directory Certificate Services templates.*

### Detecting In-Memory Malware on Network Appliances
```spl
index=network sourcetype=firewall OR sourcetype=network:traffic
| search "BRICKSTORM"
| stats count by src_ip, dest_ip, dest_port, signature
| table src_ip, dest_ip, dest_port, signature
```
*Comment: This search identifies network traffic associated with the BRICKSTORM backdoor.*

### Detecting Voice Phishing Attempts
```spl
index=voip sourcetype=cisco:callmanager
| search "caller_id"="*" AND "call_type"="incoming"
| stats count by caller_id, call_type
| where count > 10
| table caller_id, call_type
```
*Comment: This search identifies potential voice phishing attempts by analyzing high-frequency incoming calls.*

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, the collapse of the "hand-off" window in cybercrime operations, and the evolution of ransomware into recovery denial attacks. Sophisticated threat actors are increasingly targeting edge devices and leveraging zero-day vulnerabilities for extreme persistence, while also exploiting SaaS environments via stolen OAuth tokens and session cookies. Organizations are advised to prioritize behavioral anomaly detection, extend log retention policies, and treat low-impact alerts as critical indicators to counter these advanced threats. Immediate action is recommended to secure critical control planes, isolate backup environments, and implement continuous identity verification to mitigate risks.