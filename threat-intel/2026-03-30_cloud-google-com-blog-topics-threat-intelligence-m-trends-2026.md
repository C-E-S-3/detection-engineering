---
  scraped_at: "2026-03-23T00:00:00Z"
  source_url: "https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/"
  report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- No new IP addresses identified.

### Domains/URLs
- No new domains/URLs identified.

### File Hashes
- No new file hashes identified.

### Email Addresses
- No new email addresses identified.

### File Names/Paths
- No new file names/paths identified.

### Registry Keys
- No new registry keys identified.

### Mutex Names
- No new mutex names identified.

### C2 Infrastructure
- No new C2 infrastructure identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques

- **Tactic: Initial Access**
  - **T1190: Exploit Public-Facing Application**
    - Exploits remained the most common initial infection vector, accounting for 32% of intrusions.
  - **T1566.002: Spearphishing via Service**
    - Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
  - **T1078: Valid Accounts**
    - Threat actors leveraged compromised credentials, including OAuth tokens and session cookies, to gain access to SaaS environments.

- **Tactic: Persistence**
  - **T1505.003: Server Software Component - Web Shell**
    - Attackers pre-staged malware or tunnels during initial infections to enable immediate secondary operations.
  - **T1547.001: Boot or Logon Autostart Execution**
    - Adversaries exploited misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.
  - **T1547.006: Boot or Logon Autostart Execution: Kernel Modules and Extensions**
    - Custom in-memory malware like BRICKSTORM was deployed on edge devices for extreme persistence.

- **Tactic: Credential Access**
  - **T1552.001: Unsecured Credentials: Credentials In Files**
    - Threat actors stole hard-coded keys and personal access tokens from SaaS vendors.
  - **T1557.002: Adversary-in-the-Middle: Network Device**
    - Adversaries leveraged native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

- **Tactic: Impact**
  - **T1485: Data Destruction**
    - Ransomware operators targeted backup infrastructure and virtualization management planes to destroy recovery capabilities.
  - **T1486: Data Encrypted for Impact**
    - Attackers encrypted hypervisor datastores, rendering associated virtual machines inoperable.

## 3. Malware & Tools

- **BRICKSTORM**: Custom in-memory backdoor deployed on network appliances for extreme persistence.
- **PROMPTFLUX** and **PROMPTSTEAL**: Malware families utilizing large language models (LLMs) to evade detection.
- **QUIETVAULT**: Credential stealer targeting local AI command-line tools to extract sensitive data.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201**: Exploits edge and core network devices for extreme persistence.
- **UNC5807**: Focuses on targeting VPNs and routers to evade detection.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware groups targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token Abuse
```spl
index=proxy sourcetype=access_combined
| search "Authorization: Bearer"
| stats count by src_ip, user, uri_path
| where count > 10
| table src_ip, user, uri_path, count
```

### Detecting Malicious Use of SaaS Integration Tokens
```spl
index=cloud sourcetype=aws:cloudtrail OR sourcetype=gcp:pubsub
| search "AssumeRole" OR "GenerateAccessToken"
| stats count by user, src_ip, action
| where count > 5
| table user, src_ip, action, count
```

### Detecting Hypervisor Datastore Access
```spl
index=vmware sourcetype=vmware:vsphere
| search "datastore" AND ("delete" OR "encrypt")
| stats count by user, host, action
| where count > 1
| table user, host, action, count
```

### Detecting Packet-Capturing on Edge Devices
```spl
index=network sourcetype=network:device
| search "packet capture" OR "tcpdump" OR "wireshark"
| stats count by src_ip, dest_ip, action
| where count > 5
| table src_ip, dest_ip, action, count
```

### Detecting Voice Phishing (Vishing) Attempts
```spl
index=voip sourcetype=voip:calllogs
| search "caller_id"="*" AND "call_duration" > 300
| stats count by caller_id, callee_id, call_duration
| where count > 1
| table caller_id, callee_id, call_duration, count
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant advancements in adversary tactics, including the rise of voice phishing (vishing) as a major initial access vector, the use of AI-powered malware, and the targeting of edge devices for extreme persistence. Ransomware groups have evolved their operations to focus on recovery denial by attacking backup and virtualization infrastructure. Organizations are advised to prioritize behavioral anomaly detection, extend log retention policies, and adopt strict access controls for critical systems to mitigate these emerging threats.