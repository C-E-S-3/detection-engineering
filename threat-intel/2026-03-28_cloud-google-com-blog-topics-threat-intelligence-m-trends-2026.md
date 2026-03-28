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

- **Tactic: Initial Access**
  - **T1190: Exploit Public-Facing Application**
    - Exploits remain the most common initial infection vector, accounting for 32% of intrusions.
  - **T1566.002: Spearphishing via Service**
    - Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector.
  - **T1078: Valid Accounts**
    - Threat actors are leveraging compromised SaaS credentials, OAuth tokens, and session cookies to gain unauthorized access.

- **Tactic: Persistence**
  - **T1505.003: Web Shell**
    - Adversaries are deploying custom in-memory malware like the BRICKSTORM backdoor on network appliances for deep persistence.
  - **T1078.003: Valid Accounts - Cloud Accounts**
    - Attackers are exploiting hard-coded keys and personal access tokens in third-party SaaS vendors to pivot into downstream environments.

- **Tactic: Defense Evasion**
  - **T1218: Signed Binary Proxy Execution**
    - Adversaries are leveraging native network functionalities and tools to evade detection.
  - **T1553.004: Subvert Trust Controls - Install Root Certificate**
    - Exploiting misconfigured Active Directory Certificate Services templates to create admin accounts that bypass password rotation.

- **Tactic: Credential Access**
  - **T1552.001: Credentials in Files**
    - Threat actors are harvesting long-lived OAuth tokens and session cookies.
  - **T1557.002: Adversary-in-the-Middle**
    - Leveraging native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

- **Tactic: Impact**
  - **T1486: Data Encrypted for Impact**
    - Ransomware operators are encrypting hypervisor datastores to render virtual machines inoperable.
  - **T1485: Data Destruction**
    - Attackers are actively deleting backup objects from cloud storage and targeting virtualization storage layers to destroy recovery capabilities.

## 3. Malware & Tools

- **BRICKSTORM**: A custom in-memory backdoor deployed on network appliances for deep persistence.
- **REDBIKE (Akira)**: Ransomware targeting backup infrastructure and virtualization management planes.
- **AGENDA (Qilin)**: Ransomware targeting identity services and backup environments.
- **PROMPTFLUX**: Malware querying large language models (LLMs) mid-execution to evade detection.
- **PROMPTSTEAL**: Malware leveraging AI for evasion.
- **QUIETVAULT**: Credential stealer targeting local AI command-line tools to extract sensitive data.

## 4. Threat Actor / Campaign Attribution

- **UNC3944**: Known for targeting IT help desks to bypass MFA and gain access to SaaS environments.
- **UNC6201**: Focused on exploiting edge and core network devices for extreme persistence.
- **UNC5807**: Similar focus on edge devices and long-term persistence.
- **REDBIKE (Akira)** and **AGENDA (Qilin)**: Ransomware operators targeting recovery capabilities.

## 5. Splunk Detection Searches

### Detecting OAuth Token Harvesting
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="*/oauth2/token"
| stats count by src_ip, user, uri_path
| where count > 10
```

### Detecting Voice Phishing Attempts
```spl
index=voip_logs sourcetype=voip:call
| search "caller_id"="*"
| stats count by caller_id, dest_number
| where count > 5
```

### Detecting Ransomware Targeting Backup Infrastructure
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Security-Auditing
EventCode=4663 Object_Type="File" Object_Name="*backup*"
| stats count by Account_Name, Object_Name, Accesses
| where Accesses="DELETE"
```

### Detecting BRICKSTORM Backdoor Activity
```spl
index=network sourcetype=firewall
| search "packet_capture"="enabled"
| stats count by src_ip, dest_ip, action
| where action="ALLOW"
```

### Detecting Hypervisor Datastore Encryption
```spl
index=vmware sourcetype=vmware:logs
| search "datastore" "encryption"
| stats count by host, user, action
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, the evolution of ransomware into recovery denial, and the exploitation of edge devices for extreme persistence. Notable threat actors like UNC3944 and UNC6201 are leveraging advanced techniques to bypass defenses and establish long-term footholds. Organizations are advised to adopt behavioral anomaly detection, enhance log retention, and implement strict access controls to counter these emerging threats. Immediate action is recommended to address the growing sophistication of adversaries and their ability to exploit vulnerabilities at an unprecedented pace.
