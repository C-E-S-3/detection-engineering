---
scraped_at: "2026-03-23T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains
- None identified

### Hashes
- None identified

### IPs
- None identified

### Other IOCs
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques

- **Tactic: Initial Access**
  - **Technique ID:** T1190 (Exploit Public-Facing Application)
    - **Description:** Exploits remained the most common initial infection vector, accounting for 32% of intrusions in 2025.
  - **Technique ID:** T1566.002 (Phishing: Spearphishing Link)
    - **Description:** Highly interactive voice phishing (vishing) surged to 11%, becoming the second-most common initial infection vector in 2025.
  - **Technique ID:** T1078 (Valid Accounts)
    - **Description:** Adversaries used compromised credentials, including OAuth tokens and session cookies, to gain access to SaaS environments.

- **Tactic: Persistence**
  - **Technique ID:** T1505.003 (Server Software Component: Web Shell)
    - **Description:** Threat actors deployed custom in-memory malware like the BRICKSTORM backdoor onto network appliances for extreme persistence.

- **Tactic: Credential Access**
  - **Technique ID:** T1552.001 (Unsecured Credentials: Credentials In Files)
    - **Description:** Threat actors used the QUIETVAULT credential stealer to search for configuration files and harvest credentials.
  - **Technique ID:** T1557.002 (Adversary-in-the-Middle: Network Device)
    - **Description:** Adversaries leveraged native packet-capturing functionality on edge devices to intercept sensitive data and plaintext credentials.

- **Tactic: Impact**
  - **Technique ID:** T1485 (Data Destruction)
    - **Description:** Ransomware operators targeted backup infrastructure, identity services, and virtualization management planes to destroy recovery capabilities.
  - **Technique ID:** T1486 (Data Encrypted for Impact)
    - **Description:** Attackers encrypted hypervisor datastores, rendering associated virtual machines inoperable.

## 3. Malware & Tools

- **BRICKSTORM:** Custom in-memory backdoor deployed on network appliances to achieve extreme persistence.
- **PROMPTFLUX & PROMPTSTEAL:** Malware families leveraging AI and large language models (LLMs) to evade detection.
- **QUIETVAULT:** Credential stealer targeting local AI command-line tools to extract configuration files.

## 4. Threat Actor / Campaign Attribution

- **UNC3944:** Known for targeting IT help desks to bypass MFA and gain initial access to SaaS environments.
- **UNC6201 & UNC5807:** Espionage groups targeting edge and core network devices for extreme persistence.
- **REDBIKE (Akira) & AGENDA (Qilin):** Ransomware groups focusing on recovery denial by targeting backup infrastructure and virtualization management planes.

## 5. Splunk Detection Searches

### Detecting OAuth Token and Session Cookie Theft
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="*/oauth2/token" OR uri_path="*/session/cookie"
| stats count by src_ip, dest_ip, uri_path, user
| where count > 10
| table src_ip, dest_ip, uri_path, user
```

### Detecting Anomalous Bulk API Operations
```spl
index=api_logs sourcetype=api:gateway
| stats count by api_endpoint, user, http_method
| where count > 100
| table api_endpoint, user, http_method, count
```

### Detecting Hypervisor Datastore Access
```spl
index=vmware_logs sourcetype=vmware:vsphere
| search event_type="datastore_access"
| stats count by user, vm_name, datastore
| where count > 5
| table user, vm_name, datastore, count
```

### Detecting Packet-Capturing on Edge Devices
```spl
index=network_device_logs sourcetype=cisco:ios
| search "packet capture started"
| stats count by src_ip, dest_ip, device_name
| table src_ip, dest_ip, device_name, count
```

### Detecting BRICKSTORM Backdoor Activity
```spl
index=network_device_logs sourcetype=cisco:ios
| search "in-memory process execution" OR "unexpected process"
| stats count by process_name, device_name, src_ip
| table process_name, device_name, src_ip
```

## 6. Executive Summary

The M-Trends 2026 report highlights significant shifts in the cyber threat landscape, including the rise of voice phishing, the collapse of the "hand-off" window between initial access and secondary operations, and the evolution of ransomware into recovery denial attacks. Espionage groups are increasingly targeting edge devices for extreme persistence, leveraging zero-day vulnerabilities and deploying in-memory malware like BRICKSTORM. Additionally, attackers are exploiting AI technologies to evade detection and accelerate their operations. Organizations are advised to prioritize behavioral anomaly detection, extend log retention policies, and adopt robust identity verification measures to counter these advanced threats.