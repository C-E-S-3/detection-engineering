---
scraped_at: "2026-04-02T14:32:23Z"
source_url: "https://blog.talosintelligence.com/uat-10608-inside-a-large-scale-automated-credential-harvesting-operation-targeting-web-applications/"
report_type: threat-intel
severity: "critical"
title: "UAT-10608 automated credential harvesting via CVE-2025-55182 and NEXUS Listener framework"
---

## 1. Indicators of Compromise (IOCs)
### IP Addresses
- 144.172.102.88 (C2 server hosting NEXUS Listener)
- 172.86.127.128 (C2 server hosting NEXUS Listener)
- 144.172.112.136 (C2 server hosting NEXUS Listener)
- 144.172.117.112 (C2 server hosting NEXUS Listener)

### Domains
No new domains identified.

### File Hashes
No new hashes identified.

### File Paths
- `/tmp/.eba9ee1e4.sh` (Staged payload dropper script)

### URLs
- `http://<NEXUS_LISTENER_IP>:8080/h=<VICTIM_HOSTNAME>&l=info&id=123abc45` (Callback URL for exfiltration)
- `http://<NEXUS_LISTENER_IP>:8080/h=<VICTIM_HOSTNAME>&l=jsenv&id=123abc45` (Callback URL for exfiltration)
- `http://<NEXUS_LISTENER_IP>:8080/h=<VICTIM_HOSTNAME>&l=k8s&id=123abc45` (Callback URL for exfiltration)
- `http://<NEXUS_LISTENER_IP>:8080/h=<VICTIM_HOSTNAME>&l=crontab&id=123abc45` (Callback URL for exfiltration)

## 2. TTPs (MITRE ATT&CK Mapping)
### Tactics and Techniques
- **Initial Access**: T1190 - Exploit Public-Facing Application
  - Exploitation of CVE-2025-55182 (React2Shell vulnerability in Next.js applications).
- **Execution**: T1059.004 - Command and Scripting Interpreter: Unix Shell
  - Use of staged shell scripts for credential harvesting.
- **Credential Access**: T1552.001 - Unsecured Credentials
  - Harvesting of SSH keys, cloud tokens, and environment secrets.
- **Exfiltration**: T1041 - Exfiltration Over C2 Channel
  - Callback to NEXUS Listener C2 server for data exfiltration.
- **Discovery**: T1082 - System Information Discovery
  - Enumeration of environment variables, cloud metadata, Kubernetes tokens, and Docker configurations.

## 3. Malware & Tools
- **Malware Framework**: NEXUS Listener
  - Web-based GUI for managing stolen credentials and victim data.
- **Exploitation Tool**: React2Shell
  - Pre-authentication RCE vulnerability exploitation tool targeting Next.js applications.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: UAT-10608
  - Likely an organized threat cluster leveraging automated scanning and exploitation.
- **Campaign Name**: UAT-10608 Credential Harvesting Operation
  - Targeting Next.js applications vulnerable to CVE-2025-55182.

## 5. Splunk Detection Searches
### Detecting Staged Payload Execution
```spl
index=main sourcetype=linux:syslog
| search "nohup sh /tmp/."
| stats count by host, process
| where count > 0
```
*Detects execution of staged shell scripts dropped in `/tmp`.*

### Detecting Callback URLs
```spl
index=main sourcetype=proxy
| search "http://*:<port>/h=*"
| stats count by src_ip, dest_ip, url
| where like(url, "%h=%")
```
*Identifies HTTP callback URLs matching NEXUS Listener patterns.*

### Detecting Exploitation of CVE-2025-55182
```spl
index=main sourcetype=web
| search "POST /api/server-function"
| stats count by src_ip, dest_ip, uri
| where like(uri, "%serialized_payload%")
```
*Detects exploitation attempts targeting vulnerable React Server Components.*

### Detecting Exfiltration Over Port 8080
```spl
index=main sourcetype=network
| search "dest_port=8080"
| stats count by src_ip, dest_ip
| where count > 10
```
*Flags unusual outbound traffic to port 8080.*

## 6. Executive Summary
Cisco Talos has disclosed a critical automated credential harvesting campaign, tracked as UAT-10608, targeting Next.js applications vulnerable to CVE-2025-55182 (React2Shell). The campaign leverages the NEXUS Listener framework to exfiltrate credentials, SSH keys, cloud tokens, and environment secrets from compromised systems. Over 766 hosts have been affected globally, with significant implications for cloud security, lateral movement, and supply chain risks. Organizations are advised to patch vulnerable systems, rotate credentials, and audit their environments for signs of compromise.