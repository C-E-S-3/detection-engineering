---
scraped_at: "2026-04-02T08:32:35Z"
source_url: "https://www.bleepingcomputer.com/news/security/over-14-000-f5-big-ip-apm-instances-still-exposed-to-rce-attacks/"
report_type: threat-intel
severity: "critical"
title: "CVE-2025-53521 actively exploited for RCE on F5 BIG-IP APM systems"
---

## 1. Indicators of Compromise (IOCs)
### IP Addresses
- **17,100 IPs** with BIG-IP APM fingerprints tracked by Shadowserver (specific IPs not disclosed in the source).

### Domains
No new domains disclosed.

### File Hashes
No new file hashes disclosed.

### Other IOCs
- **Affected Systems**: F5 BIG-IP APM instances vulnerable to CVE-2025-53521.

## 2. TTPs (MITRE ATT&CK Mapping)
- **Tactic**: Initial Access
  - **Technique**: Exploit Public-Facing Application (T1190)
    - **Description**: Attackers exploit CVE-2025-53521 to gain remote code execution on unpatched BIG-IP APM systems.

- **Tactic**: Execution
  - **Technique**: Command and Scripting Interpreter (T1059)
    - **Description**: Exploited systems may allow attackers to execute arbitrary commands remotely.

## 3. Malware & Tools
No specific malware or tools disclosed in the source.

## 4. Threat Actor / Campaign Attribution
- **Threat Actors**: Nation-state and cybercrime groups have historically targeted BIG-IP vulnerabilities.
- **Motivations**: Breaching corporate networks, hijacking devices, deploying malware, mapping internal servers, and stealing sensitive data.

## 5. Splunk Detection Searches
### Detecting Exploitation Attempts
```spl
index=firewall OR index=proxy OR index=dns
| search dest_ip IN (list_of_big_ip_apm_ips) AND (uri_path="/" OR uri_path="/vulnerable_path")
| stats count by src_ip, dest_ip, uri_path
| where count > 10
```
*Detects repeated access attempts to vulnerable BIG-IP APM systems.*

### Monitoring for RCE Exploitation
```spl
index=sysmon OR index=crowdstrike:events:sensor OR index=windows
| search process="cmd.exe" OR process="powershell.exe" AND parent_process="bigip_apm_process_name"
| stats count by host, process, parent_process
| where count > 5
```
*Flags suspicious command execution originating from BIG-IP APM processes.*

### Identifying Malicious Configuration Changes
```spl
index=bigip_logs
| search "configuration change" AND "policy update"
| stats count by user, change_type, timestamp
| where count > 3
```
*Detects unauthorized configuration changes on BIG-IP systems.*

## 6. Executive Summary
A critical vulnerability (CVE-2025-53521) in F5 BIG-IP APM systems has been reclassified as a remote code execution (RCE) flaw and is actively exploited by attackers. Over 14,000 systems remain exposed despite advisories from F5 and CISA. Organizations using BIG-IP APM should immediately patch affected systems and monitor for signs of compromise. Rebuilding compromised systems from known good backups is strongly recommended to eliminate persistent malware risks.