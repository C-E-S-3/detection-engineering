---
scraped_at: "2026-03-30T14:28:37-04:00"
source_url: "https://www.bleepingcomputer.com/news/security/critical-citrix-netscaler-memory-flaw-actively-exploited-in-attacks/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None explicitly mentioned in the source.

### Domains/URLs
- None explicitly mentioned in the source.

### File Hashes
- None explicitly mentioned in the source.

### Other IOCs
- Endpoint paths:
  - `/saml/login` (SAML authentication endpoint targeted by CVE-2026-3055)
  - `/wsfed/passive` (WS-Federation passive authentication endpoint targeted by CVE-2026-3055)

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Credential Access
- **Technique ID**: T1557.002 (Man-in-the-Middle: Application Layer Protocol)
  - **Description**: Threat actors are exploiting CVE-2026-3055 to extract sensitive information, including administrative session IDs, by targeting the `/saml/login` and `/wsfed/passive` endpoints.

### Tactic: Initial Access
- **Technique ID**: T1190 (Exploit Public-Facing Application)
  - **Description**: Threat actors are exploiting CVE-2026-3055, a critical memory overread vulnerability in Citrix NetScaler ADC and Gateway appliances, to gain unauthorized access to sensitive data.

### Tactic: Discovery
- **Technique ID**: T1595 (Active Scanning)
  - **Description**: Reconnaissance activity targeting vulnerable Citrix NetScaler instances was observed by watchTowr, indicating active scanning for exploitable systems.

## 3. Malware & Tools
- **Custom Tools**: Threat actors have been observed using a Python script to identify vulnerable hosts in their environments.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: Unnamed threat actors have been observed exploiting CVE-2026-3055. Some of the source IPs used in the attacks were identified by watchTowr's honeypot network.
- **Campaign**: No specific campaign name was mentioned, but the activity is linked to the exploitation of CVE-2026-3055.
- **Motivations**: Likely data theft and potential full compromise of Citrix NetScaler appliances.

## 5. Splunk Detection Searches

### Detecting Exploitation Attempts via Targeted Endpoints
```spl
index=proxy_logs sourcetype=bluecoat:proxysg OR sourcetype=squid
| search uri_path IN ("/saml/login", "/wsfed/passive")
| stats count by src_ip, uri_path, http_user_agent
| where count > 10
| table src_ip, uri_path, http_user_agent, count
```
*Comment: This search identifies repeated access to the vulnerable endpoints `/saml/login` and `/wsfed/passive`, which may indicate exploitation attempts.*

### Detecting Reconnaissance Activity
```spl
index=network_traffic sourcetype=bro_conn OR sourcetype=zeek_conn
| search dest_port=443
| stats count by src_ip, dest_ip, dest_port
| where count > 100
| table src_ip, dest_ip, dest_port, count
```
*Comment: This search identifies high-frequency scanning activity targeting port 443, which may indicate reconnaissance for vulnerable Citrix NetScaler instances.*

### Detecting Administrative Session ID Exfiltration
```spl
index=web_logs sourcetype=apache:access OR sourcetype=iis
| search uri_path IN ("/saml/login", "/wsfed/passive")
| rex field=_raw "SessionID=(?<session_id>[a-zA-Z0-9]+)"
| stats count by src_ip, session_id
| where count > 5
| table src_ip, session_id, count
```
*Comment: This search identifies potential exfiltration of administrative session IDs from the targeted endpoints.*

## 6. Executive Summary

A critical memory overread vulnerability (CVE-2026-3055) in Citrix NetScaler ADC and Gateway appliances is being actively exploited by threat actors. The vulnerability affects appliances configured as SAML identity providers and allows attackers to extract sensitive information, including administrative session IDs, potentially leading to full system compromise. Reconnaissance activity and exploitation have been observed in the wild since March 27, 2026. Organizations using affected Citrix appliances should immediately apply the vendor's patches and monitor for suspicious activity targeting the `/saml/login` and `/wsfed/passive` endpoints.