---
scraped_at: 2026-03-30T00:00:00Z
source_url: https://blog.cloudflare.com/client-side-security-open-to-everyone/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- **hxxps://ns[.]qpft5[.]com/ads/core[.]js**: Malicious script URL targeting Xiaomi OpenWrt-based routers.
- **hxxps://api[.]qpft5[.]com**: C2 domain used in the core.js router exploit.

### Hashes
- **4f2b7d46148b786fae75ab511dc27b6a530f63669d4fe9908e5f22801dea9202** (SHA256): Malicious core.js script targeting Xiaomi OpenWrt-based routers.

### IPs
- None identified.

## 2. TTPs (MITRE ATT&CK Mapping)

- **T1185 - Browser Session Hijacking**: The core.js script was injected into user sessions via compromised browser extensions.
- **T1556.003 - Network Device Authentication**: The script attempted to change the admin password of compromised routers to lock out legitimate users.
- **T1565.003 - Data Manipulation: Stored Data Manipulation**: The script overwrote DNS settings on Xiaomi OpenWrt-based routers to hijack traffic through malicious DNS servers.
- **T1027 - Obfuscated Files or Information**: The core.js script was heavily obfuscated using an array string obfuscator to evade detection.
- **T1203 - Exploitation for Client Execution**: The core.js script exploited vulnerabilities in browser extensions to execute malicious code.

## 3. Malware & Tools

- **Malware**: 
  - **core.js**: A malicious, heavily obfuscated JavaScript targeting Xiaomi OpenWrt-based routers. It modifies DNS settings, queries WAN configurations, and changes admin passwords.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not explicitly attributed in the source.
- **Campaign**: No specific campaign name provided, but the attack targeted Xiaomi OpenWrt-based routers via compromised browser extensions.
- **Motivations**: Likely financial or espionage-related, given the DNS hijacking and credential theft capabilities.
- **Targeted Sectors/Geographies**: Users in specific regions, particularly those using Xiaomi OpenWrt-based routers.

## 5. Splunk Detection Searches

### Detecting Malicious Domain Access

```spl
index=proxy OR index=firewall
| search dest_domain IN ("ns.qpft5.com", "api.qpft5.com")
| stats count by src_ip, dest_ip, dest_domain, uri_path
| table src_ip, dest_ip, dest_domain, uri_path, count
```
*Comment: This search identifies any access to the malicious domains associated with the core.js router exploit.*

### Detecting Malicious Script Hash

```spl
index=endpoint
| search file_hash="4f2b7d46148b786fae75ab511dc27b6a530f63669d4fe9908e5f22801dea9202"
| stats count by host, file_name, file_path
| table host, file_name, file_path, count
```
*Comment: This search detects the presence of the malicious core.js script on endpoints by its SHA256 hash.*

### Detecting DNS Hijacking Attempts

```spl
index=dns
| search query IN ("8.8.8.8", "8.8.4.4")
| stats count by src_ip, query, query_type
| table src_ip, query, query_type, count
```
*Comment: This search identifies DNS queries to public DNS servers that may indicate hijacking attempts.*

### Detecting Router API Exploitation Attempts

```spl
index=proxy OR index=firewall
| search uri_path="/cgi-bin/luci/api/xqsystem/login"
| stats count by src_ip, dest_ip, uri_path
| table src_ip, dest_ip, uri_path, count
```
*Comment: This search identifies attempts to exploit the Xiaomi OpenWrt router API.*

## 6. Executive Summary

Cloudflare's recent blog highlights a sophisticated client-side attack involving a malicious JavaScript file (core.js) targeting Xiaomi OpenWrt-based routers. The script modifies DNS settings, queries WAN configurations, and changes admin passwords to lock out legitimate users. The attack was delivered via compromised browser extensions and evaded traditional detection methods due to heavy obfuscation. Cloudflare's advanced detection pipeline, leveraging a Graph Neural Network (GNN) and a Large Language Model (LLM), successfully identified this zero-day threat. Immediate actions include monitoring for related IOCs, detecting DNS hijacking attempts, and securing browser extensions to prevent further exploitation.