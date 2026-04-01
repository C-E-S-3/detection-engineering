---
scraped_at: "2026-04-01T10:05:15-04:00"
source_url: "https://www.bleepingcomputer.com/news/security/routine-access-is-powering-modern-intrusions-a-new-threat-report-finds/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified

### File Hashes
- None identified

### IP Addresses
- None identified

### Other IOCs
- "Roadk1ll" implant: A new malware designed to pivot across systems using WebSocket-based communication and maintain access while blending into network traffic.

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1078 - Valid Accounts**: Threat actors are increasingly using valid but compromised credentials to gain access to systems, often through SSL VPN abuse (32.8% of incidents).
- **T1566.002 - Spearphishing Link**: Social engineering campaigns, such as fake CAPTCHA and ClickFix-style attacks, trick users into executing commands via the Windows Run dialog box.

### Persistence
- **T1219 - Remote Access Software**: Abuse of legitimate Remote Monitoring and Management (RMM) tools, such as ScreenConnect, for persistence. Unauthorized installations often mimic legitimate activity.

### Defense Evasion
- **T1070.004 - File Deletion**: Attackers use built-in Windows tools to execute commands without traditional malware downloads, making detection more difficult.
- **T1556.004 - Adversary-in-the-Middle**: Attackers capture authenticated session tokens after successful multi-factor authentication (MFA) and reuse them to access cloud services.

### Lateral Movement
- **T1570 - Lateral Tool Transfer**: The "Roadk1ll" implant uses WebSocket-based communication to pivot across systems while blending into normal network traffic.

## 3. Malware & Tools
- **Roadk1ll**: A new implant leveraging WebSocket-based communication for lateral movement and persistence.
- Abuse of legitimate tools: ScreenConnect and other RMM tools frequently used for unauthorized access and persistence.

## 4. Threat Actor / Campaign Attribution
- No specific threat actor or campaign attribution was provided in the source material.

## 5. Splunk Detection Searches

### Detecting SSL VPN Abuse (T1078 - Valid Accounts)
```spl
index=network sourcetype=pan:traffic
| search app="ssl-vpn"
| stats count by src_ip, dest_ip, user, app
| where count > 100
```
*Comment: This search identifies unusual SSL VPN activity, such as excessive login attempts or connections from unexpected IPs.*

### Detecting RMM Tool Abuse (T1219 - Remote Access Software)
```spl
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=1 Image="*\\ScreenConnect*"
| stats count by ComputerName, User, Image
| where count > 10
```
*Comment: This search identifies unauthorized installations or executions of ScreenConnect.*

### Detecting Adversary-in-the-Middle (T1556.004 - Adversary-in-the-Middle)
```spl
index=network sourcetype=proxy
| search "session token reuse"
| stats count by src_ip, dest_ip, user_agent
```
*Comment: This search identifies potential session token reuse in cloud environments.*

### Detecting Roadk1ll Implant Activity (T1570 - Lateral Tool Transfer)
```spl
index=network sourcetype=stream:tcp
| search "WebSocket"
| stats count by src_ip, dest_ip, uri_path
| where count > 50
```
*Comment: This search identifies suspicious WebSocket-based communication that could indicate Roadk1ll activity.*

## 6. Executive Summary

The 2026 Annual Threat Report by Blackpoint Cyber highlights a significant shift in attacker tactics, focusing on legitimate access methods rather than traditional exploits. Key findings include the abuse of SSL VPNs (32.8% of incidents), misuse of Remote Monitoring and Management (RMM) tools like ScreenConnect (30.3% of incidents), and social engineering campaigns (57.5% of incidents). A new implant, "Roadk1ll," was identified, leveraging WebSocket-based communication for lateral movement and persistence. Security teams should prioritize monitoring for legitimate access abuse, maintaining inventories of approved tools, and applying conditional access controls. Immediate actions include implementing detection mechanisms for SSL VPN abuse, RMM tool misuse, and session token reuse in cloud environments.
