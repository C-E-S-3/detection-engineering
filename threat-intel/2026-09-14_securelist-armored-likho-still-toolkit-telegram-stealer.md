---
scraped_at: "2026-09-14T00:00:00Z"
source_url: "https://securelist.com/armored-likho-still-toolkit/121033/"
report_type: threat-intel
severity: high
title: "Armored Likho (Eagle Werewolf) Still Toolkit — Telegram Desktop Session Stealer and Eavesdropping Implant; Kaspersky Securelist September 2026"
---

## 1. IOCs

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `grked[.]online` | C2 domain | Still Toolkit C2 domain; Armored Likho campaign; Kaspersky September 2026 |

### IP Addresses

| Indicator | Type | Context |
|-----------|------|---------|
| `159[.]198[.]41[.]140` | C2 IP | Still Toolkit primary C2 server; Armored Likho (Eagle Werewolf) campaign |
| `159[.]198[.]32[.]222` | Tunnel IP | Still Toolkit tunnel relay node; Armored Likho campaign |

### Behavioral indicators (host)

- Executable mimicking a donation service application (initial delivery lure)
- Unexpected process accessing Telegram Desktop session files (`%APPDATA%\Telegram Desktop\tdata\`)
- Process reading `key_datas` or `D877F783D5D3EF8C` (Telegram Desktop session key files) from `tdata\` directory
- Audio recording or screen capture from non-browser, non-standard productivity application
- Outbound connections to `grked[.]online` or `159.198.41.140` / `159.198.32.222`
- Kaspersky detection name: `Trojan.Win64.Agent`

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|-------------|-------------|----------------|-------|
| Initial Access | T1204.002 | User Execution: Malicious File | Victim runs an application impersonating a donation service; lure is themed around charitable giving |
| Execution | T1059 | Command and Scripting Interpreter | Implant executes via trojanized application launcher |
| Credential Access | T1539 | Steal Web Session Cookie | Still Toolkit targets Telegram Desktop session data (`tdata/`) to steal active sessions without needing credentials |
| Credential Access | T1555 | Credentials from Password Stores | Session file theft enables account takeover of Telegram account without knowing the password or triggering 2FA |
| Collection | T1113 | Screen Capture | Eavesdropping module captures screen content |
| Collection | T1123 | Audio Capture | Still Toolkit eavesdropping capability records audio from victim microphone |
| Collection | T1005 | Data from Local System | Telegram `tdata/` directory exfiltrated to attacker infrastructure |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | C2 communication to `grked[.]online` over HTTP/HTTPS |
| Command and Control | T1090 | Proxy | Tunnel relay via `159.198.32.222` used to relay C2 traffic |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Stolen Telegram session data and captured media exfiltrated over C2 channel |

### Attack Chain

1. **Delivery**: Victim receives or downloads an application impersonating a donation service (specific delivery vector — email, messaging, SEO, or direct targeting — not disclosed in open-source coverage).
2. **Execution**: Victim runs the malicious application; Still Toolkit implant is loaded.
3. **Session theft**: Implant reads Telegram Desktop `tdata/` directory, exfiltrating session key files that enable the attacker to replay the victim's Telegram session without their password or OTP.
4. **Eavesdropping**: Eavesdropping module activates audio capture and screen recording.
5. **Exfiltration**: Stolen session data and captured media exfiltrated to `159.198.41.140` via C2 domain `grked[.]online`; traffic tunneled through `159.198.32.222`.

## 3. Malware & Tools

| Tool | Description |
|------|-------------|
| Still Toolkit | New Armored Likho implant; steals Telegram Desktop session data from `tdata/` directory; includes eavesdropping capability (audio recording, screen capture); Kaspersky detects as `Trojan.Win64.Agent` |
| Donation-app lure | Trojanized Windows executable posing as a donation service; serves as the initial delivery vehicle for Still Toolkit |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| **Threat Actor** | Armored Likho (also: Eagle Werewolf, related to Awaken Likho) |
| **Classification** | APT / Cyber-espionage |
| **Motivation** | Intelligence collection; Telegram-based espionage targeting Russian domestic organizations |
| **Targeting** | Private individuals and organizations in Russia — confirmed verticals: corporations, public sector, IT, education |
| **Previous tools** | BusySnake Stealer (July 2026 Kaspersky report targeting government agencies and power sector); legacy implants from Awaken Likho cluster |
| **Tooling evolution** | Still Toolkit is a new capability distinct from the previously-reported BusySnake Stealer; both tools demonstrate continued investment in credential-theft and espionage tooling targeting Russian entities |
| **Publication date** | Kaspersky Securelist, approximately September 7, 2026 |

## 5. Splunk Detection Searches

No existing detection in this repository directly covers Telegram Desktop session data theft. The searches below detect the two highest-fidelity behavioral signals.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*\\Telegram Desktop\\tdata\\*"
    AND Filesystem.action IN ("read","accessed")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_id
     Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where NOT match(process_name,"(?i)telegram\\.exe|updater\\.exe")
| eval risk_score=case(
    match(process_name,"(?i)wscript|cscript|powershell|pwsh|cmd\\.exe|mshta"), 95,
    1=1, 85)
| where risk_score >= 85
| table firstTime lastTime dest user process_name file_path file_name risk_score
```
**Detects:** Non-Telegram processes reading Telegram Desktop `tdata/` session files — the primary behavior of Still Toolkit and any session-hijacking implant targeting Telegram Desktop. High fidelity: only `Telegram.exe` and its updater have legitimate reasons to read these files.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN ("159.198.41.140","159.198.32.222")
     OR All_Traffic.dest_host="grked.online"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
     All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_host dest_port process_name risk_score
```
**Detects:** Connections to known Armored Likho Still Toolkit C2 infrastructure (`159.198.41.140`, `159.198.32.222`, `grked.online`).

## 6. Executive Summary

Kaspersky published analysis in early September 2026 of a new campaign by Armored Likho (also known as Eagle Werewolf), a threat actor previously documented targeting Russian government agencies, power sector, and corporate organizations. The new campaign delivers the Still Toolkit, a purpose-built implant focused on stealing Telegram Desktop session data and eavesdropping on victims.

The infection chain begins with a Windows application impersonating a donation service — a social engineering lure consistent with Armored Likho's pattern of using topical or charitable themes to target Russian organizations and individuals. Once executed, Still Toolkit reads the Telegram Desktop `tdata/` directory, exfiltrating session key files that allow the attacker to take over the victim's Telegram account without knowing their password or triggering two-factor authentication. The toolkit also includes audio capture and screen recording capabilities for active eavesdropping. C2 communication runs to `grked[.]online` / `159.198.41.140` via a tunnel relay at `159.198.32.222`.

Armored Likho previously deployed the BusySnake Stealer (Kaspersky, July 2026) against government agencies and power sector targets. The Still Toolkit represents a new tool in the group's arsenal, with an expanded targeting scope to include corporations, public sector, IT, and educational institutions. The group's persistent focus on Telegram-based intelligence collection reflects the platform's widespread use within Russian organizations for sensitive business and government communications.

**Recommended actions:**
1. Block or alert on network connections to `grked[.]online`, `159.198.41.140`, and `159.198.32.222` at perimeter and endpoint.
2. Deploy the Telegram `tdata/` access detection above to catch session-theft implants across any threat actor targeting Telegram Desktop.
3. Educate users on donation-themed social engineering lures; verify executable authenticity before running.
4. Where Telegram Desktop is used for business communications, consider session-audit tooling or organizational Telegram migration to managed channels.

## References

- [Kaspersky Securelist — New Armored Likho tools target Telegram and eavesdropping](https://securelist.com/armored-likho-still-toolkit/121033/)
- [Kaspersky Securelist — Armored Likho's new weapon: BusySnake Stealer (July 2026)](https://securelist.com/armored-likho-apt-with-busysnake-stealer/120292/)
- [The Hacker News — Armored Likho Targets Government Agencies, Power Sector with BusySnake Stealer](https://thehackernews.com/2026/07/armored-likho-targets-government.html)
- [MITRE ATT&CK — T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK — T1123 Audio Capture](https://attack.mitre.org/techniques/T1123/)
- [MITRE ATT&CK — T1113 Screen Capture](https://attack.mitre.org/techniques/T1113/)
