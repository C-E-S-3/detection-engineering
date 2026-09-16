# Iran MOIS HEAVYGRAM/CHOSEN BRICK Telegram Bot C2 Communication

## Description

Detects non-messaging, non-browser processes connecting to the Telegram Bot API (`api.telegram.org`) for command-and-control communication. The HEAVYGRAM malware (designated CHOSEN BRICK by the UK NCSC) is a Windows spyware family attributed to Iran's Ministry of Intelligence and Security (MOIS) that exclusively uses Telegram bots as its C2 channel. Each infected device communicates with a unique bot, preventing victim enumeration from any single compromised device.

Legitimate access to `api.telegram.org` is expected from the official Telegram Desktop client and mobile sync processes. This detection flags all other processes making outbound HTTPS connections to this host — a technique also used by other Telegram-based C2 malware families including IOCONTROL, PolyRAT, and various commodity RATs sold in cybercrime forums.

False positive sources: automated bots running on server infrastructure with the Telegram client libraries installed; developers testing Telegram bots locally from a workstation. Tune by whitelisting specific hosts or service accounts where Telegram bot automation is expected.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service |
| Technique ID | T1102 |
| Sub-technique | Bidirectional Communication |
| Sub-technique ID | T1102.002 |
| Secondary Tactic | Collection (TA0009) |
| Secondary Technique | Screen Capture (T1113), Audio Capture (T1123), Email Collection (T1114) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host="api.telegram.org"
    AND NOT All_Traffic.app IN ("Telegram","telegram.exe","Telegram Desktop","telegram-desktop")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
   All_Traffic.app All_Traffic.process All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(app,"(?i)(powershell|wscript|cscript|cmd\.exe|mshta|regsvr32|rundll32)"), 95,
    match(app,"(?i)(python[23]?|node|java[w]?|perl|ruby|php)"), 85,
    match(app,"(?i)(svchost|lsass|winlogon|services|dllhost)"), 95,
    NOT match(app,"(?i)(chrome|firefox|msedge|opera|brave|iexplore|safari|electron)"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src user app process dest_host dest_port risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Known script interpreter (PowerShell, WScript, CScript, CMD, MSHTA, etc.) connecting to Telegram API | 95 | No legitimate use case; consistent with HEAVYGRAM C2 or commodity Telegram RAT |
| Runtime interpreters (Python, Node, Java, Perl) connecting to Telegram API | 85 | Legitimate for development but high-value alert on production endpoints or servers |
| Core Windows OS processes (svchost, lsass, winlogon) connecting to Telegram API | 95 | Process injection into system processes; near-certain malicious |
| Non-browser, non-Telegram process making any connection to api.telegram.org | 80 | Suspicious; warrants investigation |
| Any match | 70 | Baseline — all alerts require analyst review |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Iran MOIS / UNC6085 (HEAVYGRAM/CHOSEN BRICK) | [NCSC Advisory (2026-09-15)](https://www.ncsc.gov.uk/news/uk-allies-expose-spyware-iranian-state-actors-target-dissidents-activists-journalists), [FBI FLASH-20260915-001](https://www.ic3.gov/CSA/2026/260915.pdf) |
| IRGC CyberAv3ngers (IOCONTROL RAT) | [MITRE ATT&CK G1028 — CyberAv3ngers](https://attack.mitre.org/groups/G1028/) |
| Various commodity Telegram RAT operators | [Any.run Telegram C2 Analysis](https://any.run/cybersecurity-blog/telegram-as-c2/) |

## References

- [NCSC — UK, US, Netherlands expose Iranian MOIS spyware campaign (2026-09-15)](https://www.ncsc.gov.uk/news/uk-allies-expose-spyware-iranian-state-actors-target-dissidents-activists-journalists)
- [FBI FLASH-20260915-001 — HEAVYGRAM IOCs and Technical Analysis](https://www.ic3.gov/CSA/2026/260915.pdf)
- [FBI FLASH-20260320-001 — Original MOIS Telegram C2 Alert (2026-03-20)](https://www.ic3.gov/CSA/2026/260320.pdf)
- [MITRE ATT&CK — T1102.002 Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [Splunk Security Content — Detect processes accessing Telegram API](https://research.splunk.com/)
