# Red Lamassu Showboat/JFMBackdoor C2 Traffic Detection

## Description

Detects network communications to known command-and-control infrastructure operated by Red Lamassu (Calypso APT), a China-nexus threat actor targeting telecommunications providers in Central Asia and the Middle East. The actor deploys two custom malware families: **Showboat** (Linux ELF SOCKS5 backdoor masquerading as `kworker`) and **JFMBackdoor** (Windows implant delivered via DLL side-loading with hardcoded `C:\Users\public\jfm` artifact). C2 domains `namefuture[.]site` and `newsprojects[.]online` are backed by servers in the `23.27.201.0/24`, `166.88.11.0/24`, and `139.180.223.0/24` ranges.

False positives are expected to be near-zero — these are attacker-registered domains with no legitimate business purpose.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |
| Secondary Technique | Proxy: Internal Proxy (SOCKS5) |
| Secondary Technique ID | T1090.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_ip IN ("23.27.201.160","166.88.11.196","139.180.223.193")
    OR All_Traffic.dest_domain IN ("namefuture.site","newsprojects.online"))
by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.dest_domain All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    All_Traffic.dest_domain IN ("namefuture.site","newsprojects.online"), 95,
    All_Traffic.dest_ip IN ("23.27.201.160","166.88.11.196","139.180.223.193"), 90,
    1=1, 85)
| where risk_score >= 85
| table firstTime lastTime src_ip dest_ip dest_port dest_domain app risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Connection to `namefuture.site` or `newsprojects.online` | 95 | Confirmed Red Lamassu C2 domains — JFMBackdoor and Showboat/kworker C2 respectively |
| Connection to listed C2 IP addresses | 90 | Confirmed Red Lamassu C2 infrastructure backing the above domains |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Red Lamassu (Calypso APT) | [PwC TI — Open Directory, Open Season](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/red-lamassu-open-season.html), [Lumen — Introducing Showboat](https://www.lumen.com/blog/en-us/introducing-showboat-a-new-malware-family-taunts-defenses-and-targets-international-telecom-firms) |

## References

- [PwC Threat Intelligence — Red Lamassu JFMBackdoor (May 2026)](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/red-lamassu-open-season.html)
- [Lumen Black Lotus Labs — Introducing Showboat (May 2026)](https://www.lumen.com/blog/en-us/introducing-showboat-a-new-malware-family-taunts-defenses-and-targets-international-telecom-firms)
- [PwC GitHub IOC Repository](https://github.com/PwCUK-CTO/TI-blog-2026-Red-Lamassu-JFMBackdoor)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1090.001 — Proxy: Internal Proxy](https://attack.mitre.org/techniques/T1090/001/)
