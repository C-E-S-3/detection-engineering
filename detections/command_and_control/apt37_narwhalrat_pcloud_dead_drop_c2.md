# APT37 NarwhalRAT pCloud Dead-Drop C2 Resolver

## Description

Detects NarwhalRAT command-and-control activity by APT37 (ScarCruft). NarwhalRAT is a compiled Python RAT that uses the legitimate pCloud API (`api.pcloud.com`) as a dead-drop resolver: after initial execution the malware fetches an attacker-controlled pCloud file to discover the live C2 server address. This avoids embedding a hardcoded C2 IP and makes network-based blocking ineffective without blocking the pCloud API entirely.

Legitimate pCloud usage occurs primarily from browsers and dedicated pCloud desktop applications. Connections from PowerShell, CMD, Python, script interpreters, or Office application child processes indicate potential NarwhalRAT dead-drop activity. False positives include developer scripts or automation using the pCloud API, which should be baselined and excluded.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service: Dead Drop Resolver |
| Technique ID | T1102.001 |

Secondary: T1566.001 (Phishing delivery), T1059.001 (PowerShell), T1059.006 (Python), T1053.005 (Scheduled Task persistence)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host="api.pcloud.com"
  AND All_Traffic.app IN (
    "powershell","powershell.exe","cmd","cmd.exe",
    "wscript","wscript.exe","cscript","cscript.exe",
    "mshta","mshta.exe","regsvr32","regsvr32.exe",
    "python","python.exe","python3","python3.exe",
    "WINWORD","WINWORD.EXE","EXCEL","EXCEL.EXE",
    "POWERPNT","POWERPNT.EXE","OUTLOOK","OUTLOOK.EXE",
    "schtasks","schtasks.exe","rundll32","rundll32.exe"
  )
by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    app IN ("powershell.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe"), 85,
    app IN ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE"), 85,
    app IN ("python.exe","python3.exe","python","python3"), 75,
    app IN ("schtasks.exe","cmd.exe"), 70,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest dest_host dest_port app risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Script interpreters (wscript, cscript, mshta, regsvr32, rundll32) connecting to pCloud | 85 | High-confidence malicious: script engines have no legitimate reason to use pCloud API |
| Office applications (Word, Excel, PowerPoint, Outlook) connecting to pCloud | 85 | High-confidence: Office macros or child processes should not use pCloud API directly |
| Python/python3 process connecting to pCloud | 75 | High-suspicion: NarwhalRAT is Python-based; legitimate Python pCloud clients should be baselined |
| Schtasks or CMD connecting to pCloud | 70 | Suspicious: could indicate scheduled task-based persistence polling dead-drop |
| Any other non-browser process connecting to pCloud | 60 | Medium-suspicion: requires analyst review to exclude legitimate tools |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| APT37 / ScarCruft (G0067) | [MITRE ATT&CK G0067](https://attack.mitre.org/groups/G0067/) |
| APT37 NarwhalRAT campaign (June 2026) | [Genians Threat Intelligence — NarwhalRAT](https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat) |

## References

- [Genians — Analysis of APT37 NarwhalRAT Leveraging MS-Themed Phishing and Dead-drop C2 (2026)](https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat)
- [MITRE ATT&CK T1102.001 — Web Service: Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK G0067 — APT37](https://attack.mitre.org/groups/G0067/)
