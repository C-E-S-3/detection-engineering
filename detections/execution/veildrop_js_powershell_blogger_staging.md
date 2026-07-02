# VEIL#DROP JavaScript Dropper with Blogger C2 Channel

## Description

Detects the VEIL#DROP attack chain: JavaScript execution via wscript.exe spawning PowerShell stagers that use Google Blogger (blogspot.com) posts as a covert command-and-control channel. VEIL#DROP retrieves encrypted second-stage configuration or payload URLs from attacker-controlled Blogger posts, exploiting the legitimate domain reputation of blogspot.com to bypass web category filtering and domain-based blocklists. The final payload is PureLogs infostealer.

Two complementary signals are detected:

1. **JS-to-PowerShell spawn**: wscript.exe or cscript.exe executing a `.js` file that spawns PowerShell or cmd — the initial dropper stage.
2. **Blogger C2 DNS**: DNS resolution of `*.blogspot.com` from scripting engine or PowerShell processes, specifically `htlwub00klocate[.]blogspot[.]com` as a known VEIL#DROP C2 host.

**False positives:** Legitimate scripting tasks that happen to contact blogspot.com (rare in enterprise environments). The JS→PowerShell spawn pattern has higher fidelity; tune out known-good wscript parent processes if needed.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution (TA0002) |
| Technique | Command and Scripting Interpreter: JavaScript (T1059.007) |
| Technique | Command and Scripting Interpreter: PowerShell (T1059.001) |
| Technique | Web Service: Bidirectional Communication (T1102.002) |

## Lockheed Martin Kill Chain

| Field | Value |
|-------|-------|
| Phase | Exploitation |

## Splunk Detection Query

### Rule 1 — JavaScript Dropper Spawning PowerShell (High Confidence)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("wscript.exe","cscript.exe")
    AND Processes.parent_process="*.js*"
    AND Processes.process_name IN ("powershell.exe","cmd.exe","mshta.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table dest user parent_process_name parent_process process_name process risk_score firstTime lastTime
```

### Rule 2 — Known VEIL#DROP Blogger C2 Domain (Critical — IOC Match)

```spl
`dns` query IN ("htlwub00klocate.blogspot.com")
| stats count min(_time) as firstTime max(_time) as lastTime by src query
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table src query risk_score firstTime lastTime
```

### Rule 3 — Scripting Engine Connecting to Blogspot (Medium Confidence, Anomaly)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="*.blogspot.com"
    AND All_Traffic.app IN ("powershell","wscript","cscript","python","pythonw","mshta")
  by All_Traffic.src All_Traffic.dest_host All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest_host="htlwub00klocate.blogspot.com", 95,
    app IN ("wscript","cscript","mshta"), 80,
    true(), 65)
| where risk_score >= 65
| table src user app dest_host risk_score firstTime lastTime
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | DNS/connection to known VEIL#DROP C2 (`htlwub00klocate.blogspot.com`) |
| 85 | wscript.exe/cscript.exe with `.js` parent process spawning PowerShell or cmd |
| 80 | wscript.exe or mshta.exe connecting to any `*.blogspot.com` host |
| 65 | PowerShell connecting to `*.blogspot.com` |

## Associated Threat Actors

| Actor | Reference |
|-------|-----------|
| VEIL#DROP operators (unknown, financially motivated) | [The Hacker News — VEIL#DROP (2026-07-01)](https://thehackernews.com/2026/07/veildrop-javascript-dropper-uses-blogger-purelogs.html) |
| PureLogs MaaS operators | Various criminal forums |

## References

- [The Hacker News — VEIL#DROP (2026-07-01)](https://thehackernews.com/2026/07/veildrop-javascript-dropper-uses-blogger-purelogs.html)
- [MITRE ATT&CK — T1102.002: Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK — T1059.007: Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK — T1059.001: Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
