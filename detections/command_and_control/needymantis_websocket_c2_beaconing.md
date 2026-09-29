# NeedyMantis WebSocket C2 Beaconing

## Description

Detects NeedyMantis post-compromise malware communicating with attacker-controlled C2 infrastructure via WebSocket connections over TLS port 443. NeedyMantis — deployed by Storm-3069 (China-based) in targeted intrusions against telecoms, universities, medical nonprofits, and government contractors — uses a communications DLL (WinINet or Libwebsockets) to establish WebSocket C2 with XOR + RC4 encrypted, compressed traffic. The known C2 domain `corp.tripswithengine[.]com` uses URI `/library/zip/` for tasking.

False positives: legitimate applications using WebSocket connections (e.g., Slack, Teams, VS Code extensions) may trigger the behavioral rule. The domain IOC rule has no expected false positives.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols (WebSocket) |
| Technique ID | T1071.001 |

Secondary: Defense Evasion — T1574.002 (DLL Side-Loading), T1027 (Obfuscated Files or Information)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query="corp.tripswithengine.com"
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100, detection="NeedyMantis C2 Domain IOC"
| table firstTime lastTime src query answer detection risk_score
```

Behavioral variant (non-browser WebSocket egress — broader, lower confidence):

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("rundll32.exe", "powershell.exe", "wscript.exe", "cscript.exe")
    AND NOT Processes.parent_process_name IN ("explorer.exe", "svchost.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)rundll32") AND NOT match(process, "(?i)System32"), 80,
    match(process_name, "(?i)powershell") AND match(parent_process_name, "(?i)poedit|notepad\+\+|winrar|7z|vlc"), 85,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS query matches `corp.tripswithengine.com` | 100 | Known NeedyMantis C2 domain; no legitimate use |
| rundll32.exe from non-System32 path | 80 | DLL sideloading pattern consistent with NeedyMantis first-stage loader |
| PowerShell spawned by known-good application (Poedit, Notepad++, etc.) | 85 | Second-stage shellcode loader pattern; legitimate apps rarely spawn PowerShell |
| Generic suspicious process | 50 | Needs analyst review; high false-positive rate without additional context |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Storm-3069 (China-based; DAEMON Tools supply chain) | [Microsoft — NeedyMantis (2026-09-28)](https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/) |

## References

- [Microsoft Security Blog — NeedyMantis (2026-09-28)](https://www.microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations/)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1574.002 — DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
