# CrystalRAT WebSocket C2 Communication

## Description

Detects WebSocket-based command and control (C2) communication patterns used by CrystalRAT (also known as CrystalX RAT), a Malware-as-a-Service (MaaS) RAT sold on Telegram and YouTube. CrystalRAT uses WebSocket connections to a C2 server for real-time keystroke streaming, clipboard monitoring (cryptocurrency wallet address hijacking), screen/audio capture, and remote command execution via CMD. Payloads are zlib-compressed and encrypted with ChaCha20. The malware targets Chromium-based browsers, Yandex, Opera, Steam, Discord, and Telegram. Common false positives: legitimate WebSocket applications (Slack, Teams, gaming platforms, financial trading apps); apply whitelist of known-good WebSocket destinations.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |

Secondary techniques: T1573 (Encrypted Channel — ChaCha20), T1056.001 (Keylogging), T1115 (Clipboard Data), T1113 (Screen Capture)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.app="websocket"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port
     All_Traffic.src_port All_Traffic.app All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| stats count sum(bytes_out) as total_bytes_out dc(dest_ip) as unique_dests
    min(firstTime) as firstTime max(lastTime) as lastTime
  by src_ip app
| where unique_dests < 3 AND total_bytes_out > 50000
| eval risk_score=case(
    total_bytes_out > 500000 AND unique_dests == 1, 80,
    total_bytes_out > 100000, 65,
    1=1, 50)
| where risk_score >= 50
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip unique_dests total_bytes_out risk_score
```

**Supplemental: Clipboard access with cryptocurrency wallet pattern**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process="*OpenClipboard*" OR Processes.process="*GetClipboardData*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    NOT match(process_name, "(?i)chrome|firefox|msedge|outlook|teams|slack|explorer"), 75,
    1=1, 45)
| where risk_score >= 55
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Supplemental: Anti-analysis evasion checks (VM/debugger detection)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process="*vmware*" OR Processes.process="*virtualbox*"
         OR Processes.process="*sandbox*" OR Processes.process="*IsDebuggerPresent*")
    AND NOT Processes.process_name IN ("vmtoolsd.exe","vmwaretray.exe","VBoxService.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=60
| where risk_score >= 50
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| High-volume WebSocket egress (>500KB) to single destination | 80 | Keylogging stream or file exfil; normal apps use multiple CDN endpoints |
| WebSocket with >100KB outbound to 1-2 destinations | 65 | Suspicious data volume; validate against known-good destinations |
| Clipboard API access from non-browser process | 75 | Wallet address replacement; legitimate use limited to browser/office apps |
| VM/debugger detection strings from non-VM processes | 60 | Anti-analysis capability indicating malware context |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| CrystalRAT / CrystalX RAT | Primary malware; MaaS RAT using WebSocket C2, keylogging, clipboard hijacking, ChaCha20-encrypted payloads. Promoted on Telegram and YouTube targeting low-skilled threat actors. |

## References

- [BleepingComputer - CrystalRAT New MaaS RAT](https://www.bleepingcomputer.com/news/security/new-crystalrat-malware-adds-rat-stealer-and-prankware-features/)
- [MITRE ATT&CK - T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK - T1115 Clipboard Data](https://attack.mitre.org/techniques/T1115/)
- [MITRE ATT&CK - T1056.001 Keylogging](https://attack.mitre.org/techniques/T1056/001/)
