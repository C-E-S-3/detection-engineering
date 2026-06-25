# DragonForce Backdoor.Turn: Microsoft Teams TURN Relay C2 Abuse

## Description

Detects the novel C2 technique used by DragonForce's Backdoor.Turn malware, which routes command-and-control traffic through legitimate Microsoft Teams TURN relay servers to evade network detection. The backdoor acquires an anonymous Teams visitor token from Microsoft's Skype-backed identity services, establishes a QUIC session through a real Microsoft TURN relay, and tunnels attacker C2 communication through that legitimate channel.

The primary behavioral indicators are:
1. Non-Teams processes (especially unexpected system utilities like Sysinternals tools) making outbound connections to Microsoft Teams/Skype TURN relay infrastructure on TURN ports (3478/5349) or via QUIC
2. `DbgView64.exe` (Sysinternals DebugView) exhibiting network activity — Backdoor.Turn injects into this process specifically
3. Processes acquiring anonymous visitor tokens from Microsoft identity endpoints while not being a Teams or Skype binary

**False positive sources:** Legitimate Microsoft Teams client, Skype, Microsoft Edge (Teams integration), corporate video conferencing tools may contact the same TURN infrastructure. Filter by process name to exclude known-good clients.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Proxy: External Proxy |
| Technique ID | T1090.002 |
| Secondary Technique | Web Service |
| Secondary Technique ID | T1102 |
| Secondary Technique | Process Injection |
| Secondary Technique ID | T1055 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.dest_port=3478 OR All_Traffic.dest_port=5349
         OR All_Traffic.app="quic")
    AND (All_Traffic.dest_host="*.turn.skype.com"
         OR All_Traffic.dest_host="*.relay.teams.microsoft.com"
         OR All_Traffic.dest_host="*.teams.microsoft.com")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
     All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where NOT match(process_name, "(?i)(teams|msedge|chrome|firefox|outlook|lync|skype|webexmta)")
| eval risk_score=case(
    process_name="DbgView64.exe", 95,
    match(process_name, "(?i)(svchost|lsass|winlogon|csrss|wininit)"), 90,
    match(process_name, "(?i)(procmon|procexp|autoruns|handle|listdlls|psexec|procdump)"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest dest_host dest_port process_name app risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="DbgView64.exe"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where NOT match(parent_process_name, "(?i)(dbgview\.exe|explorer\.exe|cmd\.exe|powershell\.exe|msiexec\.exe)")
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `DbgView64.exe` connecting to Teams TURN relay | 95 | Sysinternals DebugView has no legitimate reason to use Teams relay; direct IoC of Backdoor.Turn |
| Core Windows process (svchost, lsass) using TURN relay | 90 | Injected malware masquerading in system process using Teams TURN for C2 |
| Other Sysinternals tools using TURN relay | 85 | High suspicion — Sysinternals tools do not use Teams infrastructure |
| Unknown process using Teams TURN relay on TURN ports | 70 | Suspicious but could be legitimate; requires analyst investigation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| DragonForce (RaaS) | [MITRE ATT&CK G1075](https://attack.mitre.org/groups/G1075/), [Symantec — Backdoor.Turn (2026-06-16)](https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor) |

## References

- [Symantec — Hidden in Teams: DragonForce Backdoor.Turn (2026-06-16)](https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor)
- [BleepingComputer — Ransomware Gang Abuses Microsoft Teams Relays (2026-06-16)](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)
- [MITRE ATT&CK — T1090.002: Proxy: External Proxy](https://attack.mitre.org/techniques/T1090/002/)
- [MITRE ATT&CK — T1102: Web Service](https://attack.mitre.org/techniques/T1102/)
- [MITRE ATT&CK — T1055: Process Injection](https://attack.mitre.org/techniques/T1055/)
