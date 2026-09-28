# MacSync iCloud Calendar Dead-Drop C2 and macOS Keychain Harvesting

## Description

Detects MacSync macOS infostealer/backdoor behavior: a non-calendar process connecting to Apple's CalDAV endpoint (`caldav.icloud.com`) to retrieve attacker-placed commands from public iCloud Calendar event DESCRIPTION fields, which are then piped to `zsh` for execution. Also covers associated credential theft from macOS Keychain and LaunchAgent persistence creation.

MacSync is distributed as a trojanized cryptocurrency wallet DMG (e.g., fake "Toria" wallet) via X and Telegram. The iCloud calendar dead-drop is architecturally similar to HollowGraph (M365 calendar), APT37 NarwhalRAT (pCloud), and Glassworm (Google Calendar), but uses Apple's CalDAV service, making it difficult to block at the network layer without disrupting legitimate macOS Calendar sync.

False positive sources: legitimate `CalendarAgent` and `dataaccessd` daemons connecting to `caldav.icloud.com`; third-party calendar sync utilities. The key discriminator is the _process name_: only Apple's own calendar daemons should initiate CalDAV connections.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service: Dead Drop Resolver |
| Technique ID | T1102.001 |

Secondary mappings:
- TA0006 / T1555.001 — Credentials from Password Stores: Keychain
- TA0003 / T1543.001 — Create or Modify System Process: Launch Agent
- TA0002 / T1059.004 — Command and Scripting Interpreter: Unix Shell

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |
| Actions on Objectives |

## Splunk Detection Query

### Primary: Non-Calendar Process Connecting to caldav.icloud.com
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="caldav.icloud.com"
    AND NOT All_Traffic.app IN ("Calendar","CalendarAgent","dataaccessd","accountsd","cloudd","nsurlsessiond")
  by All_Traffic.src All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src src_ip dest dest_port app process risk_score
```

### Secondary: Shell Spawned by Network Download Process (iCloud C2 Stage Execution)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("zsh","sh","bash")
    AND Processes.parent_process_name IN ("curl","wget","python","python3","ruby","perl","nscurl")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name,"(curl|wget|nscurl)"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Tertiary: Unexpected Process Accessing macOS Keychain Files
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*/Library/Keychains/*","*login.keychain*","*login.keychain-db*")
    AND NOT Filesystem.process_name IN ("security","securityd","ksfetch","keychain-interpose","SystemUIServer","SecurityAgent")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| where risk_score >= 80
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

### Quaternary: LaunchAgent Plist Created by Non-System Process (macOS Persistence)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*/Library/LaunchAgents/*.plist")
    AND Filesystem.action="created"
    AND NOT Filesystem.process_name IN ("launchd","installd","pkgutil","softwareupdate")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Non-Apple process connecting to caldav.icloud.com | 90 | Any non-calendar process using CalDAV is anomalous; highly indicative of dead-drop C2 |
| Shell spawned by curl/wget/nscurl | 85 | Classic pipe-to-shell C2 execution pattern |
| Shell spawned by python/ruby/perl | 70 | Less direct but consistent with script-based stage delivery |
| Unexpected process accessing Keychain files | 80 | MacSync specifically targets login.keychain-db; non-system access is near-always malicious |
| New LaunchAgent plist from non-system process | 75 | Persistence mechanism; combined with above creates high-confidence composite signal |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| MacSync Operators (Unknown — MaaS) | [Kaspersky Securelist — MacSync new version (2026-09)](https://securelist.com/macsync-new-version/121383/) |
| Glassworm (Google Calendar dead-drop variant) | [CrowdStrike — Disrupting Glassworm (2026-05-26)](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/) |
| Cavern Manticore / HollowGraph (M365 Calendar dead-drop) | [Group-IB — HollowGraph (2026-07-20)](https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html) |
| APT37 / ScarCruft (pCloud dead-drop variant) | [MITRE ATT&CK G0067](https://attack.mitre.org/groups/G0067/) |

## References

- [Kaspersky Securelist: MacSync new version analysis](https://securelist.com/macsync-new-version/121383/)
- [BleepingComputer: MacSync malware uses public iCloud calendars to deliver new payloads](https://www.bleepingcomputer.com/news/security/macsync-malware-uses-public-icloud-calendars-to-deliver-new-payloads/)
- [MITRE ATT&CK T1102.001: Web Service: Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK T1555.001: Credentials from Password Stores: Keychain](https://attack.mitre.org/techniques/T1555/001/)
