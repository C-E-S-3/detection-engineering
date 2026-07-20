# SmartLoader / StealC Scheduled Task Persistence via Masquerading

## Description

Detects the persistence mechanism used by SmartLoader after successful delivery via the FakeGit MCP server supply chain campaign. After the LuaJIT dropper deploys its payload to `%LOCALAPPDATA%`, SmartLoader creates two scheduled tasks that masquerade as legitimate Windows system software:

1. **Persistence task** — re-executes the cached LuaJIT stage to survive takedowns of the original GitHub repository. Named and located to resemble audio manager services (e.g., `AudioManager`, `SoundCore`) or Microsoft Office update helpers.
2. **Update task** — re-downloads a fresh encrypted Lua stage from GitHub on each execution, providing resilience against local cleanup. Named similarly to the persistence task.

Both tasks point to LuaJIT executables (`luajit.exe`) stored in `%LOCALAPPDATA%` subdirectories with names chosen to blend with legitimate software. This differs from Gootloader's scheduled task pattern (which uses wscript/cscript) and from DEV#POPPER (which uses a LaunchAgent on macOS) — SmartLoader uses LuaJIT as the scheduled task binary.

Detection focuses on:
- Scheduled task creation pointing to `%LOCALAPPDATA%` executables (never a legitimate Windows task behavior)
- Task names matching audio-manager or Office update patterns combined with unusual task paths
- LuaJIT or Lua being set as a scheduled task binary

False positives: Third-party software that legitimately installs scheduled tasks pointing to AppData binaries (some Electron apps, some game clients). Filter with allowlists on known software publishers. The combination of a Lua interpreter + scheduled task is highly unusual in enterprise environments.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Scheduled Task/Job: Scheduled Task |
| Technique ID | T1053.005 |
| Secondary Tactic | Defense Evasion |
| Secondary Technique | Masquerading: Match Legitimate Name or Location |
| Secondary Technique ID | T1036.005 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Queries

### Query 1: Scheduled Task Created with LuaJIT Binary in Task Path

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("schtasks.exe", "at.exe")
  AND (Processes.process LIKE "%luajit%"
       OR Processes.process LIKE "%lua.exe%"
       OR Processes.process LIKE "%lua52.exe%"
       OR Processes.process LIKE "%lua53.exe%"
       OR Processes.process LIKE "%lua54.exe%"
       OR Processes.process LIKE "%resource.txt%")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95, note="LuaJIT binary registered as scheduled task — SmartLoader persistence pattern"
| table firstTime lastTime dest user parent_process_name process_name process risk_score note
```

### Query 2: Scheduled Task Pointing to LOCALAPPDATA Binary (Windows Event ID 4698)

```spl
`wineventlog_security` EventCode=4698
(TaskContent LIKE "%AppData\\Local\\%"
 OR TaskContent LIKE "%LOCALAPPDATA%")
(TaskContent LIKE "%luajit%"
 OR TaskContent LIKE "%lua.exe%"
 OR TaskContent LIKE "%AudioManager%"
 OR TaskContent LIKE "%SoundCore%"
 OR TaskContent LIKE "%OfficeUpdate%"
 OR TaskContent LIKE "%MicrosoftOffice%"
 OR TaskContent LIKE "%resource.txt%")
| eval risk_score=case(
    match(TaskContent, "(?i)luajit|lua\.exe|lua52|lua53|lua54"), 95,
    match(TaskContent, "(?i)AppData\\\\Local.*(audiomanager|soundcore|officeupdate|microsoftoffice)"), 85,
    1=1, 75)
| eval note="Scheduled task with LOCALAPPDATA path — matches SmartLoader/StealC persistence"
| table _time Computer SubjectUserName TaskName TaskContent risk_score note
```

### Query 3: Task Name Masquerade — Audio or Office Pattern with Unusual Executable Path

```spl
`wineventlog_security` EventCode IN (4698, 4702)
(TaskName LIKE "%Audio%"
 OR TaskName LIKE "%Sound%"
 OR TaskName LIKE "%Office%"
 OR TaskName LIKE "%Microsoft%Update%"
 OR TaskName LIKE "%Windows%Audio%")
NOT (TaskContent LIKE "%System32%"
     OR TaskContent LIKE "%Program Files%"
     OR TaskContent LIKE "%SysWOW64%"
     OR TaskContent LIKE "%Windows\\system%")
| eval risk_score=80, note="Task name impersonates audio/Office service but points outside system paths — SmartLoader masquerade pattern"
| table _time Computer SubjectUserName TaskName TaskContent risk_score note
```

### Query 4: Registry-Based Scheduled Task with LuaJIT Path (Alternative Persistence Path)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Registry
where Registry.registry_path LIKE "*\\Schedule\\TaskCache\\Tasks\\*"
  AND (Registry.registry_value_data LIKE "*luajit*"
       OR Registry.registry_value_data LIKE "*lua.exe*"
       OR Registry.registry_value_data LIKE "*resource.txt*"
       OR Registry.registry_value_data LIKE "*AppData\\Local*lua*")
by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name
   Registry.registry_value_data Registry.action
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user registry_path registry_value_data action risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| schtasks.exe creating task with `luajit.exe` or `lua*.exe` in task path | 95 | LuaJIT has no legitimate role as a scheduled task binary in enterprise environments |
| Security Event 4698 — task pointing to LOCALAPPDATA Lua/LuaJIT | 95 | Direct creation event; LuaJIT + LOCALAPPDATA path is SmartLoader's exact persistence pattern |
| Registry `TaskCache` entry with LuaJIT path | 90 | Registry-layer evidence of scheduled task persistence |
| Audio/Office-named task pointing outside System32/Program Files | 80 | Masquerade pattern; correlate with Lua execution or Polygon C2 events |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| SmartLoader Gang (FakeGit) | [Hexastrike Analysis](https://hexastrike.com/resources/blog/threat-intelligence/cloned-loaded-and-stolen-how-109-fake-github-repositories-delivered-smartloader-and-stealc/), [The Hacker News (2026-02)](https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html) |
| StealC (secondary payload loaded by SmartLoader) | [SOC Prime — SmartLoader/StealC](https://socprime.com/active-threats/smartloader-analysis/) |

## References

- [The Hacker News — SmartLoader Attack Uses Trojanized Oura MCP (2026-02)](https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html)
- [Hexastrike — 109 Fake GitHub Repos Deliver SmartLoader and StealC](https://hexastrike.com/resources/blog/threat-intelligence/cloned-loaded-and-stolen-how-109-fake-github-repositories-delivered-smartloader-and-stealc/)
- [Microsoft Security — Detecting Malicious Scheduled Tasks (MITRE T1053.005)](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK — T1053.005: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK — T1036.005: Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
