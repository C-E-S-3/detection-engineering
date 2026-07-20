# SmartLoader LuaJIT Postinstall Hook Dropper

## Description

Detects SmartLoader's execution stage in which an obfuscated LuaJIT script (`resource.txt`) is spawned by an npm or pip package postinstall hook. When a user installs a trojanized MCP server or AI skill package from a malicious GitHub repository in the FakeGit campaign, the package's postinstall hook invokes a LuaJIT interpreter with the embedded `resource.txt` script as its argument. The Lua script deploys the LuaJIT runtime to two locations under `%LOCALAPPDATA%` (e.g., `%LOCALAPPDATA%\AudioManager\luajit.exe` and a second copy under a Microsoft Office-like path), writes a decoded copy of itself to disk as the persistence payload, and invokes SmartLoader as the primary dropper.

Key distinguishing behaviors:
- `lua.exe`, `luajit.exe`, or `lua52.exe` spawned as a child of `node.exe`, `npm.cmd`, `python.exe`, or `pip.exe`
- LuaJIT process command line references `resource.txt` or files in temp/package directories
- LuaJIT writing executables or Lua scripts to `%LOCALAPPDATA%` subdirectories masquerading as system software
- LuaJIT or its children making outbound connections shortly after invocation

Lua is not a common runtime on developer workstations except in game development (Roblox Studio, LÖVE, etc.) and embedded-systems contexts. A Lua interpreter spawned by an npm/pip process is a high-confidence indicator of this specific dropper pattern.

False positives: Game developers using Lua alongside Node.js; some legacy IoT toolchains that invoke Lua from pip-managed build systems. Suppress with an allowlist on known-legitimate parent application paths.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: Other (Lua/LuaJIT) |
| Technique ID | T1059.007 |
| Secondary Tactic | Defense Evasion |
| Secondary Technique | Obfuscated Files or Information |
| Secondary Technique ID | T1027 |
| Secondary Tactic (2) | Defense Evasion |
| Secondary Technique (2) | Masquerading: Match Legitimate Name or Location |
| Secondary Technique ID (2) | T1036.005 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation (postinstall hook triggers LuaJIT dropper execution) |
| Installation (LuaJIT writes payload to %LOCALAPPDATA%) |

## Splunk Detection Queries

### Query 1: LuaJIT Spawned by npm, pip, or Node.js (Postinstall Hook Execution)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN (
    "node.exe", "node", "npm.cmd", "npm", "npx.cmd", "npx",
    "python.exe", "python3", "python", "pip.exe", "pip", "pip3")
  AND Processes.process_name IN (
    "lua.exe", "luajit.exe", "lua52.exe", "lua53.exe", "lua54.exe",
    "lua", "luajit", "lua5.1", "lua5.2", "lua5.3", "lua5.4")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process_id
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)resource\.txt"), 95,
    match(parent_process_name, "(?i)node\.exe|npm\.cmd"), 85,
    match(parent_process_name, "(?i)python|pip"), 80,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 2: LuaJIT Writing Executables to LOCALAPPDATA (Payload Deployment)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.process_name IN (
    "lua.exe", "luajit.exe", "lua52.exe", "lua53.exe", "lua54.exe",
    "lua", "luajit")
  AND (Filesystem.file_path LIKE "%\\AppData\\Local\\%"
       OR Filesystem.file_path LIKE "%/.local/%"
       OR Filesystem.file_path LIKE "%/tmp/%")
  AND (Filesystem.file_name LIKE "%.exe"
       OR Filesystem.file_name LIKE "%.lua"
       OR Filesystem.file_name LIKE "%.dll"
       OR Filesystem.file_name LIKE "resource.txt")
  AND Filesystem.action IN ("created", "write")
by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)audiomanager|audioservice|officeupdate|microsoft.office"), 95,
    match(file_name, "(?i)luajit\.exe"), 90,
    match(file_name, "(?i)resource\.txt"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user process_name file_path file_name action risk_score
```

### Query 3: LuaJIT Process Making Outbound Network Connection

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.process_name IN (
    "lua.exe", "luajit.exe", "lua52.exe", "lua53.exe", "lua54.exe",
    "lua", "luajit")
  AND All_Traffic.direction="outbound"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
   All_Traffic.process_name All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime src dest_ip dest_port process_name app risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| LuaJIT spawned by node/npm with `resource.txt` in command line | 95 | Exact SmartLoader IOC — high confidence malicious |
| LuaJIT writing `luajit.exe` to LOCALAPPDATA/AudioManager or Office path | 95 | Matches SmartLoader payload masquerade location |
| LuaJIT writing `resource.txt` anywhere on disk | 90 | SmartLoader persistence copy of the Lua stage |
| LuaJIT spawned by node.exe or npm.cmd (any argument) | 85 | No legitimate npm packages invoke Lua; near-certain malicious |
| LuaJIT making outbound network connection | 85 | Lua interpreters do not make outbound connections in legitimate use on managed endpoints |
| LuaJIT spawned by python/pip | 80 | Less common than npm vector but same attack chain via pip install |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| SmartLoader Gang | [Hexastrike Analysis](https://hexastrike.com/resources/blog/threat-intelligence/cloned-loaded-and-stolen-how-109-fake-github-repositories-delivered-smartloader-and-stealc/), [The Hacker News (2026-02)](https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html) |

## References

- [The Hacker News — SmartLoader Attack Uses Trojanized Oura MCP Server (2026-02)](https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html)
- [Hexastrike — 109 Fake GitHub Repos Deliver SmartLoader and StealC](https://hexastrike.com/resources/blog/threat-intelligence/cloned-loaded-and-stolen-how-109-fake-github-repositories-delivered-smartloader-and-stealc/)
- [SOC Prime — SmartLoader Analysis](https://socprime.com/active-threats/smartloader-analysis/)
- [Security Affairs — SmartLoader MCP Clone StealC](https://securityaffairs.com/188135/ai/smartloader-hackers-clone-oura-mcp-project-to-spread-stealc-malware.html)
- [MITRE ATT&CK — T1059.007: JavaScript/Scripting](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK — T1036.005: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
