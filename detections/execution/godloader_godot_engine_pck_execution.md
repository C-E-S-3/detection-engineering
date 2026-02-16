# Godloader Godot Engine .pck Execution

## Description

Godloader abuses the Godot game engine to execute malicious GDScript packaged in `.pck` (pack) files. The attack involves a renamed Godot Engine runtime executable loading a sibling `.pck` file that contains GDScript payloads. On load, the GDScript `_ready()` callback fires and uses `OS.execute()` to spawn PowerShell for Defender evasion, payload download, and execution. This detection identifies uncommon processes that behave as Godot Engine runtimes spawning PowerShell, as well as process creation events where the command line references `.pck` files from user-writable directories.

The Godot Engine binary is typically renamed (e.g., `Laucnherkks.exe`) and distributed alongside its malicious `.pck` file via fake GitHub repositories operated by the Stargazers Ghost Network. Nearly zero antivirus engines detect the Godot-based loader on VirusTotal due to its use of a legitimate game engine runtime.

False positive sources: Legitimate Godot game developers testing projects. Tuning: whitelist known Godot development directories and signed game executables.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter |
| Technique ID | T1059 |
| Secondary Technique | Shared Modules (T1129) |
| Secondary Technique | Masquerading (T1036) |
| Secondary Tactic | Defense Evasion (TA0005) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name!="explorer.exe"
    AND Processes.process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where NOT match(parent_process_name, "(?i)(wscript|cscript|explorer|svchost|services|cmd|powershell|mmc|taskmgr)\.exe$")
| eval risk_score=case(
    match(process, "(?i)Add-MpPreference") AND match(process, "(?i)ExclusionPath"), 95,
    match(process, "(?i)(Invoke-WebRequest|DownloadFile|DownloadString|Start-BitsTransfer|bitbucket\.org|raw\.githubusercontent)"), 90,
    match(parent_process, "(?i)\\\\(Users|Temp|Downloads|AppData|ProgramData)\\\\"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name parent_process process_name process risk_score
```

### Supplemental Query: .pck File Creation in User Directories

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="*.pck"
    AND (Filesystem.file_path="*\\Users\\*"
         OR Filesystem.file_path="*\\Temp\\*"
         OR Filesystem.file_path="*\\Downloads\\*"
         OR Filesystem.file_path="*\\AppData\\*"
         OR Filesystem.file_path="*\\ProgramData\\*")
    AND NOT Filesystem.file_path IN ("*\\Steam\\*", "*\\Epic Games\\*", "*\\GOG Galaxy\\*", "*\\Program Files*")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)\\\\(Temp|Downloads)\\\\"), 80,
    match(file_path, "(?i)\\\\AppData\\\\"), 75,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user file_name file_path process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Unusual parent spawns PowerShell with Defender exclusion commands | 95 | Signature Godloader behavior: disable Defender then download payloads |
| Unusual parent spawns PowerShell with download cradle commands | 90 | Payload retrieval from Bitbucket or GitHub, characteristic of Godloader |
| Unusual parent from user-writable directory spawns PowerShell | 85 | Renamed executable in staging path indicates loader behavior |
| Any other uncommon parent spawning PowerShell | 70 | Anomalous process lineage warrants investigation |
| .pck file created in Temp/Downloads | 80 | Godot pack files in download directories are not normal |
| .pck file created in AppData | 75 | Possible staging of malicious Godot pack file |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Stargazer Goblin (Stargazers Ghost Network) | [Check Point - Stargazers Ghost Network](https://research.checkpoint.com/2024/stargazers-ghost-network/) |
| Godloader / GodLoader | [Check Point - Gaming Engines: An Undetected Playground for Malware Loaders](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/) |

## References

- [Check Point Research - Gaming Engines: An Undetected Playground for Malware Loaders](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/)
- [The Hacker News - Cybercriminals Exploit Popular Game Engine Godot to Distribute Cross-Platform Malware](https://thehackernews.com/2024/11/cybercriminals-exploit-popular-game.html)
- [BleepingComputer - Hackers Abuse Popular Godot Game Engine to Infect Thousands of PCs](https://www.bleepingcomputer.com/news/security/new-godloader-malware-infects-thousands-of-gamers-using-godot-scripts/)
- [Godot Engine - Statement on GodLoader Malware Loader](https://godotengine.org/article/statement-on-godloader-malware-loader/)
