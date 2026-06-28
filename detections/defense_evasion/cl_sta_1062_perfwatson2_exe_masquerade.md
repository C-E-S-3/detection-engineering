# CL-STA-1062 TinyRCT PerfWatson2.exe Process Masquerade

## Description

Detects the TinyRCT C# backdoor deployed by the Chinese-speaking APT cluster CL-STA-1062 against Southeast Asian energy and government organizations. The backdoor is deployed as `PerfWatson2.exe` to `%LOCALAPPDATA%`, impersonating the legitimate Microsoft Visual Studio 2022 performance telemetry binary (`PerfWatson2.exe`) which legitimately resides in `C:\Program Files\Microsoft Visual Studio\<version>\Common7\IDE\`.

TinyRCT is delivered via `chrome_setup.zip` — a malicious archive that bundles a legitimate Chrome installer with a hidden DLL and a trojanized `.config` file. The `.config` file uses `APPDOMAIN_MANAGER_ASM` / `APPDOMAIN_MANAGER_TYPE` directives to force the .NET runtime to load the attacker's DLL as an AppDomainManager inside a trusted .NET host process (T1574.014), which then drops and executes `PerfWatson2.exe`.

Once running, TinyRCT performs an environment check and terminates silently if it is not executing from `%LOCALAPPDATA%`, defeating sandbox detonation. It beacons every 10 seconds to 45.32.113[.]172 over plain HTTP with AES-128-CBC encrypted payloads (hardcoded key: `ThisIsASecretKey87654321`). Capabilities include arbitrary command execution via `cmd.exe`, file enumeration, file exfiltration in 40 KB gzip-compressed chunks, JPEG screenshot capture, file download, and self-deletion.

**False positives:** Visual Studio installations will legitimately execute `PerfWatson2.exe` from `C:\Program Files\Microsoft Visual Studio\...\Common7\IDE\`. Any execution from paths outside this directory — especially `%LOCALAPPDATA%` or `%TEMP%` — is highly anomalous. Developers who do not have Visual Studio installed will never generate true positives.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Masquerade: Match Legitimate Name or Location |
| Technique ID | T1036.005 |
| Secondary Tactic | Command and Control |
| Secondary Technique | Application Layer Protocol: Web Protocols |
| Secondary Technique ID | T1071.001 |
| Secondary Tactic | Execution |
| Secondary Technique | AppDomain Manager Injection |
| Secondary Technique ID | T1574.014 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Command & Control (C2) |

## Splunk Detection Query

### Query 1 — PerfWatson2.exe Executing from Non-Visual-Studio Path

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="PerfWatson2.exe"
  AND NOT Processes.process_path IN (
    "*\\Microsoft Visual Studio\\*\\Common7\\IDE\\*",
    "*\\Program Files\\Microsoft Visual Studio\\*",
    "*\\Program Files (x86)\\Microsoft Visual Studio\\*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process_path Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_path, "(?i)localappdata|appdata"), 95,
    match(process_path, "(?i)temp|tmp|public|programdata"), 90,
    NOT match(process_path, "(?i)microsoft visual studio|program files"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process_path process risk_score
```

### Query 2 — chrome_setup.zip Creation Followed by PerfWatson2.exe Execution (Delivery Chain)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="chrome_setup.zip"
  AND Filesystem.action="created"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| join type=left dest
    [| tstats `security_content_summariesonly` count min(_time) as exec_time
     from datamodel=Endpoint.Processes
     where Processes.process_name="PerfWatson2.exe"
     by Processes.dest Processes.user Processes.process_name Processes.process_path
     | `drop_dm_object_name(Processes)`]
| where isnotnull(exec_time) AND (exec_time - firstTime) < 3600
| `security_content_ctime(firstTime)`
| `security_content_ctime(exec_time)`
| eval risk_score=95
| table firstTime exec_time dest user file_path process_name process_path risk_score
```

### Query 3 — HTTP Traffic to Known TinyRCT C2 and Staging IPs

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_ip IN ("45.32.113.172", "139.180.134.221")
by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest_ip dest_port process_name risk_score
```

### Query 4 — Suspicious .config File Written to AppData or Temp Paths (AppDomainManager Stage)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where (Filesystem.file_name="*.config" OR Filesystem.file_name="*.exe.config")
  AND (Filesystem.file_path="*\\AppData\\Local\\*"
       OR Filesystem.file_path="*\\Temp\\*"
       OR Filesystem.file_path="*\\ProgramData\\*"
       OR Filesystem.file_path="*\\Users\\Public\\*")
  AND NOT Filesystem.process_name IN ("msiexec.exe", "setup.exe", "installer.exe",
    "nuget.exe", "dotnet.exe", "devenv.exe")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
   Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)localappdata.*chrome|appdata.*chrome"), 90,
    match(process_name, "(?i)cmd|powershell|wscript|cscript"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| PerfWatson2.exe in %LOCALAPPDATA% or AppData path | 95 | Gaslight-specific deployment path; legitimate binary never lives here |
| PerfWatson2.exe in Temp/tmp/Public/ProgramData | 90 | Common staging paths; not a legitimate VS location |
| PerfWatson2.exe anywhere outside VS installation | 85 | Baseline masquerade detection; analyst review required |
| chrome_setup.zip followed by PerfWatson2.exe within 1 hour | 95 | Confirms full TinyRCT delivery chain; near-certain true positive |
| Network traffic to 45.32.113.172 or 139.180.134.221 | 95 | Unit 42-confirmed TinyRCT C2 and staging IPs |
| Suspicious .config in Chrome/AppData path | 90 | Matches AppDomainManager injection via chrome_setup.zip delivery |
| Suspicious .config written by cmd/PowerShell | 85 | Script-driven config drop is anomalous in these paths |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| CL-STA-1062 | [Unit 42 — CL-STA-1062 TinyRCT Backdoor (2026-06-25)](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/) |

## References

- [Unit 42 — CL-STA-1062: Chinese-Speaking APT Deploys Novel TinyRCT C# Backdoor Against Southeast Asian Energy and Government Sectors (2026-06-25)](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [MITRE ATT&CK T1036.005 — Masquerade: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [MITRE ATT&CK T1574.014 — Hijack Execution Flow: AppDomain Manager Injection](https://attack.mitre.org/techniques/T1574/014/)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
