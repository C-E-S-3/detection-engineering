# ConnectWise ScreenConnect Unauthorized File Transfer and Execution (CVE-2026-84869)

## Description

Detects exploitation of CVE-2026-84869 (CVSS 9.9), a critical improper privilege management and missing authorization vulnerability in ConnectWise ScreenConnect added to CISA KEV September 12, 2026. The flaw allows an attacker to transfer files and execute code through an active ScreenConnect remote session without proper authorization.

Huntress documented three separate, unrelated incidents in which threat actors exploited this vulnerability to distribute malicious VBScript payloads to newly connected client endpoints. The detection focuses on the resulting execution behavior: ScreenConnect client processes spawning scripting interpreters or download utilities, which is anomalous in any legitimate ScreenConnect deployment.

**False positive sources:**
- Legitimate IT administrators running scripts via ScreenConnect (review session context and operator identity)
- ScreenConnect automated deployment scripts that invoke scripting hosts on first connection

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution |
| Secondary Tactic ID | TA0002 |
| Secondary Technique | Command and Scripting Interpreter: Visual Basic |
| Secondary Technique ID | T1059.005 |
| Secondary Technique | Command and Scripting Interpreter: PowerShell |
| Secondary Technique ID | T1059.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

### Query 1: ScreenConnect Spawning Scripting Interpreter or Download Utility

Detects ScreenConnect client processes spawning any scripting interpreter or common download utility — the primary exploitation behavior for CVE-2026-84869.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN (
      "ScreenConnect.ClientService.exe",
      "ScreenConnect.WindowsClient.exe",
      "ScreenConnect.Service.exe",
      "screenconnect.exe"
    )
    AND Processes.process_name IN (
      "wscript.exe","cscript.exe","powershell.exe","pwsh.exe",
      "cmd.exe","mshta.exe","rundll32.exe","regsvr32.exe",
      "certutil.exe","bitsadmin.exe","msiexec.exe","installutil.exe",
      "curl.exe","wget.exe"
    )
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)wscript|cscript|mshta"), 95,
    match(process_name,"(?i)powershell|pwsh"), 90,
    match(process_name,"(?i)rundll32|regsvr32|installutil|msiexec"), 85,
    match(process_name,"(?i)certutil|bitsadmin|curl|wget"), 85,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

### Query 2: Suspicious File Written by ScreenConnect Process

Detects script files written to user-writable locations by ScreenConnect client processes — the file staging step before VBScript or PowerShell execution.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.process_name IN (
      "ScreenConnect.ClientService.exe",
      "ScreenConnect.WindowsClient.exe",
      "ScreenConnect.Service.exe"
    )
    AND (Filesystem.file_name="*.vbs" OR Filesystem.file_name="*.ps1"
      OR Filesystem.file_name="*.bat" OR Filesystem.file_name="*.js"
      OR Filesystem.file_name="*.hta" OR Filesystem.file_name="*.exe"
      OR Filesystem.file_name="*.dll")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"(?i)\\.vbs$|\\.hta$"), 95,
    match(file_name,"(?i)\\.ps1$|\\.js$"), 90,
    match(file_name,"(?i)\\.exe$|\\.dll$|\\.bat$"), 85)
| where risk_score >= 85
| table firstTime lastTime dest user process_name file_path file_name risk_score
```

### Query 3: New Executable or Script Executed Within 60 Seconds of ScreenConnect File Write

Correlates a file write by ScreenConnect with subsequent execution of that file — the full kill chain of CVE-2026-84869 exploitation.

```spl
index=* sourcetype IN ("xmlwineventlog","WinEventLog:Microsoft-Windows-Sysmon/Operational")
  EventCode IN (11,1)
| eval event_type=case(EventCode=11,"file_create", EventCode=1,"process_create", 1=1,"other")
| eval process_parent=lower(coalesce(ParentImage,ParentProcessName,""))
| eval file_written=if(event_type="file_create"
    AND match(process_parent,"screenconnect"), 1, 0)
| eval suspect_exec=if(event_type="process_create"
    AND match(process_parent,"screenconnect")
    AND match(lower(coalesce(Image,CommandLine,"")),"wscript|cscript|powershell|mshta|cmd"), 1, 0)
| stats sum(file_written) as file_writes sum(suspect_exec) as script_execs
        min(_time) as firstTime max(_time) as lastTime
        values(TargetFilename) as written_files values(CommandLine) as exec_cmdlines
        by Computer
| where file_writes >= 1 AND script_execs >= 1
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime Computer written_files exec_cmdlines file_writes script_execs risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| ScreenConnect spawning wscript/cscript/mshta | 95 | VBScript payload execution; direct CVE-2026-84869 exploitation pattern |
| ScreenConnect spawning PowerShell/pwsh | 90 | Scripted post-exploitation; uncommon in legitimate ScreenConnect sessions |
| ScreenConnect spawning download utility (certutil, curl) | 85 | Payload staging; second-stage malware retrieval |
| ScreenConnect writing VBS/HTA to disk | 95 | File staging precursor to VBScript execution |
| ScreenConnect file write + scripting exec within session | 95 | Full kill chain correlation; near-certain exploitation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (multiple incidents) | Three unrelated incidents documented by Huntress; multiple independent threat actors exploiting CVE-2026-84869; CISA KEV Sep 12 2026 |

## References

- [The Hacker News — CISA Adds 5 Actively Exploited Artifactory, ScreenConnect, and RouterOS Flaws to KEV](https://thehackernews.com/2026/09/cisa-adds-5-actively-exploited.html)
- [HOL Blog — CVE-2026-84869 ScreenConnect Client File Transfer Execution KEV](https://hol.org/blog/cve-2026-84869-screenconnect-client-file-transfer-execution-kev)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD — CVE-2026-84869](https://nvd.nist.gov/vuln/detail/CVE-2026-84869)
- [Threat Intel Report — CISA KEV Sep 12 2026](../../threat-intel/2026-09-14_cisa-kev-jfrog-artifactory-screenconnect-cve-2026-42016-42018-84869.md)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1059.005 Visual Basic](https://attack.mitre.org/techniques/T1059/005/)
- [MITRE ATT&CK — T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
