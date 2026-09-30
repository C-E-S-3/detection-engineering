# Star Blizzard RedFlick: Scheduled Task CPL Proxy Execution via control.exe

## Description

Detects the RedFlick delivery technique used by Star Blizzard (Russia FSB Centre 18 / COLDRIVER / SEABORGIUM) where a VHD-contained LNK file registers a scheduled task that invokes `control.exe` with a malicious `.cpl` (Control Panel) file argument. This abuses T1218.002 (Signed Binary Proxy Execution: Control Panel) to execute attacker-controlled code through a legitimate, signed Windows binary, bypassing detections that focus on PowerShell, wscript, or other common execution vectors.

The technique was first documented by Microsoft Threat Intelligence in September 2026. False positive sources include legitimate Control Panel extension deployments in enterprise environments; a filter on non-System32 CPL paths reduces false positives significantly.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Signed Binary Proxy Execution: Control Panel |
| Technique ID | T1218.002 |

Secondary techniques: T1053.005 (Scheduled Task — used to persist and trigger the CPL execution), T1566.002 (Spearphishing Link — initial delivery via VHD in phishing archive)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

### Query 1: control.exe Loading CPL File from Non-Standard Path

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="control.exe"
    AND Processes.process="*.cpl*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    NOT match(process,"(?i)\\\\windows\\\\system32\\\\"), 90,
    match(parent_process_name,"(?i)svchost|taskeng|wmiprvse|mmc"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 2: Scheduled Task Created to Execute control.exe with CPL Argument

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="schtasks.exe"
    AND Processes.process="*/create*"
    AND Processes.process="*control.exe*"
    AND Processes.process="*.cpl*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 3: VHD/VHDX or CPL File Written to User-Writable Path

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_name="*.cpl" OR Filesystem.file_name="*.vhd" OR Filesystem.file_name="*.vhdx")
    AND Filesystem.file_path IN ("*\\Users\\*","*\\AppData\\*","*\\Temp\\*","*\\Downloads\\*")
    AND Filesystem.action="created"
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"(?i)\.cpl$"), 80,
    match(file_name,"(?i)\.(vhd|vhdx)$"), 70,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

### Query 4: DNS IOC Hunt — Star Blizzard RedFlick Infrastructure

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("etia.ca","groy.cc","gliderrompercycl.com","muvb.net",
    "divekickspolic.org","matjk.click","bpdaersa.click","stuseamandesilt.org",
    "itechx.tel","guach.net","ruten.observer","byveo.org","secure-dns-hub.com",
    "qumel.link","cyrna.top","drasw.club")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src query answer risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| schtasks.exe `/create` with `control.exe` + `.cpl` argument | 95 | Near-certain malicious; legitimate scheduled tasks do not point control.exe at .cpl files |
| DNS query to known Star Blizzard IOC domain | 100 | Confirmed indicator; any match warrants immediate investigation |
| control.exe loading .cpl from outside %SystemRoot%\System32 | 90 | Legitimate CPL extensions reside in System32; non-standard path is highly suspicious |
| control.exe spawned from svchost/taskeng/wmiprvse with .cpl | 85 | Task scheduler parent with CPL execution is the core RedFlick pattern |
| Any .cpl file created in user-writable directory | 80 | CPL files are not normally written to user directories by legitimate software |
| VHD/VHDX created in Downloads/Temp/AppData | 70 | VHD phishing delivery vector; combined with follow-on CPL activity is high confidence |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Star Blizzard (COLDRIVER / SEABORGIUM) | [MITRE ATT&CK G0122](https://attack.mitre.org/groups/G0122/) · [Microsoft Threat Actor Profile](https://www.microsoft.com/en-us/security/blog/2024/01/11/star-blizzard-increases-sophistication-and-evasion-in-ongoing-attacks/) · [UK NCSC COLDRIVER Advisory](https://www.ncsc.gov.uk/news/coldriver-russian-threat-actor-targeting-high-value-targets) |

## References

- [Microsoft Security Blog — Star Blizzard RedFlick (2026-09-29)](https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/)
- [MITRE ATT&CK T1218.002 — Control Panel](https://attack.mitre.org/techniques/T1218/002/)
- [MITRE ATT&CK T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [Threat intel report: threat-intel/2026-09-29_microsoft-security-blog-star-blizzard-redflick-cosmicpulse.md]
