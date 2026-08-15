# APT36 PATCHCORD/SHEETCORD/HACKERAI — Cloud Service C2 Detection

## Description

Detects APT36 (Transparent Tribe, G0134) three-implant cluster abusing cloud services for command and control:

- **PATCHCORD**: C/C++ HTTP backdoor with hard-coded C2 at `appstoore[.]solutions` (→ 46.30.188[.]13:8080)
- **SHEETCORD**: Go-based backdoor using Google Sheets API as a bidirectional C2 channel
- **HACKERAI**: Go-based backdoor using GitHub Gist API for command retrieval; persists via browser LNK shortcut hijacking

Three SPL queries cover IOC-based DNS detection (high confidence) and behavioral detection of non-browser/non-developer processes communicating with Google Sheets or GitHub Gist APIs (medium-high confidence). Targeting Afghan telecom operators and South Asian critical infrastructure since March 2026.

**Expected false positives:**
- Legitimate developer tools (python.exe, node.exe, go.exe) contacting GitHub APIs — tune the exclusion list to your environment
- Automated scripts or CI/CD pipelines using Google Sheets — add known process names to the exclusion list
- Security scanning tools probing cloud service endpoints

## MITRE ATT&CK Mapping

- **Tactic:** Command and Control (TA0011)
- **Techniques:**
  - T1071.001 — Application Layer Protocol: Web Protocols (PATCHCORD HTTP C2)
  - T1102.002 — Web Service: Bidirectional Communication (SHEETCORD / Google Sheets)
  - T1102.001 — Web Service: Dead Drop Resolvers (HACKERAI / GitHub Gist)

## Lockheed Martin Kill Chain Phase

- Command & Control (C2)

## Splunk SPL Query

### Query 1: DNS IOC Match — PATCHCORD C2 and SHEETCORD Delivery Domains

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("appstoore.solutions", "nic-support.site")
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query record_type risk_score
```

### Query 2: Behavioral — Non-Browser Process Connecting to Google Sheets API (SHEETCORD)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_dns="sheets.googleapis.com"
  AND All_Traffic.process_name NOT IN (
    "chrome.exe","firefox.exe","msedge.exe","iexplore.exe","safari","opera.exe",
    "brave.exe","vivaldi.exe","WINWORD.exe","EXCEL.EXE","OUTLOOK.EXE",
    "Sheets.exe","googledrivesync.exe","GoogleDriveFS.exe","python.exe","node.exe","java"
  )
by All_Traffic.src All_Traffic.dest_dns All_Traffic.process_name All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)mshta|wscript|cscript|powershell|rundll32|regsvr32"), 90,
    match(process_name, "(?i)svchost|services"), 75,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime src dest_dns process_name dest_port risk_score
```

### Query 3: Behavioral — Non-Developer Process Connecting to GitHub Gist API (HACKERAI)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_dns="gist.github.com" OR All_Traffic.dest_dns="api.github.com")
  AND All_Traffic.process_name NOT IN (
    "chrome.exe","firefox.exe","msedge.exe","git.exe","gh.exe","code.exe",
    "node.exe","python.exe","java","go.exe","curl.exe","wget.exe"
  )
by All_Traffic.src All_Traffic.dest_dns All_Traffic.process_name All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)mshta|wscript|cscript|powershell|rundll32|regsvr32"), 90,
    match(process_name, "(?i)svchost|services"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest_dns process_name dest_port risk_score
```

## Risk Score Logic

| Condition | Score |
|-----------|-------|
| DNS query matches APT36 IOC domains (`appstoore.solutions`, `nic-support.site`) | 95 |
| Sheets.googleapis.com from scripting engine (mshta, wscript, powershell, etc.) | 90 |
| GitHub Gist/API from scripting engine | 90 |
| GitHub Gist/API from svchost/services | 80 |
| Sheets.googleapis.com from svchost/services | 75 |
| GitHub Gist/API from other unexpected process | 60 |
| Sheets.googleapis.com from other non-browser process | 55 |

Minimum threshold: 55 (Sheets query) / 60 (GitHub query).

## Associated Threat Actors

- **APT36 / Transparent Tribe (G0134)** — Pakistan-nexus nation-state APT; active since at least 2016; primary targets include Indian and Afghan government, military, and critical infrastructure

## References

- [Acronis TRU — PATCHCORD Cluster (2026-08-13)](https://www.acronis.com/en/tru/posts/patchcord-new-malware-cluster-targets-afghan-telecom-and-south-asian-critical-infrastructure/)
- [MITRE ATT&CK G0134 — APT36](https://attack.mitre.org/groups/G0134/)
- [MITRE ATT&CK T1102.002 — Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK T1102.001 — Web Service: Dead Drop Resolvers](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
