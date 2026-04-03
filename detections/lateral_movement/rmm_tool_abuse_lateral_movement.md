# RMM Tool Abuse for Lateral Movement and Persistence

## Description

Detects unauthorized use of Remote Monitoring and Management (RMM) tools (ScreenConnect, AnyDesk, TeamViewer, Atera, Splashtop) for attacker-controlled lateral movement and persistent access. According to Mandiant M-Trends 2026, RMM tool abuse featured in 30.3% of intrusions. Attackers install these tools post-compromise to establish a second, persistent foothold that survives EDR response actions — because many organizations allowlist these tools, they are overlooked by defenses. Indicators include: RMM tool launched from unusual parent processes (wscript, cmd, PowerShell), run from non-standard paths, or executed without a prior approved change record. Common false positives: legitimate IT support sessions; maintain an inventory of approved RMM agents and alert on deviations (new installations, unusual parent, non-IT source hosts).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Lateral Movement |
| Tactic ID | TA0008 |
| Technique | Remote Access Software |
| Technique ID | T1219 |

Secondary technique: T1021.001 (Remote Services: Remote Desktop Protocol — often combined)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe",
      "connectwisecontrol.client.exe","AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
      "AteraAgent.exe","SplashtopStreamer.exe","LogMeIn.exe","GoToAssist.exe",
      "rustdesk.exe","RemotePC.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id Processes.process_path
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(parent_process_name, "(?i)wscript|cscript|mshta|rundll32|regsvr32|powershell|cmd"), 90,
    NOT match(process_path, "(?i)C:\\\\Program Files|C:\\\\Program Files \\(x86\\)"), 85,
    match(parent_process_name, "(?i)python|python3|node|bash|sh"), 85,
    1=1, 50)
| where risk_score >= 85
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process_path risk_score
```

**Supplemental: New RMM service installation (persistence)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Services
  where Services.service_name IN ("ScreenConnect","AnyDesk Service","TeamViewer","Atera Agent",
      "Splashtop Remote Service","RustDesk","LogMeIn") OR
    (Services.service_path="*ScreenConnect*" OR Services.service_path="*AnyDesk*"
     OR Services.service_path="*TeamViewer*" OR Services.service_path="*AteraAgent*"
     OR Services.service_path="*Splashtop*" OR Services.service_path="*rustdesk*")
  by Services.dest Services.user Services.service_name Services.service_path Services.start_mode
| `drop_dm_object_name(Services)`
| eval risk_score=case(
    match(start_mode, "(?i)auto"), 80,
    1=1, 70)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user service_name service_path start_mode risk_score
```

**Supplemental: RMM download from scripting engine (initial deployment)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")
         AND (Processes.process="*ScreenConnect*" OR Processes.process="*AnyDesk*"
              OR Processes.process="*TeamViewer*" OR Processes.process="*rustdesk*"
              OR Processes.process="*splashtop*"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process, "(?i)Invoke-WebRequest|wget|curl|Start-BitsTransfer|WebClient"), 90,
    match(process, "(?i)msiexec.*http|msiexec.*ftp"), 85,
    1=1, 75)
| where risk_score >= 75
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| RMM process spawned by scripting engine (wscript, PowerShell, cmd) | 90 | Attacker-driven deployment; IT admins use GPO/SCCM, not interpreters |
| RMM binary running from non-standard path | 85 | Evasion via path masquerading; legitimate installs always use Program Files |
| RMM spawned by Python/Node/bash | 85 | Post-exploit deployment from compromised CI/CD or developer host |
| RMM downloaded via PowerShell WebClient/Invoke-WebRequest | 90 | Classic attacker RMM drop pattern during lateral movement |
| New RMM service set to auto-start | 80 | Persistence installation; correlate with recent compromise indicators |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| Scattered Spider (UNC3944) | ScreenConnect and other RMM tools for lateral movement and persistence; 30%+ of Scattered Spider intrusions use RMM abuse |
| LockBit Affiliates | AnyDesk and TeamViewer commonly deployed post-compromise for persistent access and ransomware staging |
| Conti / Black Basta | RMM tools used in place of C2 frameworks to avoid detection during dwell time |
| Various Initial Access Brokers | ClickFix and social engineering campaigns deploy RMM tools as primary access mechanism (M-Trends 2026) |

## References

- [Google Threat Intelligence - M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/)
- [BleepingComputer - Routine Access Powering Modern Intrusions](https://www.bleepingcomputer.com/news/security/routine-access-is-powering-modern-intrusions-a-new-threat-report-finds/)
- [CISA - Malicious Use of Legitimate Remote Monitoring and Management Software](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a)
- [MITRE ATT&CK - T1219 Remote Access Software](https://attack.mitre.org/techniques/T1219/)
