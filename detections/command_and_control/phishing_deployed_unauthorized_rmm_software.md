# Phishing-Deployed Unauthorized RMM Software

## Description

Detects remote monitoring and management (RMM) software installed or executed outside of expected enterprise deployment paths, which is a strong indicator that phishing, social engineering, or malware delivered the RMM client as an unauthorized persistent access channel. Threat actors abuse legitimate RMM tools (MSP360, ConnectWise ScreenConnect, AnyDesk, TeamViewer) because they: (1) install as trusted Windows services, (2) use signed binaries that evade EDR, (3) blend with legitimate MSP traffic, and (4) give full interactive access without triggering traditional C2 detections.

This detection covers two documented September 2026 campaigns: a Microsoft-reported phishing campaign distributing trojanized MSP360/ScreenConnect installers (adswre[.]cfd, trews[.]cfd), and tech support fraud browser lockers (Unit 42) that socially engineer victims into installing AnyDesk/TeamViewer after a fake security alert.

False positive sources: legitimate IT teams installing RMM tools from non-standard paths during deployment, help desk sessions initiated from browser-based jump pages. Tune `process_path` exclusions to match your managed RMM deployment locations.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Remote Access Software |
| Technique ID | T1219 |

Secondary techniques: T1566.002 (Spearphishing Link — delivery), T1543.003 (Windows Service — persistence), T1547.001 (Registry Run Keys — autostart)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

### Query 1: RMM Process Running from Non-Standard Install Path

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN (
    "msp360rmm.exe","MSP360Backup.exe","MSP360RemoteDesktopService.exe",
    "ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe",
    "AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(\\\\temp\\\\|\\\\appdata\\\\|\\\\downloads\\\\|\\\\desktop\\\\)"), 90,
    NOT match(process,"(?i)(\\\\program files\\\\|\\\\program files (x86)\\\\)"), 80,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 2: Browser Process Spawning RMM Software (Social Engineering Pattern)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN (
    "AnyDesk.exe","TeamViewer.exe","msra.exe","QuickAssist.exe",
    "ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe",
    "msp360rmm.exe","MSP360Backup.exe")
    AND Processes.parent_process_name IN (
      "chrome.exe","msedge.exe","firefox.exe","iexplore.exe",
      "opera.exe","brave.exe","MicrosoftEdge.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 3: DNS Queries to Known Phishing-RMM Delivery Infrastructure

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN (
    "adswre.cfd","trews.cfd","adsaw.cfd","sdfghj.rd-team.ru",
    "swedcorry.stefneyv.com","ojsuyw.niyari.org","bunstar.harej.si",
    "hitrelay.com","acrobat-reader-installer.com","03webzoominvite.us")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src query answer risk_score
```

### Query 4: New RMM Service Installation (Windows Event Log)

```spl
index=wineventlog EventCode=7045
(ServiceName="MSP360*" OR ServiceName="ScreenConnect*" OR ServiceName="AnyDesk*"
 OR ServiceName="TeamViewer*" OR ServiceName="ConnectWise*")
| eval risk_score=case(
    match(ServiceFileName,"(?i)(temp|appdata|downloads|desktop)"), 95,
    NOT match(ServiceFileName,"(?i)program files"), 80,
    1=1, 60)
| where risk_score >= 60
| table _time ComputerName ServiceName ServiceFileName AccountName risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS query to known phishing delivery domain | 100 | Confirmed IOC; immediate action required |
| Browser spawning RMM software | 90 | Strong social engineering indicator; browser should not launch RMM directly |
| RMM process running from %TEMP%, %APPDATA%, Downloads, or Desktop | 90 | Legitimate enterprise RMM is deployed to Program Files via GPO/MDM, not user-writable directories |
| New RMM service installed from non-Program Files path | 80-95 | Service installation from temp paths is a strong phishing-install indicator |
| RMM process running from outside Program Files (any path) | 80 | Warrants investigation of how/why it was installed |
| RMM process present with no asset in IT inventory | 55 | Requires CMDB/ITSM correlation; unenrolled RMM clients are unauthorized by default |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unattributed cybercrime (RMM phishing, Sep 2026) | [Microsoft Security Blog 2026-09-29](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/) |
| Tech support fraud operators (browser locker) | [Unit 42 2026-09-28](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel) |
| Kimsuky (DWAgent RMM abuse) | [MITRE ATT&CK G0094](https://attack.mitre.org/groups/G0094/) |
| UNC3944 / Scattered Spider (AnyDesk/TeamViewer) | [MITRE ATT&CK G1015](https://attack.mitre.org/groups/G1015/) |

## References

- [Microsoft Security Blog — Phishing Abuses RMM Tools (2026-09-29)](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/)
- [Unit 42 — Browser Locker Scareware leading to RMM abuse (2026-09-28)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel)
- [CISA Advisory AA23-025A — Malicious Use of Legitimate RMM Software](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a)
- [MITRE ATT&CK T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [Threat intel: threat-intel/2026-09-29_microsoft-security-blog-phishing-rmm-msp360-screenconnect.md]
- [Threat intel: threat-intel/2026-09-28_unit42-paloaltonetworks-cloud-hosted-browser-locker-scareware.md]
