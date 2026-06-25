# Mistic Backdoor / KongTuke DLL Side-Loading and Credential Harvesting

## Description

Detects deployment and operation of the Mistic backdoor (also called MTLBackdoor) by the KongTuke financially-motivated access broker, which sells access to ransomware affiliates. First publicly reported June 24, 2026.

KongTuke uses a multi-stage infection chain: (1) Microsoft Teams ClickFix social engineering lure directs victims to paste a Base64-encoded command into a terminal; (2) ModeloRAT is deployed as an initial implant; (3) Mistic is installed via DLL side-loading using a legitimate Microsoft Defender component (MpExtMs.exe) to load a malicious version.dll, which in turn loads the Mistic core as EndpointDlp.dll — a filename chosen to mimic Microsoft's legitimate endpoint DLP component; (4) A companion .NET DLL renders fake login/MFA prompts to harvest credentials; (5) Mistic executes payloads in-memory via Beacon Object Files (BOF), leaving no disk artifacts. A self-deletion kill switch allows the operator to remove all traces.

Detection prioritizes: (1) MpExtMs.exe executing from non-standard paths; (2) version.dll loaded by MpExtMs.exe from outside System32; (3) EndpointDlp.dll created or loaded outside the MDATP install path; (4) outbound network connections from MpExtMs.exe; (5) Teams/browser spawning PowerShell with Base64-encoded commands (ClickFix delivery).

False positive sources: Microsoft Defender for Endpoint updates occasionally modify the location of legitimate MpExtMs.exe. Verify file path, parent process, and signature before escalation. Base64-encoded PowerShell from Teams occurs in IT automation workflows.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Hijack Execution Flow: DLL Side-Loading |
| Technique ID | T1574.002 |
| Secondary Tactic | Credential Access |
| Secondary Technique | T1056.004 — Input Capture: Credential API Hooking |
| Secondary Tactic | Initial Access |
| Secondary Technique | T1566.002 — Phishing: Spearphishing Link (Teams ClickFix) |
| Secondary Tactic | Command and Control |
| Secondary Technique | T1071.001 — Application Layer Protocol: Web Protocols |
| Secondary Tactic | Defense Evasion |
| Secondary Technique | T1070.004 — Indicator Removal: File Deletion (self-delete kill switch) |
| Secondary Tactic | Execution |
| Secondary Technique | T1055 — Process Injection (in-memory BOF execution) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Installation |
| Command and Control |
| Actions on Objectives |

## Splunk Detection Query

```spl
| comment "Query 1: MpExtMs.exe loaded version.dll from non-System32 path (core Mistic sideload signal)"
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=7
Image="*\\MpExtMs.exe"
ImageLoaded="*\\version.dll"
NOT ImageLoaded IN ("C:\\Windows\\System32\\version.dll","C:\\Windows\\SysWOW64\\version.dll")
| stats count min(_time) as firstTime max(_time) as lastTime by Computer Image ImageLoaded Signed SignatureStatus
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(Signed="false" OR Signed="FALSE", 98, 1=1, 93)
| table firstTime lastTime Computer Image ImageLoaded Signed SignatureStatus risk_score
```

```spl
| comment "Query 2: EndpointDlp.dll outside MDATP install path (Mistic core DLL artifact)"
index=endpoint (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode IN (7,11))
(ImageLoaded="*\\EndpointDlp.dll" OR TargetFilename="*\\EndpointDlp.dll")
NOT (ImageLoaded IN ("C:\\Program Files\\Windows Defender\\*","C:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\*")
  OR TargetFilename IN ("C:\\Program Files\\Windows Defender\\*","C:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\*"))
| stats count min(_time) as firstTime max(_time) as lastTime by Computer EventCode Image ImageLoaded TargetFilename Signed
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime Computer EventCode Image ImageLoaded TargetFilename Signed risk_score
```

```spl
| comment "Query 3: MpExtMs.exe outbound network connection (Mistic C2 beaconing)"
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3
Image="*\\MpExtMs.exe"
NOT (DestinationPort IN (135,445,389,636,88,53))
| stats count min(_time) as firstTime max(_time) as lastTime by Computer Image DestinationIp DestinationPort Initiated Protocol
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(DestinationPort IN (80,443,8080,8443), 90, 1=1, 85)
| table firstTime lastTime Computer Image DestinationIp DestinationPort Protocol risk_score
```

```spl
| comment "Query 4: ClickFix delivery via Teams — Base64-encoded command execution"
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
ParentImage IN ("*\\Teams.exe","*\\msedge.exe","*\\chrome.exe","*\\msedgewebview2.exe","*\\firefox.exe")
Image IN ("*\\powershell.exe","*\\pwsh.exe","*\\cmd.exe","*\\mshta.exe","*\\wscript.exe","*\\cscript.exe")
(CommandLine="*-enc *" OR CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64String*")
| stats count min(_time) as firstTime max(_time) as lastTime by Computer ParentImage Image CommandLine User
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(match(CommandLine,"(?i)MpExtMs|EndpointDlp|version\.dll"), 95, 1=1, 80)
| table firstTime lastTime Computer User ParentImage Image CommandLine risk_score
```

```spl
| comment "Query 5: Composite — DLL sideload followed by C2 connection from MpExtMs.exe (30-minute window)"
| tstats `security_content_summariesonly` count min(_time) as sideload_time
  from datamodel=Endpoint.Processes
  where Processes.process_name="MpExtMs.exe"
  by Processes.dest Processes.user
| rename Processes.* AS *
| join dest [
  | tstats `security_content_summariesonly` count min(_time) as c2_time
    from datamodel=Network_Traffic
    where All_Traffic.app="MpExtMs.exe"
    by All_Traffic.dest_ip All_Traffic.src
  | rename All_Traffic.* AS *, src AS dest
]
| eval delta_minutes = round((c2_time - sideload_time)/60,1)
| where delta_minutes >= 0 AND delta_minutes <= 30
| eval risk_score=95
| table dest user sideload_time c2_time delta_minutes risk_score
```

## Wazuh Detection Coverage

| Rule ID | Description | Severity |
|---------|-------------|----------|
| 103590 | MpExtMs.exe executed from non-standard path | 9 (Medium) |
| 103591 | version.dll loaded by MpExtMs.exe from non-System32 path | 14 (Critical) |
| 103592 | EndpointDlp.dll created/accessed outside MDATP directory | 13 (Critical) |
| 103593 | MpExtMs.exe initiated outbound network connection | 14 (Critical) |
| 103594 | Correlated: DLL sideload + C2 connection within 5 minutes | 15 (Critical) |
| 103595 | Child process creation from MpExtMs.exe (fake UI or payload) | 12 (High) |
| 103596 | Teams/browser spawned PowerShell with Base64 command (ClickFix) | 11 (High) |
| 103597 | MpExtMs.exe spawned file deletion command (self-delete kill switch) | 13 (Critical) |
| 103598 | Unsigned DLL loaded by MpExtMs.exe | 12 (High) |
| 103599 | Known Mistic filename written to disk outside MDATP path | 11 (High) |

## Risk Score Logic

- **98**: version.dll sideloaded by MpExtMs.exe with unsigned DLL — near-certain Mistic deployment
- **95**: Composite sideload + C2 connection, or ClickFix delivery executing Mistic filenames
- **93**: version.dll sideloaded by MpExtMs.exe (signed status unknown)
- **90**: MpExtMs.exe outbound on port 80/443 (HTTPS C2 beaconing typical)
- **85**: MpExtMs.exe network connection on non-standard port
- **80**: ClickFix Base64 delivery without Mistic-specific filenames

## Associated Threat Actors

| Actor | Role |
|-------|------|
| KongTuke | Access broker; deploys Mistic for ransomware affiliate access |
| Unknown ransomware affiliates | End consumers of KongTuke-brokered access |

Target sectors: Insurance, Education, IT, Professional Services (as of June 2026 reporting)

## References

- BleepingComputer: "Stealthy Mistic Backdoor Linked to Ransomware Access Broker KongTuke" (2026-06-24)
- MITRE ATT&CK T1574.002: https://attack.mitre.org/techniques/T1574/002/
- MITRE ATT&CK T1056.004: https://attack.mitre.org/techniques/T1056/004/
- MITRE ATT&CK T1566.002: https://attack.mitre.org/techniques/T1566/002/
