# SCKit RelayTrap — RMM Session Cookie Theft via ScreenConnect Technician Session Interception

## Description

Detects SCKit malware deployment and RelayTrap behavior in which attackers abuse ConnectWise ScreenConnect's Run Command feature to silently install a rogue MSI package that replaces the legitimate ScreenConnect Guest client with a malicious interceptor. RelayTrap hijacks incoming technician support sessions to scan browser credential stores and process memory for authenticated MSP management console session cookies. Approximately 288 endpoints across 48 organizations were compromised in the November 2026 campaign within a 90-minute window. The technique specifically targets IT technicians to pivot from a single managed endpoint to an entire MSP customer portfolio.

False positives: Legitimate silent MSI deployments via ScreenConnect Run Command; IT teams deploying software through RMM. The specific combination of ScreenConnect spawning msiexec with `/quiet` from Windows\TEMP is unusual in well-managed environments but may occur in automated patching workflows.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Steal Web Session Cookie |
| Technique ID | T1539 |

Secondary techniques: T1218.007 (Msiexec signed binary proxy), T1554 (Compromise Host Software Binary — RelayTrap replaces ScreenConnect Guest), T1072 (Software Deployment Tools — ScreenConnect Run Command abuse).

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

**Rule 1 — ScreenConnect Spawning Silent MSI Install from TEMP**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ScreenConnectClient.exe")
  AND Processes.process_name="msiexec.exe"
  AND (Processes.process="*/quiet*" OR Processes.process="*/qn*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(lower(process), "windows\\\\temp"), 90,
    match(lower(process), "appdata\\\\local\\\\temp"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Rule 2 — MSI Dropped to Windows\TEMP by RMM Process**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="*.msi"
  AND (Filesystem.file_path="*\\Windows\\TEMP\\*" OR Filesystem.file_path="*\\Windows\\Temp\\*")
  AND Filesystem.process_name IN ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ScreenConnectClient.exe", "cmd.exe", "powershell.exe", "curl.exe", "bitsadmin.exe")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name, "^sc\.msi$"), 95,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

**Rule 3 — ScreenConnect Process Reading Browser Credential Storage (RelayTrap Behavior)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.process_name IN ("ScreenConnect.ClientService.exe", "ScreenConnect.WindowsClient.exe", "ScreenConnectClient.exe", "sc.exe")
  AND (Filesystem.file_path="*\\Chrome\\User Data\\Default\\Login Data*"
    OR Filesystem.file_path="*\\Edge\\User Data\\Default\\Login Data*"
    OR Filesystem.file_path="*\\Firefox\\Profiles\\*\\logins.json*"
    OR Filesystem.file_path="*\\Cookies*"
    OR Filesystem.file_path="*\\Network\\Cookies*")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| ScreenConnect spawning msiexec /quiet from C:\Windows\TEMP | 90 | Strongly anomalous; legitimate RMM deployments typically use vendor-signed paths |
| ScreenConnect spawning msiexec /quiet from AppData\Temp | 85 | Suspicious; possible SCKit staging from download directory |
| MSI named exactly `sc.msi` dropped to Windows\TEMP | 95 | Matches specific SCKit observed filename; near-certain indicator |
| ScreenConnect process reading browser credential/cookie stores | 100 | RelayTrap behavior; no legitimate RMM scenario involves browser credential access |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| SCKit campaign operators (unattributed) | [Microsoft Security Blog — SCKit (Nov 13, 2026)](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/) |

## References

- [Microsoft Security Blog — SCKit abuses ScreenConnect to deploy remote access and target technician sessions (Nov 13, 2026)](https://www.microsoft.com/en-us/security/blog/2026/11/13/sckit-abuses-screenconnect-deploy-remote-access-target-technician-sessions/)
- [BleepingComputer — New worm-like 'SCKit' malware targets MSPs in ScreenConnect attacks](https://www.bleepingcomputer.com/news/security/new-worm-like-sckit-malware-targets-msps-in-screenconnect-attacks/)
- [Lavx News — SCKit malware turns ScreenConnect support sessions into attack paths for MSPs](https://news.lavx.hu/article/sckit-malware-turns-screenconnect-support-sessions-into-attack-paths-for-msps)
- [MITRE ATT&CK — T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK — T1554 Compromise Host Software Binary](https://attack.mitre.org/techniques/T1554/)
