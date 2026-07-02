# ScreenConnect DLL Sideloading Leading to AsyncRAT Deployment

## Description

Detects trojanized ScreenConnect (ConnectWise Control) installers distributed via SEO-poisoned software download sites that use DLL sideloading to deploy AsyncRAT. Attackers place a malicious DLL in the ScreenConnect installation directory; when the legitimate ScreenConnect executable loads, it sideloads the malicious DLL (T1574.002), which then spawns AsyncRAT via process hollowing (T1055.012) into a host Windows process.

The primary detection focuses on ScreenConnect client processes spawning command interpreters or living-off-the-land binaries — behavior that has no legitimate purpose in normal ScreenConnect operation. A secondary rule detects network connections to known campaign infrastructure from these processes.

**False positives:** Legitimate ScreenConnect remote support sessions where a support technician manually opens a terminal on the remote machine will generate ScreenConnect→cmd.exe spawn events. Validate against ScreenConnect session logs and user context.

Known malicious software distribution domains for this campaign: `vlc-media[.]com`, `studio-obs[.]net`, `kms-tools[.]com`, `crosshairx[.]pro`, `fileget[.]loseyourip[.]com`.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion (TA0005) |
| Technique | Hijack Execution Flow: DLL Side-Loading (T1574.002) |
| Technique | Process Injection: Process Hollowing (T1055.012) |
| Secondary Tactic | Execution (TA0002) |
| Secondary Technique | Command and Scripting Interpreter: PowerShell (T1059.001) |

## Lockheed Martin Kill Chain

| Field | Value |
|-------|-------|
| Phase | Installation |

## Splunk Detection Query

### Rule 1 — ScreenConnect Spawning Command Interpreter (High Confidence)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN (
    "ScreenConnect.ClientService.exe",
    "ScreenConnect.WindowsClient.exe",
    "ConnectWiseControl.ClientService.exe",
    "connectwisecontrol.clientservice.exe")
    AND Processes.process_name IN (
    "powershell.exe","cmd.exe","wscript.exe","cscript.exe",
    "mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("powershell.exe","mshta.exe","wscript.exe","cscript.exe"), 85,
    process_name IN ("cmd.exe"), 75,
    process_name IN ("rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe"), 90,
    true(), 70)
| where risk_score >= 70
| table dest user parent_process_name process_name process risk_score firstTime lastTime
```

### Rule 2 — Known Campaign Payload Delivery Domain (Critical — IOC Match)

```spl
`dns` query IN (
  "vlc-media.com","studio-obs.net","kms-tools.com",
  "crosshairx.pro","fileget.loseyourip.com")
| stats count min(_time) as firstTime max(_time) as lastTime by src query
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table src query risk_score firstTime lastTime
```

### Rule 3 — Unusual Module Load from User-Writable Path by ScreenConnect (Sysmon Required)

```spl
`sysmon` EventCode=7
  ImageLoaded="*\\Users\\*" OR ImageLoaded="*\\AppData\\*" OR ImageLoaded="*\\Temp\\*"
  Image IN (
    "*\\ScreenConnect.ClientService.exe",
    "*\\ScreenConnect.WindowsClient.exe",
    "*\\ConnectWiseControl.ClientService.exe")
| stats count by Computer User Image ImageLoaded Signed SignatureStatus
| where Signed=false OR SignatureStatus != "Valid"
| table _time Computer User Image ImageLoaded Signed SignatureStatus
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | DNS/connection to known SEO-poisoned distribution domain |
| 90 | ScreenConnect spawning certutil, bitsadmin, regsvr32, or rundll32 |
| 85 | ScreenConnect spawning PowerShell, mshta, wscript, or cscript |
| 75 | ScreenConnect spawning cmd.exe |
| 70 | Any other suspicious child process from ScreenConnect |

## Associated Threat Actors

| Actor | Reference |
|-------|-----------|
| Unknown (SEO-poisoned software campaign, July 2026) | [The Hacker News — ScreenConnect AsyncRAT (2026-07-01)](https://thehackernews.com/2026/07/seo-poisoned-software-sites-distribute-screenconnect-asyncrat.html) |
| Scattered Spider / UNC3944 | [MITRE ATT&CK — Scattered Spider (G1015)](https://attack.mitre.org/groups/G1015/) — known AsyncRAT users |

## References

- [The Hacker News — SEO-Poisoned Sites: ScreenConnect + AsyncRAT (2026-07-01)](https://thehackernews.com/2026/07/seo-poisoned-software-sites-distribute-screenconnect-asyncrat.html)
- [MITRE ATT&CK — T1574.002: Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1055.012: Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK — T1608.006: Stage Capabilities: SEO Poisoning](https://attack.mitre.org/techniques/T1608/006/)
- [ConnectWise ScreenConnect — Legitimate RMM Tool](https://www.connectwise.com/platform/unified-management/control)
