# OWAReaper — Exchange OWA JavaScript Webshell Persistence

## Description

Detects server-side JavaScript implant deployment to Microsoft Exchange Outlook Web Access (OWA) application directories, consistent with the OWAReaper technique attributed to TA488 (Laundry Bear / Void Blizzard) exploiting CVE-2026-42897. The technique writes a JavaScript backdoor into Exchange OWA's server-side application files, where it executes in the context of every OWA page render and persists across credential rotations and endpoint reimaging.

Key detection signals are unexpected file creation or modification within Exchange OWA application directories (typically under `%ExchangeInstallPath%\FrontEnd\HttpProxy\owa\` or `%ExchangeInstallPath%\ClientAccess\owa\`) by IIS worker processes or their children, and unusual outbound HTTP POST requests originating from Exchange processes to non-Microsoft destinations.

False positives include legitimate Exchange cumulative updates modifying OWA files (file operations performed by `msiexec.exe`, `Setup.exe`, or Exchange setup routines), Exchange add-in deployments, and authorized OWA customization by Exchange administrators. Tune by excluding known update/patch windows and the Exchange setup process parent chain.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Server Software Component: Web Shell |
| Technique ID | T1505.003 |

Secondary: T1190 (Exploit Public-Facing Application — CVE-2026-42897 initial delivery), T1185 (Browser Session Hijacking), T1114 (Email Collection), T1539 (Steal Web Session Cookie), T1041 (Exfiltration Over C2 Channel)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where
    (Filesystem.file_path="*\\FrontEnd\\HttpProxy\\owa\\*"
     OR Filesystem.file_path="*\\ClientAccess\\owa\\*"
     OR Filesystem.file_path="*\\inetpub\\wwwroot\\owa\\*")
    AND (Filesystem.file_name="*.js" OR Filesystem.file_name="*.aspx" OR Filesystem.file_name="*.htm*")
    AND Filesystem.action IN ("created", "modified")
  by Filesystem.dest Filesystem.user Filesystem.process_name
     Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="w3wp.exe", 90,
    process_name="cmd.exe" OR process_name="powershell.exe", 95,
    true(), 75
  )
| where risk_score >= 75
| table dest user process_name file_path file_name firstTime lastTime risk_score count
```

## Supplemental Query — Unusual Outbound HTTP from Exchange Processes

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where
    All_Traffic.app IN ("http", "https", "ssl")
    AND All_Traffic.src_category="exchange_server"
    AND NOT All_Traffic.dest_host IN ("*.microsoft.com", "*.office.com", "*.office365.com",
                                       "*.live.com", "*.microsoftonline.com", "*.windows.net",
                                       "*.outlook.com", "*.protection.outlook.com",
                                       "*.symantec.com", "*.symcb.com", "*.digicert.com",
                                       "*.crl.microsoft.com", "ocsp.msocsp.com")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.dest_host
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest_port IN (80, 8080), 85,
    dest_port=443, 75,
    true(), 80
  )
| where risk_score >= 75
| table src dest dest_host dest_port firstTime lastTime risk_score count
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | OWA directory file write by `cmd.exe` or `powershell.exe` (strong indicator of post-exploitation shell) |
| 90 | OWA directory file write by `w3wp.exe` (IIS worker — expected process for serving OWA but not for file creation during normal operation) |
| 85 | Outbound HTTP (port 80/8080) from Exchange server to non-Microsoft destination |
| 75 | Outbound HTTPS from Exchange server to non-Microsoft destination / other OWA file write by unlisted process |

Alert at 75 or higher. Combine both queries for correlation: a host that appears in both queries in the same 1-hour window should be escalated immediately as a likely OWAReaper deployment.

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| TA488 / Laundry Bear / Void Blizzard | SVR-linked Russia-nexus actor; OWAReaper JavaScript implant via CVE-2026-42897; infrastructure created March 2026 — two months before Microsoft's May 14, 2026 patch; targets US/EU government, telco, financial, hospitality, aerospace |

## References

- [Proofpoint — OWAReaper: TA488 Exchange OWA Persistent JavaScript Implant (2026-07-29)](https://www.proofpoint.com/us/blog/threat-insight/owareaper-ta488-exchange-owa-persistent-javascript-implant)
- [BleepingComputer — Russian hackers use OWAReaper backdoor to spy on Exchange email servers (2026-07-29)](https://www.bleepingcomputer.com/news/security/russian-hackers-use-owareaper-backdoor-to-spy-on-exchange-email-servers/)
- [NVD — CVE-2026-42897](https://nvd.nist.gov/vuln/detail/CVE-2026-42897)
- [MITRE ATT&CK — T1505.003: Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
