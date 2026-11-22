# RRM Campaign FleetDeck and ScreenConnect Install via Fake PDF Reader MSI

## Description

Detects the RRM phishing campaign pattern where a fake PDF reader MSI installer silently deploys a FleetDeck or ScreenConnect remote management agent configured to an attacker-controlled management console. The installer is typically named `pdf_Reader_en_install.msi` (or similar PDF-reader lure names) and executes via msiexec. After installation the RMM agent runs as a Windows service, providing persistent remote access that blends with legitimate IT traffic.

**False positives:** Legitimate MSI deployments of FleetDeck or ScreenConnect by IT administrators. These should be installed from enterprise software distribution paths or with known management servers, not from user-writable directories or attacker infrastructure domains. Tune by excluding known-good management console hostnames and standard install paths under `%ProgramFiles%`.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Remote Access Software |
| Technique ID | T1219 |
| Secondary Tactic | Execution |
| Secondary Tactic ID | TA0002 |
| Secondary Technique | User Execution: Malicious File |
| Secondary Technique ID | T1204.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name="msiexec.exe"
    AND (Processes.process="*pdf*reader*install*"
      OR Processes.process="*pdf_reader*"
      OR Processes.process="*fleetdeck*"))
   OR (Processes.process_name IN ("FleetDeckAgent.exe","fleetdeck.exe","fleetdeck-agent.exe")
    AND (Processes.process_path="*\\AppData\\*"
      OR Processes.process_path="*\\Downloads\\*"
      OR Processes.process_path="*\\Temp\\*"
      OR Processes.process_path="*\\Users\\Public\\*"))
   OR (Processes.process_name="ScreenConnect.ClientService.exe"
    AND (Processes.process_path="*\\AppData\\*"
      OR Processes.process_path="*\\Downloads\\*"
      OR Processes.process_path="*\\Temp\\*"))
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)(pdf.*reader.*install|pdf_reader.*install)") AND process_name="msiexec.exe", 90,
    match(lower(process_name), "fleetdeck") AND match(process_path, "(?i)(appdata|downloads|\\\\temp\\\\|public)"), 85,
    match(process_name, "ScreenConnect.ClientService.exe") AND match(process_path, "(?i)(appdata|downloads|\\\\temp\\\\)"), 75,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process process_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| msiexec with PDF reader / FleetDeck keyword in command line | 90 | Near-certain campaign IOC; legitimate PDF readers are not MSI-distributed with these naming patterns |
| FleetDeck process running from AppData / Downloads / Temp / Public | 85 | FleetDeck should install to Program Files; user-writable path indicates unauthorized installation |
| ScreenConnect from AppData / Downloads / Temp | 75 | Legitimate ScreenConnect installs to Program Files; user-path execution indicates phishing deployment |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unattributed cybercrime (RRM campaign, November 2026) | [Unit 42 — RRM Packages Disguised as PDF Reader Software (2026-11-20)](https://unit42.paloaltonetworks.com/rrm-packages-pdf-reader-software/) |
| Unattributed cybercrime (RMM phishing, September 2026) | [Microsoft — Phishing Abuses RMM Tools (2026-09-29)](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/) |

## References

- [Unit 42 — RRM Packages Disguised as PDF Reader Software (2026-11-20)](https://unit42.paloaltonetworks.com/rrm-packages-pdf-reader-software/)
- [MITRE ATT&CK T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [CISA — Protecting Against Malicious Use of Remote Monitoring and Management Software](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a)
- Related detection: `phishing_deployed_unauthorized_rmm_software.md` (broader RMM phishing coverage)
