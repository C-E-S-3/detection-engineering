# APT28 BeardShell filen.io Cloud Storage C2 (Operation Neusploit)

## Description

Detects APT28 BeardShell C2 activity abusing filen.io's legitimate cloud storage HTTPS API for bidirectional command-and-control, as documented in Operation Neusploit (Trellix / Zscaler, 2026). BeardShell, injected into `explorer.exe`, and the accompanying CovenantGrunt implant communicate exclusively via filen.io API endpoints, making C2 traffic indistinguishable from normal cloud storage use without process-level correlation. False positives may include legitimate use of the filen.io desktop or mobile client; correlate with parent process and injection indicators to reduce noise. Also detects NotDoor, the Outlook COM add-in backdoor used for persistence, via Outlook spawning unusual child processes.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service: Bidirectional Communication |
| Technique ID | T1102.002 |

Secondary techniques covered:
- T1055 — Process Injection (BeardShell into explorer.exe)
- T1137.006 — Office Application Startup: Office Add-ins (NotDoor Outlook COM add-in)
- T1566.001 — Phishing: Spearphishing Attachment (delivery vector)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.dest_host="api.filen.io" OR All_Traffic.dest_host="*.filen.io")
    AND NOT (All_Traffic.process IN ("filen*","filen-desktop*","filen-sync*","chrome.exe","firefox.exe","msedge.exe","safari"))
  by All_Traffic.src_ip All_Traffic.dest_host All_Traffic.dest_port All_Traffic.process
     All_Traffic.app All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process="explorer.exe", 95,
    process="OUTLOOK.EXE" OR process="outlook.exe", 85,
    NOT match(process, "(?i)(filen|browser|chrome|firefox|edge|safari|teams|slack)"), 80,
    1=1, 50)
| where risk_score >= 80
| table firstTime lastTime src_ip dest_host dest_port process app bytes_out risk_score
```

### Supplemental: NotDoor Outlook COM Add-in Spawning Unusual Children

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("OUTLOOK.EXE","outlook.exe")
    AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe",
                                    "rundll32.exe","regsvr32.exe","curl.exe","certutil.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)(powershell|wscript|cscript|mshta)"), 90,
    match(process_name, "(?i)(cmd|rundll32|regsvr32|curl|certutil)"), 80,
    1=1, 65)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Supplemental: APT28 Operation Neusploit Infrastructure DNS IOC

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("wellnesscaremed.com","freefoodaid.com","wellnessmedcare.org")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query answer risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| explorer.exe connecting to api.filen.io | 95 | Critical — BeardShell injection into explorer.exe using filen.io C2 |
| OUTLOOK.EXE connecting to api.filen.io | 85 | High — CovenantGrunt/NotDoor C2 via Outlook process |
| Any non-browser process connecting to filen.io | 80 | High — filen.io has minimal legitimate non-browser usage enterprise-wide |
| Outlook spawning PowerShell/wscript/mshta | 90 | Critical — NotDoor COM add-in command execution |
| DNS resolution of known APT28 infrastructure | 95 | Critical — direct IOC match to confirmed APT28 C2 domains |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| APT28 (Fancy Bear / Forest Blizzard / GRU Unit 26165) | [MITRE ATT&CK G0007](https://attack.mitre.org/groups/G0007/) |

## References

- [Trellix — Operation Neusploit (2026-02)](https://www.trellix.com/blogs/research/operation-neusploit-apt28-office-ole-bypass/)
- [Zscaler ThreatLabz — APT28 BeardShell Campaign](https://www.zscaler.com/blogs/security-research/apt28-beardshell-filen-io-c2)
- [Threat Intel Report — 2026-10-05_trellix-apt28-operation-neusploit-cve-2026-21509-beardshell.md](../../../threat-intel/2026-10-05_trellix-apt28-operation-neusploit-cve-2026-21509-beardshell.md)
- [MITRE ATT&CK G0007 — APT28](https://attack.mitre.org/groups/G0007/)
- [MITRE ATT&CK T1102.002 — Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
