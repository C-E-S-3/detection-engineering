# UNC7017 AOMEI Backupper Trojanized Installer Execution (CROSSROAD/SHINYROAD)

## Description

Detects AOMEI Backupper backup software spawning unexpected child processes, which is the primary behavioral signal for UNC7017's ephemeral supply chain tampering campaign (April–July 2026). In the attack chain, a tampered AOMEI Backupper update delivers the CROSSROAD downloader, which runs as a child of the backup software process and proceeds to load SHINYROAD backdoor via the Adaptix C2 framework.

Legitimate AOMEI Backupper child processes are limited to its own binaries and Windows error reporting components. Any interpreter, scripting engine, LOLBin, or administrative tool spawned by AOMEI parent processes is anomalous.

**False positive sources:** Custom post-backup scripts invoking cmd.exe from AOMEI task automation (rare; verify against scheduled task configurations). Exclude known-good wrapper scripts if encountered.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Primary Tactic | Execution (TA0002) |
| Primary Technique | T1204.002 — User Execution: Malicious File |
| Secondary Tactic | Initial Access (TA0001) |
| Secondary Technique | T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain |
| Sub-technique | — |

## Lockheed Martin Kill Chain Phase

Exploitation, Delivery

## Splunk SPL Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN (
      "AomeiBackupper.exe","ABService.exe","AomeiBackupperBoot.exe",
      "AomeiBackupperPortable.exe")
    AND NOT Processes.process_name IN (
      "AomeiBackupper.exe","ABService.exe","AomeiBackupperBoot.exe",
      "AomeiBackupperPortable.exe","AomeiMBRFix.exe",
      "conhost.exe","WerFault.exe","werfault.exe","WerFaultSecure.exe",
      "dllhost.exe","SearchProtocolHost.exe","SearchFilterHost.exe",
      "svchost.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.parent_process Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)(powershell\.exe|pwsh\.exe|wscript\.exe|cscript\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe)"), 85,
    match(process_name,"(?i)(certutil\.exe|bitsadmin\.exe|wmic\.exe|msiexec\.exe|installutil\.exe|cmstp\.exe|odbcconf\.exe)"), 80,
    match(process_name,"(?i)(cmd\.exe)"), 70,
    match(process_name,"(?i)(schtasks\.exe|sc\.exe|reg\.exe|net\.exe|net1\.exe|at\.exe)"), 65,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime dest user parent_process_name parent_process process_name process process_id risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 85 | Scripting engine or proxy execution LOLBin spawned by AOMEI (highest confidence CROSSROAD behavior) |
| 80 | Download/execution utility spawned by AOMEI (certutil, bitsadmin, msiexec, installutil) |
| 70 | cmd.exe spawned by AOMEI |
| 65 | Persistence/discovery tools spawned by AOMEI (schtasks, sc, reg, net) |
| 55 | Any other unexpected child process |

Threshold set at 55 to catch all unexpected children. Tune the exclusion list based on observed legitimate behavior in your environment.

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| **UNC7017** | Suspected nation-state-aligned; tampered AOMEI Technology update infrastructure during 5–10 minute windows; April–July 2026; delivers CROSSROAD downloader → SHINYROAD backdoor → ADAPTAGENT |

## References

- https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering
- https://attack.mitre.org/techniques/T1195/002/
- https://attack.mitre.org/techniques/T1204/002/
- `threat-intel/2026-10-16_cloud-google-com-blog-topics-threat-intelligence-investigating-ephemeral-supply-chain-tampering.md`
