# Veeam Agent for Windows gRPC Named Pipe LPE (CVE-2026-32996)

## Description

Detects local privilege escalation exploitation of CVE-2026-32996 in Veeam Agent for Microsoft Windows (≤ v13.0.1.2067). The vulnerability allows any low-privileged local user to send privileged gRPC control messages over the named pipe `\\.\pipe\Veeam\VAW\ServiceConnectionPipe`, causing `VeeamAgentSvc.exe` (running as SYSTEM) to execute attacker-controlled operations.

Post-exploitation indicators include `VeeamAgentSvc.exe` spawning interactive shells (`cmd.exe`, `powershell.exe`) or system management utilities as SYSTEM, and unexpected processes opening the Veeam named pipe.

Observed exploitation context: ransomware intrusion chains (post-initial-access foothold on backup servers) where attackers escalate to SYSTEM to disable backup jobs and destroy recovery points before deploying ransomware.

**False positives:** Veeam management consoles and legitimate backup administrators performing break-glass recovery may spawn elevated processes from Veeam services. Tune by excluding known Veeam administrative hosts and scheduled maintenance windows.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation |
| Tactic ID | TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |

Secondary tactics: Impact (TA0040) — T1490 Inhibit System Recovery (backup destruction observed in exploitation chains)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

### Query 1 — VeeamAgentSvc Spawning Interactive Shell (High Confidence)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name="VeeamAgentSvc.exe"
        Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                                    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
                                    "certutil.exe", "bitsadmin.exe", "msiexec.exe")
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)(cmd\.exe|powershell\.exe|pwsh\.exe)"), 90,
    match(process_name, "(?i)(mshta\.exe|wscript\.exe|cscript\.exe)"), 85,
    match(process_name, "(?i)(rundll32\.exe|regsvr32\.exe|msiexec\.exe)"), 80,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id parent_process_id risk_score
```

### Query 2 — Named Pipe Access to Veeam Service Connection Pipe (Medium Confidence)

```spl
index=wineventlog EventCode=4656
    Object_Name="\\.\pipe\Veeam\VAW\ServiceConnectionPipe"
| eval suspicious=if(
    NOT match(Account_Name, "(?i)(SYSTEM|veeam|VeeamBackup)"),
    1, 0)
| where suspicious=1
| stats count min(_time) as firstTime max(_time) as lastTime
    by host Account_Name Account_Domain Object_Name Process_Name Process_ID
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(Account_Name, "(?i)(guest|anonymous)"), 90,
    1=1, 65)
| where risk_score >= 50
| table firstTime lastTime host Account_Name Account_Domain Object_Name Process_Name Process_ID risk_score
```

*Note: Query 2 requires Windows Security audit policy — Object Access → Audit File System or Audit Handle Manipulation — with the Veeam pipe path added to the SACL. Enable via Group Policy: Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy.*

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| VeeamAgentSvc.exe spawns cmd.exe / powershell.exe / pwsh.exe | 90 | Near-certain exploitation — Veeam agent service has no legitimate reason to spawn interactive shells |
| VeeamAgentSvc.exe spawns mshta.exe / wscript.exe / cscript.exe | 85 | Script host launch from backup service is highly anomalous |
| VeeamAgentSvc.exe spawns rundll32.exe / regsvr32.exe / msiexec.exe | 80 | LOLBins launched from SYSTEM-level backup service — suspicious |
| Any VeeamAgentSvc.exe unexpected child process | 75 | Baseline alert for analyst review |
| Named pipe access by non-Veeam account | 65 | Reconnaissance or exploitation attempt requiring investigation |
| Named pipe access by Guest / Anonymous | 90 | Definitive exploitation attempt |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Multiple ransomware operators (active exploitation Sep 2026) | [Arctic Wolf CVE-2026-32996 advisory](https://arcticwolf.com/resources/blog/) |
| Unknown (CISA KEV confirmed active exploitation, Sep 21 2026) | [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| LockBit / Gold Mystic affiliates | [MITRE ATT&CK — LockBit (S1091)](https://attack.mitre.org/software/S1091/) — known for pre-ransomware backup destruction via Veeam |

## References

- [Veeam KB4650 — CVE-2026-32996 Security Patch](https://www.veeam.com/kb4650)
- [CISA KEV — CVE-2026-32996 (added 2026-09-21)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Arctic Wolf — Active Exploitation Advisory](https://arcticwolf.com/resources/blog/)
- [MITRE ATT&CK T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
