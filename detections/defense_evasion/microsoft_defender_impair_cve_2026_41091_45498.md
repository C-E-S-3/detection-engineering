# Microsoft Defender Impairment via CVE-2026-41091 (EoP) and CVE-2026-45498 (DoS) — BlueHammer

## Description

Detects active exploitation of two Microsoft Defender vulnerabilities added to CISA's KEV catalog on May 20, 2026, observed together in the **BlueHammer** campaign cluster tracked by Huntress.

**CVE-2026-41091** (CVSS 7.8): A privilege escalation vulnerability in the Microsoft Malware Protection Engine (`mpengine.dll`). The engine improperly resolves filesystem links (symlinks, junctions) before accessing files during a scan. A local attacker with standard user privileges can exploit this to gain a SYSTEM-level arbitrary file write primitive when Defender scans a crafted path. The practical result is full SYSTEM access from a low-privileged account without triggering normal escalation events.

**CVE-2026-45498** (CVSS 4.0): A denial-of-service vulnerability in the Microsoft Defender Antimalware Platform that crashes or stops real-time protection, creating an unmonitored window for payload deployment. This is typically used as a pre-step to CVE-2026-41091 or before deploying additional malware.

**BlueHammer** simultaneously targets a third Defender-adjacent CVE (CVE-2026-33825), suggesting a systematic effort to dismantle Windows Defender as a pre-ransomware disarmament step.

**False positives (Defender service stop):** Legitimate administrative operations or Windows Update cycles that stop/restart Defender services. Correlate with change management windows and administrative accounts. Unexpected service crashes (Event 7034) are high-confidence.

**False positives (Defender child processes):** Legitimate Defender operations that spawn helper utilities. The process_name allowlist in the SPL filters known-good Defender subprocesses; review any remaining findings against patch level.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Impair Defenses: Disable or Modify Tools |
| Technique ID | T1562.001 |
| Secondary Tactic | Privilege Escalation |
| Secondary Tactic ID | TA0004 |
| Secondary Technique | Exploitation for Privilege Escalation |
| Secondary Technique ID | T1068 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

### Query 1 — Unexpected Process Spawned by Defender Engine with SYSTEM Privileges

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("MsMpEng.exe","msmpeng.exe","MpCmdRun.exe")
  AND Processes.user="NT AUTHORITY\\SYSTEM"
  AND NOT Processes.process_name IN ("MsMpEng.exe","msmpeng.exe","MpCmdRun.exe",
      "NisSrv.exe","MpUXSrv.exe","MpDlpCmd.exe","mpengcpyreg.exe","MpSigStub.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)(cmd\.exe|powershell\.exe|pwsh)"), 95,
    match(process_name,"(?i)(wscript\.exe|cscript\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe)"), 90,
    match(process_name,"(?i)(net\.exe|net1\.exe|whoami\.exe|certutil\.exe)"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

### Query 2 — Defender Service Crash or Unexpected Stop (CVE-2026-45498 Indicator)

```spl
index=wineventlog source="WinEventLog:System"
(EventCode=7034 OR EventCode=7036)
(Service_Name IN ("WinDefend","WdNisSvc","Sense","WdFilter","WdNisDrv")
 OR Message="*Windows Defender*" OR Message="*Microsoft Defender*")
| eval service_state=case(
    EventCode=7034, "crashed_unexpectedly",
    EventCode=7036 AND match(Message,"(?i)stopped"), "stopped",
    1=1, "other")
| eval risk_score=case(
    EventCode=7034, 90,
    EventCode=7036 AND service_state="stopped" AND Service_Name="WinDefend", 80,
    1=1, 50)
| where risk_score >= 80
| `security_content_ctime(_time)`
| table _time host EventCode Service_Name service_state risk_score
```

### Query 3 — Windows Security Event 4688: High-Privilege Shell from Defender Parent

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4688
Creator_Process_Name IN ("*\\MsMpEng.exe","*\\MpCmdRun.exe","*\\msmpeng.exe")
(New_Process_Name="*\\cmd.exe" OR New_Process_Name="*\\powershell.exe" OR New_Process_Name="*\\pwsh.exe")
| eval risk_score=95
| `security_content_ctime(_time)`
| table _time host Creator_Process_Name New_Process_Name Process_Command_Line risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| cmd.exe/PowerShell spawned by Defender engine as SYSTEM | 95 | Defender engine (CVE-2026-41091) being used as SYSTEM-level shell launcher; extremely high confidence |
| LOLBin (wscript, mshta, regsvr32) spawned by Defender engine as SYSTEM | 90 | Classic post-exploitation proxy execution via Defender engine privilege |
| net.exe/whoami spawned by Defender engine as SYSTEM | 85 | Discovery/enumeration using Defender engine SYSTEM context |
| Defender service crashed (Event 7034) | 90 | Unexpected crash strongly indicates DoS exploitation (CVE-2026-45498) |
| WinDefend service stopped (Event 7036) | 80 | Unexpected stop may be CVE-2026-45498 or administrative action; correlate with change window |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| BlueHammer (unattributed cluster) | [Help Net Security — CVE-2026-41091 and CVE-2026-45498](https://www.helpnetsecurity.com/2026/05/21/microsoft-defender-vulnerabilities-cve-2026-41091-cve-2026-45498/), [Huntress Active Exploitation Report] |
| Ransomware affiliates (general) | Pattern consistent with pre-ransomware defense disarmament tradecraft |

## References

- [CISA KEV — May 20, 2026 Additions](https://www.cisa.gov/news-events/alerts/2026/05/20/cisa-adds-seven-known-exploited-vulnerabilities-catalog)
- [The Hacker News — Microsoft Warns of Two Actively Exploited Defender Vulnerabilities](https://thehackernews.com/2026/05/microsoft-warns-of-two-actively.html)
- [Malwarebytes — Microsoft Defender Vulnerabilities Are Being Exploited in the Wild](https://www.malwarebytes.com/blog/bugs/2026/05/microsoft-defender-vulnerabilities-are-being-exploited-in-the-wild)
- [MITRE ATT&CK — T1562.001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK — T1068: Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
