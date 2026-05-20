# MiniPlasma — Windows Cloud Filter Driver Local Privilege Escalation

## Description

Detects exploitation of the "MiniPlasma" Windows local privilege escalation zero-day (unpatched as of May 2026). The vulnerability abuses the `HsmOsBlockPlaceholderAccess` routine in `cldflt.sys` (Windows Cloud Filter driver) via the undocumented `CfAbortHydration` API, enabling any standard user to obtain a SYSTEM-level process on fully patched Windows 10 and Windows 11 systems. A public PoC was released on May 18, 2026 by researcher "Nightmare Eclipse."

Detection strategy covers three angles: (1) SYSTEM-privileged shells spawned from unexpected parent processes; (2) anomalous `CfAbortHydration` / Cloud Filter driver references in process command lines; (3) unexpected processes creating or modifying registry keys under the Cloud Store path used by the Cloud Filter driver.

False positives: OneDrive sync processes legitimately write `CloudStore` registry keys; IIS/svchost can legitimately appear as parents of system processes. Tune the exclusion list for the environment before deploying.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion / Privilege Escalation |
| Tactic ID | TA0005 / TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.user="NT AUTHORITY\\SYSTEM"
    AND Processes.process_name IN ("cmd.exe","powershell.exe","powershell_ise.exe","wscript.exe","cscript.exe","mshta.exe")
    AND Processes.parent_process_name NOT IN (
        "services.exe","wininit.exe","lsass.exe","smss.exe","csrss.exe",
        "winlogon.exe","taskhost.exe","taskhostw.exe","svchost.exe",
        "TiWorker.exe","TrustedInstaller.exe","MsMpEng.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name IN ("explorer.exe","chrome.exe","firefox.exe","msedge.exe","iexplore.exe"), 90,
    parent_process_name IN ("python.exe","python3","node.exe","java.exe","javaw.exe"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

**Supplemental: Cloud Filter registry key anomaly (CfAbortHydration exploitation artifact)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\CloudStore\\*"
    AND Registry.action IN ("created","modified")
  by Registry.dest Registry.user Registry.registry_path
     Registry.registry_value_name Registry.process_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name NOT IN ("OneDrive.exe","explorer.exe","svchost.exe","SystemSettingsAdminFlows.exe"), 75,
    1=1, 10)
| where risk_score >= 75
| table firstTime lastTime dest user registry_path registry_value_name process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| SYSTEM shell (`cmd.exe`/`powershell.exe`) spawned by browser or interpreter | 90 | Strongly anomalous; no legitimate scenario for browser→SYSTEM shell chain |
| SYSTEM shell spawned by scripting runtime (Python, Node, Java) | 85 | Exploit typically runs as a user-mode binary or script; SYSTEM shell outcome is direct exploitation indicator |
| SYSTEM shell spawned by any unexpected parent | 75 | Broad catch for novel chaining; requires analyst review |
| CloudStore registry key written by non-OneDrive/non-Explorer process | 75 | CfAbortHydration exploitation modifies Cloud Filter registry state; legitimate writes come from OneDrive/Explorer |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Nightmare Eclipse (security researcher — PoC only; no threat-actor exploitation confirmed) | [BleepingComputer — MiniPlasma PoC](https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/) |

## References

- [BleepingComputer — New Windows MiniPlasma zero-day exploit gives SYSTEM access, PoC released](https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/)
- [The Hacker News — MiniPlasma Windows 0-Day Enables SYSTEM Privilege Escalation on Fully Patched Systems](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)
- [Barracuda Blog — Nightmare Eclipse: six zero-days, six weeks and one big grudge](https://blog.barracuda.com/2026/05/19/nightmare-eclipse-zero-days-grudge)
- [MITRE ATT&CK — T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [CVE-2020-17103 — Original Cloud Filter vulnerability (incomplete fix)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17103)
