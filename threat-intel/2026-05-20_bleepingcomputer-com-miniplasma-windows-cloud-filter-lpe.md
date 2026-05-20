---
scraped_at: 2026-05-20T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/
report_type: threat-intel
severity: high
title: "MiniPlasma: Unpatched Windows Cloud Filter Driver LPE Zero-Day with Public PoC"
---

## 1. IOCs

No threat-actor-associated IOCs available. This is a vulnerability disclosure with a public PoC; no in-the-wild exploitation by a named threat actor has been confirmed as of 2026-05-20.

---

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | Public PoC abuses the `HsmOsBlockPlaceholderAccess` routine in `cldflt.sys` (Windows Cloud Filter driver) via the undocumented `CfAbortHydration` API to escalate from standard user to SYSTEM on fully patched Windows 10/11 |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | SYSTEM-level access obtained without triggering UAC; can be chained with EDR tampering post-privilege escalation |

---

## 3. Malware & Tools

### MiniPlasma PoC

- **Researcher:** "Nightmare Eclipse" (also known as "Chaotic Eclipse")
- **Published:** May 18, 2026
- **Delivery:** GitHub (public PoC repository, source code and compiled executable)
- **Target Component:** `cldflt.sys` — Windows Cloud Filter driver
- **Vulnerable Routine:** `HsmOsBlockPlaceholderAccess`
- **Attack API:** Undocumented `CfAbortHydration` API; exploit abuses unexpected registry key creation through this path
- **Affected Systems:** All fully patched Windows 10 and Windows 11 (as of May 2026 Patch Tuesday)
- **Canary Build Exception:** Does NOT work in the latest Windows 11 Insider Preview Canary build
- **Patch Status:** UNPATCHED; next Patch Tuesday is June 10, 2026
- **Historical Context:** Root cause traces to a logic flaw first reported by Google Project Zero researcher James Forshaw (September 2020, CVE-2020-17103, patched December 2020); MiniPlasma demonstrates the 2020 fix was incomplete

**Attack Outcome (verified by BleepingComputer):** Running the compiled PoC executable as a standard user opens a `cmd.exe` with SYSTEM privileges on a fully patched Windows 11 Pro system.

---

## 4. Threat Actor / Campaign Attribution

No confirmed threat actor attribution. The PoC was released by security researcher "Nightmare Eclipse" who published alongside a Barracuda blog post (May 19, 2026) documenting six zero-day vulnerabilities and referencing a long-standing dispute with Microsoft over incomplete vulnerability remediation.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name NOT IN ("services.exe","wininit.exe","lsass.exe","smss.exe","csrss.exe")
    AND Processes.user="NT AUTHORITY\\SYSTEM"
    AND Processes.process_name IN ("cmd.exe","powershell.exe","powershell_ise.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name IN ("explorer.exe","chrome.exe","firefox.exe","msedge.exe"), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process="*CfAbortHydration*"
     OR Processes.process="*cldflt*"
     OR Processes.process="*HsmOsBlockPlaceholderAccess*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_path="*\\CloudStore\\*"
    AND Registry.action IN ("created","modified")
  by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.process_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name NOT IN ("OneDrive.exe","explorer.exe","svchost.exe"), 75,
    1=1, 20)
| where risk_score >= 75
| table firstTime lastTime dest user registry_path registry_value_name process_name risk_score
```

---

## 6. Executive Summary

On May 18, 2026, a security researcher publishing under the alias "Nightmare Eclipse" released a public proof-of-concept exploit for a local privilege escalation (LPE) zero-day in Windows dubbed "MiniPlasma." The vulnerability affects the `HsmOsBlockPlaceholderAccess` routine within `cldflt.sys` (Windows Cloud Filter driver) and is exploited through the undocumented `CfAbortHydration` API, which allows unexpected registry key creation leading to SYSTEM-level process execution.

BleepingComputer independently confirmed the PoC opens a SYSTEM shell from a standard user account on a fully patched Windows 11 Pro system running the May 2026 Patch Tuesday updates. The next scheduled Microsoft Patch Tuesday is June 10, 2026; no out-of-band patch has been released. The vulnerability does not work in the Windows 11 Insider Preview Canary build, suggesting Microsoft is aware and working on a fix.

The root cause traces back to CVE-2020-17103 (reported by Google Project Zero in September 2020, patched December 2020), indicating the 2020 fix was incomplete. Defenders should monitor for SYSTEM-level shells spawned from unexpected parent processes, anomalous Cloud Filter registry key creation (under `\CloudStore\`), and process command lines referencing `CfAbortHydration` or `cldflt`. Organizations running Windows 10/11 at or below the May 2026 Patch Tuesday level are affected.

## References

- [BleepingComputer — MiniPlasma zero-day PoC](https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/)
- [The Hacker News — MiniPlasma](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)
- [Barracuda Blog — Nightmare Eclipse six zero-days](https://blog.barracuda.com/2026/05/19/nightmare-eclipse-zero-days-grudge)
- [MITRE ATT&CK — T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
