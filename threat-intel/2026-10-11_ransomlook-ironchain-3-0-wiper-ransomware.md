---
scraped_at: "2026-10-13T00:00:00Z"
source_url: "https://www.ransomlook.io/group/ironchain/analysis/v3"
report_type: threat-intel
severity: critical
title: "IronChain 3.0: Python PyInstaller Ransomware-Wiper with BYOVD, MBR/UEFI Destruction, and Zero Recovery Feasibility"
---

## 1. IOCs

### Hashes

| Indicator | Type | Role |
|-----------|------|------|
| 2d57b05e8fbcae3da196ed972074577fa6604ba7f3afcadbf79b94c8f8f6de22 | SHA-256 | IronChain 3.0 main executable (Python 3.14 PyInstaller, last modified 2026-04-30) |

### Domains

No C2 domains identified in public reporting.

### IPs

No C2 IPs identified in public reporting.

### Artifacts

| Artifact | Description |
|----------|-------------|
| `IronChain_SYSTEM` | Scheduled task name for SYSTEM-level persistence (September 2026 variant) |
| `BdApiUtil.sys` | Baidu kernel driver used for BYOVD process termination (September 2026 variant) |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Terminates 39 security-related processes and stops 16 services including AV/EDR products |
| Defense Evasion | T1068 | Exploitation for Privilege Escalation | BYOVD using bundled BdApiUtil.sys (Baidu kernel driver) for privileged process termination and defense evasion; SYSTEM-level execution |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | Scheduled task `IronChain_SYSTEM` for SYSTEM-privilege persistence across six persistence layers |
| Impact | T1490 | Inhibit System Recovery | Deletes all VSS shadow copies via vssadmin.exe; modifies boot configuration via bcdedit.exe to prevent recovery |
| Impact | T1561.002 | Disk Structure Wipe: Disk Content Wipe | Overwrites MBR and UEFI partition table; renders system unbootable; recovery feasibility assessed as zero |
| Impact | T1486 | Data Encrypted for Impact | Ransomware-style encryption attempt; however, flawed encryption logic in observed samples results in effective data destruction rather than recoverable encryption |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| IronChain 3.0 | Ransomware / Wiper | Python 3.14 PyInstaller-packed Windows PE; functions as a destructive wiper due to flawed encryption logic; no exfiltration observed; recovery feasibility zero; kills 39 processes, stops 16 services; six-layer persistence; deletes VSS, overwrites MBR/UEFI |

---

## 4. Threat Actors

| Actor | Description |
|-------|-------------|
| Unknown / IronChain Group | Attribution unknown; no overlap with known nation-state or cybercrime groups identified in public reporting as of October 2026 |

---

## 5. Victims / Targeting

No specific victim sectors or countries attributed in public reporting. Wiper-capable behavior suggests potential use for destructive attacks on any sector.

---

## 6. Recommended SPL Searches

### Hunt: IronChain BYOVD Kernel Driver Load (BdApiUtil.sys)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="schtasks.exe"
    AND Processes.process="*IronChain_SYSTEM*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Hunt: VSS Deletion + Bcdedit Recovery Inhibition (IronChain Pattern)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="vssadmin.exe" AND Processes.process="*delete shadows*")
     OR (Processes.process_name="bcdedit.exe" AND Processes.process="*recoveryenabled*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats count values(process) as processes by dest user
| where count >= 2
| eval risk_score=90
| table firstTime lastTime dest user processes risk_score
```

### Hunt: Suspicious Kernel Driver Drop (BYOVD — BdApiUtil.sys)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="BdApiUtil.sys"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_path file_name risk_score
```

---

## 7. Executive Summary

IronChain 3.0, surfaced in October 2026 weekly threat intelligence reporting, is a Python 3.14 PyInstaller-packed Windows executable with both ransomware and wiper capabilities. However, flawed encryption logic in analyzed samples means it functions in practice as a pure destructive wiper with zero recovery feasibility.

The malware executes an aggressive defense evasion routine — terminating 39 security-related processes and stopping 16 services — before establishing six layers of persistence, including a scheduled task named `IronChain_SYSTEM`. Notably, the September 2026 variant uses a Bring Your Own Vulnerable Driver (BYOVD) technique with a bundled Baidu `BdApiUtil.sys` kernel driver to achieve SYSTEM-level process termination capabilities, bypassing protected process light (PPL) defenses.

The destructive payload overwrites the MBR and UEFI, deletes VSS shadow copies, and modifies boot configuration via bcdedit — leaving no recoverable state. No exfiltration has been observed, and no C2 infrastructure has been publicly attributed. Attribution remains unknown.

The combination of BYOVD, wiper capability, and zero recovery feasibility makes IronChain 3.0 a critical threat requiring detection at the driver-load and scheduled-task creation phases.

---

## 8. References

- [RansomLook — IronChain 3.0 Ransomware Full Analysis](https://www.ransomlook.io/group/ironchain/analysis/v3)
- [Hendry Adrian — IronChain Ransomware Threatens Businesses with Permanent Data Loss (Oct 2026)](https://www.hendryadrian.com/?p=115158)
- [Threat Research Weekly Recap, Oct 11 2026 — hendryadrian.com](https://hendryadrian.com/threat-research-weekly-recap-11-oct-2026)
- [MITRE ATT&CK — T1068 Exploitation for Privilege Escalation (BYOVD)](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK — T1561.002 Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002/)
