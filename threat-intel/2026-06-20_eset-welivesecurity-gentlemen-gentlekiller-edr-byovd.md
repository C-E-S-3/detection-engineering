---
scraped_at: 2026-06-20T00:00:00Z
source_url: https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/
report_type: threat-intel
severity: critical
title: "Gentlemen RaaS GentleKiller EDR Framework: BYOVD Suite Targeting 400+ Security Processes Across 48 Products (ESET, June 18, 2026)"
---

## 1. IOCs

No new file hashes were published in accessible portions of the report. For file hashes of the Gentlemen encryptor, see the prior Microsoft Security Blog report tracked in `2026-05-28_microsoft-com-security-blog-gentlemen-ransomware-storm-2697.md`.

### EDR Killer Tool Inventory

| Tool | Type | Origin | Notes |
|------|------|--------|-------|
| GentleKiller | Self-developed BYOVD EDR killer | Storm-2697 / Gentlemen RaaS | 8 known variants; targets 400+ security processes across 48 products; uses IOCTL commands to kernel-exploited vulnerable driver for Ring-0 process termination |
| HexKiller | Third-party BYOVD EDR killer | Operationally integrated by Gentlemen affiliates | Commercially available EDR killer used by multiple threat actors |
| ThrottleBlood | Third-party BYOVD EDR killer | Operationally integrated by Gentlemen affiliates | Part of affiliate toolkit |
| HavocKiller | Third-party BYOVD EDR killer | Operationally integrated by Gentlemen affiliates | Integrated for redundancy if primary GentleKiller fails |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | GentleKiller terminates 400+ security processes including EDR agents with tamper protection enabled |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | BYOVD: Exploit vulnerable kernel driver to achieve Ring-0 execution context |
| Defense Evasion | T1543.003 | Create or Modify System Process: Windows Service | Deploy vulnerable driver as kernel service (sc.exe or API) to enable IOCTL exploitation |
| Impact | T1486 | Data Encrypted for Impact | XChaCha20 + Curve25519 per-file encryption; appends `.umc16h` extension |
| Lateral Movement | T1021.003 | Remote Services: Distributed Component Object Model | Wormable lateral movement via WMI (WMIC) |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral movement via PsExec over SMB admin shares |
| Lateral Movement | T1021.006 | Remote Services: Windows Remote Management | WinRM-based lateral spread |
| Discovery | T1082 | System Information Discovery | Pre-encryption enumeration of domain and host configuration |
| Discovery | T1018 | Remote System Discovery | Network scanning for lateral movement targets |
| Defense Evasion | T1036.004 | Masquerading: Masquerade Task or Service | GentleKiller variants mimic legitimate kernel service names |

---

## 3. Malware & Tools

**GentleKiller** — Self-developed BYOVD EDR impairment toolkit. The most sophisticated component of the Gentlemen RaaS affiliate toolkit. Sends crafted IOCTL requests to a kernel-exploited vulnerable driver to gain Ring-0 privileges and terminate any user-mode or kernel-protected process, including EDR agents with anti-tamper protection. Operates below the level at which user-mode tamper protection can intervene. Eight variants observed, each leveraging a different vulnerable driver, giving affiliates redundancy when specific drivers are blocked or detected. Each variant targets a tailored list of security product processes.

Gentlemen demonstrates an unusual capability to rapidly weaponize newly disclosed BYOVD proof-of-concepts, often incorporating new vulnerable drivers into GentleKiller within days of public release.

**The Gentlemen Encryptor** — Go binary obfuscated with Garble; XChaCha20 + Curve25519 per-file encryption; appends `.umc16h` extension; wormable via PsExec/WMIC/WinRM. See prior report.

---

## 4. Threat Actor / Campaign Attribution

**The Gentlemen / Storm-2697 (Microsoft tracking)** — Prolific Ransomware-as-a-Service operation. Attribution:
- **Operator identified:** Alexander Andreevich Yapaev, alias `hastalamuerte`, Russian national, age 36
- **Scale (as of June 13, 2026):** 483 victims listed across 66 countries; 478+ encrypted in the prior reporting period
- **Victimology:** Healthcare, critical infrastructure, logistics, manufacturing, financial services

**Campaign timeline:**
- Late 2025: Initial Gentlemen RaaS activity observed
- May 28, 2026: Microsoft Security Blog encryptor analysis published
- June 13, 2026: 483 victims listed on DLS
- June 18, 2026: ESET publishes GentleKiller EDR framework analysis

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Services
where Services.service_type=kernel
  AND Services.start_type IN ("demand_start","auto_start")
by Services.dest Services.user Services.service_name Services.image_path
| `drop_dm_object_name(Services)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(image_path,"(?i)(temp|programdata|appdata|users\\\\[^\\\\]+\\\\documents)"), 80,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user service_name image_path risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process IN ("*taskkill*","*pskill*","*tskill*")
  AND (Processes.process IN ("*MsMpEng*","*SentinelAgent*","*CrowdStrike*","*CbDefense*","*bdservicehost*","*mbam*","*cylance*","*sfc*")
      OR Processes.process IN ("*360*","*avg*","*avp*","*avast*","*norton*","*mcshield*"))
by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="*.umc16h"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=99
| table firstTime lastTime dest user file_path file_name risk_score
```

---

## 6. Executive Summary

ESET published a comprehensive analysis on June 18, 2026 of The Gentlemen ransomware group's in-house EDR killer framework, GentleKiller. Unlike most ransomware groups that purchase or repurpose third-party BYOVD tools, Storm-2697 has developed and actively maintains GentleKiller — at least eight variants that each exploit a different vulnerable kernel driver to achieve Ring-0 privileges, allowing termination of any security process including those with EDR tamper-protection enabled.

GentleKiller targets more than 400 security-related processes across 48 security products. Affiliates also have access to three commercially-sourced EDR killers (HexKiller, ThrottleBlood, HavocKiller) for redundancy. Gentlemen demonstrates unusually short time-to-weaponization for newly disclosed BYOVD proof-of-concepts.

The gang has claimed 483 victims across 66 countries as of June 13, 2026. Russian national Alexander Andreevich Yapaev (hastalamuerte) has been identified as the gang's leader. The encryptor uses XChaCha20 + Curve25519 encryption and is capable of self-propagation via PsExec, WMIC, and WinRM.

**Immediate actions:** Ensure kernel driver allow-listing is active; enable audit logs for kernel driver service creation; monitor for mass process termination of security tooling from non-standard parents.
