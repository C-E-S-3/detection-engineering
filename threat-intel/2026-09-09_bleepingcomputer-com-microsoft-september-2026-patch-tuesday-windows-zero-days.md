---
scraped_at: "2026-09-09T12:00:00Z"
source_url: "https://www.bleepingcomputer.com/news/microsoft/microsoft-september-2026-patch-tuesday-fixes-966-flaws-2-zero-days/"
report_type: threat-intel
severity: high
title: "Microsoft September 2026 Patch Tuesday — Two Actively Exploited Windows LPE Zero-Days (CVE-2026-85880, CVE-2026-81963)"
---

## 1. IOCs

No network-based IOCs associated with exploitation of these vulnerabilities have been publicly disclosed. Exploitation requires an authorized local attacker (post-initial-access) and produces no unique network artifacts. Endpoint behavior indicators are documented in Section 5 (Splunk Detection Searches).

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|-------------|-------------|----------------|-------|
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | Attackers exploiting CVE-2026-85880 (Windows ALPC heap buffer overflow) and CVE-2026-81963 (Windows Update Stack link following) to escalate from low-privilege or AppContainer to SYSTEM |
| Privilege Escalation | T1134 | Access Token Manipulation | Post-LPE token manipulation to maintain SYSTEM-level access |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Historical pattern: LPE zero-days paired with AV/EDR disablement post-escalation |

### CVE-2026-85880 — Windows ALPC Heap-Based Buffer Overflow

- **Component:** Windows Advanced Local Procedure Call (ALPC) subsystem
- **CWE:** CWE-122 (Heap-Based Buffer Overflow)
- **CVSS v3.1:** 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **Root Cause:** ALPC subsystem fails to validate input data lengths before copying into fixed-size heap buffers. An attacker with code execution in a low-privilege AppContainer can trigger the overflow, escape the sandbox, and gain SYSTEM privileges with no additional user interaction required.
- **Affected Products:** Windows 10 (all versions), Windows 11, Windows Server 2012/2012R2/2016/2019/2022 (all editions including Server Core)
- **Exploitation Status:** Confirmed zero-day exploitation in the wild; added to CISA KEV September 8, 2026. First ALPC vulnerability exploited as zero-day since January 2023.
- **Patch:** KB5070906 and related September 2026 cumulative update packages targeting Windows 10.0.14393.9512 and equivalent per-OS baselines

### CVE-2026-81963 — Windows Update Stack Link Following EoP

- **Component:** Windows Update Stack (privileged update service)
- **CWE:** CWE-59 (Improper Link Resolution Before File Access)
- **CVSS v3.1:** 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **Root Cause:** The Windows Update privileged component improperly resolves file-system symbolic links before file access. An authorized local attacker with low privileges manipulates how the update component resolves a path, causing the privileged process to act on a file of the attacker's choosing — achieving SYSTEM-level writes or execution.
- **Exploitation Status:** Confirmed zero-day exploitation in the wild. First Windows Update Stack vulnerability exploited as a zero-day. Credited to Romain Deperne and Microsoft Threat Intelligence Centre (MSTIC). CISA KEV added September 8, 2026; FCEB patch deadline September 22, 2026.
- **Exploit Maturity:** CVSS Exploit Code Maturity: Functional (confirmed working exploit observed in attacks)

## 3. Malware & Tools

No specific malware families have been publicly attributed to exploitation of these zero-days at time of writing. The vulnerabilities require pre-existing code execution on the target system (post-initial-access), indicating their use as part of a multi-stage attack chain rather than standalone exploitation.

## 4. Threat Actor / Campaign Attribution

Attribution for in-the-wild exploitation of CVE-2026-85880 and CVE-2026-81963 has not been publicly disclosed. The FCEB patch deadline of September 22, 2026 (14 days from CISA KEV addition) suggests moderate urgency without confirmed nation-state attribution at time of writing. MSTIC credited discovery of CVE-2026-81963, implying Microsoft observed exploitation before patch release.

Historical context: Windows ALPC zero-days have been exploited by APT28 (CVE-2018-8120), Lazarus Group (CVE-2019-0859), and various ransomware operators.

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("svchost.exe","TrustedInstaller.exe","wuauclt.exe",
        "UsoClient.exe","musnotification.exe","musnotificationux.exe")
    AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
        "mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","net.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name="TrustedInstaller.exe", 95,
    parent_process_name="UsoClient.exe" AND process_name IN ("powershell.exe","cmd.exe"), 90,
    parent_process_name IN ("wuauclt.exe","musnotification.exe"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```
**Detects:** CVE-2026-81963 Windows Update Stack LPE — privileged Windows Update components (TrustedInstaller, UsoClient, wuauclt) spawning shell interpreters, indicating a link-following attack caused a privileged write or execution to be redirected to attacker-controlled code.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_integrity_level="high" OR Processes.process_integrity_level="system"
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id Processes.process_integrity_level
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search process_integrity_level="system"
| where user!="SYSTEM" AND user!="LOCAL SERVICE" AND user!="NETWORK SERVICE"
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process process_id process_integrity_level risk_score
```
**Detects:** SYSTEM-integrity process running under a non-service user account — post-LPE indicator applicable to both CVE-2026-85880 and CVE-2026-81963. A process running at SYSTEM integrity under a regular user identity is a strong indicator of privilege escalation.

```spl
index=wineventlog EventCode=4688
  NewProcessName IN ("*\\cmd.exe","*\\powershell.exe","*\\wscript.exe","*\\cscript.exe")
  (ParentProcessName="*\\TrustedInstaller.exe" OR ParentProcessName="*\\UsoClient.exe"
   OR ParentProcessName="*\\wuauclt.exe")
| eval risk_score=90
| table _time Computer SubjectUserName NewProcessName CommandLine ParentProcessName risk_score
```
**Detects:** Raw Event Log fallback for CVE-2026-81963 when ES data models are not accelerated. Windows Security Event 4688 (process creation) with Windows Update parents spawning shells.

## 6. Executive Summary

Microsoft's September 2026 Patch Tuesday (released September 9, 2026) includes patches for 974 CVEs, including two actively exploited Windows local privilege escalation zero-days. Both vulnerabilities were added to CISA's Known Exploited Vulnerabilities (KEV) catalog on September 8, 2026, with a federal patch deadline of September 22, 2026.

**CVE-2026-85880** is a heap-based buffer overflow in the Windows ALPC subsystem (CVSS 7.8). It allows an attacker already executing in a low-privilege AppContainer environment to escape the sandbox and gain SYSTEM privileges without any user interaction. This is the first ALPC zero-day exploited in the wild since January 2023.

**CVE-2026-81963** is a link-following vulnerability in the Windows Update Stack (CVSS 7.8). The privileged update component fails to safely resolve file-system symbolic links, allowing a low-privilege local attacker to redirect privileged file operations to attacker-controlled targets, achieving SYSTEM. This is the first-ever zero-day exploitation of a Windows Update Stack vulnerability.

Both vulnerabilities require prior code execution on the target — typically obtained via phishing, drive-by, or exploitation of a public-facing application — and are most likely used as the second stage in a multi-stage attack chain. Organizations should prioritize September 2026 cumulative updates on Windows endpoints and servers, particularly those where initial access via other means is plausible.

## References

- [Microsoft Security Update Guide — CVE-2026-85880](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-85880)
- [Microsoft Security Update Guide — CVE-2026-81963](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-81963)
- [BleepingComputer — Microsoft September 2026 Patch Tuesday](https://www.bleepingcomputer.com/news/microsoft/microsoft-september-2026-patch-tuesday-fixes-966-flaws-2-zero-days/)
- [Tenable — September 2026 Patch Tuesday Analysis](https://www.tenable.com/blog/microsofts-september-2026-patch-tuesday-addresses-964-cves-cve-2026-81963-cve-2026-85880)
- [SecurityWeek — Microsoft Patches Record 974 Vulnerabilities](https://www.securityweek.com/microsoft-patches-record-974-vulnerabilities-including-two-exploited-zero-days/)
- [CISA KEV — CVE-2026-85880 Added September 8, 2026](https://www.cisa.gov/news-events/alerts/2026/09/08/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- [CISA KEV — CVE-2026-81963 Added September 8, 2026](https://www.cisa.gov/news-events/alerts/2026/09/08/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK — T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
