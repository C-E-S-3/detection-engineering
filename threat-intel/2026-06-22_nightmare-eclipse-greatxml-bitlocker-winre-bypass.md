---
scraped_at: 2026-06-23T00:00:00Z
source_url: https://www.securityweek.com/greatxml-zero-day-exploit-bypasses-bitlocker/
report_type: threat-intel
severity: medium
title: "GreatXML: Zero-Day PoC Bypasses BitLocker via Windows Defender Offline Scan State and WinRE Answer Files"
---

## 1. IOCs

### File Artifacts

| Indicator | Type | Context |
|-----------|------|---------|
| `GreatXML/` (Git repo: git.churchofmalware.org/Nightmare_Eclipse/GreatXML) | PoC tool | Public PoC released by researcher Nightmare Eclipse on June 22, 2026; contains XML and Recovery folder structure to exploit the bypass |
| `Autounattend.xml` / `unattend.xml` on recovery partition | File | Attacker-controlled answer file placed on EFI system partition or recovery partition; parsed by WinRE to spawn SYSTEM shell |

### No Network IOCs

This vulnerability requires physical access to the target device. There are no network-based IOCs, C2 domains, or IP addresses associated with this PoC.

---

## 2. TTPs (MITRE ATT\&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Defense Evasion | T1542.001 | Pre-OS Boot: System Firmware | Abuses Windows Recovery Environment (WinRE) to execute attacker-controlled XML answer files before the OS boots, bypassing BitLocker full-disk encryption |
| Defense Evasion | T1553 | Subvert Trust Controls | BitLocker's encryption is rendered ineffective because the attacker spawns a SYSTEM-privileged command prompt with broad filesystem access to the protected volume |
| Persistence | T1542 | Pre-OS Boot | XML files placed on the recovery partition survive OS reinstallation; attack can be retried on subsequent WinRE invocations |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | WinRE answer file processing spawns a cmd.exe process with SYSTEM privileges, providing attacker-level access to the protected drive |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| GreatXML PoC | Exploit | Public PoC by Nightmare Eclipse; XML + Recovery folder structure placed on target's recovery partition |
| Windows Answer Files (Autounattend.xml) | Living-off-the-land | Legitimate Windows Unattended Setup answer file format abused to trigger shell execution in WinRE |
| Windows Recovery Environment (WinRE) | Living-off-the-land | Built-in Windows recovery OS invoked by holding SHIFT + Restart; processes answer files in EFI/recovery partition before BitLocker unlock |

---

## 4. Vulnerability Details

| Attribute | Detail |
|-----------|--------|
| CVE | Not yet assigned (as of June 23, 2026) |
| Researcher | Nightmare Eclipse (aka Chaotic Eclipse); same researcher responsible for YellowKey (CVE-2026-45585) BitLocker bypass |
| Disclosure | June 22, 2026; public PoC immediately released |
| Affected systems | Any Windows system with BitLocker enabled **that has ever had Windows Defender Offline Scan initiated at least once** |
| Physical access required | YES — attacker must have physical access to the target device to place files on the EFI/recovery partition |
| Patch status | No patch issued as of June 23, 2026; Microsoft has not confirmed a CVE |
| Exploitation in the wild | No confirmed active exploitation by threat actors as of disclosure |

**Attack Procedure (from PoC):**
1. Physical access to the target device
2. Place GreatXML `XML` file and `Recovery/` folder at the root of the recovery partition or EFI system partition
3. Reboot the device into WinRE (SHIFT + Restart → Troubleshoot → Advanced Options → Startup Settings, or hold power button)
4. WinRE processes the answer file and spawns a SYSTEM-privileged cmd.exe
5. Attacker has broad command-line access to the BitLocker-protected volume

**Pre-condition:** The target must have run Windows Defender Offline Scan at least once. This scan leaves state on the system that alters WinRE boot behavior, making it susceptible to answer-file-triggered shell execution.

---

## 5. Splunk Detection Searches

### 5a. Unusual BCDEdit or Boot Configuration Modification (WinRE Tamper)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name="bcdedit.exe" OR Processes.process_name="reagentc.exe")
  AND (Processes.process="*winre*" OR Processes.process="*recoveryenabled*"
    OR Processes.process="*bootsequence*" OR Processes.process="*bootmgr*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)/set.*winre|reagentc.*disable|reagentc.*enable"), 85,
    match(parent_process_name, "(?i)cmd|powershell|wscript|cscript"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### 5b. Answer File Created in System Drive Root or Recovery Path

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where (Filesystem.file_name="Autounattend.xml" OR Filesystem.file_name="unattend.xml"
    OR Filesystem.file_name="autounattend.xml")
  AND (Filesystem.file_path="C:\\*" OR Filesystem.file_path="*\\Recovery\\*"
    OR Filesystem.file_path="*\\EFI\\*")
  AND NOT Filesystem.process_name IN ("setup.exe", "sysprep.exe", "msiexec.exe", "dism.exe")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
   Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

---

## 6. Executive Summary

On June 22, 2026, security researcher Nightmare Eclipse (aka Chaotic Eclipse) publicly released a PoC exploit named GreatXML that bypasses Windows BitLocker full-disk encryption by abusing the interaction between Windows Defender Offline Scan state and the Windows Recovery Environment (WinRE) answer file processing mechanism.

An attacker with physical access to a BitLocker-protected device copies a malicious `Autounattend.xml` file and companion `Recovery/` folder to the device's recovery or EFI partition, then reboots into WinRE. WinRE processes the attacker-controlled answer file and spawns a SYSTEM-privileged `cmd.exe` with broad access to the protected volume — without requiring the BitLocker recovery key or PIN.

The critical pre-condition is that the victim's device must have had Windows Defender Offline Scan invoked at least once; this scan leaves system state that enables the attack. Nightmare Eclipse is the same researcher who previously released YellowKey (CVE-2026-45585) and GreenPlasma BitLocker bypasses.

As of June 23, 2026, Microsoft has not assigned a CVE, issued a patch, or confirmed a workaround. No active threat actor exploitation has been confirmed.

**Recommended actions:**
- Restrict physical access to endpoint devices (locked cabinets, cable locks)
- Configure UEFI Secure Boot and set a BIOS/UEFI administrator password to prevent unauthorized boot media
- Disable Windows Defender Offline Scan in environments where BitLocker is the primary encryption control
- Monitor for creation of `Autounattend.xml` or `unattend.xml` files outside of known software deployment workflows
- Monitor for `reagentc.exe` and `bcdedit.exe` executions by non-IT processes
