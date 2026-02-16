# Defense Evasion Detections

**MITRE ATT&CK Tactic:** [Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005/)
**Kill Chain Phase:** Exploitation / Installation

Detections for techniques adversaries use to avoid detection, including abuse of signed binaries (LOLBAS), DLL sideloading, obfuscation, and proxy execution.

---

## Detections

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| [Suspicious RunDLL Risk Scoring](suspicious_rundll_risk_scoring.md) | T1218.011 | Composite risk scoring for rundll32.exe abuse based on path, parent, DLL, and command line |
| [Suspicious RunDLL Control_RunDLL](suspicious_rundll_control_dll.md) | T1218.011 | RunDLL32 Control_RunDLL invocations with non-standard DLLs or paths |
| [Gootloader Non-Standard Wscript Execution](gootloader_nonstandard_wscript.md) | T1218 | Cscript or wscript executing JS from paths outside Windows system directories |
| [Lazarus LOLBAS Execution](lazarus_lolbas_execution.md) | T1218, T1197 | Living-off-the-land binary abuse (certutil, bitsadmin, mshta, regsvr32, rundll32) |
| [Lazarus DLL Sideloading](lazarus_dll_sideloading.md) | T1574.002 | DLL loading from non-standard paths with low host prevalence |
| [BYOVD Vulnerable Driver Loading](byovd_vulnerable_driver_loading.md) | T1562.001, T1068 | Detection of known vulnerable kernel drivers used in Bring Your Own Vulnerable Driver attacks |
| [BYOVD Kernel Driver Service Creation](byovd_driver_service_creation.md) | T1562.001, T1543.003 | Kernel driver service creation via sc.exe indicating potential BYOVD driver deployment |
| [BYOVD Security Tool Process Termination](byovd_security_tool_termination.md) | T1562.001 | Rapid termination of multiple security tool processes indicating BYOVD-enabled EDR killing |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Gootloader / UNC2565 | Malware Loader | Fileless execution via registry, wscript/cscript proxy execution from non-standard paths | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Extensive LOLBAS usage (certutil, rundll32, mshta, regsvr32), DLL sideloading, BYOVD via FudModule rootkit | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/), [AhnLab - Lazarus DLL Side-Loading](https://asec.ahnlab.com/en/57873/), [ESET - Lazarus FudModule](https://www.welivesecurity.com/2022/09/30/amazon-themed-campaigns-lazarus-netherlands-belgium/) |
| Scattered Spider (UNC3944) | Cybercrime Group | BYOVD to disable EDR, social engineering, identity-based attacks | [MITRE - Scattered Spider (G1015)](https://attack.mitre.org/groups/G1015/), [Mandiant - Scattered Spider](https://www.mandiant.com/resources/blog/scattered-spider-advisory) |
| BlackByte Ransomware | Ransomware Operator | BYOVD using RTCore64.sys (MSI Afterburner driver) to disable security tools | [Sophos - BlackByte BYOVD](https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/) |
| Cuba Ransomware (BurntCigar) | Ransomware Operator | BYOVD via BurntCigar tool to terminate EDR processes at kernel level | [Mandiant - Cuba Ransomware](https://www.mandiant.com/resources/blog/unc2596-cuba-ransomware) |
| RobbinHood Ransomware | Ransomware Operator | BYOVD using GIGABYTE driver (gdrv.sys) to disable endpoint protection | [Sophos - RobbinHood BYOVD](https://news.sophos.com/en-us/2020/02/06/living-off-another-land-ransomware-borrows-vulnerable-driver-to-remove-security-software/) |
| AvosLocker Ransomware | Ransomware Operator | BYOVD to disable antivirus solutions before ransomware deployment | [Trend Micro - AvosLocker BYOVD](https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-virus-solutions.html) |
| Medusa Ransomware | Ransomware Operator | BYOVD for EDR evasion and privilege escalation | [Elastic - Medusa BYOVD](https://www.elastic.co/security-labs/medusa-ransomware-escalation) |
