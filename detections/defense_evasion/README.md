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
| [Godloader Windows Defender Exclusion Manipulation](godloader_defender_exclusion_manipulation.md) | T1562.001 | PowerShell Add-MpPreference commands adding broad Defender exclusion paths |
| [Qilin EDR Killer Defense Evasion](qilin_edr_killer_defense_evasion.md) | T1562.001 | EDR killer tool execution targeting 300+ security drivers; geo-fencing locale checks |
| [MiniPlasma Windows Cloud Filter LPE](miniplasma_windows_cloud_filter_lpe.md) | T1068 | Unpatched Windows LPE via Cloud Filter driver (cldflt.sys); SYSTEM shell from standard user; public PoC released May 2026 |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Gootloader / UNC2565 | Malware Loader | Fileless execution via registry, wscript/cscript proxy execution from non-standard paths | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |
| Godloader / GodLoader (Stargazer Goblin) | Malware Loader | Windows Defender exclusion path manipulation (entire C:\ drive), masquerading as Godot game engine | [Check Point - Gaming Engines: An Undetected Playground](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/), [Check Point - Stargazers Ghost Network](https://research.checkpoint.com/2024/stargazers-ghost-network/) |
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Extensive LOLBAS usage (certutil, rundll32, mshta, regsvr32), DLL sideloading, BYOVD via FudModule rootkit | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/), [AhnLab - Lazarus DLL Side-Loading](https://asec.ahnlab.com/en/57873/), [ESET - Lazarus FudModule](https://www.welivesecurity.com/2022/09/30/amazon-themed-campaigns-lazarus-netherlands-belgium/) |
| Scattered Spider (UNC3944) | Cybercrime Group | BYOVD to disable EDR, social engineering, identity-based attacks | [MITRE - Scattered Spider (G1015)](https://attack.mitre.org/groups/G1015/), [Mandiant - Scattered Spider](https://www.mandiant.com/resources/blog/scattered-spider-advisory) |
| BlackByte Ransomware | Ransomware Operator | BYOVD using RTCore64.sys (MSI Afterburner driver) to disable security tools | [Sophos - BlackByte BYOVD](https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/) |
| Cuba Ransomware (BurntCigar) | Ransomware Operator | BYOVD via BurntCigar tool to terminate EDR processes at kernel level | [Mandiant - Cuba Ransomware](https://www.mandiant.com/resources/blog/unc2596-cuba-ransomware) |
| RobbinHood Ransomware | Ransomware Operator | BYOVD using GIGABYTE driver (gdrv.sys) to disable endpoint protection | [Sophos - RobbinHood BYOVD](https://news.sophos.com/en-us/2020/02/06/living-off-another-land-ransomware-borrows-vulnerable-driver-to-remove-security-software/) |
| AvosLocker Ransomware | Ransomware Operator | BYOVD to disable antivirus solutions before ransomware deployment | [Trend Micro - AvosLocker BYOVD](https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-virus-solutions.html) |
| Medusa Ransomware | Ransomware Operator | BYOVD for EDR evasion and privilege escalation | [Elastic - Medusa BYOVD](https://www.elastic.co/security-labs/medusa-ransomware-escalation) |
| Qilin Ransomware Group | Ransomware Operator (RaaS) | EDR killer malware targeting 300+ EDR drivers before ransomware deployment; geo-fencing to avoid post-Soviet regions | [Cisco Talos - Qilin in Japan 2025](https://blog.talosintelligence.com/an-overview-of-ransomware-threats-in-japan-in-2025-and-early-detection-insights-from-qilin-cases/) |
| Nightmare Eclipse (security researcher) | PoC Author | Released public PoC for MiniPlasma — Windows Cloud Filter LPE zero-day enabling SYSTEM access on fully patched Windows 10/11; unpatched as of May 2026 | [BleepingComputer — MiniPlasma](https://www.bleepingcomputer.com/news/microsoft/new-windows-miniplasma-zero-day-exploit-gives-system-access-poc-released/) |
