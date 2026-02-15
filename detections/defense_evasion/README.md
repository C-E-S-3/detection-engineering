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

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Gootloader / UNC2565 | Malware Loader | Fileless execution via registry, wscript/cscript proxy execution from non-standard paths | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Extensive LOLBAS usage (certutil, rundll32, mshta, regsvr32), DLL sideloading | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/), [AhnLab - Lazarus DLL Side-Loading](https://asec.ahnlab.com/en/57873/) |
