# Lateral Movement Detections

**MITRE ATT&CK Tactic:** [Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/)
**Kill Chain Phase:** Actions on Objectives

Detections for techniques adversaries use to move through a network, including remote service exploitation, SMB/WMI-based execution, and use of legitimate remote access tools.

---

## Detections

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| [Medusa SMB/WMI Lateral Execution](medusa_smb_wmi_exec.md) | T1021.002, T1047 | Invoke-SMBExec and Invoke-WMIExec PowerShell lateral movement tools |
| [Medusa Lateral Movement Indicators](medusa_lateral_indicators.md) | T1021.002, T1003.001 | Medusa-specific lateral movement patterns including admin share access and credential dumping |
| [RMM Tool Abuse for Lateral Movement](rmm_tool_abuse_lateral_movement.md) | T1219, T1021.001 | Unauthorized ScreenConnect, AnyDesk, TeamViewer, and other RMM tools launched from scripting engine parents or installed as persistent services |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Medusa Ransomware | Ransomware Operator | PowerShell-based Invoke-SMBExec/Invoke-WMIExec for lateral movement, admin share access, comsvcs.dll credential dumping | [MITRE - Medusa (S1131)](https://attack.mitre.org/software/S1131/), [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Remote services, SMB lateral movement with stolen credentials | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |
| Scattered Spider (UNC3944) | Cybercrime / ALPHV Affiliate | ScreenConnect and other RMM tools for lateral movement and persistence | [MITRE - Scattered Spider (G1015)](https://attack.mitre.org/groups/G1015/) |
| LockBit Affiliates | RaaS Affiliates | AnyDesk and TeamViewer post-compromise for persistent access and ransomware staging | [MITRE - LockBit (S1091)](https://attack.mitre.org/software/S1091/) |
