---
title: "FalconFlank: Public PoC for CrowdStrike Falcon Sensor Local Privilege Escalation"
source: "The Register / SOCRadar / Abstract Security"
date: 2026-09-03
tags: [lpe, edr-bypass, crowdstrike, falcon-sensor, privilege-escalation, poc, chaotic-eclipse]
mitre_tactics: [TA0004, TA0005]
severity: high
type: threat-intel
---

# FalconFlank: Public PoC for CrowdStrike Falcon Sensor Local Privilege Escalation

## Summary

On 2026-09-03, security researcher **Chaotic Eclipse** (also tracked as Nightmare-Eclipse, responsible for prior Windows zero-days including the June 2026 BitLocker/WinRE bypass) published a proof-of-concept exploit named **FalconFlank** targeting the CrowdStrike Falcon Sensor for Windows. The vulnerability resides in the **macro-remediation cleanup routine**, which runs as SYSTEM and can be manipulated into processing attacker-controlled files, allowing a local low-privileged user to escalate to SYSTEM.

As of 2026-09-06, **no CVE has been assigned** and **CrowdStrike has not released a patch**. No confirmed in-the-wild exploitation has been reported. The public PoC lowers the bar for exploitation significantly.

## Technical Details

- **Affected product:** CrowdStrike Falcon Sensor for Windows (versions unspecified at time of disclosure)
- **Vulnerability class:** Local Privilege Escalation (LPE)
- **Precondition:** Local code execution as a standard (non-administrator) user
- **Root cause:** The Falcon macro-remediation cleanup service (`CsFalconService.exe`) runs as SYSTEM and performs file operations on paths that can be influenced by a low-privileged user. By creating a symbolic link or junction point at the target path before the cleanup routine runs, an attacker can redirect the elevated file operation to an arbitrary location — a classic "planting" style TOCTOU (time-of-check/time-of-use) race.
- **Impact:** SYSTEM-level code execution on any Windows endpoint running a vulnerable Falcon Sensor version

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Exploitation for Privilege Escalation | T1068 | Exploiting a vulnerability in the CrowdStrike Falcon cleanup service to gain SYSTEM |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Once at SYSTEM, attacker could tamper with or unload the Falcon sensor |
| Abuse Elevation Control Mechanism | T1548 | Abuses a privileged service's file handling to gain elevated token |

## Lockheed Martin Kill Chain Phase

**Exploitation** — LPE is used post-initial-access to escalate from standard user to SYSTEM on a compromised endpoint.

## Risk Score

**High (75)** — Public PoC available, no patch, affects all Falcon-protected Windows endpoints. Exploitation requires local access (lowering score from Critical). Confidence in eventual exploitation is high given researcher's track record.

## Threat Actor Context

| Actor | Notes |
|-------|-------|
| Chaotic Eclipse (Nightmare-Eclipse) | Independent security researcher with prior Windows zero-day PoC history (BitLocker/WinRE bypass June 2026, GreatXML privilege escalation). Publishes PoCs without coordinated disclosure. |
| Ransomware operators | LPE vulnerabilities are routinely incorporated into ransomware kill chains within days of public PoC release. |
| APT clusters | Groups with initial access capability will incorporate this to achieve SYSTEM on Falcon-protected endpoints, potentially enabling sensor tampering. |

## Detection Opportunities

1. **CsFalconService spawning shell processes** — `CsFalconService.exe` should never spawn `cmd.exe`, `powershell.exe`, or other interactive shells. Any such parent-child relationship is highly suspicious.
2. **Symbolic link / junction creation** — Monitor for junction point or symbolic link creation in directories the Falcon cleanup routine operates on (`C:\Windows\Temp`, `C:\ProgramData\CrowdStrike\`, etc.).
3. **Falcon service file operations in user-writable paths** — ETW/Sysmon Process Tamper events or file system mini-filter events showing Falcon service writing to user-controlled directories.
4. **Integrity level anomaly** — A process spawned from a medium-integrity parent gaining high/SYSTEM integrity via Falcon cleanup (detectable via Windows Security Event ID 4688 with token elevation type).

## IOCs

No malware-specific IOCs. The exploit is a technique, not tracked infrastructure. Monitor for PoC tool artifacts:

| Artifact | Notes |
|----------|-------|
| `FalconFlank.exe` (PoC tool name) | May appear in endpoint telemetry if PoC binary is transferred to a victim system |
| Junctions/symlinks in `C:\ProgramData\CrowdStrike\` | Attacker-created symlinks targeting arbitrary write locations |

## Associated Malware / Tools

- **FalconFlank.exe** — Public PoC exploit by Chaotic Eclipse; not commercially distributed but accessible via GitHub/research communities.

## References

- [The Register: Prolific Microsoft 0-day hunter drops CrowdStrike Falcon exploit PoC (2026-09-03)](https://www.theregister.com/security/2026/09/03/prolific-microsoft-0-day-hunter-drops-crowdstrike-falcon-exploit-poc/5294318)
- [SOCRadar: FalconFlank — CrowdStrike Falcon 0-Day PoC](https://socradar.io/blog/falconflank-crowdstrike-falcon-0day-poc/)
- [Abstract Security: Chaotic Eclipse Releases CrowdStrike Falcon Zero-Day FalconFlank Detection Guidance](https://www.abstract.security/blog/chaotic-eclipse-releases-crowdstrike-falcon-zero-day-falconflank-detection-guidance)
- [MITRE ATT&CK T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [Prior work — Nightmare-Eclipse GreatXML BitLocker Bypass (June 2026)](https://cloud.google.com/blog/topics/threat-intelligence/greatxml-winre-bypass-nightmare-eclipse)
