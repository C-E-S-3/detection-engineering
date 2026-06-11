# Microsoft Defender RoguePlanet TOCTOU Local Privilege Escalation (CVE-2026-47281)

## Description

Detects exploitation of CVE-2026-47281 (RoguePlanet), a TOCTOU (Time-of-Check to Time-of-Use) race condition in Microsoft Defender's MsMpEng.exe scanning engine. An unprivileged local attacker mounts a crafted ISO image to trigger a Defender scan by the SYSTEM-privileged MsMpEng process, then atomically swaps filesystem objects using directory junctions and symbolic links during the brief interval between Defender's path verification and file access, redirecting the SYSTEM-level operation to attacker-controlled code.

The exploit results in a SYSTEM-privileged command shell launched by MsMpEng.exe. As of June 11, 2026, no patch is available. A public PoC was released by researcher Nightmare Eclipse (Chaotic Eclipse) hours after June 2026 Patch Tuesday.

False positive sources: Legitimate software using ISO mounting (disk imaging tools, virtual drive software); automated junction creation by installers or virtualization platforms. These can be baselined per environment. MsMpEng.exe spawning interactive shells has essentially no legitimate baseline.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation |
| Tactic ID | TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |
| Secondary Tactic | Defense Evasion |
| Secondary Tactic ID | TA0005 |
| Secondary Technique | Subvert Trust Controls: Mark-of-the-Web Bypass |
| Secondary Technique ID | T1553.005 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="MsMpEng.exe"
    AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                                   "mshta.exe","rundll32.exe","regsvr32.exe","conhost.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("cmd.exe","powershell.exe"), 98,
    process_name="conhost.exe", 95,
    1=1, 90)
| where risk_score >= 90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| MsMpEng.exe spawning cmd.exe or powershell.exe | 98 | Near-certain indicator of successful RoguePlanet exploitation — Defender has no legitimate reason to launch interactive shells |
| MsMpEng.exe spawning conhost.exe | 95 | Console host spawned by Defender indicates interactive shell activity — high confidence exploitation |
| MsMpEng.exe spawning any other shell/interpreter | 90 | Any interactive or scripting process spawned by Defender is highly anomalous |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Nightmare Eclipse (PoC author; exploitation may be weaponized by any actor) | [BleepingComputer — RoguePlanet (2026-06-10)](https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/) |
| BlueHammer cluster (pattern of Defender exploitation pre-ransomware) | [CISA KEV — CVE-2026-41091 (2026-05-20)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |

## References

- [BleepingComputer — Microsoft Defender 'RoguePlanet' zero-day grants SYSTEM privileges (2026-06-10)](https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/)
- [The Hacker News — Microsoft Defender RoguePlanet Zero-Day Grants SYSTEM Access](https://thehackernews.com/2026/06/microsoft-defender-rogueplanet-zero-day.html)
- [MITRE ATT&CK — T1068: Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK — T1553.005: Subvert Trust Controls: Mark-of-the-Web Bypass](https://attack.mitre.org/techniques/T1553/005/)
