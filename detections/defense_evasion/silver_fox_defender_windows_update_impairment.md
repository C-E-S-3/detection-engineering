# Silver Fox Defender and Windows Update Impairment via MSI Installer

## Description

Detects the combined defense impairment pattern used by the Silver Fox (Yinhu) Chinese threat cluster during fake software installer campaigns. The pattern involves an MSI installer running as SYSTEM that stops and disables the Windows Update service, adds a Windows Defender exclusion path via PowerShell, and deletes Volume Shadow Copies (VSS) to inhibit system recovery. This specific combination — Windows Update service disable + Defender exclusion + VSS deletion in the same session, initiated from an installer parent — is highly characteristic of this campaign and has very low legitimate-use overlap.

False positive sources: enterprise software deployment tools (SCCM, Intune) may suppress Windows Update during maintenance windows, but would not combine that with Defender exclusion modification and VSS deletion in a single installer context.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion, Impact |
| Tactic ID | TA0005, TA0040 |
| Technique | Impair Defenses: Disable or Modify Tools |
| Technique ID | T1562.001 |
| Sub-technique | T1562.001 (Disable or Modify Tools) |
| Additional Technique | Inhibit System Recovery |
| Additional Technique ID | T1490 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (
    (Processes.process_name="net.exe" AND Processes.process="*stop wuauserv*")
    OR (Processes.process_name="sc.exe" AND Processes.process="*wuauserv*" AND Processes.process="*disabled*")
    OR (Processes.process_name="powershell.exe" AND Processes.process="*Add-MpPreference*" AND Processes.process="*ExclusionPath*")
    OR (Processes.process_name="vssadmin.exe" AND Processes.process="*delete shadows*")
  )
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval signal=case(
    process_name="vssadmin.exe" AND match(process,"(?i)delete shadows"), "vss_deletion",
    process_name="powershell.exe" AND match(process,"(?i)Add-MpPreference") AND match(process,"(?i)ExclusionPath"), "defender_exclusion",
    process_name="net.exe" AND match(process,"(?i)stop wuauserv"), "wupdate_stop",
    process_name="sc.exe" AND match(process,"(?i)wuauserv") AND match(process,"(?i)disabled"), "wupdate_disable",
    1=1, "other"
  )
| stats count values(signal) as signals values(process) as commands
    min(firstTime) as firstTime max(lastTime) as lastTime
    by dest user parent_process_name
| eval signal_count=mvcount(signals)
| eval risk_score=case(
    signal_count >= 3, 95,
    signal_count == 2 AND mvfind(signals,"vss_deletion") >= 0, 90,
    signal_count == 2, 75,
    signal_count == 1 AND mvfind(signals,"vss_deletion") >= 0, 70,
    signal_count == 1, 50,
    1=1, 40
  )
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name signals signal_count commands risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| 3+ distinct signals present (wupdate stop/disable + Defender exclusion + VSS deletion) | 95 | Complete Silver Fox impairment chain; near-certain malicious |
| 2 signals including VSS deletion | 90 | VSS deletion + any other impairment is highly anomalous |
| 2 signals without VSS deletion | 75 | Partial chain; suspicious, requires triage |
| VSS deletion alone from installer parent | 70 | VSS deletion from non-backup parent is suspicious standalone |
| Single impairment signal | 50 | Context-dependent; may be legitimate software management |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Silver Fox (Yinhu) | [Microsoft Blog](https://www.microsoft.com/en-us/security/blog/2026/09/03/silver-fox-fake-installer-campaign-disables-windows-update-deploys-ghost-rat/) |
| Earth Berberoka (TTP overlap) | [MITRE ATT&CK G1016](https://attack.mitre.org/groups/G1016/) |

## References

- [Microsoft — Silver Fox Fake Installer Campaign (September 2026)](https://www.microsoft.com/en-us/security/blog/2026/09/03/silver-fox-fake-installer-campaign-disables-windows-update-deploys-ghost-rat/)
- [MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [ValleyRAT / WinOS 4.0 Technical Analysis](https://www.fortinet.com/blog/threat-research/valleyrat-new-malware-targeting-chinese-speakers)
- [Threat Intel Report](../../../threat-intel/2026-09-03_microsoft-silver-fox-fake-installer-defender-disable.md)
