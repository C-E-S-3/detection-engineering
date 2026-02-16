# Godloader Windows Defender Exclusion Path Manipulation

## Description

Godloader disables Windows Defender scanning by adding broad exclusion paths via `Add-MpPreference -ExclusionPath`. In its most aggressive form, it excludes the entire `C:\` drive, effectively blinding Defender to all file-based detections on the system drive. This allows subsequent payload drops (RedLine Stealer, XMRig miner) to land without triggering real-time protection.

This detection identifies PowerShell commands that modify Defender exclusion preferences, with elevated risk scoring for overly broad exclusion paths such as drive roots or `C:\ProgramData`. While the `Add-MpPreference` cmdlet is legitimate for administrative tuning, excluding entire drives or broad system paths is almost never warranted and is a strong indicator of malicious intent.

False positive sources: IT administrators configuring build servers or development machines with targeted exclusions. Tuning: whitelist specific service accounts or hosts where broad Defender exclusions are expected (e.g., CI/CD build agents).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Impair Defenses: Disable or Modify Tools |
| Technique ID | T1562.001 |
| Secondary Technique | Obfuscated Files or Information (T1027) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe", "pwsh.exe")
    AND Processes.process="*Add-MpPreference*"
    AND Processes.process="*ExclusionPath*"
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)ExclusionPath\s+['\"]?[A-Za-z]:\\\\?['\"]?\s*$") OR match(process, "(?i)ExclusionPath\s+['\"]?[A-Za-z]:\\\\['\"]?\s"), 95,
    match(process, "(?i)ExclusionPath.*\\\\ProgramData"), 85,
    match(process, "(?i)ExclusionPath.*\\\\Users\\\\"), 80,
    match(process, "(?i)ExclusionPath.*\\\\(Temp|AppData)\\\\"), 80,
    1=1, 70)
| eval risk_bonus=if(NOT match(parent_process_name, "(?i)(explorer|svchost|services|mmc|taskmgr|cmd)\.exe$"), 5, 0)
| eval risk_score=risk_score + risk_bonus
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name parent_process process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Exclusion of an entire drive root (e.g., `C:\`) | 95 | Signature Godloader behavior; effectively disables Defender for entire volume |
| Exclusion of `C:\ProgramData` | 85 | Common malware staging directory; broad exclusion enables payload drops |
| Exclusion of user profile or Temp directories | 80 | Allows downloaded payloads to execute unscanned |
| Any other Add-MpPreference ExclusionPath command | 70 | Modifying Defender exclusions via script is suspicious and warrants review |
| Unusual parent process bonus | +5 | Non-standard parent processes increase suspicion |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Godloader / GodLoader (Stargazer Goblin) | [Check Point - Gaming Engines: An Undetected Playground for Malware Loaders](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/) |

## References

- [Check Point Research - Gaming Engines: An Undetected Playground for Malware Loaders](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/)
- [Splunk Security Content - Windows Defender Exclusion Added via PowerShell](https://research.splunk.com/endpoint/773b66fe-4dd9-11ec-8289-acde48001122/)
- [Elastic Security - Windows Defender Exclusions Added via PowerShell](https://www.elastic.co/guide/en/security/current/windows-defender-exclusions-added-via-powershell.html)
- [Microsoft - Add-MpPreference Documentation](https://learn.microsoft.com/en-us/powershell/module/defender/add-mppreference)
