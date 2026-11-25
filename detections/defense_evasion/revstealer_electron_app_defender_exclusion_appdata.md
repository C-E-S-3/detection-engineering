# RevStealer Electron App AppData Defender Exclusion Bypass

## Description

Detects Windows Defender exclusion manipulation where a PowerShell process spawned by an Electron application adds an AppData subdirectory to the Microsoft Defender exclusion list via `Add-MpPreference -ExclusionPath`. This technique is used by the RevStealer fake "Claude Opus 5 Free Desktop" campaign (Morphisec, November 2026): a trojanized Electron app decrypts and stages a native stealer payload in an obfuscated AppData subdirectory (`AppData\.<random8char>`) and whitelists it from Defender before execution.

Legitimate Electron applications (Slack, VS Code, Discord, Signal) do not add AppData paths to Defender exclusions. The pattern of an Electron process directly invoking `Add-MpPreference` with an AppData argument is highly anomalous. The ObfuscatedPath variant (paths matching `AppData\.[a-z0-9]{6,12}`) is a near-certain true positive.

**False positives:** Enterprise software deployment tools (SCCM, Intune) may legitimately modify Defender exclusions, but these spawn from `msiexec.exe`, `ccmexec.exe`, or similar management processes — not Electron. Developer tools occasionally modify exclusions but do so from installation wrappers.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Impair Defenses: Disable or Modify Tools |
| Technique ID | T1562.001 |
| Secondary Tactic | Execution |
| Secondary Technique ID | T1204.002 (User Execution: Malicious File) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("powershell.exe","pwsh.exe")
    AND Processes.process IN ("*Add-MpPreference*","*MpPreference*")
    AND Processes.process IN ("*ExclusionPath*","*ExclusionExtension*","*ExclusionProcess*")
    AND Processes.process IN ("*AppData*","*appdata*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name,"(?i)electron|claude|opus|\.asar"),        95,
    match(process,"(?i)appdata\.[a-z0-9]{6,12}"),                        95,
    NOT match(parent_process_name,"(?i)msiexec|ccmexec|setup|install|update|squirrel|deploy"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Parent process name matches Electron, `claude`, `opus`, or `.asar` pattern | 95 | Electron app directly invoking Defender exclusion modification is highly anomalous; near-certain indicator of trojanized Electron payload |
| AppData path matches obfuscated dot-prefix pattern (`AppData\.[a-z0-9]{6,12}`) | 95 | RevStealer-specific staging path; legitimate software never uses this naming scheme |
| PowerShell spawned by non-standard parent adding AppData exclusion (parent NOT msiexec/ccmexec/setup/install/update/squirrel/deploy) | 80 | High confidence malicious Defender bypass from non-managed-deployment context |
| All other cases passing the base filter | 65 | Unusual but may have legitimate explanation; warrants analyst review |

## Associated Threat Actors

| Actor | Malware | References |
|-------|---------|-----------|
| Unattributed (RevStealer operator) | RevStealer (Electron delivery variant) | [Morphisec RevStealer Threat Analysis v5](https://engage.morphisec.com/hubfs/2026-PDFs/RevStealer_ThreatAnalysis_5.pdf) |
| Multiple financially motivated actors | Generic trojanized Electron loaders | [CyberInsider: Fake Claude Opus 5 RevStealer](https://cyberinsider.com/new-revstealer-malware-spreads-as-fake-claude-opus-5-desktop-app/) |

## References

- [Morphisec: RevStealer Threat Analysis v5 (PDF)](https://engage.morphisec.com/hubfs/2026-PDFs/RevStealer_ThreatAnalysis_5.pdf)
- [MITRE ATT&CK T1562.001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK T1204.002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- Threat-intel report: `2026-11-24_morphisec-revstealer-fake-claude-opus5-electron-infostealer.md`
- Related detection: `detections/command_and_control/revstealer_dns_c2_lookup.md`
