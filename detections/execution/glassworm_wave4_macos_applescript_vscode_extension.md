# GlassWorm Wave 4: macOS AppleScript Execution via VSCode Extension Host

## Description

Detects macOS `osascript` (AppleScript) spawned by VSCode-family extension host processes. GlassWorm Wave 4 (October 2026) was the first GlassWorm campaign targeting macOS; the shift from Windows required replacing PowerShell with AppleScript for payload execution. Malicious OpenVSX extensions load an AES-256-CBC-encrypted payload from compiled JavaScript after a 15-minute delay, then execute it via osascript to set up a LaunchAgent and run the credential-stealing implant.

Legitimate VSCode extensions have no reason to invoke osascript. On developer workstations it may appear as a false positive if a task runner (gulp, make, npm scripts) invokes applescript for IDE automation or notification; tune with an allowlist of known-good osascript command lines (e.g., `display notification`). Any osascript invocation that reaches out to the network, writes to ~/Library/LaunchAgents/, or accesses browser extension data paths warrants immediate investigation.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: AppleScript |
| Technique ID | T1059.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("extensionHost","code","cursor","vscodium","code-oss","node")
    AND Processes.process_name="osascript"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(launchagent|library/launch|curl|wget|base64|eval|exec)"), 95,
    match(process,"(?i)(do shell script)"), 90,
    NOT match(process,"(?i)(display notification|display dialog|say )"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*/Library/LaunchAgents/*.plist"
    AND Filesystem.process_name IN ("osascript","node","extensionHost","code","cursor","vscodium")
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"osascript"), 95,
    match(process_name,"(?i)(extensionHost|code|cursor|vscodium)"), 90,
    match(process_name,"node"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| osascript from extensionHost/code/cursor referencing LaunchAgents or network utilities | 95 | Near-certain GlassWorm Wave 4 infection; no legitimate use for this combination |
| osascript from extensionHost using `do shell script` | 90 | Shell execution via AppleScript; consistent with Wave 4 implant launch sequence |
| osascript from extensionHost with non-notification content | 85 | Suspicious; legitimate automation uses display notification/dialog, not arbitrary script execution |
| osascript from extensionHost with any content | 70 | Requires review; low-confidence without further context |
| LaunchAgent plist written by osascript | 95 | GlassWorm Wave 4 persistence step; osascript has no business writing LaunchAgent plists |
| LaunchAgent plist written by extensionHost/code/cursor | 90 | Consistent with Wave 4 post-execution persistence |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| GlassWorm (Wave 4) | [Palo Alto Networks — GlassWorm Goes Mac](https://www.paloaltonetworks.com/blog/security-operations/glassworm-goes-mac-fresh-infrastructure-new-tricks/), [koi.ai](https://www.koi.ai/blog/glassworm-goes-mac-fresh-infrastructure-new-tricks) |

## References

- [Palo Alto Networks Blog — GlassWorm Goes Mac: Fresh Infrastructure, New Tricks](https://www.paloaltonetworks.com/blog/security-operations/glassworm-goes-mac-fresh-infrastructure-new-tricks/)
- [koi.ai — GlassWorm Goes Mac: Fresh Infrastructure, New Tricks](https://www.koi.ai/blog/glassworm-goes-mac-fresh-infrastructure-new-tricks)
- [BleepingComputer — New GlassWorm Malware Wave Targets Macs with Trojanized Crypto Wallets](https://www.bleepingcomputer.com/news/security/new-glassworm-malware-wave-targets-macs-with-trojanized-crypto-wallets/)
- [MITRE ATT&CK — T1059.002 Command and Scripting Interpreter: AppleScript](https://attack.mitre.org/techniques/T1059/002/)
- [MITRE ATT&CK — T1543.001 Create or Modify System Process: Launch Agent](https://attack.mitre.org/techniques/T1543/001/)
