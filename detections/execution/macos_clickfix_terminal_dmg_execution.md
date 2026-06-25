# macOS ClickFix Terminal DMG Execution (AMOS Delivery)

## Description

Detects the macOS ClickFix attack pattern where users are socially engineered via fake CAPTCHA pages into opening Terminal and pasting a command that silently downloads and mounts a DMG disk image using `hdiutil attach -quiet -nobrowse`. This technique was documented by Unit 42 on June 23, 2026, delivering Atomic macOS Stealer (AMOS) to victims. The `-quiet` and `-nobrowse` flags suppress both Finder notifications and disk image browsing dialogs, hiding the mount from the user.

Secondary detection: `curl` with silent flags downloading `.dmg`/`.pkg` files from a shell, and processes executing from `/Volumes/` paths spawned by shell parents.

False positives: Automated CI/CD build pipelines that mount DMG files (e.g., Xcode toolchain installers, macOS build systems extracting application components). Tune by excluding known DevOps service account users or specific parent process paths (e.g., `xcodebuild`, `make`, Jenkins agent processes).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | User Execution: Malicious File |
| Technique ID | T1204.002 |
| Secondary Technique | Command and Scripting Interpreter: Unix Shell |
| Secondary Technique ID | T1059.004 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Delivery |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="hdiutil" Processes.parent_process_name IN ("bash","zsh","sh","Terminal","osascript")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search process="*attach*" AND (process="*quiet*" OR process="*nobrowse*")
| eval risk_score=case(
    match(process, "-quiet") AND match(process, "-nobrowse"), 90,
    match(process, "-quiet") OR match(process, "-nobrowse"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| hdiutil attach with both -quiet AND -nobrowse from shell parent | 90 | High-confidence ClickFix indicator; both flags together deliberately suppress all user-visible disk mount signals |
| hdiutil attach with -quiet OR -nobrowse from shell parent | 80 | Strong indicator; single suppression flag called from interactive shell is highly suspicious |
| hdiutil attach from shell parent (no suppression flags) | 60 | Anomalous; legitimate shell-invoked DMG mounts without suppression flags are rare |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| AMOS MaaS Operators (macOS ClickFix DMG campaign, June 2026) | [BleepingComputer — macOS ClickFix DMG (2026-06-23)](https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/), [Unit 42 Threat Research](https://unit42.paloaltonetworks.com/) |
| ClawHavoc campaign (OpenClaw skill marketplace) | [Unit 42 — OpenClaw Supply Chain (2026-06-23)](https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/) |

## References

- [BleepingComputer — New macOS ClickFix Attack Silently Mounts DMGs (2026-06-23)](https://www.bleepingcomputer.com/news/security/new-macos-clickfix-attack-silently-mounts-dmgs-to-push-infostealer/)
- [Unit 42 — ClickFix Factory: First Exposure of IUAM Generator (2025-10-08)](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [MITRE T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [threat-intel/2026-06-23_unit42-paloaltonetworks-com-macos-clickfix-amos-dmg-stealer.md](../../threat-intel/2026-06-23_unit42-paloaltonetworks-com-macos-clickfix-amos-dmg-stealer.md)
