# ChainDrop: VS Code Workspace Task and Claude Code SessionStart Hook Persistence

## Description

Detects the ChainDrop npm worm establishing persistence by injecting malicious entries into VS Code workspace task configuration files (`.vscode/tasks.json`) and Claude Code hook configuration files (`.claude/settings.json`). The worm adds a folder-open task to VS Code that re-executes the payload whenever a developer opens a project, and registers a `SessionStart` hook in Claude Code to re-execute on every Claude Code session start.

This technique abuses legitimate developer tool extension points to survive package removal and maintain long-term access to developer environments with cloud credentials. It is distinct from malicious VS Code extension installation (which requires marketplace interaction); this attack requires only npm package installation.

False positives are possible from developers legitimately configuring VS Code tasks or Claude Code hooks, but npm/Bun processes writing these files at package install time is anomalous.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Persistence |
| **Tactic ID** | TA0003 |
| **Technique** | Event Triggered Execution |
| **Technique ID** | T1546 |
| **Sub-technique** | T1546.011 — Application Shimming (closest available; VS Code task triggers are analogous) |
| **Secondary Technique** | T1037 — Boot or Logon Initialization Scripts (Claude Code SessionStart hook) |

## Lockheed Martin Kill Chain Phase

Installation

## Splunk SPL Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_path="*/.vscode/tasks.json"
    OR Filesystem.file_path="*/.claude/settings.json"
    OR Filesystem.file_path="*/.claude/CLAUDE.md")
    Filesystem.process_name IN ("bun","node","node.exe","npm","npm.exe","npx","npx.exe")
    Filesystem.action IN ("created","modified","write")
  by Filesystem.dest Filesystem.user Filesystem.file_path
     Filesystem.process_name Filesystem.process_id Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path,"/.claude/settings.json"), 90,
    match(file_path,"/.claude/CLAUDE.md"), 85,
    match(file_path,"/.vscode/tasks.json"), 80,
    true(), 70)
| table firstTime lastTime dest user file_path process_name process_id action risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 90 | npm/Bun process writes to `.claude/settings.json` — direct abuse of Claude Code hook system |
| 85 | npm/Bun process writes to `.claude/CLAUDE.md` — CLAUDE.md injection variant of Claude Code hook abuse |
| 80 | npm/Bun process writes to `.vscode/tasks.json` — VS Code workspace task persistence |

Any score ≥ 80 warrants immediate investigation. The combination of an npm/node process writing to these files at package install time is highly anomalous and represents near-certain supply chain compromise.

## Associated Threat Actors

| Threat Actor | Attribution | Notes |
|---|---|---|
| ChainDrop Campaign | Alluring Pisces / Sapphire Sleet (DPRK-nexus; Unit 42 assessment) | npm worm targeting developer environments; 444 packages, 2,212 versions |
| PolinRider | DPRK-linked | Infrastructure/TTP overlap with ChainDrop per Unit 42 |
| Shai-Hulud Family | DPRK-linked | Parent family designation per Zscaler ThreatLabz |

## References

- [Unit 42: ChainDrop npm Worm Analysis](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/)
- [Zscaler: Tracking Shai-Hulud — Inside ChainDrop npm Worm](https://www.zscaler.com/blogs/security-research/tracking-shai-hulud-inside-chaindrop-npm-worm)
- [StepSecurity: ChainDrop npm Worm — Bun-loaded CI/CD credential harvester](https://www.stepsecurity.io/blog/chaindrop-npm-worm)
- [Datadog Security Labs: npm Worm Compromises Popular npm Packages](https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/)
- [MITRE ATT&CK: T1546 — Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
- Threat intel report: `threat-intel/2026-10-07_unit42-paloaltonetworks-com-chaindrop-npm-worm-blockchain-c2.md`
