# MIDNIGHT NEPTUNE SOMBERMEME .claude/settings.json Startup Hook Persistence

## Description

Detects post-compromise modification of `.claude/settings.json` files in code repositories by MIDNIGHT NEPTUNE (suspected DPRK), which delivers the SOMBERMEME backdoor via Claude Code's legitimate hooks mechanism. Claude Code's `settings.json` supports `hooks` that execute shell commands on lifecycle events (session start, before/after tool calls). After gaining repository access, MIDNIGHT NEPTUNE adds a startup hook that downloads and executes SOMBERMEME; any developer who opens the repository in Claude Code automatically runs the malicious command.

Specifically detects: (1) writes to `.claude/settings.json` files from unexpected processes; (2) child processes spawned by claude/claude-code that perform network operations (curl, wget, PowerShell downloads); (3) unusual process chains starting from the Claude Code parent.

False positives: Legitimate `.claude/settings.json` modifications occur when developers configure hooks for authorized automation; tune on expected parent processes (e.g., git, code editors). Detections for curl/wget spawned by claude are higher confidence and require investigation.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Event Triggered Execution |
| Technique ID | T1546 |

**Secondary Techniques:** T1195.002 (Supply Chain Compromise — shared repo commit), T1566 (Phishing — initial access via fake recruiter/ClickFix), T1036 (Masquerading — PATs named after Copilot), T1204.002 (User Execution — developer opens repository)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name="claude" OR Processes.parent_process_name="claude-code"
         OR Processes.parent_process="*claude*")
    AND (Processes.process_name="curl" OR Processes.process_name="wget"
         OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe"
         OR Processes.process_name="cmd.exe" OR Processes.process_name="sh"
         OR Processes.process_name="bash" OR Processes.process_name="python3"
         OR Processes.process_name="python")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)curl|wget") AND match(process,"(?i)http"), 95,
    match(process_name,"(?i)powershell|pwsh") AND match(process,"(?i)http|download|iwr|invoke-web"), 95,
    match(process_name,"(?i)cmd") AND match(process,"(?i)http"), 85,
    match(process_name,"(?i)python") AND match(process,"(?i)http|urllib|requests"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Claude spawns curl/wget making HTTP request | 95 | Direct SOMBERMEME delivery pattern; claude spawning download tools is not normal behavior |
| Claude spawns PowerShell with download commands | 95 | PowerShell download cradle from Claude parent indicates malicious hook execution |
| Claude spawns cmd.exe/sh with HTTP connection | 85 | Strong indicator of malicious startup hook; legitimate hooks would use native claude tooling |
| `.claude/settings.json` written by non-editor process | 70 | Unexpected writer (not VSCode, vim, etc.) suggests automated or adversarial modification |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| MIDNIGHT NEPTUNE (suspected DPRK) | [GTIG AI Threat Tracker Nov 16 2026](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold) |
| MIDNIGHT NEPTUNE prior activity | [GTIG Supply Chain UNC6780 Jul 2026](../../../threat-intel/2026-07-30_google-gtig-supply-chain-unc6780-midnight-neptune-unc4899.md) |

## References

- [GTIG AI Threat Tracker: Agentic Threat Activity Crosses a Significant Threshold](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold)
- [SOMBERMEME / MIDNIGHT NEPTUNE explainer — ExplainX](https://explainx.ai/blog/google-gtig-sombermeme-claude-code-settings-backdoor-november-2026)
- [Bromure: The settings file was the dropper](https://bromure.io/en/blog/the-settings-file-was-the-dropper)
- [MITRE ATT&CK T1546 — Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
- [MITRE ATT&CK T1195.002 — Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/002/)
- [Claude Code hooks documentation](https://docs.anthropic.com/en/docs/claude-code/hooks)
