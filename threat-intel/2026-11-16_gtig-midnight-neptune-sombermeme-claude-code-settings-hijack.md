---
scraped_at: 2026-11-21T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold
report_type: threat-intel
severity: high
title: "MIDNIGHT NEPTUNE (DPRK) SOMBERMEME Backdoor via .claude/settings.json Developer Supply Chain Compromise"
---

# MIDNIGHT NEPTUNE (DPRK) SOMBERMEME Backdoor via .claude/settings.json Developer Supply Chain Compromise

**Source:** Google Threat Intelligence Group (GTIG)
**Published:** 2026-11-16
**Note:** The underlying GTIG article covers agentic AI threats broadly; this report focuses on the SOMBERMEME/MIDNIGHT NEPTUNE campaign embedded in that article, which was not captured in the November 16 processing run. The exploit_agent and CAIRN content is in the existing file `2026-11-16_gtig-ai-threat-tracker-exploit-agent-autonomous-patch-to-exploit.md`.
**Severity:** High

---

## 1. IOCs

### File / Configuration Artifacts

| Artifact | Type | Context |
|---------|------|---------|
| `.claude/settings.json` | Configuration file | Modified by MIDNIGHT NEPTUNE post-compromise to add malicious hook commands that download SOMBERMEME when Claude Code starts |
| SOMBERMEME | Backdoor | Specific malware name; downloaded via `.claude/settings.json` startup hook; targets cryptocurrency organizations |

### Social Engineering Artifacts

| Artifact | Context |
|---------|---------|
| Fake recruiter profile images with SynthID watermarks | LLM-synthesized imagery used in fake LinkedIn/email recruiter personas targeting crypto developers |
| ClickFix video-meeting lures | Fake video meeting verification flows prompting targets to run diagnostic scripts |
| GitHub PATs named after Microsoft Copilot | Personal Access Tokens created by MIDNIGHT NEPTUNE named to blend in with legitimate Copilot integration tokens |

> **Note:** No specific network IOCs (domains, IPs, hashes) were published in the GTIG article. For C2 infrastructure, check subsequent GTIG/Mandiant bulletins.

---

## 2. TTPs

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566 | Phishing | Fake recruiter profiles and ClickFix video-meeting lures targeting cryptocurrency developers |
| Initial Access | T1566.003 | Spearphishing via Service | LLM-generated fake recruiter personas on professional networks; SynthID-watermarked profile photos |
| Initial Access | T1204.002 | User Execution: Malicious File | ClickFix lures prompt users to run "diagnostic fix" scripts |
| Persistence | T1176 | Browser Extensions | `.claude/settings.json` modification — a startup hook triggers malware download when Claude Code initializes in the project |
| Persistence | T1546 | Event Triggered Execution | Claude Code `hooks` in `settings.json` auto-execute on session start; MIDNIGHT NEPTUNE abuses this to persist across any developer who opens the compromised repository |
| Supply Chain | T1195.002 | Compromise Software Supply Chain | Single `.claude/settings.json` commit to a shared internal repository propagates SOMBERMEME to every developer who opens the project |
| Defense Evasion | T1036 | Masquerading | GitHub PATs named to resemble legitimate Microsoft Copilot tokens |
| Defense Evasion | T1027 | Obfuscated Files or Information | LLM-synthesized profile images include deliberate camera artifacts and no background text to avoid synthetic-image detection |
| Credential Access | T1552.001 | Credentials in Files | Public GitHub repository credential harvesting |
| Resource Development | T1583 | Acquire Infrastructure | LLM services and underground resellers used for social engineering content generation |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| **SOMBERMEME** | Backdoor | DPRK-linked backdoor delivered via Claude Code `.claude/settings.json` hook modification; triggered on Claude Code startup in compromised repository; targeting cryptocurrency organizations |
| **Claude Code `hooks` mechanism** | Legitimate developer tool (abused) | Claude Code `settings.json` supports `hooks` that execute shell commands on events (session start, tool call, etc.); MIDNIGHT NEPTUNE abuses `PreToolUse`/startup hooks to trigger malicious downloads |

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|-----------|-------|
| GTIG cluster name | MIDNIGHT NEPTUNE |
| Prior tracking | MIDNIGHT NEPTUNE is a suspected DPRK cluster; overlaps with Lazarus Group IT worker operations |
| Motivation | Financial — targets cryptocurrency organizations in North America and Europe |
| Campaign method | Post-compromise `.claude/settings.json` hook tampering in internal repositories |
| Victim sector | Cryptocurrency organizations (North America, Europe) |
| Attribution confidence | Suspected DPRK (GTIG) |
| Prior file | See `2026-07-30_google-gtig-supply-chain-unc6780-midnight-neptune-unc4899.md` for earlier MIDNIGHT NEPTUNE context |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*/.claude/settings.json"
    OR Filesystem.file_path="*\\.claude\\settings.json"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| table firstTime lastTime dest user process_name file_path risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="claude" OR Processes.parent_process_name="claude-code"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where process_name!="node" AND process_name!="git" AND process_name!="bash"
    AND process_name!="sh" AND process_name!="zsh" AND process_name!="python3"
| eval risk_score=case(
    match(process_name,"(?i)curl|wget|powershell|pwsh|cmd|mshta|wscript|cscript|regsvr32|rundll32"), 90,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="curl" OR Processes.process_name="wget"
         OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe")
    AND (Processes.parent_process="*.claude*" OR Processes.parent_process="*claude-code*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

## 6. Executive Summary

Google GTIG's November 16 AI Threat Tracker update includes documentation of a suspected North Korean (DPRK) cluster tracked as MIDNIGHT NEPTUNE compromising cryptocurrency organizations in North America and Europe via a novel developer supply chain technique: post-compromise modification of `.claude/settings.json` files in shared internal code repositories.

The attack abuses Claude Code's legitimate `hooks` configuration, which allows project-level settings to execute shell commands on session lifecycle events (startup, tool calls, etc.). MIDNIGHT NEPTUNE, after gaining initial access via fake recruiter profiles and ClickFix video-meeting lures, commits a modified `settings.json` to an internal repository. Any developer who subsequently opens the project in Claude Code automatically downloads and executes the SOMBERMEME backdoor.

The technique is especially dangerous because a single repository commit propagates malware to every developer on the team simultaneously, without any further social engineering. GTIG notes this represents a maturing pattern of AI coding assistant configuration abuse — analogous to supply chain poisoning via CI/CD pipeline scripts.

**Recommended actions:** Audit all `.claude/settings.json` files in internal repositories for unexpected `hooks` commands; restrict commit access to Claude Code configuration files; monitor for child processes spawned by `claude` or `claude-code` that perform network operations (curl/wget downloads, outbound connections from unexpected parent processes).
