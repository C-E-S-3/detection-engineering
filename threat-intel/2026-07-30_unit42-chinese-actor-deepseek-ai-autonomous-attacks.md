---
scraped_at: "2026-07-31T08:00:00Z"
source_url: https://unit42.paloaltonetworks.com/autonomous-ai-cyber-attack-campaign/
report_type: threat-intel
severity: high
title: "Chinese-Speaking Threat Actor (knaithe/KnYuan) Uses DeepSeek + Hermes Agent for Autonomous Cyberattacks"
---

# Chinese-Speaking Threat Actor (knaithe/KnYuan) Uses DeepSeek + Hermes Agent for Autonomous Cyberattacks

Unit 42 published July 30, 2026 documenting one of the first confirmed real-world cases of an AI reasoning model autonomously orchestrating an intrusion end-to-end — from target enumeration through exploit selection to data exfiltration — without continuous human direction.

## 1. IOCs

No confirmed network-level IOCs published. The actor's OPSEC failure (HTTP file server exposed from /home/worker) revealed operation files to Unit 42 researchers, but specific IPs, domains, or hashes have not been released publicly.

## 2. Threat Actor

- **Aliases:** knaithe, KnYuan (Chinese-speaking operator)
- **Attribution:** Chinese-speaking based on language artifacts and operational patterns; no formal nation-state attribution
- **Framework:** Hermes Agent (open-source) + DeepSeek AI model as autonomous reasoning engine
- **C2 orchestration:** Telegram (operator sends high-level commands; AI executes the rest autonomously)

## 3. Campaign Details

### Attack Framework

| Component | Role |
|-----------|------|
| Hermes Agent | Terminal access, Telegram C2 integration, "skills" plugin system |
| DeepSeek (AI) | Autonomous reasoning: target selection, code generation, vulnerability assessment, pivot decisions |
| Telegram | C2 channel for operator → Hermes Agent commands |

### Scale and Confirmed Outcomes
- Approximately 460 attempted targets across the campaign
- 3 confirmed successful compromises (all Citrix NetScaler appliances)
- All three involved memory data exfiltration; suspected session hijacking against a Malaysian government entity
- One recovered Hermes Agent session log from May 7, 2026

### OPSEC Failure That Exposed the Campaign
The Hermes Agent, responding to a Telegram command, launched an HTTP file server from `/home/worker` instead of a sandboxed directory, inadvertently exposing the entire operation's file structure to Unit 42 researchers.

## 4. TTPs

| Tactic | Technique ID | Technique | Notes |
|--------|-------------|-----------|-------|
| Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning | AI autonomously enumerated ~460 targets |
| Initial Access | T1190 | Exploit Public-Facing Application | Multiple CVEs (see below) |
| Execution | T1059.006 | Command and Scripting Interpreter: Python | Hermes Agent uses Python for terminal access |
| Collection | T1005 | Data from Local System | Memory data exfiltrated from Citrix NetScaler |
| Command and Control | T1102.002 | Web Service: Bidirectional Communication | Telegram used as C2 channel |

## 5. Vulnerabilities Targeted

| CVE | Product | Status | CVSS |
|-----|---------|--------|------|
| CVE-2026-3055 | Citrix NetScaler | **Confirmed exploitation** — memory data exfiltration | — |
| CVE-2026-34486 | Apache Tomcat | Targeted | — |
| CVE-2026-39987 | Marimo Notebook | Targeted | — |
| CVE-2026-33824 | Windows IKE VPN Extensions | Targeted | — |
| CVE-2026-33017 | Langflow | Autonomously identified (CVSS 9.8); AI abandoned and pivoted to higher-value target | 9.8 |
| CVE-2026-0300 | PAN-OS | Research only; no confirmed exploitation | 9.3 |

## 6. Significance

This campaign represents a qualitative shift in attacker capability:
- AI performs autonomous decision loops: enumerate → select exploit → execute → assess result → pivot
- Human operator provides only high-level goals via Telegram; AI fills in all tactical steps
- Attack is self-correcting: when CVE-2026-33017 exploitation proved unproductive, the AI independently pivoted to a higher-value target
- Scale becomes cheaper: one operator can direct attacks against hundreds of targets simultaneously

## 7. References

- [Unit 42 — Chinese-Speaking Threat Actor Harnesses AI Models for Autonomous Cyberattacks](https://unit42.paloaltonetworks.com/autonomous-ai-cyber-attack-campaign/)
- [GBHackers — Chinese-Speaking Hacker Uses DeepSeek Agent to Launch Autonomous Cyberattacks](https://gbhackers.com/hacker-uses-deepseek-agent/)
- [The Hacker News — ThreatsDay coverage](https://thehackernews.com/2026/07/threatsday-ai-powered-hacking-370.html)
