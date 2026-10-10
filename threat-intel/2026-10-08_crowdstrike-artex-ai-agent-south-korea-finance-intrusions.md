---
scraped_at: "2026-10-10T00:00:00Z"
source_url: "https://www.crowdstrike.com/blog/adversary-use-of-ai-coding-agents-artex-south-korea-finance/"
report_type: threat-intel
severity: high
title: "CrowdStrike: China-Based Threat Actor Uses ARTEX AI Agent to Compromise South Korean Financial Institutions"
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses

| IP | Description |
|----|-------------|
| `38.244.50[.]120` | Server hosting ARTEX AI agent instance used in South Korean financial sector intrusion campaign |

### Artifacts Found (Adversary Operational Security Failure)

CrowdStrike researchers discovered an exposed directory on threat actor infrastructure containing:
- Claude Code session history files
- ARTEX AI agent configuration files
- Claude memory files
- A Chinese-language LLM prompt document describing penetration testing methodology

No additional IPs, domains, or file hashes were published in available public reporting.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Usage |
|--------|-----------|----|-------|
| Reconnaissance | Active Scanning | T1595 | ARTEX AI agent autonomously conducted port scanning and service enumeration against bank infrastructure |
| Reconnaissance | Gather Victim Network Information | T1590 | AI agent used to identify internal network topology and enumerate service accounts |
| Initial Access | Valid Accounts | T1078 | Post-exploitation access maintained via compromised employee credentials harvested through AI-assisted phishing or credential stuffing |
| Execution | Command and Scripting Interpreter | T1059 | ARTEX agent autonomously generated and executed scripts for lateral movement and data access |
| Credential Access | Brute Force | T1110 | AI agent directed credential stuffing and password spraying attempts against banking authentication portals |
| Collection | Data from Information Repositories | T1213 | AI agent directed collection of financial transaction data and customer PII from banking systems |
| Defense Evasion | Masquerading | T1036 | AI-generated traffic and requests designed to blend with legitimate banking system interactions |
| Impact | Data Manipulation | T1565 | Financial data exfiltration from Kookmin Bank, Hana Bank, BNK Busan Bank, and others |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| **ARTEX** | AI Hacking Agent | Autonomous AI agent framework used to direct reconnaissance, exploitation, and data collection against financial sector targets; configuration files and sessions found on exposed threat actor server |
| **Claude Code** (abused) | AI Coding Tool (legitimate) | CrowdStrike found Claude Code session histories on actor infrastructure, indicating use of commercial AI coding assistants as part of intrusion toolchain |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Designation | Unattributed (no CrowdStrike adversary name assigned) |
| Suspected Origin | China (Guangdong region suspected; moderate confidence); Chinese-language penetration testing prompt document found on infrastructure |
| Motivation | Financial (data theft from banking institutions) |
| Activity Window | Late September through early October 2026 |
| Targets | South Korean financial sector: Kookmin Bank, Hana Bank, BNK Busan Bank; full scope unconfirmed |
| Infrastructure | Hong Kong-based primary server; 38.244.50[.]120 (ARTEX instance); additional IPs not published |
| AI Tool Use | ARTEX agent plus commercial Claude Code sessions; Chinese-language LLM prompt for pentesting methodology |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest="38.244.50.120"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port process_name user risk_score
```
*Detects connections to the known ARTEX infrastructure IP; high-fidelity indicator.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*/.claude/projects/*","*/.claude/sessions/*","*/CLAUDE.md")
    Filesystem.action="created" OR Filesystem.action="modified"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=50
| table firstTime lastTime dest user file_path process_name risk_score
```
*Detects creation or modification of Claude Code session and project files on servers where AI coding assistants should not be running — operator security failure indicator.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("claude","claude-code","cline","aider","cursor")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(dest,"(?i)(prod|server|srv|dc|domain)"), 80,
    true(), 40)
| where risk_score >= 40
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```
*Detects AI coding agent processes running on servers or production systems — anomalous indicator suggesting AI-assisted intrusion tooling may be deployed.*

---

## 6. Executive Summary

CrowdStrike published findings on October 7–8, 2026, documenting a financially motivated intrusion campaign against multiple South Korean banks (Kookmin Bank, Hana Bank, BNK Busan Bank) conducted by a suspected China-based threat actor. The distinguishing feature of this campaign is the use of **ARTEX**, an AI agent framework, to autonomously direct reconnaissance, credential attacks, and data collection against banking infrastructure.

CrowdStrike researchers discovered an exposed directory on threat actor infrastructure (38.244.50[.]120, Hong Kong-hosted) containing Claude Code session histories, ARTEX configuration files, and a Chinese-language LLM prompt document containing penetration testing methodology. This operational security failure allowed attribution of the AI tooling stack and provided insight into the adversary's tradecraft.

The threat actor has not been assigned a named adversary designation. Attribution to a China-based operator is assessed with moderate confidence based on language artifacts in recovered documents and Hong Kong-based infrastructure. No formal nation-state nexus has been established.

This campaign represents early observed use of autonomous AI agent frameworks as a primary intrusion tool rather than a development aid. Defenders should monitor for AI coding agent processes running in server environments, unexpected Claude Code session files on infrastructure, and outbound connections to known ARTEX infrastructure.
