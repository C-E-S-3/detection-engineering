---
scraped_at: 2026-07-22T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/fakegit-campaign-uses-7-600-github-repos-to-push-smartloader-malware/
report_type: threat-intel
severity: high
title: "FakeGit Campaign Scales to 7,600 Malicious GitHub Repos Delivering SmartLoader — New C2 Domain and Hash"
---

## 1. IOCs

### SHA256 Hashes

| Hash | Description |
|------|-------------|
| `87de3e5a8ef669589c421220cd392ae8027a8f8d3cd97d35ac339f87dcff12c8` | SmartLoader LuaJIT 2.1.0-beta3 PE binary (GUI subsystem); PE compile timestamp 2026-04-10 20:06 UTC; dropped to %LOCALAPPDATA% masquerade path by postinstall hook in FakeGit repos; variant active in the July 2026 campaign wave |

### Domains (C2 Infrastructure)

| Domain | Description |
|--------|-------------|
| `pasteflawwed[.]world` | SmartLoader primary C2 domain; HTTP callback for SmartLoader LuaJIT binary; registered for July 2026 campaign wave; fallback C2 is a hardcoded Polygon blockchain smart contract address (cannot be sinkholed) |

## 2. TTPs

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | 7,600+ malicious GitHub repositories impersonate legitimate npm packages, pip packages, AI skills, and MCP (Model Context Protocol) servers; victims install via `npm install <github-url>` or `pip install` |
| Execution | T1059.007 | Command and Script Interpreter: JavaScript | npm/pip postinstall hook extracts and executes obfuscated LuaJIT script (`resource.txt`) immediately after package installation, without further user interaction |
| Execution | T1204.002 | User Execution: Malicious File | Victim executes `npm install` or `pip install` on a malicious package believing it to be a legitimate MCP server or AI skill; "AgentBaiting" technique targets AI coding agents instructed to install MCP tools from public registries |
| Defense Evasion | T1027.001 | Obfuscated Files or Information: Binary Padding | SmartLoader release archives artificially padded to exceed 1 GB; bypasses antivirus and automated sandbox scanning (many sandboxes skip or abort analysis of files over 1 GB) |
| Defense Evasion | T1497.001 | Virtualization/Sandbox Evasion: System Checks | SmartLoader invokes Windows `findstr` utility to detect sandbox indicators in environment strings and running process list before executing primary payload |
| Defense Evasion | T1036.004 | Masquerading: Masquerade Task or Service | 800+ FakeGit repositories impersonate AI skills and MCP server implementations (Oura Ring MCP, generic agent-tool packages) and submit to public MCP registries; appear legitimate to AI coding agents searching for tool integrations |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | SmartLoader beacons to `pasteflawwed[.]world` over HTTP for payload delivery instructions |
| Command and Control | T1102.002 | Web Service: Bidirectional Communication | Hardcoded Polygon blockchain smart contract polled as fallback C2; operator encodes instructions in contract state; sinkhole-resistant because Polygon address cannot be seized via DNS intervention |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | StealC secondary payload harvests browser-stored credentials, cookies, and saved passwords |
| Credential Access | T1528 | Steal Application Access Token | StealC and Lumma Stealer secondary payloads harvest cloud provider API keys, LLM API keys, and cryptocurrency wallet credentials from developer workstations |

## 3. Malware & Tools

### SmartLoader

A LuaJIT 2.1.0-beta3 compiled PE binary (GUI subsystem) used as the primary downloader and C2 agent. The July 2026 variant (SHA256 `87de3e5a8ef669589c421220cd392ae8027a8f8d3cd97d35ac339f87dcff12c8`, PE timestamp 2026-04-10) is delivered from GitHub Release assets attached to FakeGit repository releases. SmartLoader performs environmental checks via `findstr` to detect sandbox analysis environments before executing. It beacons to `pasteflawwed[.]world` for primary C2 instructions. When the HTTP endpoint is unavailable, it falls back to polling a hardcoded Polygon blockchain smart contract for instructions encoded in contract state. After C2 registration, SmartLoader drops StealC or Lumma Stealer as its secondary payload.

### AgentBaiting (Campaign Technique)

FakeGit repos in this campaign specifically target AI coding agents (Cursor, GitHub Copilot, Claude Code, Gemini CLI) that scan MCP registries for tool integrations. 800+ malicious repos are crafted to appear as legitimate MCP server implementations, complete with README documentation, semantic versioning, and star farming. AI agents instructed to "install relevant MCP tools" or "set up development environment" may autonomously execute `npm install <malicious-github-url>` without explicit user approval. This "AgentBaiting" technique bypasses traditional delivery models that depend on human victim decision-making.

### Delivery Infrastructure

At its July 2026 peak, the FakeGit campaign operates 7,600 malicious GitHub repositories accumulating 14 million+ total GitHub Release asset downloads. The original February 2026 campaign wave used 109 repositories; the campaign scaled 70x by exploiting GitHub's fork and release infrastructure. Release archives are deliberately padded to exceed 1 GB to evade automated scanning. The actual malicious payload (`resource.txt`, a LuaJIT script) is embedded inside the archive and extracted by the postinstall hook.

### StealC

Commodity infostealer MaaS (Malware-as-a-Service) deployed as SmartLoader's primary secondary payload. Harvests browser credentials, cookies, and cryptocurrency wallets.

### Lumma Stealer

Additional infostealer secondary payload observed in July 2026 campaign wave alongside StealC. Lumma Stealer targets developer-specific credentials including cloud provider credentials, LLM API keys, CI/CD tokens, and SSH keys — consistent with the campaign's strategic pivot to targeting developers and AI practitioners.

## 4. Threat Actor / Campaign Attribution

**Campaign:** FakeGit (SmartLoader Gang)

**Motivation:** Financially motivated; targeting developer and AI practitioner credentials with high monetary value — cloud API keys, LLM API keys, cryptocurrency wallets, CI/CD tokens

**Attribution:** No firm nation-state attribution; operational patterns consistent with cybercrime MaaS operations. The Polygon blockchain C2 follows a pattern previously observed in EtherHiding (used by WeedHack MaaS) and Starland RAT (UAT-11795), suggesting awareness of and adaptation from public research.

**Campaign evolution:**
- **February 2026:** Initial 109-repository campaign; trojanized Oura Ring MCP server clone; discovered by Hexastrike; original SHA1 hashes documented
- **April 2026:** New SmartLoader binary compiled (PE timestamp 2026-04-10); `pasteflawwed[.]world` C2 domain registered; Lumma Stealer added as secondary payload alongside StealC
- **July 2026:** Campaign scaled to 7,600+ repositories; 14 million+ GitHub Release downloads; AgentBaiting technique explicitly targeting AI coding agent MCP registries; 800+ repos crafted as AI skill impersonators

**Target profile:** Developer workstations; AI practitioners; CI/CD systems; cryptocurrency holders

## 5. Splunk Detection Searches

### Query 1: DNS Resolution of SmartLoader C2 Domain

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("pasteflawwed.world", "www.pasteflawwed.world")
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100, note="Confirmed SmartLoader C2 domain — FakeGit July 2026 campaign"
| table firstTime lastTime src query answer risk_score note
```

### Query 2: SmartLoader SHA256 Hash Match in Filesystem

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_hash IN (
    "87de3e5a8ef669589c421220cd392ae8027a8f8d3cd97d35ac339f87dcff12c8")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_hash Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100, note="Confirmed SmartLoader LuaJIT binary hash — July 2026 FakeGit campaign wave"
| table firstTime lastTime dest user file_path file_hash action risk_score note
```

### Query 3: npm/pip Install from GitHub MCP or AI-Skill URL Pattern

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("npm", "npm.cmd", "npx", "npx.cmd", "pip", "pip3", "pip.exe")
  AND (Processes.process LIKE "%github.com%mcp%"
       OR Processes.process LIKE "%github.com%ai-skill%"
       OR Processes.process LIKE "%github.com%agent-tool%"
       OR Processes.process LIKE "%github.com%skill-server%"
       OR Processes.process LIKE "%git+https://github.com%")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)github\.com.*(mcp|ai.?skill|agent.?tool|skill.?server)"), 75,
    match(process, "(?i)git\+https://github\.com"), 60,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 4: LuaJIT Spawned by npm, pip, or Node as Postinstall Hook

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("lua51.exe", "luajit.exe", "lua.exe", "lua5.1.exe")
  AND Processes.parent_process_name IN ("node.exe", "npm", "npm.cmd", "python.exe", "pip", "pip3")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90, note="LuaJIT spawned by package manager — matches SmartLoader FakeGit postinstall hook vector"
| where risk_score >= 90
| table firstTime lastTime dest user parent_process_name process_name process risk_score note
```

## 6. Executive Summary

On July 21–22, 2026, BleepingComputer reported that the FakeGit SmartLoader campaign has scaled to 7,600+ malicious GitHub repositories accumulating 14 million+ total downloads of poisoned release archives. The campaign originated in February 2026 with 109 repositories impersonating the legitimate Oura Ring MCP (Model Context Protocol) server; it has since diversified to impersonate hundreds of AI skill packages and MCP server implementations, with 800+ repositories specifically crafted to appear in MCP registry search results — a technique researchers have named "AgentBaiting" because it targets AI coding agents (Cursor, Claude Code, GitHub Copilot) that autonomously install MCP tool integrations without per-install user confirmation.

The July 2026 variant introduces a new SmartLoader LuaJIT binary (SHA256 `87de3e5a8ef669589c421220cd392ae8027a8f8d3cd97d35ac339f87dcff12c8`, PE compile timestamp 2026-04-10 20:06 UTC) and a new primary C2 domain (`pasteflawwed[.]world`), both previously untracked in this repository. SmartLoader continues to use a hardcoded Polygon blockchain smart contract as a sinkhole-resistant C2 fallback channel. Release archives are deliberately padded to exceed 1 GB to evade antivirus and sandbox scanning. Secondary payloads include StealC and Lumma Stealer, both targeting high-value developer credentials (cloud API keys, LLM API keys, CI/CD tokens, cryptocurrency wallets). New IOCs (`pasteflawwed[.]world` and the July 2026 SHA256 hash) have been added to the repository IOC CSVs.

## References

- [BleepingComputer — FakeGit Campaign Uses 7,600 GitHub Repos to Push SmartLoader (2026-07-22)](https://www.bleepingcomputer.com/news/security/fakegit-campaign-uses-7-600-github-repos-to-push-smartloader-malware/)
- [Hexastrike — 109 Fake GitHub Repos Deliver SmartLoader and StealC (2026-02)](https://hexastrike.com/resources/blog/threat-intelligence/cloned-loaded-and-stolen-how-109-fake-github-repositories-delivered-smartloader-and-stealc/)
- [The Hacker News — SmartLoader Attack Uses Trojanized Oura MCP Server (2026-02)](https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html)
- [Detection: SmartLoader FakeGit MCP AI Skill Supply Chain](../detections/initial_access/smartloader_fakegit_mcp_ai_skill_supply_chain.md)
- [MITRE ATT&CK — T1195.001: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK — T1102.002: Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK — T1027.001: Binary Padding](https://attack.mitre.org/techniques/T1027/001/)
