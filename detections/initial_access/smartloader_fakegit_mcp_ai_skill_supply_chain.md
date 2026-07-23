# SmartLoader FakeGit — Malicious GitHub Repos Impersonating MCP Servers and AI Skills

## Description

Detects installation of trojanized packages from the SmartLoader FakeGit campaign, in which attackers created 7,600–9,330 malicious GitHub repositories impersonating legitimate AI skill packages and MCP (Model Context Protocol) servers. The most documented cluster cloned the legitimate Oura Ring MCP server and submitted the trojanized version to public MCP registries, where it accumulated installs before removal. The release archive contained a hidden `resource.txt` — a heavily obfuscated LuaJIT script. npm and pip `postinstall` hooks invoked LuaJIT with this script, which deployed the SmartLoader downloader to `%LOCALAPPDATA%` and configured two scheduled tasks for persistence. SmartLoader then loaded StealC as its secondary payload.

The campaign represents a strategic pivot by the SmartLoader gang from piracy-site distribution to direct targeting of developer and AI practitioner environments, where credentials carry high monetary value (cloud API keys, crypto wallets, CI/CD tokens).

Detection focuses on three signals:
1. `npm install` or `pip install` commands referencing GitHub-hosted MCP server / AI skill repos
2. LuaJIT or Lua interpreter spawned as a child of npm, node, pip, or python (the postinstall hook vector)
3. Matched known-malicious package names or file hashes from the campaign

False positives: Developers who legitimately use Lua-based npm packages or pip packages that invoke Lua; filter with allowlisted packages in query 2. `npm install <github-repo>` installs are common in developer environments — tune query 1 with asset group scoping to non-developer endpoints or use the process-ancestry and LuaJIT child signals for higher confidence.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Primary Tactic | Initial Access |
| Primary Tactic ID | TA0001 |
| Primary Technique | Supply Chain Compromise: Compromise Software Dependencies and Development Tools |
| Primary Technique ID | T1195.001 |
| Secondary Tactic | Execution |
| Secondary Technique | Command and Scripting Interpreter: JavaScript (npm postinstall hook) |
| Secondary Technique ID | T1059.007 |
| Secondary Technique (2) | User Execution: Malicious File |
| Secondary Technique ID (2) | T1204.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery (malicious GitHub repo install via npm/pip) |
| Exploitation (postinstall hook executes LuaJIT dropper) |

## Splunk Detection Queries

### Query 1: npm/pip Install from GitHub MCP or AI-Skill URL

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("npm", "npm.cmd", "npx", "npx.cmd", "pip", "pip3", "pip.exe")
  AND (Processes.process LIKE "%github.com%mcp%"
       OR Processes.process LIKE "%github.com%ai-skill%"
       OR Processes.process LIKE "%github.com%oura%"
       OR Processes.process LIKE "%github.com%skill-server%"
       OR Processes.process LIKE "%github.com%agent-tool%"
       OR Processes.process LIKE "%git+https://github.com%"
       OR Processes.process LIKE "%install%github.com%")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)oura.*mcp|mcp.*oura"), 95,
    match(process, "(?i)github\.com.*(mcp|ai.?skill|agent.?tool|skill.?server)"), 75,
    match(process, "(?i)git\+https://github\.com"), 60,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 2: Known SmartLoader File Hashes in Endpoint Filesystem

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_hash IN (
    "87de3e5a8ef669589c421220cd392ae8027a8f8d3cd97d35ac339f87dcff12c8",
    "c36e15f0532569d789ba9fdbfccf6a1bb5ac2c75",
    "2a2ef9cd83bdb635bb3da2fe6b6a42c9b0cc657f",
    "43eae0fb588987107a4805ecd1cf5c301263643b")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_hash Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100, note="Confirmed SmartLoader hash — full IR response warranted"
| table firstTime lastTime dest user file_path file_hash action risk_score note
```

### Query 2b: DNS Resolution of SmartLoader C2 Domain

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("pasteflawwed.world", "www.pasteflawwed.world")
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100, note="Confirmed SmartLoader C2 domain — FakeGit July 2026 campaign; full IR response warranted"
| table firstTime lastTime src query answer risk_score note
```

### Query 3: resource.txt Created or Modified in npm Package Directory

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.process_name IN ("node.exe", "node", "npm", "npm.cmd")
  AND (Filesystem.file_name="resource.txt"
       OR Filesystem.file_path LIKE "%node_modules%resource.txt%")
  AND Filesystem.action IN ("created", "write")
by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85, note="resource.txt created by node — matches SmartLoader Lua payload delivery pattern"
| table firstTime lastTime dest user process_name file_path action risk_score note
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Known SmartLoader Lua script hash on disk | 100 | Confirmed IOC; binary match leaves no ambiguity; full IR response |
| npm/pip install of Oura MCP GitHub URL | 95 | The most-documented SmartLoader campaign vector; no legitimate install of this specific cloned repo |
| resource.txt created by node/npm in package directory | 85 | Matches SmartLoader payload delivery pattern; low FP rate outside of this specific campaign |
| npm/pip install from generic GitHub MCP/AI-skill URL | 75 | High-risk delivery vector; correlate with LuaJIT child process or Polygon C2 signals |
| npm/pip install from any github.com URL via git+https | 60 | Anomalous on managed endpoints; low-signal alone, high-signal when combined with Lua execution |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| SmartLoader Gang (financially motivated, attribution TBD) | [The Hacker News — SmartLoader Oura MCP (2026-02)](https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html), [Hexastrike Analysis](https://hexastrike.com/resources/blog/threat-intelligence/cloned-loaded-and-stolen-how-109-fake-github-repositories-delivered-smartloader-and-stealc/) |
| StealC (MaaS infostealer, secondary payload) | [SOC Prime — SmartLoader Analysis](https://socprime.com/active-threats/smartloader-analysis/), [Bitsight — StealC Infrastructure](https://www.bitsight.com/blog/bitsight-aids-disruption-efforts-on-amadey-malware-and-stealc-malware) |

## Wazuh Detection Rules

**Rule file:** `wazuh/rules/staged/smartloader_fakegit_mcp_supply_chain.xml`
**Rule IDs:** 104058–104065

| Rule ID | Level | Description |
|---------|-------|-------------|
| 104058 | 14 | LuaJIT spawned by node.exe/npm on Windows (T1195.001, T1059.007) |
| 104059 | 13 | LuaJIT spawned by python/pip on Windows (T1195.001, T1059.007) |
| 104060 | 14 | LuaJIT writing file to %LOCALAPPDATA% masquerade path (T1036.005) |
| 104061 | 14 | schtasks.exe spawned by LuaJIT — SmartLoader persistence (T1053.005) |
| 104062 | 14 | Non-browser process connecting to Polygon JSON-RPC endpoint (T1102.002, T1568) |
| 104063 | 15 | FIM: SmartLoader Lua script IOC hash match (SHA1) — confirmed compromise |
| 104064 | 14 | Linux/macOS auditd: LuaJIT spawned by npm/node/pip (T1195.001, T1059.007) |
| 104065 | 15 | FIM: LuaJIT binary created in LOCALAPPDATA AudioManager/OfficeUpdate path |

## References

- [The Hacker News — SmartLoader Attack Uses Trojanized Oura MCP Server (2026-02)](https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html)
- [Hexastrike — 109 Fake GitHub Repos Deliver SmartLoader and StealC](https://hexastrike.com/resources/blog/threat-intelligence/cloned-loaded-and-stolen-how-109-fake-github-repositories-delivered-smartloader-and-stealc/)
- [SOC Prime — SmartLoader Analysis](https://socprime.com/active-threats/smartloader-analysis/)
- [Straiker — SmartLoader Clones Oura Ring MCP](https://www.straiker.ai/blog/smartloader-clones-oura-ring-mcp-to-deploy-supply-chain-attack)
- [GBHackers — 109 Fake GitHub Repos Spread SmartLoader, StealC](https://gbhackers.com/109-fake-github-repos/)
- [byteiota — 10,000 Trojan GitHub Repos Targeting AI Agents](https://byteiota.com/10000-trojan-github-repos-are-targeting-ai-agents-audit-your-dependencies-now/)
- [MITRE ATT&CK — T1195.001: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK — T1059.007: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
