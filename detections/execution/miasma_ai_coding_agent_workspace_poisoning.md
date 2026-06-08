# Miasma AI Coding Agent Workspace Poisoning

## Description

Detects indicators of the Miasma supply chain worm's novel AI coding agent workspace poisoning technique, where malicious commits to GitHub repositories plant configuration files that auto-execute a credential-harvesting JavaScript payload when a developer opens the repository in Claude Code, Gemini CLI, Cursor, or VS Code.

The Miasma worm (variant of Mini Shai-Hulud, assessed to be TeamPCP/UNC6780 tooling) compromised 73 Microsoft Azure GitHub repositories on June 5, 2026 using this technique. The planted configuration files trigger payload execution at repository load time — before the developer can review the code — making this a particularly dangerous pre-review execution vector. The JavaScript payload (4.6 MB, heavily obfuscated) harvests all available developer credentials (AWS, Azure, GCP, Kubernetes, npm, GitHub tokens) and exfiltrates them to attacker-controlled public GitHub repositories.

Three detection rules are provided:
1. Credential file access from AI coding agent processes (highest fidelity)
2. Suspicious HTTP POST from developer hosts to GitHub after repository operations
3. Shell interpreter spawned from AI coding agent parent processes

False positives for rule 1 are possible when developers legitimately configure cloud profiles; context of recent git clone/pull events significantly increases confidence. Rules 2 and 3 are higher-noise but catch post-execution exfiltration.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: JavaScript |
| Technique ID | T1059.007 |

Secondary techniques: T1195.001 (Supply Chain Compromise: Software Dependencies), T1552.001 (Unsecured Credentials: Credentials In Files), T1567.001 (Exfiltration to Code Repository)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*\\.aws\\credentials"
    OR Filesystem.file_path="*/.ssh/id_rsa" OR Filesystem.file_path="*\\.ssh\\id_rsa"
    OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.kube/config"
    OR Filesystem.file_path="*/.azure/accessTokens.json"
    OR Filesystem.file_path="*\\.azure\\accessTokens.json")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)cursor|claude|gemini-cli|code"), 92,
    match(process_name,"(?i)bun|node"), 75,
    match(process_name,"(?i)python|python3"), 65,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user process_name file_path risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name IN ("cursor.exe","claude.exe","code.exe","node.exe","bun.exe"))
    AND Processes.process_name IN ("cmd.exe","powershell.exe","powershell","bash","sh","python.exe","python3","python")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.http_method=POST AND Web.dest="api.github.com"
    AND Web.bytes_out > 20000
  by Web.src Web.dest Web.uri_path Web.http_user_agent Web.bytes_out
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(uri_path,"(?i)liuende501"), 97,
    bytes_out > 500000, 85,
    bytes_out > 50000, 70,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest uri_path http_user_agent bytes_out risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| AI coding agent process accessing ~/.aws/credentials or similar credential file | 92 | Highly anomalous — legitimate AI coding agents do not need direct access to raw credential files |
| node/bun accessing credential files | 75 | Possible legitimate use; high suspicion when combined with recent git activity |
| Python accessing credential files | 65 | Broader legitimate use; suspicious in context of recent repository open event |
| AI coding agent spawning shell interpreter (cmd, powershell, bash, sh) | 90 | Legitimate AI agents may spawn shells but harvesting pattern (accessing credential paths) distinguishes malicious activity |
| HTTP POST to api.github.com targeting liuende501 repos | 97 | Direct IOC match; known Miasma exfiltration dead-drop account |
| Large HTTP POST (>500 KB) to api.github.com | 85 | Unusual upload size to GitHub API from developer workstation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| TeamPCP (UNC6780) — Miasma worm operator | [The Hacker News — Miasma Worm Hits 73 Microsoft GitHub Repositories](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html) |
| TeamPCP (UNC6780) — Mini Shai-Hulud (progenitor worm) | [Wiz — Mini Shai-Hulud Strikes Again: TanStack and More npm Packages Compromised (2026-05-17)](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised) |

## References

- [The Hacker News — Miasma Worm Hits 73 Microsoft GitHub Repositories in Major Supply Chain Attack (2026-06-06)](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)
- [SafeDep — Miasma Worm Targets AI Coding Agents via GitHub Repos](https://safedep.io/miasma-worm-ai-coding-agent-config-injection/)
- [StepSecurity — Miasma npm Supply Chain Attack: Self-Spreading Worm via Phantom Gyp](https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm)
- [OpenSourceMalware — The Blight Reaches Microsoft: 73 Repos Disabled in 105 Seconds](https://opensourcemalware.com/blog/miasma-reaches-azure)
- [MITRE ATT&CK — T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK — T1195.001 Supply Chain Compromise: Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
