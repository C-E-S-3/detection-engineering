---
scraped_at: 2026-06-08T00:00:00Z
source_url: https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html
report_type: threat-intel
severity: critical
title: "Miasma Worm Escalates to Microsoft GitHub: AI Coding Agent Workspace Poisoning Hits 73 Azure Repositories"
---

# Miasma Worm Escalates to Microsoft GitHub: AI Coding Agent Workspace Poisoning Hits 73 Azure Repositories

On June 5, 2026, the self-replicating Miasma supply chain worm — a variant of the Mini Shai-Hulud worm previously attributed to TeamPCP/UNC6780 — reached Microsoft's Azure GitHub organizations. A compromised contributor account pushed a malicious commit (5f456b8) to the `Azure/durabletask` repository containing five AI coding agent configuration files. When any developer opened the poisoned repository in Claude Code, Gemini CLI, Cursor, or VS Code, a 4.6 MB obfuscated JavaScript credential-harvesting payload executed automatically. GitHub's automated abuse detection disabled all 73 affected repositories across four Microsoft GitHub organizations (Azure, Azure-Samples, Microsoft, MicrosoftDocs) within 105 seconds. This escalation represents the first confirmed targeting of a major vendor's official GitHub organization by an AI coding agent workspace-poisoning worm.

## 1. IOCs

### File Hashes (SHA256)

| Hash | Description |
|------|-------------|
| d630397de8b01af0f6f5cf4463da91b17f28195a2c50c8f3f38ad9f7873fdb8e | Miasma obfuscated JavaScript credential-harvesting payload — icflorescu / taxepfa campaign wave; 4.6 MB |
| 3a9db5ba0c8cd4c91e91717df6b1a141fc1e0fbc0558b5a78d7f5c23f5b2a150 | Miasma payload variant — Azure/durabletask repository compromise (June 5, 2026) |
| ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90 | Miasma binding.gyp variant — Phantom Gyp npm supply chain wave; executes on native module builds |

### Network / Infrastructure Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| liuende501 (GitHub account) | Exfil dead-drop operator | GitHub account hosting 236 public repositories used as credential dump buckets; repos created with description "Miasma - The Spreading Blight" |
| github.com/liuende501/* | Exfiltration endpoint | HTTP POST of harvested developer credentials to attacker-controlled public GitHub repositories under this account |

### Targeted Configuration File Paths (Workspace Poisoning Artifacts)

Malicious commits planted configuration files that auto-execute the JS payload in the following AI coding tool contexts:

| File Path | Targeted Tool |
|-----------|-------------|
| `.cursor/rules` | Cursor IDE |
| `CLAUDE.md` | Claude Code (Anthropic CLI) |
| `.gemini/settings.json` | Gemini CLI |
| `.vscode/settings.json` | VS Code (with task runner) |
| `.copilot-instructions.md` | GitHub Copilot workspace instructions |

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Malicious commits pushed to legitimate, high-trust GitHub repositories (Azure/durabletask and 72 others) using compromised contributor accounts; developers cloning or opening these repos become victims |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | 4.6 MB obfuscated JavaScript payload auto-executes when developer opens repository in a targeted AI coding agent |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | Payload scans for and harvests AWS, Azure, GCP, Vault, Kubernetes, npm, and GitHub token credential files (~/.aws/credentials, ~/.azure/, env vars, .npmrc, kubeconfig) |
| Credential Access | T1552.007 | Unsecured Credentials: Container API | Kubernetes service account tokens and container registry credentials targeted |
| Lateral Movement / Propagation | T1080 | Taint Shared Content | Worm uses stolen GitHub tokens from victim environments to push copies of the malicious workspace config files to other repositories the victim has write access to, enabling self-replication |
| Exfiltration | T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository | Harvested credentials POSTed to attacker-controlled public GitHub repositories under the liuende501 account; repos are ephemeral credential dump buckets |
| Defense Evasion | T1027 | Obfuscated Files or Information | 4.6 MB JavaScript payload is heavily obfuscated; binding.gyp variant triggers only during native module builds to evade automated scanning |
| Resource Development | T1586.003 | Compromise Accounts: Cloud Accounts | Worm self-replicates using stolen GitHub OAuth tokens from victim developer environments; each new victim's tokens enable further repository poisoning |

## 3. Malware & Tools

| Component | Type | Description |
|-----------|------|-------------|
| Miasma Worm | Self-replicating supply chain worm | AI coding agent workspace poisoning variant; variant of Mini Shai-Hulud (TeamPCP, mid-May 2026); plants AI tool config files in GitHub repos; auto-executes JS credential harvester when developer opens repo in Claude Code, Gemini CLI, Cursor, or VS Code |
| Bun Stealer (payload) | Multi-cloud credential harvester | Decrypted payload family underlying both Miasma and Mini Shai-Hulud waves; targets AWS, Azure, GCP, Vault, Kubernetes, npm, and GitHub secrets; scans entire developer filesystem for credential files; exfiltrates to public GitHub dead-drop repos |
| Phantom Gyp Variant | npm native module payload | Variant delivering the Bun Stealer via malicious `binding.gyp` in npm packages; triggers on native module compilation (`node-gyp`); used in parallel with AI coding agent poisoning wave |

## 4. Threat Actor / Campaign Attribution

**Assessed Attribution:** Miasma worm is a variant of the Mini Shai-Hulud worm publicly identified in connection with TeamPCP (also tracked as UNC6780). TeamPCP has been responsible for multiple high-profile supply chain compromises in 2026 including the Trivy Action GitHub Action compromise (March), TanStack npm packages (May), and the Azure/durabletask GitHub Actions workflow compromise (Wave 3, May 20).

The June 5 Miasma wave represents an escalation distinct from prior TeamPCP waves:
- Targets AI coding agents specifically (Claude Code, Gemini CLI, Cursor, VS Code) rather than CI/CD pipeline actions
- Achieves broader developer reach: any developer who clones and opens the repository triggers execution, regardless of CI/CD configuration
- Self-replicating: each victim's GitHub tokens immediately enable additional repository poisoning

**Developer tooling targeted (confirmed configurations planted):**
- Claude Code (Anthropic): `CLAUDE.md` workspace instructions
- Google Gemini CLI: `.gemini/settings.json`
- Cursor IDE: `.cursor/rules`
- VS Code: `.vscode/settings.json`
- GitHub Copilot: `.copilot-instructions.md`

**GitHub Response:** GitHub's automated systems detected and disabled 73 Microsoft repositories in a 105-second sweep on June 5-6, 2026. All affected repositories required manual review before re-enabling.

## 5. Splunk Detection Searches

```spl
-- Detect credential file access from AI coding agent processes (Claude Code, Cursor, VS Code, Gemini CLI)
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_path="*/.aws/credentials" OR Filesystem.file_path="*/.ssh/id_rsa*"
    OR Filesystem.file_path="*/.npmrc" OR Filesystem.file_path="*/.kube/config"
    OR Filesystem.file_path="*/.azure/accessTokens.json" OR Filesystem.file_path="*/kubeconfig")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)cursor|claude|gemini|code"), 90,
    match(process_name,"(?i)node|bun|npm"), 75,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user process_name file_path risk_score
```

```spl
-- Detect Miasma exfiltration: HTTP POSTs from developer hosts to github.com shortly after git clone/pull
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.http_method=POST AND Web.dest="api.github.com"
    AND (Web.uri_path="*/repos/*" OR Web.uri_path="*/gists*")
  by Web.src Web.dest Web.uri_path Web.http_user_agent Web.bytes_out
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(uri_path,"(?i)liuende501"), 95,
    bytes_out > 50000, 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest uri_path http_user_agent bytes_out risk_score
```

```spl
-- Detect suspicious process spawning from AI coding agent parent processes (Miasma payload execution)
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name IN ("cursor.exe","claude.exe","code.exe","gemini.exe","bun.exe","node.exe"))
    AND (Processes.process_name IN ("cmd.exe","powershell.exe","bash","sh","python.exe","python3"))
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## 6. Executive Summary

On June 5, 2026, the self-replicating Miasma supply chain worm — assessed as a variant of TeamPCP's Mini Shai-Hulud — reached Microsoft's official Azure GitHub organization, compromising 73 repositories in under two minutes. The attack vector is novel: rather than targeting CI/CD pipeline actions (prior TeamPCP/Miasma waves), it plants AI coding tool configuration files directly in repository roots. When a developer opens a poisoned repository in Claude Code, Gemini CLI, Cursor, or VS Code, a 4.6 MB obfuscated JavaScript payload auto-executes and harvests all available developer credentials (AWS, Azure, GCP, Kubernetes, npm, GitHub tokens). Stolen GitHub tokens are immediately used to propagate the worm to further repositories, creating a self-amplifying attack with an exponentially growing blast radius.

GitHub disabled all 73 affected repositories within 105 seconds via automated detection. However, any developer who cloned or opened the affected repositories before takedown may have credential sets harvested and exfiltrated to the liuende501 GitHub dead-drop account.

**Priority actions for development organizations:**
1. Audit recent git clones/pulls from Azure GitHub organizations for repositories now marked as disabled
2. Rotate all cloud and developer credentials on any host where a poisoned repository was opened in an AI coding agent
3. Search for `.cursor/rules`, modified `CLAUDE.md`, `.gemini/settings.json`, or modified `.vscode/settings.json` files in recently cloned repositories — especially those not containing these files in prior commits
4. Monitor for outbound HTTP POST traffic to `api.github.com` from developer workstations with unusual payload sizes

## References

- [The Hacker News — Miasma Worm Hits 73 Microsoft GitHub Repositories in Major Supply Chain Attack](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)
- [OpenSourceMalware — The Blight Reaches Microsoft: 73 Repos Disabled in 105 Seconds](https://opensourcemalware.com/blog/miasma-reaches-azure)
- [SafeDep — Miasma Worm Targets AI Coding Agents via GitHub Repos](https://safedep.io/miasma-worm-ai-coding-agent-config-injection/)
- [StepSecurity — Miasma npm Supply Chain Attack: Self-Spreading Worm via Phantom Gyp](https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm)
- [Microsoft Security Blog — Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing campaign (Wave 1, 2026-06-02)](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)
- [MITRE ATT&CK — T1195.001 Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
