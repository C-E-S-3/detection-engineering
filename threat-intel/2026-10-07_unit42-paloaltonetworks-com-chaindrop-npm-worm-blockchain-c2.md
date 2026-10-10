---
scraped_at: "2026-10-10T00:00:00Z"
source_url: "https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
report_type: threat-intel
severity: critical
title: "ChainDrop: Self-Propagating npm Worm with Ethereum Smart Contract Dead-Drop C2 — 444 Packages Compromised in Under Four Hours"
---

## 1. Indicators of Compromise (IOCs)

### File Hashes (MD5)

| Hash | Type | Description |
|------|------|-------------|
| `f92ee93a0af971a3966bfa8efa9c2625` | MD5 | ChainDrop worm payload component (Zscaler ThreatLabz) |
| `7bcf8d9f6834c44450eac145a967d2f2` | MD5 | ChainDrop worm payload component (Zscaler ThreatLabz) |
| `4140f7e17e6f97f83aa3472473e01add` | MD5 | ChainDrop worm payload component (Zscaler ThreatLabz) |

### C2 Domains

| Domain | Notes |
|--------|-------|
| `npm-cache[.]com` | Primary C2 domain; endpoint npm-cache[.]com:443/router; initial C2 before Ethereum-based rotation |
| `awqhnjewqjkl[.]icu` | Rotated C2 domain; silently substituted via Ethereum contract update |

### Ethereum Smart Contract

| Indicator | Value |
|-----------|-------|
| Contract Address | `0xE1f2395ee43e45A1556EC6438a88c31B83493103` |
| Contract Type | StringListStore |
| Function Selector | `0x53ed5143` |
| Purpose | Dead-drop C2 rotation; stores AES-256-GCM encrypted domain list; payload queries up to 75 public Ethereum RPC endpoints |

### Compromised npm Packages (Representative)

| Package | Version | Notes |
|---------|---------|-------|
| `keyv` | 6.0.0 | Initial seeded package; first malicious commit August 4, 2026 |
| `cacheable-request` | Dependent | Downstream infection via keyv dependency |

> Total scope: 444 packages, 2,212 versions infected in under four hours. Full package list available from Unit 42 and StepSecurity advisories.

### Behavioral Indicators

- GitHub repositories with description "Shai-Hulud: Here We Go Again" or other Dune-themed names linked to campaign infrastructure
- Outbound connections to `npm-cache.com:443/router` from Node.js/Bun processes
- Ethereum JSON-RPC calls from build environments to public RPC endpoints (eth_call targeting contract 0xE1f23...)

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Usage |
|--------|-----------|----|-------|
| Initial Access | Supply Chain Compromise: Compromise Software Dependencies | T1195.001 | Malicious postinstall/preinstall hooks injected into keyv@6.0.0 and 443 downstream packages; dependency chain auto-spreads malware to projects that install affected packages |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | npm postinstall hook executes payload via Bun runtime (`bun run`) or Node.js; Bun used as execution vehicle but not itself compromised |
| Persistence | Event Triggered Execution: Accessibility Features | T1546.008 | VS Code workspace `.vscode/tasks.json` folder-open task added to re-execute payload when developer opens any project folder |
| Persistence | Boot or Logon Initialization Scripts | T1037 | Claude Code `SessionStart` hook injected into `.claude/settings.json` to execute payload on every Claude Code session start |
| Defense Evasion | Obfuscated Files or Information | T1027 | C2 domain list AES-256-GCM encrypted inside Ethereum smart contract; payload decrypts after querying contract |
| Defense Evasion | Indicator Removal | T1070 | C2 domain silently rotated by updating Ethereum contract; old domain `npm-cache[.]com` replaced with `awqhnjewqjkl[.]icu` without recompiling payload |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 | Harvests npm tokens, GitHub tokens, SSH private keys (`~/.ssh/`), Kubernetes service account tokens, Terraform state files, Vault tokens |
| Credential Access | Credentials from Password Stores | T1555 | Targets cloud provider credential files (AWS `~/.aws/credentials`, GCP `~/.config/gcloud/`, Azure `~/.azure/`) |
| Collection | Data from Local System | T1005 | Exfiltrates all harvested credentials and tokens to C2 |
| Command and Control | Dynamic Resolution: Dead Drop Resolver | T1568.001 | Ethereum smart contract used as immutable dead-drop; payload resolves live C2 address by calling contract on public RPC endpoints |
| Lateral Movement | Supply Chain Compromise | T1195 | Worm self-propagates by modifying `package.json` of locally installed npm packages; infection spreads to dependent projects |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| **ChainDrop** | npm Supply Chain Worm | Self-propagating worm that infects installed npm packages by injecting malicious hooks; uses Ethereum dead-drop C2 for infrastructure rotation |
| **Shai-Hulud** (family) | Malware Family | Umbrella family designation (Zscaler ThreatLabz); ChainDrop is a member; related to Mini Shai-Hulud and TeamPCP variants |
| **PolinRider** | Associated Malware | DPRK-nexus family linked to Alluring Pisces / Sapphire Sleet threat cluster; Unit 42 assesses ChainDrop has TTPs/infrastructure overlap |
| **Bun** | Runtime (legitimate) | High-performance JavaScript runtime used as execution vehicle; not itself malicious or compromised |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Designation | Unattributed (ChainDrop campaign) |
| Linked Group | Alluring Pisces / Sapphire Sleet (DPRK-nexus; Unit 42 assessment) |
| Also Tracked As | PolinRider (infrastructure/TTP overlap); Shai-Hulud family (Zscaler ThreatLabz) |
| Motivation | Financial (credential theft, cloud access for monetization); consistent with DPRK IT-worker and crypto-theft operations |
| Campaign Start | August 4, 2026 (keyv@6.0.0 first malicious commit) |
| Scope | 444 packages, 2,212 versions; 453 public GitHub repositories across 5 victim accounts; 10+ execution environments |
| Target | npm-consuming developers, CI/CD pipelines, build environments; especially those with cloud credentials, Kubernetes access, Terraform state |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host IN ("npm-cache.com","awqhnjewqjkl.icu")
  by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port All_Traffic.process_name All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest_host dest_port process_name user risk_score
```
*Detects direct connections to known ChainDrop C2 domains — high-fidelity indicator requiring immediate investigation.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.dest_host="*.rpc.ankr.com" OR All_Traffic.dest_host="*infura.io*"
    OR All_Traffic.dest_host="*alchemy.com*" OR All_Traffic.dest_host="*cloudflare-eth.com*")
    All_Traffic.process_name IN ("bun","node","node.exe","npm","npm.exe")
  by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port All_Traffic.process_name All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime src dest_host dest_port process_name user risk_score
```
*Detects Ethereum RPC calls from Node.js/Bun processes — ChainDrop queries up to 75 public RPC endpoints to resolve C2 via smart contract; legitimate developer tooling rarely calls ETH RPC from CI/CD.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*/.vscode/tasks.json","*/.claude/settings.json","*/.claude/CLAUDE.md")
    Filesystem.process_name IN ("bun","node","node.exe","npm","npm.exe")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user file_path process_name risk_score
```
*Detects npm/Bun processes writing to VS Code task configs or Claude Code hook files — ChainDrop persistence mechanism.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*/node_modules/*/package.json"
    Filesystem.process_name IN ("bun","node","node.exe")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| table firstTime lastTime dest user file_path process_name risk_score
```
*Detects Node.js/Bun writing to installed package.json files — ChainDrop self-propagation modifies package manifests of locally installed packages to inject malicious hooks.*

---

## 6. Executive Summary

Unit 42 published analysis on October 7, 2026, documenting **ChainDrop**, a self-propagating npm supply chain worm that infected 444 packages and 2,212 package versions in under four hours. The worm originated in `keyv@6.0.0` (published August 4, 2026), a widely used key-value caching library with millions of weekly downloads. ChainDrop exploits the npm `postinstall`/`preinstall` hook mechanism to inject malicious code into a victim's locally installed package tree, then re-infects any package that gets installed from an infected environment.

The most operationally notable aspect is the **Ethereum smart contract dead-drop C2**: instead of hardcoding a C2 domain, ChainDrop stores an AES-256-GCM encrypted domain list inside an Ethereum StringListStore contract at `0xE1f2395ee43e45A1556EC6438a88c31B83493103`. The payload queries up to 75 public Ethereum RPC endpoints to retrieve the current C2 domain, making takedown difficult. When `npm-cache[.]com` was taken down, the threat actor silently updated the contract to return `awqhnjewqjkl[.]icu` — no payload recompilation required.

ChainDrop targets high-value developer credentials: AWS/GCP/Azure credentials, npm and GitHub tokens, SSH keys, Kubernetes tokens, Terraform state, and HashiCorp Vault tokens. It establishes **dual persistence** by adding a VS Code workspace folder-open task and a **Claude Code `SessionStart` hook** to ensure re-execution on developer tool launch.

Unit 42 assesses infrastructure and TTP overlap with **PolinRider** (Alluring Pisces / Sapphire Sleet nexus — DPRK-linked). Defenders should immediately audit environments for the two known C2 domains, monitor Ethereum RPC calls from build tools, and inspect `.vscode/tasks.json` and `.claude/settings.json` for unauthorized entries.
