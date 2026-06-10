---
scraped_at: 2026-06-09T12:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-focused-pypi-packages/
report_type: threat-intel
severity: high
title: "Shai-Hulud Hades Wave: 19 Bioinformatics PyPI Packages Trojanized with PTH Startup Hook — Bun-Based Miasma Credential Stealer Auto-Executes on Python Start"
---

# Shai-Hulud Hades Wave: 19 Bioinformatics PyPI Packages Trojanized with PTH Startup Hook

Socket detected a new coordinated supply chain campaign dubbed the "Hades" wave, comprising 37 malicious wheel releases across 19 PyPI packages concentrated in bioinformatics and computational biology tooling. The attack uses a new delivery mechanism — a Python `.pth` site-startup file that executes automatically whenever the Python interpreter starts — to deploy a Bun JavaScript runtime that runs an obfuscated Miasma-lineage credential stealer. The campaign was active and discoverable on PyPI as of June 8-9, 2026.

This campaign is the fourth major wave of the Shai-Hulud supply chain worm family, following Mini Shai-Hulud (April 2026), the Miasma Red Hat npm wave (June 2026), and the Miasma Worm AI coding agent workspace poisoning campaign (June 5-6, 2026). All waves share the same Bun Stealer credential harvesting core and exfiltrate via GitHub Actions to attacker-controlled repositories.

---

## 1. IOCs

### Compromised PyPI Packages (Hades Wave — confirmed by Socket/BleepingComputer)
| Package | Notes |
|---------|-------|
| dynamo-release | Popular bioinformatics trajectory analysis library |
| spateo-release | Spatial transcriptomics toolkit |
| coolbox | Genomics data visualization library |
| u-fish | Bioinformatics utility package |
| napari-ufish | Napari plugin for bioinformatics |
| 14 additional packages | Single-maintainer cluster; complete list in Socket advisory |

**Attack artefacts present in malicious releases:**
- `*-setup.pth` — Python site startup hook (auto-executes on any Python import or interpreter start)
- `_index.js` — Obfuscated Bun JavaScript credential harvester payload

### GitHub Exfiltration Repository Markers
| Marker Type | Value |
|-------------|-------|
| Repository description | `Hades - The End for the Damned` |
| Commit marker string | `IfYouYankThisTokenItWillNukeTheComputerOfTheOwnerFully` |
| Generated repo-name keywords | stygian, tartarean, cerberus, charon, styx, lethe, thanatos, persephone |
| GitHub workflow name | `Run Copilot` (used to trigger exfiltration actions) |

### Credential Targets (per Hades payload analysis)
AWS, GCP, Azure, GitHub tokens, npm tokens, PyPI tokens, RubyGems tokens, JFrog tokens, CircleCI tokens, Anthropic API keys, Kubernetes configs, HashiCorp Vault tokens, SSH private keys, Docker configs, shell history, .env files, .npmrc, .pypirc, Claude/MCP agent configuration files

### Camouflage / Evasion
- Secondary exfiltration method sends data to `api[.]anthropic[.]com/v1/api` — **this is NOT a real Anthropic API endpoint**; Socket assesses it is used purely for camouflage to make outbound traffic blend with legitimate Claude/Anthropic API calls. Do not block `api.anthropic.com` itself.
- Payload checks for Russian locale/environment variables to skip execution in certain environments
- Checks for StepSecurity Harden-Runner and other CICD security tooling

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Attacker either compromised a legitimate PyPI maintainer account (via stolen token or expired email domain) or published under a new account impersonating legitimate package namespaces; malicious wheel releases published to PyPI alongside or replacing legitimate versions |
| Execution | T1059.006 | Command and Scripting Interpreter: Python | Malicious `.pth` file installed into Python's site-packages directory triggers automatic execution of attacker code on every Python interpreter start, even before any import statement runs |
| Persistence | T1546 | Event Triggered Execution | Python site startup hooks (`.pth` files placed in site-packages) auto-execute at Python interpreter startup; persist across reboots and virtual environment reactivations |
| Defense Evasion | T1027 | Obfuscated Files or Information | `_index.js` payload is heavily obfuscated JavaScript; download of Bun runtime from GitHub may appear as a legitimate developer workflow |
| Defense Evasion | T1497.001 | Virtualization/Sandbox Evasion: System Checks | Payload checks Russian locale settings and CI/CD security tooling (StepSecurity Harden-Runner) to skip execution in monitored environments |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials in Files | Stealer harvests .env files, .npmrc, .pypirc, .git-credentials, shell history, Docker configs, Kubernetes configs, SSH keys, and all stored cloud provider credentials |
| Exfiltration | T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository | Stolen credentials written to automatically-created GitHub repositories via GitHub Actions (workflow named "Run Copilot"); repositories identified by Hades-themed naming pattern |
| Lateral Movement | T1534 | Internal Spearphishing | Stolen GitHub tokens allow self-replication into victim repositories (worm behavior); compromised CI/CD tokens allow lateral movement into connected cloud infrastructure |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| Hades Bun Stealer | Credential Stealer | JavaScript credential harvester delivered via `_index.js`; requires Bun JavaScript runtime; part of the Miasma/Shai-Hulud worm family; sweeps all developer and cloud credential classes; self-replicates via stolen VCS tokens |
| Bun JavaScript Runtime | Legitimate Runtime (LOLBin) | Downloaded from GitHub (github.com/oven-sh/bun) if not already present; used to execute `_index.js` payload; using a legitimate runtime binary avoids suspicious process-name detection |
| Python `.pth` startup hook | Persistence/Execution Mechanism | A `.pth` file installed in Python's site-packages directory; Python evaluates lines beginning with `import ` as import statements and lines without that prefix as path additions; a line calling `exec(open('payload.py').read())` or similar triggers execution at Python startup |

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Campaign Name | Shai-Hulud Hades Wave |
| Previous Waves | Mini Shai-Hulud (April 2026), Miasma Red Hat npm (June 2-3 2026), Miasma AI Coding Agent workspace poisoning (June 5-6 2026), Phantom Gyp/binding.gyp npm (June 7-8 2026) |
| Actor | TeamPCP (UNC6780) assessed with moderate confidence based on consistent Bun Stealer payload, same exfiltration-via-GitHub-Actions methodology, and targeting overlap with previous waves |
| Motivation | Developer credential theft at scale; GitHub/cloud token harvesting for downstream supply chain attacks and access broker operations |
| Targeting | Bioinformatics/computational biology researchers and developers (new vertical compared to prior waves that targeted general npm/React/ML tooling) |
| Scope | 37 malicious releases across 19 packages; packages collectively downloaded hundreds of thousands of times; PyPI has removed malicious versions |
| Worm Attribution Count | 453 total Shai-Hulud-attributed malicious artefacts across all waves per Socket |

---

## 5. Splunk Detection Searches

```spl
| comment "Hades wave / Shai-Hulud PTH hook: Python process spawning curl/wget to download Bun runtime from GitHub — auto-triggered by malicious site-startup .pth file"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name IN ("python.exe","python3","python","python3.11","python3.12","python3.13")
         OR Processes.parent_process="*python*")
    AND (Processes.process_name IN ("curl","wget","bun","node") OR Processes.process="*github.com/oven-sh/bun*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)oven-sh/bun|bun.sh|github.com.*bun"), 90,
    process_name IN ("curl","wget") AND match(process,"(?i)github"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Hades wave: New .pth file created in Python site-packages directory — potential supply chain PTH startup hook installation"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.pth"
    AND (Filesystem.file_path="*site-packages*" OR Filesystem.file_path="*dist-packages*")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_guid
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"(?i)setup\.pth|install\.pth"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user file_path file_name risk_score
```

```spl
| comment "Hades wave: Python spawning Bun or Node.js to execute JavaScript in temp/cache directories — Bun Stealer payload execution"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("bun","bun.exe") OR Processes.parent_process_name IN ("bun","bun.exe"))
    AND (Processes.process="*_index.js*" OR Processes.process="*tmp*" OR Processes.process="*cache*" OR Processes.process="*/T/*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Hades exfiltration: GitHub API calls creating repositories with Hades-themed names from developer workstations — Shai-Hulud exfiltration pattern"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.dest_host="api.github.com"
    AND Web.http_method="POST"
    AND Web.uri_path="/user/repos"
  by Web.src Web.dest_host Web.uri_path Web.http_method Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime src dest_host uri_path http_method http_user_agent risk_score
```

---

## 6. Executive Summary

The Shai-Hulud "Hades" wave is the latest evolution of a persistent, cross-ecosystem supply chain credential theft campaign that has been active since April 2026. This wave introduces a new PyPI-specific delivery mechanism: a Python `.pth` site startup file that triggers automatically on every Python interpreter invocation — including in CI/CD runners, developer workstations, Jupyter notebooks, and virtual environments — before any user code executes.

The campaign specifically targets bioinformatics and computational biology researchers, compromising 19 popular data science packages (including dynamo-release, spateo-release, and coolbox) across 37 malicious releases from a single PyPI account. The payload downloads the legitimate Bun JavaScript runtime from GitHub and executes an obfuscated `_index.js` credential harvester that collects developer and cloud credentials from all standard locations (AWS, GCP, Azure, GitHub, npm, PyPI, Anthropic, SSH keys, Docker, Kubernetes, .env files, shell history) and exfiltrates them to attacker-controlled GitHub repositories named with Greek underworld mythology keywords (stygian, cerberus, charon, etc.).

This wave is notable for: (1) pivoting to bioinformatics to target a new victim pool less familiar with supply chain risks; (2) using `.pth` startup hooks instead of `setup.py` preinstall scripts, bypassing detection tools that focus on preinstall execution; and (3) checking for and evading StepSecurity Harden-Runner, the most widely deployed open-source CI/CD security tool.

**Immediate Actions:**
1. Audit Python environments for unexpected `.pth` files in site-packages directories.
2. If any of the 19 named packages (especially dynamo-release, spateo-release, coolbox, u-fish, napari-ufish) were installed from PyPI between approximately June 4-9, 2026, treat the environment as compromised and rotate all credentials accessible from that system.
3. Monitor Python processes for child process spawning of curl/wget to GitHub or execution of Bun runtime from temp directories.
4. Add detection for GitHub repository creation API calls from developer workstations (unusual in most environments).
5. For CI/CD: add StepSecurity Harden-Runner or equivalent; audit allowed outbound destinations from pipeline runners.

---

## References

- [BleepingComputer — New Shai-Hulud attack trojanizes 19 science-focused PyPI packages](https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-focused-pypi-packages/)
- [Socket.dev — Shai-Hulud Descends to Hades: Miasma Worm Campaign Spreads with New PyPI Wave](https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave)
- [The Hacker News — Hades PyPI Attack: 19 Packages Poisoned to Auto-Run Bun Credential Stealer](https://thehackernews.com/2026/06/hades-pypi-attack-19-packages-poisoned.html)
- [StepSecurity — The Hades Campaign: Graph ML PyPI Packages Deploy Cross-Platform Memory Scrapers](https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages)
- [SOCRadar — Shai-Hulud Hades PyPI Campaign](https://socradar.io/blog/shai-hulud-hades-pypi-campaign/)
- [SecurityWeek — Over 100 NPM, PyPI Packages Hit in New Shai-Hulud Supply Chain Attacks](https://www.securityweek.com/over-100-npm-pypi-packages-hit-in-new-shai-hulud-supply-chain-attacks/)
- [MITRE ATT&CK — T1195.001: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK — T1059.006: Python](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK — T1546: Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
