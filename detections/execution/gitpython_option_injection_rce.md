# GitPython Option Injection Remote Code Execution

## Description

Detects exploitation of GitPython CVEs (GHSA-wvpp-8hx9-p66j, GHSA-jm78-9fvv-mhgr, GHSA-9rj7-rf2p-w77r) where a Python process spawns `git` with dangerous argument patterns that bypass GitPython's unsafe-option guard and can result in OS command execution, git hook planting, or SSH command hijacking.

GitPython ≤ 3.1.57 forwards attacker-controlled kwargs directly to git subprocess calls in several methods (`clone_from`, `init`, `config_writer`, etc.) without properly validating all dangerous option patterns. Exploitation occurs when a Python application processes untrusted repository input — common in CI/CD pipelines, repository management tools, and security scanning utilities.

**False positive sources:** Legitimate use of `--template` during git repository bootstrapping scripts; rare CI jobs that explicitly set `--upload-pack` for mirroring. Validate against the parent application context.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: Python |
| Technique ID | T1059.006 |

Secondary: Exploit Public-Facing Application (T1190) if the Python application is server-hosted.

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

### Query 1 — Python Spawning git with Dangerous Argument Patterns

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("python.exe", "python3.exe", "python", "python3",
    "python3.10", "python3.11", "python3.12", "python3.13")
  AND Processes.process_name IN ("git", "git.exe")
  AND (
    Processes.process="*--upload-pack*"
    OR Processes.process="*--receive-pack*"
    OR Processes.process="*--template*"
    OR Processes.process="*--pathspec-from-file*"
  )
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "--upload-pack|--receive-pack"), 80,
    match(process, "--template"), 75,
    match(process, "--pathspec-from-file"), 65,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 2 — Suspicious .git/hooks File Creation

Detects the hook planting stage of GHSA-9rj7-rf2p-w77r (template injection) and GHSA-jm78-9fvv-mhgr (hooksPath config injection). New executable files appearing under `.git/hooks/` outside of legitimate repository provisioning warrant investigation.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where (Filesystem.file_path="*/.git/hooks/*" OR Filesystem.file_path="*\\.git\\hooks\\*")
  AND Filesystem.action IN ("write", "create")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "python.exe|python3.exe|python|python3"), 75,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user process_name file_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Python spawning git with `--upload-pack` or `--receive-pack` | 80 | Highest-risk pattern; exploits GHSA-wvpp-8hx9-p66j option guard bypass; enables arbitrary command execution |
| Python spawning git with `--template` | 75 | Hook planting via GHSA-9rj7-rf2p-w77r; copies malicious hooks into .git/hooks |
| Python spawning git with `--pathspec-from-file` | 65 | File read exfiltration via GHSA-hh9p-6wh2-4mfc; lower immediate impact |
| .git/hooks file written by Python process | 75 | Indicates successful hook planting — pre-execution stage of RCE |
| .git/hooks file written by non-Python process | 50 | May indicate legitimate git template use; investigate context |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any attacker with ability to provide malicious repository input to a Python application using GitPython ≤ 3.1.57 | [GHSA-wvpp-8hx9-p66j](https://github.com/advisories/GHSA-wvpp-8hx9-p66j) |
| Supply chain attackers targeting CI/CD pipelines | [MITRE ATT&CK — T1195.001](https://attack.mitre.org/techniques/T1195/001/) |

## References

- [GHSA-wvpp-8hx9-p66j — GitPython Option Guard Bypass (CVSS 8.8)](https://github.com/advisories/GHSA-wvpp-8hx9-p66j)
- [GHSA-jm78-9fvv-mhgr — GitPython Config Option Name Injection (CVSS 8.8)](https://github.com/advisories/GHSA-jm78-9fvv-mhgr)
- [GHSA-hmq2-w58f-27jc — GitPython Submodule Path Traversal (CVSS 8.2)](https://github.com/advisories/GHSA-hmq2-w58f-27jc)
- [GHSA-9rj7-rf2p-w77r — GitPython Template Option Hook Execution (CVSS 7.5)](https://github.com/advisories/GHSA-9rj7-rf2p-w77r)
- [GitPython 3.1.58 Release Notes](https://github.com/gitpython-developers/GitPython/releases/tag/3.1.58)
- [MITRE ATT&CK — T1059.006: Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
