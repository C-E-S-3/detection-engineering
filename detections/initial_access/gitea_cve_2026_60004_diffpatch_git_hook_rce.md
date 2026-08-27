# Gitea CVE-2026-60004 — diffpatch Git Hook RCE

## Description

Detects exploitation of CVE-2026-60004 (CVSS 9.8, CWE-94), a critical remote code execution vulnerability in Gitea self-hosted git service versions prior to 1.27.1. The vulnerability exists in Gitea's `diffpatch` HTTP endpoint: any authenticated user with repository write access can inject a malicious git hook into a repository. On the next qualifying git operation (push, receive), that hook executes arbitrary shell commands as the Gitea OS service user.

**Critical amplifier:** Gitea enables open registration by default, reducing the practical exploitation bar from "authenticated" to "unauthenticated" for any publicly exposed Gitea instance. An attacker self-registers, creates a repository, and immediately has write access to inject hooks.

CISA added CVE-2026-60004 to the Known Exploited Vulnerabilities catalog on August 25, 2026 with a federal remediation deadline of August 28, 2026. Active exploitation has been confirmed: at least one attack delivered a shell-loader dropper and crypto-miner payload to a Gitea instance.

Detection signals:
1. Gitea service process spawning unexpected child processes (sh, bash, curl, wget, nc, xmrig)
2. HTTP POST requests to the `diffpatch` endpoint or Gitea git hooks API
3. File creation or modification within `.git/hooks/` directories on Gitea hosts

False positives: Gitea administrators legitimately execute scripts as the Gitea service user; allowlist known admin activity by source IP or process signature.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution |
| Secondary Tactic ID | TA0002 |
| Secondary Technique | Command and Scripting Interpreter: Unix Shell |
| Secondary Technique ID | T1059.004 |
| Tertiary Technique | Ingress Tool Transfer |
| Tertiary Technique ID | T1105 |
| Quaternary Technique | Resource Hijacking |
| Quaternary Technique ID | T1496 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

Primary signal — Gitea service spawning unexpected child processes:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("gitea", "gitea.exe")
  AND Processes.process_name IN (
    "sh", "bash", "dash", "zsh", "ksh", "ash",
    "curl", "wget", "python", "python3", "perl", "ruby",
    "nc", "ncat", "netcat", "php", "xmrig", "minerd")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("nc", "ncat", "netcat", "xmrig", "minerd"), 95,
    process_name IN ("curl", "wget") AND match(process, "(?i)http"), 90,
    process_name IN ("sh", "bash", "dash", "zsh", "ksh", "ash"), 85,
    process_name IN ("python", "python3", "perl", "ruby", "php"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

Secondary signal — HTTP POST to Gitea diffpatch or hooks API endpoints:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.http_method="POST"
  AND (Web.url="*diffpatch*" OR Web.url="*/api/v1/repos/*/git/hooks*")
by Web.src Web.dest Web.dest_port Web.url Web.http_method Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "diffpatch") AND http_method="POST", 85,
    match(url, "git/hooks") AND http_method IN ("POST","PUT"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest dest_port url http_method status http_user_agent risk_score
```

Tertiary signal — Malicious git hook file creation on Gitea hosts:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path="*/.git/hooks/*"
  AND Filesystem.action IN ("created", "modified")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name, "pre-receive|post-receive|pre-push|update|post-update"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user file_path file_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Gitea spawning netcat, ncat, xmrig, or minerd | 95 | Near-certain post-exploitation: reverse shell or crypto-miner execution |
| Gitea spawning curl/wget with HTTP URL argument | 90 | Shell-loader dropper retrieval — primary attack pattern in confirmed exploits |
| Gitea spawning shell interpreter (sh/bash/dash/zsh) | 85 | High-confidence hook execution; Gitea does not normally exec shell interpreters directly |
| Gitea spawning Python/Perl/Ruby/PHP | 80 | Scripting engine execution by git service is anomalous |
| POST to diffpatch endpoint | 85 | Direct exploitation attempt of CVE-2026-60004 vulnerability |
| POST/PUT to git/hooks API | 80 | Programmatic hook installation — normal operations use UI or git push |
| Hook file created/modified in .git/hooks/ (pre-receive, post-receive, etc.) | 80 | Direct evidence of hook injection; verify expected vs. unexpected hook names |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (opportunistic financially motivated actors, August 2026) | [Help Net Security — CVE-2026-60004 exploited (2026-08-26)](https://www.helpnetsecurity.com/2026/08/26/gitea-cve-2026-60004-exploited-in-the-wild/) |
| Unknown (Gogs GHSA-qf6p-p7ww-cwr9 actors, same technique class) | [Rapid7 — Gogs argument injection RCE (2026-05-28)](https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/) |

## References

- [Help Net Security — Gitea CVE-2026-60004 Exploited in the Wild (2026-08-26)](https://www.helpnetsecurity.com/2026/08/26/gitea-cve-2026-60004-exploited-in-the-wild/)
- [The Hacker News — Critical Gitea RCE Actively Exploited (2026-08-26)](https://thehackernews.com/2026/08/critical-gitea-rce-actively-exploited.html)
- [CISA KEV Catalog — CVE-2026-60004 (added 2026-08-25)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Gitea 1.27.1 Release Notes](https://github.com/go-gitea/gitea/releases/tag/v1.27.1)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1059.004: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE ATT&CK — T1496: Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- [threat-intel/2026-08-27_cisa-kev-cve-2026-60004-gitea-rce-actively-exploited.md](../../threat-intel/2026-08-27_cisa-kev-cve-2026-60004-gitea-rce-actively-exploited.md)
- [threat-intel/2026-07-07_thehackernews-com-cve-2026-20896-gitea-docker-auth-bypass.md](../../threat-intel/2026-07-07_thehackernews-com-cve-2026-20896-gitea-docker-auth-bypass.md)
