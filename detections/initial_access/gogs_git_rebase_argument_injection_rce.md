# Gogs Self-Hosted Git Argument Injection RCE via Pull Request Branch Name

## Description

Detects exploitation of an unpatched critical RCE vulnerability (GHSA-qf6p-p7ww-cwr9, CVSS 9.4) in the Gogs self-hosted Git service. The vulnerability allows any authenticated user — including self-registered accounts on default-configured instances — to execute arbitrary OS commands on the server by creating a pull request with a branch name that injects the `--exec` flag into a `git rebase` operation.

The root cause is that Gogs passes the pull request base branch name directly to `git rebase` without a POSIX `--` separator. An attacker creates a branch named `--exec=<shell_command>` (e.g., `--exec=touch${IFS}/tmp/rce_proof`). When a "Rebase before merging" merge is triggered, git interprets `--exec` as a flag and runs the attacker-controlled command via `sh -c` after each replayed commit.

Detection covers:
1. Shell processes (`sh`, `bash`, `cmd.exe`) spawned directly by a `gogs`/`gogs.exe` parent process
2. `git` processes with `--exec` in their command line, particularly with shell metacharacters
3. Shell processes spawned by `git` outside expected git-core helper paths (anomalous git subprocess execution)

**False positives:** 
- Legitimate git operations may spawn `sh` or `bash` for hook scripts (`pre-commit`, `post-merge`, etc.); filter on process path — hook-invoked shells typically reference `.git/hooks/` in their command line
- The git `--exec` flag is used legitimately in some rebase workflows (`git rebase --exec 'make test'`) in CI pipelines; correlate with the spawning user account and whether the Gogs server is exposed externally

**No patch is available** as of 2026-05-30. Gogs maintainers have been unresponsive since March 28, 2026. Mitigate by disabling open registration and restricting internet exposure.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution |
| Secondary Technique | Command and Scripting Interpreter: Unix Shell |
| Secondary ID | T1059.004 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("gogs","gogs.exe")
  AND Processes.process_name IN ("sh","bash","dash","zsh","ksh","cmd.exe","powershell.exe","python","python3","perl","ruby")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="git"
  AND Processes.process IN ("*rebase*--exec*","*--exec=*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "--exec=.*[\$\`\|\;\(\)]"), 95,
    match(process, "--exec=.*\$\{IFS\}"), 95,
    match(process, "--exec"), 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name="git"
  AND Processes.process_name IN ("sh","bash","dash","cmd.exe","powershell.exe")
  AND NOT Processes.process IN ("*/usr/lib/git-core/*","*git-credential*","*git-remote*","*git-lfs*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Shell process spawned directly by `gogs`/`gogs.exe` | 90 | Gogs should not directly spawn shell interpreters; strong indicator of post-exploitation or hook abuse |
| `git rebase --exec=<cmd>` with shell metacharacters (`$`, `|`, `;`, backtick) in exec payload | 95 | Direct indicator of GHSA-qf6p-p7ww-cwr9 exploitation payload; metacharacters required to inject OS commands |
| `git rebase --exec=` without metacharacters | 75 | Legitimate CI use is possible (e.g., `git rebase --exec 'make test'`); requires correlation |
| Shell process spawned by `git` outside known git-core helper paths | 75 | Anomalous; suggests `--exec` injection or malicious git hook execution |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Opportunistic / Unknown (multiple) | No specific attribution; CISA confirmed active exploitation as of 2026-05-28 |
| Nation-state actors targeting developer infrastructure | Historical pattern of targeting self-hosted code repositories for source code theft and credential harvesting |

## References

- [Rapid7 — Authenticated RCE via Argument Injection in Gogs (NOT FIXED, 2026-05-28)](https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/)
- [BleepingComputer — New Gogs Zero-Day Flaw Lets Hackers Get Remote Code Execution](https://www.bleepingcomputer.com/news/security/new-gogs-zero-day-flaw-lets-hackers-get-remote-code-execution/)
- [The Register — No Fix Yet for Critical RCE Bug in Open-Source Git Service Gogs (2026-05-29)](https://www.theregister.com/security/2026/05/29/no-fix-yet-for-critical-gogs-rce-bug-exploit-module-is-out/)
- [Infosecurity Magazine — CISA Flags Actively Exploited Gogs Vulnerability With No Patch](https://www.infosecurity-magazine.com/news/cisa-flags-exploited-gogs-flaw-no/)
- [GHSA-qf6p-p7ww-cwr9 — GitHub Security Advisory](https://github.com/advisories/GHSA-qf6p-p7ww-cwr9)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
