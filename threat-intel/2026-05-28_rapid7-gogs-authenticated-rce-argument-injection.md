---
scraped_at: "2026-05-30T00:00:00Z"
source_url: "https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/"
report_type: threat-intel
severity: critical
title: "Gogs Self-Hosted Git Service: Unpatched Authenticated RCE via Git Rebase Argument Injection (GHSA-qf6p-p7ww-cwr9)"
---

## 1. IOCs

No specific campaign C2 infrastructure (IPs, domains, hashes) has been publicly attributed to exploitation of this vulnerability as of 2026-05-30. CISA has confirmed active exploitation in the wild. Defenders should treat any Gogs server with default registration enabled as a target.

**Affected Software Versions:**
- Gogs 0.14.2 (latest stable release)
- Gogs 0.15.0+dev (latest development build)
- All older versions are presumed affected

**Indicators of Exploitation (host-based):**
- Unexpected files in `/tmp/` on Gogs server hosts (PoC creates `/tmp/rce_proof`)
- Unexpected shell processes (`sh`, `bash`, `cmd.exe`) spawned as children of `git` or the Gogs web process
- Repository pull requests with branch names containing `--exec`, `--exec=`, or shell metacharacters (`${IFS}`, `$(...)`, backticks)
- Git rebase logs showing command execution outside expected replay paths

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1190 | Exploit Public-Facing Application | Attacker exploits Gogs web interface accessible from internet; requires only authenticated (non-admin) account; open registration by default lowers bar to unauthenticated-equivalent access |
| Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | `--exec=<cmd>` flag injected into `git rebase` causes git to pass attacker-controlled string to `sh -c` after each replayed commit |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Same mechanism on Windows targets; cmd.exe executes the injected `--exec` payload |
| Discovery | T1083 | File and Directory Discovery | Post-exploitation: attacker reads all repository content, including private repos from other tenants on shared instance |
| Discovery | T1552.001 | Unsecured Credentials: Credentials In Files | Git repository content may contain hardcoded secrets; attacker can dump all hosted repos |
| Lateral Movement | T1021 | Remote Services | Attacker accesses other network-accessible systems from the compromised Gogs host using harvested credentials |
| Impact | T1565.001 | Data Manipulation: Stored Data Manipulation | Attacker can tamper with any hosted repository code after RCE |
| Impact | T1486 | Data Encrypted for Impact | Full server RCE enables deployment of ransomware or wiper against the Git server |

### Vulnerability Technical Detail

**GHSA ID:** GHSA-qf6p-p7ww-cwr9
**CVE:** Not yet assigned (as of 2026-05-30; Gogs maintainer unresponsive)
**CVSS v4 Score:** 9.4 (Critical)
**CWE:** CWE-88 — Argument Injection or Modification

**Root Cause:** The `Merge()` function in `internal/database/pull.go` passes the pull request's **base branch name** directly to a `git rebase` command without a POSIX `--` separator or argument sanitization. An attacker crafts a branch name such as:

```
--exec=touch${IFS}/tmp/rce_proof
```

When a "Rebase before merging" merge operation is triggered on a pull request using this branch, git's argument parser treats `--exec` as a flag rather than a branch name. Git then executes the attacker-controlled shell command via `sh -c` after each replayed commit.

**Prerequisites:**
1. Any authenticated Gogs account (no admin required)
2. Create a repository and open a pull request with the malicious branch name
3. Trigger a "Rebase before merging" merge operation (default merge strategy)

**Escalation to Unauthenticated:** Gogs ships with open registration (`DISABLE_REGISTRATION = false`) and no creation limit (`MAX_CREATION_LIMIT = -1`) by default. Any internet-exposed Gogs instance is effectively exploitable by an unauthenticated remote attacker who self-registers.

**Metasploit Module:** Rapid7 released a Metasploit module automating the full exploit chain against Linux and Windows targets (exploit completes in seconds).

**Disclosure Timeline:**
- 2026-03-17: Rapid7 researcher Jonah Burgess reports to Gogs maintainers
- 2026-03-28: Gogs maintainer acknowledges receipt
- 2026-03-28 through 2026-05-28: No further maintainer response; no patch delivered
- 2026-05-28: Rapid7 public disclosure; Metasploit module released
- 2026-05-28: CISA confirms active exploitation; no patch available

**Patch Status:** No official patch as of 2026-05-30. Rapid7 submitted a pull request with a suggested fix awaiting maintainer review.

**Internet Exposure:** Shadowserver tracks approximately 2,400 Gogs servers exposed online (1,894 in Asia, 319 in Europe). Shodan identifies over 1,000 IP addresses with Gogs fingerprints.

---

## 3. Malware & Tools

| Name | Type | Key Details |
|------|------|-------------|
| Metasploit Module (Rapid7) | Exploit Framework Module | Automates full RCE exploit chain against Gogs 0.14.2 and 0.15.0+dev on Linux and Windows; publicly available |
| No specific malware families | — | No malware family associated with observed exploitation at time of disclosure; exploitation grants full server OS command execution enabling deployment of any payload |

---

## 4. Threat Actor / Campaign Attribution

No specific threat actor has been publicly attributed to exploitation of GHSA-qf6p-p7ww-cwr9 at time of disclosure. CISA confirmed active exploitation in the wild. Given:
- The vulnerability's low exploitation complexity
- Immediate availability of a Metasploit module
- Large attack surface (2,400+ exposed servers globally)
- Cross-tenant data breach potential on shared hosting instances
- Potential for credential harvesting from hosted repositories

Exploitation is likely opportunistic by multiple actors, potentially including nation-state groups that target source code and developer infrastructure.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("gogs","gogs.exe")
  AND Processes.process_name IN ("sh","bash","dash","zsh","cmd.exe","powershell.exe","python","python3","perl","ruby")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
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
  AND (Processes.process="*rebase*--exec*" OR Processes.process="*--exec=*")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "--exec=.*[\$\(\)\`\;\|]"), 95,
    match(process, "--exec"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name="git"
  AND Processes.process_name IN ("sh","bash","cmd.exe","powershell.exe")
  AND NOT Processes.process IN ("*/usr/lib/git-core/*","*git-credential*","*git-remote*")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

## 6. Executive Summary

Rapid7 disclosed on 2026-05-28 a critical unpatched remote code execution vulnerability in Gogs, a widely deployed open-source self-hosted Git service. Tracked as GHSA-qf6p-p7ww-cwr9 (CVSS 9.4, no CVE yet), the flaw allows any authenticated user — including self-registered accounts on default-configured instances — to execute arbitrary OS commands on the server by opening a pull request with a specially crafted branch name containing the git `--exec` argument injection payload.

CISA confirmed active exploitation with no patch available. Rapid7 published a Metasploit module on the same day as disclosure, making exploitation fully automated.

The attack grants full OS command execution on the Gogs host, enabling:
- Cross-tenant data breach (access to all repositories on the instance)
- Credential harvesting from hosted repository content
- Lateral movement to other network-accessible systems
- Full server compromise (ransomware/wiper deployment)

**Immediate mitigations (no patch available):**
1. Disable open registration (`DISABLE_REGISTRATION = true` in `app.ini`)
2. Restrict the "Rebase before merging" merge strategy in repository settings
3. Remove internet exposure for Gogs instances not requiring public access
4. Monitor for shell processes spawned by the Gogs process or git on the host

---

## References

- [Rapid7 — Authenticated RCE via Argument Injection in Gogs (NOT FIXED, 2026-05-28)](https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/)
- [BleepingComputer — New Gogs Zero-Day Flaw Lets Hackers Get Remote Code Execution](https://www.bleepingcomputer.com/news/security/new-gogs-zero-day-flaw-lets-hackers-get-remote-code-execution/)
- [The Register — No Fix Yet for Critical RCE Bug in Open-Source Git Service Gogs (2026-05-29)](https://www.theregister.com/security/2026/05/29/no-fix-yet-for-critical-gogs-rce-bug-exploit-module-is-out/)
- [Infosecurity Magazine — CISA Flags Actively Exploited Gogs Vulnerability With No Patch](https://www.infosecurity-magazine.com/news/cisa-flags-exploited-gogs-flaw-no/)
- [GHSA-qf6p-p7ww-cwr9 — GitHub Security Advisory](https://github.com/advisories/GHSA-qf6p-p7ww-cwr9)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
