---
title: "Red Heron Weaponizes Gitea RCE to Deliver JITTERLY Implant and SIXZUT LD_PRELOAD Rootkit"
source: Acronis Threat Research Unit
source_url: https://www.acronis.com/en/tru/posts/red-heron-exploits-gitea-n-day-flaw-in-multinational-campaign-exposing-new-linux-rootkit/
date: 2026-09-19
scraped_at: 2026-09-19T00:00:00Z
report_type: threat-intel
severity: critical
tags: [red-heron, jitterly, sixzut, gitea, ld-preload, rootkit, linux, cve-2026-60004, china, espionage]
mitre_tactics: [TA0001, TA0002, TA0003, TA0005, TA0011]
---

# Red Heron Weaponizes Gitea RCE to Deliver JITTERLY Implant and SIXZUT LD_PRELOAD Rootkit

## Executive Summary

Acronis Threat Research Unit published research in September 2026 documenting a multinational campaign by the Chinese-speaking threat actor **Red Heron**, which rapidly weaponized **CVE-2026-60004**—a critical remote code execution vulnerability in Gitea (CVSS 9.8, affects 1.17–1.27.0)—to compromise 13 organizations across 5+ countries. The actor deployed a previously undocumented C++ Linux implant (**JITTERLY**) paired with a novel LD_PRELOAD rootkit (**SIXZUT**) capable of hiding files, processes, and network connections from standard administrative tools. CVE-2026-60004 was patched in Gitea 1.27.1 on July 27, 2026; Red Heron began automated exploitation via a Python framework (`exp_enhanced.py`) by July 29, 2026—two days after patch release.

**Note:** CVE-2026-60004 exploitation was previously tracked in `2026-08-27_cisa-kev-cve-2026-60004-gitea-rce-actively-exploited.md`. This report adds Red Heron threat-actor attribution and details the post-exploitation toolchain (JITTERLY + SIXZUT) for the first time.

## IOCs

### File Artifacts

| Indicator | Role |
|-----------|------|
| `exp_enhanced.py` | Red Heron Python exploitation framework for CVE-2026-60004; automated scanning and weaponization; git hook injection and account registration |
| `libglthread.so.2` | SIXZUT rootkit shared library disguised as a legitimate threading library; loaded via `/etc/ld.so.preload` |
| `/etc/ld.so.preload` | Persistence mechanism; SIXZUT injects itself into dynamically linked processes by registering here |

### Network Infrastructure

No specific C2 IP addresses or domains recovered from publicly available reporting at time of ingestion. Refer to the Acronis TRU full disclosure for network indicators.

### File Hashes

No specific hashes available from publicly accessible reporting at time of ingestion. Full hashes are in the Acronis TRU report.

## TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Initial Access | Exploit Public-Facing Application | T1190 | CVE-2026-60004 Gitea RCE (CVSS 9.8); exploited within 2 days of patch release; affects Gitea 1.17–1.27.0; patched in 1.27.1 |
| Execution | Command and Scripting Interpreter: Python | T1059.006 | `exp_enhanced.py` Python framework automates exploitation, git hook injection, and account registration |
| Execution | Exploitation for Client Execution | T1203 | Git hook abuse triggers arbitrary command execution on the Gitea server after initial RCE |
| Persistence | Hijack Execution Flow: Dynamic Linker Hijacking | T1574.006 | SIXZUT rootkit installed as `libglthread.so.2`; registered in `/etc/ld.so.preload` for automatic loading into all dynamically linked processes |
| Defense Evasion | Rootkit | T1014 | SIXZUT patches 15 Linux kernel functions to hide files, processes, and network connections from ls, ps, netstat, and similar tools |
| Defense Evasion | Indicator Removal | T1070 | SIXZUT hides persistence artifacts, network connections, and JITTERLY process from administrators; relaunches JITTERLY if terminated |
| Command and Control | Encrypted Channel: Symmetric Cryptography | T1573.001 | JITTERLY uses AES-128-GCM for all C2 communications; protocol closely resembles the Adaptix open-source C2 framework Linux agent |
| Command and Control | Protocol Tunneling | T1572 | JITTERLY supports network tunneling for internal pivoting to non-internet-exposed assets |
| Collection | Data from Local System | T1005 | Source code repositories and sensitive files stolen from compromised Gitea instances |

### Kill Chain Phase
**Delivery → Exploitation → Installation → Command & Control → Actions on Objectives**

## Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| JITTERLY | C++ Linux implant | 30+ post-exploitation commands: shell execution, file transfer, process termination, network tunneling, interactive terminal access, internal pivoting; AES-128-GCM encrypted C2; Adaptix-compatible protocol |
| SIXZUT | LD_PRELOAD rootkit | Deployed as `libglthread.so.2`; loaded via `/etc/ld.so.preload`; patches 15 Linux functions to hide files, processes, and network connections; auto-relaunches JITTERLY if killed |
| exp_enhanced.py | Python exploitation framework | Weaponizes CVE-2026-60004 for automated scanning and exploitation of 1,386 scanned Gitea instances; leverages git hook injection and account registration for initial access |

## Threat Actor / Campaign Attribution

- **Threat Actor**: Red Heron (Chinese-speaking APT, unconfirmed state alignment)
- **Motivation**: Espionage — target classifications recorded in Simplified Chinese cover defense, elections, energy, aerospace, telecommunications, government, and research sectors
- **Scale**: 1,386 Gitea instances scanned; 13 confirmed compromises
- **Countries affected**: Canada, Argentina, Taiwan, United States, Sri Lanka (6 countries total)
- **Campaign start**: July 29, 2026 (two days after CVE-2026-60004 patch release)
- **Disclosure**: September 2026 (Acronis TRU)

## Associated Threat Actors

| Actor | Alias | Attribution |
|-------|-------|-------------|
| Red Heron | (no established ATT&CK group page at time of report) | Chinese-speaking; Simplified Chinese target categorization; espionage focus across critical sectors in 6 countries |

## Splunk Detection Searches

See also: `detections/initial_access/gitea_cve_2026_60004_diffpatch_git_hook_rce.md` for initial exploitation detection.
See also: `detections/persistence/ld_preload_rootkit_persistence.md` for generic SIXZUT rootkit persistence detection.

### 1 — SIXZUT Rootkit: /etc/ld.so.preload Modification (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="/etc/ld.so.preload"
     OR Filesystem.file_name="libglthread.so.2"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
     Filesystem.process_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    file_path="/etc/ld.so.preload", 90,
    file_name="libglthread.so.2", 85,
    true(), 70)
| where risk_score >= 70
| table firstTime lastTime dest user file_path file_name process_name action risk_score
```

**Risk Score**: 85–90 (Critical) — `/etc/ld.so.preload` modification is the primary persistence mechanism for LD_PRELOAD rootkits; `libglthread.so.2` is a SIXZUT-specific file name indicator.

### 2 — JITTERLY: Gitea Spawning Unexpected Child Processes (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("gitea","git","git-http-backend","git-receive-pack")
    AND Processes.process_name NOT IN ("git","gitea","sh","bash","git-http-backend","git-receive-pack","git-upload-pack")
  by Processes.dest Processes.user Processes.process_name Processes.process_path
     Processes.process Processes.parent_process_name Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name process_path parent_process_name process process_id
```

**Risk Score**: 90 (Critical) — Gitea spawning non-git child processes is a strong indicator of git hook RCE exploitation (CVE-2026-60004 attack path).

### 3 — Red Heron: Python Exploitation Framework Execution from Web Server Context (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("python","python3","python3.10","python3.11","python3.12")
    AND (Processes.process="*exp_enhanced*"
      OR Processes.parent_process_name IN ("gitea","git","nginx","apache2","httpd"))
  by Processes.dest Processes.user Processes.process_name Processes.process
     Processes.parent_process_name Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name process parent_process_name process_id
```

**Risk Score**: 90 (Critical) — Python spawned from a Gitea/web server parent process is characteristic of the Red Heron `exp_enhanced.py` exploitation framework executing post-hook-injection.

## References

- [Acronis TRU: Red Heron exploits Gitea n-day flaw exposing new Linux rootkit](https://www.acronis.com/en/tru/posts/red-heron-exploits-gitea-n-day-flaw-in-multinational-campaign-exposing-new-linux-rootkit/)
- [The Hacker News: Red Heron Exploits Gitea RCE to Compromise 13 Organizations](https://thehackernews.com/2026/09/red-heron-exploits-gitea-rce-to.html)
- [Industrial Cyber: Red Heron exploits Gitea RCE flaw in multinational campaign](https://industrialcyber.co/ransomware/red-heron-exploits-gitea-rce-flaw-in-multinational-campaign-targeting-industrial-and-government-organizations/)
- [GBHackers: Red Heron Hackers Exploit Critical Gitea RCE](https://gbhackers.com/red-heron-hackers-exploit-critical-gitea-rce/)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006/)
- [MITRE ATT&CK T1014 — Rootkit](https://attack.mitre.org/techniques/T1014/)
- [CVE-2026-60004 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60004)
- [Prior KEV tracking: 2026-08-27_cisa-kev-cve-2026-60004-gitea-rce-actively-exploited.md]
