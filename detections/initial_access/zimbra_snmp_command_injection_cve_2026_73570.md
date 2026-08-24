# Zimbra SNMP Command Injection (CVE-2026-73570) Exploitation and Post-Exploitation

## Description

Detects exploitation and post-exploitation activity for CVE-2026-73570, an unauthenticated OS command injection in Zimbra Collaboration Suite (ZCS) versions before 10.1.20. The flaw exists in SNMP notification processing (`swatchdog` service) when the optional `zimbra-snmp` package is installed and `snmp_notify` is enabled. An attacker sends specially crafted SMTP requests that are relayed through the SNMP notification handler and result in arbitrary shell command execution as the `zimbra` user.

CERT Polska confirmed active in-the-wild exploitation on 2026-08-17 and CISA added the CVE to its Known Exploited Vulnerabilities catalog on 2026-08-21 (FCEB deadline 2026-08-24). The bug yields shell as the `zimbra` user, sufficient for webshell drop under Jetty webapps directories and privilege escalation.

**Detection strategy:** three complementary conditions —
1. `swatchdog` or Zimbra Jetty/Java parent process spawning a shell / interpreter as the `zimbra` (or `postfix`) user,
2. `.jsp`, `.jspx`, `.war`, or `.class` file creation under `/opt/zimbra/jetty/webapps/` or `/opt/zimbra/jetty_base/webapps/`, and
3. file drops in `/tmp/` by the `zimbra` user with executable extensions.

**Expected false positives:**
- Zimbra admin scripts and package upgrades legitimately spawn shells from Jetty/Java; scope by user and by parent process.
- Backup and monitoring agents may create files under `/tmp/` — allowlist known agent names in the `file_name` regex.
- Custom Zimbra extensions ship `.jsp` files under Jetty webapps at install/upgrade time; correlate with change-management windows.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution (TA0002) |
| Secondary Technique | T1059.004 — Unix Shell |
| Secondary Tactic 2 | Persistence (TA0003) |
| Secondary Technique 2 | T1505.003 — Web Shell |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.parent_process_name IN ("swatchdog","perl","java","httpd","nginx","mailboxd")
       OR Processes.parent_process_path="*/opt/zimbra/*")
  AND Processes.process_name IN ("sh","bash","dash","zsh","perl","python","python3","curl","wget","nc","ncat","socat")
  AND Processes.user IN ("zimbra","postfix")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name,"swatchdog"), 95,
    match(process,"(?i)(base64|-e\\s|\\|.*sh|/dev/tcp|bash\\s-i|curl.*http|wget.*http)"), 85,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Companion query — Zimbra webshell file drop:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where (Filesystem.file_path="/opt/zimbra/jetty/webapps/*"
       OR Filesystem.file_path="/opt/zimbra/jetty_base/webapps/*")
  AND Filesystem.action IN ("created","modified")
  AND Filesystem.file_name IN ("*.jsp","*.jspx","*.war","*.class","*.sh","*.pl","*.py")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"(?i)(shell|cmd|proxy|backdoor|jspspy|reGeorg|godzilla|behinder|c99)"), 95,
    match(file_name,"(?i)\\.jspx?$"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user file_path file_name action risk_score
```

**Companion query — `/tmp/` staging by `zimbra` user:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path="/tmp/*"
  AND Filesystem.user="zimbra"
  AND Filesystem.action="created"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"(?i)\\.(sh|elf|py|pl|jsp|war|so|bin)$"), 90,
    match(file_name,"(?i)^\\."), 80,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime dest user file_path file_name file_hash risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `swatchdog` parent spawning shell as `zimbra` user | 95 | Direct exploitation artifact — `swatchdog` is the vulnerable SNMP notification handler; no benign reason to spawn interactive shells |
| Shell/interpreter with encoded / reverse-shell / download indicators (`base64`, `bash -i`, `/dev/tcp`, `curl http`) | 85 | Strong post-exploitation staging signal from Zimbra web tier |
| Jetty webapps webshell filename matches known family (`shell`, `godzilla`, `behinder`, `reGeorg`, `jspspy`, `c99`) | 95 | Named webshell family — near-certain compromise |
| Generic `.jsp`/`.jspx` file creation under Jetty webapps | 85 | Suspicious outside of formal Zimbra upgrade windows |
| `/tmp/` file drop by `zimbra` user with executable extension | 90 | Consistent with CERT.PL exploitation guidance |
| Any other Zimbra-tier interpreter spawn | 60 | Baseline suspicion — analyst triage tier |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unattributed (CVE-2026-73570 in-the-wild exploitation) | [CERT.PL / SecurityWeek — 2026-08-17](https://www.securityweek.com/hackers-target-zimbra-servers-in-active-exploitation-campaign/) |
| TA488 / OwaReaper (historical Zimbra n-day exploiter) | [BleepingComputer / Proofpoint 2026-08-03 CVE-2026-42897 report](https://www.bleepingcomputer.com/) |
| Laundry Bear (historical Zimbra XSS exploiter — CVE-2025-66376) | [CISA AA26-204A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-204a) |
| Winter Vivern (historical Zimbra CVE-2023-37580 exploiter) | [MITRE ATT&CK Winter Vivern (G1035)](https://attack.mitre.org/groups/G1035/) |
| UNC3707 / TA445 (historical Zimbra CVE-2022-27924 exploiter) | [Mandiant Zimbra reporting](https://cloud.google.com/blog/topics/threat-intelligence) |

## References

- [CISA KEV catalog — 2026-08-21 addition](https://www.cisa.gov/news-events/alerts/2026/08/21/cisa-adds-one-known-exploited-vulnerability-catalog)
- [GitHub Security Advisory GHSA-jqh7-pchh-v74j (CVE-2026-73570)](https://github.com/advisories/GHSA-jqh7-pchh-v74j)
- [SecurityWeek — Hackers Target Zimbra Servers in Active Exploitation Campaign](https://www.securityweek.com/hackers-target-zimbra-servers-in-active-exploitation-campaign/)
- [BleepingComputer — Critical Zimbra RCE flaw now actively exploited in attacks](https://www.bleepingcomputer.com/news/security/critical-zimbra-rce-flaw-now-actively-exploited-in-attacks/)
- [The Hacker News — Attackers Exploit Zimbra SNMP Flaw for Unauthenticated Remote Code Execution](https://thehackernews.com/2026/08/attackers-exploit-zimbra-snmp-flaw-for.html)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [Related threat intel report in this repo](../../threat-intel/2026-08-23_zimbra-cve-2026-73570-snmp-command-injection-kev.md)
