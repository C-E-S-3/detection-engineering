# LiteSpeed cPanel Plugin Symlink Following → Root (CVE-2026-54420)

## Description

Detects exploitation of CVE-2026-54420, a symlink-following privilege escalation in the LiteSpeed Web Server cPanel integration plugin (lsws-cpanel / LSWrap). The LSWrap daemon runs as root to manage virtual host configurations. When processing user-controlled document root paths, it follows symbolic links without validating symlink targets. An authenticated cPanel user can:

1. Create a symlink inside their document root pointing to `/etc/shadow`, `/root/.ssh/authorized_keys`, or `/etc/cron.d/`
2. Trigger a LiteSpeed config reload or vhost rebuild
3. LSWrap (root) follows the symlink, giving the attacker read/write access to the target

CISA added CVE-2026-54420 to the KEV catalog on 2026-06-15; federal deadline 2026-06-29. Exploitation chains observed in-the-wild: symlink → SSH key injection → persistent root access.

False positives: Rule 102302 (config reload) fires on legitimate admin reloads; correlate with rule 102300/102301 (symlink creation) before escalating. Rule 102306 (root session) is common on dedicated hosting servers; only escalate when preceded by symlink activity within the timeframe window.

**Audit key prerequisites (deploy via inframan `proxmox-auditd-security` role):**
- `symlink_priv_path`: `-a always,exit -F arch=b64 -S symlink,symlinkat -F dir=/var/www -F key=symlink_priv_path`
- `web_docroot_write`: `-a always,exit -F arch=b64 -S write,rename,symlink -F dir=/var/www -k web_docroot_write`
- `sensitive_file_access`: `-a always,exit -F arch=b64 -S open,openat -F path=/etc/shadow -F path=/etc/passwd -F path=/root -k sensitive_file_access`
- `exec_shell`: `-a always,exit -F arch=b64 -S execve -F exe=/bin/bash -F exe=/bin/sh -k exec_shell`

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation |
| Tactic ID | TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |

Secondary techniques: T1098.004 (Account Manipulation: SSH Authorized Keys — root key injection, rule 102304), T1053.003 (Scheduled Task/Job: Cron — root cron persistence, rule 102305), T1078.003 (Valid Accounts: Local Accounts — root session post-exploitation, rule 102306/102307)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Privilege Escalation |
| Installation (SSH key / cron) |

## Wazuh Rules

| Rule ID | Level | Description |
|---------|-------|-------------|
| 102300 | 14 | Auditd: symlink to privileged path (`symlink_priv_path` key) |
| 102301 | 12 | Auditd: symlink syscall in web document root (`web_docroot_write` key) |
| 102302 | 10 | Syslog: LiteSpeed config reload triggered |
| 102303 | 15 | Auditd: LiteSpeed process accessing sensitive system file |
| 102304 | 15 | Auditd: LiteSpeed process wrote /root/.ssh/authorized_keys |
| 102305 | 15 | Auditd: LiteSpeed process wrote to cron directory |
| 102306 | 13 | Syslog: root session opened on LiteSpeed host |
| 102307 | 15 | Auditd: LiteSpeed process spawned an interactive shell |
| 102310 | 14 | 3+ symlinks in docroot within 60s — scripted exploitation |
| 102311 | 15 | Symlink + config reload within 5 min — exploitation sequence |
| 102312 | 15 | Full kill chain: symlink + reload + root session within 10 min |

## Splunk Detection Query

```spl
index=linux sourcetype=linux_audit
(key="symlink_priv_path" OR key="web_docroot_write" OR key="sensitive_file_access" OR key="exec_shell")
| eval lspeed_exec=if(match(exe, "(?i)/(lshttpd|lsphp|lswrap|lsws)"), "YES", "NO")
| where key="symlink_priv_path" OR lspeed_exec="YES"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(key) as audit_keys values(exe) as executables values(file_name) as files_accessed
    by host auid uid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    mvcount(audit_keys) >= 3, 98,
    in(audit_keys, "sensitive_file_access") AND lspeed_exec="YES", 95,
    in(audit_keys, "symlink_priv_path"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime host auid uid audit_keys executables files_accessed count risk_score
| sort -risk_score
```

**Supplemental: SSH authorized_keys write by LiteSpeed process**

```spl
index=linux sourcetype=linux_audit
key="sensitive_file_access"
file_name="/root/.ssh/authorized_keys"
| regex exe="(?i)/(lshttpd|lsphp|lswrap|lsws)"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(exe) as process values(syscall) as syscalls
    by host auid uid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=98
| table firstTime lastTime host auid uid process syscalls count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Full kill chain: symlink + reload + root session | 98 | All three exploitation stages confirmed |
| LiteSpeed accessing /root/ or /etc/shadow | 95 | Direct exploitation artifact — root file read |
| LiteSpeed writing authorized_keys or cron | 98 | Persistence established — immediate containment required |
| Symlink to privileged path (audit key hit) | 85 | Attacker planted symlink; reload not yet triggered |
| Multiple symlinks in short window | 80 | Scripted exploitation; manual verification needed |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Web hosting compromise campaigns | Mass-exploitation of cPanel vulnerabilities for crypto mining / spam relay |
| Ransomware initial access brokers | Privilege escalation on shared hosting for lateral movement |

## References

- [CISA KEV June 15 2026](https://www.cisa.gov/news-events/alerts/2026/06/15/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [MITRE T1068](https://attack.mitre.org/techniques/T1068/)
- [MITRE T1098.004](https://attack.mitre.org/techniques/T1098/004/)
- [MITRE T1053.003](https://attack.mitre.org/techniques/T1053/003/)
