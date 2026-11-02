# ARTEX MySQL general_log Webshell Deployment

## Description

Detects weaponization of MySQL's global query logging feature (`general_log_file`) to write JSP, PHP, ASPX, or other web application shell content to arbitrary filesystem paths accessible by the web server. This technique, observed in ARTEX agentic offensive framework intrusions (GTIG, October 2026), bypasses `INTO OUTFILE`-based write restrictions and file write ACLs by routing the webshell payload through the MySQL logging subsystem.

The attack sequence is:
1. Attacker obtains MySQL root or SUPER-privilege access (via SQL injection, credential compromise, or post-exploitation).
2. `SET GLOBAL general_log_file` is changed to a web-accessible path ending in `.jsp`, `.php`, `.aspx`, etc.
3. `SET GLOBAL general_log = 'ON'` activates logging.
4. A `SELECT` statement containing the webshell source code causes MySQL to write the payload to the target path as a log entry.
5. The JSP/PHP webshell is now accessible through the web server.

Observed webshell filenames: `cl1217.jsp`, `f1219a.jsp`, `z1219.jsp`.

False positives are extremely low. Legitimate applications almost never set `general_log_file` to a web application deploy path. DBA activity that changes the log file path (e.g., during maintenance) typically targets `/var/log/mysql/` or similar system log directories, not webroot paths. Tune the path pattern to your web server deploy directories if needed.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Primary Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter |
| Technique ID | T1059 |
| Secondary Tactic | Persistence |
| Secondary Technique ID | TA0003 |
| Secondary Technique | Server Software Component: Web Shell |
| Secondary Technique ID | T1505.003 |
| Secondary Tactic | Defense Evasion |
| Secondary Tactic ID | TA0005 |
| Secondary Technique | Indirect Command Execution (via logging subsystem) |
| Secondary Technique ID | T1202 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
index=* (sourcetype="mysql" OR sourcetype="mysql:general" OR sourcetype="mysql:error")
  "general_log_file"
| regex _raw="(?i)SET\s+GLOBAL\s+general_log_file\s*=\s*['\"]?[^'\";\s]*\.(jsp|php|aspx|cfm|asp|war|jspx)"
| rex field=_raw "general_log_file\s*=\s*['\"]?(?P<webshell_path>[^'\";\s]+)"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(webshell_path) as webshell_paths
    values(src) as src_hosts
    by host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime host src_hosts webshell_paths count risk_score
```

### Supplemental: Webshell File Creation in Web Deploy Directories

This query detects the resulting webshell file being created on disk, useful when MySQL logs are not forwarded to the SIEM:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_name="*.jsp" OR Filesystem.file_name="*.jspx")
    AND (match(Filesystem.file_path, "(?i)(webapps|deploy|ROOT|htdocs|www|public_html|wwwroot)")
         OR Filesystem.process_name IN ("mysqld", "mysqld_safe", "mysql"))
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
     Filesystem.process_name Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("mysqld", "mysqld_safe", "mysql"), 95,
    match(file_path, "(?i)(webapps|ROOT|deploy)"), 80,
    true(), 65)
| where risk_score >= 65
| table firstTime lastTime dest user file_name file_path process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `general_log_file` SET to web extension path (primary query) | 90 | Near-certain malicious; no legitimate DBA workflow sets log path to `.jsp`/`.php` |
| JSP/JSPX file created by `mysqld` process (supplemental) | 95 | MySQL daemon writing JSP files is always anomalous |
| JSP/JSPX file created in `webapps`/`ROOT`/`deploy` path | 80 | Webshell deployment highly likely; correlate with process that wrote it |
| JSP/JSPX in web path by other process | 65 | Suspicious; correlate with SQL injection indicators |

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| UNC7228 (STORM-0940) | PRC-nexus cluster; primary operator of ARTEX; observed using this technique in enterprise AD intrusions (GTIG, October 2026) |
| ARTEX framework users (broad) | Any operator using ARTEX, ScopeWeaver, or ARTEX PRO may leverage this built-in module |
| Financially motivated extortion groups | ARTEX forks used by ransomware precursor operators who use webshells for persistent access before deploying ransomware |

## References

- [GTIG — ARTEX and Friends: Enter Agentic Offensive Frameworks (2026-10-30)](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks)
- [MITRE ATT&CK — T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MySQL Reference — general_log_file System Variable](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_general_log_file)
- Threat intel report: `threat-intel/2026-10-30_cloud-google-com-blog-topics-threat-intelligence-artex-and-friends-agentic-offensive-frameworks.md`
