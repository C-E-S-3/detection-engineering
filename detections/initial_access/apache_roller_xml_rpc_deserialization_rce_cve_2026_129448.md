# Apache Roller XML-RPC Deserialization RCE (CVE-2026-129448)

## Description

Detects post-exploitation activity following unauthenticated deserialization RCE via Apache Roller's XML-RPC endpoint (`/roller-services/xmlrpc`). The endpoint deserializes extension-typed XML-RPC parameters before validating session credentials, allowing any unauthenticated attacker to execute OS commands as the Tomcat/JVM service user. CVE-2026-129448 affects Apache Roller versions 4.0.0 through 6.1.4; fix is 6.1.6+.

CISA added this to KEV on November 20, 2026 with a November 24 remediation deadline. Active exploitation confirmed; a public PoC is available on sploitus.com.

**False positives:** Legitimate administrative use of the Roller XML-RPC API (rare in production), Roller upgrade/migration scripts that invoke the endpoint, security scanner probes. The process-spawn detection (Tomcat spawning shells) has very low false positive rates in well-managed environments.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Persistence |
| Secondary Technique | Server Software Component: Web Shell |
| Secondary Technique ID | T1505.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("java","java.exe","catalina.sh","startup.sh","wrapper")
    AND Processes.process_name IN ("bash","sh","dash","zsh","cmd.exe","powershell.exe","pwsh.exe",
                                    "curl","wget","nc","ncat","nmap","python","python3","perl","ruby",
                                    "id","whoami","uname","ifconfig","ip")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)base64|/dev/tcp|/dev/udp|mkfifo|nc.*-e|bash.*-i|wget.*sh|curl.*sh"), 95,
    match(process,"(?i)whoami|id|uname|ifconfig") AND match(parent_process_name,"(?i)java|catalina"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url="*/roller-services/xmlrpc*"
    AND Web.http_method="POST"
  by Web.src Web.dest Web.url Web.http_method Web.status Web.bytes Web.user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    bytes > 2000 AND match(user_agent,"(?i)python|curl|wget|java|apache|xmlrpc"), 90,
    bytes > 1000, 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src dest url http_method status bytes user_agent risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_path IN ("*/webapps/roller/*","*/webapps/ROOT/*","*/tomcat/webapps/*")
    OR Filesystem.file_path LIKE "%/roller/WEB-INF/%")
    AND Filesystem.file_name IN ("*.jsp","*.jspx","*.war","*.php")
    AND (Filesystem.action="created" OR Filesystem.action="modified")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_path file_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Java/Tomcat spawning shell with reverse shell indicators (`/dev/tcp`, `mkfifo`, `nc -e`, `base64`) | 95 | Critical — matches active exploitation pattern; near-certain post-exploitation activity |
| Java/Tomcat spawning reconnaissance commands (`whoami`, `id`, `uname`) | 90 | High — post-exploitation recon immediately following deserialization RCE |
| Java/Tomcat spawning any unexpected interpreter/shell | 80 | High — anomalous child process from JVM parent |
| POST to `/roller-services/xmlrpc` with large body and tool User-Agent | 90 | High — matches exploit tooling signature |
| POST to `/roller-services/xmlrpc` with body > 1000 bytes | 80 | High — normal XML-RPC calls are small; large bodies suggest serialized payloads |
| JSP/WAR file created in Tomcat webapps directory | 95 | Critical — web shell deployment |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unattributed (active exploitation per CISA KEV) | [CISA KEV — CVE-2026-129448](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Generic ransomware pre-positioning actors | [Apache Roller Advisory](https://lists.apache.org/thread/roller-dev) |

## References

- [CISA KEV Alert — November 20, 2026](https://www.cisa.gov/news-events/alerts/2026/11/20/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- [The Hacker News — Apache Roller CVE-2026-129448](https://thehackernews.com/2026/11/critical-apache-roller-rce-flaw-under.html)
- [BleepingComputer — Apache Roller RCE exploited](https://www.bleepingcomputer.com/news/security/apache-warns-of-roller-rce-vulnerability-exploited-in-attacks/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/)
