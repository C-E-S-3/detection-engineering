# PHP2Shell Web Worker Shell Spawn (CVE-2026-109618 / CVE-2026-109619)

## Description

Detects PHP or web server worker processes spawning a shell interpreter — the primary post-exploitation signal for PHP2Shell (CVE-2026-109618 and CVE-2026-109619). Both CVEs enable unauthenticated RCE in PHP 8.2–8.5 via memory corruption and stale global state; successful exploitation results in the web server or PHP-FPM process executing attacker-controlled commands via a shell child process. This detection covers Apache (httpd/apache2), PHP-FPM, LiteSpeed, and FrankenPHP as parent processes. False positive sources: legitimate PHP applications that intentionally invoke shell_exec(), system(), or proc_open() for admin tasks; custom PHP build scripts that call shell commands directly. Baseline expected parent→child process pairs in your environment before enabling at high alert priority.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary technique: T1059.004 (Unix Shell) — the shell spawn is the execution phase of the exploit; T1505.003 (Server Software Component: Web Shell) if the attacker writes a persistent PHP file.

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name IN ("httpd","apache2","apache","php-fpm","php","php8.2","php8.3","php8.4","php8.5","litespeed","lsphp","frankenphp"))
    AND (Processes.process_name IN ("sh","bash","dash","zsh","ksh","csh","tcsh"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(wget|curl|chmod\s+[0-7]{3,4}|nc\s|ncat\s|python|perl|ruby|base64|xxd|dd\s|cp\s.*/tmp|mv\s.*/tmp)"), 95,
    match(process,"(?i)(/tmp/|/dev/shm/|/var/tmp/|/run/shm/)"), 90,
    match(process,"(?i)(id\b|whoami|uname|cat\s.*/etc/passwd|cat\s.*/etc/shadow)"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Shell command executing download tools (wget/curl), netcat, Python, Perl, base64 decode, or moving files to /tmp | 95 | Extremely high confidence attacker shell execution; no legitimate PHP app should spawn these via a shell |
| Shell child process path contains /tmp/, /dev/shm/, /var/tmp/ | 90 | Attacker staging in writable temp directories; unusual for legitimate PHP execution |
| Shell running recon commands (id, whoami, uname, passwd) | 85 | Classic post-exploitation enumeration via web shell or direct RCE |
| Any shell spawn from PHP/Apache parent (no suspicious content matched) | 75 | Baseline suspicious; PHP rarely needs to spawn a shell interpreter; investigate for false positive baseline |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| PHP2Shell opportunistic actors (unattributed) | [Datadog Security Labs PHP2Shell Analysis](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/) |
| Any threat actor targeting PHP web infrastructure | [CVE-2026-109618 NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109618), [CVE-2026-109619 NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109619) |

## References

- [Datadog Security Labs — PHP2Shell: CVE-2026-109618 & CVE-2026-109619 Technical Analysis](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [BleepingComputer — PHP Ships Emergency Patches for Critical PHP2Shell Flaws](https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/)
- [CrowdStrike — PHP2Shell Customer Protection](https://www.crowdstrike.com/en-us/blog/crowdstrike-protects-customers-from-php-rce-zero-days/)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1059.004 — Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
