# SonicWall SMA1000 OS Command Injection (CVE-2026-15410)

## Description

Detects exploitation of CVE-2026-15410, an OS command injection vulnerability in SonicWall SMA1000 Secure Mobile Access appliances. An attacker with administrator credentials can inject arbitrary OS commands via specific parameters in the SMA1000 admin API. Under specific conditions, shell metacharacters in admin API request parameters are passed unsanitized to an OS shell call, resulting in arbitrary command execution with the privileges of the SMA1000 web management daemon.

CISA added CVE-2026-15410 to the Known Exploited Vulnerabilities catalog on 2026-07-14 with a federal remediation deadline of 2026-07-17.

Detection covers three signal layers:

1. **HTTP/Proxy layer (Traefik JSON)**: Admin API requests to SMA1000 configuration and diagnostic endpoints containing shell metacharacters (`; | \` $( %3B %7C %60`) or URL-encoded command injection sequences.
2. **SMA1000 syslog layer**: Management daemon log messages referencing admin API endpoints combined with URL-encoded or hex-encoded shell metacharacter patterns.
3. **Process execution layer**: Shell interpreter or general-purpose scripting process spawned directly from the SMA1000 web management daemon — the definitive confirmation of successful code injection.

Exploitation requires admin authentication (admin credentials must be compromised or guessed). The combination of an authenticated admin session with shell metacharacters in API parameters is highly suspicious and has minimal benign explanation in the SMA1000 admin API context.

False positive sources: Admin API parameter values sometimes contain characters that superficially resemble metacharacters (e.g., pipe in regex values). Review the full request path and parameter context. Process spawning from the management daemon has no legitimate benign explanation and should be treated as confirmed exploitation.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: Unix Shell |
| Technique ID | T1059.004 |
| Secondary Tactic | Initial Access |
| Secondary Technique | T1190 — Exploit Public-Facing Application |
| Secondary Tactic | Persistence |
| Secondary Technique | T1505.003 — Server Software Component: Web Shell (post-exploitation) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |
| Actions on Objectives |

## Wazuh Detection Coverage

| Rule ID | Description | Severity |
|---------|-------------|----------|
| 103941 | Base anchor: HTTP request to SMA1000 admin configuration or diagnostic API | 7 (Low) |
| 103942 | Code injection: shell metacharacters in SMA1000 admin API request parameters | 14 (Critical) |
| 103943 | Process confirmation: shell/interpreter spawned from SMA1000 management daemon | 15 (Critical) |
| 103944 | Syslog: SMA1000 management daemon log shows encoded injection in admin API call | 13 (Critical) |

## Splunk Detection Query

```spl
| comment "Query 1: Shell metacharacters in SMA1000 admin API request (web/proxy)"
index=proxy OR index=web OR index=traefik
(uri_path="*/management/configure/*" OR uri_path="*/api/v1/admin/*"
 OR uri_path="*/api/v2/admin/*" OR uri_path="*/api/v1/system/*"
 OR uri_path="*/api/v2/system/*" OR uri_path="*/cfg/*"
 OR uri_path="*/diagnose/*" OR uri_path="*/management/diagnostic/*"
 OR uri_path="*/management/upgrade/*" OR uri_path="*/api/v1/network/*")
(uri_query="*;*" OR uri_query="*|*" OR uri_query="*`*" OR uri_query="*$(*"
 OR uri_query="*%3B*" OR uri_query="*%7C*" OR uri_query="*%60*"
 OR uri_query="*%24%28*" OR uri_query="*%0A*" OR uri_query="*%0D*"
 OR uri_query="*%26%26*" OR uri_query="*%7C%7C*")
| stats count min(_time) as firstTime max(_time) as lastTime
    by src_ip uri_path uri_query http_method http_status dest
| eval risk_score=case(
    match(uri_query,"(?i)%0[aA]|%0[dD]|\\\\x0a|\\\\x0d"), 90,
    match(uri_query,"(?i)%24%28|\\$\\("), 90,
    match(uri_query,"(?i)%60|`"), 85,
    match(uri_query,"(?i)%3[Bb]|;"), 80,
    match(uri_query,"(?i)%7[Cc]|\\|"), 75,
    1=1, 70)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest uri_path uri_query http_method http_status risk_score
```

```spl
| comment "Query 2: Shell process spawned from SMA1000 management daemon (auditd/syslog)"
index=linux_auditd OR index=syslog OR index=endpoint
(parent_process_name IN ("smad","webservd","sma1000d","sslvpnd","vpnd","httpd")
 OR parent_process="*/smad" OR parent_process="*/webservd" OR parent_process="*/sslvpnd")
(process_name IN ("bash","sh","dash","zsh","python","python3","perl","ruby")
 OR process IN ("*/bash","*/sh","*/dash","*/python","*/python3","*/perl"))
| stats count min(_time) as firstTime max(_time) as lastTime
    by dest parent_process_name parent_process process_name process cmdline user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest parent_process_name process_name cmdline user
```

```spl
| comment "Query 3: Post-exploitation - unusual file writes or network tools from SMA1000 daemon"
index=linux_auditd OR index=endpoint
(parent_process_name IN ("smad","webservd","sma1000d","sslvpnd","httpd"))
(process_name IN ("curl","wget","nc","ncat","socat","python","python3","perl")
 OR (process_name IN ("bash","sh") AND match(cmdline,"(?:curl|wget|nc |socat|/dev/tcp)")))
| stats count min(_time) as firstTime max(_time) as lastTime
    by dest parent_process_name process_name cmdline user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest parent_process_name process_name cmdline user
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Shell spawned from SMA1000 management daemon | 100 | No benign explanation; confirmed code injection |
| Newline injection (%0a/%0d) in admin API params | 90 | Command separation via HTTP injection |
| Command substitution ($() or backtick) in admin params | 90 | Direct OS command execution attempt |
| Semicolon/pipe in admin API params (multiple classes) | 85 | Command chaining injection pattern |
| Single shell metachar in URL-encoded form | 75 | Possible injection; correlate with endpoint |
| Download tool spawned from SMA1000 daemon | 95 | Post-exploitation tool staging |

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| Unknown nation-state and financially-motivated actors | CISA KEV designation indicates confirmed in-the-wild exploitation as of 2026-07-14 |
| Ransomware affiliates | VPN appliance compromise is a common ransomware initial access vector for lateral movement |

## Remediation

1. Apply SonicWall security patches for CVE-2026-15410 immediately (federal deadline 2026-07-17)
2. Restrict SMA1000 admin API access to known admin workstation IPs only; block external access to admin endpoints
3. Rotate all SMA1000 administrator credentials as a precaution; treat any admin session from unexpected source IPs as compromised
4. Enable web application firewall (WAF) rules to block shell metacharacters in API parameters as a temporary mitigation
5. Monitor Wazuh rules 103941-103944; treat any alert from rule 103943 as a confirmed incident requiring immediate response

## References

- CISA KEV: CVE-2026-15410 added 2026-07-14, deadline 2026-07-17
- SonicWall Security Advisory: SNWLID-2026-0024 (SMA1000 Command Injection)
- NVD: CVE-2026-15410
- MITRE ATT&CK: T1059.004 — Unix Shell
- CWE-77: Improper Neutralization of Special Elements used in a Command (Command Injection)
