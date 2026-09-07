# StyleSmuggler: Magento / Adobe Commerce Unauthenticated GraphQL RCE

## Description

Detects exploitation attempts and successful compromise of Magento Open Source and Adobe Commerce installations via the **StyleSmuggler** zero-day vulnerability, disclosed by Sansec on 2026-09-05. The flaw allows unauthenticated attackers to inject PHP code through a specially crafted GraphQL `POST` request targeting the `styles` endpoint. The injected code executes server-side when Magento renders its internal "Payment Transaction Failed Reminder" email — no email recipient interaction is required.

Upon execution, a PHP dropper cycles through available PHP execution functions (`exec`, `shell_exec`, `system`, `proc_open`, `popen`, `passthru`) to spawn a shell, downloads a persistent Rust ELF binary, and launches it masquerading as a Linux kernel worker thread (`[kworker/...]`).

As of 2026-09-07, Adobe has assigned no CVE identifier and released no patch. All Magento Open Source and Adobe Commerce versions including 2.4.9 are affected. Estimated exposure: ~111,000 stores.

**Interim mitigation:** Disable or restrict GraphQL access at the web application firewall or load balancer level until Adobe releases a patch.

**False positive sources:**
- Legitimate GraphQL API integrations with Magento stores
- Security scanners and pen testers running GraphQL fuzzing
- Magento extensions using the GraphQL styles endpoint for theming features

## MITRE ATT&CK Mapping

- **Tactic:** Initial Access (TA0001)
- **Technique:** Exploit Public-Facing Application (T1190)
- **Secondary Tactic:** Execution (TA0002)
- **Secondary Technique:** Command and Scripting Interpreter: PHP (T1059.007)
- **Secondary Tactic:** Persistence (TA0003)
- **Secondary Technique:** Server Software Component: Web Shell (T1505.003)
- **Defense Evasion:** Masquerading: Masquerade Task or Service (T1036.004) — Rust implant mimics `[kworker/...]`

## Lockheed Martin Kill Chain Phase

**Delivery** (GraphQL injection), **Exploitation** (PHP dropper execution), **Installation** (Rust backdoor persistence)

## Splunk SPL Query

### Rule 1 — Suspicious Unauthenticated POST to Magento GraphQL Endpoint (Web / WAF)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url="*/graphql*"
    AND Web.http_method="POST"
    AND Web.http_content_type="application/json"
  by Web.src Web.dest Web.url Web.http_method Web.status Web.bytes_in Web.user_agent
| `drop_dm_object_name(Web)`
| where match(user_agent, "(?i)(python-requests|curl|wget|go-http|nuclei|httpx|zgrab|masscan)")
     OR (isnull(user_agent) OR user_agent="")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest url status bytes_in user_agent
```

### Rule 2 — PHP Spawning Shell Commands Post-GraphQL (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("php","php-fpm","php8.1","php8.2","php8.3","php8.4")
    AND Processes.process_name IN ("sh","bash","dash","curl","wget","python3","python","perl","nc","ncat")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)(wget|curl).*(http)"), 90,
    match(process, "(?i)(chmod\s+[0-9]+|/tmp/|/var/tmp/)"), 85,
    match(process, "(?i)(nc|ncat|netcat).+(-e|-c|bash)"), 95,
    true(), 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Rule 3 — Process Masquerading as Linux Kernel Worker Thread (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="kworker*"
  by Processes.dest Processes.user Processes.process_name Processes.process_path
     Processes.process Processes.process_id Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| where NOT match(process_path, "(?i)^\[kworker")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name process_path parent_process_name process_id
```

### Rule 4 — PHP Execution Function Enumeration (Endpoint — Wazuh/Syslog)

```spl
`linux_auditd`
(execve AND (php OR php-fpm))
| rex field=msg "exe=\"(?P<exe>[^\"]+)\""
| rex field=msg "a0=\"(?P<cmd_arg>[^\"]+)\""
| where match(cmd_arg, "(?i)(exec|shell_exec|system|proc_open|popen|passthru)")
| stats count min(_time) as firstTime max(_time) as lastTime by host user exe cmd_arg
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host user exe cmd_arg
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | PHP spawning reverse shell (`nc`/`ncat` with `-e`/`-c bash`) |
| 90 | PHP spawning `curl`/`wget` with HTTP URL (implant download) |
| 90 | `kworker`-named process with actual filesystem path (masquerade) |
| 85 | PHP spawning shell commands writing to `/tmp/` or `/var/tmp/` |
| 75 | Unauthenticated POST to `/graphql` with scripted user agent |
| 60 | PHP spawning any shell interpreter without explicit URL or file |

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| Unknown (StyleSmuggler campaign) | First exploitation observed 2026-09-04 22:20 UTC; targets Magento/Adobe Commerce stores including fully patched 2.4.9; deploys Rust ELF backdoor; no CVE or patch as of 2026-09-07; ~111K stores exposed globally |

## References

- [Sansec: StyleSmuggler research](https://sansec.io/research/stylesmuggler)
- [CyberSecurityNews coverage](https://cybersecuritynews.com/magento-and-adobe-commerce-0-day-rce/)
- [SecurityOnline coverage](https://securityonline.info/stylesmuggler-magento-zero-day-rce/)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1059.007 — Command and Scripting Interpreter: PHP](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK T1036.004 — Masquerading: Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004/)
