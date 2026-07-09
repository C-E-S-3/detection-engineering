# UNK_MassTraction Roundcube XSS Chain to PHP Webshell (CVE-2024-42009 / CVE-2025-49113)

## Description

Detects the UNK_MassTraction two-stage exploitation chain targeting Roundcube webmail servers. This China-aligned espionage actor targets physics and engineering departments at US and Canadian universities, active since May 2026.

**Stage 1 — CVE-2024-42009 XSS (Roundcube ≤1.5.7 / ≤1.6.7):**
A malicious email triggers JavaScript execution via `onanimationstart` event in `message_body()` when the victim views the email in their browser. The IceCube JavaScript stealer harvests credentials, session cookies, 2FA/TOTP tokens, and email content, then triggers Stage 2.

**Stage 2 — CVE-2025-49113 PHP Object Deserialization RCE (Roundcube ≤1.5.9 / ≤1.6.10):**
IceCube sends a serialized `Crypt_GPG_Engine` gadget chain to the `_from` parameter in `upload.php`, achieving server-side RCE. A lightweight PHP webshell (SquareShell) is written to `plugins/newmail_notifier/mail_preview.php` and timestomped to blend with legitimate plugin files.

**Fallback chain (June 2026):** If Stage 2 fails, a shell script downloads SNOWLIGHT (ELF loader previously associated with UNC5174) which memory-loads VShell, a Go-based commodity RAT that impersonates a legitimate system process.

False positives: The filesystem query for `mail_preview.php` in the newmail_notifier plugin path has near-zero false positive rate; the deserialization HTTP query may trigger on security scanning tools that submit serialized PHP test payloads.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Persistence |
| Secondary Tactic ID | TA0003 |
| Secondary Technique | Server Software Component: Web Shell |
| Secondary Technique ID | T1505.003 |
| Additional Technique | Exploitation for Client Execution |
| Additional Technique ID | T1203 |
| Additional Technique | Steal Web Session Cookie |
| Additional Technique ID | T1539 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |

## Splunk Detection Query

**Query 1 — SquareShell webshell drop (highest fidelity):**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*plugins/newmail_notifier/mail_preview.php*"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| eval detection="UNK_MassTraction_SquareShell_Drop"
| table firstTime lastTime dest user file_path file_name process_name risk_score detection
```

**Query 2 — CVE-2025-49113 PHP deserialization exploit attempt:**

```spl
`web` dest_port IN (80,443) method=POST
  (uri="*upload.php*" OR uri="*_from=*" OR uri_query="*_from=O%3A*")
| eval risk_score=case(
    match(uri_query, "_from=O%3A"), 90,
    match(uri, "upload.php"), 70,
    1=1, 60)
| eval detection="Roundcube_PHP_Deserialization_Exploit_CVE_2025_49113"
| where risk_score >= 70
| table _time, src_ip, dest, uri, uri_query, method, status, risk_score, detection
```

**Query 3 — Web server spawning shell children (webshell execution / SNOWLIGHT fallback):**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("httpd","apache2","nginx","php-fpm")
    AND Processes.process_name IN ("sh","bash","wget","curl","python*","perl","ruby","nc","ncat")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Query 4 — VShell Go RAT in-memory (fallback chain indicator):**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process IN ("*vshell*","*VShell*"))
     OR (Processes.process_name="go" AND Processes.parent_process_name IN ("httpd","apache2","nginx","php-fpm","sh","bash"))
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `mail_preview.php` created in newmail_notifier plugin directory | 95 | Exact SquareShell IOC; no legitimate Roundcube file matches this path |
| `_from=O%3A` (URL-encoded PHP serialized object) in upload.php POST | 90 | CVE-2025-49113 exploitation-specific payload pattern |
| POST to `upload.php` without serialization marker | 70 | Broad upload.php activity; suspicious in context of Roundcube server |
| Web server spawning wget/curl/bash/nc | 85 | Classic webshell post-exploitation; very low false positive rate |
| Go binary or VShell process with web server parent | 80 | SNOWLIGHT → VShell fallback chain indicator |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| UNK_MassTraction (China-aligned) | [Proofpoint — One Email Closer to the Edge](https://www.proofpoint.com/us/blog/threat-insight/one-email-closer-edge-unkmasstraction-physics-exploitation) |
| UNC5174 (China-aligned, infrastructure/tooling overlap) | [Google Threat Intelligence — UNC5174](https://cloud.google.com/blog/topics/threat-intelligence/unc5174-china-nexus-actor-vshell-snowlight) |

## References

- [Proofpoint — One Email Closer to the Edge: UNK_MassTraction & the Physics of Exploitation](https://www.proofpoint.com/us/blog/threat-insight/one-email-closer-edge-unkmasstraction-physics-exploitation)
- [BleepingComputer — Hackers exploit Roundcube flaw to spy on academic researchers](https://www.bleepingcomputer.com/news/security/hackers-exploit-roundcube-flaw-to-spy-on-academic-researchers/)
- [OfSec — CVE-2025-49113 PHP Object Deserialization in Roundcube](https://www.offsec.com/blog/cve-2025-49113/)
- [Exploit-DB — EDB-52324 Roundcube 1.6.10 RCE](https://www.exploit-db.com/exploits/52324)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
