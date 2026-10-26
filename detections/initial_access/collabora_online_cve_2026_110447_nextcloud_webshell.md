# Collabora Online Built-in CODE Server CVE-2026-110447 — Nextcloud Web Shell Deployment

## Description

Detects exploitation of CVE-2026-110447, an unauthenticated OS command injection vulnerability in the Collabora Online Built-in CODE Server (`richdocumentscode`) app for Nextcloud. The vulnerability is exploitable during brief windows when the local CODE server process is not running (container restarts, upgrades, crashes). Active exploitation since mid-September 2026; CISA added to KEV October 23, 2026.

Post-exploitation behavior includes web shell deployment followed by reconnaissance targeting credential stores, password manager artifacts, and cryptocurrency wallets. Common false positives: Collabora code server legitimately spawns child processes during document conversions; tune `process_name` allowlist for your environment.

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
| Delivery |
| Exploitation |
| Installation |

## Splunk Detection Query

### Query A — Collabora CODE Server Process Spawning Unexpected Children

Detects the Collabora CODE server process (`coolwsd`, `loolwsd`, or `collabora`) spawning shell interpreters or download utilities consistent with OS command injection exploitation.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("coolwsd","loolwsd","collabora","cool","lool")
        AND Processes.process_name IN ("bash","sh","dash","python","python3","perl","curl","wget","nc","ncat","socat","php")
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "nc|ncat|socat"), 95,
    match(process, "curl|wget"), 90,
    match(process_name, "bash|sh|dash"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

### Query B — New PHP Web Shell Created Under Nextcloud Web Root

Detects creation of new `.php` files in Nextcloud or Collabora app directories, which may indicate web shell staging.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where Filesystem.action=created Filesystem.file_name="*.php"
        (Filesystem.file_path="*/nextcloud/*" OR Filesystem.file_path="*/richdocuments/*"
         OR Filesystem.file_path="*/richdocumentscode/*" OR Filesystem.file_path="*/apps/*")
    by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "richdocumentscode|richdocuments"), 95,
    match(file_path, "nextcloud"), 75,
    1=1, 60)
| where risk_score >= 75
| table firstTime lastTime dest file_name file_path process_name risk_score
```

### Query C — POST Requests to Collabora CODE Endpoints During Process-Down Window

Detects POST requests to Collabora-specific paths returning 200 OK from external source IPs, consistent with exploitation during the vulnerable window.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Web.Web
    where Web.http_method=POST Web.status=200
        (Web.url="*/richdocumentscode/*" OR Web.url="*/lool/*" OR Web.url="*/cool/*")
    by Web.dest Web.src Web.url Web.status Web.user_agent Web.bytes_in
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "richdocumentscode"), 85,
    match(url, "lool|cool"), 70,
    1=1, 50)
| where risk_score >= 70
| table firstTime lastTime dest src url status user_agent bytes_in risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Collabora parent spawns netcat/socat/ncat | 95 | Near-certain exploitation; no legitimate code path spawns raw sockets |
| Collabora parent spawns curl/wget via shell | 90 | Strongly indicative of post-exploit download cradle |
| Collabora parent spawns bash/sh/dash | 85 | High confidence; legitimate conversions do not spawn interactive shells |
| PHP file created under richdocumentscode/ path | 95 | No legitimate Nextcloud code creates PHP files in Collabora app directories |
| POST to richdocumentscode/ path returning 200 | 85 | Unusual; application traffic should flow through Nextcloud, not directly to CODE paths |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown financially motivated actor | Exploitation observed targeting credential stores and cryptocurrency wallets; no group attribution at time of writing |

## References

- [CISA KEV — CVE-2026-110447](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [BleepingComputer — Hackers exploit Collabora RCE flaw to backdoor Nextcloud servers](https://www.bleepingcomputer.com/news/security/hackers-exploit-collabora-rce-flaw-to-backdoor-nextcloud-servers/)
- [The Hacker News — CISA Flags Two Actively Exploited Critical Flaws in Collabora Online and Arista VeloCloud](https://thehackernews.com/2026/10/cisa-flags-two-actively-exploited.html)
- [Rescana — CVE-2026-110447 Analysis](https://www.rescana.com/post/collabora-built-in-code-server-cve-2026-110447-nextcloud-kev)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [Threat Intel Report — 2026-10-23 CISA Collabora Online](../../threat-intel/2026-10-23_cisa-collabora-online-cve-2026-110447-nextcloud-webshell.md)
