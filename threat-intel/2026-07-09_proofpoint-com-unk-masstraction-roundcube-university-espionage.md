---
scraped_at: "2026-07-09T00:00:00Z"
source_url: "https://www.proofpoint.com/us/blog/threat-insight/one-email-closer-edge-unkmasstraction-physics-exploitation"
report_type: threat-intel
severity: high
title: "UNK_MassTraction Exploits Roundcube XSS + PHP Deserialization Chain to Target US/Canadian University Physics Departments"
---

## 1. IOCs

### File Paths (Behavioral)

| Path | Context |
|------|---------|
| `plugins/newmail_notifier/mail_preview.php` | SquareShell webshell drop path; timestomped to blend with legitimate plugin files |

### Malware Families (Platform Pivoting)

| Family | Type | Notes |
|--------|------|-------|
| IceCube | JavaScript credential stealer | Custom; initial XSS payload harvesting credentials, cookies, 2FA tokens, email content |
| SquareShell | PHP webshell | Primary persistence; installed via CVE-2025-49113 deserialization |
| VShell | Go-based RAT | Fallback payload; memory-resident; masquerades as legitimate system process |
| SNOWLIGHT | ELF loader | Intermediate loader in fallback chain; previously seen in China-nexus UNC5174 intrusions |

### CVEs Exploited

| CVE | Description | Affected Versions | Fixed In |
|-----|-------------|-------------------|----------|
| CVE-2024-42009 | Roundcube XSS via `onanimationstart` event in `message_body()` | <= 1.5.7, 1.6.x <= 1.6.7 | 1.5.8 / 1.6.8 |
| CVE-2025-49113 | Roundcube PHP object deserialization RCE via `_from` parameter in `upload.php` | <= 1.5.9, 1.6.0–1.6.10 | 1.5.10 / 1.6.11 |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|---------------|-------|
| Initial Access | T1190 | Exploit Public-Facing Application | CVE-2024-42009 XSS on Roundcube webmail server triggered when victim views malicious email |
| Execution | T1203 | Exploitation for Client Execution | JavaScript execution in victim's browser via XSS; escapes iframe sandbox |
| Execution | T1059.004 | Unix Shell | Shell script in fallback chain downloads and executes SNOWLIGHT ELF loader |
| Persistence | T1505.003 | Server Software Component: Web Shell | SquareShell PHP webshell written to `plugins/newmail_notifier/mail_preview.php` |
| Defense Evasion | T1070.006 | Indicator Removal: Timestomp | SquareShell timestomped to match legitimate Roundcube plugin files |
| Defense Evasion | T1036 | Masquerading | VShell masquerades as a legitimate system process in memory |
| Defense Evasion | T1620 | Reflective Code Loading | VShell runs entirely in memory; no disk artifact |
| Credential Access | T1539 | Steal Web Session Cookie | IceCube harvests session cookies and CSRF tokens |
| Credential Access | T1056 | Input Capture | IceCube captures credentials and 2FA/TOTP tokens |
| Collection | T1114 | Email Collection | IceCube exfiltrates full email content and contact lists |
| Lateral Movement | T1210 | Exploitation of Remote Services | Roundcube mail servers used as network pivot points into academic networks |

---

## 3. Malware & Tools

### IceCube (JavaScript)
- Delivered via CVE-2024-42009 XSS execution in victim's browser session
- Escapes Roundcube iframe sandbox
- Harvests: username, password, session cookies, CSRF tokens, 2FA tokens, browser telemetry, full email content and contact list
- Implements "deferred triggers" — monitors for page close, tab change, or mouse leave; hijacks logout button
- If any such action detected, re-attempts CVE-2025-49113 exploitation and beacons to C2 that session ended
- Sends PHP serialized `Crypt_GPG_Engine` gadget chain payload to exploit CVE-2025-49113 server-side

### SquareShell (PHP Webshell)
- Lightweight PHP webshell
- Installed at `plugins/newmail_notifier/mail_preview.php`
- Timestomped to mimic legitimate Roundcube plugin files
- Provides persistent RCE via common PHP system functions

### VShell (Go RAT)
- Publicly available commodity tool; previously linked to multiple China-nexus groups (UNC5174)
- Runs entirely in memory
- Disguises itself as a legitimate system process
- Capabilities: interactive shell, port forwarding (comparable to Cobalt Strike)
- **Fallback chain:** Introduced June 2026 — shell script → SNOWLIGHT ELF loader → VShell in memory

### SNOWLIGHT (ELF Loader)
- Architecture-dependent ELF loader
- Previously associated with China-nexus intrusion sets via Google Threat Intelligence
- Downloads and memory-maps VShell in the fallback path

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Actor Name | UNK_MassTraction |
| Attribution | China-aligned espionage cluster (Proofpoint, moderate confidence) |
| Infrastructure Overlap | UNC5174 (Google TI) — shared covert VPS network and tooling (VShell, SNOWLIGHT) |
| Campaign Start | May 2026 |
| Fallback path added | June 2026 |
| Targeting | Physics and engineering departments at major US and Canadian universities; administrators and professors with national security research ties (astrophysics, particle physics) |
| Target Selection | Pre-campaign reconnaissance identified institutions running unpatched Roundcube |
| Language Artifacts | Chinese-language artifacts found in earlier phishing email headers/metadata |

---

## 5. Splunk Detection Searches

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

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="go" OR
    (Processes.process IN ("*vshell*","*VShell*"))
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
`web` dest_port IN (80,443) method=POST
  (uri="*upload.php*" OR uri="*_from=*" OR uri_query="*_from=O%3A*")
  http_user_agent IN ("Roundcube*","*Mozilla*")
| eval risk_score=case(
    match(uri_query, "_from=O%3A"), 90,
    match(uri, "upload.php"), 70,
    1=1, 60)
| eval detection="Roundcube_PHP_Deserialization_Exploit_CVE_2025_49113"
| where risk_score >= 70
| table _time, src_ip, dest, uri, uri_query, method, status, risk_score, detection
```

---

## 6. Executive Summary

Proofpoint's threat research team (published July 8, 2026) detailed a China-aligned espionage campaign by UNK_MassTraction targeting physics and engineering departments at major US and Canadian universities, active since May 2026. The actor pre-selects targets running unpatched Roundcube webmail and delivers a malicious email containing a JavaScript XSS payload exploiting CVE-2024-42009. When a targeted researcher opens the email in their browser, the IceCube JavaScript stealer executes, harvesting credentials, session cookies, 2FA tokens, and email content.

IceCube then exploits CVE-2025-49113 — a PHP object deserialization vulnerability in Roundcube's `upload.php` that has been present for approximately 10 years — to achieve server-side RCE. A PHP webshell (SquareShell) is written to `plugins/newmail_notifier/mail_preview.php` and timestomped for persistence. If the CVE-2025-49113 exploitation fails, a June 2026 fallback path downloads SNOWLIGHT (an ELF loader previously seen in UNC5174 intrusions) which memory-loads VShell, a Go-based commodity RAT that impersonates a legitimate system process.

Infrastructure and tooling overlap with UNC5174, a China-aligned cluster tracked by Google Threat Intelligence. The use of VShell and SNOWLIGHT, both previously linked to China-aligned intrusion sets, strengthens the attribution.

**Immediate actions:** Patch Roundcube to 1.6.11+ (or 1.5.10+); audit `plugins/newmail_notifier/` for unexpected PHP files; hunt for Go processes with anomalous parent-child relationships and unexpected outbound connections from Roundcube servers.

---

## References

- [Proofpoint — One Email Closer to the Edge: UNK_MassTraction & the Physics of Exploitation](https://www.proofpoint.com/us/blog/threat-insight/one-email-closer-edge-unkmasstraction-physics-exploitation)
- [BleepingComputer — Hackers exploit Roundcube flaw to spy on academic researchers](https://www.bleepingcomputer.com/news/security/hackers-exploit-roundcube-flaw-to-spy-on-academic-researchers/)
- [The Hacker News — Suspected China-Aligned Hackers Exploit Roundcube Flaws](https://thehackernews.com/2026/07/suspected-china-aligned-hackers-exploit.html)
- [CyberScoop — Suspected Chinese espionage group used Roundcube exploit chain](https://cyberscoop.com/china-espionage-attacks-us-canada-universities-proofpoint/)
- [OfSec — CVE-2025-49113 PHP Object Deserialization in Roundcube](https://www.offsec.com/blog/cve-2025-49113/)
- [Exploit-DB — EDB-52324 Roundcube 1.6.10 RCE](https://www.exploit-db.com/exploits/52324)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/)
