---
scraped_at: 2026-10-24T00:00:00Z
source_url: https://www.cyfirma.com/research/cyfirma-threat-advisory-suspected-dprk-campaign-staging-php2shell-targeting-against-global-php-infrastructure/
report_type: threat-intel
severity: high
title: "CYFIRMA v3 Advisory: Suspected DPRK/Lazarus PHP2Shell Global Scanning Campaign — 21 Scan Nodes, 216 Targets"
---

# CYFIRMA v3: Suspected DPRK-Linked PHP2Shell Global Scanning Campaign Against Government and Financial Targets

**Date:** 2026-10-24
**Source:** CYFIRMA Threat Advisory (version 3, October 24, 2026), The Hacker News, Threat Landscape
**CVEs:** CVE-2026-109618, CVE-2026-109619
**Severity:** High
**Status:** Active campaign; CYFIRMA advisory updated to v3 October 24, 2026; exploitation observed since October 17, 2026

---

## Executive Summary

CYFIRMA released version 3 of its threat advisory on October 24, 2026, attributing a global PHP2Shell scanning and exploitation campaign to a suspected DPRK-linked (Lazarus-related) threat actor. The campaign uses 21 compromised nodes to probe unpatched PHP servers across 12+ countries, with priority targeting of government entities and banking/financial services institutions. A total of 216 unpatched or partially mitigated hosts have been identified as targets.

This report supplements the earlier PHP2Shell advisory (`2026-10-21_php-security-php2shell-cve-2026-109618-109619-critical-rce.md`) with the North Korea attribution dimension and updated campaign scope. Attribution remains **suspected**, not confirmed — CYFIRMA and secondary sources note the campaign TTPs are consistent with Lazarus-linked activity, but no public definitive attribution has been made.

**Note:** Unit 42 (Palo Alto Networks) retracted its earlier assessment that specific post-exploitation activity at a European government agency was directly linked to PHP2Shell CVE exploitation. The CYFIRMA campaign is tracked independently.

---

## 1. IOCs

### Network Indicators

| Indicator | Type | Notes |
|-----------|------|-------|
| 21 compromised scan nodes | IP addresses | CYFIRMA advisory lists specific IPs (classified as U3/perimeter tier); retrieve the full list from the CYFIRMA advisory directly |
| 17 Version 2 (v2) IPs | IP addresses | Secondary scanning tier — CYFIRMA advisory classification 09 B |
| 15 staging IPs | IP addresses | Priority hunting targets — CYFIRMA advisory classification 09 A |

*The specific IP addresses are published in the CYFIRMA advisory. The hunt-back window recommended by CYFIRMA is October 17, 2026 onward.*

### Behavioral Indicators

- Low-volume `multipart/form-data` POST requests to PHP endpoints (anomalous vs. baseline)
- Unexpected worker process crashes on PHP-FPM or Apache/Nginx
- Unexpected modifications to PHP session files (`/tmp/sess_*`, session storage directories)
- Anomalous user-agent strings and canary strings (full list in CYFIRMA advisory)

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Notes |
|--------|-----------|-----|-------|
| Reconnaissance | Active Scanning: Vulnerability Scanning | T1595.002 | 21 compromised nodes probing for unpatched PHP2Shell instances globally |
| Initial Access | Exploit Public-Facing Application | T1190 | Exploitation of CVE-2026-109618 / CVE-2026-109619 on unpatched PHP servers |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Command execution via PHP RCE chain |
| Credential Access | OS Credential Dumping | T1003 | Post-exploitation credential harvesting (NTLM relay path on Windows targets) |
| Credential Access | OS Credential Dumping: NTLM Relay | T1003 | AI-structured command output suggesting NTLM relay path construction, AD enumeration |
| Lateral Movement | Lateral Tool Transfer | T1570 | Staging infrastructure used to pivot to additional targets |
| Discovery | Domain Trust Discovery | T1482 | Active Directory enumeration observed post-exploitation |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| PHP2Shell exploit (CVE-2026-109618/109619) | Exploit | RCE via malformed multipart/form-data or file upload handling in PHP |
| Post-exploitation AI-structured payloads | Technique | Command output formatted with AI-recognizable delimiters — suggests AI-assisted intrusion tooling may be involved |

---

## 4. Threat Actor / Campaign Attribution

| Actor | Confidence | Notes |
|-------|-----------|-------|
| Suspected DPRK / Lazarus-linked | Low–Medium | CYFIRMA tracks 21 scan nodes consistent with DPRK infrastructure; attribution is suspected, not confirmed |

CYFIRMA's advisory uses "suspected DPRK" language. A secondary social-media source (yousukezan) describes post-exploitation behavior at a European government agency with AI-delimiter-structured command output and NTLM relay path construction — behaviors consistent with AI-assisted intrusion frameworks. Unit 42 has separately retracted its attribution of that specific government incident to PHP2Shell initial access.

Campaign scope: 216 unpatched hosts across the United States, Japan, South Korea, Thailand, Indonesia, Australia, Taiwan, India, Singapore, UAE, Saudi Arabia, and the EU. Priority tier targets: government entities and banking/financial services institutions.

---

## 5. Splunk Detection Searches

### 5a. PHP2Shell Exploit Attempt Detection (Web Layer)

Detects anomalous multipart/form-data POST patterns targeting PHP endpoints consistent with CVE-2026-109618/CVE-2026-109619 exploitation attempts.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Web.Web
    where Web.http_method=POST Web.url="*.php*"
        Web.http_content_type="multipart/form-data*"
    by Web.dest Web.src Web.url Web.status Web.user_agent Web.bytes_in
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    status=200 AND bytes_in > 50000, 80,
    status=200, 60,
    status IN ("500","502","503"), 50,
    1=1, 30)
| where risk_score >= 50
| table firstTime lastTime dest src url status user_agent bytes_in risk_score
```

### 5b. PHP-FPM / Apache Worker Unexpected Crash (Post-Exploit Indicator)

Worker crashes on PHP web servers can indicate exploitation attempts hitting the vulnerable upload path.

```spl
index=* sourcetype IN ("syslog","linux_secure","apache_error","php-fpm")
    (message="*worker*" AND message="*exit*")
    OR (message="*child*" AND message="*terminated*")
    OR message="*SIGSEGV*"
    OR message="*php-fpm*" message="*died*"
| rex field=_raw "(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count min(_time) as firstTime max(_time) as lastTime by host src_ip
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(count > 5, 75, count > 1, 55, 1=1, 40)
| where risk_score >= 55
| table firstTime lastTime host src_ip count risk_score
```

### 5c. Global PHP Server Scan Sweep Detection

Detects high-rate PHP endpoint scanning from a single source IP — consistent with the 21-node sweep infrastructure pattern.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime dc(Web.url) as unique_urls
    from datamodel=Web.Web
    where Web.http_method=POST Web.url="*.php*"
    by Web.src Web.dest
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where count > 50 AND unique_urls > 10
| eval risk_score=case(count > 200, 85, count > 100, 70, 1=1, 55)
| where risk_score >= 55
| table firstTime lastTime src dest count unique_urls risk_score
```

---

## 6. Executive Summary

A suspected DPRK/Lazarus-linked threat actor is conducting a coordinated global scanning campaign against PHP2Shell (CVE-2026-109618 and CVE-2026-109619) — the critical PHP RCE vulnerabilities patched October 21, 2026. The campaign uses 21 compromised scan nodes and has identified 216 unpatched or partially mitigated targets across 12+ countries. Priority targets are government entities and financial institutions.

CYFIRMA's version 3 advisory (October 24) recommends hunting back to October 17 for activity across three indicator tiers. Post-exploitation behavior includes NTLM relay path construction and Active Directory enumeration. Notably, command output structured with AI-recognizable delimiters has been observed, suggesting AI-assisted intrusion tooling may be used in the post-exploitation phase.

Organizations running PHP should confirm they have applied the October 21 patches (PHP 8.5.12, 8.4.27, 8.3.36, or 8.2.35). Additionally, CVE-2026-115560 — a separate unpatched PHP session handling RCE disclosed October 23 — should be mitigated by disabling `session.upload_progress` or switching `session.serialize_handler` to `php_binary` or `php_serialize` until a patch is released.

---

## References

- [CYFIRMA Threat Advisory v3 — Suspected DPRK PHP2Shell Campaign](https://www.cyfirma.com/research/cyfirma-threat-advisory-suspected-dprk-campaign-staging-php2shell-targeting-against-global-php-infrastructure/)
- [The Hacker News — PHP2Shell Exploitation Attempts Continue Amid Suspected N. Korea Global Scanning Activity](https://thehackernews.com/2026/10/php2shell-exploitation-hits-government.html)
- [The Hacker News — PHP2Shell Exploit Attempts Hit Millions as Attackers Try to Deploy Mirai Malware](https://thehackernews.com/2026/10/php2shell-exploit-attempts-hit-millions.html)
- [Threat Landscape — PHP2Shell CVE-2026-109618 Campaign Analysis](https://threatlandscape.io/blog/php2shell-campaign-cve-2026-109618-216-hosts)
- [PHP Warns of Another Unpatched RCE Risk (CVE-2026-115560)](https://thehackernews.com/2026/10/urgent-php-warns-of-another-unpatched.html)
- [Prior PHP2Shell report — 2026-10-21](../threat-intel/2026-10-21_php-security-php2shell-cve-2026-109618-109619-critical-rce.md)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1595.002 Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/)
