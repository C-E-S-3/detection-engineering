---
title: "StyleSmuggler: Unpatched Magento / Adobe Commerce Zero-Day RCE Under Active Exploitation"
source: Sansec
source_url: https://sansec.io/research/stylesmuggler
date: 2026-09-07
scraped_at: 2026-09-07T00:00:00Z
report_type: threat-intel
severity: critical
tags: [magento, adobe-commerce, zero-day, rce, graphql, php, rust-backdoor, e-commerce, supply-chain]
mitre_tactics: [TA0001, TA0002, TA0003]
---

# StyleSmuggler: Unpatched Magento / Adobe Commerce Zero-Day RCE Under Active Exploitation

## Executive Summary

On 2026-09-05, Dutch e-commerce security firm Sansec disclosed a critical zero-day remote code execution vulnerability in all supported versions of Magento Open Source and Adobe Commerce, including the fully-patched 2.4.9 release. Dubbed **StyleSmuggler**, the flaw allows an unauthenticated attacker to inject PHP code via a manipulated GraphQL request to the `styles` endpoint, which is then executed when Magento renders an internal transactional email. Exploitation was first observed on 2026-09-04 at 22:20 UTC. As of 2026-09-07, Adobe has assigned no CVE identifier and released no patch. Approximately 111,000 Magento/Adobe Commerce stores are believed to be exposed.

## IOCs

### Domains / URLs

| Indicator | Role |
|-----------|------|
| No specific payload delivery domains recovered | — |

### IP Addresses

| Indicator | Role |
|-----------|------|
| No specific attacker IPs recovered at time of report | — |

### File Hashes

| Hash | Type | Description |
|------|------|-------------|
| No specific hashes recovered at time of report | — | Sansec full IoC list available at source URL |

### Behavioral / File-System Indicators

| Indicator | Description |
|-----------|-------------|
| PHP dropper in Magento template directory | First-stage payload cycles through 6 PHP execution functions (`exec`, `shell_exec`, `system`, `proc_open`, `popen`, `passthru`) |
| Rust ELF binary masquerading as kernel thread | Persistent implant installed by PHP dropper; presents as `[kworker/...]` process |
| Unauthorized `POST` to `/graphql` with `styles` field | Trigger for the injection; no authentication required |
| `Payment Transaction Failed Reminder` email rendering | Magento renders poisoned code server-side; no email recipient interaction required |

## TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Initial Access | Exploit Public-Facing Application | T1190 | Unauthenticated GraphQL `styles` injection in Magento/Adobe Commerce |
| Execution | Command and Scripting Interpreter: PHP | T1059.007 | PHP dropper executed via Magento's email rendering engine |
| Persistence | Server Software Component: Web Shell | T1505.003 | Rust backdoor installed to maintain persistent access |
| Defense Evasion | Masquerading: Masquerade Task or Service | T1036.004 | Rust implant masquerades as Linux kernel worker thread `[kworker/...]` |

### Kill Chain Phase
**Exploitation → Installation → Actions on Objectives**

## Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| StyleSmuggler PHP dropper | PHP dropper | Injected via GraphQL; enumerates available PHP execution functions; downloads and executes the Rust implant |
| Unnamed Rust backdoor | Persistent implant | Installed by PHP dropper; masquerades as Linux kernel thread; provides persistent remote access |

## Threat Actor / Campaign Attribution

- **Attribution**: Unknown at time of publication. Sansec noted the sophistication of the attack chain (Rust implant, kernel thread masquerading) suggests a capable actor, possibly with prior Magento skimmer experience.
- **First exploitation observed**: 2026-09-04 22:20 UTC
- **Disclosure date**: 2026-09-05 (Sansec)
- **Adobe response**: No CVE, no patch, no official workaround as of 2026-09-07
- **Exposure**: ~111,000 Magento Open Source and Adobe Commerce installations across all supported versions (2.4.x)

## Splunk Detection Searches

### 1 — Suspicious GraphQL POST to Magento Styles Endpoint (Web Proxy / WAF)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url="*/graphql*" Web.http_method="POST" Web.http_content_type="application/json"
  by Web.src Web.dest Web.url Web.http_method Web.status Web.bytes_in
| `drop_dm_object_name(Web)`
| where match(url, "(?i)/graphql")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest url http_method status bytes_in
```

**Risk Score**: 50 (Medium) — GraphQL is a legitimate endpoint; analysts should correlate with subsequent process spawning or file creation events.

### 2 — PHP Process Spawning Shell Commands (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("php", "php-fpm", "php8.1", "php8.2", "php8.3")
    AND Processes.process_name IN ("sh", "bash", "curl", "wget", "python3", "perl")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)(wget|curl).*(http)"), 90,
    match(process, "(?i)(chmod|bash|sh)\s"), 75,
    true(), 50)
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Risk Score**: 75–90 (High–Critical) — PHP spawning shell processes is a strong indicator of web shell activity.

### 3 — Suspicious Process Masquerading as Linux Kernel Thread

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

**Risk Score**: 95 (Critical) — A `kworker`-named process with a real filesystem path is a near-certain masquerade.

## References

- [Sansec StyleSmuggler research](https://sansec.io/research/stylesmuggler)
- [CyberSecurityNews coverage](https://cybersecuritynews.com/magento-and-adobe-commerce-0-day-rce/)
- [SecurityOnline coverage](https://securityonline.info/stylesmuggler-magento-zero-day-rce/)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
