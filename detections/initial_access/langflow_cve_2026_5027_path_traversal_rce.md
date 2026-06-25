# Langflow Path Traversal to Unauthenticated Root RCE (CVE-2026-5027)

## Description

Detects exploitation of CVE-2026-5027, a path traversal vulnerability (CVSS 8.8) in Langflow AI application builder (versions ≤ 1.8.4). The `POST /api/v2/files` (`upload_user_file`) endpoint does not sanitize the `filename` field in multipart form data, allowing an attacker to write arbitrary files anywhere on the filesystem using `../` path traversal. When Langflow's default auto-login configuration is active, this endpoint is reachable without authentication. Combining the file write with cron directory injection achieves unauthenticated remote code execution as root.

This is the fifth Langflow CVE exploited in the wild in 2026. MuddyWater (Iran) previously weaponized CVE-2025-34291 against government targets; CVE-2026-5027 exploitation does not yet have confirmed APT attribution.

False positive sources: Legitimate Langflow file uploads to the configured upload directory; legitimate cron file creation by system packages. Cron directory writes by web application processes (Python/uvicorn/gunicorn) have no legitimate baseline.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Persistence |
| Secondary Tactic ID | TA0003 |
| Secondary Technique | Scheduled Task/Job: Cron |
| Secondary Technique ID | T1053.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.http_method="POST"
    AND Web.uri_path="*/api/v2/files*"
  by Web.src Web.dest Web.uri_path Web.uri_query Web.http_method Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(uri_query,"(?i)(\.\./|\.\.\\\\|%2e%2e%2f|%252e%252e%252f)"), 95,
    status IN ("200","201") AND http_method="POST", 70,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest uri_path uri_query status http_user_agent risk_score
```

## Wazuh Detection Rules

Rules are in `wazuh/rules/langflow_cve_2026_5027.xml` (IDs 101700–101712).

| Rule ID | Level | Description |
|---------|-------|-------------|
| 101700 | 0 | Base anchor: POST to /api/v2/files |
| 101701 | 0 | Base anchor: POST to /api/v1/auto_login |
| 101702 | 7 | Langflow file upload visibility |
| 101703 | 15 | **Path traversal sequences in /api/v2/files — CVE-2026-5027 exploitation** |
| 101704 | 15 | Path traversal + HTTP 200/201 — successful file write |
| 101705 | 11 | Auto-login POST — possible auth bypass |
| 101706 | 14 | Auto-login + file upload from same IP in 2 min — exploitation chain |
| 101710 | 15 | **Cron directory write by Python/uvicorn process — cron injection RCE** |
| 101711 | 14 | Web app process writing cron configuration (broad) |
| 101712 | 15 | **Correlation: path traversal + cron write in 5 min — confirmed RCE** |

**Auditd prerequisites** (must be in `/etc/audit/rules.d/` on Langflow hosts):
```
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| POST /api/v2/files with `../` or URL-encoded traversal in query/body | 95 | Direct exploitation attempt — path traversal in filename field is the CVE-2026-5027 attack pattern |
| POST /api/v2/files returns HTTP 200/201 | 70 | Successful file upload; without traversal indicator warrants investigation |
| Any POST /api/v2/files | 60 | Baseline visibility; correlate with downstream cron or shell activity |
| Cron write by Python/uvicorn process | 100 | No legitimate baseline; canonical cron injection RCE path |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors (CVE-2026-5027 active exploitation) | [The Hacker News — CVE-2026-5027 (2026-06-10)](https://thehackernews.com/2026/06/unpatched-langflow-flaw-cve-2026-5027.html) |
| MuddyWater / MOIS (prior Langflow exploitation — CVE-2025-34291) | [MITRE ATT&CK G0069](https://attack.mitre.org/groups/G0069/), [CISA KEV (2026-05-21)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |

## References

- [The Hacker News — Unpatched Langflow Flaw CVE-2026-5027 Exploited for Unauthenticated RCE (2026-06-10)](https://thehackernews.com/2026/06/unpatched-langflow-flaw-cve-2026-5027.html)
- [BleepingComputer — Path traversal flaw in AI dev platform Langflow exploited in attacks (2026-06-10)](https://www.bleepingcomputer.com/news/security/path-traversal-flaw-in-ai-dev-platform-langflow-exploited-in-attacks/)
- [Tenable TRA-2026-26 — Langflow Path Traversal Arbitrary File Write via upload_user_file](https://www.tenable.com/security/research/tra-2026-26)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1053.003: Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)
