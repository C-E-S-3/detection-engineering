# GitLab CE/EE Commits API Path Traversal (CVE-2026-85706)

## Description

Detects unauthenticated exploitation of CVE-2026-85706, a CVSS 10.0 path traversal vulnerability in the GitLab CE/EE repository commits API. An attacker sends a single HTTP POST to `/api/v4/projects/{id}/repository/commits/` with a crafted `file.Path` body parameter containing path traversal sequences, bypassing directory confinement and reading arbitrary files from the GitLab server — including SSH private keys, `/etc/shadow`, CI/CD secrets, and the Rails `secret_key_base`.

Affected: GitLab CE/EE 18.7–19.1.7 (fixed in 19.1.8), 19.2.0–19.2.5 (fixed in 19.2.6), 19.3.0–19.3.1 (fixed in 19.3.2). Patches released September 10, 2026; CISA KEV added September 11, 2026 with a 3-day federal patch deadline.

**False positives:** Legitimate internal CI/CD pipelines should not POST to this API endpoint from external IPs. Internal automation from trusted RFC1918 ranges is excluded by the query and would require a separate review. WAF or reverse-proxy log sources may generate duplicate events; deduplicate by `src` + `uri_path` if needed.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access / Credential Access |
| Tactic ID | TA0001 / TA0006 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Technique | Unsecured Credentials: Credentials In Files |
| Secondary Technique ID | T1552.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.http_method="POST"
    AND Web.uri_path LIKE "/api/v4/projects/%/repository/commits/%"
  by Web.src Web.dest Web.uri_path Web.http_user_agent Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search NOT src IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
| eval risk_score=case(
    match(uri_path, "\/api\/v4\/projects\/[^\/]+\/repository\/commits\/.+\.\.")
      OR match(uri_path, "%2e%2e") OR match(uri_path, "%252e"), 95,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime src dest uri_path http_user_agent status risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| POST to commits API URI containing `..` or URL-encoded traversal sequences (`%2e%2e`, `%252e`) | 95 | Near-certain CVE-2026-85706 exploitation; path traversal sequences are never legitimate in this URI |
| POST from external IP to `/api/v4/projects/*/repository/commits/*` | 80 | Commits API POST from internet-routed source is anomalous and warrants immediate triage |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors (CVE-2026-85706 exploiters, September 2026) | [CISA KEV (2026-09-11)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Access brokers, ransomware affiliates | GitLab arbitrary file read enables credential harvest for follow-on access and supply chain attacks |

## References

- [CISA KEV — CVE-2026-85706 Added September 11, 2026](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [GitLab Security Release — September 10, 2026](https://about.gitlab.com/releases/2026/09/10/security-release-gitlab-19-3-2-released/)
- [NVD CVE-2026-85706](https://nvd.nist.gov/vuln/detail/CVE-2026-85706)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1552.001 Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
