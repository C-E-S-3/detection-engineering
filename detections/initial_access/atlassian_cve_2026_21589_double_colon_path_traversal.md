# Atlassian CVE-2026-21589 — Double-Colon Path Traversal Exploitation in Atlassian Data Center / Server

## Description

Detects exploitation of CVE-2026-21589, a critical (CVSS 9.3) unauthenticated arbitrary file read vulnerability affecting all eight Atlassian Data Center and Server products (Jira, Confluence, Bitbucket, Bamboo, Crowd, and others). The root cause is a path normalization bug in a shared web-resource library: the `::` character sequence is converted to a forward slash `/`, allowing path traversal within the Tomcat application context without authentication.

The primary exploit pattern is a URL path containing the double-colon sequence (e.g., `GET /rest/::/../WEB-INF/web.xml`). A successful exploit returns HTTP 200 for paths that should never be publicly accessible. The practical impact in Crowd-integrated environments is admin compromise: reading `crowd.properties` exposes credentials that grant application-level admin access to Jira and Confluence, enabling subsequent RCE via native admin panel features.

False positives are minimal — the `::` sequence in a URI path has no legitimate use. HTTP 200 responses to `WEB-INF/` paths represent an immediate security incident regardless of CVE context.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.uri_path="*::*"
    AND (Web.dest_port=8080 OR Web.dest_port=8443 OR Web.dest_port=443 OR Web.dest_port=80)
  by Web.src Web.dest Web.uri_path Web.http_method Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(uri_path, "WEB-INF"), 95,
    match(uri_path, "(db\.properties|\.cfg\.xml|crowd\.properties|seraph-config|jira-config)"), 95,
    status=200 AND match(uri_path, "::"), 90,
    match(uri_path, "::[./]"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest uri_path http_method status http_user_agent risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `WEB-INF` in path with `::` | 95 | Critical — WEB-INF is the target for this CVE; near-certain exploitation attempt |
| Known sensitive config file path | 95 | Critical — direct credential file access |
| HTTP 200 response to `::` path | 90 | High — confirmed file read success |
| `::` followed by `/` or `.` | 80 | High — exploitation pattern detected |
| `::` in URI path generally | 60 | Medium — unusual but warrants investigation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Opportunistic mass-exploitation actors (CVE-2026-21589, October 2026) | [watchTowr — Atlassian Arbitrary File Read CVE-2026-21589](https://watchtowr.com/intelligence/atlassian-jira-confluence-arbitrary-file-read-cve-2026-21589/) |

## References

- [watchTowr Intelligence — Atlassian Jira/Confluence Arbitrary File Read CVE-2026-21589](https://watchtowr.com/intelligence/atlassian-jira-confluence-arbitrary-file-read-cve-2026-21589/)
- [Atlassian Security Advisories](https://www.atlassian.com/trust/security/advisories)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1552.001 — Unsecured Credentials: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
