# Oracle E-Business Suite CVE-2026-46817: Oracle Payments Unauthenticated Privilege Escalation

## Description

Detects exploitation of CVE-2026-46817, a critical unauthenticated privilege escalation and file read vulnerability (CWE-269/CWE-287/CWE-306, CVSS 9.8) in the Oracle Payments File Transmission component of Oracle E-Business Suite (EBS). An unauthenticated attacker with HTTP network access can send a crafted POST request to the `/OA_HTML/ibytransmit` endpoint without any credentials. The missing authentication check allows the request to be processed, and the crafted POST body invokes an internal Oracle Java function that is redirected to read arbitrary files from the EBS server filesystem.

CISA added CVE-2026-46817 to the Known Exploited Vulnerabilities catalog on 2026-07-15 with a mandatory remediation deadline of 2026-07-18. First in-the-wild exploitation was observed on June 27, 2026, approximately six weeks after Oracle published patches in the May 2026 Critical Patch Update.

**Affected versions:** Oracle E-Business Suite 12.2.3 through 12.2.15 (Oracle Payments File Transmission component).

**Exploit chain:**

1. Attacker sends an unauthenticated HTTP POST to `/OA_HTML/ibytransmit` — no credentials required.
2. The vulnerability (missing authentication check) allows the request to be accepted with HTTP 2xx.
3. A crafted payload in the POST body invokes an internal Oracle Java function in the iPayments namespace.
4. The Java function is redirected to read an arbitrary file from the server (initial in-the-wild exploitation read `/etc/passwd`).
5. High-value follow-on targets include Oracle DBC configuration files (containing JDBC credentials), Oracle wallet files (cwallet.sso, ewallet.p12), `appsweb.cfg`, and other application configuration files containing database authentication details.
6. Credential access via these files enables lateral movement to the Oracle Database backend and full compromise of the Oracle Payments module.

**False positive sources:**

- Legitimate Oracle Payments trading partner integrations may POST to `/OA_HTML/ibytransmit` on a scheduled basis from allowlisted partner IP ranges. Baseline known-good partner IPs and suppress alerts from those sources when correlated with expected transmission windows.
- Oracle Payments system tests and load balancer health checks may generate requests to this endpoint. Identify and allowlist monitoring source IPs.
- HTTP 2xx from ibytransmit to a known authorized partner IP during a scheduled window is expected. Flag unknown source IPs and off-schedule transmissions.
- File path patterns (rule 103968) in a request body from a known Oracle EBS administrator console or integration testing tool may be benign; correlate with the source IP and operational context.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary techniques:

- T1548 (Privilege Escalation / Defense Evasion: Abuse Elevation Control Mechanism — authentication bypass enabling privilege escalation)
- T1083 (Discovery: File and Directory Discovery — attacker enumerating and reading server filesystem via Java function redirection)
- T1552.001 (Credential Access: Unsecured Credentials: Credentials in Files — targeting Oracle DBC, wallet, and configuration files containing database credentials)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Actions on Objectives |

## Known IOCs

| Type | Value | Description |
|------|-------|-------------|
| URL Path | `POST /OA_HTML/ibytransmit` returning 2xx | Authentication bypass on Oracle Payments File Transmission endpoint |
| File Path Pattern | `/etc/passwd`, `/etc/shadow` | Initial in-the-wild file-read targets confirming LFI |
| File Path Pattern | `*.dbc`, `cwallet.sso`, `ewallet.p12`, `appsweb.cfg`, `wdbc.cfg` | Oracle credential and wallet file exfiltration targets |
| File Path Pattern | `../` traversal sequences, `%2e%2e` URL-encoded | Path traversal to reach files outside web root |

## Wazuh Detection Rules

Rules 103965-103971 in `wazuh/rules/staged/oracle_ebs_cve_2026_46817_payments_privesc.xml`:

| Rule ID | Level | Description |
|---------|-------|-------------|
| 103965 | 7 | Base anchor: HTTP request to `/OA_HTML/ibytransmit` endpoint (info) |
| 103966 | 11 | POST method to ibytransmit (exploit delivery vector) |
| 103967 | 13 | POST to ibytransmit returning 2xx (auth bypass at HTTP layer confirmed) |
| 103968 | 14 | Request to ibytransmit with LFI/file path payload (file read attempt) |
| 103969 | 15 | POST 2xx to ibytransmit with file path payload (exploitation confirmed) |
| 103970 | 9 | Probe burst: 8+ requests to ibytransmit from same IP in 60 seconds |
| 103971 | 12 | Apache/Oracle HTTP Server access log: POST to ibytransmit returning 2xx |

## Splunk Detection Query

**HTTP: Unauthenticated POST to Oracle EBS ibytransmit endpoint**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url="*/OA_HTML/ibytransmit*"
    AND Web.http_method=POST
  by Web.src Web.dest Web.url Web.http_method Web.status Web.user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    status>=200 AND status<300, 85,
    status>=400, 40,
    1=1, 55)
| where risk_score >= 40
| table firstTime lastTime src dest url http_method status user_agent risk_score
```

**HTTP: Oracle EBS ibytransmit POST with file read payload**

```spl
index=* sourcetype=access_* OR sourcetype=apache:access
  (uri_path="*ibytransmit*" OR request="*ibytransmit*")
  method=POST
  (request_body="*/etc/passwd*" OR request_body="*/etc/shadow*"
   OR request_body="*\.dbc*" OR request_body="*cwallet.sso*"
   OR request_body="*ewallet.p12*" OR request_body="*appsweb.cfg*"
   OR request_body="*%2e%2e*" OR request_body="*\.\./*")
| eval risk_score=case(
    status>=200 AND status<300, 95,
    1=1, 70)
| where risk_score >= 70
| table _time src dest uri_path status request_body risk_score
```

**Probe burst: repeated requests to ibytransmit from single source**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url="*/OA_HTML/ibytransmit*"
  by Web.src Web.dest _time span=60s
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where count >= 8
| eval risk_score=75
| table firstTime lastTime src dest count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| POST to ibytransmit returning 2xx with file path payload | 95 | All three exploitation signals present; confirmed active attack |
| POST to ibytransmit returning 2xx (no payload filter) | 85 | Auth bypass confirmed; exploitation likely in progress |
| POST to ibytransmit with file path payload (any status) | 70 | Exploit payload present regardless of response code |
| Probe burst (8+ requests/60s from same source) | 75 | Automated exploitation tooling fingerprint |
| POST to ibytransmit, response unknown | 55 | Attack delivery method; context required |
| Any request to ibytransmit from unknown source | 40 | Reconnaissance or access attempt |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unattributed (exploitation confirmed in wild, June 27 2026) | [The Hacker News — CVE-2026-46817 (June 2026)](https://thehackernews.com/2026/06/oracle-e-business-suite-flaw-cve-2026.html) |
| Unattributed (CISA KEV confirmed, July 15 2026) | [Help Net Security — Oracle Payments CVE-2026-46817](https://www.helpnetsecurity.com/2026/06/30/oracle-payments-cve-2026-46817-exploitation/) |

## References

- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1548 — Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
- [MITRE ATT&CK T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [MITRE ATT&CK T1552.001 — Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [Oracle Critical Patch Update — May 2026](https://www.oracle.com/security-alerts/cpumay2026.html)
- [CISA KEV — CVE-2026-46817](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [The Hacker News — Oracle EBS Flaw CVE-2026-46817 Actively Exploited](https://thehackernews.com/2026/06/oracle-e-business-suite-flaw-cve-2026.html)
- [Help Net Security — Oracle Payments CVE-2026-46817 Under Attack](https://www.helpnetsecurity.com/2026/06/30/oracle-payments-cve-2026-46817-exploitation/)
- [Rescana — CVE-2026-46817 Active Exploitation Alert](https://www.rescana.com/post/active-exploitation-alert-critical-oracle-e-business-suite-cve-2026-46817-vulnerability-targeting-oracle-payments-module)
