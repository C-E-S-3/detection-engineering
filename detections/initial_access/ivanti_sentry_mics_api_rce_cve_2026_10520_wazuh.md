# Ivanti Sentry MICS API OS Command Injection (CVE-2026-10520) — Wazuh Detection

## Description

Detects exploitation of CVE-2026-10520, a CVSS 10.0 unauthenticated OS command injection vulnerability in Ivanti Sentry's MICS (Mobile Iron Core Server) management API. An attacker sends an HTTP POST to `/mics/api/v2/sentry/mics-config/handleMessage` with `command=execute`; the `ConfigServiceController.handleExecute()` method passes unsanitized input directly to native OS commands, achieving root-level RCE without authentication.

A companion vulnerability, CVE-2026-10523 (CVSS 9.9), enables authentication bypass to create arbitrary administrative accounts on the same appliance. CISA added CVE-2026-10520 to the KEV Catalog on June 11, 2026, with a 3-day federal remediation mandate under BOD 26-04 (unprecedented urgency). Backdoors were deployed by threat actors within 24 hours of public PoC release.

**Log source:** Traefik reverse proxy JSON access logs (JSON decoder). Rules 101800-101810.

**False positives:** Legitimate Ivanti Sentry automation tooling may POST to MICS API endpoints, but `handleMessage` with `command=execute` has no documented legitimate use case. Rule 101800 (baseline) fires on all MICS API access; tune to allowlist known-good automation source IPs or MICS admin subnets.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

**Secondary Techniques:**

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Persistence | T1136.001 | Create Account: Local Account (CVE-2026-10523 auth bypass) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Wazuh Detection Rules

Rules 101800-101810 in `wazuh/rules/ivanti_sentry_cve_2026_10520.xml`:

| Rule ID | Level | Description |
|---------|-------|-------------|
| 101800 | 0 | Baseline: any MICS API request (parent rule) |
| 101801 | 11 | Any MICS API access — anomalous management API activity |
| 101802 | 12 | POST to MICS API returning HTTP 200 or 500 — possible exploitation |
| 101803 | 13 | POST to `mics-config/handleMessage` — **direct CVE-2026-10520 exploit path** |
| 101804 | 12 | Any access to handleMessage endpoint — recon or exploitation |
| 101805 | 12 | Admin account API POST/PUT/PATCH returning 200/201 — CVE-2026-10523 |
| 101806 | 0 | Frequency baseline (parent for 101807) |
| 101807 | 14 | 10+ MICS API requests in 60 seconds — automated exploitation tooling |
| 101808 | 13 | MICS API accessed from external (non-RFC1918) IP |
| 101809 | 11 | MICS API returning 4xx/5xx error responses — failed probe |
| 101810 | 12 | MICS config export/import API access — config exfiltration risk |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url="*/mics/api/*"
by Web.src Web.dest Web.url Web.http_method Web.status Web.bytes Web.user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "(?i)handleMessage") AND http_method="POST", 100,
    match(url, "(?i)handleMessage"), 90,
    match(url, "(?i)(users|admins|accounts|auth|roles)") AND http_method IN ("POST","PUT","PATCH") AND status IN ("200","201"), 85,
    match(url, "(?i)(export|import|backup|restore|config-download|config-upload)"), 75,
    http_method="POST" AND status IN ("200","500"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest url http_method status bytes user_agent risk_score
```

```spl
index=proxy OR index=traefik
(uri_path="*/mics/api/*" OR url="*/mics/api/*")
| eval exploit_path=if(like(uri_path,"%handleMessage%") OR like(url,"%handleMessage%"), "CVE-2026-10520-direct", "mics-api-access")
| eval risk_score=case(
    exploit_path="CVE-2026-10520-direct" AND method="POST", 100,
    exploit_path="CVE-2026-10520-direct", 90,
    1=1, 70)
| stats count min(_time) as firstTime max(_time) as lastTime values(method) as methods values(status) as statuses values(user_agent) as user_agents by src, dest, exploit_path, risk_score
| where count >= 1
| sort -risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Risk Score Logic

| Condition | Score |
|-----------|-------|
| POST to `mics-config/handleMessage` | 100 — direct exploit path, treat as active attack |
| Any access to `handleMessage` endpoint | 90 — recon or exploitation |
| Admin account API POST/PUT/PATCH returning 200/201 | 85 — CVE-2026-10523 account creation |
| POST to MICS API returning 200 or 500 | 80 — exploitation attempt with server response |
| Config export/import API access | 75 — config exfiltration risk |
| Any MICS API access | 60 — anomalous baseline |

## Associated Threat Actors

- **Nation-state threat actors** — Ivanti Sentry appliances are high-value targets as MDM gateways; prior Ivanti CVEs (CVE-2023-38035, CVE-2025-22457) were exploited by UNC4841 (suspected Chinese nexus) and Volt Typhoon
- **Initial Access Brokers** — CVSS 10.0 unauth RCE on network-edge appliances aligns with IAB tradecraft for enterprise network access sales
- **APT clusters targeting mobile device management** — Ivanti Sentry manages enterprise mobile deployments; compromise provides access to MDM policies, enrolled device inventory, and credential stores

## References

- [CISA KEV — CVE-2026-10520 added 2026-06-11](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
- [Rapid7 — CVE-2026-10520 Ivanti Sentry MICS API Command Injection](https://www.rapid7.com/blog/)
- [NVD — CVE-2026-10520](https://nvd.nist.gov/vuln/detail/CVE-2026-10520)
- [NVD — CVE-2026-10523](https://nvd.nist.gov/vuln/detail/CVE-2026-10523)
