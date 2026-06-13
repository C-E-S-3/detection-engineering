# Ivanti Sentry MICS API OS Command Injection (CVE-2026-10520)

## Description

Detects exploitation of CVE-2026-10520, a CVSS 10.0 OS command injection vulnerability in Ivanti Sentry's MICS (Mobile Iron Core Server) management API. An unauthenticated attacker sends an HTTP POST to `/mics/api/v2/sentry/mics-config/handleMessage` with the `command` parameter set to `execute`; the `ConfigServiceController.handleExecute()` method passes unsanitized input directly to native OS commands, achieving root-level remote code execution. A companion authentication bypass (CVE-2026-10523, CVSS 9.9) enables attackers to create arbitrary administrative accounts on the same appliance. CISA added CVE-2026-10520 to the KEV Catalog on June 11, 2026, with a June 14 remediation deadline under BOD 26-04.

False positives: legitimate Ivanti Sentry management automation tools or health-check scripts may POST to the MICS API, but `handleMessage` with `command=execute` has no documented legitimate administrative use case.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary: T1136.001 (Create Account: Local Account) via CVE-2026-10523 post-exploitation.

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url="*/mics/api/v2/sentry/mics-config/handleMessage*"
  AND Web.http_method="POST"
by Web.src Web.dest Web.url Web.http_method Web.status Web.bytes Web.user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "(?i)handleMessage") AND http_method="POST", 90,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest url http_method status bytes user_agent risk_score
```

Broader detection covering the full MICS API surface (useful until CVE-2026-10520 is patched or the MICS port is firewalled):

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url="*/mics/api/*"
  AND Web.http_method="POST"
  AND (Web.status=200 OR Web.status=500)
by Web.src Web.dest Web.url Web.http_method Web.status Web.bytes Web.user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "(?i)handleMessage"), 90,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src dest url http_method status bytes user_agent risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| POST to `/mics/api/v2/sentry/mics-config/handleMessage` | 90 | Direct exploitation of CVE-2026-10520 — no legitimate use case for this endpoint from external sources; CVSS 10.0 |
| POST to any `/mics/api/*` path with HTTP 200 or 500 | 65 | Broad MICS API coverage for unpatched environments; HTTP 500 may indicate failed exploit attempt or error-based reconnaissance |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (rapid opportunistic exploitation post-PoC) | [Shadowserver — backdoored instances confirmed within 24 hrs of patch](https://www.shadowserver.org/) |
| China-nexus APTs (historical Ivanti targeting) | [MITRE ATT&CK — UNC5221 (G1040)](https://attack.mitre.org/groups/G1040/), [Google TI — UNC5221 Ivanti CVE-2025-22457](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-exploiting-critical-ivanti-vulnerability) |
| Ransomware affiliates (historical Ivanti targeting) | [CISA Advisory AA24-060A — Ivanti Exploitation by Threat Actors](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060a) |

## References

- [Rapid7 ETR — CVE-2026-10520 and CVE-2026-10523](https://www.rapid7.com/blog/post/etr-cve-2026-10520-cve-2026-10523-multiple-critical-vulnerabilities-affecting-ivanti-sentry/)
- [BleepingComputer — Max severity Ivanti Sentry vulnerability now exploited in attacks](https://www.bleepingcomputer.com/news/security/max-severity-ivanti-sentry-vulnerability-now-exploited-in-attacks/)
- [CISA KEV Alert — 2026-06-11 (June 14 patch deadline)](https://www.cisa.gov/news-events/alerts/2026/06/11/cisa-adds-one-known-exploited-vulnerability-catalog)
- [Help Net Security — Technical Analysis CVE-2026-10520 and CVE-2026-10523](https://www.helpnetsecurity.com/2026/06/10/ivanti-sentry-cve-2026-10520-cve-2026-10523/)
- [CERT-EU Security Advisory 2026-008](https://cert.europa.eu/publications/security-advisories/2026-008/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
