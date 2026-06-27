# PTC Windchill PDMlink / FlexPLM Unauthenticated RCE — JSP Webshell Deployment (CVE-2026-12569)

## Description

Detects exploitation of CVE-2026-12569, a critical (CVSS 9.3) unauthenticated remote code execution vulnerability in PTC Windchill PDMlink and FlexPLM CPS. The vulnerability stems from improper input validation and Java deserialization in the Windchill servlet layer. Post-exploitation, attackers write a JSP webshell with a 16-character hexadecimal filename to the `/Windchill/login/` directory, providing persistent unauthenticated command execution under the application server's service account.

CISA added CVE-2026-12569 to its Known Exploited Vulnerabilities catalog on approximately June 25, 2026 (FCEB remediation deadline June 28, 2026). PTC Windchill is widely deployed in manufacturing, defense, and aerospace sectors for product lifecycle management (PLM); access to these systems may expose sensitive engineering designs and supply chain data.

**False positive sources:**
- Application deployment or patching processes writing `.jsp` files to Windchill directories
- Legitimate POST requests to dynamic Windchill servlet URLs that match the `/login/*.jsp` pattern (rare; verify by inspecting exact filenames against the 16-char hex pattern)
- Web vulnerability scanners performing authenticated scans

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Persistence |
| Secondary Tactic ID | TA0003 |
| Secondary Technique | Server Software Component: Web Shell |
| Secondary Technique ID | T1505.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url IN ("*/Windchill/login/*.jsp") AND Web.http_method="POST"
by Web.src Web.dest Web.url Web.http_method Web.status Web.bytes Web.user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "\/Windchill\/login\/[0-9a-f]{16}\.jsp"), 95,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest url http_method status bytes user_agent risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where (Endpoint.Filesystem.file_path IN ("*\\Windchill\\login\\*.jsp","*/Windchill/login/*.jsp"))
  AND Endpoint.Filesystem.action IN ("created","modified")
by Endpoint.Filesystem.dest Endpoint.Filesystem.user Endpoint.Filesystem.file_name
   Endpoint.Filesystem.file_path Endpoint.Filesystem.process_name
| rename Endpoint.Filesystem.* as *
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name, "^[0-9a-f]{16}\.jsp$"), 95,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user file_name file_path process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| POST to `/Windchill/login/<16hexchars>.jsp` (regex match on 16-char hex filename) | 95 | Highly specific webshell pattern matching observed post-exploitation artifact; very high confidence malicious |
| POST to any `/Windchill/login/*.jsp` path (no filename filter) | 75 | Dynamic `.jsp` filename in login directory is anomalous; investigate for false positives from deployment processes |
| New `.jsp` file created in Windchill login directory matching 16-char hex filename | 95 | Webshell write event; confirms exploitation and persistence establishment |
| New `.jsp` file created in Windchill login directory (any name) | 80 | Suspicious filesystem write to servlet directory; investigate source process |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors (CVE-2026-12569 exploitation, June 2026) | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [NVD CVE-2026-12569](https://nvd.nist.gov/vuln/detail/CVE-2026-12569) |

## References

- [CISA KEV — CVE-2026-12569](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [PTC Security Advisory — Windchill CVE-2026-12569](https://www.ptc.com/en/support/article/CS432285)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [NVD — CVE-2026-12569](https://nvd.nist.gov/vuln/detail/CVE-2026-12569)
- [Threat Intel Report — CVE-2026-12569 JSP Webshell Active Exploitation](../../threat-intel/2026-06-26_cisa-kev-ptc-windchill-cve-2026-12569-flexplm-rce-webshell.md)
