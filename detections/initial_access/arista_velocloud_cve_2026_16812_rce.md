# Arista VeloCloud Orchestrator On-Prem OS Command Injection — CVE-2026-16812

## Description

Detects exploitation of CVE-2026-16812, a critical (CVSS 10.0) unauthenticated OS command injection vulnerability in Arista VeloCloud Orchestrator (VCO) On-Premises. The flaw allows a remote attacker to inject and execute arbitrary OS commands on the orchestrator host, fully compromising the SD-WAN management plane and all tenant network configurations managed by the VCO. CISA added CVE-2026-16812 to the Known Exploited Vulnerabilities catalog on July 27, 2026 with an accelerated 3-day FCEB remediation deadline (July 30, 2026), signaling high-confidence in-the-wild exploitation.

Three attacker source IPs are documented from active exploitation: `8.19.75.217`, `206.72.242.124`, `206.72.242.162`. Patches were released July 28, 2026 (fixed in VCO 5.2.3.14 / 6.1.3.4 / 6.4.2.4 / 7.0.0.1).

**False positive sources:**
- Legitimate VCO administrative API calls from authorized management hosts — filter by src IP allowlist for known management ranges
- Vulnerability scanners performing authorized scans against the VCO management interface
- Child process spawns from Java app server processes during normal operation (rare; baseline and filter per environment)

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution |
| Secondary Tactic ID | TA0002 |
| Secondary Technique | Command and Scripting Interpreter: Unix Shell |
| Secondary Technique ID | T1059.004 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.src_ip IN (
    "8.19.75.217","206.72.242.124","206.72.242.162")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
   All_Traffic.transport All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_ip dest_port transport action risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("java","javaw","python","python3","nginx","apache2","httpd")
  AND Processes.process_name IN (
    "sh","bash","curl","wget","id","whoami","uname",
    "nc","ncat","python3","python","perl")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 90
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Inbound connection from confirmed CVE-2026-16812 attacker IP (8.19.75.217, 206.72.242.124, 206.72.242.162) | 95 | Known attacker infrastructure from active exploitation; very high confidence malicious |
| Shell/OS utility spawned as child of web application server process (Java, nginx) | 90 | Highly anomalous; strongly indicative of post-exploitation command injection; very few legitimate scenarios |
| POST request to VCO API endpoint from an unexpected external IP | 70 | Suspicious; investigate for exploitation attempt vs. authorized external access |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (CVE-2026-16812 active exploitation, July 2026) | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [Arista Security Advisory 0144](https://www.arista.com/en/support/advisories-notices/security-advisory/24364-security-advisory-0144), [NVD CVE-2026-16812](https://nvd.nist.gov/vuln/detail/CVE-2026-16812) |

## References

- [CISA KEV — CVE-2026-16812 (added 2026-07-27)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Arista Networks Security Advisory 0144 — CVE-2026-16812](https://www.arista.com/en/support/advisories-notices/security-advisory/24364-security-advisory-0144)
- [NVD — CVE-2026-16812](https://nvd.nist.gov/vuln/detail/CVE-2026-16812)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1059.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [Threat Intel Report — CVE-2026-16812 Arista VeloCloud KEV](../../threat-intel/2026-07-29_cisa-kev-cve-2026-16812-arista-velocloud-rce.md)
