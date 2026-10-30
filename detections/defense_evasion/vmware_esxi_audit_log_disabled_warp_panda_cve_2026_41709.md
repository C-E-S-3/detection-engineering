# VMware ESXi Audit Log Disabled or Modified (CVE-2026-41709 / Warp Panda)

## Description

Detects modification or disabling of VMware ESXi audit logging configuration. CVE-2026-41709 is a low-CVSS (2.7) VMware ESXi logging flaw added to the CISA KEV catalog on October 28, 2026 after confirmed exploitation by Warp Panda, a China-nexus espionage actor targeting the U.S. legal sector. Attackers suppress ESXi audit records to reduce forensic visibility during intrusion operations on hypervisor infrastructure.

False positives: Legitimate administrative changes to ESXi logging configuration (scheduled maintenance, log rotation tuning, SIEM integration setup). Baseline normal change patterns and alert on deviations outside expected maintenance windows.

## MITRE ATT&CK Mapping

- **Tactic:** Defense Evasion (TA0005)
- **Technique:** T1562.001 — Impair Defenses: Disable or Modify Tools
- **Sub-technique:** T1562.008 — Impair Defenses: Disable Cloud Logs (hypervisor audit records)

## Lockheed Martin Kill Chain Phase

Exploitation / Installation (attacker modifies logging after gaining hypervisor access to extend dwell time undetected)

## Splunk SPL Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Change
where Change.object_category="VMware"
  AND (Change.object IN ("syslog","auditRecord","logLevel","logging","vmsyslogd","hostd"))
  AND Change.action IN ("modified","disabled","deleted","stopped")
by Change.dest Change.user Change.object Change.action Change.command Change.src
| `drop_dm_object_name(Change)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    action IN ("disabled","deleted") AND object="auditRecord", 85,
    action IN ("disabled","deleted") AND object="syslog", 80,
    action="stopped" AND object IN ("vmsyslogd","hostd"), 75,
    action="modified" AND object="auditRecord", 70,
    action="modified" AND object="syslog", 60,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest src user object action command risk_score
```

## Risk Score Logic

| Condition | Score | Meaning |
|-----------|-------|---------|
| auditRecord disabled or deleted | 85 | Direct impairment of ESXi forensic logging; high confidence malicious |
| syslog disabled or deleted | 80 | Suppresses all host-level event forwarding to SIEM |
| syslogd/hostd service stopped | 75 | Killing the log daemon prevents any record generation |
| auditRecord modified | 70 | Attacker may be narrowing audit scope to exclude their activity |
| syslog modified | 60 | Config change that may reduce or redirect log output |

## Associated Threat Actors

| Actor | Description | References |
|-------|-------------|-----------|
| Warp Panda | China-nexus espionage actor; exploited CVE-2026-41709 against U.S. legal sector in Oct 2026 | [The Hacker News](https://thehackernews.com/2026/10/china-linked-hackers-exploited-vmware.html) |

## References

- [CISA Adds Two Known Exploited Vulnerabilities to Catalog (Oct 28, 2026)](https://www.cisa.gov/news-events/alerts/2026/10/28/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [China-Linked Hackers Exploited VMware ESX Zero-Day to Reduce Audit Trail Visibility](https://thehackernews.com/2026/10/china-linked-hackers-exploited-vmware.html)
- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK T1562.008](https://attack.mitre.org/techniques/T1562/008/)
