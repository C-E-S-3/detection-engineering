# Lazarus C2 Beaconing via DNS

## Description

Detects Lazarus Group C2 beaconing patterns by analyzing DNS query volumes and statistical regularity. Identifies hosts making 50-200 unique DNS queries to specific domains with consistent timing patterns (low standard deviation and high average counts), which is indicative of automated C2 check-ins.

False positive sources: DNS-heavy applications, software update services. Tuning: adjust unique_queries range and statistical thresholds for your environment.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol |
| Technique ID | T1071 |
| Secondary Technique | Encrypted Channel (T1573) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
(`infoblox_dns` OR `zscaler_dns`)
| stats count dc(query) as unique_queries by src_ip, dest_domain
| where unique_queries > 50 AND unique_queries < 200
| join src_ip [
    search (`infoblox_dns` OR `zscaler_dns`)
    | bin _time span=1h
    | stats count by _time, src_ip
    | streamstats window=10 stdev(count) as std_dev avg(count) as avg_count by src_ip
    | where (count > avg_count + (2*std_dev)) OR (std_dev < 5 AND avg_count > 20)
]
| table src_ip, dest_domain, unique_queries
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Unique queries 50-200 + low stdev | High | Automated beaconing pattern with controlled query volume |
| Count exceeds 2 standard deviations | Medium | Statistical outlier in query behavior |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |

## References

- [MITRE ATT&CK - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/)
- [Kaspersky - Lazarus Under the Hood](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf)
