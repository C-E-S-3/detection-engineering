# Lazarus Domain Generation Algorithm (DGA) Detection

## Description

Detects potential domain generation algorithm (DGA) usage by analyzing DNS queries for lexical anomalies: excessive domain length (>20 characters), high consonant-to-vowel ratio (>70%), and low query counts per domain (<5). DGA is used by Lazarus Group and other threat actors to generate disposable C2 domains that are difficult to blocklist.

False positive sources: CDN domains, auto-generated cloud service hostnames. Tuning: add known-good long domains to an allowlist.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Dynamic Resolution: Domain Generation Algorithms |
| Technique ID | T1568.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
(`infoblox_dns` OR `zscaler_dns`)
| rex field=query "(?<domain>[^.]+\.[^.]+)$"
| eval domain_length=len(query)
| eval entropy=0
| eval query_lower=lower(query)
| rex field=query_lower mode=sed "s/[aeiou]//g"
| eval consonant_ratio=len(query_lower)/domain_length
| where domain_length > 20 AND consonant_ratio > 0.7
| stats count by src_ip, query, domain_length
| where count < 5
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Long domain + high consonant ratio + low frequency | High | Strong DGA indicators: randomly generated domains are long, consonant-heavy, and queried infrequently |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |

## References

- [MITRE ATT&CK - Domain Generation Algorithms (T1568.002)](https://attack.mitre.org/techniques/T1568/002/)
