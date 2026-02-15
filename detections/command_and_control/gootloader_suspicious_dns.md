# Gootloader Suspicious DNS Queries

## Description

Gootloader C2 domains are often recently registered or hosted on compromised sites. This detection identifies hosts resolving domains with suspicious lexical characteristics: excessive length (>20 chars), digit sequences, or high consonant ratios. Multiple suspicious queries from a single source may indicate Gootloader C2 check-in or payload retrieval.

False positive sources: CDN domains, cloud service endpoints with long auto-generated names. Tuning: add known-good long domain patterns to an allowlist.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: DNS |
| Technique ID | T1071.004 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.message_type="Query"
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| rex field=query "(?<tld>[^\.]+)\.(?<domain_suffix>[^\.]+)$"
| eval query_length=len(query)
| eval has_digits=if(match(query, "\d{3,}"), 1, 0)
| eval consonant_ratio=round((len(replace(query, "[aeiouAEIOU\.\-\d]", "")) / len(replace(query, "[\.\-]", "")))*100, 2)
| where query_length > 20 OR has_digits=1 OR consonant_ratio > 65
| stats count dc(query) as unique_queries values(query) as suspicious_queries by src
| where unique_queries >= 3
| eval risk_score=case(
    unique_queries >= 10, 85,
    unique_queries >= 5, 70,
    1=1, 55)
| where risk_score >= 55
| table src unique_queries suspicious_queries risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| 10+ unique suspicious domains | 85 | High volume of anomalous DNS; likely DGA or C2 rotation |
| 5-9 unique suspicious domains | 70 | Moderate anomalous DNS activity |
| 3-4 unique suspicious domains | 55 | Low-level anomaly, useful for correlation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
