# Gootloader C2 Beaconing Over HTTPS

## Description

Gootloader communicates with C2 infrastructure over HTTPS, often using compromised WordPress sites. This detection uses the Network Traffic data model to identify repeated outbound connections to uncommon external destinations that match beaconing patterns: low jitter (low standard deviation) with consistent request volumes across time windows.

False positive sources: Legitimate update checks, telemetry services, and CDN connections. Tuning: adjust the stdev and avg thresholds; add known-good destinations to an allowlist.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |
| Secondary Technique | Encrypted Channel: Asymmetric Cryptography (T1573.002) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_port IN (443, 80)
    AND All_Traffic.action="allowed"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| eventstats dc(dest) as unique_dests by src
| where unique_dests >= 5
| bin _time span=10m
| stats count as request_count values(dest) as destinations dc(dest) as unique_targets by src _time
| streamstats window=6 avg(request_count) as avg_requests stdev(request_count) as stdev_requests by src
| where stdev_requests < 3 AND avg_requests > 5
| eval risk_score=case(
    stdev_requests < 1 AND avg_requests > 15, 85,
    stdev_requests < 2 AND avg_requests > 10, 75,
    1=1, 60)
| where risk_score >= 60
| table _time src destinations unique_targets avg_requests stdev_requests risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Very low jitter (stdev < 1) + high frequency (avg > 15) | 85 | Strong beaconing pattern with machine-like regularity |
| Low jitter (stdev < 2) + moderate frequency (avg > 10) | 75 | Likely beaconing with slight variation |
| General low-jitter pattern | 60 | Possible beaconing, needs correlation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
- [MITRE ATT&CK - Web Protocols (T1071.001)](https://attack.mitre.org/techniques/T1071/001/)
