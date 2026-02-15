# Lazarus Suspicious Outbound Traffic via Fortigate

## Description

Detects suspicious outbound network traffic patterns associated with Lazarus Group operations: high total bytes transferred to external destinations, connections to many unique destination IPs, or excessive DNS-port activity. Uses Fortigate firewall logs to identify potential data exfiltration or C2 communication.

False positive sources: Legitimate cloud services, CDN traffic, backup operations. Tuning: adjust byte thresholds and unique destination counts; allowlist known cloud service IPs.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol |
| Technique ID | T1071 |
| Secondary Tactic | Exfiltration (TA0010) - T1048 Exfiltration Over Alternative Protocol |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) / Actions on Objectives |

## Splunk Detection Query

```spl
`fortigate`
(action="accept" OR action="allowed") dstip!="10.*" dstip!="172.16.*" dstip!="192.168.*"
| search dstport IN (443, 8080, 8443, 8888, 53, 80)
| stats sum(bytes_out) as total_bytes dc(dstip) as unique_dest count by srcip, dstport
| where (total_bytes > 10485760 AND unique_dest > 50) OR (dstport=53 AND count > 1000)
| table srcip, dstport, total_bytes, unique_dest, count
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| >10 MB transferred + >50 unique destinations | High | Large data volume to many targets suggests exfiltration or C2 fanout |
| >1000 DNS queries to external IPs | High | Excessive DNS may indicate DNS tunneling or C2 |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |

## References

- [MITRE ATT&CK - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/)
- [CISA - HIDDEN COBRA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-106a)
