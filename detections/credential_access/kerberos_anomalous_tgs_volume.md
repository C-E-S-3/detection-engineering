# Kerberoasting - Anomalous Volume of TGS Requests

## Description

Kerberoasting tools typically enumerate all SPNs in the domain and request service tickets for each one in rapid succession. This detection identifies accounts requesting an unusually high number of distinct service tickets within a short time window using statistical analysis (3-sigma rule). A normal user rarely requests more than a handful of unique service tickets in an hour. The detection also checks for RC4 encryption usage to elevate the risk score when weak encryption is combined with high volume.

False positive sources: Service accounts performing legitimate batch operations, monitoring tools querying multiple services, SCCM/SCOM operations. Tuning: adjust the threshold and statistical parameters based on your environment baseline.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Steal or Forge Kerberos Tickets: Kerberoasting |
| Technique ID | T1558.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`wineventlog_security` EventCode=4769
| where Service_Name!="krbtgt" AND Service_Name!="*$"
| bin _time span=1h
| stats dc(Service_Name) as unique_services count as total_requests
    values(Service_Name) as targeted_services values(Ticket_Encryption_Type) as encryption_types
    by Account_Name Client_Address _time
| eventstats avg(unique_services) as avg_services stdev(unique_services) as stdev_services
    by Account_Name
| eval threshold=avg_services + (3 * stdev_services)
| eval threshold=if(threshold < 10, 10, threshold)
| where unique_services > threshold OR unique_services > 15
| eval has_rc4=if(match(encryption_types, "0x17"), 1, 0)
| eval risk_score=case(
    unique_services > 50 AND has_rc4=1, 95,
    unique_services > 50, 85,
    unique_services > 20 AND has_rc4=1, 85,
    unique_services > 20, 75,
    has_rc4=1, 70,
    1=1, 60)
| sort - risk_score
| table _time Account_Name Client_Address unique_services total_requests encryption_types avg_services threshold targeted_services risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| 50+ unique services with RC4 | 95 | Near-certain Kerberoasting - massive SPN enumeration with weak encryption |
| 50+ unique services without RC4 | 85 | High-volume SPN enumeration, possible AES-based Kerberoasting |
| 20+ unique services with RC4 | 85 | Significant enumeration with weak encryption preference |
| 20+ unique services without RC4 | 75 | Anomalous volume, requires investigation |
| Below 20 with RC4 | 70 | Moderate volume with suspicious encryption |
| Below 20 without RC4 | 60 | Statistically anomalous but lower confidence |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using Rubeus | [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus) |
| Any adversary using Impacket | [Impacket - GetUserSPNs.py](https://github.com/fortra/impacket) |

## References

- [Splunk Security Content - Unusual Number of Kerberos Service Tickets Requested](https://research.splunk.com/endpoint/eb3e6702-8936-11ec-98fe-acde48001122/)
- [MITRE ATT&CK - Kerberoasting (T1558.003)](https://attack.mitre.org/techniques/T1558/003/)
- [TrustedSec - The Art of Bypassing Kerberoast Detections with Orpheus](https://trustedsec.com/blog/the-art-of-bypassing-kerberoast-detections-with-orpheus)
