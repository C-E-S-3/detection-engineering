# Silver Ticket - TGS Request Without Preceding TGT

## Description

A Silver Ticket is a forged Kerberos TGS ticket. Because the attacker forges the service ticket directly using the service account's hash, there is no corresponding TGT request (Event 4768) on the Domain Controller. This detection looks for TGS events (4769) for user accounts where no corresponding TGT was issued within a lookback window, which may indicate a forged service ticket. A TGT age exceeding 24 hours may also indicate ticket reuse or forgery.

False positive sources: Network interruptions may cause missed TGT logging, load-balanced Domain Controllers may log TGT and TGS on different DCs. Tuning: ensure all DC logs are forwarded to the same Splunk index; extend the lookback window in large environments; correlate across multiple DCs.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Steal or Forge Kerberos Tickets: Silver Ticket |
| Technique ID | T1558.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`wineventlog_security` EventCode=4769
| where Service_Name!="krbtgt" AND Account_Name!="*$"
| rename Account_Name as tgs_account Client_Address as tgs_client
| join type=left tgs_account tgs_client
    [search `wineventlog_security` EventCode=4768 Status=0x0
     | rename Account_Name as tgs_account Client_Address as tgs_client
     | stats max(_time) as last_tgt_time by tgs_account tgs_client]
| eval tgt_age=_time - last_tgt_time
| eval has_tgt=if(isnotnull(last_tgt_time), 1, 0)
| where has_tgt=0 OR tgt_age > 86400
| eval risk_score=case(
    has_tgt=0, 90,
    tgt_age > 86400, 70,
    1=1, 60)
| eval risk_reason=case(
    has_tgt=0, "No preceding TGT found - possible Silver Ticket",
    tgt_age > 86400, "TGT older than 24h - possible ticket reuse or forgery",
    1=1, "Anomalous TGS request")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Service_Name) as services values(Ticket_Encryption_Type) as encryption_types
    values(risk_reason) as risk_reason
    by tgs_account tgs_client risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - risk_score
| table firstTime lastTime tgs_account tgs_client services encryption_types risk_reason count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| No preceding TGT found | 90 | High-confidence Silver Ticket - forged TGS bypasses TGT issuance |
| TGT older than 24 hours | 70 | Possible ticket reuse or forgery - legitimate TGTs are typically refreshed within hours |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using Mimikatz | [Mimikatz - Silver Ticket](https://github.com/gentilkiwi/mimikatz) |
| Any adversary using Impacket (ticketer.py) | [Impacket](https://github.com/fortra/impacket) |

## References

- [MITRE ATT&CK - Silver Ticket (T1558.002)](https://attack.mitre.org/techniques/T1558/002/)
- [ADSecurity - How Attackers Use Kerberos Silver Tickets](https://adsecurity.org/?p=2011)
