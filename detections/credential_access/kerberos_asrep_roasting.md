# AS-REP Roasting - TGT Request Without Pre-Authentication

## Description

AS-REP Roasting targets accounts with Kerberos pre-authentication disabled (DONT_REQUIRE_PREAUTH). When this is set, the KDC returns an encrypted TGT without verifying the requester's identity, allowing offline password cracking. This detection monitors Event ID 4768 for successful TGT requests where the Pre-Authentication Type is `0` (disabled), especially when combined with RC4 encryption. DES encryption is scored even higher as it indicates extremely outdated or malicious configurations.

False positive sources: Service accounts intentionally configured without pre-authentication (rare but possible in legacy environments). Tuning: maintain an allowlist of known accounts with pre-authentication disabled and monitor for unauthorized changes to this attribute.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Steal or Forge Kerberos Tickets: AS-REP Roasting |
| Technique ID | T1558.004 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`wineventlog_security` EventCode=4768 Pre_Authentication_Type=0 Status=0x0
| eval is_rc4=if(Ticket_Encryption_Type="0x17", 1, 0)
| eval is_des=if(Ticket_Encryption_Type="0x03" OR Ticket_Encryption_Type="0x01", 1, 0)
| eval risk_score=case(
    is_rc4=1, 90,
    is_des=1, 95,
    1=1, 70)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Ticket_Encryption_Type) as encryption_types values(Ticket_Options) as ticket_options
    by Account_Name Client_Address Service_Name risk_score
| where Account_Name!="*$"
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - risk_score
| table firstTime lastTime Account_Name Client_Address Service_Name encryption_types ticket_options count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Pre-auth disabled with DES encryption | 95 | Deprecated encryption + no pre-auth - near-certain malicious activity |
| Pre-auth disabled with RC4 encryption | 90 | Weak encryption preferred for offline cracking - classic AS-REP Roasting |
| Pre-auth disabled with AES encryption | 70 | Anomalous but less likely to be cracked offline |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using Rubeus (asreproast) | [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus) |
| Any adversary using Impacket (GetNPUsers.py) | [Impacket](https://github.com/fortra/impacket) |

## References

- [Microsoft - Event 4768 Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [MITRE ATT&CK - AS-REP Roasting (T1558.004)](https://attack.mitre.org/techniques/T1558/004/)
