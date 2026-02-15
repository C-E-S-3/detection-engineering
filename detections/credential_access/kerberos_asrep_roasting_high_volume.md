# AS-REP Roasting - High Volume Targeting Multiple Accounts

## Description

Attackers using tools like Rubeus's `asreproast` command or Impacket's `GetNPUsers.py` will enumerate and request AS-REPs for all accounts with pre-authentication disabled. This detection identifies a single source IP requesting TGTs without pre-authentication for multiple distinct accounts within a 30-minute window, which is a strong indicator of AS-REP Roasting enumeration rather than normal authentication activity.

False positive sources: Very rare. Legitimate systems do not typically request TGTs for multiple accounts without pre-authentication. Tuning: adjust the `unique_accounts >= 3` threshold based on environment size.

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
| bin _time span=30m
| stats dc(Account_Name) as unique_accounts count as total_requests
    values(Account_Name) as targeted_accounts values(Ticket_Encryption_Type) as encryption_types
    by Client_Address _time
| where unique_accounts >= 3
| eval has_rc4=if(match(encryption_types, "0x17"), 1, 0)
| eval risk_score=case(
    unique_accounts >= 10 AND has_rc4=1, 95,
    unique_accounts >= 10, 90,
    unique_accounts >= 5 AND has_rc4=1, 85,
    unique_accounts >= 5, 80,
    has_rc4=1, 75,
    1=1, 70)
| sort - risk_score
| table _time Client_Address unique_accounts total_requests targeted_accounts encryption_types risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| 10+ accounts with RC4 | 95 | Large-scale AS-REP Roasting enumeration with weak encryption |
| 10+ accounts without RC4 | 90 | Large-scale enumeration - high confidence malicious |
| 5-9 accounts with RC4 | 85 | Moderate enumeration with offline cracking intent |
| 5-9 accounts without RC4 | 80 | Moderate enumeration requiring investigation |
| 3-4 accounts with RC4 | 75 | Small-scale targeting with weak encryption preference |
| 3-4 accounts without RC4 | 70 | Minimum threshold - could be targeted attack |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using Rubeus (asreproast) | [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus) |
| Any adversary using Impacket (GetNPUsers.py) | [Impacket](https://github.com/fortra/impacket) |

## References

- [MITRE ATT&CK - AS-REP Roasting (T1558.004)](https://attack.mitre.org/techniques/T1558/004/)
- [Microsoft - Event 4768 Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
