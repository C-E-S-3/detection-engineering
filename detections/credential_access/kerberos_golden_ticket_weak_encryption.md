# Golden Ticket - TGT Request with Deprecated Encryption

## Description

Golden Ticket attacks involve forging a TGT using the KRBTGT account's hash. Offensive tools often default to RC4 or even DES encryption when forging tickets. This detection looks for TGT requests with weak encryption (RC4 or DES) for non-machine accounts. DES encryption is almost certainly malicious in modern environments as it is deprecated and disabled by default. The risk is further elevated when the Canonicalize flag is absent, indicating offensive tooling.

False positive sources: Legacy systems using RC4 for backward compatibility. DES false positives are extremely rare in properly configured environments. Tuning: correlate with account privilege level (Domain Admins, Enterprise Admins) to prioritize triage.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Steal or Forge Kerberos Tickets: Golden Ticket |
| Technique ID | T1558.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`wineventlog_security` EventCode=4768 Status=0x0
    (Ticket_Encryption_Type=0x17 OR Ticket_Encryption_Type=0x03 OR Ticket_Encryption_Type=0x01)
| where Account_Name!="*$"
| eval is_des=if(Ticket_Encryption_Type="0x03" OR Ticket_Encryption_Type="0x01", 1, 0)
| eval risk_score=case(
    is_des=1, 95,
    Ticket_Encryption_Type="0x17", 75,
    1=1, 60)
| eval ticket_opts_dec=tonumber(replace(Ticket_Options, "^0x", ""), 16)
| eval canonicalize_set=if((floor(ticket_opts_dec / 65536) % 2) == 1, 1, 0)
| eval risk_score=if(canonicalize_set=0, risk_score + 15, risk_score)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Ticket_Options) as ticket_options
    by Account_Name Client_Address Service_Name Ticket_Encryption_Type risk_score canonicalize_set
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - risk_score
| table firstTime lastTime Account_Name Client_Address Service_Name Ticket_Encryption_Type ticket_options canonicalize_set count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DES encryption | 95 | Deprecated encryption - near-certain forgery or misconfiguration |
| DES + missing Canonicalize | 95+15 | Capped at 100 - definitive offensive tool indicator |
| RC4 encryption | 75 | Anomalous in modern environments, common in Golden Ticket attacks |
| RC4 + missing Canonicalize | 90 | RC4 with tool fingerprint - high confidence forged ticket |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using Mimikatz | [Mimikatz - Golden Ticket](https://github.com/gentilkiwi/mimikatz) |
| Any adversary using Impacket (ticketer.py) | [Impacket](https://github.com/fortra/impacket) |
| Any adversary using Rubeus | [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus) |

## References

- [MITRE ATT&CK - Golden Ticket (T1558.001)](https://attack.mitre.org/techniques/T1558/001/)
- [ADSecurity - Detecting Forged Kerberos Tickets](https://adsecurity.org/?p=1515)
