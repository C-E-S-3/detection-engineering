# OverPass-the-Hash - TGT Request with RC4 Encryption

## Description

An OverPass-the-Hash attack occurs when an adversary uses a stolen NTLM hash to request a Kerberos TGT via RC4 encryption instead of using the account's actual password. In modern environments where AES is the default, a TGT request (Event 4768) using RC4 encryption (`0x17`) is anomalous and may indicate this attack. The risk is further elevated when the Canonicalize flag is absent, indicating the use of offensive tooling rather than a legitimate legacy client.

False positive sources: Legacy systems or applications that require RC4 encryption for backward compatibility, older Windows versions (pre-2008 R2). Tuning: identify and exclude known legacy systems that legitimately use RC4.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Use Alternate Authentication Material: Pass the Hash |
| Technique ID | T1550.002 |
| Secondary Tactic | Lateral Movement (TA0008) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`wineventlog_security` EventCode=4768 Ticket_Encryption_Type=0x17 Status=0x0
| where Account_Name!="*$"
| eval ticket_opts_dec=tonumber(replace(Ticket_Options, "^0x", ""), 16)
| eval canonicalize_set=if((floor(ticket_opts_dec / 65536) % 2) == 1, 1, 0)
| eval risk_score=case(
    canonicalize_set=0, 90,
    1=1, 75)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Ticket_Options) as ticket_options values(Account_Name) as accounts
    by Client_Address Ticket_Encryption_Type risk_score canonicalize_set
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - risk_score
| table firstTime lastTime Client_Address accounts Ticket_Encryption_Type ticket_options canonicalize_set count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| RC4 TGT request without Canonicalize flag | 90 | Offensive tool using stolen NTLM hash - high confidence |
| RC4 TGT request with Canonicalize flag | 75 | Possibly legitimate legacy client, but RC4 is anomalous in modern environments |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using Mimikatz | [Mimikatz](https://github.com/gentilkiwi/mimikatz) |
| Any adversary using Rubeus | [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus) |
| Any adversary using Impacket | [Impacket](https://github.com/fortra/impacket) |

## References

- [Splunk Security Content - Kerberos TGT Request Using RC4 Encryption](https://research.splunk.com/endpoint/18916468-9c04-11ec-bdc6-acde48001122/)
- [MITRE ATT&CK - Pass the Hash (T1550.002)](https://attack.mitre.org/techniques/T1550/002/)
