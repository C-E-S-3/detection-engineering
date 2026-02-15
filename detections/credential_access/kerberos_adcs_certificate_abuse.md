# ADCS Abuse - Certificate-Based TGT with Suspicious TicketOptions

## Description

Active Directory Certificate Services (ADCS) attacks (e.g., ESC1-ESC8 via Certipy or Certify) result in TGT requests with Pre-Authentication Type 16 (certificate-based). When combined with TicketOptions starting with `0x4080` (missing Canonicalize flag), this is a high-confidence indicator of ADCS exploitation since this hex prefix is hardcoded in Certipy, Rubeus, and other ADCS attack tools. Legitimate certificate-based authentication typically includes the Canonicalize flag.

False positive sources: Very rare. Legitimate smart card or certificate-based authentication uses different TicketOptions patterns that include Canonicalize. Tuning: verify that no legitimate PKI-based authentication in your environment produces `0x4080*` TicketOptions.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Steal or Forge Authentication Certificates |
| Technique ID | T1649 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`wineventlog_security` EventCode=4768 Pre_Authentication_Type=16
| eval ticket_opts_str=Ticket_Options
| where match(ticket_opts_str, "^0x4080")
| eval risk_score=90
| eval detection_detail="Certificate-based TGT with tool-fingerprinted TicketOptions (0x4080*) - likely ADCS exploitation (Certipy/Rubeus/Certify)"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Ticket_Encryption_Type) as encryption_types
    by Account_Name Client_Address Service_Name Ticket_Options detection_detail risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime Account_Name Client_Address Service_Name Ticket_Options encryption_types detection_detail count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Certificate-based TGT with `0x4080*` TicketOptions | 90 | High-confidence ADCS exploitation - tool fingerprint in certificate auth context |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any adversary using Certipy | [Certipy - ADCS exploitation](https://github.com/ly4k/Certipy) |
| Any adversary using Certify | [GhostPack - Certify](https://github.com/GhostPack/Certify) |
| Any adversary using Rubeus (PKINIT) | [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus) |

## References

- [MITRE ATT&CK - Steal or Forge Authentication Certificates (T1649)](https://attack.mitre.org/techniques/T1649/)
- [SpecterOps - Certified Pre-Owned (ADCS Whitepaper)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
