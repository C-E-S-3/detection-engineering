# Lazarus O365 Spearphishing Detection

## Description

Lazarus Group conducts spearphishing campaigns using weaponized email attachments delivered through Office 365. This detection identifies emails with suspicious subject keywords (payment, invoice, urgent) combined with high-risk attachment types (ZIP, RAR, ISO, macro-enabled documents) originating from suspicious IP ranges.

False positive sources: Legitimate business emails with similar keywords and attachment types. Tuning: adjust IP-based suspicious_sender logic and subject keyword lists for your environment.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Phishing: Spearphishing Attachment |
| Technique ID | T1566.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |

## Splunk Detection Query

```spl
`o365` (sourcetype="o365:management:activity" OR sourcetype="ms:o365:management")
Operation IN ("MailItemsAccessed", "Send", "SendAs", "SendOnBehalf")
| search
    (Subject="*payment*" OR Subject="*invoice*" OR Subject="*urgent*" OR Subject="*document*" OR Subject="*proposal*")
    AND (AttachmentFileName="*.zip" OR AttachmentFileName="*.rar" OR AttachmentFileName="*.iso"
         OR AttachmentFileName="*.doc" OR AttachmentFileName="*.docm" OR AttachmentFileName="*.xls" OR AttachmentFileName="*.xlsm")
| eval suspicious_sender=if(match(ClientIP, "^(103\.|5\.|45\.|185\.)"), "yes", "no")
| where suspicious_sender="yes" OR (AttachmentFileName="*.iso" OR AttachmentFileName="*.rar")
| stats count by UserId, ClientIP, Subject, AttachmentFileName, Operation
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Suspicious source IP + weaponized attachment | High | IP ranges associated with DPRK infrastructure combined with common Lazarus attachment types |
| ISO or RAR attachment regardless of source | Medium | These container formats are commonly used to bypass Mark-of-the-Web protections |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |

## References

- [CISA - HIDDEN COBRA North Korean Malicious Cyber Activity](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-106a)
- [Microsoft - ZINC Weaponizing Open Source Software](https://www.microsoft.com/en-us/security/blog/2022/09/29/zinc-weaponizing-open-source-software/)
