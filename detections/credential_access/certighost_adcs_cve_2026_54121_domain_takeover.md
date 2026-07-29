# Certighost — AD CS Certificate Template Abuse for Domain Takeover (CVE-2026-54121)

## Description

Detects exploitation of CVE-2026-54121 ("Certighost"), a high-severity (CVSS 8.8) Active Directory Certificate Services (AD CS) vulnerability that allows a low-privilege domain user to achieve full domain takeover by abusing certificate template enrollment. A public proof-of-concept was released on July 27, 2026, significantly accelerating risk of adoption by ransomware operators and red-team frameworks. The attack exploits a new code path in the AD CS enrollment engine (distinct from the ESC1-ESC8 class) to enroll a certificate for any domain account including Domain Admins, enabling PKINIT-based Kerberos TGT acquisition without the target's password.

Detection focuses on three key signals: (1) certificate template creation or modification events (Windows Event IDs 4899/4900); (2) anomalous certificate enrollment for privileged accounts (Event ID 4887); (3) PKINIT-based TGT requests (Event ID 4768, Pre-Auth Type 16) for accounts that normally authenticate via password.

**False positive sources:**
- Legitimate PKI administrators creating or modifying certificate templates — verify by confirming the acting user and template purpose against change control records
- Automated certificate enrollment for domain controllers and service accounts — baseline and filter known-good PKINIT requesters per environment
- Certipy/Certify legitimate red team engagements with prior authorization

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Steal or Forge Authentication Certificates |
| Technique ID | T1649 |
| Secondary Tactic | Privilege Escalation |
| Secondary Tactic ID | TA0004 |
| Secondary Technique | Valid Accounts: Domain Accounts |
| Secondary Technique ID | T1078.002 |
| Tertiary Tactic | Lateral Movement |
| Tertiary Tactic ID | TA0008 |
| Tertiary Technique | Use Alternate Authentication Material |
| Tertiary Technique ID | T1550.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Actions on Objectives |

## Splunk Detection Query

```spl
`wineventlog_security`
| search EventCode IN (4899,4900)
| eval flag_enrollee_supplies_subject=if(
    match(TemplateContent, "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT"), 1, 0)
| eval flag_no_security_extension=if(
    match(TemplateContent, "CT_FLAG_NO_SECURITY_EXTENSION"), 1, 0)
| eval risk_score=case(
    flag_enrollee_supplies_subject=1 AND flag_no_security_extension=1, 95,
    flag_enrollee_supplies_subject=1, 90,
    1=1, 75)
| where risk_score >= 75
| `security_content_ctime(_time)`
| table _time host user TemplateInternalName TemplateOID risk_score
```

```spl
`wineventlog_security`
| search EventCode=4887
| eval is_privileged_requester=if(
    match(lower(Subject), "domain admin|da |tier0|tier-0|-da@|-admin@|krbtgt|administrator"),
    1, 0)
| eval risk_score=case(
    is_privileged_requester=1, 90,
    1=1, 65)
| where risk_score >= 65
| `security_content_ctime(_time)`
| table _time host Requester Subject TemplateName SerialNumber risk_score
```

```spl
`wineventlog_security`
| search EventCode=4768 Pre_Authentication_Type=16
| eval risk_score=case(
    match(TargetUserName, "(?i)admin|krbtgt|svc-|service|tier0"), 90,
    1=1, 70)
| where risk_score >= 70
| `security_content_ctime(_time)`
| table _time host TargetUserName IpAddress CertThumbprint Pre_Authentication_Type risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Certificate template modified with `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + `CT_FLAG_NO_SECURITY_EXTENSION` (Event 4899/4900) | 95 | Combination is the ESC1/Certighost misconfiguration pattern; essentially confirms abuse attempt |
| Certificate template modified with `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` alone (Event 4899/4900) | 90 | Primary Certighost/ESC-family attack precondition; highly suspicious |
| Any certificate template creation/modification (Event 4899/4900) | 75 | Baseline alert; AD CS templates change infrequently; requires analyst review |
| Certificate enrollment for account matching privileged name patterns (Event 4887) | 90 | Certificate issued for a privileged account by a non-admin requester is strongly anomalous |
| PKINIT TGT (Pre-Auth Type 16) for privileged account (Event 4768) | 90 | Certificate-based Kerberos auth for admin accounts; confirm against expected service accounts |
| PKINIT TGT (Pre-Auth Type 16) for any account | 70 | Hunt query; correlate against enrollment events and requester identity |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (public PoC released 2026-07-27, no confirmed in-the-wild exploitation at time of writing) | [BleepingComputer — Certighost CVE-2026-54121](https://www.bleepingcomputer.com/news/security/certighost-poc-exploit-for-active-directory-certificate-services-domain-takeover-cve-2026-54121/), [NVD CVE-2026-54121](https://nvd.nist.gov/vuln/detail/CVE-2026-54121) |
| Ransomware operators (ESC-family precedent) | AD CS abuse (ESC1-ESC8) has been a standard ransomware pre-encryption step since 2022; Certighost represents an additional vector for groups already exploiting this attack surface |

## References

- [BleepingComputer — Certighost PoC Released (2026-07-27)](https://www.bleepingcomputer.com/news/security/certighost-poc-exploit-for-active-directory-certificate-services-domain-takeover-cve-2026-54121/)
- [NVD — CVE-2026-54121](https://nvd.nist.gov/vuln/detail/CVE-2026-54121)
- [MITRE ATT&CK — T1649 Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)
- [MITRE ATT&CK — T1550.001 Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/001/)
- [SpecterOps — Certified Pre-Owned (ESC1-ESC8 background)](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [Threat Intel Report — CVE-2026-54121 Certighost AD CS Domain Takeover](../../threat-intel/2026-07-29_bleepingcomputer-cve-2026-54121-certighost-adcs-domain-takeover.md)
