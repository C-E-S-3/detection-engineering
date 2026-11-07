# SonicWall SSL-VPN SAML MFA Bypass (CVE-2026-19868)

## Description

Detects exploitation of CVE-2026-19868, an improper authentication enforcement flaw in SonicWall SonicOS SSLVPN. When SSL-VPN is configured to require SAML authentication (and therefore MFA), an attacker with valid credentials can bypass the SAML requirement by authenticating via an alternate method (local database, LDAP, or RADIUS). The VPN appliance fails to enforce the SAML-only policy, granting VPN access without a SAML assertion and without completing MFA.

This detection looks for successful SSL-VPN sessions where authentication did not involve SAML. False positives may occur when SAML is not enforced for all users or when service accounts use non-SAML auth. Tune by excluding known service account usernames and by confirming SAML is the required policy on the appliance.

**Affected builds:** SonicOS 7.3.3-7015 and older; SonicOS 8.2.2-8015 and older  
**Fixed builds:** SonicOS 7.3.4-7013+; SonicOS 8.2.3-8015+  
**CISA KEV Added:** 2026-11-07 (FCEB deadline 2026-11-20)

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion, Initial Access |
| Tactic ID | TA0005, TA0001 |
| Technique | Downgrade Attack; Valid Accounts |
| Technique ID | T1562.010; T1078 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
`sonicwall`
| rex field=_raw "usr=(?<user>[^\s]+)"
| rex field=_raw "src=(?<src_ip>[0-9\.]+)"
| rex field=_raw "proto=(?<auth_method>[^\s]+)"
| search ("SSL-VPN" OR "SSLVPN") ("login" OR "authenticated") ("success" OR "allow" OR "granted")
| where NOT (auth_method="saml" OR auth_method="SAML" OR isnull(auth_method))
| stats count min(_time) as firstTime max(_time) as lastTime values(src_ip) as src_ips by user auth_method
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    count >= 5, 85,
    count >= 1, 75)
| where risk_score >= 75
| table firstTime lastTime user src_ips auth_method count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| 1+ successful VPN auth without SAML | 75 | A single non-SAML success when SAML is required is immediately suspicious |
| 5+ successful VPN auth without SAML | 85 | Repeated non-SAML logins strongly indicates active exploitation or misconfiguration abuse |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (active exploitation per CISA KEV) | [CISA KEV — CVE-2026-19868](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| UNC5221 / ARMORY CASTLE (historical SonicWall targeting) | [Google TI — ARMORY CASTLE BeyondTrust](https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust) |

## References

- [SonicWall PSIRT Advisory SNWLID-2026-0014](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2026-0014)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CVE-2026-19868 Detail — VulnDB](https://vuldb.com/vuln/432101)
- [SonicWall fixes SSL-VPN MFA bypass flaw exploited in attacks](https://mezha.net/eng/news/mezha-4b98f9565dd1b9edb3866510_sonicwall_fixes_ssl-vpn)
