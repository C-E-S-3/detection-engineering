# BigBear 2.0 Adversary-in-the-Middle (AiTM) Microsoft 365 MFA Bypass via Evilginx2

## Description

Detects adversary-in-the-middle (AiTM) phishing attacks targeting Microsoft 365 authentication using Evilginx2-based phishing proxies, as observed in the BigBear 2.0 phishing-as-a-service (PhaaS) campaign disclosed by CloudSEK in September 2026.

In AiTM phishing, a reverse proxy (Evilginx2) sits between the victim and Microsoft's legitimate login service. The victim completes MFA normally — the proxy captures the resulting authenticated session cookie and forwards it to the operator for replay. BigBear 2.0 additionally injects JavaScript that disables FIDO2/WebAuthn on the phishing page, forcing victims toward interceptable MFA methods (TOTP, SMS).

Detections target: (1) successful M365 logins from known BigBear 2.0 infrastructure, (2) successful logins from VPS/datacenter ASNs uncommonly seen in enterprise M365 authentication, (3) impossible-travel patterns created by residential proxy geo-evasion, and (4) Evilginx2 HTTP header artifacts.

False positives: VPN users may trigger ASN-based rules; tune by adding known corporate VPN ASNs to an allowlist. Impossible travel rules may fire for mobile users traveling internationally; correlate with HR systems where possible.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Phishing: Spearphishing Link |
| Technique ID | T1566.002 |

Secondary techniques: T1111 (MFA Interception), T1539 (Steal Web Session Cookie), T1090.003 (Multi-hop Proxy).

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.app IN ("Office 365","Microsoft 365")
    AND Authentication.action="success"
  by Authentication.src Authentication.user Authentication.dest
     Authentication.user_agent Authentication.country
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| lookup asn_lookup ip AS src OUTPUT autonomous_system_number autonomous_system_org
| eval is_bigbear_ip=if(src IN ("130.94.82.180","38.54.124.58"), "true", "false")
| eval is_vultr=if(autonomous_system_org LIKE "*Constant Company*"
    OR autonomous_system_org LIKE "*Vultr*" OR autonomous_system_number="AS20473", "true", "false")
| eval risk_score=case(
    is_bigbear_ip="true", 95,
    is_vultr="true", 80,
    1=1, 0)
| where risk_score > 0
| table firstTime lastTime user src autonomous_system_org country dest user_agent
        is_bigbear_ip is_vultr risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Login from confirmed BigBear 2.0 VPS IP (130.94.82.180 or 38.54.124.58) | 95 | Critical — direct IOC match; session cookie replay from confirmed AiTM infrastructure |
| Login from Vultr (The Constant Company LLC, AS20473) | 80 | High — all 42 BigBear 2.0 VPS nodes hosted on Vultr; unusual for enterprise M365 logins |
| Login from 3+ countries in 24-hour window (per supplemental query below) | 90 | Critical — AiTM residential proxy evasion creates multi-country impossible travel |
| Evilginx2 headers detected in O365 audit log | 95 | Critical — proxy fingerprint confirms AiTM infrastructure involvement |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| BigBear 2.0 / "General Boss" (PhaaS operator) | [CloudSEK Report (September 2026)](https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign) |
| UNC6671 / BLING SAMBA (Pink; M365 vishing + AiTM) | [MITRE ATT&CK](https://attack.mitre.org/), [Google GTIG July 2026](https://cloud.google.com/blog/topics/threat-intelligence/) |
| Scattered Spider / Octo Tempest (AiTM phishing operators) | [MITRE ATT&CK G1015](https://attack.mitre.org/groups/G1015/) |
| Storm-2372 (device code phishing; related AiTM variant) | [Microsoft Threat Intelligence February 2026](https://www.microsoft.com/en-us/security/blog/) |

## References

- [CloudSEK — Tracking BigBear 2.0 Evilginx2 Phishing Campaign](https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign)
- [BleepingComputer — BigBear Microsoft 365 phishing service bypassed MFA at 258 organizations](https://www.bleepingcomputer.com/news/security/bigbear-microsoft-365-phishing-service-bypassed-mfa-at-258-organizations/)
- [Microsoft — Protect against adversary-in-the-middle phishing](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation)
- [MITRE ATT&CK — T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK — T1111 MFA Interception](https://attack.mitre.org/techniques/T1111/)
- [MITRE ATT&CK — T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [Evilginx2 GitHub](https://github.com/kgretzky/evilginx2)
