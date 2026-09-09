---
scraped_at: "2026-09-09T12:00:00Z"
source_url: "https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign"
report_type: threat-intel
severity: high
title: "BigBear 2.0 — Evilginx2-Based M365 AiTM Phishing-as-a-Service Bypasses MFA at 258 Organizations"
---

## 1. IOCs

### Phishing Infrastructure — IP Addresses (Vultr/The Constant Company LLC)

| Indicator | Type | Context |
|-----------|------|---------|
| `130[.]94[.]82[.]180` | IPv4 | BigBear 2.0 VPS node; Vultr (The Constant Company LLC); Evilginx2 phishing proxy; Microsoft 365 AiTM proxy |
| `38[.]54[.]124[.]58` | IPv4 | BigBear 2.0 VPS node; Vultr (The Constant Company LLC); Evilginx2 phishing proxy; residential proxy relay point |

### Phishing Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `konceptenterprises[.]com` | Domain | BigBear 2.0 phishing domain; Evilginx2 lure; impersonates Microsoft 365 login portal |
| `annastudios-paros[.]com` | Domain | BigBear 2.0 phishing domain; Evilginx2 lure; geo-matched residential proxy exit node correlated |

### Evilginx2 Session / Cookie Artifacts

| Artifact | Type | Context |
|----------|------|---------|
| `evginx_session` | Cookie name | BigBear 2.0 session tracking cookie set by Evilginx2 proxy on victim browser |
| `bigbear_session` | Cookie name | BigBear 2.0 affiliate session tracking cookie |
| `evginx_admin` | Cookie name | BigBear 2.0 admin panel session cookie |
| `x-evg-token` | HTTP Header | Evilginx2 internal proxy routing header present in captured session traffic |
| `x-evg-server` | HTTP Header | Evilginx2 server identification header |
| `x-evg-session` | HTTP Header | Evilginx2 session correlation header |

### Telegram C2 Bots

| Indicator | Type | Context |
|----------|------|---------|
| `@comeandget_bot` | Telegram Bot | BigBear 2.0 real-time credential exfiltration bot; sends stolen session cookies and plaintext passwords |
| `@botterxyz_bot` | Telegram Bot | BigBear 2.0 affiliate C2 bot; distributes phishing URLs to affiliates |

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|-------------|-------------|----------------|-------|
| Initial Access | T1566.002 | Spearphishing Link | Victims receive phishing emails with BigBear 2.0 infrastructure URLs targeting Microsoft 365 login |
| Initial Access | T1111 | MFA Interception | Evilginx2 AiTM proxy intercepts the authenticated session cookie after victim completes MFA, bypassing MFA entirely |
| Credential Access | T1539 | Steal Web Session Cookie | Captured Microsoft 365 session cookies replayed by attacker to access victim M365 tenant without triggering MFA |
| Credential Access | T1056.003 | Input Capture: Web Portal Capture | Evilginx2 captures plaintext passwords as they transit the proxy before encryption |
| Defense Evasion | T1090.003 | Proxy: Multi-hop Proxy | Geo-matched residential proxies in 69 countries routed through BigBear 2.0 infrastructure; makes stolen sessions appear to originate from victim's geographic location |
| Defense Evasion | T1562.010 | Impair Defenses: Downgrade Attack | Custom JavaScript on phishing pages disables FIDO2/WebAuthn functionality, forcing victims toward interceptable MFA methods (TOTP, SMS) rather than hardware security keys |
| Exfiltration | T1567 | Exfiltration Over Web Service | Stolen credentials and session cookies exfiltrated in real-time via Telegram bot API |

### Attack Chain

1. **Delivery**: Victim receives phishing email with BigBear 2.0 phishing URL. URL resolves to Evilginx2 proxy configured with the "offy" phishlet (M365-specific).
2. **Proxy Interception**: Evilginx2 acts as adversary-in-the-middle between victim browser and legitimate Microsoft login. Victim sees an authentic Microsoft 365 login page (proxied in real-time).
3. **FIDO2 Downgrade**: Custom JavaScript injected by the proxy disables WebAuthn/FIDO2 capabilities on the page, preventing hardware security key authentication. Victim is forced to use TOTP or SMS MFA.
4. **MFA Bypass**: Victim completes MFA normally. The resulting authenticated session cookie is captured by the Evilginx2 proxy before it reaches the victim browser.
5. **Exfiltration**: Stolen session cookie and plaintext password (if captured) are forwarded in real-time to the operator via Telegram bot.
6. **Replay**: Operator replays the authenticated session cookie from a geo-matched residential proxy IP (matching victim's country/region) to access victim's M365 tenant, bypassing Conditional Access location policies.

## 3. Malware & Tools

| Tool | Description |
|------|-------------|
| **Evilginx2** | Open-source adversary-in-the-middle phishing framework by Kuba Gretzky; BigBear 2.0 uses a customized build with the "offy" phishlet targeting Microsoft 365 |
| **BigBear 2.0 Admin Panel** | Multi-user PhaaS control panel; manages 42 VPS nodes, affiliate operators, and captured credential/session logs; self-describes as supporting 5+ affiliate operators |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| **Operator Alias** | "General Boss" (operator/developer identity) |
| **Attribution Type** | Cybercriminal / PhaaS operator; no state-nexus confirmed |
| **Discovery** | CloudSEK TRIAD team; June 2026; gained access to BigBear 2.0 admin panel |
| **Active Since** | June 2026; phishing infrastructure operational |
| **Scale** | 258 organizations with confirmed MFA bypasses; 461 targeted organizations; 40+ countries; 5,137 credential records; 5 identified affiliate operators |
| **Infrastructure** | 42 VPS nodes (Vultr / The Constant Company LLC); residential proxy pool spanning 69 countries; ~26 nodes deleted post-CloudSEK discovery (counter-forensic activity) |
| **Targeting** | Microsoft 365 exclusively; broad targeting across industries and geographies |

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.app="Office 365" OR Authentication.app="Microsoft 365"
    AND Authentication.action="success"
  by Authentication.src Authentication.user Authentication.dest
     Authentication.user_agent Authentication.country Authentication.city
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| lookup asn_lookup ip AS src OUTPUT asn autonomous_system_org
| search autonomous_system_org IN ("AS20473*","Constant Company*","Vultr*","The Constant Company*")
| eval risk_score=case(
    autonomous_system_org LIKE "*Constant Company*" OR autonomous_system_org LIKE "*Vultr*", 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime user src autonomous_system_org country city dest user_agent risk_score
```
**Detects:** Successful M365 authentication from Vultr-hosted IPs (The Constant Company LLC, AS20473) — the confirmed hosting provider for all 42 BigBear 2.0 VPS nodes. Vultr logins are rare in most enterprise environments and warrant investigation.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.app IN ("Office 365","Microsoft 365")
    AND Authentication.action="success"
  by Authentication.user Authentication.src Authentication.country
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats dc(country) as country_count values(country) as countries values(src) as src_ips
        min(firstTime) as firstTime max(lastTime) as lastTime by user
| where country_count > 2
| eval risk_score=case(country_count >= 4, 90, country_count == 3, 75, 1=1, 60)
| where risk_score >= 60
| table firstTime lastTime user country_count countries src_ips risk_score
```
**Detects:** M365 authentication from 3+ countries in a single session window — AiTM residential proxy evasion creates impossible-travel patterns where the phishing server country differs from the replay country differs from the victim's home country.

```spl
index=o365 sourcetype="o365:management:activity"
  (Workload="AzureActiveDirectory" OR Workload="Exchange")
  Operation IN ("UserLoggedIn","MailboxLogin","Add service principal","Consent to application")
| rex field=_raw "\"x-evg-token\":\"(?<evg_token>[^\"]+)\""
| rex field=_raw "\"x-evg-server\":\"(?<evg_server>[^\"]+)\""
| search (evg_token=* OR evg_server=*)
| eval risk_score=95
| table _time UserId ClientIP user_agent Operation evg_token evg_server risk_score
```
**Detects:** Evilginx2-specific HTTP headers (`x-evg-token`, `x-evg-server`) passed through to O365 audit logs — present when the proxy does not strip its own routing headers before forwarding to Microsoft's backend.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.app IN ("Office 365","Microsoft 365")
    AND Authentication.action="success"
    AND (Authentication.src="130.94.82.180" OR Authentication.src="38.54.124.58")
  by Authentication.user Authentication.src Authentication.dest
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime user src dest risk_score
```
**Detects:** M365 authentication from confirmed BigBear 2.0 VPS IPs (130.94.82.180 and 38.54.124.58); direct IOC match.

## 6. Executive Summary

BigBear 2.0 is a phishing-as-a-service (PhaaS) framework built on Evilginx2 — an open-source adversary-in-the-middle (AiTM) proxy — and operated by a threat actor using the alias "General Boss." Publicly disclosed by CloudSEK on September 7–8, 2026 after researchers gained access to the operator's admin panel, the campaign has been active since June 2026 and has affected 258 organizations across 40+ countries, capturing 5,137 credential records including 474 fully MFA-bypassed authenticated sessions and 1,032 plaintext passwords.

BigBear 2.0 bypasses MFA by acting as a real-time proxy between the victim and Microsoft's legitimate login portal. Because the victim completes the MFA challenge normally, Microsoft issues a valid session cookie — which the Evilginx2 proxy intercepts before it reaches the victim's browser. The attacker can then replay the session cookie from any device. To defeat location-based Conditional Access policies, BigBear 2.0 routes replayed sessions through geo-matched residential proxies in 69 countries.

A particularly novel evasion technique: custom JavaScript injected into phishing pages disables FIDO2/WebAuthn (hardware security key) authentication, forcing victims toward TOTP or SMS MFA — methods that the AiTM proxy can intercept. Organizations using hardware security keys (FIDO2-bound credentials) as their sole MFA factor would NOT be susceptible to this campaign; any organization still relying on TOTP/SMS as MFA fallback remains at risk even with hardware keys deployed.

**Recommended mitigations:**
1. Require FIDO2/WebAuthn (hardware security keys or passkeys) as the **only** MFA method for sensitive M365 accounts — disable TOTP/SMS fallback
2. Enable Continuous Access Evaluation (CAE) in Entra ID to invalidate session tokens on policy change
3. Deploy Microsoft Defender for Identity sign-in risk policies blocking logins from Vultr/residential proxy ASNs
4. Alert on successful M365 logins from Vultr (AS20473) infrastructure

## References

- [CloudSEK — Tracking BigBear 2.0 Evilginx2 Phishing Campaign](https://www.cloudsek.com/blog/tracking-bigbear-2-0-evilginx2-phishing-campaign)
- [BleepingComputer — BigBear Microsoft 365 phishing service bypassed MFA at 258 organizations](https://www.bleepingcomputer.com/news/security/bigbear-microsoft-365-phishing-service-bypassed-mfa-at-258-organizations/)
- [CyberSecurityNews — BigBear 2.0 Evilginx2 Phishing Campaign](https://cybersecuritynews.com/bigbear-2-0-evilginx2/)
- [MITRE ATT&CK — T1111 MFA Interception](https://attack.mitre.org/techniques/T1111/)
- [MITRE ATT&CK — T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK — T1090.003 Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/)
- [Evilginx2 Project](https://github.com/kgretzky/evilginx2)
