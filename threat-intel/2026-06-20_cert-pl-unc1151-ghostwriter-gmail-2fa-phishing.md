---
scraped_at: 2026-06-20T00:00:00Z
source_url: https://cert.pl/en/posts/2026/06/UNC1151-gmail-campaign/
report_type: threat-intel
severity: high
title: "UNC1151 (Ghostwriter) Gmail AiTM Phishing: 2FA Credential Theft via Fake Google Admin Panels (June 2026)"
---

## 1. IOCs

### Phishing Domains (Examples from CERT Polska Report)

| Indicator | Type | Context |
|-----------|------|---------|
| `mailverify[.]digital` | Phishing domain | Attacker-registered domain; fake Gmail admin verification portal; `.digital` TLD pattern |
| `verify-check[.]digital` | Phishing domain | Attacker-registered domain; fake account verification portal; `.digital` TLD pattern |

### Infrastructure Patterns (Not Exhaustive)

- **TLDs used:** `.digital`, `.icu`, `.top` — high-rotation, low-cost TLDs favored for rapid domain cycling
- **Hosting abuse:** `*.netlify.app` subdomains used for hosting phishing kits on legitimate infrastructure
- **Rotation:** New phishing domains registered almost daily during active campaign phases
- **Targeting pattern:** Subdomains of the form `<service>-verify[.]<tld>`, `<service>check[.]<tld>`, `mailverify[.]<tld>`

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Targeted phishing emails impersonating Gmail administrator security notifications |
| Credential Access | T1539 | Steal Web Session Cookie | AiTM proxy captures session cookies after credential/2FA submission |
| Credential Access | T1556.006 | Modify Authentication Process: Multi-Factor Authentication | Real-time 2FA interception: victim submits OTP to attacker-controlled proxy, which relays it to Google before it expires |
| Defense Evasion | T1036 | Masquerading | Phishing pages impersonate official Google/Gmail administrator interfaces |
| Defense Evasion | T1583.001 | Acquire Infrastructure: Domains | Daily registration of new phishing domains under `.digital`/`.icu`/`.top` TLDs to evade blocklists |
| Defense Evasion | T1608.005 | Stage Capabilities: Link Target | Netlify platform hosting of phishing kit to abuse legitimate CDN infrastructure and TLS certificates |
| Collection | T1056.003 | Input Capture: Web Portal Capture | Fake login portal captures Gmail address, password, and 2FA code in sequence |
| Persistence | T1078 | Valid Accounts | Compromised Gmail accounts used for further spearphishing and account takeover |
| Reconnaissance | T1589.002 | Gather Victim Identity Information: Email Addresses | Target selection focused on political figures, journalists, government employees, researchers |

---

## 3. Malware & Tools

No custom malware deployed. UNC1151 / Ghostwriter operates a lightweight adversary-in-the-middle (AiTM) phishing infrastructure:

**Phishing Kit:** Custom HTML/CSS phishing pages that faithfully replicate Google/Gmail administrator security notification interfaces. The pages present in sequence: (1) email address entry, (2) password entry, (3) 2FA code entry (presenting urgency-themed message claiming OTP has been sent). The 2FA code form is the key AiTM component — credentials are submitted to the attacker's server, which immediately relays them to Google's real authentication endpoint before the TOTP/SMS code expires, allowing full account takeover even with MFA enabled.

**Hosting Infrastructure:** Mix of attacker-registered domains (`.digital`, `.icu`, `.top`) and Netlify subdomains. Domains cycle rapidly (new domains registered near-daily). Some attacker-registered redirectors point to Netlify-hosted phishing pages.

---

## 4. Threat Actor / Campaign Attribution

**UNC1151 / Ghostwriter** — Belarus-linked threat group (MITRE G0084) assessed to conduct cyber espionage and information operations in support of Belarusian and Russian government interests. Primary targets are Baltic states, Poland, Ukraine, and other NATO-adjacent countries. Ghostwriter operations combine technical intrusions with influence operations (narrative planting in hacked news sites, fake social media personas).

**2026 Gmail campaign details:**
- **Campaign start:** March 2026 (escalation observed through June 2026)
- **Primary targets:** Politicians, public officials, military personnel, journalists, researchers, law enforcement, NGO staff in Poland, Baltic states, Ukraine
- **Vector:** Urgency-themed email lures (suspicious login alerts, account violation notices, deletion threats)
- **Objective:** Account takeover for intelligence collection and potential access to communications for influence operation content

**Related May 2026 activity:** Ghostwriter deployed Prometheus phishing malware targeting Ukrainian government entities (separate campaign, different TTP set).

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.dest IN ("mailverify.digital","verify-check.digital")
   OR (Web.url_domain LIKE "%.digital" AND (Web.url LIKE "%verify%" OR Web.url LIKE "%gmail%" OR Web.url LIKE "%google%"))
   OR (Web.url_domain LIKE "%.netlify.app" AND (Web.url LIKE "%verify%" OR Web.url LIKE "%gmail%" OR Web.url LIKE "%account%"))
by Web.src Web.dest Web.url Web.http_user_agent Web.user
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime src dest url http_user_agent user risk_score
```

```spl
index=* sourcetype IN ("o365:management:activity","gsuite:reports:admin")
(action="UserLoggedIn" OR action="SuspiciousSigninActivity")
| eval source_ip=mvindex(ClientIP,0)
| iplocation source_ip
| where Country!="United States" AND Country!=""
| stats count min(_time) as firstTime max(_time) as lastTime values(Country) as countries by user source_ip action
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=65
| table firstTime lastTime user source_ip action countries count risk_score
```

```spl
index=* sourcetype="gsuite:reports:token"
(event_name="authorize" OR event_name="revoke")
| where change_type="authorize"
| eval app_name=mvindex(client_id,0)
| stats count min(_time) as firstTime max(_time) as lastTime values(app_name) as authorized_apps by actor_email ip_address
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=55
| table firstTime lastTime actor_email ip_address authorized_apps count risk_score
```

---

## 6. Executive Summary

CERT Polska published analysis in June 2026 of a sustained UNC1151 (Ghostwriter) campaign targeting Gmail users with adversary-in-the-middle (AiTM) phishing since March 2026. The campaign impersonates Google/Gmail administrator security notifications to pressure victims into visiting attacker-controlled phishing portals that capture both passwords and time-based 2FA codes in real time.

Unlike traditional credential phishing, the AiTM architecture allows the attacker's server to relay the 2FA code to Google's real authentication endpoint before the code expires — defeating SMS-based and TOTP-based MFA. The attacker captures session cookies, achieving persistent account access even after the phishing event.

The campaign primarily targets Polish, Baltic, and Ukrainian politicians, military personnel, journalists, and government employees. Ghostwriter combines these technical intrusions with information operations: compromised accounts are used to harvest intelligence and to plant disinformation content consistent with Belarusian/Russian narratives.

**Immediate actions:** Enforce hardware security key (FIDO2/passkey) MFA for high-value accounts — AiTM attacks cannot intercept hardware key authentication. Enable anomalous sign-in alerts. Block `mailverify[.]digital` and `verify-check[.]digital` at web proxies. Monitor for suspicious OAuth app authorizations post-login.
