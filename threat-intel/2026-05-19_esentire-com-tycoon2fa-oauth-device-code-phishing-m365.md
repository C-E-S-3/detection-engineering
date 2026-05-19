---
scraped_at: 2026-05-19T12:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/tycoon2fa-hijacks-microsoft-365-accounts-via-device-code-phishing/
additional_sources:
  - https://www.esentire.com/blog/tycoon-2fa-operators-adopt-oauth-device-code-phishing
  - https://github.com/eSentire/iocs/tree/main/Tycoon2FA
report_type: threat-intel
severity: high
title: "Tycoon 2FA PhaaS Resurges with OAuth Device Code Phishing Against Microsoft 365"
---

## 1. IOCs

### Domains — Device-Code Variant (late April / May 2026, eSentire TRU analysis)

| Indicator | Role |
|-----------|------|
| `fijothi[.]com` | Tycoon2FA PhaaS backend C2 / delivery endpoint |
| `shivacrio[.]com` | Tycoon2FA PhaaS delivery endpoint (path: `/bytecore~tx1j8`) |
| `cookies.28gholland.workers[.]dev` | Cloudflare Workers redirector in delivery chain |
| `events.trustifi[.]com` | Legitimate email platform abused; tracking URLs used as lure delivery vector |

### Domains — Tycoon2FA Pre-Takedown Infrastructure (March 2026, eSentire IOC file)

| Indicator | Role |
|-----------|------|
| `gremlin.craifishi[.]business` | Tycoon2FA PhaaS Check Domain / backend |
| `artist.yedrene[.]best` | Tycoon2FA PhaaS backend |
| `international.fesxtmc[.]com` | Tycoon2FA PhaaS backend |
| `stostiyai.sistaidru[.]com` | Tycoon2FA PhaaS backend |
| `spark.shoupeatai[.]com` | Tycoon2FA PhaaS backend |
| `asw.cretrousteafi[.]icu` | Tycoon2FA PhaaS backend |
| `cloud.shailoyio[.]com` | Tycoon2FA PhaaS backend |
| `capital.yljdimage[.]com` | Tycoon2FA PhaaS backend |
| `powershell.traibiru[.]world` | Tycoon2FA PhaaS backend |
| `support.traibiru[.]world` | Tycoon2FA PhaaS backend |
| `www.alnaharegypt[.]com` | Compromised legitimate site used as Tycoon2FA redirect relay |
| `pop3.kouvadre[.]ink` | Tycoon2FA PhaaS backend |
| `dao.civushea[.]sbs` | Tycoon2FA PhaaS backend |
| `donation.cewiobu[.]center` | Tycoon2FA PhaaS backend |
| `ionic.tehipio[.]ink` | Tycoon2FA PhaaS backend |
| `bay.rifoupoumeshoo[.]club` | Tycoon2FA PhaaS backend |
| `varnish.widoupoo[.]network` | Tycoon2FA PhaaS backend |
| `coat.jadubo[.]courses` | Tycoon2FA PhaaS backend |
| `college.petristifrouja[.]bar` | Tycoon2FA PhaaS backend |
| `chain.toushatou[.]beauty` | Tycoon2FA PhaaS backend |
| `cedar.cethaicro.co[.]za` | Tycoon2FA PhaaS backend |
| `dubai.vaikaza.sa[.]com` | Tycoon2FA PhaaS backend |
| `mosquito.dralilai[.]beauty` | Tycoon2FA PhaaS backend |
| `toad.yioso[.]beer` | Tycoon2FA PhaaS backend |
| `screen.thougai[.]beer` | Tycoon2FA PhaaS backend |
| `cruise.reafraiyousteaga[.]qpon` | Tycoon2FA PhaaS backend |
| `w0re.stadrourea[.]ru` | Tycoon2FA PhaaS backend |
| `colombia.shoomoweajai[.]cyou` | Tycoon2FA PhaaS backend |
| `leopard.teashaboulouve[.]qpon` | Tycoon2FA PhaaS backend |
| `chair.shustoufraithookea[.]qpon` | Tycoon2FA PhaaS backend |
| `melon.teashaboulouve[.]qpon` | Tycoon2FA PhaaS backend |
| `shirt.roowothonio[.]cyou` | Tycoon2FA PhaaS backend |
| `storm.thobewoofricrou[.]qpon` | Tycoon2FA PhaaS backend |
| `as65cj.crimiwa.sa[.]com` | Tycoon2FA PhaaS backend |
| `tajikistan.noyaidetipio[.]qpon` | Tycoon2FA PhaaS backend |
| `oil.tracroo.it[.]com` | Tycoon2FA PhaaS backend |
| `chart.nigafo[.]download` | Tycoon2FA PhaaS backend |
| `e.goowevea[.]digital` | Tycoon2FA PhaaS backend |

### IP Addresses — Device-Code Variant (eSentire TRU analysis, April/May 2026)

| Indicator | Role |
|-----------|------|
| `47.90.180.205` | Alibaba Cloud AS45102 — operator-side token acquisition phase |
| `47.252.11.99` | Alibaba Cloud AS45102 — sustained refresh-token reuse phase |

### IP Addresses — Pre-Takedown Infrastructure (eSentire March 2026 IOC file)

| Indicator | Role |
|-----------|------|
| `193.228.131.161` | Tycoon2FA PhaaS operator infrastructure |
| `166.1.241.247` | Tycoon2FA PhaaS operator infrastructure |
| `138.249.139.6` | Tycoon2FA PhaaS operator infrastructure |
| `166.1.255.233` | Tycoon2FA PhaaS operator infrastructure |
| `142.252.86.104` | Tycoon2FA PhaaS operator infrastructure |
| `130.49.117.205` | Tycoon2FA PhaaS operator infrastructure |
| `170.168.215.64` | Tycoon2FA PhaaS operator infrastructure |
| `50.118.198.26` | Tycoon2FA PhaaS operator infrastructure |
| `172.120.234.223` | Tycoon2FA PhaaS operator infrastructure |
| `45.39.175.12` | Tycoon2FA PhaaS operator infrastructure |
| `142.252.171.135` | Tycoon2FA PhaaS operator infrastructure |
| `166.88.219.45` | Tycoon2FA PhaaS operator infrastructure |
| `172.120.57.92` | Tycoon2FA PhaaS operator infrastructure |
| `172.121.59.99` | Tycoon2FA PhaaS operator infrastructure |

### Behavioral Indicators

| Indicator | Type | Significance |
|-----------|------|--------------|
| `node` / `undici` user-agent strings | HTTP User-Agent | Post-compromise automation signature — Tycoon2FA operators use Node.js tooling to reuse stolen tokens against Microsoft services |
| `AS45102` (Alibaba US Technology Co., Ltd.) | ASN | Operator-side hosting ASN active since ~April 10, 2026; rotate to this ASN post-takedown |
| Entra sign-in via `deviceCode` authenticationProtocol | Azure AD Audit | Indicates OAuth device code grant completion; attacker-controlled device authorized |

---

## 2. TTPs

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Invoice-themed emails containing Trustifi click-tracking URLs redirect victims through a four-layer delivery chain to a fake Microsoft CAPTCHA page |
| Credential Access | T1528 | Steal Application Access Token | Device code phishing harvests OAuth device code from attacker backend, victim completes MFA on `microsoft.com/devicelogin`, attacker receives access + refresh tokens |
| Defense Evasion | T1550.001 | Use Alternate Authentication Material: Application Access Token | Stolen refresh tokens reused from Alibaba Cloud IPs (AS45102) to maintain persistent access without re-authenticating |
| Resource Development | T1583.001 | Acquire Infrastructure: Domains | DGA-style backend Check Domains registered under exotic TLDs (.qpon, .beauty, .beer, .sbs, etc.) |
| Resource Development | T1583.004 | Acquire Infrastructure: Server | Alibaba Cloud infrastructure (AS45102) used post-takedown; Cloudflare Workers abused for redirectors |

---

## 3. Malware & Tools

**Tycoon 2FA PhaaS Kit**
- JavaScript-based adversary-in-the-middle (AiTM) phishing kit sold as Phishing-as-a-Service
- Operator codebase backed up before March 2026 coalition takedown; resumed unchanged
- Key technical characteristics:
  - AES-GCM encryption for backend communications
  - Anti-debug timing trap in Check Domain verification
  - Four-layer in-browser JavaScript delivery chain
  - Same backend route patterns and AES key as 2025 version
- Delivery vector updated to abuse Trustifi email click-tracking URLs as obfuscated lure links
- Now uses OAuth 2.0 Device Authorization Grant (device code flow) instead of credential-relay to harvest tokens
- Post-compromise: Node.js automation tools (user-agent: `node`, `undici`) used to replay stolen tokens against Microsoft Graph / M365 APIs

---

## 4. Threat Actor / Campaign Attribution

**Tycoon 2FA Operators**
- PhaaS platform with an established operator history since at least 2024
- Coalition takedown in March 2026 (Microsoft + Europol + law enforcement) disrupted infrastructure but did not disrupt the actors
- Operators retained full kit codebase, resumed operations within weeks with enhanced evasion (device code flow vs. credential-relay)
- Infrastructure shifted to Alibaba Cloud (AS45102) after previous hosting providers faced takedown pressure
- No public attribution to named threat group; sold as a service to multiple buyers

**Assessed Buyers / Linked Campaigns**
- Multiple cybercriminal actors purchase access; eSentire observed the device-code variant in late April 2026

---

## 5. Splunk Detection Searches

```spl
`azure_monitor_aad`
| search operationName="Sign-in activity"
| eval user_agent=coalesce(userAgent, 'deviceDetail.browser')
| where match(user_agent, "(?i)(^|\\s)node[/\\s]|undici")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(ipAddress) as src_ips
    values(user_agent) as user_agents
    dc(ipAddress) as unique_ips
    by userPrincipalName, appDisplayName, authenticationProtocol
| eval risk_score=case(
    match(user_agents, "(?i)undici") AND authenticationProtocol="deviceCode", 90,
    match(user_agents, "(?i)undici"), 85,
    match(user_agents, "(?i)node") AND authenticationProtocol="deviceCode", 88,
    match(user_agents, "(?i)node"), 75,
    1=1, 65)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime userPrincipalName appDisplayName authenticationProtocol src_ips user_agents unique_ips risk_score
```

```spl
`azure_monitor_aad`
| search operationName="Sign-in activity" authenticationProtocol="deviceCode"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(ipAddress) as src_ips
    dc(ipAddress) as unique_ips
    by userPrincipalName, appDisplayName, conditionalAccessStatus
| where (
    match(src_ips, "47\\.90\\.180\\.205|47\\.252\\.11\\.99")
    OR unique_ips > 3
    OR conditionalAccessStatus="failure"
)
| eval risk_score=case(
    match(src_ips, "47\\.90\\.180\\.205|47\\.252\\.11\\.99"), 95,
    unique_ips > 5 AND conditionalAccessStatus="failure", 88,
    conditionalAccessStatus="failure", 80,
    unique_ips > 3, 72,
    1=1, 65)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime userPrincipalName appDisplayName conditionalAccessStatus src_ips unique_ips risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url="*trustifi*" AND (Web.url="*/api/o/v1/click*" OR Web.url="*workers.dev*")
  by Web.src Web.dest Web.url Web.http_user_agent Web.http_referrer
| `drop_dm_object_name(Web)`
| eval risk_score=case(
    match(url, "workers\\.dev") AND match(http_referrer, "trustifi"), 80,
    match(url, "trustifi") AND match(url, "click"), 65,
    1=1, 55)
| where risk_score >= 55
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest url http_user_agent http_referrer risk_score
```

---

## 6. Executive Summary

The Tycoon 2FA Phishing-as-a-Service platform, which was the target of a coalition law enforcement takedown led by Microsoft and Europol in March 2026, has resumed operations without meaningful disruption. Operators backed up the kit codebase before the takedown and relaunched within weeks, shifting their infrastructure to Alibaba Cloud (ASN 45102) to avoid the blocking that ended their previous hosting relationships.

The critical operational change is the switch from credential-relay adversary-in-the-middle to **OAuth 2.0 Device Authorization Grant phishing** (device code phishing). Rather than capturing credentials via a fake login page, the new kit:
1. Sends invoice-themed emails with Trustifi email platform click-tracking URLs, which obfuscate the true redirect destination.
2. Routes the victim through Cloudflare Workers and multiple obfuscated JavaScript layers to a fake Microsoft CAPTCHA page.
3. Presents the victim with a Microsoft OAuth device code retrieved from the attacker's backend.
4. Instructs the victim to authorize the code at the legitimate `microsoft.com/devicelogin`, completing MFA themselves.
5. The attacker's backend receives valid access and refresh tokens — never touching credentials.

Post-compromise, operators use Node.js automation tools (`user-agent: node` or `undici`) to silently replay stolen tokens against Microsoft Graph and M365 services. This automation signature is the most reliable behavioral indicator for detection teams, as it is visible in Entra ID sign-in logs and appears against the Microsoft Authentication Broker AppId.

All defenders using Microsoft 365 should review Conditional Access policies to restrict device code flow approvals and alert on `node`/`undici` user-agents in Entra sign-in logs.
