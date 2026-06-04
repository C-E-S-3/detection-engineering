---
scraped_at: 2026-06-04T06:00:00Z
source_url: https://www.ic3.gov/PSA/2026/PSA260521
report_type: threat-intel
severity: high
title: "Kali365 Phishing-as-a-Service: FBI Warning for Microsoft 365 Token Hijacking via Device Code Phishing and AiTM"
---

# Kali365 Phishing-as-a-Service: FBI Warning for Microsoft 365 Token Hijacking via Device Code Phishing and AiTM

## 1. IOCs

### Domains
| Indicator | Context |
|-----------|---------|
| kali365[.]xyz | Kali365 PhaaS operator portal and subscription management; Telegram-distributed criminal service sold at $250/month (Client tier) |

No campaign-specific redirect domains, AiTM proxy infrastructure IPs, or payload hashes have been publicly released as of June 4, 2026. Kali365 operators provision their own subdomains and proxy nodes, making campaign-level IOCs highly variable.

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Lure emails impersonating Adobe Acrobat Sign, DocuSign, and SharePoint containing links to attacker-controlled Microsoft 365-themed portals |
| Credential Access | Steal Application Access Token | T1528 | Device code flow abuse: attacker-initiated OAuth 2.0 `device_code` grant; victim authenticates on the legitimate `microsoft.com/devicelogin` endpoint while attacker polls for the resulting access and refresh tokens |
| Credential Access | MFA Interception | T1111 | AiTM component transparently proxies the victim's browser through attacker infrastructure; real-time session cookie and MFA token capture without requiring credential theft |
| Defense Evasion / Persistence | Use Alternate Authentication Material: Application Access Token | T1550.001 | Stolen OAuth refresh tokens are replayed from attacker-controlled infrastructure to access Microsoft 365 resources (Exchange, SharePoint, Teams) without MFA re-challenge |
| Collection | Email Collection | T1114 | Post-compromise: automated ingestion of victim mailboxes and SharePoint content using stolen tokens via Microsoft Graph API |

### Attack Flow — Device Code Variant
1. Attacker generates an OAuth device code via `https://login.microsoft.com/common/oauth2/v2.0/devicecode`.
2. Victim receives phishing email with a Microsoft-branded lure linking to the Kali365 AiTM landing page displaying the device code.
3. Victim visits the legitimate `microsoft.com/devicelogin`, enters the displayed code, and completes MFA normally.
4. Attacker's Kali365 panel silently acquires a valid access + refresh token pair.
5. Tokens are replayed from Alibaba Cloud or Cloudflare Workers infrastructure, bypassing conditional access policies tied to device compliance or location.

### Attack Flow — AiTM Variant
1. Phishing email contains a cookie-based link that routes victim's browser through Kali365 proxy infrastructure.
2. Victim's browser is transparently forwarded to a real Microsoft sign-in page; session cookies and MFA tokens are intercepted in real time.
3. Attacker's session is seeded with the stolen authenticated session, granting full M365 access.

## 3. Malware & Tools

Kali365 is a criminal subscription service, not traditional malware. Components:
- **Kali365 Admin Panel**: Web-based operator dashboard providing campaign management, real-time token status, victim tracking dashboards, and AI-generated lure templates.
- **AI Lure Engine**: Generates convincing phishing emails impersonating enterprise SaaS services (Adobe Sign, DocuSign, SharePoint, Microsoft Forms) tailored to target organizations.
- **AiTM Proxy Module**: Reverse proxy intercepting live authentication sessions; credential material captured in real time.
- **Device Code Module**: Automates OAuth 2.0 device authorization flow abuse; continuously polls Microsoft token endpoint.
- **Token Replay Automation**: Replays captured tokens from Cloudflare Workers or Alibaba Cloud (AS45102) infrastructure to evade location-based conditional access.

## 4. Threat Actor / Campaign Attribution

Kali365 is a criminal PhaaS marketplace first observed in April 2026, sold via Telegram at tiered pricing ($250/month Client, higher for Agent and Admin tiers granting reseller capabilities). The FBI issued Public Service Announcement IC3 PSA260521 on May 21, 2026. The service has been documented attacking organizations across manufacturing, education, government, insurance, financial services, and healthcare in North America and Europe.

Kali365 operates independently of the Tycoon2FA and EvilTokens PhaaS platforms — it represents a distinct criminal vendor ecosystem. Hundreds of attacks were documented by Arctic Wolf and Proofpoint in April 2026 alone.

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query="kali365.xyz" OR DNS.query="*.kali365.xyz"
by DNS.dest DNS.src DNS.query
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 90
| table firstTime lastTime dest src query risk_score
```

```spl
`o365` Operation="UserLoggedIn" AuthenticationDetails="*deviceCode*"
| stats count min(_time) as firstTime max(_time) as lastTime values(ClientIP) as src_ips by UserId UserAgent AppDisplayName
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    count >= 10, 80,
    mvcount(src_ips) >= 2, 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime UserId UserAgent AppDisplayName src_ips count risk_score
```

```spl
`o365` Operation="UserLoggedIn" ResultStatus="Success"
| eval src_asn=if(isnotnull(ClientIPASN), ClientIPASN, "unknown")
| search src_asn="AS45102" OR src_asn="AS13335"
| stats count min(_time) as firstTime max(_time) as lastTime values(ClientIP) as src_ips by UserId AppDisplayName src_asn
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(src_asn="AS45102", 75, 1=1, 60)
| where risk_score >= 60
| table firstTime lastTime UserId AppDisplayName src_ips src_asn count risk_score
```

## 6. Executive Summary

Kali365 is a new Phishing-as-a-Service (PhaaS) platform that emerged in April 2026 and was flagged by the FBI (IC3 PSA260521, May 21, 2026) as an active threat to Microsoft 365 environments. The platform offers two attack paths: an OAuth device code phishing module that captures M365 tokens without intercepting credentials, and an Adversary-in-the-Middle (AiTM) proxy module that steals live session cookies. Both paths bypass MFA because they capture post-authentication tokens or sessions rather than credentials.

Kali365 distinguishes itself through AI-generated lure emails, an operator dashboard with real-time campaign tracking, and a Cloudflare Workers / Alibaba Cloud (AS45102) infrastructure that complicates IP-based blocking. The primary IOC is the Kali365 operator domain `kali365[.]xyz`. Defenders should monitor for DNS resolution of kali365[.]xyz, OAuth device code flow successes from suspicious ASNs (AS45102, AS13335), and anomalous M365 sign-in activity reflecting token replay.

## References

- [FBI IC3 Public Service Announcement — Kali365 (PSA260521, 2026-05-21)](https://www.ic3.gov/PSA/2026/PSA260521)
- [The Register — FBI warns of Kali365 as device code phishing soars (2026-05-22)](https://www.theregister.com/cyber-crime/2026/05/22/fbi-warns-of-kali365-as-device-code-phishing-soars/5245024)
- [Security Boulevard — Kali365 PhaaS Technical Analysis (June 2026)](https://securityboulevard.com/2026/06/kali365-the-new-phishing-kit-hijacking-microsoft-365-tokens/)
- [Infosecurity Magazine — FBI Warns Kali365 Phishing Kit (2026-05-21)](https://www.infosecurity-magazine.com/news/fbi-kali365-phishing-kit-m365/)
- [MITRE ATT&CK — T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK — T1550.001: Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/001/)
