---
scraped_at: 2026-07-02T00:00:00Z
source_url: https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/
report_type: threat-intel
severity: high
title: "ARToken: EvilTokens Affiliate PhaaS Panel for Microsoft 365 Device Code Phishing"
---

# ARToken: EvilTokens Affiliate PhaaS Panel for Microsoft 365 Device Code Phishing

**Source:** Cisco Talos Intelligence  
**Published:** 2026-07-01  
**Severity:** High  

---

## Executive Summary

Cisco Talos documented ARToken, an affiliate panel operating under the EvilTokens Phishing-as-a-Service (PhaaS) ecosystem. ARToken automates OAuth 2.0 device authorization code phishing targeting Microsoft 365 tenants. Operators receive a full-featured web dashboard to generate device code lure URLs, track victim authentication events in real time, and collect access and refresh tokens without ever obtaining the victim's password. The device code flow abuses a legitimate Microsoft authentication endpoint (`microsoft.com/devicelogin`), meaning victims interact with authentic Microsoft UI while the attacker's panel silently harvests tokens. Captured tokens grant persistent M365 access, persisting beyond password changes unless refresh tokens are explicitly revoked. Cloudflare Workers subdomains are used to front lure infrastructure and evade static blocklists.

---

## IOCs

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `pamconj[.]com` | Domain | ARToken panel hosting domain |
| `dashboard-bl.pamconj[.]com` | Domain | ARToken operator dashboard |
| `spx.pamconj[.]com` | Domain | ARToken panel subservice |
| `clear90489058903-document[.]workers[.]dev` | Domain | Cloudflare Workers lure infrastructure |
| `reynoldsjace5[.]workers[.]dev` | Domain | Cloudflare Workers lure infrastructure |
| `917bedb0-554e-a8b9-79f1-docviewer.clear90489058903-document[.]workers[.]dev` | Domain | Document lure subdomain |
| `321a1392-939d-3bf5-4040-docviewer.clear90489058903-document[.]workers[.]dev` | Domain | Document lure subdomain |
| `98c4c82e-2d81-0837-e3d6-docviewer.clear90489058903-document[.]workers[.]dev` | Domain | Document lure subdomain |
| `112838d8-9a75-2e90-d63b-docviewer.clear90489058903-document[.]workers[.]dev` | Domain | Document lure subdomain |
| `aquaclaude-09494-9099403-docviewer.clear90489058903-document[.]workers[.]dev` | Domain | Document lure subdomain |
| `e5469cec-124a-c84f-abaa-docviewer.clear90489058903-document[.]workers[.]dev` | Domain | Document lure subdomain |
| `50a201fd-dd2d-cf72-5fa6-onedrive.clear90489058903-document[.]workers[.]dev` | Domain | OneDrive-themed lure subdomain |
| `50a201fd-dd2d-cf72-5fa6-adobe2.reynoldsjace5[.]workers[.]dev` | Domain | Adobe-themed lure subdomain |

### IP Addresses

| Indicator | Type | Context |
|-----------|------|---------|
| `172.67.214.35` | IPv4 | Cloudflare-fronted IP resolving ARToken infrastructure |

---

## TTPs

| MITRE Technique | ID | Description |
|-----------------|-----|-------------|
| Use Alternate Authentication Material: Web Session Cookie | T1550.001 | Captured OAuth tokens replayed to authenticate as victim |
| Steal Application Access Token | T1528 | Device code flow abused to steal M365 access and refresh tokens |
| Phishing: Spearphishing Link | T1566.002 | Lure URLs sent via email or messaging directing victims to device code flow |
| Resource Development: Acquire Infrastructure | T1583.001 | Cloudflare Workers used to front lure infrastructure |

---

## Malware & Tools

- **ARToken Panel** — Web-based PhaaS affiliate dashboard; generates device code lures, monitors victim auth in real time, delivers captured tokens to operators
- **EvilTokens PhaaS** — Broader platform under which ARToken operates; previously tracked as targeting Microsoft device code flows alongside Tycoon 2FA and Storm-237

---

## Threat Actor / Attribution

| Attribute | Detail |
|-----------|--------|
| Actor | EvilTokens PhaaS operators / ARToken affiliate operators |
| Motivation | Financial (credential and token monetization) |
| Target | Microsoft 365 tenants globally; enterprise users |
| Confidence | High (Talos direct panel analysis) |

---

## Splunk Detection Searches

No new dedicated detection warranted — existing `eviltokens_oauth_device_code_phishing.md` and `tycoon2fa_device_code_token_abuse.md` detections cover the device code OAuth flow. IOCs from this report (pamconj[.]com, reynoldsjace5[.]workers[.]dev, 172.67.214.35) should be added to threat intelligence lookups for block/alert enrichment.

```spl
`o365` Operation="UserLoggedIn" OR Operation="DeviceCodeAuthorizationRequest"
| eval src_ip=ClientIP
| lookup threat_intel_ips ip as src_ip OUTPUT threat_name
| where isnotnull(threat_name)
| table _time user src_ip threat_name Operation
```

---

## References

- [Cisco Talos — ARToken: Inside an EvilTokens Affiliate Panel (2026-07-01)](https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/)
- [Cisco-Talos IOCs GitHub — ARToken](https://github.com/Cisco-Talos/IOCs/blob/main/2026/07/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365.txt)
- [MITRE ATT&CK — T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK — T1550.001: Use Alternate Authentication Material: Web Session Cookie](https://attack.mitre.org/techniques/T1550/001/)
