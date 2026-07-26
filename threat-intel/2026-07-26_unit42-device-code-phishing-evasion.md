---
title: "Device Code Phishing Evasion Techniques — CAPTCHA Gates, Blob URL AES-GCM Delivery, Cyrillic Substitution, Zero-Width Chars"
source: https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-07-23-Device-code-phishing-evasion-techniques.txt
source_display: "Palo Alto Networks Unit 42 — Timely Threat Intel (July 23, 2026)"
date_published: 2026-07-23
date_added: 2026-07-26
tags:
  - device-code-phishing
  - oauth
  - aitm
  - evasion
  - captcha
  - blob-url
  - cyrillic-substitution
  - zero-width-chars
  - t1111
  - t1566.002
  - t1027
  - credential_access
  - initial_access
actors:
  - Unknown (multiple device-code phishing operators)
ioc_types:
  - domain
  - hash
mitre_techniques:
  - T1111
  - T1566.002
  - T1027
---

## Executive Summary

Palo Alto Networks Unit 42 documented four novel evasion techniques in active use by device-code phishing operators targeting Microsoft 365 and Azure environments. Device-code phishing abuses the OAuth 2.0 device authorization grant flow: victims are sent a code and URL (e.g., `microsoft.com/devicelogin`), authenticate on the legitimate Microsoft portal, and the attacker's registered application receives long-lived tokens — bypassing MFA because the victim authenticated legitimately.

The four evasion techniques documented represent a deliberate response to increased detection of basic device-code phishing lures by email security platforms and threat intelligence feeds:

1. **CAPTCHA gates**: Phishing landing pages gate the device code display behind a CAPTCHA challenge, preventing automated URL scanners from reaching the actual phishing content
2. **Multi-step SaaS redirect chains**: Lure URLs point to legitimate SaaS platforms (SharePoint, Notion, OneDrive, Dropbox) that then redirect to the actual phishing page, exploiting reputation allowlisting of major SaaS domains in email gateways
3. **Blob URL / AES-GCM delivery**: The phishing page HTML is encrypted with AES-GCM and stored as a base64 blob in the JavaScript; the decryption key is passed as a URL fragment (`#key=...`) that is never sent to the server, preventing proxy inspection of page content
4. **Cyrillic character substitution and zero-width character injection**: Lure text contains Cyrillic lookalike characters (е/е, о/о, а/а) or zero-width Unicode characters (U+200B, U+200C, U+FEFF, U+200D) inserted between characters of brand names and URLs, breaking string-matching-based detection while remaining invisible to human readers

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access, Initial Access |
| Tactic ID | TA0006, TA0001 |
| Technique | Multi-Factor Authentication Interception (device code flow abuse) |
| Technique ID | T1111 |
| Secondary Technique | Phishing: Spearphishing Link |
| Secondary Technique ID | T1566.002 |
| Tertiary Technique | Obfuscated Files or Information |
| Tertiary Technique ID | T1027 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery (phishing email with device-code lure link) |
| Exploitation (victim authenticates on legitimate Microsoft portal; attacker captures OAuth token) |
| Actions on Objectives (M365 account takeover; persistence via registered app; BEC/data theft) |

## Threat Actors

| Actor | Notes |
|-------|-------|
| Unknown (multiple device-code phishing operators) | Unit 42 observed these techniques across multiple distinct campaigns; no single named actor; techniques suggest shared tooling or underground kit |

## Indicators of Compromise

### Attacker-Controlled Domains

| Domain | Notes |
|--------|-------|
| uniqo[.]de | Device-code phishing lure/redirect domain |
| rayallen.plastlsole[.]de | Device-code phishing lure/redirect domain |
| storage-document-folder-s3-document-id-2003949.b-cdn[.]net | Device-code phishing lure; Bunny CDN-hosted redirect mimicking S3 storage URL |
| bridgehouse.co[.]nl | Device-code phishing lure/redirect domain |
| reviewdocumentandexecute.launchmint[.]us | Device-code phishing landing page; action-oriented path to prompt urgency |
| dyscova[.]com | Device-code phishing lure/redirect domain |
| tmowbre-pacifiefc-ca-s-account.workers[.]dev | Device-code phishing via Cloudflare Workers; obfuscated subdomain |
| corwins[.]nl | Device-code phishing lure/redirect domain |
| akxial.brookharbor[.]org | Device-code phishing lure/redirect domain |
| e657890765nmnbcvxbnbmnmmbvcxvbhxghjkg[.]com | Device-code phishing domain; keyboard-mash randomized hostname for evasion |
| juciy.northmarko[.]nl | Device-code phishing lure/redirect domain |
| prfesmgqqx.zh-app-jiebaoscore[.]com | Device-code phishing lure/redirect domain; randomized subdomain |
| uvyiuoio.b-cdn[.]net | Device-code phishing lure; Bunny CDN-hosted |
| 1o5ehsjoea.craftedcommunication[.]de | Device-code phishing lure/redirect domain |
| yw9hbp4oi0.techreliably[.]de | Device-code phishing lure/redirect domain |

### File Hashes (Phishing Email Samples)

| Hash | Type | Context |
|------|------|---------|
| e5b4f1f5e44905fb3f5790331cb4ac536bf881a9a2737518aa92cce30da01b2b | SHA256 | Device-code phishing email; CAPTCHA-gated lure variant |
| 0b7cf15aefa4a03729a0c736959c20aa4211df93a14e70259da109d669b94f56 | SHA256 | Device-code phishing email; multi-step SaaS redirect chain variant |
| 0fb5c0d0c2125ea26f128f51e5114e9163a18e81c6446a2f09eb65794f9a9dcf | SHA256 | Device-code phishing email; Blob URL AES-GCM encrypted payload variant |
| 20fc0c65eedea0d960056c5edca42d6c517fd5b7c429dc2e58a5bdb4372e9a83 | SHA256 | Device-code phishing email; Cyrillic/zero-width character obfuscation variant |

## Evasion Technique Detail

### Technique 1: CAPTCHA Gates
Phishing landing pages require CAPTCHA completion before displaying device codes. Automated URL analysis by email gateways and sandboxes cannot solve CAPTCHAs, so the actual phishing payload is never scanned. hCaptcha and reCAPTCHA v3 (invisible) variants observed.

**Detection implication**: URL reputation checks on the lure domain will succeed (page loads) but return a CAPTCHA page, not the phishing content. Human analyst manual verification or headless browser with CAPTCHA-solving is needed.

### Technique 2: Multi-Step SaaS Redirect Chains
Lure email contains a link to a legitimate SaaS file (SharePoint document, Notion page, OneDrive shared link). That page contains a hyperlink or JavaScript redirect to the actual attacker-controlled phishing domain. Email gateways allowlist major SaaS domains, so the initial URL passes inspection. Time-of-click URL unwrapping is needed to catch the second hop.

### Technique 3: Blob URL / AES-GCM Delivery
The phishing HTML page contains JavaScript that decrypts an AES-GCM ciphertext (base64-encoded in the script) using a key passed in the URL fragment. The URL fragment is never transmitted to the server in HTTP requests, so proxy inspection sees only an encrypted blob. The fully rendered phishing page is only visible in the victim's browser after client-side decryption.

**Detection implication**: Network-layer inspection cannot see page content. Endpoint DLP or browser telemetry (DOM inspection, navigation events) is required. Key indicator: URL fragment containing base64-encoded key material (`#key=`, `#k=`, `#dk=`).

### Technique 4: Cyrillic Character Substitution and Zero-Width Characters
Brand names, Microsoft product names, and URLs in lure text use visually identical Cyrillic Unicode codepoints (е U+0435 for e U+0065; о U+043E for o U+006F; а U+0430 for a U+0061) or insert zero-width characters (U+200B, U+200C, U+200D, U+FEFF) between characters. String-matching rules that look for "Microsoft", "OneDrive", or "device-code login" are bypassed. The text renders identically to the human eye.

**Detection implication**: Regex-based email content rules need Unicode normalization (NFKD/NFC) before matching. Zero-width character stripping should be applied to email body text before pattern matching.

## Detection Opportunities

DNS detection for known device-code phishing domains:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN (
    "uniqo.de","plastlsole.de","b-cdn.net","bridgehouse.co.nl",
    "launchmint.us","dyscova.com","workers.dev","corwins.nl",
    "brookharbor.org","northmarko.nl","jiebaoscore.com",
    "craftedcommunication.de","techreliably.de")
  by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime src query record_type risk_score
```

> **Note**: `b-cdn.net`, `workers.dev` are shared CDN/platform infrastructure. Tune by adding path-based filtering from proxy/web logs (Web.Web data model) for the specific paths observed.

Behavioral detection for OAuth device-code token request:

```spl
index=* sourcetype=o365* OR sourcetype=azure_ad*
(Operation="UserLoggedIn" OR event_type="Sign-in")
AuthenticationMethod="Device code"
| eval risk_score=case(
    like(lower(UserAgent), "%python%"), 95,
    like(lower(UserAgent), "%curl%"), 90,
    like(lower(UserAgent), "%requests%"), 90,
    1=1, 70)
| where risk_score >= 70
| stats count min(_time) as firstTime max(_time) as lastTime values(risk_score) as risk_score
  by UserId IPAddress UserAgent
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime UserId IPAddress UserAgent risk_score
```

## References

- [Unit 42 Timely Threat Intel — Device Code Phishing Evasion Techniques (2026-07-23)](https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-07-23-Device-code-phishing-evasion-techniques.txt)
- [MITRE ATT&CK — T1111: MFA Interception](https://attack.mitre.org/techniques/T1111/)
- [MITRE ATT&CK — T1566.002: Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK — T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [RFC 8628 — OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
