---
scraped_at: 2026-09-04T00:00:00Z
source_url: https://socket.dev/blog/malicious-composer-packages-ophimcms-kkphim-ios-spyware
report_type: threat-intel
severity: high
title: "Supply Chain: 13 Malicious Packagist/Composer Packages Deliver iOS Spyware via WebKit Exploit Chain (CVE-2025-31277 / CVE-2025-43529)"
---

# Supply Chain: 13 Malicious Packagist/Composer Packages Deliver iOS Spyware via WebKit Exploit Chain

## Summary

Socket.dev researchers disclosed 13 malicious Composer (PHP/Packagist) packages published as theme components for OphimCMS and KKPhim, two popular Vietnamese piracy/streaming content management systems. The packages inject JavaScript into page output that silently loads a WebKit exploit chain hosted on FUNNULL CDN infrastructure. Visitors using iOS 18.4 through 18.6.x with unpatched WebKit are served spyware that enumerates and exfiltrates cryptocurrency wallet seed phrases from seven major mobile wallet applications. Attribution is tentative Vietnamese-speaking actor; FUNNULL CDN was previously linked to the Polyfill.io supply chain attack.

## Threat Actor

| Field | Value |
|-------|-------|
| Name | Unattributed (tentative Vietnamese-speaking actor) |
| Infrastructure | FUNNULL CDN (previously linked to Polyfill.io supply chain attack, 2024) |
| Targeting | Vietnamese-operated streaming/piracy sites; iOS users visiting those sites |
| Motivation | Financial — cryptocurrency wallet seed phrase theft |

## Malicious Packages

13 packages were identified on Packagist and removed following Socket.dev disclosure. All masqueraded as legitimate OphimCMS and KKPhim theme/plugin packages:

- Packages followed naming convention: `ophimcms/<theme-name>`, `kkphim/<component-name>`
- Inserted one-line JavaScript loader into theme output templates
- Loader fetched a second-stage script from FUNNULL CDN endpoints
- FUNNULL endpoint delivered device fingerprint → CVE gating → WebKit exploit payload

## Vulnerability Chain

### CVE-2025-31277 — WebKit Type Confusion (CVSS 8.8)
- Type: Type confusion in WebKit JavaScript engine
- Affected: iOS/iPadOS 18.4 and earlier at time of patch; actively exploited against 18.4–18.6.x in this campaign
- Fixed: iOS 18.4.1 (April 2025); continued exploitation of unpatched devices observed

### CVE-2025-43529 — WebKit Sandbox Escape (CVSS 8.6)
- Type: Memory corruption enabling escape from WebKit renderer sandbox
- Affected: Same iOS/iPadOS range as CVE-2025-31277
- Chained with CVE-2025-31277 to achieve code execution outside the browser sandbox

**Combined Impact**: Silent, zero-click-equivalent remote code execution on iOS devices visiting a compromised site via Safari or any WKWebView-based browser. No user interaction beyond page load required.

## Payload: iOS Crypto Wallet Spyware

Post-exploitation payload targets seed phrases and private key material from:

| Wallet | Type |
|--------|------|
| Bitget Wallet (formerly BitKeep) | Mobile crypto wallet |
| Bitpie | Mobile crypto wallet |
| Phantom | Solana / multi-chain wallet |
| Tonkeeper | TON blockchain wallet |
| Trust Wallet | Multi-chain wallet |
| OKX Wallet | Exchange-linked mobile wallet |
| Bitget Exchange App | Exchange mobile app |

The spyware scans local app storage for wallet seed phrase files, private key backups, and keychain entries associated with the above applications. Exfiltration path is HTTPS to FUNNULL infrastructure.

## IOCs

No specific FUNNULL CDN hostnames or IP addresses have been publicly confirmed for this campaign. FUNNULL CDN rotates infrastructure frequently. Monitor for:

- JavaScript injection patterns in Composer package output templates
- Outbound connections from web servers to unfamiliar CDN endpoints following Composer updates
- Anomalous JavaScript loading from Packagist-sourced theme files

IOC CSV files not updated (no confirmed stable IOCs to track).

## Detection Guidance

### Composer Package Supply Chain
- Audit `composer.json` and `composer.lock` for OphimCMS/KKPhim packages; verify package integrity against known-good hashes
- Monitor for new Composer packages added to streaming/CMS installations
- Review theme files for injected one-liner JavaScript loaders (unusual `<script src=` tags with external CDN hostnames)

### Web Server / CDN Logs
- Alert on outbound HTTP requests from PHP/web application processes to unrecognized CDN domains
- Monitor for JavaScript responses containing device fingerprinting payloads (battery API, screen metrics, user agent inspection)

### iOS Endpoint (MDM/EDR)
- Monitor for WebKit process crashes followed by unusual child process spawning
- Alert on access to wallet app data directories by unexpected processes
- Apply iOS 18.4.1+ patches to eliminate CVE-2025-31277 and CVE-2025-43529 exposure

## MITRE ATT&CK

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 |
| Initial Access | Drive-by Compromise | T1189 |
| Credential Access | Credentials from Password Stores | T1555 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

## References

- [Socket.dev — Malicious Composer Packages OphimCMS/KKPhim iOS Spyware](https://socket.dev/blog/malicious-composer-packages-ophimcms-kkphim-ios-spyware)
- [FUNNULL CDN / Polyfill.io Supply Chain Attack (2024)](https://sansec.io/research/polyfill-supply-chain-attack)
- [NVD CVE-2025-31277](https://nvd.nist.gov/vuln/detail/CVE-2025-31277)
- [NVD CVE-2025-43529](https://nvd.nist.gov/vuln/detail/CVE-2025-43529)
- [MITRE ATT&CK T1195.002 — Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK T1189 — Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
