---
scraped_at: 2026-07-24T08:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/07/23/microsoft-digital-defense-report-q2-2026-email-threat-landscape/
report_type: threat-intel
severity: high
title: "Microsoft Q2 2026 Email Threat Landscape: BEC Surge, ClickUp CDN Phishing Relay, QR Code AiTM"
---

# Microsoft Q2 2026 Email Threat Landscape Report

**Source:** Microsoft Security Blog (Microsoft Threat Intelligence)  
**Published:** 2026-07-23  
**Severity:** High  

## Summary

Microsoft's Q2 2026 email threat landscape report documents a 34% quarter-over-quarter increase in business email compromise (BEC) attacks, and identifies three emerging TTPs observed in bulk across April–June 2026:

1. **ClickUp CDN as phishing payload relay**: Threat actors are abusing ClickUp's CDN (`clickup-attachments.com`) to host phishing payloads and serve them via direct-download links that pass major email security gateway reputation checks, because the domain is classified as a legitimate SaaS collaboration platform.
2. **QR-code-embedded AiTM phishing**: BEC actors are embedding QR codes in image attachments (bypassing text-based detection) that redirect to Adversary-in-the-Middle phishing pages, harvesting M365 session tokens while the victim believes they are completing legitimate MFA.
3. **Free/legitimate service relay chain**: Multi-hop delivery chains using Calendly, Google Forms, and other legitimate SaaS platforms as the initial lure link, with subsequent redirects to credential harvesting pages.

### ClickUp CDN Phishing Relay

Microsoft observed campaigns where threat actors:
1. Create a free ClickUp account
2. Upload a phishing payload (HTML redirect page or malicious document) to ClickUp's file attachment storage
3. Share a public ClickUp attachment link (hosted on `clickup-attachments.com` or `p.clickup-attachments.com`) in phishing emails
4. The CDN link passes email gateway URL reputation checks because ClickUp's domain is trusted

This represents a continuation of the "living-off-trusted-sites" delivery pattern, extending the technique previously seen with OneDrive, SharePoint, Dropbox, and Google Drive to ClickUp's CDN.

## IOCs

### Domains (BEC / Phishing Infrastructure)

The following domains were observed in Q2 2026 BEC and phishing campaigns documented in the Microsoft report:

| Indicator | Type | Context |
|-----------|------|---------|
| `9i6pokerdepot[.]com` | Domain | BEC actor spoofing / redirect domain |
| `ecajovna[.]sk` | Domain | BEC phishing portal mimicking Slovak business entity |
| `ilyff[.]com` | Domain | BEC actor email spoofing infrastructure |
| `j-gmails[.]com` | Domain | BEC actor lookalike domain (Gmail spoofing) |
| `x2mails[.]com` | Domain | BEC actor email infrastructure |
| `compliance-protectionoutlook[.]de` | Domain | AiTM phishing portal; impersonates Microsoft compliance notification |
| `acceptable-use-policy-calendly[.]de` | Domain | AiTM phishing portal; impersonates Calendly acceptable-use policy notification |
| `cocinternal[.]com` | Domain | BEC actor internal-spoofing domain |
| `gadellenet[.]com` | Domain | BEC phishing infrastructure |
| `harteprn[.]com` | Domain | BEC actor email relay domain |
| `t90141296286.p.clickup-attachments[.]com` | Domain | ClickUp CDN phishing relay; specific tenant subdomain hosting phishing HTML payload |

### File Hashes

| Indicator | Type | Context |
|-----------|------|---------|
| `5db1ecbbb2c90c51d81bda138d4300b90ea5eb2885cce1bd921d692214aecbc6` | SHA256 | Q2 2026 BEC phishing BAT script dropper — executes PowerShell credential harvesting one-liner |
| `b5a3346082ac566b4494e6175f1cd9873b64abe6c902db49bd4e8088876c9ead` | SHA256 | Q2 2026 phishing campaign HTML AiTM redirect page component |
| `11420d6d693bf8b19195e6b98fedd03b9bcbc770b6988bc64cb788bfabe1a49d` | SHA256 | Q2 2026 phishing attachment — QR code image with embedded AiTM URL |

## MITRE ATT&CK TTPs

| Technique | ID | Notes |
|-----------|----|-------|
| Phishing: Spearphishing Link | T1566.002 | Primary delivery vector in BEC campaigns |
| Phishing: Spearphishing Attachment | T1566.001 | QR code image attachments in email |
| Adversary-in-the-Middle: AiTM Phishing | T1557.002 | Session token harvesting via reverse proxy AiTM portals |
| Use Alternate Authentication Material: Web Session Cookie | T1550.004 | M365 session token replay after AiTM capture |
| Obtain Capabilities: Establish Accounts | T1585.002 | Actors create ClickUp free accounts to host payloads |
| Stage Capabilities: Upload Malware | T1608.001 | ClickUp CDN used to host and serve phishing HTML |
| Financial Theft | T1657 | BEC wire transfer fraud primary objective |

## Kill Chain

- **Delivery** — Phishing email with ClickUp CDN link, Calendly lure, or QR code image attachment
- **Exploitation** — AiTM session token harvest or BAT script execution
- **Actions on Objectives** — M365 session hijack, email rule creation, wire transfer fraud

## Trends

- **BEC volumes up 34% QoQ** (Q2 2026 vs Q1 2026)
- **ClickUp CDN relay** is the most-observed new delivery technique for Q2
- **QR code AiTM** bypasses text-based URL detection and is increasingly paired with fake MFA prompts
- **Free Calendly/Google Forms abuse** observed in >15% of initial-access BEC lure emails

## References

- [Microsoft Security Blog — Q2 2026 Email Threat Landscape (2026-07-23)](https://www.microsoft.com/en-us/security/blog/2026/07/23/microsoft-digital-defense-report-q2-2026-email-threat-landscape/)
- [MITRE ATT&CK — T1557.002: Adversary-in-the-Middle: AiTM Phishing](https://attack.mitre.org/techniques/T1557/002/)
- [MITRE ATT&CK — T1566.002: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK — T1608.001: Upload Malware](https://attack.mitre.org/techniques/T1608/001/)
