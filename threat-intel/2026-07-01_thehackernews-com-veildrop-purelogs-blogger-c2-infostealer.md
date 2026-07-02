---
scraped_at: 2026-07-02T00:00:00Z
source_url: https://thehackernews.com/2026/07/veildrop-javascript-dropper-uses-blogger-purelogs.html
report_type: threat-intel
severity: medium
title: "VEIL#DROP: JavaScript Dropper Using Blogger as C2 to Deliver PureLogs Infostealer"
---

# VEIL#DROP: JavaScript Dropper Using Blogger as C2 to Deliver PureLogs Infostealer

**Source:** The Hacker News  
**Published:** 2026-07-01  
**Severity:** Medium  

---

## Executive Summary

VEIL#DROP is a JavaScript-based dropper campaign documented on July 1, 2026 that uses Google Blogger (blogspot.com) posts as a covert command-and-control channel. The dropper is delivered via phishing and executes as a `.js` file. After initial execution, it retrieves encrypted configuration or second-stage payloads from attacker-controlled Blogger posts, which masquerade as legitimate blog content. Blogger's CDN and legitimate domain reputation allow VEIL#DROP traffic to blend with normal HTTPS traffic and evade web category filtering. A PowerShell stager is then downloaded and executed in memory, ultimately deploying PureLogs — a commercially available infostealer sold on criminal forums that harvests browser credentials, cookies, crypto wallet data, and VPN configurations. The use of legitimate web services (Blogger/blogspot.com) as C2 infrastructure is a growing trend among financially motivated actors seeking to avoid domain-based detection.

---

## IOCs

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `htlwub00klocate[.]blogspot[.]com` | Domain | VEIL#DROP Blogger C2 channel; attacker-controlled post hosts encrypted config/payload URLs |

---

## TTPs

| MITRE Technique | ID | Description |
|-----------------|-----|-------------|
| Command and Scripting Interpreter: JavaScript | T1059.007 | Initial dropper executes as `.js` file via wscript.exe or browser engine |
| Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell stager downloaded and executed in memory after JS dropper retrieves C2 config |
| Web Service: Bidirectional Communication | T1102.002 | Blogger (blogspot.com) used as C2 channel; attacker posts encode commands/URLs in blog content |
| Credentials from Password Stores: Credentials from Web Browsers | T1555.003 | PureLogs harvests Chromium and Gecko browser credential stores |
| Ingress Tool Transfer | T1105 | PowerShell stager downloads PureLogs binary from attacker infrastructure |
| Obfuscated Files or Information | T1027 | JS dropper uses obfuscation to hinder static analysis |

---

## Malware & Tools

- **VEIL#DROP** — JavaScript dropper; retrieves C2 configuration from Blogger posts; delivers PowerShell stager in memory
- **PureLogs** — Commercially sold infostealer (MaaS); harvests browser credentials, cookies, autofill data, crypto wallets, VPN configs; active since 2023; sold via criminal Telegram channels

---

## Threat Actor / Attribution

| Attribute | Detail |
|-----------|--------|
| Actor | Unknown financially motivated actor |
| Motivation | Financial (credential theft for fraud/resale) |
| Target | Broad; phishing-based delivery suggests opportunistic targeting |
| Confidence | Low attribution confidence; technique is consistent with multiple Eastern European cybercrime groups |

---

## Splunk Detection Searches

See `detections/execution/veildrop_js_powershell_blogger_staging.md` for the dedicated detection covering this attack chain (JS execution → PowerShell spawning → blogspot.com C2 connections).

```spl
`dns` query="*.blogspot.com"
| stats count by src query
| where count > 0
| join src [
    | tstats `security_content_summariesonly` count
      from datamodel=Endpoint.Processes
      where Processes.process_name IN ("powershell.exe","wscript.exe","cscript.exe")
      by Processes.src Processes.process_name
    | `drop_dm_object_name(Processes)`
    | rename src as src
]
| table src process_name query count
```

---

## References

- [The Hacker News — VEIL#DROP JavaScript Dropper (2026-07-01)](https://thehackernews.com/2026/07/veildrop-javascript-dropper-uses-blogger-purelogs.html)
- [MITRE ATT&CK — T1102.002: Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK — T1059.007: Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK — T1555.003: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
