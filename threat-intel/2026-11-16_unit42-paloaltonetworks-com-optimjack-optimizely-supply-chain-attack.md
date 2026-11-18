---
scraped_at: 2026-11-18T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/
report_type: threat-intel
severity: high
title: "OPTIMJACK: Optimizely CDN Supply Chain Attack Delivers Crypto Clipper, Card Skimmer, and iOS Exploit to 178+ Organizations"
---

# OPTIMJACK: Optimizely CDN Supply Chain Attack Delivers Crypto Clipper, Card Skimmer, and iOS Exploit to 178+ Organizations

**Source:** Unit 42 / Palo Alto Networks  
**Published:** 2026-11-16  
**Severity:** High — multi-payload supply chain attack with active skimming of payment card data and cryptocurrency; registrar suspended primary domain 2026-11-17 but secondary infrastructure may remain active

---

## 1. IOCs

### Domains

| Indicator | Role | First Seen | Notes |
|-----------|------|------------|-------|
| `1688360[.]cc` | Primary payload server | 2026-11-16 | Registered 2026-11-16; Google Cloud us-central1 (136.113.106.136); served /hit.php (data collection), /card.php (card exfil), /track.js (injected loader); registrar-suspended 2026-11-17 |
| `5vobauua3ojpklx[.]icu` | iOS exploit router | 2026-11-09 | Routes fingerprinted iOS user-agents to WebKit exploit chain; registered 2026-11-09 |
| `eil786npto9u5bq[.]icu` | Additional payload/tracking domain | 2026-11-16 | Payload staging and telemetry collection |
| `l7bcsnwc7nzr3uo[.]icu` | Telemetry POST endpoint | 2026-11-16 | Receives POST beacons from compromised pages |
| `linkforge[.]cc` | Additional infrastructure | 2026-11-16 | Supporting OPTIMJACK delivery infrastructure |

### IP Addresses

| Indicator | Role | Notes |
|-----------|------|-------|
| `136.113.106[.]136` | Primary C2 server | Google Cloud us-central1; hosting 1688360[.]cc and payload files |

### File Hashes

No file hashes publicly released by Unit 42 at time of initial disclosure.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | Notes |
|--------|-----------|-------|
| TA0001 Initial Access | T1195.002 — Compromise Software Supply Chain | Optimizely CDN JavaScript asset modified to inject malicious loader (`track.js`) served to 178+ downstream organizations |
| TA0002 Execution | T1059.007 — JavaScript | Malicious `track.js` loader executes in victim browsers, performing UA fingerprinting and loading stage-2 payloads |
| TA0009 Collection | T1056.003 — Input Capture: Web Portal Capture | Card skimmer exfiltrates payment form field values (card number, CVV, expiry, billing address) via POST to /card.php |
| TA0040 Impact | T1565.002 — Stored Data Manipulation | Crypto clipboard hijacker intercepts cryptocurrency wallet addresses pasted into web forms and replaces them with attacker-controlled addresses |
| TA0043 Reconnaissance | T1592 — Gather Victim Host Information | Browser fingerprinting (UA string, screen resolution, platform) used to route iOS users to WebKit exploit chain |
| TA0001 Initial Access | T1203 — Exploitation for Client Execution | iOS WebKit exploit delivered via 5vobauua3ojpklx[.]icu to fingerprinted iOS Safari users |

**Kill Chain Phase:** Delivery (CDN supply chain compromise) → Exploitation (browser-side JS execution) → Actions on Objectives (card skimming, crypto theft, iOS device compromise)

---

## 3. Malware & Tools

**OPTIMJACK Loader (`track.js`):** Malicious JavaScript injected into Optimizely CDN assets. Performs browser/OS fingerprinting on page load; loads stage-2 payload from 1688360[.]cc based on user-agent. iOS users are routed to the WebKit exploit chain; desktop users receive the crypto clipper or card skimmer.

**Crypto Clipboard Hijacker:** JavaScript component that monitors clipboard events and `paste` DOM events on web forms. Detects Bitcoin (bc1/1/3 prefix), Ethereum (0x prefix), and other cryptocurrency address patterns; silently replaces pasted address with attacker-controlled wallet.

**Card Skimmer (`/card.php` exfil):** Hooks `submit` events on payment forms and XHR/fetch calls to payment processors. Harvests PAN, CVV, expiry date, cardholder name, and billing address. Exfiltrates via asynchronous POST to 1688360[.]cc/card.php to avoid blocking page submission.

**iOS WebKit Exploit Chain:** Delivered via 5vobauua3ojpklx[.]icu; exploits unspecified WebKit vulnerability in iOS Safari. Full exploit details not released publicly; Unit 42 confirmed successful code execution on tested iOS versions.

---

## 4. Threat Actor / Campaign Attribution

OPTIMJACK is not attributed to a known named threat group by Unit 42 at time of initial disclosure. The combination of financial theft (card skimming + crypto hijacking) and mobile device exploitation (iOS WebKit exploit chain) suggests a sophisticated, financially motivated actor with capabilities beyond typical skimmer operations. The registration of infrastructure beginning November 9–16 and rapid deployment against 178+ organizations indicates pre-planned targeting of the Optimizely CDN ecosystem rather than opportunistic compromise.

The primary domain `1688360[.]cc` was registered November 16, 2026 — the same day as Unit 42 publication — and was registrar-suspended November 17, 2026, suggesting either coordinated law-enforcement action or registrar abuse reporting. Secondary `.icu` domains registered as early as November 9 may still be active.

Optimizely (formerly Episerver) is a widely deployed enterprise content management and digital experience platform. Supply chain attacks targeting CDN-hosted JavaScript assets have increased significantly following the Polyfill.io compromise (2024) and subsequent similar operations.

---

## 5. Splunk Detection Searches

### 5.1 Outbound Connections to OPTIMJACK Infrastructure (Network IOC Match)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN ("1688360.cc", "5vobauua3ojpklx.icu", "eil786npto9u5bq.icu",
    "l7bcsnwc7nzr3uo.icu", "linkforge.cc", "136.113.106.136")
  by All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src_ip dest dest_port app count risk_score
```

### 5.2 DNS Resolution of OPTIMJACK Domains

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("1688360.cc", "5vobauua3ojpklx.icu", "eil786npto9u5bq.icu",
    "l7bcsnwc7nzr3uo.icu", "linkforge.cc")
  by DNS.src DNS.query DNS.record_type DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query record_type answer count risk_score
```

### 5.3 Web Proxy Requests to Optimizely CDN with Anomalous Script Loading

Detects HTTP requests to Optimizely CDN endpoints that subsequently load content from unexpected external origins — a behavioral indicator of compromised CDN assets.

```spl
index=proxy OR index=web sourcetype IN ("pan:threat", "squid", "bluecoat", "zscaler")
| rex field=uri "(?P<cdn_host>[^/]+)"
| where match(cdn_host, "(?i)(cdn\.optimizely\.com|assets\.optimizely\.com|app\.optimizely\.com)")
| transaction src_ip maxspan=30s
| where mvcount(uri) > 1
| eval suspicious_dest=mvfilter(match(uri, "(?i)(1688360\.cc|5vobauua3ojpklx\.icu|eil786npto9u5bq\.icu|l7bcsnwc7nzr3uo\.icu|linkforge\.cc)"), uri)
| where isnotnull(suspicious_dest)
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip suspicious_dest
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip suspicious_dest count risk_score
```

---

## 6. Mitigation

- **Block IOCs:** Add all five OPTIMJACK domains and 136.113.106.136 to DNS sinkholes, proxy blocklists, and firewall ACLs immediately.
- **CSP audit:** Review Content Security Policy headers on all web applications using Optimizely; ensure `script-src` and `connect-src` do not permit arbitrary external origins.
- **Optimizely review:** Contact Optimizely to confirm whether your CDN assets were affected; request integrity checksums for all CDN-hosted JS files.
- **Subresource Integrity (SRI):** Implement `integrity=` attributes on all third-party script tags to detect future CDN tampering.
- **iOS patching:** Ensure all managed iOS devices are on the current iOS patch level; the WebKit exploit targeted in this campaign is unspecified but may be addressed by recent updates.

---

## 7. References

- [Unit 42: OPTIMJACK Supply Chain Attack](https://unit42.paloaltonetworks.com/optimjack-supply-chain-attack/)
- [MITRE ATT&CK T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK T1059.007 — JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK T1056.003 — Web Portal Capture](https://attack.mitre.org/techniques/T1056/003/)
