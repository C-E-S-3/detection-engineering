---
scraped_at: "2026-07-28T00:00:00Z"
source_url: https://github.com/stamparm/maltrail/commit/3a235f6
report_type: threat-intel
severity: high
title: "Android Kraken 2.0 (Kraken 2.0 Painel): New Mobile Banking Trojan C2 Infrastructure"
---

# Android Kraken 2.0 (Kraken 2.0 Painel): New Mobile Banking Trojan C2 Infrastructure

Maltrail received a new tracking file for **Android Kraken v2** on July 28, 2026 (commits `3a235f6` and `f6e42c5`), sourced from a public disclosure by researcher @Merlax_ on X/Twitter. The malware is identified by its control panel branding as "Kraken 2.0 — Painel" and targets Android banking applications. The infrastructure is concentrated in Brazilian IP space, strongly indicating the campaign targets Brazilian banking customers.

## 1. IOCs

### IP Addresses (35) — All on TCP/8443

| Indicator | Notes |
|-----------|-------|
| 102.165.46.129 | Kraken 2.0 C2, port 8443 |
| 102.165.46.21 | Kraken 2.0 C2, port 8443 |
| 15.228.199.254 | Kraken 2.0 C2, port 8443 |
| 151.243.218.121 | Kraken 2.0 C2, port 8443 |
| 151.243.219.162 | Kraken 2.0 C2, port 8443 |
| 151.243.219.67 | Kraken 2.0 C2, port 8443 |
| 157.254.55.222 | Kraken 2.0 C2, port 8443 |
| 157.254.55.234 | Kraken 2.0 C2, port 8443 |
| 177.136.234.233 | Kraken 2.0 C2, port 8443 |
| 177.155.199.100 | Kraken 2.0 C2, port 8443 |
| 177.155.199.21 | Kraken 2.0 C2, port 8443 |
| 190.102.40.218 | Kraken 2.0 C2, port 8443 |
| 190.102.42.133 | Kraken 2.0 C2, port 8443 |
| 190.102.43.41 | Kraken 2.0 C2, port 8443 |
| 190.102.43.66 | Kraken 2.0 C2, port 8443 |
| 190.102.43.74 | Kraken 2.0 C2, port 8443 |
| 191.101.131.105 | Kraken 2.0 C2, port 8443 |
| 191.101.131.41 | Kraken 2.0 C2, port 8443 |
| 191.101.131.74 | Kraken 2.0 C2, port 8443 |
| 191.96.78.192 | Kraken 2.0 C2, port 8443 |
| 191.96.79.144 | Kraken 2.0 C2, port 8443 |
| 191.96.79.197 | Kraken 2.0 C2, port 8443 |
| 200.9.154.111 | Kraken 2.0 C2, port 8443 |
| 200.9.154.151 | Kraken 2.0 C2, port 8443 |
| 200.9.155.94 | Kraken 2.0 C2, port 8443 |
| 216.238.124.15 | Kraken 2.0 C2, port 8443 |
| 216.238.124.48 | Kraken 2.0 C2, port 8443 |
| 38.60.241.44 | Kraken 2.0 C2, port 8443 |
| 45.157.157.138 | Kraken 2.0 C2, port 8443 |
| 45.157.157.142 | Kraken 2.0 C2, port 8443 |
| 45.158.8.117 | Kraken 2.0 C2, port 8443 |
| 45.158.8.127 | Kraken 2.0 C2, port 8443 |
| 45.158.8.30 | Kraken 2.0 C2, port 8443 |
| 45.158.8.68 | Kraken 2.0 C2, port 8443 |
| 86.106.87.135 | Kraken 2.0 C2, port 8443 |

### Domains (31)

| Indicator | Notes |
|-----------|-------|
| krakenthecontrol1oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol2oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol3oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol4oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol5oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol6oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol7oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol8oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol9oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol10oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol11oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol12oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol13oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol14oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol15oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol16oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol17oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontrol18oficial[.]xyz | Kraken 2.0 C2/panel domain |
| krakenthecontroloficial21[.]online | Kraken 2.0 C2/panel domain |
| krakenthecontroloficial23[.]online | Kraken 2.0 C2/panel domain |
| krakenthecontroloficial24[.]online | Kraken 2.0 C2/panel domain |
| krkcontrol25[.]store | Kraken 2.0 C2/panel domain |
| krkcontrol26[.]store | Kraken 2.0 C2/panel domain |
| krkcontrol27[.]store | Kraken 2.0 C2/panel domain |
| krkcontrol28[.]store | Kraken 2.0 C2/panel domain |
| krkcontrol29[.]store | Kraken 2.0 C2/panel domain |
| krkcontrol30[.]store | Kraken 2.0 C2/panel domain |
| krkcontrol31[.]store | Kraken 2.0 C2/panel domain |
| krkcontrol32[.]store | Kraken 2.0 C2/panel domain |
| krkcontrol33[.]store | Kraken 2.0 C2/panel domain |
| krkcontrol34[.]store | Kraken 2.0 C2/panel domain |
| aggbet[.]net | Kraken 2.0 delivery/lure domain |
| validaempresa[.]info | Kraken 2.0 — "Validate Business" lure domain |
| watchtv[.]tech | Kraken 2.0 lure/staging domain |

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | T1476 | Deliver Malicious App via Other Means | Trojanized Android banking app or sideloaded APK delivered via lure domains |
| Command and Control | T1437 | Application Layer Protocol: Web Protocols | HTTPS C2 on port 8443 to panel IPs |
| Collection | T1417 | Input Capture (Mobile) | Overlay attacks on Brazilian banking apps to capture credentials |
| Credential Access | T1412 | Capture SMS Messages | Likely intercepts SMS OTPs for 2FA bypass |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Credential data exfiltrated to "Kraken 2.0 Painel" control panel |
| Defense Evasion | T1406 | Obfuscated Files or Information (Mobile) | Obfuscated APK payloads common in Brazilian banking trojans |

## 3. Malware & Tools

**Android Kraken v2 ("Kraken 2.0 Painel")**

A new version of the Android Kraken mobile banking trojan. The naming "Painel" (Portuguese for "panel") and the concentration of IPs in Brazilian autonomous systems (e.g., `177.136.x`, `190.102.x`, `191.101.x`, `200.9.155.x`) indicate a Brazilian threat actor targeting Brazilian financial institution customers. The numbered sequential naming of C2 domains (`krakenthecontrol1oficial.xyz` through `krakenthecontrol18oficial.xyz`, then `krakenthecontroloficial21-24.online`, then `krkcontrol25-34.store`) suggests active campaign expansion with domain rotation. All C2 communications occur on TCP port 8443.

## 4. Threat Actor / Campaign Attribution

| Actor | Assessment | Notes |
|-------|-----------|-------|
| Unknown Brazilian cybercrime actor | Medium confidence | IP space concentration in Brazilian ISP ranges (177.x, 190.x, 191.x, 200.9.x); Portuguese domain naming convention ("oficial", "validaempresa"); sequential domain registration pattern consistent with Brazilian banking trojan MaaS operations |

## 5. Splunk Detection Searches

```spl
`-- Detect DNS lookups for Android Kraken 2.0 C2 domains`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
    "aggbet.net","validaempresa.info","watchtv.tech",
    "krakenthecontrol1oficial.xyz","krakenthecontrol2oficial.xyz",
    "krakenthecontrol3oficial.xyz","krakenthecontrol4oficial.xyz",
    "krakenthecontrol5oficial.xyz","krakenthecontrol6oficial.xyz",
    "krakenthecontrol7oficial.xyz","krakenthecontrol8oficial.xyz",
    "krakenthecontrol9oficial.xyz","krakenthecontrol10oficial.xyz",
    "krakenthecontrol11oficial.xyz","krakenthecontrol12oficial.xyz",
    "krakenthecontrol13oficial.xyz","krakenthecontrol14oficial.xyz",
    "krakenthecontrol15oficial.xyz","krakenthecontrol16oficial.xyz",
    "krakenthecontrol17oficial.xyz","krakenthecontrol18oficial.xyz",
    "krakenthecontroloficial21.online","krakenthecontroloficial23.online",
    "krakenthecontroloficial24.online",
    "krkcontrol25.store","krkcontrol26.store","krkcontrol27.store",
    "krkcontrol28.store","krkcontrol29.store","krkcontrol30.store",
    "krkcontrol31.store","krkcontrol32.store","krkcontrol33.store",
    "krkcontrol34.store")
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime src query record_type risk_score
```

```spl
`-- Detect outbound HTTPS (8443) to Android Kraken 2.0 C2 IP addresses`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_port=8443
  AND All_Traffic.dest_ip IN (
    "102.165.46.129","102.165.46.21","15.228.199.254",
    "151.243.218.121","151.243.219.162","151.243.219.67",
    "157.254.55.222","157.254.55.234","177.136.234.233",
    "177.155.199.100","177.155.199.21","190.102.40.218",
    "190.102.42.133","190.102.43.41","190.102.43.66",
    "190.102.43.74","191.101.131.105","191.101.131.41",
    "191.101.131.74","191.96.78.192","191.96.79.144",
    "191.96.79.197","200.9.154.111","200.9.154.151",
    "200.9.155.94","216.238.124.15","216.238.124.48",
    "38.60.241.44","45.157.157.138","45.157.157.142",
    "45.158.8.117","45.158.8.127","45.158.8.30",
    "45.158.8.68","86.106.87.135")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
   All_Traffic.transport All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime src dest dest_ip dest_port transport action risk_score
```

## 6. Executive Summary

On July 28, 2026, the Maltrail project added new tracking for **Android Kraken v2** ("Kraken 2.0 Painel"), a mobile banking trojan targeting Brazilian banking customers. The infrastructure consists of 35 C2 servers operating on TCP/8443 concentrated in Brazilian ISP IP space and 31 operator-registered domains following a sequential naming pattern (`krakenthecontrol[N]oficial.xyz`, `krkcontrol[N].store`). The lure domains include `validaempresa.info` ("Validate Business") consistent with business/banking impersonation targeting. Severity is rated **High** due to the scale of the C2 infrastructure and active domain registration pattern indicating an ongoing campaign. No CVE exploitation is involved; the attack vector is social engineering via trojanized Android applications.

## References

- https://github.com/stamparm/maltrail/commit/3a235f6 — maltrail initial creation of android_kraken.txt
- https://github.com/stamparm/maltrail/commit/f6e42c5 — maltrail update of android_kraken.txt
- https://x.com/Merlax_/status/2081905778751897664 — original disclosure by @Merlax_
