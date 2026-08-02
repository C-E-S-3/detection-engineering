---
scraped_at: "2026-08-02T00:00:00Z"
source_url: https://www.bleepingcomputer.com/news/security/adform-ad-network-javascript-library-compromised-in-supply-chain-attack/
report_type: threat-intel
severity: medium
title: "Adform Ad Network JavaScript Supply Chain Attack — Crypto Clipboard Hijacker via trackpoint-async.js"
---

# Adform Ad Network JavaScript Supply Chain Attack — Crypto Clipboard Hijacker

BleepingComputer and The Hacker News reported August 1, 2026 that the Adform advertising network JavaScript library `trackpoint-async.js`, served from `s2.adform.net`, was compromised on July 27, 2026 to perform cryptocurrency clipboard hijacking. The malicious code monitored clipboard content and silently replaced cryptocurrency wallet addresses with attacker-controlled addresses, redirecting payments to the threat actor's wallets.

## 1. IOCs

### Network
| Indicator | Type | Context |
|-----------|------|---------|
| `84.32.102.230` | IPv4 | C2 server receiving clipboard-hijacked crypto transactions; port 7744 |
| `s2.adform.net` | Domain | Legitimate Adform CDN host serving compromised `trackpoint-async.js` |

### File
No file hashes published. The malicious code was injected into the hosted JS file and served dynamically.

## 2. Malware & Tools

**Crypto Clipboard Hijacker (unnamed):** JavaScript payload injected into `trackpoint-async.js`. Monitors the browser clipboard for cryptocurrency wallet address patterns (Bitcoin, Ethereum, and others). On detection, replaces the wallet address with an attacker-controlled address before the user pastes. Exfiltrates replacement confirmation to C2 `84.32.102.230:7744`.

## 3. Actor Attribution

No attribution. The attack was discovered during routine ad network security monitoring. No group or nation-state has been publicly linked to this incident.

## 4. TTPs

| Tactic | Technique ID | Technique | Notes |
|--------|-------------|-----------|-------|
| Initial Access | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Compromised Adform's CDN-hosted JavaScript library |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | Malicious JS runs in victim browser context via ad network inclusion |
| Impact | T1657 | Financial Theft | Cryptocurrency address replacement in clipboard redirects payments to attacker wallets |
| Collection | T1115 | Clipboard Data | Monitors and modifies clipboard contents |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP C2 to `84.32.102.230:7744` |

## 5. Splunk Detections

### Web proxy traffic to Adform C2
```spl
index=* sourcetype=proxy OR sourcetype=pan:traffic OR sourcetype=fortigate_traffic
| search dest_ip="84.32.102.230" OR dest="84.32.102.230"
| table _time, src_ip, dest, dest_ip, dest_port, url, bytes, action
| sort -_time
```

### DNS query for compromised CDN host
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query="s2.adform.net"
  by DNS.src DNS.query DNS.record_type DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, src, query, answer, count
```

### Suspicious outbound HTTPS to non-standard port
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=7744 All_Traffic.action=allowed
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, src, dest, dest_ip, dest_port, bytes_out, count
```

## 6. Executive Summary

**Date of Compromise:** July 27, 2026  
**Date Reported:** August 1, 2026  
**Attack Type:** Supply chain JavaScript injection — crypto clipboard hijacker  
**Affected Surface:** Any website including the Adform ad network `trackpoint-async.js` library from `s2.adform.net`  

The threat actor compromised Adform's CDN to inject clipboard-monitoring JavaScript into their widely-distributed ad tracking library. End users visiting any site that included the Adform tracking pixel and attempted to copy-paste cryptocurrency wallet addresses would have their clipboard silently modified. The attack is passive and leaves no persistent artifacts on victim endpoints, making forensic investigation difficult. Enterprise risk is limited to employees conducting personal crypto transactions from monitored endpoints.

## 7. References

- [BleepingComputer — Adform ad network JavaScript library compromised in supply chain attack](https://www.bleepingcomputer.com/news/security/adform-ad-network-javascript-library-compromised-in-supply-chain-attack/)
- [The Hacker News — Adform supply chain attack](https://thehackernews.com/)
- [MITRE ATT&CK T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK T1115 — Clipboard Data](https://attack.mitre.org/techniques/T1115/)
