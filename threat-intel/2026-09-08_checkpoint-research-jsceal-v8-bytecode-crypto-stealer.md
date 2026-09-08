---
title: "JSCeal: V8 Bytecode-Compiled JavaScript Infostealer Targeting Crypto Wallets via Fake TradingView"
source: Check Point Research
source_url: https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode/
date: 2026-09-07
scraped_at: 2026-09-08T00:00:00Z
report_type: threat-intel
severity: high
tags: [jsceal, infostealer, v8-bytecode, tradingview, crypto-wallet, man-in-the-browser, meta-ads, google-ads, browser-credentials, session-hijacking]
mitre_tactics: [TA0002, TA0006, TA0011]
aliases: [WEEVILPROXY, MeadowLocust]
---

# JSCeal: V8 Bytecode-Compiled JavaScript Infostealer Targeting Crypto Wallets via Fake TradingView

## Executive Summary

Check Point Research published a detailed analysis on 2026-09-07 of **JSCeal**, an advanced JavaScript-based infostealer that compiles its core logic to V8 bytecode to evade static analysis and traditional AV detection. The malware, also tracked as **WEEVILPROXY** and **MeadowLocust**, is distributed via malicious ads on Meta and Google platforms posing as the legitimate TradingView desktop application. Once installed, JSCeal acts as a Man-in-the-Browser (MitB) proxy intercepting live browser traffic, stealing session cookies sufficient to bypass Google Account multi-factor authentication, and harvesting credentials stored by browser extensions associated with cryptocurrency wallets. The campaign primarily targets individual investors and traders in the cryptocurrency space.

## IOCs

### Domains / URLs

| Indicator | Role |
|-----------|------|
| No specific C2 domains released publicly at time of reporting | Full IOC list available to Check Point ThreatCloud subscribers |

### IP Addresses

| Indicator | Role |
|-----------|------|
| No specific C2 IPs released publicly at time of reporting | — |

### File Hashes

| Hash | Type | Description |
|------|------|-------------|
| No specific hashes released publicly at time of reporting | — | Full IOC set available in Check Point ThreatCloud portal |

### Behavioral / File-System Indicators

- Fake TradingView installer delivered via paid malicious ads (Meta Ads / Google Ads)
- Installer drops a Node.js runtime bundled with compiled `.jsc` V8 bytecode files
- Bytecode files bypass most YARA/static analysis signatures targeting JavaScript source
- RC4-encrypted strings embedded in bytecode for C2 configuration
- Control-flow flattening applied before compilation to resist dynamic deobfuscation
- Browser extension data directories targeted: MetaMask, Phantom, Coinbase Wallet, and others
- MitB component registers as a system proxy to intercept HTTPS session cookies in real time

## TTPs (MITRE ATT&CK)

| Tactic | Technique | Sub-technique | Description |
|--------|-----------|---------------|-------------|
| TA0001 Initial Access | T1566 | T1566.002 Spearphishing Link | Malicious ads redirect victims to typosquatted/lookalike download page |
| TA0002 Execution | T1059 | T1059.007 JavaScript | Node.js executes compiled V8 bytecode .jsc files |
| TA0003 Persistence | T1547 | T1547.001 Registry Run Keys | Installer registers startup entry for persistence |
| TA0005 Defense Evasion | T1027 | T1027.009 Embedded Payloads | Core logic compiled to V8 bytecode, defeating source-level static analysis |
| TA0006 Credential Access | T1555 | T1555.003 Credentials from Web Browsers | Browser extension credential stores (MetaMask, Phantom, etc.) harvested |
| TA0006 Credential Access | T1539 | — | Session cookie theft for account takeover bypassing MFA |
| TA0011 C2 | T1090 | T1090.001 Internal Proxy | MitB registers system proxy to intercept live browser traffic |
| TA0011 C2 | T1132 | T1132.001 Standard Encoding | RC4 used for C2 config string obfuscation |

## Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| JSCeal | Infostealer / MitB proxy | V8 bytecode compiled; aliases WEEVILPROXY, MeadowLocust |
| Fake TradingView installer | Dropper | Bundles Node.js runtime + JSCeal .jsc payload |

## Threat Actor Attribution

No specific threat actor attribution disclosed by Check Point Research at time of publication. The campaign's infrastructure and tooling overlap with prior MeadowLocust activity tracked by multiple vendors. The use of paid social-media ad campaigns for delivery is consistent with financially motivated threat actors targeting cryptocurrency holders.

## Splunk Detection Searches

### Node.js executing compiled bytecode files

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("node.exe","node")
    AND Processes.process="*.jsc*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table dest, user, parent_process_name, process_name, process, process_id, firstTime, lastTime, risk_score
```

### Suspicious system proxy registration (MitB pattern)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer*"
    AND Registry.registry_value_data IN ("127.0.0.1:*","localhost:*")
  by Registry.dest Registry.user Registry.registry_path Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=65
| table dest, user, registry_path, registry_value_data, firstTime, lastTime, risk_score
```

### Browser extension credential directory access by non-browser processes

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN (
    "*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn*",
    "*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa*",
    "*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\hnfanknocfeofbddgcijnmhnfnkdnaad*"
  )
  AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","brave.exe","firefox.exe")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table dest, user, process_name, file_path, firstTime, lastTime, risk_score
```

## References

- Check Point Research: https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode/
- MITRE ATT&CK T1059.007 (JavaScript): https://attack.mitre.org/techniques/T1059/007/
- MITRE ATT&CK T1555.003 (Credentials from Web Browsers): https://attack.mitre.org/techniques/T1555/003/
- MITRE ATT&CK T1539 (Steal Web Session Cookie): https://attack.mitre.org/techniques/T1539/
- MITRE ATT&CK T1027.009 (Embedded Payloads): https://attack.mitre.org/techniques/T1027/009/
