# JSCeal V8 Bytecode Infostealer — Node.js Execution and MitB Proxy

## Description

Detects activity associated with **JSCeal** (also tracked as WEEVILPROXY / MeadowLocust), a JavaScript infostealer that compiles its core logic to V8 bytecode (`.jsc` files) and executes via a bundled Node.js runtime. The malware is delivered via fake TradingView desktop application installers promoted through malicious Meta and Google ads. JSCeal acts as a Man-in-the-Browser proxy, intercepting live HTTPS session cookies to bypass MFA and harvesting credentials from cryptocurrency wallet browser extensions (MetaMask, Phantom, Coinbase Wallet).

Expected false positives: legitimate Node.js development environments executing compiled bytecode; Electron-based applications that bundle Node.js and ship precompiled assets. Baseline known Electron apps (`Slack.exe`, `Code.exe`, `Discord.exe`) as parent processes before tuning.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Primary Tactic** | Execution (TA0002) |
| **Primary Technique** | T1059.007 — Command and Scripting Interpreter: JavaScript |
| **Secondary Tactic** | Credential Access (TA0006) |
| **Secondary Techniques** | T1555.003 — Credentials from Web Browsers; T1539 — Steal Web Session Cookie |
| **Tertiary Tactic** | Defense Evasion (TA0005) |
| **Tertiary Technique** | T1027.009 — Obfuscated Files or Information: Embedded Payloads |
| **Additional** | T1090.001 — Proxy: Internal Proxy (MitB system proxy registration) |

## Lockheed Martin Kill Chain Phase

- **Exploitation** — Node.js executes compiled bytecode payload after user runs fake installer
- **Actions on Objectives** — Browser credential and session cookie theft

## Splunk SPL Query

### Detection 1: Node.js executing compiled V8 bytecode files

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("node.exe","node")
    AND (Processes.process="*.jsc*" OR Processes.process="*bytenode*" OR Processes.process="*compiled*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(parent_process_name,"(?i)(tradingview|setup|install|update)"), 90,
    match(parent_process_name,"(?i)(explorer|cmd|powershell)"), 80,
    true(), 65
  )
| where risk_score >= 65
| table dest, user, parent_process_name, process_name, process, process_id, firstTime, lastTime, risk_score
```

### Detection 2: Localhost proxy registered via registry (MitB pattern)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer"
    AND (Registry.registry_value_data="127.0.0.1:*" OR Registry.registry_value_data="localhost:*")
  by Registry.dest Registry.user Registry.registry_path Registry.registry_value_data Registry.process_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=65
| table dest, user, registry_path, registry_value_data, process_name, firstTime, lastTime, risk_score
```

### Detection 3: Non-browser process accessing crypto wallet extension data

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (
    Filesystem.file_path="*\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn*"
    OR Filesystem.file_path="*\\Local Extension Settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa*"
    OR Filesystem.file_path="*\\Local Extension Settings\\hnfanknocfeofbddgcijnmhnfnkdnaad*"
    OR Filesystem.file_path="*\\Local Extension Settings\\ojggmchlghnjlapmfbnjholfjkiidbch*"
  )
  AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","brave.exe","firefox.exe","opera.exe")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table dest, user, process_name, file_path, firstTime, lastTime, risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 90 | Node.js executing `.jsc` bytecode, parent process matches installer/TradingView pattern |
| 85 | Non-browser process accessing cryptocurrency wallet extension storage directories |
| 80 | Node.js executing `.jsc` bytecode, parent is explorer/cmd/powershell |
| 65 | Node.js executing `.jsc` bytecode (generic); or localhost proxy registered via registry |

Correlate all three detections on the same `dest`+`user`+time window (within 30 minutes) to elevate to Critical (90+).

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| MeadowLocust (unattributed) | Alias used for JSCeal campaign infrastructure; no nation-state attribution |
| Financially motivated IABs | Crypto-targeting campaigns monetized via wallet draining and credential resale |

## References

- Check Point Research — JSCeal analysis: https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode/
- MITRE ATT&CK T1059.007: https://attack.mitre.org/techniques/T1059/007/
- MITRE ATT&CK T1555.003: https://attack.mitre.org/techniques/T1555/003/
- MITRE ATT&CK T1539: https://attack.mitre.org/techniques/T1539/
- MITRE ATT&CK T1027.009: https://attack.mitre.org/techniques/T1027/009/
- MITRE ATT&CK T1090.001: https://attack.mitre.org/techniques/T1090/001/
