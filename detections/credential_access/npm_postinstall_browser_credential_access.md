# npm Postinstall Hook — Browser Credential and Crypto Wallet Access

## Description

Detects Node.js processes spawned by npm lifecycle hooks (postinstall, install, preinstall) that subsequently access browser credential stores, cryptocurrency wallet files, or environment secret files. This behavioral pattern is a hallmark of npm supply chain infostealer campaigns, in which malicious packages embed JavaScript payloads that execute silently during package installation.

This detection was developed in response to the Unit 42 obfuscated JavaScript crypto stealer campaign (2026-08-06), involving 10 malicious npm packages published between 2026-07-18 and 2026-07-22. The malware targeted:

- **Browser credentials**: Chrome, Brave, Opera, Yandex, Edge Login Data databases and session cookies
- **Crypto wallets**: Exodus, Guarda, Electrum, and Atomic desktop wallet data; browser extension wallet storage
- **Secrets**: `.env` files and keyword-matched files containing API keys and credentials
- **macOS/Linux keychains**: OS-level credential stores

The attack vector is consistent with DPRK Contagious Interview and other financially motivated supply chain campaigns that disguise credential stealers as developer utility packages.

False positives: Legitimate npm packages may invoke Node.js scripts that access credential-adjacent paths during automated testing or toolchain setup (e.g., browser-driver automation with Playwright/Puppeteer, password manager CLI tools). Allowlist known-good packages by publisher hash or use `npm_lifecycle_event` context in Node.js-level telemetry if available to correlate the triggering lifecycle hook.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Credentials from Password Stores: Credentials from Web Browsers |
| Technique ID | T1555.003 |
| Secondary Technique | Credentials from Password Stores: Keychain |
| Secondary Technique ID | T1555.001 |
| Secondary Tactic | Initial Access |
| Secondary Technique | Supply Chain Compromise: Compromise Software Dependencies and Development Tools |
| Secondary Technique ID | T1195.002 |
| Tertiary Tactic | Collection |
| Tertiary Technique | Data from Local System |
| Tertiary Technique ID | T1005 |
| Exfiltration | Exfiltration Over C2 Channel |
| Exfiltration ID | T1041 |
| Defense Evasion | Obfuscated Files or Information |
| Defense Evasion ID | T1027 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives (credential and wallet theft via supply chain delivery) |

## Splunk Detection Queries

### Query 1: Node.js Process Accessing Browser Credential Stores (Windows)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.parent_process_name IN ("node.exe","npm.cmd","npm.exe","npx.cmd","npx.exe")
    AND (Filesystem.file_path LIKE "%\\Chrome\\User Data\\Default\\Login Data%"
         OR Filesystem.file_path LIKE "%\\Chrome\\User Data\\Default\\Cookies%"
         OR Filesystem.file_path LIKE "%\\Chrome\\User Data\\Local State%"
         OR Filesystem.file_path LIKE "%\\Edge\\User Data\\Default\\Login Data%"
         OR Filesystem.file_path LIKE "%\\Brave-Browser\\User Data\\Default\\Login Data%"
         OR Filesystem.file_path LIKE "%\\Opera Software\\Opera Stable\\Login Data%"
         OR Filesystem.file_path LIKE "%\\Yandex\\YandexBrowser\\User Data\\%Login Data%"
         OR Filesystem.file_path LIKE "%\\Exodus\\exodus.wallet%"
         OR Filesystem.file_path LIKE "%\\Guarda\\%"
         OR Filesystem.file_path LIKE "%\\Electrum\\wallets\\%"
         OR Filesystem.file_path LIKE "%\\atomic\\Local Storage\\%"
         OR Filesystem.file_path LIKE "%wallet.dat%")
  by Filesystem.dest Filesystem.user Filesystem.parent_process_name
     Filesystem.process_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)Login Data|Cookies|Local State"), 95,
    match(file_path, "(?i)exodus|electrum|atomic|guarda|wallet\.dat"), 95,
    1=1, 85)
| where risk_score >= 85
| table firstTime lastTime dest user parent_process_name process_name file_path action risk_score
```

### Query 2: Node.js Process Accessing Browser Credential Stores (Linux/macOS)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.parent_process_name IN ("node","npm","npx","sh","bash","zsh")
    AND (Filesystem.file_path LIKE "%/Google/Chrome/Default/Login Data%"
         OR Filesystem.file_path LIKE "%/BraveSoftware/Brave-Browser/Default/Login Data%"
         OR Filesystem.file_path LIKE "%/com.operasoftware.Opera/Default/Login Data%"
         OR Filesystem.file_path LIKE "%/Yandex/YandexBrowser/Default/Login Data%"
         OR Filesystem.file_path LIKE "%/Microsoft Edge/Default/Login Data%"
         OR Filesystem.file_path LIKE "%/.exodus/exodus.wallet%"
         OR Filesystem.file_path LIKE "%/Electrum/wallets/%"
         OR Filesystem.file_path LIKE "%/Guarda/%"
         OR Filesystem.file_path LIKE "%/atomic-wallet/%"
         OR Filesystem.file_path LIKE "%.env"
         OR Filesystem.file_path LIKE "%/.env")
  by Filesystem.dest Filesystem.user Filesystem.parent_process_name
     Filesystem.process_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)Login Data|exodus|electrum|atomic|guarda"), 95,
    match(file_path, "(?i)\.env$"), 80,
    1=1, 85)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name file_path action risk_score
```

### Query 3: HTTPS Egress to Non-Standard Port from Node.js Process

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.process_name IN ("node.exe","node","npm.cmd","npm","npx","npx.cmd")
    AND All_Traffic.dest_port NOT IN (80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 8888)
    AND All_Traffic.app=ssl
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port
     All_Traffic.process_name All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest_port=45000, 98,
    dest IN ("31.97.137.157","46.183.25.232"), 98,
    dest_port >= 40000, 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest dest_port process_name bytes_out risk_score
```

### Query 4: Known Campaign C2 Connectivity (Any Process)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN ("31.97.137.157","46.183.25.232")
     OR (All_Traffic.dest_port=45000 AND All_Traffic.app=ssl)
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port
     All_Traffic.process_name All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=98
| table firstTime lastTime src dest dest_port process_name bytes_out risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Node.js contacting known C2 IPs (31.97.137.157, 46.183.25.232) | 98 | Direct IOC match; confirmed malicious infrastructure |
| HTTPS from Node.js to port 45000 | 98 | Campaign-specific non-standard port; no legitimate npm use case |
| Node.js parent process accessing browser Login Data or crypto wallet files | 95 | npm postinstall hooks have no legitimate need to read browser credential databases |
| Node.js HTTPS egress to ports ≥40000 | 85 | Anomalous for developer tooling; investigate destination and process lineage |
| Node.js parent accessing .env files | 80 | Environment files are valid npm build targets but access during install is suspicious |

## Associated Threat Actors

| Actor | MITRE ID | References |
|-------|----------|------------|
| Unknown (Unit 42 campaign CL-STA attribution pending) | — | [Unit 42 2026-08-06 Disclosure](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-08-06-Obfuscated-JavaScript-Crypto-Stealer.txt) |
| Lazarus Group / Contagious Interview (DPRK) | G0032 | [MITRE ATT&CK G0032](https://attack.mitre.org/groups/G0032/) — technique overlap in npm-based crypto developer targeting |
| NullReceiver (DPRK npm, A10-npm3 campaign) | — | [Related: 2026-08-05 report](../../../threat-intel/2026-08-05_nullreceiver-dprk-npm-ethereum-c2-contagious-interview.md) |

## References

- [Unit 42: Obfuscated JavaScript Crypto Stealer (2026-08-06)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-08-06-Obfuscated-JavaScript-Crypto-Stealer.txt)
- [MITRE ATT&CK — T1195.002: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK — T1555.003: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK — T1005: Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [MITRE ATT&CK — T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK — T1571: Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- [Threat Intel Report: Unit 42 npm Crypto Stealer](../../../threat-intel/2026-08-11_unit42-obfuscated-javascript-npm-crypto-stealer.md)
