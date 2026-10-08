---
scraped_at: "2026-10-08T12:00:00Z"
source_url: "https://checkmarx.com/zero-post/malfex-npm-malware-campaign-three-payloads-and-an-adversary-that-signs-their-work/"
report_type: threat-intel
severity: high
title: "MALFEX: Long-Running npm Supply Chain Campaign Delivers Overlord RAT and Credential Stealer via AutoIt PNG Steganography"
---

## 1. Indicators of Compromise (IOCs)

### File Hashes (SHA-256)

| Hash | Type | Description |
|------|------|-------------|
| `9aba4685af072231aee049e1a5e294965580001b364d7d00152d84fcec1ce793` | SHA256 | Overlord RAT loader concealed in `banner.png` via steganography |
| `fd199d3977e1a2945b6031fc8696660a980e4f4617899baa045efe7ccbc8de67` | SHA256 | Encrypted AutoIt script (`Oxygen.a3x` / `h.a3x`) — Overlord RAT body |
| `2989244eac2a4bc7a13a09dec003e5c05ef7c80b2afe0958ce25042d5b804210` | SHA256 | Decoded Overlord RAT payload (AutoIt-compiled) |
| `4f4f7d64139bde6d458a061c7fb7dd247f70f60a1ab47d87fd3634656586c106` | SHA256 | `banner.png` steganographic payload carrier (current as of report date) |
| `889e13e227bc2b762178b88c35c691db3256e72be64d92ff1f381d29a2789849` | SHA256 | Stealer-chain downloader stage (observed 2026-09-25) |
| `e7f86f6cc4380db66d333eaf6f7dfc2c12d232c2bcd526434681245dea25efa4` | SHA256 | Stealer-chain downloader stage (observed 2026-09-25) |
| `5d69a932a077fee044b193c28e84564143f5c7e51079ab48e88fef74ab0b77b7` | SHA256 | Legitimate signed `AutoIt3.exe` used as LOLBin to execute encrypted .a3x script — do not block hash alone |

### Malicious npm Packages

| Package Name | Downloads | Status (2026-10-08) |
|---|---|---|
| `function-flag` | ~37,000+ | Still available at report time; malicious since July 2025 |
| `function-color` | Included in ~40,767 total | Still available |
| `cdn-img-fetch` | Included in ~40,767 total | Still available |
| `img-to-native` | — | Flagged malicious |
| `native-runner` | — | Flagged malicious |
| `tlxbnhd` | — | Flagged malicious |
| `tldriver` | — | Flagged malicious |
| `mxdriver` | — | Flagged malicious |

### GitHub C2 Payload Hosting

| Indicator | Type | Notes |
|-----------|------|-------|
| `raw.githubusercontent.com/cavecrew/proj/main/banner.png` | URL | GitHub raw URL hosting the steganographic `banner.png` payload carrier |
| `github.com/cavecrew` | GitHub account | Account hosting MALFEX campaign payloads |

### Operator Handle

| Indicator | Notes |
|-----------|-------|
| `Murizada` | Handle found in one package README listed as Malfex team owner (CloudSEK attribution) |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Usage |
|--------|-----------|----|-------|
| Initial Access | Supply Chain Compromise: Compromise Software Dependencies | T1195.001 | Eight malicious npm packages with 40,767+ downloads; `postinstall` hooks execute malware at package installation time |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | npm `postinstall` script runs Node.js code to download and execute the payload chain |
| Execution | System Binary Proxy Execution: Compiled HTML File | T1218 | Legitimate signed `AutoIt3.exe` used as LOLBin to execute encrypted `.a3x` script containing Overlord RAT |
| Defense Evasion | Obfuscated Files or Information: Steganography | T1027.003 | Overlord RAT loader hidden inside a PNG file (`banner.png`) hosted on GitHub; extracted at runtime |
| Defense Evasion | Masquerading | T1036 | Malicious packages use plausible developer utility names (`function-flag`, `cdn-img-fetch`, etc.) |
| Defense Evasion | Install as Root | T1548 | Windows-only payloads; silently fails on macOS/Linux; installation completes even if payload download fails |
| Credential Access | Credentials from Web Browsers | T1555.003 | Stealer chain exfiltrates browser-stored passwords, cookies, and Discord tokens |
| Collection | Data from Local System | T1005 | Credential stealer targets browser password vaults, Discord tokens, and cryptocurrency wallet files |
| Command and Control | Web Service | T1102 | Overlord RAT resolves C2 address from encrypted Solana transaction memos (novel technique; not observed in analyzed sample per Checkmarx) |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| **Overlord RAT** | Remote Access Trojan | AutoIt-compiled Windows RAT; encrypted in `.a3x` format; executed via legitimate signed `AutoIt3.exe`; novel C2 resolution via Solana blockchain transaction memos |
| **Movinlike Stealer** | Credential Stealer | Browser password/cookie/Discord token stealer deployed in the second payload chain; easily rebuilt, so hash-only detection is insufficient |
| **AutoIt3.exe** | LOLBin (legitimate) | Legitimate signed AutoIt interpreter used to execute encrypted `.a3x` RAT scripts; the signed binary itself is not malicious |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Campaign Name | MALFEX (Checkmarx / CloudSEK designation) |
| Operator Handle | Murizada (self-attributed) |
| Activity Start | August 2023 (first malicious package; 12 total packages, 8 confirmed malicious) |
| Scale | ~40,767 downloads across malicious packages |
| Target Platform | Windows (payloads fail silently on macOS/Linux) |
| Target Victims | npm-consuming developers (supply chain) |
| Attribution Confidence | Low (solo operator; no nation-state nexus identified) |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="node.exe"
    Processes.process_name IN ("AutoIt3.exe","AutoIt3_x64.exe","autoit3.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```
*Detects AutoIt3.exe spawned by node.exe — primary MALFEX execution chain; npm postinstall hook invoking AutoIt LOLBin.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("AutoIt3.exe","AutoIt3_x64.exe")
    (Processes.process="*.a3x*" OR Processes.process="*Oxygen*" OR Processes.process="*h.a3x*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```
*Detects AutoIt3.exe executing encrypted .a3x scripts — Overlord RAT execution stage in MALFEX campaign.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="raw.githubusercontent.com"
    All_Traffic.process_name IN ("node.exe","npm.exe","npm","node")
    All_Traffic.http_uri="*/cavecrew/*"
  by All_Traffic.src All_Traffic.dest_host All_Traffic.http_uri All_Traffic.process_name All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest_host http_uri process_name user risk_score
```
*Detects node/npm fetching raw GitHub content from the cavecrew account — MALFEX banner.png payload staging URL.*

```spl
index=* sourcetype="npm:audit" OR sourcetype="osquery"
(package_name IN ("function-flag","function-color","cdn-img-fetch","img-to-native",
  "native-runner","tlxbnhd","tldriver","mxdriver"))
| eval risk_score=90
| table _time host package_name package_version risk_score
```
*Detects installation of any of the eight MALFEX malicious npm packages via npm audit logs or osquery package enumeration.*

---

## 6. Executive Summary

Checkmarx and CloudSEK published joint research on October 5–8, 2026, documenting **MALFEX** — a long-running npm supply chain campaign operated by a single actor (handle: Murizada) since August 2023. The campaign deployed eight malicious packages that accumulated 40,767+ downloads, with `function-flag` alone reaching 37,000+ downloads while remaining unflagged for over a year. Packages use `postinstall` hooks to execute a multi-stage Windows payload chain: Node.js downloads a PNG file (`banner.png`) from a GitHub-hosted repository (`cavecrew`), extracts a hidden executable via steganography, then invokes legitimate signed `AutoIt3.exe` to run an encrypted `.a3x` script containing the **Overlord RAT**.

A secondary stealer chain targeting browser passwords, Discord tokens, and cryptocurrency wallets was also observed. Uniquely, the Overlord RAT is designed to resolve C2 server addresses from encrypted **Solana blockchain transaction memos** — a novel blockchain-based C2 resolution technique not yet observed in execution. Defenders should immediately audit npm dependencies for the eight malicious package names, block AutoIt3.exe execution from npm/Node.js processes, and monitor outbound Node.js connections to `raw.githubusercontent.com`.
