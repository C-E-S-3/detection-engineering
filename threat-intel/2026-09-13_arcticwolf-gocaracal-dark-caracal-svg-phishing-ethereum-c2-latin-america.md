---
scraped_at: "2026-09-13T00:00:00Z"
source_url: "https://arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/"
report_type: threat-intel
severity: high
title: "Dark Caracal GoCaracal — Go-Based RAT with Ethereum Smart Contract C2 Fallback Targeting Latin America; Arctic Wolf Labs August 2026"
---

## 1. IOCs

No specific file hashes, C2 IP addresses, or C2 domains are available from open-source sources at time of writing. Arctic Wolf Labs confirmed 24 unique C2 addresses extracted from 249 GoCaracal samples (23 of 24 on AEZA Group / AS210644 infrastructure), but the full IOC set is restricted to Arctic Wolf customer access and was not reproduced in open-source coverage. The Ethereum contract address for the "BulletproofC2" fallback resolver was similarly not published in open-source reporting.

**Behavioral indicators (host):**
- Go-compiled ELF or PE binary with unusually high number of exported function symbols (~34 command handlers in extended build)
- Process making `eth_getStorageAt` JSON-RPC calls to public Ethereum endpoints
- SVG file open triggering child browser or script interpreter process
- Keylogger activity (extended build: window-title-tagged keystrokes written to encrypted local buffer)
- SOCKS5 proxy listener on localhost (extended build)
- WebRTC peer connection establishment from non-browser process (extended build remote desktop)

**Behavioral indicators (network):**
- HTTPS connections from non-browser processes to Ethereum JSON-RPC endpoints (cloudflare-eth.com, mainnet.infura.io, eth-mainnet.g.alchemy.com, rpc.ankr.com, ethereum.publicnode.com, 1rpc.io) — Ethereum fallback C2 resolution
- Custom AES-GCM encrypted TCP C2 (primary channel); no cleartext protocol identifier
- URL shortener redirect chains immediately followed by binary download (initial access delivery)

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|-------------|-------------|----------------|-------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | SVG file email attachment (Spanish-language financial/tax lures); embedded JavaScript executes on SVG open and initiates redirect chain to GoCaracal payload download |
| Execution | T1059 | Command and Scripting Interpreter | JavaScript embedded in SVG attachment triggers execution of redirect chain without requiring additional user interaction beyond file open |
| Execution | T1204.002 | User Execution: Malicious File | Victim opens SVG attachment; on many platforms SVG opens in browser context which executes the embedded JS |
| Persistence | T1547 | Boot or Logon Autostart Execution | Extended build installs persistence mechanism (specific registry/service method not disclosed in open-source coverage) |
| Credential Access | T1056.001 | Input Capture: Keylogging | Extended build captures keystrokes with window-title context |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Extended build harvests browser-stored credentials |
| Discovery | T1082 | System Information Discovery | Lightweight build performs host enumeration (OS version, hardware, user, domain) on first execution |
| Discovery | T1083 | File and Directory Discovery | Extended build enumerates filesystem for collection targeting |
| Lateral Movement | T1021 | Remote Services | Extended build implements WebRTC-based remote desktop capability for interactive operator access |
| Command and Control | T1573.001 | Encrypted Channel: Symmetric Cryptography | Primary C2 channel uses AES-GCM encrypted custom TCP protocol |
| Command and Control | T1568 | Dynamic Resolution | Ethereum smart contract fallback C2: after primary C2 failure, GoCaracal calls `eth_getStorageAt` against "BulletproofC2" Solidity contract on Ethereum mainnet to retrieve replacement C2 address; operator rotates infrastructure by updating a single contract storage slot |
| Command and Control | T1102.002 | Web Service: Bidirectional Communication | `eth_getStorageAt` JSON-RPC query to public Ethereum node retrieves operator-controlled C2 address from blockchain state |
| Command and Control | T1008 | Fallback Channels | Ethereum blockchain functions as fallback when primary off-chain C2 is unreachable or burned |
| Command and Control | T1090.003 | Proxy: Multi-hop Proxy | Extended build includes SOCKS5 proxy module for traffic routing through compromised hosts |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Harvested credentials, keylog data, and files sent over primary AES-GCM C2 channel |

### Attack Chain

1. **Delivery**: Victim receives Spanish-language phishing email with malicious SVG attachment themed around financial/tax documents.
2. **Execution**: SVG is opened (browser or image viewer); embedded JavaScript executes without additional user prompts on most platforms.
3. **Payload staging**: JavaScript initiates a redirect chain through a URL shortener to an attacker-controlled payload staging server on AEZA Group (AS210644) infrastructure.
4. **Installation**: GoCaracal binary (lightweight or extended build) is downloaded and executed; establishes persistence (extended build).
5. **Initial C2**: Implant connects to hardcoded primary C2 server via AES-GCM encrypted custom TCP protocol; performs host enumeration.
6. **Fallback C2 activation**: If primary C2 is unreachable, implant queries the "BulletproofC2" Ethereum smart contract using `eth_getStorageAt` against a public JSON-RPC node to retrieve a replacement C2 address.
7. **Actions on objectives**: Extended build performs keylogging, browser credential harvesting, WebRTC remote desktop, file collection, and SOCKS5 proxying for lateral movement support.

## 3. Malware & Tools

| Tool | Description |
|------|-------------|
| GoCaracal (lightweight build) | Go-compiled RAT; host enumeration, interactive shell, file download/execution, shellcode loading/injection, AES-GCM encrypted custom C2 protocol |
| GoCaracal (extended build) | Go-compiled RAT with 34 command handlers; adds keylogging, browser credential theft, WebRTC remote desktop, SOCKS5 proxying, persistence, and Ethereum smart contract C2 fallback |
| Bandook (updated variant) | Dark Caracal legacy RAT deployed alongside GoCaracal in the June 2026 Venezuela intrusion; GoCaracal complements rather than replaces Bandook |
| Delphi loader | Recurring loader component used to deliver and execute GoCaracal/Bandook payloads; long-running Dark Caracal infrastructure characteristic |
| "BulletproofC2" Ethereum smart contract | Attacker-deployed Solidity contract storing a mutable C2 address; queried via `eth_getStorageAt` as resilient fallback; tested on Ethereum Sepolia testnet before mainnet deployment |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| **Threat Actor** | Dark Caracal (MITRE G0070) |
| **Historical Attribution** | Lebanese General Directorate of General Security (GDGS); medium-confidence persistent attribution from prior Lookout/EFF and Citizen Lab reporting; not independently reasserted in August 2026 Arctic Wolf analysis |
| **Activity Period** | GoCaracal samples tracked January 2026 – July 2026 (249 samples analyzed by Arctic Wolf); confirmed intrusion: June 2026 (Venezuelan communications organization) |
| **Motivation** | Cyber espionage / intelligence collection |
| **Targeting** | Confirmed: Venezuela (communications sector). Assessed: broader Latin America — Brazil, Ecuador, Chile, Colombia, El Salvador, Uruguay; Spanish-language lures consistent with regional targeting |
| **C2 Hosting** | 23 of 24 extracted C2 addresses hosted on AEZA Group (AS210644) bulletproof hosting; AEZA Group has recurring association with Eastern European and Russian-language cybercrime and espionage infrastructure |
| **Infrastructure Separation** | GoCaracal and Bandook C2 infrastructure intentionally kept separate (different hosting), limiting blast radius of infrastructure takedowns |
| **Sample Set** | 249 GoCaracal samples (Arctic Wolf), 2 distinct build profiles (lightweight and extended) |
| **Tooling Evolution** | GoCaracal represents a significant modernization from Dark Caracal's historical Delphi-based tooling; the shift to Go provides cross-platform compilation and improved operational security through Go's memory safety and static compilation |

## 5. Splunk Detection Searches

The existing [EtherHiding Ethereum Smart Contract C2 Dead Drop](../../detections/command_and_control/etherhiding_ethereum_smart_contract_c2.md) detection directly covers GoCaracal's Ethereum fallback C2 channel. The searches below complement it with GoCaracal-specific initial access (SVG phishing) and initial execution indicators.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("msedge.exe","chrome.exe","firefox.exe","iexplore.exe","opera.exe","brave.exe")
    AND Processes.process_name NOT IN ("msedge.exe","chrome.exe","firefox.exe","iexplore.exe",
      "opera.exe","brave.exe","chrome_crashpad_handler.exe","crashpad_handler.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)powershell|pwsh|cmd\.exe|wscript|cscript|mshta"), 90,
    match(process_name, "(?i)curl|wget|certutil|bitsadmin"), 85,
    match(process_name, "(?i)python|node\.exe|go\.exe"), 75,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```
**Detects:** Process spawned from a browser after SVG file open — the JavaScript in a GoCaracal SVG attachment executing a command or download via a child process spawned from the browser. Browser-spawning non-browser processes (PowerShell, cmd, curl, certutil) is a high-fidelity indicator of malicious SVG/HTML execution.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.svg"
    AND Filesystem.action IN ("created","write")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)\\\\downloads\\\\|\\\\temp\\\\|\\\\appdata\\\\local\\\\temp"), 80,
    match(file_path, "(?i)\\\\desktop\\\\|\\\\documents\\\\"), 70,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime dest user file_path file_name risk_score
```
**Detects:** SVG file written to user-facing locations (Downloads, Desktop, Documents, Temp) — a precursor indicator for GoCaracal SVG phishing delivery; low specificity alone but high value when correlated with subsequent browser child process execution in the same host+timeframe.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host IN (
      "cloudflare-eth.com", "mainnet.infura.io", "eth-mainnet.g.alchemy.com",
      "rpc.ankr.com", "ethereum.publicnode.com", "rpc.flashbots.net",
      "eth.llamarpc.com", "1rpc.io", "eth.drpc.org", "ethereum.drpc.org"
    )
    AND NOT All_Traffic.app IN (
      "chrome","firefox","msedge","brave","safari","chromium","opera","vivaldi","iexplore"
    )
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
     All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_host dest_port app process_name risk_score
```
**Detects:** Non-browser process connecting to Ethereum JSON-RPC endpoints — GoCaracal's Ethereum fallback C2 resolver (`eth_getStorageAt` to "BulletproofC2" contract). Any non-browser process connecting to Ethereum nodes on an enterprise endpoint is anomalous. Correlation: run within a 10-minute window against the SVG file write detection above on the same host for high-confidence GoCaracal staging indicator.

## 6. Executive Summary

GoCaracal is a new Go-based RAT framework attributed with medium confidence to Dark Caracal (MITRE G0070), a threat actor historically linked to Lebanese intelligence (GDGS). Arctic Wolf Labs published an analysis on August 27, 2026, covering 249 samples tracked from January to July 2026, anchored by a confirmed June 2026 intrusion into a Venezuelan communications organization.

GoCaracal comes in two build profiles: a lightweight variant performing host enumeration, shell access, and AES-GCM encrypted C2; and an extended variant adding keylogging, browser credential theft, WebRTC-based remote desktop, SOCKS5 proxying, and the headline capability — a Ethereum smart contract fallback C2 channel. The extended build queries an attacker-controlled Solidity contract named "BulletproofC2" via `eth_getStorageAt` against public Ethereum JSON-RPC endpoints when the primary off-chain C2 is unreachable. This is an EtherHiding-family technique: the operator can rotate burned infrastructure by publishing a single Ethereum transaction, without pushing a new payload to victims. Arctic Wolf found evidence of the contract being tested on the Ethereum Sepolia testnet before mainnet deployment, indicating deliberate capability development.

Initial delivery uses Spanish-language financial and tax-themed phishing emails with malicious SVG attachments. SVG files can contain and execute JavaScript without requiring a user to enable macros, making them a lower-friction alternative to malicious Office documents in regions and enterprises where macro execution has been hardened. GoCaracal was deployed alongside an updated Bandook variant in the observed intrusion.

23 of 24 extracted C2 addresses were hosted on AEZA Group (AS210644) bulletproof hosting. The shift to Go represents a significant modernization of Dark Caracal's historically Delphi-based tooling, improving cross-platform portability and operational security.

**Recommended actions:**
1. Deploy the [EtherHiding detection](../../detections/command_and_control/etherhiding_ethereum_smart_contract_c2.md) to alert on non-browser Ethereum JSON-RPC connections (covers GoCaracal fallback C2)
2. Alert on browser-spawned non-browser processes (PowerShell, cmd, curl) as an SVG phishing execution indicator
3. Block or alert on employee receipt of SVG email attachments at the email gateway — SVG is not a standard business document format and has low legitimate use in financial/tax communications
4. Add Ethereum JSON-RPC provider domains to URL filtering policy for endpoints that have no blockchain development use case
5. Hunt for Go-compiled binaries with unusually high exported symbol counts in endpoint telemetry

## References

- [Arctic Wolf Labs — Dark Caracal Reloaded: New Malware, Same Hunting Grounds (2026-08-27)](https://arcticwolf.com/resources/blog/dark-caracal-reloaded-new-malware-same-hunting-grounds/)
- [The Hacker News — GoCaracal Malware Uses Ethereum Smart Contract to Fetch Replacement C2 Address (2026-08)](https://thehackernews.com/2026/08/gocaracal-malware-uses-ethereum-smart.html)
- [Security Affairs — Dark Caracal Deploys New Go Malware With Ethereum-Based C2 Fallback (2026-08)](https://securityaffairs.com/197948/apt/dark-caracal-deploys-new-go-malware-with-ethereum-based-c2-fallback.html)
- [MITRE ATT&CK — Dark Caracal (G0070)](https://attack.mitre.org/groups/G0070/)
- [MITRE ATT&CK — T1566.001 Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK — T1568 Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
- [MITRE ATT&CK — T1102.002 Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK — T1008 Fallback Channels](https://attack.mitre.org/techniques/T1008/)
- [Detection — EtherHiding Ethereum Smart Contract C2 Dead Drop](../../detections/command_and_control/etherhiding_ethereum_smart_contract_c2.md)
