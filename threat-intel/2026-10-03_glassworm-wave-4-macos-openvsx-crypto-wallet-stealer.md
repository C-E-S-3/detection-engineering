---
scraped_at: "2026-10-04T00:00:00Z"
source_url: "https://www.paloaltonetworks.com/blog/security-operations/glassworm-goes-mac-fresh-infrastructure-new-tricks/"
report_type: threat-intel
severity: high
title: "GlassWorm Wave 4: macOS Developer Targeting via Trojanized OpenVSX Extensions and Trojanized Hardware Wallets"
---

# GlassWorm Wave 4: macOS Developer Targeting via Trojanized OpenVSX Extensions

## 1. IOCs

### C2 / Exfiltration Infrastructure

| Indicator | Type | Note |
|-----------|------|------|
| BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC | Solana address | Wave 4 blockchain dead-drop for C2 endpoint retrieval (same pattern as Wave 3 / GlassWASM) |
| 45.32.151.157 | IP | Primary C2 server (shared with GlassWASM/Wave 3 — infrastructure reuse confirmed) |
| 45.32.150.251 | IP | Exfiltration server (shared with GlassWASM/Wave 3) |

Note: IPs 45.32.151.157 and 45.32.150.251 were previously tracked from the GlassWASM (Wave 3) campaign in June 2026. Wave 4 reuses the same infrastructure.

### Malicious OpenVSX Extension Identifiers

| Extension ID | Description |
|-------------|-------------|
| studio-velte-distributor.pro-svelte-extension | Trojanized Svelte extension on OpenVSX |
| cudra-production.vsce-prettier-pro | Trojanized Prettier extension on OpenVSX |
| Puccin-development.full-access-catppuccin-pro-extension | Trojanized Catppuccin theme extension on OpenVSX |

## 2. TTPs

| Tactic | Technique | Detail |
|--------|-----------|--------|
| Initial Access | T1195.001 – Supply Chain: Compromise Software Dependencies | Publishes malicious extensions to OpenVSX marketplace mimicking popular VSCode extensions |
| Execution | T1059.002 – AppleScript | Uses osascript (AppleScript) instead of PowerShell; Wave 4 is first macOS-only wave |
| Execution | T1204.002 – User Execution: Malicious File | 15-minute execution delay; AES-256-CBC encrypted payload in compiled JavaScript to evade static analysis |
| Persistence | T1543.001 – Launch Agent | Establishes persistence via macOS LaunchAgent plist in ~/Library/LaunchAgents/ |
| Credential Access | T1528 – Steal Application Access Token | Steals GitHub, npm, and OpenVSX credentials |
| Credential Access | T1539 – Steal Web Session Cookie | Harvests tokens from 50+ browser extension crypto wallets |
| Command and Control | T1102 – Web Service | Retrieves C2 server address from Solana blockchain transaction memo field (dead-drop) |
| Impact | T1496 – Resource Hijacking / T1565 – Data Manipulation | Replaces Ledger Live and Trezor Suite with trojanized versions to compromise hardware wallet transactions |

### Wave 4 Technical Innovations vs Prior Waves

| Feature | Waves 1–3 (Windows) | Wave 4 (macOS) |
|---------|---------------------|----------------|
| Platform | Windows | macOS only |
| Payload obfuscation | Plain/minified JS | AES-256-CBC encrypted payload in compiled JavaScript |
| Execution delay | Immediate or short | 15 minutes (sandbox evasion) |
| Shell | PowerShell | AppleScript (osascript) |
| Persistence | Registry Run keys | LaunchAgent plists |
| C2 retrieval | Solana blockchain dead-drop | Solana blockchain dead-drop (unchanged) |
| New target | — | Hardware wallet trojanization (Ledger Live, Trezor Suite) |

## 3. Malware & Tools

| Tool / Malware | Description |
|----------------|-------------|
| GlassWorm Wave 4 implant | macOS infostealer; loaded via AES-256-CBC encrypted payload in OpenVSX extension JavaScript |
| Trojanized Ledger Live | Replacement for the legitimate Ledger hardware wallet desktop app; harvests seed phrases and transaction data |
| Trojanized Trezor Suite | Replacement for the legitimate Trezor hardware wallet desktop app; in-development as of October 2026 |
| LaunchAgent plist | macOS persistence mechanism written to ~/Library/LaunchAgents/ |

## 4. Threat Actor / Campaign Attribution

| Field | Detail |
|-------|--------|
| Campaign | GlassWorm Wave 4 (aka "GlassWorm Goes Mac") |
| Previous waves | Wave 1-2: npm/PyPI supply chain (2025); Wave 3 / GlassWASM: VSCode marketplace + WASM stager (June 2026) |
| C2 infrastructure | Partially reused from Wave 3 (45.32.151.157, 45.32.150.251) |
| Target profile | macOS developers using VSCode-compatible editors (Cursor, VSCodium) and the OpenVSX marketplace |
| Credential targets | GitHub, npm, OpenVSX tokens; 50+ browser extension crypto wallets (MetaMask, Phantom, Coinbase Wallet, Exodus, etc.) |
| Hardware wallet targets | Ledger Live, Trezor Suite (trojanized replacement binaries; functionality described as still in development) |

Wave 4 represents a significant capability expansion for GlassWorm: the shift from Windows to macOS uses platform-native execution (AppleScript, LaunchAgents) and introduces AES-256-CBC payload encryption to defeat static analysis tools. The Solana blockchain C2 retrieval mechanism is unchanged from Wave 3, confirming the same threat actor. Infrastructure reuse (45.32.151.157 and 45.32.150.251) is consistent with prior GlassWorm operational security patterns.

## 5. Splunk Detection Searches

### VSCode Extension Host Spawning osascript (AppleScript) on macOS

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("extensionHost","code","cursor","vscodium")
    AND Processes.process_name="osascript"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Suspicious LaunchAgent Created by Developer Tooling

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*/Library/LaunchAgents/*"
    AND Filesystem.file_name="*.plist"
    AND Filesystem.process_name IN ("node","npm","extensionHost","code","cursor","vscodium","osascript","bash","sh","python3")
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

### Solana Blockchain C2 Dead-Drop

See `detections/command_and_control/glassworm_blockchain_solana_c2_beaconing.md` — the existing detection covers the Wave 4 Solana RPC beaconing pattern unchanged from Wave 3.

## 6. Executive Summary

GlassWorm Wave 4 marks the campaign's first macOS-specific wave, targeting developers who use VSCode-compatible editors with OpenVSX extensions. The delivery mechanism is similar to prior waves — malicious extensions published to the OpenVSX marketplace mimicking popular tools — but the payload is now AES-256-CBC encrypted within compiled JavaScript, and execution is delayed 15 minutes to defeat dynamic sandbox analysis. Once executed, the macOS implant persists via a LaunchAgent, steals developer credentials (GitHub, npm, OpenVSX), harvests 50+ browser extension crypto wallet tokens, and attempts to replace Ledger Live and Trezor Suite desktop applications with trojanized versions capable of intercepting hardware wallet transactions.

The C2 infrastructure (IPs 45.32.151.157 / 45.32.150.251) and Solana blockchain dead-drop technique are carried over from Wave 3, confirming the same threat actor. Developers should audit installed OpenVSX extensions, verify extension publisher identity, monitor for unexpected LaunchAgent plist creation by developer tooling, and review Ledger Live / Trezor Suite binary integrity.

## References

- [Palo Alto Networks Blog — GlassWorm Goes Mac: Fresh Infrastructure, New Tricks](https://www.paloaltonetworks.com/blog/security-operations/glassworm-goes-mac-fresh-infrastructure-new-tricks/)
- [koi.ai — GlassWorm Goes Mac: Fresh Infrastructure, New Tricks](https://www.koi.ai/blog/glassworm-goes-mac-fresh-infrastructure-new-tricks)
- [koi.ai — Live Updates: GlassWorm First Self-Propagating Worm Using Invisible Code Hits OpenVSX](https://www.koi.ai/incident/live-updates-glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-and-vscode-marketplaces)
- [BleepingComputer — New GlassWorm Malware Wave Targets Macs with Trojanized Crypto Wallets](https://www.bleepingcomputer.com/news/security/new-glassworm-malware-wave-targets-macs-with-trojanized-crypto-wallets/)
- [Rewterz — GlassWorm Malware Targets macOS via Trojanized VSCode Extensions](https://rewterz.com/threat-advisory/glassworm-malware-targets-macos-via-trojanized-vscode-extensions-active-iocs)
- [Socket.dev — GlassWASM: Open VSX Extensions (Wave 3 reference)](https://socket.dev/blog/glasswasm-malware-open-vsx-extensions)
- [MITRE ATT&CK — T1195.001 Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK — T1102 Web Service (Blockchain C2)](https://attack.mitre.org/techniques/T1102/)
- [MITRE ATT&CK — T1543.001 Create or Modify System Process: Launch Agent](https://attack.mitre.org/techniques/T1543/001/)
