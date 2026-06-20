---
scraped_at: 2026-06-20T00:00:00Z
source_url: https://socket.dev/blog/glasswasm-malware-open-vsx-extensions
report_type: threat-intel
severity: high
title: "GlassWASM: WebAssembly Malware in Trojanized Open VSX Extensions Using Solana Blockchain C2 Dead Drop (June 2026 Resurgence)"
---

## 1. IOCs

### File / Package Indicators

| Indicator | Type | Notes |
|-----------|------|-------|
| `ExarGD/vsblack@0.0.1` | Open VSX extension | Malicious theme clone uploaded 2026-06-09 by account `zaitoona43` |
| `noellee-doc/flint-debug@0.1.1` | Open VSX extension | Malicious blockchain debugger clone uploaded 2026-06-10 by account `zaitoona43` |

### IP Addresses (C2 Infrastructure)

| Indicator | Context |
|-----------|---------|
| `45.32.150.251` | GlassWASM C2 server (post-WASM loader second-stage) |
| `45.32.151.157` | GlassWASM C2 server |
| `70.34.242.255` | GlassWASM C2 server |

### Blockchain Indicators

| Indicator | Type | Context |
|-----------|------|---------|
| `BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC` | Solana wallet | Attacker-controlled wallet; WASM payload reads SPL Memo fields from transactions here as C2 dead-drop |
| `6YGcuyFRJKZtcaYCCFba9fScNUvPkGXodXE1mJiSzqDJ` | Solana wallet | Second attacker-controlled Solana wallet used as dead-drop C2 |

### Cryptographic Material

| Material | Value | Context |
|----------|-------|---------|
| AES key | `wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz` | Hardcoded ChaCha20 key within WASM module for hiding network indicators |
| AES IV | `c4b9a3773e9dced6015a670855fd32b` | Corresponding initialization vector |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | Trojanized Open VSX extensions injected with malicious WASM payload |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | WebAssembly loaded via Node.js `syscall/js` bridge at extension activation |
| Defense Evasion | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | TinyGo-compiled WebAssembly hides payload logic; ChaCha20 encrypts all network strings |
| Defense Evasion | T1036 | Masquerading | Extensions published under identity-cloned names matching legitimate VS Marketplace projects |
| Command and Control | T1102 | Web Service | Solana public RPC API polled for C2 instructions in SPL Memo transaction fields |
| Command and Control | T1102.001 | Web Service: Dead Drop Resolver | Solana blockchain transaction memos serve as immutable, censorship-resistant C2 dead drops |
| Collection | T1056.001 | Input Capture: Keylogging | GlassWASM stager delivers RAT with keylogging capability |
| Collection | T1539 | Steal Web Session Cookie | RAT targets browser session cookies and credentials |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Targets 50+ crypto wallets and browser credential stores |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Credentials and tokens exfiltrated via direct C2 channel to attacker-controlled IPs |

---

## 3. Malware & Tools

**GlassWASM** — WebAssembly-based stager compiled via TinyGo. Activated when extension is loaded by the editor. Polls Solana blockchain public RPC API for attacker instructions encoded as SPL Memo fields on transactions sent to attacker-controlled wallets. After receiving second-stage URL, contacts attacker C2 IPs directly. ChaCha20 encryption conceals all network indicators within the WASM binary. Node.js `syscall/js` bridge used for host execution.

**GlassWormRAT** — Second-stage RAT delivered by GlassWASM stager. Browser credential stealer, keylogger, crypto wallet exfiltrator.

This is the second wave of Open VSX-targeting activity by the GlassWorm threat actor. The original GlassWorm campaign (December 2025–March 2026) was disrupted by CrowdStrike, Google, and Shadowserver on May 26, 2026 (sinkhole at 164.92.88.210). The June 2026 GlassWASM variant uses new C2 infrastructure and WebAssembly obfuscation not present in the original campaign.

---

## 4. Threat Actor / Campaign Attribution

**GlassWorm** — Supply chain botnet assessed with medium confidence to be Russian-nexus based on targeting patterns (avoids post-Soviet CIS countries), infrastructure overlap, and operational security practices. Exclusively targets software developers through poisoned tooling (IDE extensions, npm packages, PyPI packages). Previously operated a four-channel resilient C2 (Solana memos, BitTorrent DHT, Google Calendar, direct VPS). After the May 2026 takedown, the actor pivoted to WebAssembly-based stagers (GlassWASM) to evade behavioral detection and introduced new Solana wallets and C2 IPs to replace sinkholed infrastructure.

Original campaign links:
- CrowdStrike May 26, 2026 takedown
- Sonatype npm Solana dead-drop analysis

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest IN ("45.32.150.251","45.32.151.157","70.34.242.255")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port app risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host IN ("api.mainnet-beta.solana.com","api.devnet.solana.com","solana-api.projectserum.com")
  AND All_Traffic.app IN ("node","npm","python","python3","code","code-server","cursor","vscodium")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| table firstTime lastTime src dest dest_host app risk_score
```

```spl
index=* (process_name="node" OR process_name="npm" OR process_name="python" OR process_name="python3")
  dest_host="api.mainnet-beta.solana.com"
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip dest_ip dest_host process_name user host
| where count > 5
| eval risk_score=65
| table firstTime lastTime host user process_name src_ip dest_ip dest_host count risk_score
```

---

## 6. Executive Summary

Socket Security disclosed on June 15–16, 2026 that the GlassWorm threat actor has returned following the May 26, 2026 takedown with a new WebAssembly-based malware family, GlassWASM. Two trojanized Open VSX extensions (`ExarGD/vsblack` and `noellee-doc/flint-debug`) were uploaded on June 9–10, 2026 by a fake publisher account (`zaitoona43`) using identity-cloned names matching legitimate VS Marketplace projects.

The WASM payload uses TinyGo compilation and ChaCha20 encryption to evade static analysis and signature-based detection. Rather than hardcoding C2 addresses, GlassWASM polls Solana blockchain transaction memo fields on two attacker wallets to receive second-stage payload URLs — a censorship-resistant dead-drop mechanism that survived the May 2026 sinkholing operation. The stager then contacts new C2 IPs (45.32.150.251, 45.32.151.157, 70.34.242.255) to download GlassWormRAT, which targets browser credentials, 50+ crypto wallets, and session cookies.

**Immediate actions:** Remove or block the malicious extensions if installed. Block the three new C2 IPs. Monitor for development-tool processes connecting to Solana RPC endpoints. The existing Glassworm Solana C2 detection covers the blockchain polling pattern.
