---
scraped_at: 2026-06-22T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
report_type: threat-intel
severity: high
title: "CryptoBandits: USB LNK Worm Spreading Tor-Backed Crypto Clipboard Hijacker (Microsoft, June 2026)"
---

## 1. IOCs

### File Hashes (SHA-256) — Malware Samples

| Hash | Type | Notes |
|------|------|-------|
| `7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c` | SHA-256 | CryptoBandits dropper/component |
| `a7abf1d9d6686af1cefcd60b17a312e7eb8cfe267def1ec34aeab6128c811630` | SHA-256 | CryptoBandits dropper/component |
| `23c1e673f315dafa14b73034a90dd3d393a984451ff6601b8be8142be6487b43` | SHA-256 | CryptoBandits dropper/component |
| `cf9fc891ea5ca5ecd8113ef3e69f6f52ff538b6cccbdaa9559106fc72bc6da30` | SHA-256 | CryptoBandits dropper/component |
| `100407796028bf3649752d9d2a67a0e4394d752eb8de86daa42920e814f3fae8` | SHA-256 | CryptoBandits dropper/component |
| `d14b80cbd1a19d4ad0473a0661297f8fdf598e81ff6c4ab24e212dcad2e54b3f` | SHA-256 | CryptoBandits dropper/component |
| `9d90f54ae36c6c5435d5b8bed40faf54cc91f6db28574a6310b5ffaeb0362e96` | SHA-256 | CryptoBandits dropper/component |
| `67fc5cf395e28294bbb91ed0e954fdf2e80ebd9119022a115a42c286dc8bacf5` | SHA-256 | CryptoBandits dropper/component |
| `0020d23b0f9c5e6851a7f737af73fd143175ee47054931166369edd93338538a` | SHA-256 | CryptoBandits dropper/component |
| `35a6bc44b176a050fd6824904b7604f0f45b0fdfa26bf9500b9e05973b387cfd` | SHA-256 | CryptoBandits dropper/component |
| `c824630154ac4fdfce94ded01f037c305eab51e9bef3f493c60ff3184a640502` | SHA-256 | CryptoBandits dropper/component |
| `d43bf94f0cb0ab97c88113b7e07d1a4024d1610617b5ad05882b1dbab89e15ba` | SHA-256 | CryptoBandits dropper/component |
| `b2777b73a4c33ac6a409d475057843be6b5d32262ef28a1f1ff5bb52e3834c5f` | SHA-256 | CryptoBandits dropper/component |
| `7787a9a7d8ae393aa32f257d083903c4dc9b97a1e5b0458c4cd480d4f3cb5b05` | SHA-256 | CryptoBandits dropper/component |
| `f3b54984caca95fd496bcfe5d7db1611b08d2f5b7d250b43b430e5d76393f9e0` | SHA-256 | CryptoBandits dropper/component |
| `20db98af3037b197c8a846dbf17b87fc6f049c3e0d9a188f9b9a74d3916dd5e1` | SHA-256 | CryptoBandits dropper/component |

### C2 Infrastructure — Tor Hidden Service (.onion) Addresses

| Indicator | Type | Notes |
|-----------|------|-------|
| `cgky6bn6ux5wvlybtmm3z255igt52ljml2ngnc5qp3cnw5jlglamisad.onion` | .onion | CryptoBandits C2; beacon via /route.php |
| `gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad.onion` | .onion | CryptoBandits C2 |
| `he5vnov645txpcv57el2theky2elesn24ebvgwfoewlpftksxp4fnxad.onion` | .onion | CryptoBandits C2 |
| `lyhizqy2js2eh6ufngkbzntouiikdek5zsdj3qwa22b4z6knpqorgiad.onion` | .onion | CryptoBandits C2 |
| `j3bv7g27oramhbxxuv6gl3dcyfmf44qnvju3offdyrap7hurfprq74qd.onion` | .onion | CryptoBandits C2 |
| `shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid.onion` | .onion | CryptoBandits C2 |
| `7goms4byw26kkbaanz5a5u5234gusot7rp5imzc3ozh66wwcvmcudjid.onion` | .onion | CryptoBandits C2 |
| `facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion` | .onion | CryptoBandits C2; Facebook-impersonating name |
| `wt26llpl5k6gok3vnaxmucwgzv2wk3l7nuibbh25clghrtus3p5ctsid.onion` | .onion | CryptoBandits C2 |
| `ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion` | .onion | CryptoBandits C2 |

### File System Artifacts

| Indicator | Type | Notes |
|-----------|------|-------|
| `C:\Users\Public\Documents\[5-char]\[5-char].js` | File path | Staging directory for malicious JS payload; e.g. `omoho\` |
| `ugate.exe` | Filename | Bundled Tor proxy binary (renamed from official Tor binary) |
| `localhost:9050` | Network | SOCKS5 proxy port; all C2 traffic routes through this Tor proxy |

### C2 Endpoint Paths (on .onion servers)

| Path | Purpose |
|------|---------|
| `/route.php` | Beacon and command retrieval |
| `/recvf.php` | Stolen file upload (screenshots, clipboard dumps) |
| `/stub.php` | Additional payload download |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1091 | Replication Through Removable Media | Malicious LNK shortcuts on USB drives; replaces document files (.doc/.xlsx/.pdf) with LNK shortcuts bearing the same names |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | WScript + ActiveXObject-driven JS payload execution; dual-layer XOR-encrypted JavaScript |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell invoked during initial infection chain |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | Scheduled task created with XML wrapper for persistence across reboots |
| Defense Evasion | T1027 | Obfuscated Files or Information | Dual-layer JavaScript encryption; PyArmor-protected Python installer |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Adds Defender exclusions for staging folder (`C:\Users\Public\Documents\[5-char]`) |
| Defense Evasion | T1057 | Process Discovery | Queries running processes; exits if Task Manager is detected (sandbox/analyst evasion) |
| Collection | T1115 | Clipboard Data | High-frequency clipboard polling (~500ms); replaces BTC/ETH/Monero/Tron wallet addresses with attacker-controlled ones; also targets BIP39 12/24-word seed phrases and WIF private keys |
| Collection | T1113 | Screen Capture | Exfiltrates 5 screenshots at 10-second intervals to C2 via /recvf.php |
| Command and Control | T1090.003 | Proxy: Multi-hop Proxy | All C2 traffic routed through Tor via localhost SOCKS5 proxy (ugate.exe) |
| Exfiltration | T1048.002 | Exfiltration Over Alternative Protocol | HTTP POST over Tor to .onion hidden services |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| CryptoBandits | Crypto Clipper + USB Worm | Detected by Microsoft Defender as `Trojan:Win32/CryptoBandits.A`, `Trojan:Win32/CryptoBandits.B`, `Trojan:JS/CryptoBandits.A`, `Trojan:JS/CryptoBandits.B` |
| ugate.exe | Tor Proxy | Official Tor binary renamed and bundled; configures SOCKS5 on localhost:9050 |
| PyArmor/PyInstaller | Obfuscation packer | Python installer component packed with PyArmor and PyInstaller |

### Targeted Cryptocurrency Wallet Formats

- Bitcoin: legacy (1*), P2SH (3*), Taproot (bc1p*), Bech32 (bc1q*)
- Tron (T*)
- Monero (4/* and 8/*)
- BIP39 12/24-word seed phrases
- Ethereum/Bitcoin WIF private keys

---

## 4. Threat Actor / Campaign Attribution

No specific threat actor or group attribution provided by Microsoft. The campaign has been active since at least **February 2026** with quiet operation until Microsoft disclosure on June 17, 2026.

The use of the Tor network for all C2 communications and the financial focus on cryptocurrency theft (clipboard hijacking + seed phrase/private key collection) suggests financially motivated cybercrime.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name IN ("wscript.exe","cscript.exe")
    AND Processes.parent_process_name="explorer.exe"
    AND match(Processes.process, "Users\\\\Public\\\\Documents"))
   OR Processes.process_name="ugate.exe"
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="ugate.exe", 95,
    match(process,"Users\\\\Public\\\\Documents\\\\[a-z]{5}"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="schtasks.exe"
    AND Processes.parent_process_name IN ("wscript.exe","cscript.exe","powershell.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="powershell.exe"
    AND match(Processes.process, "(?i)(Add-MpPreference|ExclusionPath)")
    AND match(Processes.process, "(?i)Users\\\\Public\\\\Documents")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

## 6. Executive Summary

Microsoft disclosed on June 17, 2026 a cryptocurrency-targeting clipboard hijacker campaign dubbed **CryptoBandits**, active since February 2026. The malware spreads via USB drives using Windows LNK shortcut files (.lnk), which replace legitimate document files to trigger execution when victims open what they believe to be normal documents.

Once installed, the malware deploys a bundled Tor proxy (`ugate.exe`) and routes all C2 communications through Tor hidden services (.onion addresses), making network-layer detection difficult. The malware polls the clipboard every ~500 milliseconds to intercept and replace cryptocurrency wallet addresses for Bitcoin (four address format types), Ethereum, Tron, and Monero. It also exfiltrates BIP39 seed phrases, WIF private keys, and periodic screenshots.

Persistence is achieved via scheduled tasks. The malware actively evades analysis by detecting Task Manager and exiting. Microsoft provides 16 SHA-256 file hashes and 10 Tor .onion C2 addresses as IOCs. Detection opportunities include: `ugate.exe` execution, WScript/CScript spawned from Explorer via `C:\Users\Public\Documents\` paths, schtasks spawned from scripting engines, and Defender exclusion additions for user-writable directories.

---

## References

- [Microsoft Security Blog — CryptoBandits (2026-06-17)](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/)
- [BleepingComputer — USB worm spreads crypto-stealing malware via Windows shortcut files (2026-06-21)](https://www.bleepingcomputer.com/news/security/usb-worm-spreads-crypto-stealing-malware-via-windows-shortcut-files/)
- [MITRE ATT&CK — T1091: Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/)
- [MITRE ATT&CK — T1115: Clipboard Data](https://attack.mitre.org/techniques/T1115/)
