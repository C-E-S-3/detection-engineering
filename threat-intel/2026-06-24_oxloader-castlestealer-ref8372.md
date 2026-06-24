# OXLOADER + CastleStealer — Campaign REF8372

**Source:** BleepingComputer, Elastic Security (REF8372)  
**Date:** 2026-06-22  
**Attribution:** Russian-speaking, financially motivated threat actors  
**Status:** ACTIVE — ongoing Google Ads malvertising campaign

## Summary

Campaign REF8372 uses malicious Google Ads to deliver OXLOADER, a multi-stage loader that installs CastleStealer on victim Windows systems. CastleStealer is a sophisticated information stealer targeting browser credentials, cryptocurrency wallets, and Telegram session data.

## Attack Chain

1. **Malvertising**: Victim searches for popular software (e.g., WinRAR, 7-Zip, PDF editors) on Google; malicious ad appears above organic results
2. **Landing Page**: Victim redirected to lookalike download site with convincing UI
3. **Download**: OXLOADER installer downloaded (often mimics legitimate software installer MSI/EXE)
4. **OXLOADER Stage 1**: Installer drops multiple executables to %TEMP% in rapid succession; uses multiple obfuscation layers
5. **OXLOADER Stage 2**: PowerShell loader downloads CastleStealer DLL from C2
6. **CastleStealer**: Harvests credentials and exfiltrates to Russian C2 infrastructure

## CastleStealer Targets

- **Browsers**: Chrome, Firefox, Edge, Brave, Opera (Login Data, Cookies, Web Data SQLite DBs)
- **Crypto Wallets**: Exodus, Electrum, MetaMask (browser extension), Binance, atomic wallet
- **Messaging**: Telegram Desktop (tdata session files), Discord tokens
- **VPN/RDP**: saved VPN credentials, RDP credentials from Credential Manager

## IOCs

### File Paths (CastleStealer staging)
- `%TEMP%\ox[random8].exe`
- `%APPDATA%\Roaming\[random5]\[random8].dll`
- `%TEMP%\cs_stage[1-3].bin`

### Registry Persistence
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` → OXLOADER persistence

## MITRE ATT&CK

| Technique | Description |
|-----------|-------------|
| T1566.002 | Phishing: Spearphishing Link |
| T1204.001 | User Execution: Malicious Link |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers |
| T1555 | Credentials from Password Stores |
| T1071.001 | C2: Application Layer Protocol Web |
| T1041 | Exfiltration Over C2 Channel |

## Detection

Wazuh rules: 103613–103617
