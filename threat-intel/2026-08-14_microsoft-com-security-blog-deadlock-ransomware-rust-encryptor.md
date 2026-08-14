---
scraped_at: 2026-08-14T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/
report_type: threat-intel
severity: high
title: "DeadLock Ransomware: Rust-Based Encryptor with Polygon Blockchain Decentralized Recovery Infrastructure"
---

# DeadLock Ransomware: Rust-Based Encryptor with Polygon Blockchain Decentralized Recovery Infrastructure

**Source:** Microsoft Security Blog  
**Published:** August 10, 2026  
**Severity:** High  

---

## 1. IOCs

### File Hashes

| Hash | Type | Description |
|------|------|-------------|
| `a1fdf65020ce4a0f0940c793c6425baf8a0b994ec48b9baaf72788661a9d29f4` | SHA256 | DeadLock ransomware encryptor binary (Rust-based) |

### Domains / Leak Sites

| Indicator | Context |
|-----------|---------|
| `deadlock.liveblog365[.]com` | Leak site / victim blog hosted on free blogging platform |
| `dlock.liveblog365[.]com` | Secondary leak site domain on liveblog365.com |
| `deadlockblog.great-site[.]net` | Leak site on free hosting; mirrors blockchain-based content |
| `deadlockblog.medianewsonline[.]com` | Additional leak site domain |

### Tor Hidden Services

| Indicator | Context |
|-----------|---------|
| `deadblogdbdu5wprek7wa2o4ce7rnt6u6ntqeud3hzjjcveosgpsqqqd[.]onion` | DeadLock Tor hidden service; hosts encrypted victim chat, data leak blog, and file browser via Session network + Wasabi S3 |

### Blockchain / Smart Contract Addresses (Polygon)

| Address | Context |
|---------|---------|
| `0x8EF7c3e531d871D3B9D559722DE77EB1dEc19dAe` | Polygon smart contract — victim-operator encrypted chat proxy (decentralized C2 fallback) |
| `0x757984507c82c8dA1d3969c535dB5706eEE6426C` | Polygon smart contract — leak blog configuration and victim index |

### Encrypted File Extension

- `.dlock` — appended to all encrypted files

### Ransom Note Filenames

- `HOW_RECOVER.<UID>.txt`
- `RECOVERY_CHAT.<UID>.html` (self-contained HTML app with embedded chat + data browser)

### Registry Keys Modified

- `HKLM\SOFTWARE\Classes\.dlock\DefaultIcon`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Wallpaper`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels` (enumerated for event log disabling)

### Polygon RPC Endpoints (infrastructure fallback chain)

`polygon-bor-rpc.publicnode[.]com`, `polygon.drpc[.]org`, `polygon-pokt.nodies[.]app`, `polygon-rpc[.]com`, `1rpc[.]io/matic`, `polygon.meowrpc[.]com`

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | DeadLock Usage |
|--------|-------------|----------------|---------------|
| Defense Evasion | T1518.001 | Software Discovery: Security Software Discovery | Language geofencing — queries system locale before executing; aborts on CIS-region victims |
| Privilege Escalation | T1548.004 | Abuse Elevation Control Mechanism: UAC Bypass | `ShellExecuteW` with `RunAs` verb to self-elevate |
| Defense Evasion | T1134.001 | Access Token Manipulation: Token Impersonation/Theft | Enables `SeDebugPrivilege` and related tokens |
| Impact | T1489 | Service Stop | Terminates Windows Defender, VSS, backup, and cloud-sync services |
| Impact | T1486 | Data Encrypted for Impact | XChaCha20 symmetric per-file encryption; Curve25519 ECDH + XSalsa20-Poly1305 key wrapping; ephemeral keys per file; partial encryption on files >50 MB |
| Impact | T1490 | Inhibit System Recovery | Disables Volume Shadow Copy Service and backup services |
| Impact | T1491.001 | Defacement: Internal Defacement | `.dlock`-extension icon + custom BMP wallpaper |
| Collection/Impact | T1074 | Data Staged | Exfiltrates victim files to Wasabi S3-compatible storage for double-extortion leak site |
| Defense Evasion | T1562.008 | Impair Defenses: Disable Cloud Logging | Disables EDR and security monitoring services |
| Defense Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs | Eliminates forensic evidence via Windows Event Log API |
| Execution | T1106 | Native API | Kills security tools, cloud sync, and remote access applications |

---

## 3. Malware & Tools

### DeadLock Encryptor

- **Language:** Rust
- **Encryption:** XChaCha20 (file content) + Curve25519 ECDH + XSalsa20-Poly1305 (key wrapping; NaCl `crypto_box`)
- **Key generation:** Ephemeral per-file keys derived from Curve25519 ECDH between operator public key and ephemeral victim keypair; eliminates key reuse
- **Operator public key:** `03bf50bbf97c4e951e66ff12b689a37a3ce675b4921e254eae76da77573843e4a9`
- **Magic footer string:** `dDlK` (trailer appended to each encrypted file)
- **File-size-adaptive encryption strategy:**
  - Full encryption for files <~50 MB
  - 50% for ~50 MB+ files
  - 25% for ~118 MB+ files
  - 10% for ~500 MB+ files
  - Chunked mode for ~1 GB+ files
- **Resource throttling:** Monitors free memory (29% threshold) and CPU idle (30% threshold) via waitable timer — pauses to avoid triggering anomaly detection

### Decentralized Recovery Infrastructure (Novel TTP)

- **Ransom note `RECOVERY_CHAT.<UID>.html`** is a self-contained HTML application embedding:
  1. **Polygon blockchain** — operator reads victim identity and config from smart contracts
  2. **Session (onion-routed) network** — end-to-end encrypted victim-operator chat without traditional backend
  3. **Wasabi S3-compatible** — leaked data hosted with in-browser file explorer
  4. **Public RPC endpoint chain** — six Polygon RPC endpoints for resilience; victim app auto-rotates if one is unreachable

This design achieves takedown resilience: no traditional C2 server, all communication routed through censorship-resistant decentralized infrastructure.

---

## 4. Threat Actor / Campaign Attribution

- **Name:** DeadLock ransomware operation
- **Type:** Financially motivated ransomware-as-a-service (RaaS)
- **Ecosystem affiliations:** Overlaps with Lynx ransomware and INC ransomware affiliates (shared victim pool, similar targeting profiles)
- **Geofencing:** Auto-exits on: Russia, Ukraine, Belarus, Tajikistan, Iran, Armenia, Azerbaijan, Georgia, Kazakhstan, Kyrgyzstan, Turkmenistan, Syria, Moldova, Oman, Yemen
- **Targeted sectors:** Information technology, mining, transportation/logistics, manufacturing, hospitality, consumer goods
- **Geographic distribution:** Europe (>50% of leaked victims), Asia, North America, South America, Africa
- **Attribution confidence:** Low (no nation-state nexus indicated; financially motivated)

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.dlock"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user file_name file_path risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_path="*\\Classes\\.dlock*"
     OR Registry.registry_path="*\\System\\Wallpaper*"
  by Endpoint.Registry.dest Endpoint.Registry.user Endpoint.Registry.registry_path Endpoint.Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user registry_path registry_value_data risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="wevtutil.exe" AND Processes.process="*cl *")
     OR (Processes.process_name="sc.exe" AND Processes.process="*stop*" AND
         (Processes.process="*vss*" OR Processes.process="*VSS*" OR Processes.process="*WinDefend*"))
     OR (Processes.process_name="vssadmin.exe" AND Processes.process="*delete shadows*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)delete shadows"), 95,
    match(process_name, "(?i)wevtutil"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

## 6. Executive Summary

**DeadLock** is an emerging financially motivated ransomware operation deploying a Rust-based encryptor notable for its novel **Polygon blockchain + Session network decentralized recovery infrastructure** — a takedown-resistant architecture that eliminates traditional C2 servers. The encryptor uses XChaCha20 + Curve25519 (NaCl `crypto_box`) with ephemeral per-file keys, appends the `.dlock` extension, and employs resource-aware throttling to evade behavioral detection. The ransom note is a self-contained HTML application that communicates with Polygon smart contracts and routes victim-operator chat through the onion-based Session network, making infrastructure takedowns largely ineffective.

DeadLock shows ecosystem overlaps with the **Lynx** and **INC** ransomware affiliates, suggesting shared infrastructure or affiliate recruitment. It targets IT, manufacturing, logistics, and hospitality across Europe, Asia, and North America.

**Key detection pivot points:** `.dlock` file extension creation (T1486), `HKLM\SOFTWARE\Classes\.dlock` registry key creation, event log clearing, and VSS deletion. The decentralized C2 design means traditional C2 domain-based detection will be insufficient; endpoint-side behavioral and file extension IOCs are the primary detection surface.
