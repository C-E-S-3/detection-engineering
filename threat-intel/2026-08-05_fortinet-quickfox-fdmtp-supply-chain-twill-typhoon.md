---
scraped_at: 2026-08-10T00:00:00Z
source_url: https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant
report_type: threat-intel
severity: high
title: "QuickFox VPN Supply Chain Attack Delivers FDMTP Backdoor via Trojanized Installer — Twill Typhoon Attribution"
---

# QuickFox VPN Supply Chain Attack Delivers FDMTP Backdoor — Twill Typhoon Attribution

**Source:** Fortinet Threat Research  
**Published:** 2026-08-05  
**Severity:** High  

## Executive Summary

Fortinet researchers identified a supply chain compromise of QuickFox, a VPN application primarily marketed to Chinese-speaking users accessing mainland-blocked content abroad. Trojanized installer packages for versions 3.51.0–3.55.5 drop the **FDMTP** (Full-Duplex Multi-Tunnel Protocol) backdoor via DLL sideloading. The campaign is attributed to **Twill Typhoon** (significant tooling and infrastructure overlap with Mustang Panda / RedDelta). Patched QuickFox 3.59.6 was released by the vendor; users on affected versions should treat their hosts as compromised.

## Technical Details

### Delivery — Supply Chain Trojanization

The threat actor modified the QuickFox Electron-based desktop installer prior to distribution. Two infection vectors were observed:

1. **DLL Sideloading via Legitimate Signed Binary** — The installer bundles a legitimate, signed helper executable alongside a malicious DLL that matches the name expected by the helper's import table. On launch, the OS loader resolves the malicious DLL before the trusted system path.
2. **Electron Renderer Tampering** — The `renderer.html` and associated JavaScript bundle inside the Electron application package (`app.asar`) were modified to include a loader stub that decrypts and executes shellcode from an embedded resource at runtime.

### FDMTP Backdoor

FDMTP is a custom implant not previously publicly documented prior to this report.

**Key characteristics:**
- **Communications:** Custom binary protocol over TCP; observed port range **20800–20816**
- **Encryption:** AES-128-ECB with a hardcoded key in Generation 2 samples: `POt_L[Bsh0=+@0a`
- **Architecture:** Full-duplex tunneling allowing simultaneous bidirectional data streams without a polling loop
- **Capabilities:** Remote shell, file transfer, keylogging, screenshot capture, credential harvesting from browser stores
- **Persistence:** Installs as a Windows service with a benign-sounding name (e.g., `QuickFoxUpdater`) or via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

### C2 Infrastructure

| Indicator | Type | Context |
|-----------|------|---------|
| `www[.]icloud-cdn[.]net` | Domain | FDMTP C2; typosquats Apple CDN branding |
| `www[.]google-apis[.]net` | Domain | FDMTP C2; typosquats Google API branding |
| TCP 20800–20816 | Port range | FDMTP custom protocol listener ports |

### Victim Fingerprinting

The JavaScript loader performs pre-execution fingerprinting and aborts payload delivery if:
- The system locale is `zh-CN` (PRC mainland)
- The username matches a known analysis sandbox account
- A virtualization artifact is detected (VMware registry key, VirtualBox MAC prefix)

This avoids infecting the very demographic QuickFox is marketed to and reduces sandbox detection risk.

## Affected Versions

| Product | Affected Versions | Fixed Version |
|---------|------------------|---------------|
| QuickFox VPN (Windows) | 3.51.0 – 3.55.5 | 3.59.6 |

## IOCs

### Domains
| Indicator | Context |
|-----------|---------|
| `www[.]icloud-cdn[.]net` | FDMTP Generation 2 C2 |
| `www[.]google-apis[.]net` | FDMTP Generation 2 C2 |

### Network
| Indicator | Context |
|-----------|---------|
| TCP/20800–20816 | FDMTP custom protocol port range |

### String Artifacts
| Indicator | Context |
|-----------|---------|
| `POt_L[Bsh0=+@0a` | AES-128-ECB key, FDMTP Generation 2 |
| `QuickFoxUpdater` | Malicious service name (persistence) |

## MITRE ATT&CK TTPs

| Technique | ID | Notes |
|-----------|----|-------|
| Supply Chain Compromise: Software Supply Chain | T1195.002 | Trojanized QuickFox installer packages distributed via official and mirror channels |
| Hijack Execution Flow: DLL Side-Loading | T1574.002 | Malicious DLL placed alongside legitimate signed binary in installer package |
| Command and Scripting Interpreter: JavaScript | T1059.007 | Modified Electron renderer executes loader stub at runtime |
| Encrypted Channel: Symmetric Cryptography | T1573.001 | FDMTP uses AES-128-ECB for C2 traffic encryption |
| Application Layer Protocol | T1071 | Custom binary protocol over TCP masquerading as update traffic |
| Credentials from Web Browsers | T1555.003 | FDMTP harvests stored browser credentials |
| Scheduled Task/Job or Boot/Logon Autostart | T1547.001 | Persistence via `HKCU\...\Run` registry key |
| Create or Modify System Process: Windows Service | T1543.003 | Persistence as malicious Windows service |
| Virtualization/Sandbox Evasion | T1497 | Aborts execution in VM environments and zh-CN locale |

## Kill Chain

| Phase | Activity |
|-------|----------|
| Weaponization | Attacker modifies QuickFox installer: injects malicious DLL and tampers with Electron renderer bundle |
| Delivery | Users download trojanized installer via official mirrors or QuickFox update mechanism |
| Exploitation | DLL sideloading triggers on installer execution; JavaScript loader decrypts shellcode |
| Installation | FDMTP establishes persistence as Windows service or registry Run key |
| Command & Control | FDMTP beacons to C2 via custom AES-128-ECB encrypted protocol on ports 20800–20816 |
| Actions on Objectives | Credential harvest, keylogging, screenshot capture, remote shell |

## Attribution

**Twill Typhoon** (also tracked as Mustang Panda, RedDelta, TA416, BRONZE PRESIDENT):
- Chinese state-sponsored threat actor assessed to conduct intelligence collection against diaspora communities and political targets
- FDMTP shares code patterns with previously documented Twill Typhoon/Mustang Panda plugins
- C2 infrastructure registration patterns and hosting overlap with known Mustang Panda campaigns

## Remediation

| Action | Priority |
|--------|----------|
| Update QuickFox to ≥ 3.59.6 or remove entirely if not required | Critical |
| On hosts running affected versions (3.51.0–3.55.5): assume full compromise; reimage | Critical |
| Hunt for FDMTP C2 connections to `icloud-cdn[.]net` and `google-apis[.]net` | High |
| Block outbound TCP/20800–20816 to non-inventory hosts at perimeter | High |
| Search for `QuickFoxUpdater` service and associated DLLs | High |
| Search for AES key string `POt_L[Bsh0=+@0a` in memory dumps and disk artifacts | Medium |

## Splunk Hunting Queries

### DLL Sideloading — Unsigned DLL Loaded by Signed Parent
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="QuickFox.exe" OR Processes.parent_process_name="QuickFox.exe"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### FDMTP C2 Domain Lookup
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("www.icloud-cdn.net","www.google-apis.net")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### FDMTP Custom Protocol — Outbound TCP 20800–20816
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port>=20800 AND All_Traffic.dest_port<=20816
    AND All_Traffic.direction="outbound"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## References

- [Fortinet Threat Research — QuickFox Supply Chain Attack FDMTP](https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant)
- [MITRE ATT&CK — T1195.002: Supply Chain Compromise: Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK — T1574.002: Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — Twill Typhoon / Mustang Panda (G0129)](https://attack.mitre.org/groups/G0129/)
