---
scraped_at: "2026-05-26T00:00:00Z"
source_url: "https://blog.fox-it.com/2026/05/22/remotepe-the-lazarus-rat-that-lives-in-memory/"
report_type: threat-intel
severity: high
title: "Lazarus Group RemotePE: Memory-Only RAT Using DPAPI Loader Chain and ETW Patching to Target Financial and Crypto Sectors"
---

## 1. IOCs

### Domains

| Indicator | Context |
|-----------|---------|
| `aes-secure[.]net` | RemotePELoader HTTP C2 — second-stage loader contacts this server to fetch the memory-only RemotePE RAT payload |

### File Artifacts

| Artifact | Context |
|----------|---------|
| `Iassvc.dll` | DPAPILoader filename — masquerades as IAS (Internet Authentication Service) DLL; placed on disk and sideloaded; DPAPI-decrypts RemotePELoader into memory |

### Notes on Sample Availability

No RemotePELoader or RemotePE samples were found on VirusTotal at the time of publication. The DPAPILoader artifact dates to November 2023; RemotePE was first documented in September 2025 in connection with a DeFi sector attack.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | DPAPILoader calls `CryptUnprotectData` (Windows DPAPI) to decrypt RemotePELoader payload from disk |
| Defense Evasion | T1562.006 | Impair Defenses: Indicator Blocking | RemotePELoader patches `EtwEventWrite` in ntdll.dll in-process memory to suppress ETW-based telemetry before fetching RemotePE |
| Defense Evasion | T1055.012 | Process Injection: Process Hollowing | RemotePE uses Hell's Gate (direct syscalls bypassing hooked ntdll) to execute in memory without triggering user-mode API hooks |
| Defense Evasion | T1027.002 | Obfuscated Files or Information: Software Packing | DPAPI-encrypted payload on disk; no plaintext on-disk artifact for RemotePELoader or RemotePE |
| Execution | T1129 | Shared Modules | DPAPILoader deployed as a sideloaded DLL (`Iassvc.dll`) within a legitimate service process |
| Defense Evasion | T1574.002 | Hijack Execution Flow: DLL Side-Loading | `Iassvc.dll` placed alongside a legitimate binary to be loaded via search-order hijacking |
| Command & Control | T1071.001 | Application Layer Protocol: Web Protocols | RemotePELoader fetches RemotePE RAT from `aes-secure[.]net` over HTTP; RemotePE polls C2 for instructions |
| Collection | T1005 | Data from Local System | RemotePE RAT provides full remote access including file system access and data collection |

---

## 3. Malware & Tools

| Name | Type | Details |
|------|------|---------|
| DPAPILoader | Loader DLL | Written to disk as `Iassvc.dll`; uses Windows DPAPI (`CryptUnprotectData`) to decrypt the next stage; dates to November 2023; first Lazarus toolset component to persist on disk |
| RemotePELoader | In-Memory Loader | Decrypted by DPAPILoader; contacts `aes-secure[.]net` over HTTP to retrieve RemotePE; uses Hell's Gate direct syscall technique to bypass user-mode API hooks; patches `EtwEventWrite` to suppress ETW telemetry before executing next stage |
| RemotePE | Memory-Only RAT (C++) | Final payload; lives entirely in memory with no on-disk artifact; polls C2 for commands; full remote access capability; first documented September 2025 in a DeFi sector intrusion; cross-platform capability noted |

---

## 4. Threat Actor / Campaign Attribution

- **Actor:** Lazarus Group (HIDDEN COBRA) — North Korea (DPRK)-nexus state-sponsored APT
- **Attribution Confidence:** Medium (Fox-IT attribution based on TTP overlap with known Lazarus tooling and operational patterns)
- **Targeted Sectors:** Financial services, cryptocurrency exchanges, decentralized finance (DeFi) platforms
- **Objective:** Long-term observation, credential theft, and financial theft; Lazarus Group stole approximately $577 million in cryptocurrency in the first four months of 2026 (76% of global crypto thefts)
- **Earliest Activity:** DPAPILoader artifact dates to November 2023; campaign using RemotePE first identified September 2025

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where (DNS.query="aes-secure.net" OR DNS.query="*.aes-secure.net")
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90,
       actor="Lazarus Group",
       malware="RemotePELoader"
| table firstTime lastTime src query answer actor malware risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host="aes-secure.net" OR All_Traffic.dest_host LIKE "%.aes-secure.net"
by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest_host dest_port app risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="Iassvc.dll"
  AND Filesystem.action="created"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)system32"), 85,
    match(file_path, "(?i)(temp|appdata|users)"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user file_path file_name risk_score
```

---

## 6. Executive Summary

On May 22, 2026, Fox-IT published detailed technical analysis of a Lazarus Group toolset centered on RemotePE — a C++ remote access trojan that executes entirely in memory, leaving no on-disk artifact. The toolset uses a three-stage loader chain specifically engineered to evade modern endpoint defenses:

1. **DPAPILoader** (`Iassvc.dll`) is placed on disk and sideloaded alongside a legitimate process; it uses the Windows Data Protection API to decrypt the second-stage loader from an encrypted on-disk blob.
2. **RemotePELoader** runs in memory, contacts `aes-secure[.]net` over HTTP to fetch RemotePE, and immediately patches `EtwEventWrite` in ntdll to suppress ETW-based telemetry before executing the next stage via Hell's Gate direct syscalls (bypassing user-mode hook-based EDRs).
3. **RemotePE** is a full-featured C++ RAT that runs exclusively in memory, polling C2 for operator commands.

The environmental keying, memory-only execution, EDR telemetry suppression, and minimal forensic footprint indicate this toolset is purpose-built for long-term covert access in high-value financial and cryptocurrency targets. Lazarus Group has stolen approximately $577 million in cryptocurrency in 2026 alone (76% of all global crypto theft). Defenders should hunt for `Iassvc.dll` creation events, DNS/network connections to `aes-secure[.]net`, and any svchost-family processes with unusual outbound HTTP connections to newly-registered or low-reputation domains.
