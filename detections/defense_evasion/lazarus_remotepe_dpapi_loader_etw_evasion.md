# Lazarus Group RemotePE DPAPI Loader Chain and ETW Evasion

## Description

Detects the Lazarus Group's three-stage RemotePE toolchain, which uses Windows DPAPI to decrypt and load a memory-only RAT while actively patching ETW telemetry to suppress endpoint detection.

The attack chain operates as follows:
1. **DPAPILoader** (`Iassvc.dll`) is placed on disk masquerading as an IAS (Internet Authentication Service) DLL and sideloaded into a host process. It calls `CryptUnprotectData` (Windows DPAPI) to decrypt the next-stage payload from an on-disk encrypted blob.
2. **RemotePELoader** executes in memory, patches `EtwEventWrite` in ntdll.dll to suppress ETW-based telemetry, uses Hell's Gate direct syscalls to bypass user-mode EDR hooks, then contacts `aes-secure[.]net` over HTTP to fetch RemotePE.
3. **RemotePE** is a memory-only C++ RAT with no on-disk presence; it polls C2 for commands and provides full remote access.

**Observable behaviors:**
- DNS or network traffic to `aes-secure[.]net`
- Unexpected `Iassvc.dll` file creation events, particularly outside `System32\` or in non-standard service DLL paths
- Svchost-family or service-hosting processes making outbound HTTP connections to newly-registered or low-reputation domains
- Endpoint telemetry gaps (ETW patching may cause unexplained silences in process activity logs)

**False positives:**
- The domain `aes-secure[.]net` is attacker-controlled; any DNS hit should be treated as a confirmed indicator
- `Iassvc.dll` creation outside of a Windows update process is highly suspicious
- No known legitimate software uses this combination of behaviors

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Impair Defenses: Indicator Blocking |
| Technique ID | T1562.006 |
| Secondary Technique | Deobfuscate/Decode Files or Information |
| Secondary Technique ID | T1140 |
| Secondary Technique | Hijack Execution Flow: DLL Side-Loading |
| Secondary Technique ID | T1574.002 |
| Tertiary Tactic | Command and Control |
| Tertiary Tactic ID | TA0011 |
| Tertiary Technique | Application Layer Protocol: Web Protocols |
| Tertiary Technique ID | T1071.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where (DNS.query="aes-secure.net" OR DNS.query LIKE "%.aes-secure.net")
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90,
       actor="Lazarus Group",
       malware="RemotePELoader / RemotePE RAT",
       note="Confirmed Lazarus C2 domain — treat any hit as high-priority indicator"
| table firstTime lastTime src query answer actor malware risk_score note
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_host="aes-secure.net" OR All_Traffic.dest_host LIKE "%.aes-secure.net")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_host dest_port app risk_score
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
    NOT match(file_path, "(?i)\\\\windows\\\\system32\\\\"),  90,
    match(file_path, "(?i)\\\\windows\\\\system32\\\\"), 80,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user file_path file_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Any DNS or network traffic to `aes-secure[.]net` | 90 | Attacker-controlled C2 domain; confirmed Lazarus infrastructure; zero legitimate use |
| `Iassvc.dll` created outside `System32\` | 90 | Sideloading from non-standard path is a direct TTP indicator |
| `Iassvc.dll` created in `System32\` | 80 | May indicate Windows update; investigate immediately; DPAPI-loader variant may place in system32 to blend in |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Lazarus Group (HIDDEN COBRA, G0032) | [MITRE ATT&CK — Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/), [Fox-IT — RemotePE: The Lazarus RAT that lives in memory (2026-05-22)](https://blog.fox-it.com/2026/05/22/remotepe-the-lazarus-rat-that-lives-in-memory/) |

## References

- [Fox-IT — RemotePE: The Lazarus RAT that lives in memory (2026-05-22)](https://blog.fox-it.com/2026/05/22/remotepe-the-lazarus-rat-that-lives-in-memory/)
- [The Hacker News — Lazarus Deploys RemotePE Memory-Only RAT Against Financial and Crypto Firms (2026-05-25)](https://thehackernews.com/2026/05/lazarus-deploys-remotepe-memory-only.html)
- [MITRE ATT&CK — T1562.006: Impair Defenses: Indicator Blocking](https://attack.mitre.org/techniques/T1562/006/)
- [MITRE ATT&CK — T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [MITRE ATT&CK — T1574.002: Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
