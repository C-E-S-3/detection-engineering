---
scraped_at: "2026-08-25T00:00:00Z"
source_url: "https://www.seqrite.com/blog/operation-quicsilver-china-nexus-actor-targets-myanmar-diplomats-via-vhd-delivered-go-backdoor/"
report_type: "threat-actor-campaign"
severity: "high"
title: "Operation QUICSILVER: China-Nexus Actor Targets Myanmar Diplomats via VHD-Delivered Go Backdoor"
---

# Operation QUICSILVER: China-Nexus Actor Targets Myanmar Diplomats via VHD-Delivered Go Backdoor

## IOCs

### Domains
| Indicator | Type | Context |
|-----------|------|---------|
| `register[.]mediumser[.]com` | Cloudflare Workers domain | Dynamic C2 resolver; returns current C2 IP via Cloudflare Worker; obfuscates true C2 address |

### IP Addresses
| Indicator | Type | Context |
|-----------|------|---------|
| `104[.]64[.]211[.]22` | C2 server | QUICAgent C2 server; QUIC protocol over UDP/443; confirmed active at time of report |

### Hashes
None confirmed from source.

### Files / Artifacts
| Artifact | Context |
|----------|---------|
| VHD (Virtual Hard Disk) file | Delivery mechanism; mounted by Windows Explorer on double-click; drops QUICAgent payload inside virtual filesystem |
| LNK shortcut inside VHD | T1547.009; executes ftp.exe to load QUICAgent into memory |
| `ftp.exe` (LOLBin) | T1218; used to side-load QUICAgent Go backdoor via AppDomain abuse |

### Infrastructure Notes
- C2 IP dynamically resolved at runtime via Cloudflare Workers; actual C2 address is not embedded in the malware binary.
- Shared builder artifact `desktop-stv6gg` hostname ties QUICAgent to Operation GriefLure infrastructure (separate Seqrite campaign disclosure).

---

## TTPs

| Technique ID | Technique | Notes |
|-------------|-----------|-------|
| T1566 | Phishing | VHD attachment delivered via spearphishing email targeting Myanmar diplomatic personnel |
| T1547.009 | Boot/Logon Autostart: Shortcut Modification | LNK inside mounted VHD used to trigger execution |
| T1218 | System Binary Proxy Execution | `ftp.exe` Windows LOLBin used as loader to launch QUICAgent |
| T1071.001 | Application Layer Protocol: Web Protocols | QUIC protocol used for C2; runs over UDP/443 to blend with HTTPS traffic |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | RC4 encryption applied to C2 communications |
| T1568 | Dynamic Resolution | Cloudflare Workers domain resolves to live C2 IP; allows rapid C2 rotation without binary updates |
| T1497 | Virtualization/Sandbox Evasion | QUICAgent performs sandbox checks prior to C2 initiation |

---

## Malware & Tools

**QUICAgent**
- 64-bit Go 1.20 backdoor
- Uses the QUIC protocol (UDP/443) for C2 communications, making it difficult to distinguish from legitimate HTTPS/3 traffic in network monitoring
- C2 resolution uses a Cloudflare Workers intermediary to dynamically supply the real C2 IP, eliminating hardcoded infrastructure from the binary
- RC4-encrypted command channel
- Conducts anti-sandbox checks (uptime, environment, cursor movement indicators inferred from sandbox detection pattern)
- Delivers via VHD container; VHD is a virtual disk image that Windows auto-mounts on double-click, bypassing Mark-of-the-Web (MotW) propagation that would occur with ZIP or ISO

---

## Attribution

| Attribute | Value |
|-----------|-------|
| Actor name | Operation QUICSILVER (campaign designation, Seqrite) |
| Nexus | China (moderate confidence) |
| Targeting | Myanmar diplomatic personnel |
| Confidence | Moderate — infrastructure overlap with Operation GriefLure (shared builder hostname `desktop-stv6gg`); TTPs consistent with China-nexus APT tradecraft |
| Linked campaigns | Operation GriefLure (Seqrite prior disclosure) |

---

## Splunk Detection Searches

### 1. ftp.exe Spawning Non-Standard Child Process (LOLBin Abuse)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="ftp.exe"
    AND NOT Processes.process_name IN ("ftp.exe","conhost.exe","cmd.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### 2. QUIC Protocol C2 Beacon (UDP/443 Non-Browser Egress)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=443
    AND All_Traffic.transport="udp"
    AND NOT All_Traffic.app IN ("quic","zoom","teams","meet","webex","skype","slack","chrome","msedge","firefox")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport
     All_Traffic.app All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    bytes_out > 10000, 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest dest_port transport app bytes_out risk_score
```

### 3. IOC: Cloudflare Workers C2 Resolver DNS Lookup
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("register.mediumser.com","mediumser.com")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query answer risk_score
```

### 4. IOC: Known QUICAgent C2 IP Communication
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN ("104.64.211.22")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port transport risk_score
```

### 5. VHD Mount Followed by LOLBin Execution (Behavioral Chain)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*.vhd" OR Filesystem.file_path="*.vhdx"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name _time
| `drop_dm_object_name(Filesystem)`
| eval vhd_time=_time
| join dest [
  | tstats `security_content_summariesonly` count min(_time) as exec_time
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("ftp.exe","mshta.exe","regsvr32.exe","certutil.exe","rundll32.exe")
    by Processes.dest Processes.process_name Processes.process
  | `drop_dm_object_name(Processes)`]
| where (exec_time - vhd_time) > 0 AND (exec_time - vhd_time) < 300
| eval risk_score=85
| table firstTime lastTime dest user file_path process_name process risk_score
```

---

## Executive Summary

Operation QUICSILVER is a China-nexus espionage campaign targeting Myanmar diplomatic personnel, disclosed by Seqrite on or before August 25, 2026. The threat actor delivers a 64-bit Go backdoor named **QUICAgent** inside a VHD (Virtual Hard Disk) file sent via spearphishing email. When the victim double-clicks the VHD, Windows auto-mounts it and executes an LNK shortcut that abuses the `ftp.exe` Windows LOLBin to load QUICAgent into memory, bypassing Mark-of-the-Web restrictions.

QUICAgent's most notable characteristic is its use of the **QUIC protocol over UDP/443** for C2 communications, which is designed to blend with legitimate HTTPS/3 traffic and evade protocol-based network inspection. The C2 IP address is not hardcoded; instead, the malware contacts a Cloudflare Workers domain (`register[.]mediumser[.]com`) to dynamically resolve the current C2 server address (`104[.]64[.]211[.]22`), making C2 rotation trivial for the operator.

Infrastructure overlap via a shared builder hostname (`desktop-stv6gg`) links QUICAgent to Seqrite's previously disclosed Operation GriefLure, suggesting a common tooling development pipeline. Attribution is China-nexus at moderate confidence based on targeting (Myanmar diplomatic sector), TTPs, and infrastructure patterns.

**Analyst action items:** Block the C2 domain and IP at perimeter controls. Alert on non-browser UDP/443 QUIC connections and `ftp.exe` spawning unexpected child processes. VHD file delivery should trigger enhanced user awareness.

---

## References

- [Seqrite — Operation QUICSILVER](https://www.seqrite.com/blog/operation-quicsilver-china-nexus-actor-targets-myanmar-diplomats-via-vhd-delivered-go-backdoor/)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1218 — System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [MITRE ATT&CK T1568 — Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
- [MITRE ATT&CK T1573.001 — Encrypted Channel: Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001/)
