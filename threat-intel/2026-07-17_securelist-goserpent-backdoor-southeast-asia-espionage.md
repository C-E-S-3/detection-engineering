---
scraped_at: 2026-07-17T00:00:00Z
source_url: https://securelist.com/goserpent-backdoor-in-southeast-asia/120687/
report_type: threat-intel
severity: high
title: "GoSerpent: Go-Based RAT Targeting Southeast Asian Government and Diplomatic Networks Since 2021"
---

## 1. IOCs

### File System Artifacts

| Indicator | Type | Description |
|-----------|------|-------------|
| `C:\Users\Public\thumbcache_605a.db` | File path | Password-protected archive created by ThumbcacheService; contains files collected from the victim host; distinctive artifact for threat hunting |

### Infrastructure Notes

Kaspersky identified 11 C2 IP addresses hosted on **Alibaba Cloud** and **UCLOUD HK**. Specific IP values were not publicly released at time of reporting; consult the full Kaspersky Securelist report for the complete IOC list.

---

## 2. MITRE ATT&CK

| Field | Value |
|-------|-------|
| Tactic (Primary) | Command and Control (TA0011) |
| Technique | Encrypted Channel: Symmetric Cryptography (T1573.001) |
| Additional Tactics | Collection (TA0009), Lateral Movement (TA0008), Credential Access (TA0006), Defense Evasion (TA0005) |
| Additional Techniques | Archive Collected Data (T1560), OS Credential Dumping (T1003), Proxy (T1090), Masquerading (T1036) |
| Platform | Windows |

---

## 2. Summary

**GoSerpent** is a Go-language remote access trojan (RAT) first observed in 2021, targeting government agencies, diplomatic missions, and intelligence organizations in Southeast Asia. Kaspersky Securelist published the full analysis on July 17, 2026.

### Toolset

The actor deploys a multi-tool intrusion framework:

| Tool | Description |
|------|-------------|
| **GoSerpent** | Primary Go RAT; receives and executes commands over an encrypted channel; ChaCha20 encryption with key derived as SHA256 of the communication password |
| **McMx** | Simpler Go implant functioning as a proxy or secondary RAT |
| **ThumbcacheService** | DLL-based file collector; harvests files of interest and archives them to `C:\Users\Public\thumbcache_605a.db` (password-protected) |
| **Stowaway** | Open-source SOCKS5 proxy / port-forward / reverse tunnel tool; routes traffic through compromised hosts to chain C2 communication |
| **TmcLoader** | Loader component; stages and executes the other payloads |
| **Mimikatz** | Standard credential dumping tool; obtains NTLM hashes and plaintext credentials |
| **QuarksDumpLocalHash** | Supplementary credential dumper; targets local account hashes |

### Encryption

GoSerpent uses **ChaCha20** for C2 communications. The encryption key is the **SHA256 hash of a per-campaign communication password**. GoSerpent configuration parameters (including the password and C2 address) are embedded in the binary and decrypted at runtime using **AES-CBC**.

### C2 Infrastructure

All observed C2 nodes were hosted on **Alibaba Cloud** and **UCLOUD HK** — Chinese cloud providers commonly used by China-nexus threat actors to mask attribution and reduce US-jurisdiction takedown risk. The actor chains compromised hosts via Stowaway SOCKS5 tunnels to further obscure traffic routing.

### Attribution

The actor has not been formally attributed to a named group by Kaspersky. The targeting of Southeast Asian governments, use of Chinese-language cloud infrastructure, SOCKS5 proxying through victim networks, and tooling profile (Stowaway is widely used by Chinese-nexus groups) are consistent with a China-nexus espionage operator.

---

## 4. Detection Notes

- **Hunt for the ThumbcacheService artifact**: `C:\Users\Public\thumbcache_605a.db` is a highly specific forensic indicator. Any host with this file at this path should be treated as compromised.
- **Monitor Stowaway usage**: Stowaway binaries have recognizable network fingerprints (SOCKS5 negotiation on non-standard ports, specific protocol framing). The actor routes C2 through compromised hosts, so internal east-west connections to non-standard ports from servers may indicate Stowaway relay activity.
- **Credential dumping**: Monitor for Mimikatz and QuarksDumpLocalHash execution (process names, hash of known binaries, LSASS read access via `OpenProcess`).
- **Outbound to Alibaba Cloud / UCLOUD HK**: For organizations without a business relationship with Chinese cloud providers, outbound connections from servers to Alibaba/UCLOUD IP ranges may warrant investigation.

---

## 5. References

- Kaspersky Securelist (2026-07-17): https://securelist.com/goserpent-backdoor-in-southeast-asia/120687/
- MITRE ATT&CK — Stowaway: https://attack.mitre.org/software/S0266/
- MITRE ATT&CK — T1573.001 Encrypted Channel Symmetric Cryptography: https://attack.mitre.org/techniques/T1573/001/
