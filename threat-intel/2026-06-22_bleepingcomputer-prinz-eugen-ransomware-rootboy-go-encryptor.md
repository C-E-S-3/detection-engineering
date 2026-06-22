---
scraped_at: 2026-06-22T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/new-prinz-eugen-ransomware-prioritizes-recent-files-for-encryption/
report_type: threat-intel
severity: high
title: "Prinz Eugen: New Go-Based Ransomware Prioritizing Recent Files with No Ransom Note (ROOTBOY, June 2026)"
---

## 1. IOCs

### File System Artifacts

| Indicator | Type | Notes |
|-----------|------|-------|
| `.prinzeugen` | File extension | Extension appended to all encrypted files; CHV1 magic bytes appear in file header |
| `servertool.exe` | Filename | Main encryptor binary dropped by attacker after initial access via RDP; manually executed |
| `CHV1` | File header magic | 4-byte header present in all Prinz Eugen encrypted files |

### Encryption Characteristics

| Property | Value |
|----------|-------|
| Cipher | ChaCha20-Poly1305 (AEAD) |
| Key size | 32-byte master key |
| IV | Per-file random initialization vector |
| KDF | 3-stage: Argon2id → SHA-256 → HKDF-SHA256 |
| Block size | 1 MB chunks |
| Integrity | SHA-256 hash per chunk |
| Anti-forensics | Master key zeroed in memory post-encryption; GC forced to prevent key persistence; binary self-deletes |

**Note:** No SHA-256 hashes for malware samples are publicly available as of June 22, 2026. Researchers are advised to use ThreatDown/Malwarebytes IOC feeds for sample hashes when available.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1078 | Valid Accounts | RDP access via compromised credentials; hands-on-keyboard style post-compromise |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Manual execution of servertool.exe after attacker RDP session established |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | servertool.exe named to blend with legitimate administration tools |
| Defense Evasion | T1027 | Obfuscated Files or Information | Go binary; keys zeroed in memory; self-deletion to obstruct forensics |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Binary self-deletes after encryption completes |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Abuses legitimate RMM tools (remote monitoring and management software) for persistence and to blend with authorized IT activity |
| Credential Access | T1003 | OS Credential Dumping | Post-compromise credential harvesting to enable lateral movement |
| Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol | Primary lateral movement vector via stolen/compromised RDP credentials |
| Impact | T1486 | Data Encrypted for Impact | ChaCha20-Poly1305 file encryption with prioritization of recently modified files; skips .prinzeugen files to avoid double-encryption |
| Impact | T1489 | Service Stop | Terminates processes that hold file handles to maximize encryption coverage |
| Impact | T1657 | Financial Theft | Out-of-band extortion via email, phone, or dark web portal; data theft for double-extortion leverage |

### Novel Behavior: File Modification Time Prioritization

Prinz Eugen's encryptor ranks files by last-modified timestamp, encrypting most recently used files first. This maximizes business impact by prioritizing files that are actively in use, increasing likelihood of business disruption before detection and backup restoration.

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| Prinz Eugen | Ransomware (RaaS) | Go-based; Garble obfuscation suspected; no ransom note dropped; out-of-band extortion only |
| Legitimate RMM tools | Persistence/Access | Specific RMM tools not publicly named; operator abuses them to blend with authorized IT activity and maintain access |

---

## 4. Threat Actor / Campaign Attribution

| Actor | Details |
|-------|---------|
| **ROOTBOY** | Ransomware operator attributed to Prinz Eugen by ThreatDown/Malwarebytes; active on Russian-language underground forums (Exploit, DarkForums) as "ROOTBOY" and previously as "avtokz" on XSS; linked via shared TOX ID; advertises via Telegram and Jabber |

**First confirmed victim:** Standard Bank Group (South Africa), a leading financial institution; first public disclosure April 16, 2026 when leak portal appeared listing Standard Bank as victim. Extortion portal hosted on dark web for victim pressure.

**Campaign timeline:** Prinz Eugen discovered May 11, 2026; BleepingComputer/ThreatDown analysis published June 20-21, 2026.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="*.prinzeugen"
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user file_name file_path risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="servertool.exe"
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.action="modified"
by Filesystem.dest Filesystem.user _time
| `drop_dm_object_name(Filesystem)`
| stats count as file_modifications by dest user
| where file_modifications > 200
| eval risk_score=case(file_modifications > 1000, 90, file_modifications > 500, 75, 1=1, 60)
| table dest user file_modifications risk_score
```

---

## 6. Executive Summary

**Prinz Eugen** is a new Go-based ransomware operation disclosed publicly in June 2026, attributed to a threat actor operating under the alias **ROOTBOY** on Russian-language cybercrime forums. The malware is technically sophisticated: it uses ChaCha20-Poly1305 authenticated encryption with a three-stage key derivation function (Argon2id → SHA-256 → HKDF-SHA256), and uniquely **prioritizes recently modified files for encryption** — ensuring business-critical, actively-used files are encrypted first to maximize disruption before detection.

Initial access is achieved through **compromised RDP credentials**. The operator follows a hands-on-keyboard style, manually downloading and executing `servertool.exe` after establishing RDP access. Lateral movement occurs via additional RDP sessions and legitimate RMM tools to avoid triggering alerts. Unlike most ransomware, Prinz Eugen **drops no ransom note** and conducts all extortion communications out-of-band (email, phone, dark web portal), complicating initial incident identification.

The binary performs aggressive anti-forensic measures: the encryption key is zeroed in memory after use, Go's garbage collector is explicitly triggered to prevent key remnants, and the binary self-deletes. The `.prinzeugen` file extension and `CHV1` file header magic bytes are reliable detection artifacts. ROOTBOY's first known victim was Standard Bank Group (South Africa), first noted April 16, 2026. Analysts should monitor for RDP logins from unusual ASNs, `servertool.exe` execution, and any appearance of the `.prinzeugen` file extension.

---

## References

- [BleepingComputer — New Prinz Eugen ransomware prioritizes recent files for encryption (2026-06-20)](https://www.bleepingcomputer.com/news/security/new-prinz-eugen-ransomware-prioritizes-recent-files-for-encryption/)
- [ThreatDown by Malwarebytes — Prinz Eugen deep dive](https://www.threatdown.com/blog/prinz-eugen-ransomware-a-deep-dive-into-a-new-go-based-encryptor/)
- [MITRE ATT&CK — T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
