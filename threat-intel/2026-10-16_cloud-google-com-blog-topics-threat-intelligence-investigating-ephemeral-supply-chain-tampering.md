# UNC7017: Ephemeral Supply Chain Tampering via AOMEI Backupper Update Infrastructure

**Source:** https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering  
**Published:** 2026-10-15 / 2026-10-16  
**Reported by:** Mandiant / Google Threat Intelligence Group (GTIG)  
**Date Added:** 2026-10-18  

---

## Summary

Mandiant/GTIG documented a campaign by UNC7017 — a suspected nation-state-aligned threat actor — that tampered with AOMEI Technology's software update delivery infrastructure during brief 5–10 minute windows between April and July 2026. Rather than compromising the vendor's signing keys or repository directly, the actor intermittently redirected the update endpoint to attacker-controlled infrastructure, serving CROSSROAD downloaders to users who ran AOMEI Backupper during one of these windows.

The technique is notable for its operational security: by limiting tampering to very short windows, UNC7017 reduced the chance of vendor detection while still achieving code execution on victim hosts running legitimate, signed backup software.

---

## Threat Actor

**UNC7017**  
- Classification: Suspected nation-state-aligned; attribution not finalized at time of publication  
- First documented in this campaign  
- Named tools: CROSSROAD, SHINYROAD, ADAPTAGENT, Adaptix (open-source C2 framework)

---

## Campaign Timeline

| Period | Activity |
|--------|----------|
| April 2026 | First observed AOMEI Backupper update endpoint tampering; CROSSROAD payloads staged on Alibaba Cloud Object Storage (Alibaba Cloud HK) |
| April–June 2026 | Infrastructure shifted to vendor-themed actor-controlled domains (e.g., aomei[.]storage-data[.]com, promotion[.]storage-data[.]com) |
| June–July 2026 | Some later-stage payloads distributed via public Google Cloud Storage buckets |
| July 2026 | Last confirmed tampering window observed |

---

## Malware Chain

```
AOMEI Backupper update check
  └─ CROSSROAD Downloader (DLL or EXE; Alibaba Cloud / vendor-themed domain)
        ├─ WebDAV NTLM request to 8.210.84.56 → captures victim NTLM hash
        └─ SHINYROAD Backdoor (modular; Adaptix C2 framework)
              └─ ADAPTAGENT second-stage payload (disguised as Nitro PDF installer)
```

### CROSSROAD
- Downloader; first-stage payload delivered via tampered update
- Initiates WebDAV NTLM request to attacker-controlled server to harvest NTLM credentials
- Fetches and executes SHINYROAD from C2

### SHINYROAD
- Full-featured backdoor using the open-source Adaptix C2 framework
- Communicates with 8.210.84.56 (Alibaba Cloud HK) and 8.218.65.184
- Supports file operations, process injection, shell execution, screen capture

### ADAPTAGENT
- Second-stage payload disguised as a Nitro PDF installer
- Purpose: secondary persistence and lateral movement staging

---

## Infrastructure

### Domains (defanged)

| Domain | Role |
|--------|------|
| `storage-data[.]com` | Primary attacker-controlled infrastructure domain |
| `promotion[.]storage-data[.]com` | Subdomain serving CROSSROAD payloads for AOMEI update tampering |
| `aomei[.]storage-data[.]com` | Vendor-impersonating subdomain; served CROSSROAD downloader disguised as legitimate AOMEI update |

### IP Addresses

| IP | Role |
|----|------|
| `8.210.84.56` | Alibaba Cloud HK; WebDAV NTLM credential capture target and Adaptix C2 server |
| `8.218.65.184` | Historical SHINYROAD C2 server |
| `47.239.60.117` | UNC7017 campaign infrastructure server |

*Note: No file hashes were available in the search-accessible version of this report. The Mandiant report includes YARA rules for CROSSROAD and SHINYROAD; consult the primary source for signature content.*

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Initial Access (TA0001) | T1195.002 — Compromise Software Supply Chain | Update endpoint for AOMEI Backupper tampered to deliver CROSSROAD |
| Execution (TA0002) | T1204.002 — Malicious File | User executes AOMEI Backupper; update mechanism delivers and runs CROSSROAD |
| Credential Access (TA0006) | T1187 — Forced Authentication | CROSSROAD initiates WebDAV request to capture victim NTLM hash |
| Command and Control (TA0011) | T1071.001 — Application Layer Protocol: Web Protocols | SHINYROAD uses Adaptix C2 over HTTP/S |
| Defense Evasion (TA0005) | T1036.005 — Masquerading: Match Legitimate Name or Location | ADAPTAGENT masquerades as Nitro PDF installer |

**Kill Chain Phases:** Delivery, Exploitation, Installation, C2

---

## Detection Notes

- Process tree: `AomeiBackupper.exe` spawning LOLBins (cmd.exe, powershell.exe, regsvr32.exe, etc.) is the primary behavioral signal
- Network: Outbound connections to 8.210.84.56, 8.218.65.184, 47.239.60.117 from any host
- The tampering windows were 5–10 minutes, so not all AOMEI installs in this period were affected — triage should focus on hosts running AOMEI Backupper that show child process anomalies
- See detection: `detections/execution/unc7017_aomei_backupper_trojanized_installer_execution.md`

---

## References

- https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering
- https://attack.mitre.org/techniques/T1195/002/
- https://attack.mitre.org/techniques/T1187/
