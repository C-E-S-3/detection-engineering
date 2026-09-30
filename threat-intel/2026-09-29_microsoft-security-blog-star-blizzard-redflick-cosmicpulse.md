---
scraped_at: 2026-09-29T14:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
report_type: threat-intel
severity: high
title: "Star Blizzard RedFlick: Phishing via VHD/RAR Delivery with Scheduled Task CPL Proxy Execution (CosmicPulse)"
---

# Star Blizzard RedFlick: Phishing via VHD/RAR Delivery with Scheduled Task CPL Proxy Execution (CosmicPulse)

## 1. IOCs

### Domains
| Indicator | Type | Context |
|-----------|------|---------|
| `etia[.]ca` | C2/Delivery | Star Blizzard / COLDRIVER phishing infrastructure; September 2026 RedFlick campaign |
| `groy[.]cc` | C2/Delivery | Star Blizzard phishing infrastructure |
| `gliderrompercycl[.]com` | C2/Delivery | Star Blizzard phishing/C2 domain |
| `muvb[.]net` | C2/Delivery | Star Blizzard CosmicPulse C2 |
| `divekickspolic[.]org` | C2/Delivery | Star Blizzard phishing infrastructure |
| `matjk[.]click` | C2/Delivery | Star Blizzard phishing link domain |
| `bpdaersa[.]click` | C2/Delivery | Star Blizzard phishing link domain |
| `stuseamandesilt[.]org` | C2/Delivery | Star Blizzard phishing infrastructure |
| `itechx[.]tel` | C2/Delivery | Star Blizzard CosmicPulse C2 |
| `guach[.]net` | C2/Delivery | Star Blizzard CosmicPulse C2 |
| `ruten[.]observer` | C2/Delivery | Star Blizzard phishing infrastructure |
| `byveo[.]org` | C2/Delivery | Star Blizzard phishing infrastructure |
| `secure-dns-hub[.]com` | C2/Delivery | Star Blizzard BAITSWITCH decoy redirect domain |
| `qumel[.]link` | C2/Delivery | Star Blizzard phishing link domain |
| `cyrna[.]top` | C2/Delivery | Star Blizzard phishing infrastructure |
| `drasw[.]club` | C2/Delivery | Star Blizzard phishing infrastructure |

### IP Addresses
| Indicator | Type | Context |
|-----------|------|---------|
| `103[.]245[.]231[.]248` | C2 IP | Star Blizzard RedFlick campaign C2 server |
| `2[.]57[.]241[.]246` | C2 IP | Star Blizzard RedFlick campaign C2 server |
| `89[.]125[.]209[.]168` | C2 IP | Star Blizzard RedFlick campaign infrastructure |
| `103[.]245[.]231[.]79` | C2 IP | Star Blizzard RedFlick campaign C2 server |
| `45[.]84[.]59[.]66` | C2 IP | Star Blizzard CosmicPulse C2 server |
| `103[.]160[.]59[.]97` | C2 IP | Star Blizzard CosmicPulse C2 server |

### File Hashes (SHA256)
| Hash | Context |
|------|---------|
| `9707a8694e954e9ee13e839d6e5905ce626c0837c7c90da6d1025bfbe152866b` | Documents.zip — RedFlick phishing delivery archive |
| `1f2096ff906915fbf80778f0636446206197351f7e271af97936eeb6f32c179d` | Documents.vhdx — VHD container dropping .cpl payload |
| `699e92a9e0edf7835879d5697bc67138c0b137117f459caf1a44df357407cad9` | Chatham_London_Conference_2026_Invitation.rar — lure archive |
| `24b6e36a09eb2acfc2a95478ca685acb7593b1689be6a4a639fe0d222393cfa7` | USUBC_Private_Executive_Roundtable_Webex.rar — lure archive |
| `dd98dbc1a55afe6fd0ed2ed53a79c76f6bde15081a0060422185b74eb1799ee4` | Payment Advice Note.zip — lure archive |

---

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | TA0001 | T1566.002 | Spearphishing Link — email with link to ZIP/RAR containing VHD/VHDX file; lures themed around conferences, policy roundtables, and payment notifications targeting policy researchers and NGOs |
| Execution | TA0002 | T1053.005 | Scheduled Task/Job — LNK inside VHD creates a scheduled task pointing to `control.exe` with a `.cpl` argument |
| Defense Evasion | TA0005 | T1218.002 | Signed Binary Proxy Execution: Control Panel — `control.exe` used to proxy-execute the attacker's `.cpl` payload; avoids direct PowerShell/script execution |
| Defense Evasion | TA0005 | T1036 | Masquerading — lure filenames reference legitimate institutions (Chatham House, USUBC, Webex) |
| Defense Evasion | TA0005 | T1140 | Deobfuscate/Decode — CosmicPulse payload decrypts embedded configuration at runtime |
| Command and Control | TA0011 | T1071.001 | Application Layer Protocol: Web Protocols — CosmicPulse HTTPS C2 beaconing (YESROBOT variant); NOROBOT used as decoy with BAITSWITCH router |
| iOS Targeting | TA0001 | T1566 | DarkSword iOS implant delivered via separate iMessage spearphishing (accompanying campaign, not via RedFlick) |

---

## 3. Malware & Tools

### RedFlick Technique
A new delivery chain where a VHD/VHDX container auto-mounted from a ZIP/RAR phishing archive contains an LNK file. The LNK creates a scheduled task via `schtasks.exe` to invoke `control.exe` with a malicious `.cpl` file. This avoids triggering common script-execution detections (no PowerShell, no wscript) and abuses a legitimate Windows signed binary.

### CosmicPulse (YESROBOT / NOROBOT / BAITSWITCH)
- **YESROBOT** — primary HTTP/S C2 implant; beacons to attacker-controlled domains; encrypted configuration
- **NOROBOT** — decoy implant that appears to fail C2 connectivity, drawing analyst attention away from YESROBOT
- **BAITSWITCH** — URL router served from delivery infrastructure; redirects defenders to benign content (e.g., `secure-dns-hub[.]com`) while directing real victims to the C2

### DarkSword (iOS)
A separate mobile implant delivered via iMessage spearphishing alongside the Windows RedFlick campaign. Targets iOS devices of the same policy/NGO community. Details limited.

---

## 4. Threat Actor / Campaign Attribution

**Star Blizzard** (Microsoft designation) / **SEABORGIUM** (Google) / **COLDRIVER** (UK NCSC)

- **Attribution:** Russia FSB Centre 18
- **Targeting:** UK/US/European policy researchers, NGOs, think tanks, former government officials, journalists covering Russia/Ukraine
- **Campaign period:** Active through September 2026; RedFlick technique first observed August 2026
- **Previous activity:** Earlier campaigns used EvilGinx adversary-in-the-middle credential harvesting; RedFlick marks a shift to direct malware delivery

---

## 5. Splunk Detection Searches

### Control.exe Loading CPL File from Non-Standard Path
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="control.exe"
    AND Processes.process="*.cpl*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    NOT match(process,"(?i)\\\\windows\\\\system32\\\\"), 90,
    match(parent_process_name,"(?i)svchost|taskeng|wmiprvse"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Scheduled Task Creating control.exe + CPL Execution Chain
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="schtasks.exe"
    AND Processes.process="*/create*"
    AND Processes.process="*control.exe*"
    AND Processes.process="*.cpl*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### DNS Query to Known Star Blizzard IOC Domains
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("etia.ca","groy.cc","gliderrompercycl.com","muvb.net",
                      "divekickspolic.org","matjk.click","bpdaersa.click","stuseamandesilt.org",
                      "itechx.tel","guach.net","ruten.observer","byveo.org","secure-dns-hub.com",
                      "qumel.link","cyrna.top","drasw.club")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src query answer risk_score
```

### VHD/VHDX Mounted in User-Accessible Path Followed by .cpl File Creation
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_name="*.cpl" OR Filesystem.file_name="*.vhd" OR Filesystem.file_name="*.vhdx")
    AND Filesystem.file_path IN ("*\\Users\\*","*\\AppData\\*","*\\Temp\\*","*\\Downloads\\*")
    AND Filesystem.action="created"
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"(?i)\.cpl$"), 80,
    match(file_name,"(?i)\.(vhd|vhdx)$"), 70,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

---

## 6. Executive Summary

Microsoft Threat Intelligence published analysis on September 29, 2026 of a new phishing delivery chain used by **Star Blizzard** (Russia FSB Centre 18, also tracked as SEABORGIUM/COLDRIVER) dubbed **RedFlick**. The technique represents a maturation from Star Blizzard's earlier credential-harvesting operations toward direct malware delivery with defense evasion.

**Attack chain:** A spearphishing email delivers a link to a ZIP or RAR archive containing a Virtual Hard Disk (VHD/VHDX) file. When the victim mounts the VHD (which is a standard Windows action that requires only double-clicking), an LNK shortcut within the VHD executes a `schtasks.exe` command to register a scheduled task that invokes `control.exe` with a malicious `.cpl` (Control Panel) file argument. Because `control.exe` is a legitimate, signed Windows binary, this CPL proxy execution (T1218.002) sidesteps many script-execution detections. The scheduled task provides persistence and executes the payload after VHD unmount.

**Payload:** The CPL file loads **CosmicPulse**, a multi-component implant architecture. The **YESROBOT** variant beacons to attacker HTTPS C2 infrastructure. The **NOROBOT** decoy appears to fail C2 contact to mislead analysts. The **BAITSWITCH** router serves benign redirects (e.g., `secure-dns-hub[.]com`) to analysts while routing real victims to active C2.

**Targeting:** UK and European policy researchers, NGOs, think tanks, and journalists covering Russia-Ukraine. Lure filenames reference Chatham House, USUBC (US-Ukraine Business Council), Webex meeting invitations, and payment notifications — themes consistent with Star Blizzard's long-running focus on policy and academic communities.

**Accompanying iOS campaign:** DarkSword mobile implant delivered via iMessage spearphishing targets the same victim population on iOS.

**Detection priority:** Block the 16 infrastructure domains at DNS/proxy. Hash-based IOC hunting is immediately actionable. Behavioral detection should focus on `control.exe` loading `.cpl` files from outside `%SystemRoot%\System32`, especially when spawned from scheduled task engines.

---

## References

- [Microsoft Security Blog — Star Blizzard RedFlick (2026-09-29)](https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/)
- [MITRE ATT&CK — Star Blizzard (G0122)](https://attack.mitre.org/groups/G0122/)
- [MITRE ATT&CK T1218.002 — Control Panel](https://attack.mitre.org/techniques/T1218/002/)
- [MITRE ATT&CK T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [UK NCSC: COLDRIVER threat actor assessment](https://www.ncsc.gov.uk/news/coldriver-russian-threat-actor-targeting-high-value-targets)
