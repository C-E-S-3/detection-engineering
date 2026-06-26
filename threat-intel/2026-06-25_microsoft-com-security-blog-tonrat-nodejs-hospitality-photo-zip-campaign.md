---
scraped_at: "2026-06-26T00:00:00Z"
source_url: "https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/"
report_type: threat-intel
severity: high
title: "TonRAT: Node.js Implant Targeting Hospitality Sector via Photo ZIP Phishing with Authentication Laundering"
---

## 1. IOCs

### C2 IP Addresses

| Indicator | Ports | Context |
|-----------|-------|---------|
| `178.16.54[.]27` | 56001, 56002 | TonRAT primary C2; active in both Wave 1 and Wave 2 |
| `95.217.97[.]121` | Multiple non-standard | TonRAT Wave 1 C2 server |
| `193.202.84[.]32` | Multiple non-standard | TonRAT Wave 1 C2 server |
| `178.16.55[.]179` | Multiple non-standard | TonRAT Wave 1 C2 server |

Note: `172.67.161[.]215` is a shared Cloudflare CDN IP — not added to IOC list.

**Non-standard Ports Used:** 8443, 8445, 8453, 5555, 56001, 56002, 56003

### C2 Domains — Wave 1 (.info TLDs)

| Indicator | Context |
|-----------|---------|
| `safedocphoto[.]info` | TonRAT Wave 1 C2 domain |
| `recallnine[.]info` | TonRAT Wave 1 C2 domain |
| `kentjerk[.]info` | TonRAT Wave 1 C2 domain |
| `photodoc-secure[.]info` | TonRAT Wave 1 C2 domain |
| `kelopins[.]info` | TonRAT Wave 1 C2 domain |
| `sec-safe-dc[.]info` | TonRAT Wave 1 C2 domain |
| `visaphoto-secure[.]info` | TonRAT Wave 1 C2 domain |
| `visa-safedocs[.]info` | TonRAT Wave 1 C2 domain |
| `docshub-01[.]info` | TonRAT Wave 1 C2 domain |
| `photo-box[.]info` | TonRAT Wave 1 C2 domain |

### C2 Domains — Wave 2 (.cfd/.bond TLDs)

| Indicator | Context |
|-----------|---------|
| `photo-26254[.]cfd` | TonRAT Wave 2 C2 domain (Cloudflare-fronted) |
| `photo-26654[.]cfd` | TonRAT Wave 2 C2 domain |
| `photo-132454[.]cfd` | TonRAT Wave 2 C2 domain |
| `photo-8632454[.]cfd` | TonRAT Wave 2 C2 domain |
| `photo-26653[.]cfd` | TonRAT Wave 2 C2 domain |
| `photo-26656[.]cfd` | TonRAT Wave 2 C2 domain |
| `photo-27857[.]cfd` | TonRAT Wave 2 C2 domain |
| `zloapobikahy23[.]bond` | TonRAT Wave 2 C2 domain |
| `higoksbupwou[.]com` | TonRAT Wave 2 C2 domain |
| `aluminiostramuntana[.]com` | TonRAT Wave 2 C2 domain |

### File Hashes (SHA-256)

| Hash | Filename | Description |
|------|----------|-------------|
| `04ec44f2618460f5c77c5e56014a512cc03a123c9c5b6b6b1273e2a1681ac2e1` | xmnrwv9l.exe | TonRAT PE payload (present in both Wave 1 and Wave 2) |
| `9f10e3b6e5745784f26d18c38ce01fba054b19749c17260978ac11472564aee2` | IMG-386443483.png.lnk | TonRAT LNK dropper masquerading as PNG image (Wave 2) |
| `97448688b292bfec6d83b153588076fe59b111c35ac4e42a916238df16a71e2f` | PHOTO-215746435.png.lnk | TonRAT LNK dropper masquerading as PNG image (Wave 2) |
| `c5baa0c16b0074a1e94b48aa0177e9bfc23746aca8a5b42848a6685da85658b5` | qFWe908J.ps1 | TonRAT Wave 2 PowerShell stage (419 KB, heavily obfuscated — seven obfuscation evolution phases documented) |
| `b7f46b192cd83a1d2487cb048cca645f6e8855b9673d500d50bbdb04eebc6bea` | bjygtujc.dll | TonRAT Wave 2 compiled .NET DLL (csc.exe compile-after-delivery) |
| `d14ba95cdce1ef7dc9ad3ac74949ca5db38b27378ee30f30a23cf26f9e875a11` | node.exe | Node.js v24.13.0 runtime (89.9 MB) — embedded with TonRAT and deployed to victim ProgramData path |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique | TonRAT Usage |
|--------|-------------|-----------|--------------|
| Resource Development | T1583.001 | Acquire Infrastructure: Domains | 40+ .info/.cfd/.bond/.click C2 domains registered per campaign wave |
| Resource Development | T1584.006 | Compromise Infrastructure: Web Services | Cloudflare Turnstile CAPTCHA-protected landing pages fronting Wave 2 C2 |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Calendly URLs delivered via email; routes victim through Google share.google redirect to photo-*.cfd lure page |
| Initial Access | T1199 | Trusted Relationship | Authentication laundering routes phishing via Calendly/SendGrid infrastructure, passing SPF/DKIM/DMARC/CompAuth checks |
| Execution | T1204.002 | User Execution: Malicious File | Victim opens ZIP containing .LNK file disguised as .PNG photo |
| Execution | T1059.001 | PowerShell | Multi-stage obfuscated PowerShell decoder chain (7 documented evolution phases, April–May 2026) |
| Execution | T1059.007 | JavaScript | Node.js JavaScript implant (TonRAT) executing as persistent runtime |
| Defense Evasion | T1027 | Obfuscated Files or Information | Seven PowerShell obfuscation phases: XOR bigint → subtraction → hex-to-decimal → arithmetic masking → modulo/division → syntax diversification → for-loop with arithmetic masks |
| Defense Evasion | T1027.004 | Compile After Delivery | Wave 2: .NET DLL compiled on victim via csc.exe from obfuscated PowerShell |
| Defense Evasion | T1036 | Masquerading | LNK files named *.png.lnk inside photo-themed ZIP archives |
| Defense Evasion | T1562.001 | Impair Defenses | Microsoft Defender exclusion manipulation added post-installation |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder | Dual persistence: HKCU\Software\Microsoft\Windows\CurrentVersion\Run → node.exe implant; HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce → ProgramData executable (self-refreshing) |
| Discovery | T1016 | System Network Configuration Discovery | IP geolocation lookups for environment reconnaissance |
| Command and Control | T1571 | Non-Standard Port | C2 on ports 56001/56002/56003/8443/8445/8453/5555 |

---

## 3. Malware & Tools

**TonRAT** (Microsoft Defender detection name: PureRat for persistence component, Wacatac for initial LNK)
- Node.js-based JavaScript implant using embedded Node.js v24.13.0 runtime (89.9 MB, deployed to ProgramData)
- Capabilities: persistent C2 communications, forced system shutdowns, PE payload compilation, browser automation, IP geolocation-based environment reconnaissance, Defender exclusion manipulation
- Written as a JavaScript payload executed by the bundled node.exe interpreter

**Attack Chain (Wave 2):**
1. Phishing email with Calendly URL (authentication laundering via SendGrid/Google — passes all email auth checks)
2. Calendly → share.google redirect → Google intermediate → photo-*.cfd Cloudflare-fronted landing page (Turnstile CAPTCHA gate)
3. Visitor downloads photo-themed ZIP archive
4. ZIP contains `.png.lnk` shortcut files (masquerade as images)
5. LNK executes obfuscated PowerShell decoder (Phase 7: for-loop with arithmetic masks)
6. PowerShell downloads and compiles .NET DLL via csc.exe (compile-after-delivery)
7. Node.js v24.13.0 runtime (node.exe) deployed to ProgramData; JavaScript implant executed
8. Dual registry persistence established: Run key (node.exe implant) + RunOnce key (ProgramData executable, self-refreshing after each execution to maintain persistence across reboots)
9. TonRAT C2 established on non-standard ports (56001/56002) to 178.16.54[.]27

**PowerShell Obfuscation Evolution (April–May 2026):**
1. XOR bigint decoding
2. Subtraction replacement
3. Hex-to-decimal substitution
4. Arithmetic masking
5. Modulo/division operations
6. Syntax diversification with randomized variables
7. For-loop variants with arithmetic masks (Wave 2)

---

## 4. Threat Actor / Campaign Attribution

Microsoft Threat Intelligence has **not attributed** this campaign to a known threat actor group as of the June 25, 2026 report. The campaign is tracked as an active intrusion operation.

**Campaign Characteristics:**
- Active multi-stage intrusion targeting hospitality organizations in Europe and Asia
- Specific targeting of reception, front desk, reservations, and front office staff roles
- April–May 2026 active timeframe based on PowerShell evolution phases
- 40+ domains registered per campaign wave across .info, .com, .pro, .xyz, .cloud, .icu, .sbs, .cfd, .bond TLDs

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
  "safedocphoto.info","recallnine.info","kentjerk.info","photodoc-secure.info",
  "kelopins.info","sec-safe-dc.info","visaphoto-secure.info","visa-safedocs.info",
  "docshub-01.info","photo-box.info",
  "photo-26254.cfd","photo-26654.cfd","photo-132454.cfd","photo-8632454.cfd",
  "photo-26653.cfd","photo-26656.cfd","photo-27857.cfd",
  "zloapobikahy23.bond","higoksbupwou.com","aluminiostramuntana.com"
)
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query record_type risk_score
```
*Detects DNS queries for known TonRAT C2 domains (Waves 1 and 2).*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Registry
where (Registry.registry_key_name="*\\CurrentVersion\\Run" OR Registry.registry_key_name="*\\CurrentVersion\\RunOnce")
  AND (Registry.registry_value_data="*node.exe*" OR Registry.registry_value_data="*node *")
by Registry.dest Registry.user Registry.registry_key_name Registry.registry_value_name Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(registry_value_data, "(?i)programdata|appdata|temp|tmp"), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user registry_key_name registry_value_name registry_value_data risk_score
```
*Detects Node.js runtime registered in Run/RunOnce keys pointing to non-standard paths — core TonRAT persistence mechanism.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_ip IN ("178.16.54.27","95.217.97.121","193.202.84.32","178.16.55.179")
  OR All_Traffic.dest_port IN (56001, 56002, 56003, 8445, 8453)
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(dest, "178.16.54.27"), 95,
    dest_port IN (56001, 56002, 56003), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest dest_port process_name risk_score
```
*Detects connections to known TonRAT C2 IPs or use of campaign-specific non-standard ports.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="node.exe"
  AND (Processes.process="*ProgramData*" OR Processes.process="*AppData*" OR Processes.process="*Temp*")
  AND Processes.parent_process_name IN ("powershell.exe","cmd.exe","wscript.exe","mshta.exe","rundll32.exe")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```
*Detects Node.js runtime (node.exe) spawned from scripting interpreters and executing from non-standard paths — TonRAT execution pattern.*

---

## 6. Executive Summary

Microsoft Threat Intelligence published on June 25, 2026 a detailed analysis of an active multi-stage intrusion campaign targeting the hospitality sector in Europe and Asia. The campaign delivers **TonRAT**, a Node.js-based JavaScript implant, via photo-themed ZIP archives containing LNK shortcut files disguised as PNG images.

A notable differentiator is **authentication laundering**: phishing emails are routed through Calendly's SendGrid infrastructure and Google's share.google redirect service, enabling them to pass all email authentication checks (SPF/DKIM/DMARC/CompAuth) while concealing the actual phishing origin. Landing pages are protected by Cloudflare Turnstile CAPTCHA to prevent automated security scanning.

The implant uses an embedded Node.js v24.13.0 runtime (89.9 MB) deployed to ProgramData, establishing a dual registry persistence mechanism: a standard Run key pointing to the Node.js implant, plus a self-refreshing RunOnce key that re-registers itself after each execution, creating resilience against single-path remediation. C2 communication uses non-standard high ports (56001/56002/56003) to `178.16.54[.]27` (primary) and other attacker-controlled infrastructure.

The campaign's PowerShell obfuscation evolved through seven documented phases between April and May 2026, indicating active development. Wave 2 added compile-after-delivery (.NET DLL compiled on-victim via csc.exe) to further evade static detection. Organizations in the hospitality sector should monitor for Node.js persistence via registry Run keys pointing to ProgramData paths, and for outbound connections to high-numbered non-standard ports.

**Severity: High** — Actively targeted hospitality sector campaign in Europe and Asia; no known attribution.

---

## References

- [Microsoft Threat Intelligence — Photo ZIP Campaign Targeting Hospitality (2026-06-25)](https://www.microsoft.com/en-us/security/blog/2026/06/25/photo-zip-campaign-targeting-hospitality-industry-delivers-node-js-implant-persistent-access/)
- [MITRE ATT&CK — T1547.001 Boot or Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK — T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK — T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
