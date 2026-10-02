---
scraped_at: 2026-10-02T00:00:00Z
source_url: https://blog.talosintelligence.com/uat-11587/
report_type: threat-intel
severity: high
title: "UAT-11587 Targets Government and Policy Organizations Across Asia with Antino Backdoor"
---

# UAT-11587 Targets Government and Policy Organizations Across Asia with Antino Backdoor

**Source:** Cisco Talos  
**Published:** 2026-09-30  
**Severity:** High  
**Threat Actor:** UAT-11587 (China-nexus)

## Executive Summary

Cisco Talos reported on September 30, 2026 that UAT-11587, a China-nexus threat actor, has been conducting a targeted espionage campaign against government ministries, diplomatic missions, and policy research organizations across Asia. The campaign delivers a newly identified backdoor named **Antino** via spear-phishing lures disguised as legitimate government reports and institutional documents.

Lure files are HTA (HTML Application) and WSF (Windows Script File) formats hosted on Cloudflare Pages subdomain infrastructure (`my-*.pages.dev`), Cloudflare R2 CDN (`pub-*.r2.dev`), and AWS CloudFront (`*.cloudfront.net`) — legitimate hosting platforms used to evade network-based reputation filtering. UAT-11587 has demonstrated operational security tradecraft including anti-debug checks (T1622) and obfuscated scripting (T1027) in the Antino backdoor.

## TTPs (MITRE ATT&CK)

| Technique | ID | Description |
|-----------|-----|-------------|
| Spearphishing Attachment | T1566.001 | Lure documents delivered via spear-phishing targeting government and policy personnel |
| User Execution: Malicious File | T1204.002 | Recipients open HTA/WSF files masquerading as government reports |
| System Binary Proxy Execution: Mshta | T1218.005 | `mshta.exe` used to execute HTA lure files |
| Obfuscated Files or Information | T1027 | Antino backdoor code is obfuscated to evade static analysis |
| Debugger Evasion | T1622 | Antino performs anti-debug checks before executing payload |
| Command and Scripting Interpreter: Windows Script Host | T1059.005 | WSF files executed via `wscript.exe` |
| Ingress Tool Transfer | T1105 | Antino backdoor downloaded from staging infrastructure |

## Malware & Tools

### Antino Backdoor
- **Type:** Custom Windows backdoor (attributed exclusively to UAT-11587)
- **Delivery:** Dropped by HTA/WSF lures; also staged on Cloudflare R2 and CloudFront CDN
- **Anti-analysis:** Implements debugger evasion (T1622); obfuscated code (T1027)
- **C2 Protocol:** HTTPS to hardcoded C2 domains
- **C2 Infrastructure:**
  - `osc-cdn.com`
  - `microsoft-flash.com`
  - `wps-cn.com`
  - `103.27.110.220`

## IOCs

### IP Addresses

| Indicator | Type | Context |
|-----------|------|---------|
| `103.27.110.220` | IPv4 | Antino backdoor C2 server |

### Domains

| Indicator | Context |
|-----------|---------|
| `osc-cdn.com` | Antino backdoor C2 domain |
| `microsoft-flash.com` | Antino backdoor C2 domain (typosquatting Microsoft branding) |
| `wps-cn.com` | Antino backdoor C2 domain |
| `d2nq35tel3ucuo.cloudfront.net` | HTA/WSF payload staging (CloudFront CDN) |
| `pub-abfa7742e315485a98a5fafd6dbfb68e.r2.dev` | Payload staging (Cloudflare R2 CDN) |
| `pub-0173d1566dcd4fd49fa25f11f14bfe4c.r2.dev` | Payload staging (Cloudflare R2 CDN) |
| `oisadjfoinsiduhfnoisdnfosdnoifnsoid.pages.dev` | Lure/payload hosting (Cloudflare Pages) |
| `my-3lyt6wcp.pages.dev` | Lure/payload hosting (Cloudflare Pages) |
| `my-qc39r814.pages.dev` | Lure/payload hosting (Cloudflare Pages) |
| `my-662ylt3w.pages.dev` | Lure/payload hosting (Cloudflare Pages) |
| `my-6g16qsfe.pages.dev` | Lure/payload hosting (Cloudflare Pages) |
| `my-goq6xmbm.pages.dev` | Lure/payload hosting (Cloudflare Pages) |
| `my-h3qli6kq.pages.dev` | Lure/payload hosting (Cloudflare Pages) |
| `my-sv7c1fzs.pages.dev` | Lure/payload hosting (Cloudflare Pages) |
| `my-u0up9qri.pages.dev` | Lure/payload hosting (Cloudflare Pages) |
| `my-vtsdod2n.pages.dev` | Lure/payload hosting (Cloudflare Pages) |
| `my-wgoxp32b.pages.dev` | Lure/payload hosting (Cloudflare Pages) |

### File Hashes (SHA-256)

| Hash | Context |
|------|---------|
| e809da86bd81463347fa7f922d3e088755a94a331889d32acb55aa8f57778a34 | UAT-11587 Antino backdoor component |
| e6ff096a0562c0042b09d250bd60272ffcd8d72bd95c563842acf765a8dc8bcf | UAT-11587 Antino backdoor component |
| 4d0fdce4c098635fe9b296c3a82c74645f9885eb5e383aa44a0fe7e50da3ca3f | UAT-11587 Antino backdoor component |
| f1ef5fe4c0cdcff13cc750c867728b89719f81437bdc49041edd1ae1f3edb4e8 | UAT-11587 Antino backdoor component |
| 01b5c6acb20e41799a0e96d9d1d6e1c44791883706b6285e874fcb15cc93b31a | UAT-11587 Antino backdoor component |
| 5a35fcd4458e808ab0fa52bb2a92923b60566ee4d7aaadaac7c95cad3d839562 | UAT-11587 Antino backdoor component |
| 17b53ffa8e005f0e82491d3f9c0a4984c44da52e1668a855c11a137f627c5b4b | UAT-11587 Antino backdoor component |
| 484ab497072ea09f12187b349f5b1c80754e4942408a009cccb20a2a3c8c6506 | UAT-11587 Antino backdoor component |
| 3a94910eb8022592ce030e6861359f7e980fc1b5a6ccd290cbb071d3e95ed02a | UAT-11587 Antino backdoor component |
| 6a1dbbfcfe6867ac83d35012b2717084388b4a34707efd0b725466dfd0e8fa56 | UAT-11587 Antino backdoor component |
| 75c12795016ae48b1bddd34a9f5adea63a12f58701eae01e1b4ab3d9dfa1513c | UAT-11587 Antino backdoor component |
| bd8ddc8f33e0fe43147ee6f1713654996420a27c5d2cd91751ad67124ebc6fe4 | UAT-11587 Antino backdoor component |
| b75492466462141c56d97b705f0c606faf272577631dc2822aa8d6bda53633b6 | UAT-11587 Antino backdoor component |
| 23d5f1af8581ae200615d9a66d539f2043c3248b649e862557b379d7e8b7a3ac | UAT-11587 Antino backdoor component |
| 0b4e5e017c0f0ccac79e13ca5d580a75af67a24ca0763f9ebfdaaeb1ba4fc739 | UAT-11587 Antino backdoor component |
| ae1b45fb56b9f1b9cb3ee30d2bb1279c9b90b70bb62f8de305d198c6a4e0585e | UAT-11587 Antino backdoor component |
| cd3509fa82e506cc6f2eeafa0a45d4b8b76a07edadd29779daf00568febcaba7 | UAT-11587 Antino backdoor component |
| b8e6e83a73e6e07f8873c364dd2a4b830bceb60758163e2efcd7e387cb604655 | UAT-11587 Antino backdoor component |
| 7969ae5f11fc163049c8eadba06f814f5edece13a707e6087c1c49011a45b838 | UAT-11587 Antino backdoor component |
| aea5e9029f9212d05bde10f7806d1f2819be45d167e6fd877b9fb1b11088ac90 | UAT-11587 Antino backdoor component |
| 7fa98efba59614cec0b7291aedee98764f8dc037b6cc798c93951a31208e9e32 | UAT-11587 Antino backdoor component |
| 65f4b9292e91abfa5adf42a03526932930c1c0a436bb186a7948fe6770295788 | UAT-11587 Antino backdoor component |
| 61a8f5add6c35f99c389012dbb2343061fd0b54611b40490b9a7f0b49d707da0 | UAT-11587 Antino backdoor component |
| 747b1d13bdf06956b5da5f47250fefd5284ebcf7961971732c3d348aa1a2d533 | UAT-11587 Antino backdoor component |
| a13182699a12a8dd9d07c336dbd8de5e9b086b9b09793b7de2e9761aa03ce1dc | UAT-11587 Antino backdoor component |
| 2f1513c822af0c6635dd3c69dc38f0b2f6e02012ea36415fff111a5d4d5fae05 | UAT-11587 Antino backdoor component |
| a0e91085f08956a9a7034ace73cee60cb211f5d96f02bc91a026601bde8f2221 | UAT-11587 Antino backdoor component |
| 47f98dfe01759a464e22d5ec55d012dccb38ce010dd73e3ba8d7ffefca12b4b2 | UAT-11587 Antino backdoor component |
| b3416726a064dd7f657bbb400adeb365eea7f8bb60783ad2d9da1a1d93768731 | UAT-11587 Antino backdoor component |
| 0a6fb71ab1362d065c7ec2678c1e73d9a0721b0e7099d392ba7559bb2eec4970 | UAT-11587 Antino backdoor component |
| f0c1dc6d6daa4d010932c7818ed5f22929c182f58e5f495fabe2fb3cfc835b97 | UAT-11587 Antino backdoor component |
| 5555e904101689351a2a1359c9c06da0a57139a9470df7d26823c1b75db55041 | UAT-11587 Antino backdoor component |
| 5168a2696a0ed858f996f388bfe94f952d475158f4ee6206816608936db005ca | UAT-11587 Antino backdoor component |
| 7c2ac9c040b3300bffa7d2e435dbb1bc12e7efd644d2216d603c72121266395c | UAT-11587 Antino backdoor component |
| d87201c1299a7f5854929645e6891c6c424d2a690031272bedacba7c5fe73a3e | UAT-11587 Antino backdoor component |
| 334f39279ff3aae40fe74340c887ae018c75bc42790586bdf9070adb5889100c | UAT-11587 Antino backdoor component |
| 077bd873217d8abfbb6482d11966ca34f3fef7ad5166f24fbc5dc3ddefe894a1 | UAT-11587 Antino backdoor component |
| ad0bd2b45e2416fb1384bf30af068d857e7c06b4226615d66b55b610a34c5670 | UAT-11587 Antino backdoor component |
| e2f59d8d5a81583ed482b6c7bf37699efdb2264e452cf7d8cfc0c54dfbd9ab3f | UAT-11587 Antino backdoor component |
| 3a4c9020eeb5ef22a1ff443e606ccb6705fe287c583121c713d2c9f9f1f2a2af | UAT-11587 Antino backdoor component |
| 4b614e5c37abaddca162119e42a969945caa681305e246e0ed0060ea9984008b | UAT-11587 Antino backdoor component |
| c8e1239d7276178b6620f47ec4880494be1cb394477b223fc54bffb0947bff50 | UAT-11587 Antino backdoor component |
| 079acd58a74479ac8b108b618d2a4da8a8bd560a04459cd90e2fec9da5027513 | UAT-11587 Antino backdoor component |
| 8e1d68906d6de92f359945d3a95da1480e72773a3e8dea7682d6bf0f6699f75f | UAT-11587 Antino backdoor component |
| 170b0eee60a335f32c1d0c19a0bb8d8bbc0a5b298ea9486b546f58d25cc8a464 | UAT-11587 Antino backdoor component |
| b31ca75f73a9363b0e35042a41216c3f581eaa0b9cd78cb58f089c2e40babd40 | UAT-11587 Antino backdoor component |
| d753a615aedf8e58ffc75b2b7ebd320c0cbe6bcb5cbb885db749a2a85c55d3bf | UAT-11587 Antino backdoor component |
| 133a46ba41136ca21c93fb08c28446826d8c0d9b7923a16f2d152d595a710098 | UAT-11587 Antino backdoor component |
| 9fc50cf28f86201fda8306926817b1ede41fdd993202515905dd072f6803542f | UAT-11587 Antino backdoor component |
| d4cb2f5df16ec9b9c5b796ae55848534e15d4f8b8806f0431108fc7a99a2548a | UAT-11587 Antino backdoor component |
| 131ac3e0df777910e0a32e43d5744bccb0490750d4c2adc359da41d76d383c46 | UAT-11587 Antino backdoor component |
| 09ef7c736bccfafefc44d9910d499173b88063b73b221fc0dc9e9105107e5cff | UAT-11587 Antino backdoor component |
| 0c39264337a1186b2e765e24073399cbdcba118306614eb411e315887af578bd | UAT-11587 Antino backdoor component |
| 1fadc90b61ce536abda78eb387a7f3d745f00c16775d3f762845ccc0fde567da | UAT-11587 Antino backdoor component |
| 40e7e77aff603f4c2ef17b3bc8ea836e714d0734a1e5b946e52f95536ec5c91d | UAT-11587 Antino backdoor component |
| 5c5c060b272cd4a5c3767edc0e9478bd35b7e1756e183d0446a5491bd65519cb | UAT-11587 Antino backdoor component |
| 971cb2448b5d67dcc1f5eaa10d12e77f213035ad31230dc2ac7a510610a2059d | UAT-11587 Antino backdoor component |
| 9b7df409c9a89f7536d3ba7b6d43fb6dbac618c8bb52615ba34cc971ad71bbf3 | UAT-11587 Antino backdoor component |
| b90a4e770869c28fd2140acb3ebdc50c113bb6f096b4bbdb9ac87c349c70e85e | UAT-11587 Antino backdoor component |
| ca14ad0344dc7216f6da29a5cbe4237d886cc5257e8c3a48fb4885a311c9b800 | UAT-11587 Antino backdoor component |
| e2eb7703047b37b28dc34e6990205d758a2454b39bc655b460606745fadcb530 | UAT-11587 Antino backdoor component |
| e7e3b0bcd6798634adf8b49d305f3a7b7682e4b76db549682a183c5a186df4bb | UAT-11587 Antino backdoor component |
| fdbd047031c13a17c9f491c9355f44d587584ebe2b8927be8482e6c236c8e1c1 | UAT-11587 Antino backdoor component |

## Threat Actor Attribution

**UAT-11587** is a China-nexus threat actor assessed with high confidence based on targeting patterns, infrastructure, and tooling. The actor focuses on government entities, diplomatic missions, think tanks, and policy research organizations across Southeast and East Asia — sectors aligned with PRC intelligence collection priorities.

Key attribution indicators:
- Targeting exclusively government and policy organizations aligned with PRC intelligence interests
- Custom tooling (Antino backdoor) with no prior public attribution
- Infrastructure patterns (Cloudflare Pages abuse for delivery, APAC-registered C2 domains) consistent with China-nexus APT tradecraft
- Lures crafted to match target government and institutional document templates

## Splunk Detection Searches

### 1. mshta.exe Executing HTA Files from User-Writable Paths

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="mshta.exe"
    AND (Processes.process="*\\Users\\*" OR Processes.process="*\\AppData\\*"
         OR Processes.process="*\\Downloads\\*" OR Processes.process="*\\Temp\\*"
         OR Processes.process="*\\Public\\*" OR Processes.process="*\\Desktop\\*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process
```

### 2. wscript.exe/cscript.exe Executing WSF from User-Writable Paths

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe")
    AND Processes.process="*.wsf*"
    AND (Processes.process="*\\Users\\*" OR Processes.process="*\\AppData\\*"
         OR Processes.process="*\\Downloads\\*" OR Processes.process="*\\Temp\\*"
         OR Processes.process="*\\Public\\*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process
```

### 3. DNS Lookups to UAT-11587 C2 and Delivery Infrastructure

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("osc-cdn.com","microsoft-flash.com","wps-cn.com",
    "d2nq35tel3ucuo.cloudfront.net","oisadjfoinsiduhfnoisdnfosdnoifnsoid.pages.dev",
    "my-3lyt6wcp.pages.dev","my-qc39r814.pages.dev","my-662ylt3w.pages.dev",
    "my-6g16qsfe.pages.dev","my-goq6xmbm.pages.dev","my-h3qli6kq.pages.dev",
    "my-sv7c1fzs.pages.dev","my-u0up9qri.pages.dev","my-vtsdod2n.pages.dev",
    "my-wgoxp32b.pages.dev","pub-abfa7742e315485a98a5fafd6dbfb68e.r2.dev",
    "pub-0173d1566dcd4fd49fa25f11f14bfe4c.r2.dev")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src query answer
```

## References

- [Cisco Talos — UAT-11587 IOC File (GitHub)](https://github.com/Cisco-Talos/IOCs/blob/main/2026/09/uat-11587-targets-gov.json)
- [MITRE ATT&CK — T1204.002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK — T1218.005: System Binary Proxy Execution: Mshta](https://attack.mitre.org/techniques/T1218/005/)
- [MITRE ATT&CK — T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK — T1622: Debugger Evasion](https://attack.mitre.org/techniques/T1622/)
- [MITRE ATT&CK — T1059.005: Windows Script Host](https://attack.mitre.org/techniques/T1059/005/)
