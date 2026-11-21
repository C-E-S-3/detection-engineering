---
scraped_at: 2026-11-21T00:00:00Z
source_url: https://blackpointcyber.com/blog/romulus-cncmachinerms/
report_type: threat-intel
severity: high
title: "ROMULUS ClickFix Delivery Platform Drops CNCMachineRMS RAT via Trojanized Stardock Installer"
---

# ROMULUS ClickFix Delivery Platform Drops CNCMachineRMS RAT via Trojanized Stardock Installer

**Source:** Blackpoint Cyber APG / Forescout / malware-traffic-analysis.net
**Published:** 2026-11-19 (Blackpoint); supplementary Forescout analysis ~2026-10-15
**Severity:** High

---

## 1. IOCs

### IP Addresses — C2 Infrastructure

| IP | Context | Source |
|----|---------|--------|
| 167.76.44[.]160 | CNCMachineRMS C2 (Blackpoint ROMULUS campaign, Nov 2026) | Blackpoint Cyber |
| 167.148.201[.]224 | CNCMachineRMS C2 (Blackpoint ROMULUS campaign, Nov 2026) | Blackpoint Cyber |
| 93.152.213[.]151 | CNCMachineRMS C2 (Blackpoint ROMULUS campaign, Nov 2026) | Blackpoint Cyber |
| 87.199.205[.]61 | CNCMachineRMS C2 — SmartApeSG ClickFix campaign (Nov 12, port 443) | malware-traffic-analysis.net |
| 96.62.224[.]81 | ROMULUS delivery infrastructure (Forescout) | Forescout |
| 86.109.75[.]7 | ROMULUS delivery infrastructure (Forescout; link to ROMULUS not fully confirmed) | Forescout |
| 151.240.151[.]223 | ROMULUS delivery infrastructure (Forescout) | Forescout |
| 23.94.145[.]224 | ROMULUS delivery infrastructure (Forescout) | Forescout |
| 93.152.224[.]118 | ROMULUS delivery infrastructure (Forescout) | Forescout |
| 2.27.248[.]127 | ROMULUS delivery infrastructure (Forescout) | Forescout |

### Domains

| Domain | Context | Source |
|--------|---------|--------|
| cashewminaret[.]org | Fake CAPTCHA domain used in SmartApeSG ClickFix campaign pushing CNCMachineRMS | malware-traffic-analysis.net |
| novatrafficcore[.]lol | Staging domain linked to ROMULUS delivery chain (unconfirmed) | Search summary |

### File Artifacts

| Artifact | Type | Context |
|---------|------|---------|
| IconEdit2Turb.msi | MSI installer | Trojanized Stardock-branded MSI; executed silently via msiexec.exe by PowerShell stager |
| CNCMachineRMS\tasks | Registry/runtime path | RAT runtime artifact; task storage path built dynamically at runtime |
| task_payload.bin | Runtime file | RAT payload staging file built at runtime |
| WinWrapIDE.exe | Signed binary | Legitimate IBM SPSS IDE used as the BabaDeda loader chain's LOLBin carrier |

> **Note:** No complete SHA256 hashes were confirmed in accessible sources. The partial value `91a22cf3…fb0fe2` was reported by Forescout for IconEdit2Turb.msi; verify against the original Forescout report before blocklisting.

---

## 2. TTPs

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1189 | Drive-by Compromise | ROMULUS fake CAPTCHA pages lure victims into running clipboard-injected PowerShell |
| Initial Access | T1566.002 | Spearphishing Link | ClickFix delivery pages presented as CAPTCHA verification or software update prompts |
| Execution | T1204.002 | User Execution: Malicious File | User manually runs a clipboard-pasted PowerShell command |
| Execution | T1059.001 | PowerShell | Obfuscated PowerShell stager strips Zone.Identifier (MotW) and executes IconEdit2Turb.msi |
| Defense Evasion | T1553.005 | Mark-of-the-Web Bypass | PowerShell stager removes Zone.Identifier ADS before invoking msiexec.exe silently |
| Defense Evasion | T1218.007 | Msiexec | MSI payload executed via msiexec.exe /q to suppress UAC prompts |
| Defense Evasion | T1574.002 | DLL Side-Loading | BabaDeda chain: signed IBM SPSS IDE (WinWrapIDE.exe) loads malicious DLL |
| Command and Control | T1095 | Non-Application Layer Protocol | CNCMachineRMS communicates to C2 over TCP; Netresec has published C2 protocol analysis |
| Collection | T1056 | Input Capture | RAT can spy on users and capture input from compromised PC |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| **ROMULUS** | ClickFix delivery platform (MaaS) | Multi-payload delivery infrastructure; hosts fake CAPTCHA/verification pages; orchestrates victim redirection and payload staging across multiple C2 nodes |
| **CNCMachineRMS** | RAT | Previously undocumented remote access trojan; builds C2 path strings at runtime (CNCMachineRMS\tasks); can spy on users and remote-control the PC; Netresec has analyzed its C2 protocol |
| **SmartApeSG** | Traffic distribution / redirect service | Threat actor / campaign using CNCMachineRMS as the payload; uses ROMULUS infrastructure; observed Nov 12, 2026 |

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|-----------|-------|
| Campaign name | ROMULUS ClickFix |
| Primary payload | CNCMachineRMS RAT |
| Delivery service | ROMULUS (possibly a MaaS platform) |
| Delivery sub-campaign | SmartApeSG (Nov 12, 2026) |
| Attribution | Unattributed; ROMULUS appears to be a delivery platform used by multiple actors |
| Targeting | Broad; consumer-facing lures suggest opportunistic targeting |
| Analysis source | Blackpoint Cyber APG (Nov 19, 2026), Forescout (~Oct 2026), malware-traffic-analysis.net (Nov 12, 2026) |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe")
    AND (Processes.process="*Unblock-File*" OR Processes.process="*Zone.Identifier*"
         OR Processes.process="*msiexec*" OR Processes.process="*IconEdit2Turb*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)IconEdit2Turb"), 95,
    match(process,"(?i)Zone\.Identifier") AND match(process,"(?i)msiexec"), 85,
    match(process,"(?i)Unblock-File"), 70,
    1=1, 50)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.dest="167.76.44.160" OR All_Traffic.dest="167.148.201.224"
         OR All_Traffic.dest="93.152.213.151" OR All_Traffic.dest="87.199.205.61"
         OR All_Traffic.dest="96.62.224.81" OR All_Traffic.dest="151.240.151.223"
         OR All_Traffic.dest="23.94.145.224" OR All_Traffic.dest="93.152.224.118"
         OR All_Traffic.dest="2.27.248.127")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.bytes_out All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port bytes_out user risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where (DNS.query="cashewminaret.org" OR DNS.query="*.cashewminaret.org"
         OR DNS.query="novatrafficcore.lol" OR DNS.query="*.novatrafficcore.lol")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query answer risk_score
```

---

## 6. Executive Summary

ROMULUS is a multi-payload ClickFix delivery platform observed delivering CNCMachineRMS, a previously undocumented remote access trojan. Victims are lured to fake CAPTCHA verification pages that inject a PowerShell command into the clipboard; executing it triggers an obfuscated stager that strips Mark-of-the-Web from a malicious MSI (`IconEdit2Turb.msi`) and silently installs it via `msiexec.exe`. An alternate delivery chain uses the BabaDeda loader with a signed IBM SPSS IDE binary to sideload a malicious DLL before deploying the RAT.

CNCMachineRMS builds its task storage paths dynamically at runtime (`CNCMachineRMS\tasks`), suggesting deliberate string obfuscation to evade static signatures. Blackpoint confirmed C2 to three IPs (167.76.44[.]160, 167.148.201[.]224, 93.152.213[.]151) on November 19, 2026; Forescout had identified additional ROMULUS hosting infrastructure approximately a month earlier.

**Recommended actions:** Block ROMULUS infrastructure IPs at the network perimeter; alert on PowerShell stripping Zone.Identifier metadata before MSI execution; monitor for `msiexec.exe /q` invocations from PowerShell parent processes.
