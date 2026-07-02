---
scraped_at: 2026-07-02T00:00:00Z
source_url: https://thehackernews.com/2026/07/seo-poisoned-software-sites-distribute-screenconnect-asyncrat.html
report_type: threat-intel
severity: high
title: "SEO-Poisoned Software Download Sites Distribute Trojanized ScreenConnect to Deploy AsyncRAT via DLL Sideloading"
---

# SEO-Poisoned Software Download Sites Distribute Trojanized ScreenConnect to Deploy AsyncRAT via DLL Sideloading

**Source:** The Hacker News  
**Published:** 2026-07-01  
**Severity:** High  

---

## Executive Summary

A campaign documented on July 1, 2026 abuses SEO poisoning to surface malicious software download sites in search results for popular free tools (VLC, OBS Studio, KMS activators, game cheats). Victims download trojanized installers that bundle a modified ScreenConnect (ConnectWise Control) client alongside a malicious DLL. When ScreenConnect loads, it side-loads the malicious DLL (T1574.002), which then spawns AsyncRAT via process hollowing (T1055.012) into a legitimate Windows process. This attack chain is notable because:

1. **ScreenConnect is a legitimate RMM tool** — its presence alone does not trigger AV
2. **DLL sideloading evades many EDR controls** that check process lineage rather than loaded modules
3. **Process hollowing via AsyncRAT** obscures the true malicious process behind a legitimate host
4. AsyncRAT provides full remote access: keylogging, screen capture, file transfer, reverse shell

The five confirmed malicious domains impersonate popular software brands with slightly modified names and TLDs.

---

## IOCs

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `vlc-media[.]com` | Domain | SEO-poisoned site impersonating VLC media player download |
| `studio-obs[.]net` | Domain | SEO-poisoned site impersonating OBS Studio download |
| `kms-tools[.]com` | Domain | SEO-poisoned site distributing trojanized KMS activator |
| `crosshairx[.]pro` | Domain | SEO-poisoned site targeting gamers (crosshair overlay tool lure) |
| `fileget[.]loseyourip[.]com` | Domain | Second-stage payload delivery domain for AsyncRAT binary |

---

## TTPs

| MITRE Technique | ID | Description |
|-----------------|-----|-------------|
| Drive-by Compromise / SEO Poisoning | T1608.006 | Attacker manipulates search results to surface malicious software download sites |
| Masquerading: Match Legitimate Name or Location | T1036.005 | Malicious installer bundles legitimate ScreenConnect client binary to appear benign |
| Hijack Execution Flow: DLL Side-Loading | T1574.002 | Malicious DLL placed in ScreenConnect install directory; loaded automatically by legitimate ScreenConnect executable |
| Process Injection: Process Hollowing | T1055.012 | AsyncRAT injected into legitimate Windows host process via process hollowing |
| Remote Access Software | T1219 | ScreenConnect client provides RMM backdoor; AsyncRAT provides full C2 channel |
| Ingress Tool Transfer | T1105 | AsyncRAT binary fetched from `fileget[.]loseyourip[.]com` post-sideload |

---

## Malware & Tools

- **Trojanized ScreenConnect installer** — Legitimate ScreenConnect client bundled with malicious DLL; installer passes AV checks; sideloading occurs at runtime
- **AsyncRAT** — Open-source .NET RAT; provides keylogging, screen capture, reverse shell, file management; widely abused by low- to mid-tier threat actors; previously seen in Scattered Spider and ClickFix campaigns

---

## Threat Actor / Attribution

| Attribute | Detail |
|-----------|--------|
| Actor | Unknown; technique and tooling consistent with financially motivated cybercrime groups |
| Motivation | Financial (initial access brokering, ransomware staging, data theft) |
| Target | Broad consumer and SMB targets seeking free/cracked software |
| Confidence | Low attribution confidence |

---

## Splunk Detection Searches

See `detections/defense_evasion/screenconnect_dll_sideload_asyncrat.md` for the dedicated detection covering ScreenConnect spawning suspicious child processes (DLL sideload → AsyncRAT indicator).

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe","ConnectWiseControl.ClientService.exe")
AND Processes.process_name IN ("powershell.exe","cmd.exe","wscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table dest user parent_process_name process_name process firstTime lastTime
```

---

## References

- [The Hacker News — SEO-Poisoned Sites Distribute ScreenConnect + AsyncRAT (2026-07-01)](https://thehackernews.com/2026/07/seo-poisoned-software-sites-distribute-screenconnect-asyncrat.html)
- [MITRE ATT&CK — T1574.002: Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1055.012: Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK — T1608.006: Stage Capabilities: SEO Poisoning](https://attack.mitre.org/techniques/T1608/006/)
- [AsyncRAT GitHub (Reference)](https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp)
