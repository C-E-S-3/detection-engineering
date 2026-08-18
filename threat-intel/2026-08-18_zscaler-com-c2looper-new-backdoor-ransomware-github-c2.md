---
scraped_at: 2026-08-18T00:00:00Z
source_url: https://www.zscaler.com/blogs/security-research/c2looper-new-backdoor-likely-tied-ransomware-github-c2
report_type: threat-intel
severity: high
title: "C2looper: New Backdoor Likely Tied to Ransomware with GitHub C2 Infrastructure"
---

# C2looper: New Backdoor Likely Tied to Ransomware with GitHub C2 Infrastructure

**Source:** Zscaler ThreatLabz  
**Date Added:** 2026-08-18  
**Severity:** High

## Summary

Zscaler ThreatLabz identified a new Windows backdoor dubbed **C2looper** that is likely affiliated with ransomware operations. The malware is notable for using **GitHub as its command-and-control (C2) infrastructure**, a living-off-trusted-sites (LoTS) technique that allows C2 traffic to blend in with legitimate GitHub API or raw content requests. Three malware samples were identified along with two C2 IP endpoints communicating over port 8888.

## Threat Actor / Malware Family

- **Malware:** C2looper
- **Type:** Windows backdoor
- **Suspected affiliation:** Ransomware operations (group unattributed at time of reporting)
- **C2 mechanism:** GitHub-based (living-off-trusted-sites)

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Command and Control | T1102.001 | Web Service: Dead Drop Resolver (GitHub used as C2 channel) |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols |
| Defense Evasion | T1036 | Masquerading (blending with legitimate GitHub traffic) |

## Indicators of Compromise

### IP Addresses

| Indicator | Port | Context |
|-----------|------|---------|
| 45.158.196.184 | 8888 | C2looper C2 server |
| 45.158.196.23 | 8888 | C2looper C2 server |

### File Hashes (SHA256)

| Hash | Context |
|------|---------|
| f96ff2f3abbff7f382ace509b90e54853b4b61c402ecde27d82f1c17b414867b | C2looper malware sample |
| 20675a659c338f7267fd09bacb431f4491f061d3acf42d07aca2dec3d25fa549 | C2looper malware sample |
| f59f32c9af4fa8a5dbd4668df8893593bc0c4324816cbf9b956acedcbfb8cdb6 | C2looper malware sample |

## References

- Zscaler ThreatLabz: https://www.zscaler.com/blogs/security-research/c2looper-new-backdoor-likely-tied-ransomware-github-c2
- VirusTotal sample 1: https://www.virustotal.com/gui/file/f96ff2f3abbff7f382ace509b90e54853b4b61c402ecde27d82f1c17b414867b/detection
- VirusTotal sample 2: https://www.virustotal.com/gui/file/20675a659c338f7267fd09bacb431f4491f061d3acf42d07aca2dec3d25fa549/detection
- VirusTotal sample 3: https://www.virustotal.com/gui/file/f59f32c9af4fa8a5dbd4668df8893593bc0c4324816cbf9b956acedcbfb8cdb6/detection
- Maltrail trail: https://github.com/stamparm/maltrail/blob/master/trails/static/malware/c2looper.txt
