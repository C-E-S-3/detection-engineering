---
scraped_at: 2026-08-31T00:00:00Z
source_url: https://www.sonatype.com/blog/flooding-dropper-800-malicious-npm-packages
report_type: threat-intel
severity: high
title: "WEL1DROPPER / Flooding Dropper: ~800 AI-Typosquatted npm Packages Deliver Cross-Platform RAT"
---

# WEL1DROPPER / Flooding Dropper: ~800 AI-Typosquatted npm Packages Deliver Cross-Platform RAT

**Date Reported:** ~August 7, 2026  
**Source:** Sonatype  
**Severity:** High  
**Note:** Campaign first reported ~August 7, 2026; IOC (`wel1[.]ru`) newly tracked in this repository.

## 1. IOCs

### Domains
| Indicator | Type | Context |
|-----------|------|---------|
| wel1[.]ru | C2 domain | WEL1DROPPER C2; payload fetched via Cloudflare Workers or DNS TXT record from this domain; cross-platform RAT |

### Infrastructure Notes
- Payload delivery uses Cloudflare Workers as CDN obfuscation layer
- DNS TXT records from `wel1[.]ru` used as fallback C2 channel
- ~800 malicious npm packages, all with AI-generated typosquatted names designed to match popular packages

## 2. TTPs

| Tactic | Technique | Details |
|--------|-----------|---------|
| Initial Access | T1195.001 — Supply Chain: Software | ~800 malicious npm packages published with AI-generated typosquatted names |
| Execution | T1059.001 — PowerShell | WEL1DROPPER disables ETW and AMSI via PowerShell on Windows before executing RAT |
| Defense Evasion | T1562.001 — Impair Defenses: AMSI | AMSI bypass on Windows |
| Defense Evasion | T1562.006 — Impair Defenses: ETW | ETW disabled on Windows |
| Command & Control | T1071.001 — Web Protocols | C2 via Cloudflare Workers (HTTPS CDN-fronted) and DNS TXT from wel1[.]ru |
| Command & Control | T1071.004 — DNS | DNS TXT record used as secondary C2 channel |
| Persistence | T1547 — Boot or Logon Autostart | RAT establishes persistence on Windows, macOS, and Linux |
| Collection | T1005 — Data from Local System | Cross-platform RAT capable of file exfiltration, keylogging, screen capture |

**MITRE Tactics:** TA0001, TA0002, TA0003, TA0005, TA0011  
**Kill Chain Phases:** Delivery, Exploitation, Installation, C2

## 3. Malware & Tools

### WEL1DROPPER
A multi-platform downloader/dropper distributed via malicious npm packages. When the npm package is installed (e.g., `npm install <typosquatted-name>`), a postinstall script invokes WEL1DROPPER, which:
1. On Windows: disables ETW telemetry and AMSI scanning before fetching the next stage
2. Fetches the RAT payload from Cloudflare Workers (HTTPS), falling back to a DNS TXT record lookup against `wel1[.]ru` if Cloudflare delivery fails
3. Establishes persistence and executes the cross-platform RAT

### Cross-Platform RAT
Targets Windows, macOS, and Linux. Capabilities include remote shell access, file operations, credential harvesting, and self-update. The RAT is controlled from wel1[.]ru infrastructure.

## 4. Threat Actor

Attribution is not publicly confirmed. The scale (~800 packages) and AI-generated naming suggest an organized, likely financially-motivated threat actor. The .ru TLD of the C2 domain is consistent with Eastern European cybercriminal ecosystems but is not conclusive for attribution.

## 5. Splunk Detection Searches

### Detect DNS TXT lookups to wel1[.]ru (C2 channel)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query="wel1.ru" OR DNS.query="*.wel1.ru"
  by DNS.src DNS.query DNS.record_type DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query record_type answer risk_score
```

### Detect npm postinstall ETW/AMSI disable (WEL1DROPPER Windows indicator)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("node.exe", "npm.cmd", "npm")
    AND Processes.process_name="powershell.exe"
    AND (Processes.process="*ETW*" OR Processes.process="*amsi*" OR Processes.process="*Reflection*" OR Processes.process="*patch*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Detect npm package installation spawning network connections
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("node.exe", "node")
    AND Processes.parent_process_name IN ("npm", "npm.cmd", "yarn", "pnpm")
  by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Risk Scores:** 90–95 (Critical/High) for confirmed IOC or ETW/AMSI disable via npm; 60 (Medium) for npm spawning network connections

## 6. Executive Summary

In approximately early August 2026, Sonatype's automated scanning detected a campaign publishing approximately **800 malicious npm packages** with names generated by AI to closely mimic popular packages (typosquatting). When installed, these packages execute **WEL1DROPPER**, a multi-platform downloader that:

1. On Windows, first disables ETW and AMSI to blind endpoint defenses
2. Fetches a cross-platform RAT payload via **Cloudflare Workers** (CDN-fronted for evasion)
3. Falls back to DNS TXT record lookups against **`wel1[.]ru`** for C2 channel resilience
4. Establishes persistence and activates the RAT targeting Windows, macOS, and Linux

The AI-generated typosquatting approach dramatically scales the name-confusion attack surface; developers and CI systems installing packages with minor name variations are the primary targets.

**Recommended actions:**
1. Block `wel1[.]ru` and `*.wel1[.]ru` at DNS and proxy layers.
2. Alert on DNS TXT queries to this domain — a strong indicator of active WEL1DROPPER C2 communication.
3. Alert on PowerShell spawned by npm/node that references ETW, AMSI, or reflection patching.
4. Audit npm install logs for recently installed packages and cross-reference against Sonatype's published malicious package list.
5. Enforce lockfile integrity checks (`npm ci` over `npm install`) in CI pipelines.

## References

- https://www.sonatype.com/blog/flooding-dropper-800-malicious-npm-packages
- https://attack.mitre.org/techniques/T1195/001/
- https://attack.mitre.org/techniques/T1562/001/
- https://attack.mitre.org/techniques/T1071/004/
