---
scraped_at: 2026-07-02T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/chocopoc-trojanized-exploit-poc-repos-target-security-researchers/
report_type: threat-intel
severity: high
title: "ChocoPoC: Trojanized CVE Proof-of-Concept Repositories on GitHub Target Security Researchers"
---

# ChocoPoC: Trojanized CVE Proof-of-Concept Repositories on GitHub Target Security Researchers

**Source:** BleepingComputer / Sekoia TDR  
**Published:** 2026-07-02  
**Severity:** High  

---

## Executive Summary

Sekoia's Threat Detection & Research team documented ChocoPoC on July 2, 2026 — a campaign distributing trojanized CVE proof-of-concept repositories on GitHub targeting security researchers. Malicious actors create convincing GitHub repos that appear to offer working exploits for recent high-profile CVEs. When researchers clone and execute the PoC, a hidden payload contacts attacker-controlled C2 domains (`mora1987.work[.]gd`, `hone32.work[.]gd`) and executes a secondary stage. The technique closely mirrors Operation Dream Job and prior Lazarus Group campaigns targeting security researchers (2021–2024), though attribution for ChocoPoC has not been confirmed.

The malicious payloads are embedded via:
- PowerShell commands hidden in `setup.py`, `requirements.txt`, or `install.sh` scripts that execute on `pip install` or environment setup
- Malicious `__init__.py` or module files in Python packages that auto-execute on import
- Pre-commit hooks or CI scripts that trigger on common dev actions

The PoC repos were indexed by search engines and surfaced when researchers searched for recently published CVE numbers, making this a targeted supply chain attack against the security research community.

---

## IOCs

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `mora1987.work[.]gd` | Domain | ChocoPoC C2 domain; first-stage beacon contact |
| `hone32.work[.]gd` | Domain | ChocoPoC C2 domain; secondary payload delivery |

---

## TTPs

| MITRE Technique | ID | Description |
|-----------------|-----|-------------|
| Supply Chain Compromise: Compromise Software Dependencies and Development Tools | T1195.001 | Malicious code embedded in PoC repos executed as part of normal research workflow |
| Stage Capabilities: SEO Poisoning | T1608.006 | Malicious repos indexed and surfaced in CVE-specific search results |
| Phishing: Spearphishing via Service | T1566.003 | Repos shared via Twitter/X, Discord security communities, and researcher blogs |
| Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell payload executed via hidden setup scripts in PoC repo |
| Command and Scripting Interpreter: Python | T1059.006 | Malicious Python code executes during `pip install` or package import |
| Ingress Tool Transfer | T1105 | Secondary payload downloaded from `hone32.work[.]gd` after initial beacon |

---

## Malware & Tools

- **ChocoPoC trojanizer** — Embeds hidden execution hooks in PoC repositories; delivers generic downloader payload; Sekoia classified as targeting researcher credentials and development environment access
- **Secondary payload** — Unattributed; behaves as credential/token harvester targeting developer toolchain (SSH keys, AWS/GitHub tokens, browser sessions)

---

## Threat Actor / Attribution

| Attribute | Detail |
|-----------|--------|
| Actor | Unknown; technique overlap with prior Lazarus Group researcher-targeting campaigns (Operation Dream Job) but attribution not confirmed |
| Motivation | Espionage or initial access (targeting researcher environments and exploit knowledge) |
| Target | Security researchers, threat intelligence analysts, red team operators |
| Confidence | Low attribution confidence; Sekoia notes stylistic similarities to prior DPRK campaigns |

---

## Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host IN ("mora1987.work.gd","hone32.work.gd")
by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table src dest_host dest_port app firstTime lastTime
```

```spl
`dns` (query="mora1987.work.gd" OR query="hone32.work.gd")
| stats count by src query _time
| table _time src query count
```

---

## References

- [BleepingComputer — ChocoPoC Trojanized PoC Repos (2026-07-02)](https://www.bleepingcomputer.com/news/security/chocopoc-trojanized-exploit-poc-repos-target-security-researchers/)
- [Sekoia TDR — ChocoPoC Analysis](https://blog.sekoia.io/chocopoc-trojanized-proof-of-concept-targeting-security-researchers/)
- [MITRE ATT&CK — T1195.001: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK — T1608.006: Stage Capabilities: SEO Poisoning](https://attack.mitre.org/techniques/T1608/006/)
- [MITRE ATT&CK — G0032: Lazarus Group (context reference)](https://attack.mitre.org/groups/G0032/)
