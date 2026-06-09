# SEO-Poisoned Developer Tool Sites — TDS Delivery of Remus Stealer and AnimateClipper

## Description

Detects endpoint connections to infrastructure associated with a large-scale malware distribution ecosystem that impersonates legitimate security and developer tools (Ghidra, dnSpy, SpiderFoot) via SEO-poisoned websites. Victims visiting these fake download pages are silently routed through a CloudFront-hosted JavaScript Traffic Distribution System (TDS) that fingerprints them (anti-bot checks, VPN filtering, first-visit gating) before serving the payload.

The TDS delivers three malware families: **Remus Stealer** (Windows infostealer targeting 20+ browsers, crypto wallets, and 2FA apps), **AnimateClipper** (clipboard hijacker for 20+ blockchain ecosystems), and **SessionGate** (multi-stage obfuscated loader). This campaign primarily targets security researchers, penetration testers, and software developers who search for open-source security tools.

False positives are unlikely because the known C2 domains (asper1.freeddns.org, cheapoca.biz) and the DigitalOcean TDS server (165.22.170.129) have no legitimate use.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Drive-by Compromise |
| Technique ID | T1189 |
| Secondary Tactic | Initial Access |
| Secondary Technique | Phishing: Spearphishing Link |
| Secondary Technique ID | T1566.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.dest="165.22.170.129")
     OR (All_Traffic.dest_host IN ("asper1.freeddns.org","guiformat.com","cheapoca.biz"))
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest="165.22.170.129" OR dest_host="asper1.freeddns.org" OR dest_host="cheapoca.biz", 85,
    dest_host="guiformat.com", 70,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest dest_host dest_port action risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("asper1.freeddns.org","guiformat.com","cheapoca.biz")
  by DNS.src DNS.query DNS.record_type DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime src query record_type answer risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Connection to 165.22.170.129 (TDS server) or asper1.freeddns.org or cheapoca.biz | 85 | High-confidence Remus Stealer C2 infrastructure; no legitimate use |
| DNS query to guiformat.com | 70 | TDS staging domain; legitimate use is plausible but unlikely in enterprise contexts |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (Remus Stealer MaaS operator, 2026) | [Check Point Research — Impersonation, Click Hijacking, and TDS (2026-06-04)](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/) |

## References

- [Check Point Research — Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem (2026-06-04)](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [The Hacker News — Fake Sites Mimicking Open-Source Tools Rank High on Google to Deliver Malware via TDS (2026-06-04)](https://thehackernews.com/2026/06/fake-sites-mimicking-open-source-tools.html)
- [MITRE ATT&CK — T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK — T1608.006 SEO Poisoning](https://attack.mitre.org/techniques/T1608/006/)
