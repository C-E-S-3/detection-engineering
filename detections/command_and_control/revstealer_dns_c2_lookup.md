# RevStealer DNS C2 Lookup Detection

## Description

Detects DNS queries to known RevStealer infostealer C2 domains. RevStealer is a newly identified Windows information-stealing malware (first observed 2026-07-31) with a large infrastructure footprint of 260 C2 domains spanning diverse TLDs (.click, .lol, .xyz, .sbs, .one, .cloud, .monster, .pics). The malware family uses both apex domains and API/proxy subdomains for exfiltration.

False positive potential is very low given the specificity of the domain list. Any internal resolution of these domains should be treated as a confirmed compromise indicator requiring immediate host isolation.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Command and Control (TA0011) |
| **Technique** | T1071.001 — Application Layer Protocol: Web Protocols |
| **Sub-technique** | T1568 — Dynamic Resolution |

## Lockheed Martin Kill Chain Phase

**Command & Control** — Detection of outbound C2 channel establishment via DNS resolution of known RevStealer infrastructure.

## Splunk SPL Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Resolution.DNS
    where DNS.query IN (
        "alpha-zone.click", "amberscreen.lol", "apiforge.click",
        "aqua-grid77.xyz", "atlasbyte.xyz", "autoscope.sbs",
        "bench-grid.one", "birch-studio29.one", "brewtrail.click",
        "brighttempo.lol", "calmtexture.click", "cchain-gov.org",
        "cchain.pro", "cchaingov.org", "ccw.lat", "cdnbazaar.xyz",
        "civicblaze.click", "craftlayer.click", "deepclimate.click",
        "easttrail5.xyz", "everatlas.lol", "fastmoneyflux.com",
        "hexatecha.com", "nexbu.cloud", "youthchain.cc",
        "api.atlasbyte.xyz", "api.autoscope.sbs", "proxy.everatlas.lol",
        "eth.cchain-gov.org", "eth.cchain.pro", "eth.cchaingov.org",
        "eth.ccw.lat", "eth.youthchain.cc",
        "sancamilowebhook.nexbu.cloud"
    )
    by DNS.src DNS.query DNS.answer DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query answer record_type risk_score
```

## Risk Score Logic

| Score | Rationale |
|-------|-----------|
| 90 (Critical) | Any DNS resolution of a known RevStealer C2 domain is a near-certain true positive — these domains have no legitimate use and are confirmed infostealer infrastructure. Immediate host investigation and credential rotation warranted. |

## Associated Threat Actors

| Actor | Type | Notes |
|-------|------|-------|
| RevStealer operators | Unknown | Attribution unknown as of 2026-08-01; large 260-domain infrastructure suggests MaaS (Malware-as-a-Service) distribution model |

## References

- [Maltrail RevStealer trail](https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/revstealer.txt)
- [ThreatFox Win.RevStealer](https://threatfox.abuse.ch/browse/malware/win.revstealer/)
- [MITRE ATT&CK T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1568](https://attack.mitre.org/techniques/T1568/)
- Threat intel report: `threat-intel/2026-08-01_maltrail-win-revstealer-windows-infostealer.md`
